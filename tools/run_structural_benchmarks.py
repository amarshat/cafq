#!/usr/bin/env python3
"""Decisive comparison: per-fault analysis vs post-hoc quotient vs structural
quotient. Writes data/structural_benchmarks.{json,md}.

Approaches (identical programs, fault model, field, and proof obligations):
  A   independent symbolic analysis of every fault (cafq.analyzer.analyze:
      full re-execution per fault) + baseline checker; one root-set
      computation per fault.
  A'  the same analysis with prefix caching (cafq.baselines) + baseline
      checker. A fairer comparator for generation time.
  B   A plus post-hoc quotient classes (already computed inside analyze);
      one root-set computation per L4 class. Checked by the baseline checker,
      which re-executes every fault.
  C   structural quotient (cafq.structural) + structural checker.

Every reported total is generation + independent checking. The script aborts
if C's verdicts differ from A's on any fault or if any checker rejects.

    python tools/run_structural_benchmarks.py            # full table
    python tools/run_structural_benchmarks.py --quick    # small subset
"""
import json
import pathlib
import platform
import subprocess
import sys
import time
import tracemalloc

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
from cafq import checker, structural, structural_checker  # noqa: E402
from cafq import circuits as C  # noqa: E402
from cafq.analyzer import analyze  # noqa: E402
from cafq.baselines import analyze_prefix_cached  # noqa: E402
from cafq.kernels import cyclic_mul  # noqa: E402
from cafq_helpers import masked_check, nonlinear_trap, square_check  # noqa: E402

FULL = [
    ("schoolbook n=4", lambda: C.polymul_schoolbook(4), True),
    ("schoolbook n=6", lambda: C.polymul_schoolbook(6), True),
    ("schoolbook n=8", lambda: C.polymul_schoolbook(8), True),
    ("karatsuba 2x2", C.polymul_karatsuba2, True),
    ("butterfly 4", C.butterfly4, True),
    ("cyclic mul n=5", lambda: cyclic_mul(5), True),
    ("cyclic mul n=7", lambda: cyclic_mul(7), True),
    ("cyclic mul n=11", lambda: cyclic_mul(11), True),
    ("cyclic mul n=5, tautological check", lambda: cyclic_mul(5, weak=True), True),
    ("AR discrepancy n=6 (adversarial input)", lambda: C.ar_discrepancy(6), True),
    ("masked check, nonlinear (adversarial)", lambda: masked_check(8, True), True),
    ("nonlinear trap (adversarial)", lambda: nonlinear_trap(8), True),
    ("square check (adversarial)", lambda: square_check(8), True),
    ("cyclic mul n=17 (C only)", lambda: cyclic_mul(17), False),
    ("cyclic mul n=23 (C only)", lambda: cyclic_mul(23), False),
    ("cyclic mul n=31 (C only)", lambda: cyclic_mul(31), False),
]
QUICK = [FULL[0], FULL[3], FULL[5], FULL[8], FULL[11]]


def wire(obj):
    return json.loads(json.dumps(obj))


def best(fn, reps):
    out, t = None, float("inf")
    for _ in range(reps):
        t0 = time.perf_counter()
        out = fn()
        t = min(t, time.perf_counter() - t0)
    return out, t


def peak_mb(fn):
    tracemalloc.start()
    fn()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak / 1e6


def run_one(label, build, with_baselines, reps):
    prog = build()
    wp = wire(prog.to_json())
    n, F = len(prog.instrs), len(prog.fault_space())
    row = {"program": label, "name": prog.name, "sha256": prog.sha256(),
           "field": f"GF({1 << prog.m})", "instructions": n, "faults": F}

    res, t_gen = best(lambda: structural.generate(prog), reps)
    doc = wire(res.document)
    rep, t_chk = best(lambda: structural_checker.check(wp, doc), reps)
    if not rep["ok"]:
        raise SystemExit(f"structural checker rejected {label}: {rep['errors'][:2]}")
    cw = [k for k in rep["classes"] if k.startswith("covered|k=")]
    modes = {}
    for c in res.faults:
        modes[c["mode"]] = modes.get(c["mode"], 0) + 1
    row["C"] = {
        "gen_s": t_gen, "check_s": t_chk, "total_s": t_gen + t_chk,
        "certificate_bytes": len(json.dumps(doc)),
        "templates": len(doc["templates"]),
        "classes_covered_wrong": len(cw), "classes_all": len(rep["classes"]),
        "modes": modes, "work_gen": res.work.as_dict(), "work_check": rep["stats"],
        "symbolic_instr_gen": res.work.forward_instr + res.work.backward_instr
        + res.work.perturbed_instr,
        "symbolic_instr_check": 2 * n + rep["stats"]["per_fault_executions"] * n,
        "expensive_analyses": res.work.template_analyses + res.work.baseline_classifications,
        "peak_mb": peak_mb(lambda: structural_checker.check(
            wp, wire(structural.generate(prog).document))),
        "counts": res.counts(), "unsound_or_rejected": 0,
    }
    row["counts"] = res.counts()
    if not with_baselines:
        return row

    a, ta = best(lambda: analyze(prog), reps)
    certs = wire(a.certificates)
    ra, tca = best(lambda: checker.check(wp, certs), reps)
    if not ra["ok"]:
        raise SystemExit(f"baseline checker rejected {label}")
    a2, ta2 = best(lambda: analyze_prefix_cached(prog), reps)
    if a2.certificates != a.certificates:
        raise SystemExit("prefix-cached baseline diverged")
    base = {c["site_id"]: c for c in a.certificates if c["fault"]}
    for c in res.faults:
        b = base[c["site_id"]]
        if (c["classification"], c["wrong_output_possible"]) != \
                (b["classification"], b["wrong_output_possible"]):
            raise SystemExit(f"VERDICT MISMATCH {label} {c['site_id']}")
        if c["degree_bound"] is not None and c["degree_bound"] > b["degree_bound"]:
            raise SystemExit(f"WEAKER BOUND {label} {c['site_id']}")
    exact = [c for c in a.certificates if c["fault"] and c["quotient"]
             and c["quotient"]["exact_roots"] is not None]
    covered_wrong = a.counts()["covered_wrong_possible"]
    cc = a.class_counts(True)
    common = {
        "check_s": tca, "certificate_bytes": len(json.dumps(certs)),
        "symbolic_instr_check": (F + 1) * n,
        "expensive_analyses": F,       # one witness/factorisation attempt per fault
    }
    row["A"] = {**common, "gen_s": ta, "total_s": ta + tca,
                "symbolic_instr_gen": (F + 1) * n,
                "classes_covered_wrong": covered_wrong, "root_sets": len(exact),
                "peak_mb": peak_mb(lambda: checker.check(wp, wire(analyze(prog).certificates)))}
    row["A_prefix"] = {**common, "gen_s": ta2, "total_s": ta2 + tca,
                       "symbolic_instr_gen": a2.classes["symbolic_instr"],
                       "classes_covered_wrong": covered_wrong, "root_sets": len(exact)}
    row["B"] = {**common, "gen_s": ta, "total_s": ta + tca,
                "symbolic_instr_gen": (F + 1) * n,
                "classes_covered_wrong": cc["L3"], "classes_L4": cc["L4"],
                "root_sets": len({c["class_keys"]["L4"] for c in exact})}
    row["speedup_total_vs_A"] = row["A"]["total_s"] / row["C"]["total_s"]
    row["speedup_total_vs_A_prefix"] = row["A_prefix"]["total_s"] / row["C"]["total_s"]
    return row


def main():
    quick = "--quick" in sys.argv
    progs = QUICK if quick else FULL
    reps = 1 if quick else 3
    rows = [run_one(l, b, w, reps) for l, b, w in progs]
    cpu = ""
    try:
        cpu = next(l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo")
                   if l.startswith("model name"))
    except (OSError, StopIteration):
        pass
    rev = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                         text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain", "src"], cwd=ROOT,
                                capture_output=True, text=True).stdout.strip())
    meta = {"python": platform.python_version(), "system": platform.platform(),
            "cpu": cpu, "git_revision": rev, "src_dirty": dirty, "repetitions": reps,
            "timing": "best of repetitions, wall-clock, single thread"}
    if quick:
        print(json.dumps({"environment": meta, "rows": rows}, indent=1)[:1500])
        return
    (ROOT / "data" / "structural_benchmarks.json").write_text(
        json.dumps({"environment": meta, "rows": rows}, indent=1) + "\n")

    md = ["# Structural quotient benchmarks (generated by tools/run_structural_benchmarks.py)", "",
          f"Environment: Python {meta['python']}; {meta['system']}; CPU {cpu}; "
          f"source revision `{rev}`{' (uncommitted changes in src/)' if dirty else ''}.",
          f"Timing: best of {reps}, wall-clock seconds, single thread. "
          "Fault model in every row: single skip / result-zero / bit-flip on every instruction, GF(256).",
          "Verdict parity between A and C is asserted fault by fault; all checkers accepted.",
          "", "## Total verification cost = generation + independent checking", "",
          "| program | instrs | faults | A total s | A' (prefix-cached) total s | B total s | C total s | C gen | C check | A/C | A'/C |",
          "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        c = r["C"]
        if "A" in r:
            md.append(f"| {r['program']} | {r['instructions']} | {r['faults']} | {r['A']['total_s']:.3f} | "
                      f"{r['A_prefix']['total_s']:.3f} | {r['B']['total_s']:.3f} | {c['total_s']:.4f} | "
                      f"{c['gen_s']:.4f} | {c['check_s']:.4f} | {r['speedup_total_vs_A']:.1f}x | "
                      f"{r['speedup_total_vs_A_prefix']:.1f}x |")
        else:
            md.append(f"| {r['program']} | {r['instructions']} | {r['faults']} | not run | not run | not run | "
                      f"{c['total_s']:.4f} | {c['gen_s']:.4f} | {c['check_s']:.4f} | - | - |")
    md += ["", "## Work actually performed", "",
           "Symbolic instruction executions (generator + checker) and expensive analyses "
           "(witness search + factorisation + root set). For C an expensive analysis is one "
           "template or one fault sent to the per-fault classifier.", "",
           "| program | A sym. instr | A' sym. instr | C sym. instr | A/B expensive analyses | C expensive analyses | C templates | C per-fault poly mults (gen/check) | C per-fault executions in checker |",
           "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        c = r["C"]
        ci = c["symbolic_instr_gen"] + c["symbolic_instr_check"]
        if "A" in r:
            ai = r["A"]["symbolic_instr_gen"] + r["A"]["symbolic_instr_check"]
            a2 = r["A_prefix"]["symbolic_instr_gen"] + r["A_prefix"]["symbolic_instr_check"]
            ea = r["A"]["expensive_analyses"]
        else:
            ai = a2 = ea = "not run"
        md.append(f"| {r['program']} | {ai} | {a2} | {ci} | {ea} | {c['expensive_analyses']} | "
                  f"{c['templates']} | {c['work_gen']['per_fault_poly_mul']}/{c['work_check']['per_fault_poly_mul']} | "
                  f"{c['work_check']['per_fault_executions']} |")
    md += ["", "## Classes, root sets, certificates, memory", "",
           "| program | covered faults that can corrupt output | A classes (=faults) | B classes L3 / L4 | C classes (checker-derived) | root sets A / B / C | cert bytes A,B | cert bytes C | peak MB A | peak MB C |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        c = r["C"]
        cw = r["counts"]["covered_wrong_possible"]
        if "A" in r:
            md.append(f"| {r['program']} | {cw} | {r['A']['classes_covered_wrong']} | "
                      f"{r['B']['classes_covered_wrong']} / {r['B']['classes_L4']} | {c['classes_covered_wrong']} | "
                      f"{r['A']['root_sets']} / {r['B']['root_sets']} / {c['templates']} | "
                      f"{r['A']['certificate_bytes']} | {c['certificate_bytes']} | "
                      f"{r['A']['peak_mb']:.1f} | {c['peak_mb']:.1f} |")
        else:
            md.append(f"| {r['program']} | {cw} | - | - | {c['classes_covered_wrong']} | - / - / {c['templates']} | - | "
                      f"{c['certificate_bytes']} | - | {c['peak_mb']:.1f} |")
    md += ["", "## Verdicts (every in-scope fault counted once; identical for A, B, C)", "",
           "| program | faults | benign | covered | of which can corrupt output | bypass | unknown | C modes |",
           "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        k = r["counts"]
        md.append(f"| {r['program']} | {k['sites']} | {k['benign']} | {k['covered']} | "
                  f"{k['covered_wrong_possible']} | {k['bypass']} | {k['unknown']} | "
                  f"{', '.join(f'{m}:{v}' for m, v in sorted(r['C']['modes'].items()))} |")
    out = ROOT / "data" / "structural_benchmarks.md"
    out.write_text("\n".join(md) + "\n")
    print(out.read_text())


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Restricted two-fault study: ONE data fault + ONE checker fault.

Question: do the single-fault classifications conceal bypasses?

Method. For every pair (d, c) with d a single fault in the data/fold region
that the single-fault analysis certified 'covered, can corrupt the output',
and c any single fault in the check region, execute the program symbolically
with BOTH faults and classify the resulting (outputs, discrepancy) with the
unchanged baseline classifier. No structural shortcut is used for the verdicts.

Cross-check (structural consequence, Corollary S5): for skip/zero checker
faults the pair verdicts are also obtained by running the structural
generator on the checker-mutated program P^c; the two must agree.

Writes data/two_fault_study.{json,md}.
"""
import json
import pathlib
import random
import sys
import time
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from cafq import circuits as C  # noqa: E402
from cafq import structural  # noqa: E402
from cafq.analyzer import analyze, classify_observation, reference  # noqa: E402
from cafq.field import get_field  # noqa: E402
from cafq.ir import Fault, Instr, Program  # noqa: E402
from cafq.kernels import cyclic_mul  # noqa: E402
from cafq.poly import Poly  # noqa: E402

PROGRAMS = [("karatsuba 2x2", C.polymul_karatsuba2),
            ("schoolbook n=2", lambda: C.polymul_schoolbook(2)),
            ("cyclic mul n=2", lambda: cyclic_mul(2)),
            ("butterfly 4", C.butterfly4)]


def run2(prog: Program, faults: list[Fault]) -> dict:
    F = get_field(prog.m, prog.modulus)
    zero = Poly(F)
    by_site = {f.site: f for f in faults}
    reg = {v: Poly.var(F, v) for v in prog.inputs + [prog.challenge]}
    for i, ins in enumerate(prog.instrs):
        f = by_site.get(i)
        if f is not None and f.kind == "skip":
            continue
        if ins.op == "const":
            v = Poly.const(F, ins.a)
        elif ins.op == "mov":
            v = reg.get(ins.a, zero)
        elif ins.op == "add":
            v = reg.get(ins.a, zero) + reg.get(ins.b, zero)
        else:
            v = (reg.get(ins.a, zero) * reg.get(ins.b, zero)).reduce()
        if f is not None and f.kind == "zero":
            v = zero
        if f is not None and f.kind == "bitflip":
            v = v + Poly.const(F, 1 << f.bit)
        reg[ins.dst] = v
    return reg


def mutate(prog: Program, c: Fault) -> Program:
    """P^c for skip/zero checker faults, keeping instruction indices."""
    ins = list(prog.instrs)
    old = ins[c.site]
    if c.kind == "skip":
        ins[c.site] = Instr("mov", old.dst, old.dst, None, old.region)   # no-op
    else:
        ins[c.site] = Instr("const", old.dst, 0, None, old.region)
    return Program(prog.name + f"^{c.site_id}", prog.m, prog.modulus, prog.inputs,
                   prog.challenge, ins, prog.outputs, prog.disc, prog.inconsistency)


def study(label, build):
    t0 = time.perf_counter()
    prog = build()
    F = get_field(prog.m, prog.modulus)
    zero = Poly(F)
    rng = random.Random(0)
    ref = reference(prog)
    single = {c["site_id"]: c for c in analyze(prog).certificates if c["fault"]}
    space = prog.fault_space()
    data = [f for f in space if prog.instrs[f.site].region != "check"
            and single[f.site_id]["classification"] == "covered"
            and single[f.site_id]["wrong_output_possible"]]
    chk = [f for f in space if prog.instrs[f.site].region == "check"]

    pair_cls = Counter()
    per_checker = {}
    worst_bound = {}
    mismatches = 0
    search_diffs = 0
    crosschecked = 0
    for c in chk:
        tally = Counter()
        verdicts = {}
        for d in data:
            st = run2(prog, [d, c])
            outs = [st.get(o, zero).reduce() for o in prog.outputs]
            g = st.get(prog.disc, zero).reduce()
            cert = classify_observation(prog, ref, d, outs, g, rng)
            cls = cert["classification"]
            if cls == "covered" and not cert["wrong_output_possible"]:
                cls = "covered-no-wrong"
            verdicts[d.site_id] = cls
            tally[cls] += 1
            pair_cls[cls] += 1
            if cls == "bypass" and g.is_zero():
                # undetected on EVERY state and challenge, not just a special state
                pair_cls["bypass-identically-undetected"] += 1
                tally["identical"] += 1
            if cls == "covered":
                inc = cert["degree_bound"] - single[d.site_id]["degree_bound"]
                worst_bound[c.site_id] = max(worst_bound.get(c.site_id, 0), inc)
        per_checker[c.site_id] = dict(tally)
        if c.kind in ("skip", "zero"):
            pc = mutate(prog, c)
            sres = {x["site_id"]: x for x in structural.generate(pc).faults}
            for d in data:
                x = sres[d.site_id]
                cls = x["classification"]
                if cls == "covered" and not x["wrong_output_possible"]:
                    cls = "covered-no-wrong"
                crosschecked += 1
                a, b = cls, verdicts[d.site_id]
                if a != b:
                    # bypass vs unknown only reflects the incomplete randomised
                    # bypass search; anything else is a real disagreement
                    if {a, b} == {"bypass", "unknown"}:
                        search_diffs += 1
                    else:
                        mismatches += 1

    def single_label(sid):
        s = single[sid]
        if s["classification"] == "covered" and not s["wrong_output_possible"]:
            return "covered-no-wrong"
        return s["classification"]

    total_disable = [sid for sid, t in per_checker.items() if t.get("bypass", 0) == len(data)]
    some_bypass = [sid for sid, t in per_checker.items() if t.get("bypass", 0) > 0]
    some_unknown = [sid for sid, t in per_checker.items() if t.get("unknown", 0) > 0]
    harmless = [sid for sid, t in per_checker.items()
                if t.get("covered", 0) == len(data) and worst_bound.get(sid, 0) <= 0]
    weaker = [sid for sid, t in per_checker.items()
              if t.get("bypass", 0) == 0 and t.get("unknown", 0) == 0
              and worst_bound.get(sid, 0) > 0]
    return {
        "program": label, "name": prog.name, "sha256": prog.sha256(),
        "data_faults": len(data), "checker_faults": len(chk), "pairs": len(data) * len(chk),
        "pair_verdicts": dict(pair_cls),
        "checker_faults_single_fault_labels": dict(Counter(single_label(c.site_id) for c in chk)),
        "checker_faults_disabling_all_data_faults": len(total_disable),
        "checker_faults_enabling_some_bypass": len(some_bypass),
        "checker_faults_causing_some_unknown": len(some_unknown),
        "checker_faults_only_weakening_bounds": len(weaker),
        "checker_faults_harmless_for_every_data_fault": len(harmless),
        "single_labels_of_bypass_enabling_checker_faults":
            dict(Counter(single_label(s) for s in some_bypass)),
        "max_bound_increase": max(worst_bound.values(), default=0),
        "examples_total_disable": [
            {"site": s, "instr": prog.instrs[int(s.split("@")[1].split(".")[0])].to_json()[:4]}
            for s in total_disable[:6]],
        "structural_crosscheck_pairs": crosschecked,
        "structural_crosscheck_mismatches": mismatches,
        "structural_crosscheck_bypass_vs_unknown": search_diffs,
        "checker_faults_generic_disable": len([s for s, t in per_checker.items()
                                               if t.get("identical", 0) == len(data)]),
        "seconds": time.perf_counter() - t0,
    }


def main():
    rows = [study(l, b) for l, b in PROGRAMS]
    (ROOT / "data" / "two_fault_study.json").write_text(json.dumps(rows, indent=1) + "\n")
    md = ["# Two-fault study: one data fault + one checker fault (generated by tools/two_fault_study.py)", "",
          "Data faults: every single fault outside the check region that the single-fault analysis "
          "certified 'covered, can corrupt the output'. Checker faults: every single fault in the "
          "check region. Verdicts by double-fault symbolic execution + the unchanged baseline classifier. GF(256).",
          "", "## Pair verdicts", "",
          "| program | data faults | checker faults | pairs | still covered | covered, output not corrupted | bypass (some state) | of which undetected on every state | unknown |",
          "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        v = r["pair_verdicts"]
        md.append(f"| {r['program']} | {r['data_faults']} | {r['checker_faults']} | {r['pairs']} | "
                  f"{v.get('covered', 0)} | {v.get('covered-no-wrong', 0) + v.get('benign', 0)} | "
                  f"{v.get('bypass', 0)} | {v.get('bypass-identically-undetected', 0)} | {v.get('unknown', 0)} |")
    md += ["", "'bypass (some state)' means a state exists on which the output is wrong and the "
           "discrepancy is 0 for all challenges; for most pairs that state is special (the two "
           "error terms cancel) and its density among all states was not measured. 'Undetected on "
           "every state' means the faulted discrepancy is the zero polynomial.",
           "", "## What the single-fault labels of checker faults conceal", "",
           "| program | checker faults | single-fault labels | disable detection of EVERY data fault | enable a bypass for at least one data fault | only weaken a bound | cause unknown | harmless for every data fault | max bound increase |",
           "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['program']} | {r['checker_faults']} | {r['checker_faults_single_fault_labels']} | "
                  f"{r['checker_faults_disabling_all_data_faults']} | {r['checker_faults_enabling_some_bypass']} | "
                  f"{r['checker_faults_only_weakening_bounds']} | {r['checker_faults_causing_some_unknown']} | "
                  f"{r['checker_faults_harmless_for_every_data_fault']} | {r['max_bound_increase']} |")
    md += ["", "## Structural cross-check (skip/zero checker faults via the mutated program)", "",
           "| program | pairs cross-checked | covered-vs-not-covered disagreements | bypass-vs-unknown differences (incomplete randomised search) | seconds (whole study) |", "|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['program']} | {r['structural_crosscheck_pairs']} | "
                  f"{r['structural_crosscheck_mismatches']} | {r['structural_crosscheck_bypass_vs_unknown']} | {r['seconds']:.1f} |")
    md += ["", "## Examples of checker faults that disable detection completely", ""]
    for r in rows:
        md.append(f"- {r['program']}: " + "; ".join(f"`{e['site']}` on `{e['instr']}`"
                                                    for e in r["examples_total_disable"]))
    out = ROOT / "data" / "two_fault_study.md"
    out.write_text("\n".join(md) + "\n")
    print(out.read_text())


if __name__ == "__main__":
    main()

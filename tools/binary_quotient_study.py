#!/usr/bin/env python3
"""Compiler-aware quotient versus fault-by-fault emulation, on the same
binaries, the same single-instruction-skip fault model, the same state and
challenges, and the same property (wrong output undetected).

  per-fault   every dynamic instruction skip x every challenge is emulated
              (tools/compiled_kernel_study.py machinery): the ground truth.
  quotient    cafq.binquot: one traced run per training input, a def-use /
              post-dominator analysis, injection validation of realisation
              points, then a predicted class for every skip, or 'outside
              coverage'.

Reported: coverage, UNSOUND predictions (prediction contradicted by ground
truth), what the complete bypasses were predicted as, emulation counts and
wall-clock for both. Writes data/binary_quotient_study.{json,md}.
"""
import hashlib
import json
import pathlib
import random
import sys
import time
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
import compiled_kernel_study as CK  # noqa: E402
from cafq import binquot  # noqa: E402
from cafq.kernels import karatsuba2_memory_model  # noqa: E402

BUILDS = [("gcc-O2", "gcc", "-O2"), ("clang-O2", "clang", "-O2"), ("gcc-O0", "gcc", "-O0")]
STATE = CK.STATE
INPUTS = ["A0", "A1", "B0", "B1"]
CHALLENGES = list(range(256))


def training_inputs():
    rng = random.Random(20261116)
    out = [(STATE, 0)]
    for _ in range(7):
        out.append((tuple(rng.randrange(1, 256) for _ in range(4)), rng.randrange(1, 256)))
    return out


def ground_truth(elf, entry):
    t0 = time.perf_counter()
    M = CK.Machine(elf, entry)
    pcs, _ = M.trace(STATE, 0)
    n = len(pcs)
    per = [(Counter(), set(), set()) for _ in range(n)]
    for r in CHALLENGES:
        exp = CK.expected(STATE, r)
        for k, (st, out) in enumerate(M.all_skips(STATE, r, pcs, 0)):
            status, wrong_r, U = per[k]
            status[st] += 1
            if st == "ok" and out[:3] != exp:
                wrong_r.add(r)
                if out[3] == 0:
                    U.add(r)
    return per, n * len(CHALLENGES), time.perf_counter() - t0


def study(label, cc, opt):
    elf, ver, flags, entry, _dis = CK.build(label, cc, opt)
    prog = karatsuba2_memory_model()
    truth, gt_runs, gt_s = ground_truth(elf, entry)
    res = binquot.analyse(elf.read_bytes(), entry, prog, INPUTS, STATE, training_inputs(),
                          CHALLENGES)
    n_ch = len(CHALLENGES)
    tally, unsound, bypass_as, outside_reasons = Counter(), [], Counter(), Counter()
    covered_wrong = 0
    for p, (status, wrong_r, U) in zip(res.predictions, truth):
        ok = binquot.consistent(p, status, wrong_r, U, n_ch)
        tally[p["class"]] += 1
        if p["class"] == "outside":
            outside_reasons[p["reason"]] += 1
        if ok is False:
            unsound.append({"k": p["k"], "asm": p["asm"], "predicted": p["class"],
                            "site": p["site"], "roots": p.get("roots"),
                            "status": dict(status), "wrong": len(wrong_r),
                            "undetected": len(U)})
        if status["ok"] == n_ch and len(wrong_r) == n_ch and len(U) == n_ch:
            bypass_as[p["class"]] += 1
        if p["class"] != "outside" and wrong_r:
            covered_wrong += 1
    n = len(res.predictions)
    realised_sites = sorted(set(res.realised.values()))
    return {
        "label": label, "compiler": ver, "flags": flags,
        "elf_sha256": hashlib.sha256(elf.read_bytes()).hexdigest(),
        "ir_program": prog.name, "ir_sha256": prog.sha256(), "ir_sites": len(prog.instrs),
        "dynamic_instructions": n, "challenges": n_ch, "state": list(STATE),
        "predicted": dict(tally),
        "coverage": 1 - tally["outside"] / n,
        "outside_reasons": dict(outside_reasons),
        "unsound_predictions": unsound,
        "ground_truth_bypasses_predicted_as": dict(bypass_as),
        "covered_skips_that_corrupt_output": covered_wrong,
        "validated_realisation_points": len(res.realised),
        "ir_sites_realised": realised_sites,
        "ir_sites_not_realised": [i for i in range(len(prog.instrs)) if i not in realised_sites],
        "quotient": {"traced_runs": res.stats["traced_runs"],
                     "candidate_points": res.stats.get("candidate_points", 0),
                     "rejected_upper_bits_live": res.stats.get("rejected_upper_bits_live", 0),
                     "rejected_no_matching_site": res.stats.get("rejected_no_matching_site", 0),
                     "emulated_suffix_runs": res.stats.get("injection_runs", 0),
                     "seconds": res.stats["seconds"]},
        "per_fault": {"emulated_suffix_runs": gt_runs, "seconds": gt_s},
    }


def main():
    only = sys.argv[1:]
    rows = [study(*b) for b in BUILDS if not only or b[0] in only]
    if only:
        for r in rows:
            print(json.dumps({k: v for k, v in r.items() if k not in ("flags",)}, indent=1)[:3500])
        return
    (ROOT / "data" / "binary_quotient_study.json").write_text(json.dumps(rows, indent=1) + "\n")
    md = ["# Compiler-aware quotient vs per-fault emulation (generated by tools/binary_quotient_study.py)", "",
          "Kernel `src/compiled/kernel.c`; IR model `polymul_karatsuba2_memory_model` (with explicit "
          "loads and stores). x86-64, emulated. Fault model: one dynamic instruction skipped. "
          f"State {tuple(hex(v) for v in STATE)}, all 256 challenges. Ground truth = every skip x every "
          "challenge emulated. A prediction is UNSOUND if the ground truth contradicts it.", "",
          "## Coverage and soundness", "",
          "| build | dynamic instrs | assigned to an IR site: template | IR site: checker-blind | cannot corrupt output | no effect | outside coverage | coverage | UNSOUND predictions |",
          "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        p = r["predicted"]
        md.append(f"| {r['label']} | {r['dynamic_instructions']} | {p.get('template', 0)} | "
                  f"{p.get('unobserved', 0)} | {p.get('no-wrong-output', 0)} | {p.get('no-effect', 0)} | "
                  f"{p.get('outside', 0)} | {100 * r['coverage']:.1f}% | {len(r['unsound_predictions'])} |")
    md += ["", "## What the complete bypasses (wrong and undetected for all 256 challenges) were predicted as", "",
           "| build | ground-truth bypasses | predicted checker-blind (correct) | outside coverage (not claimed) | predicted safe (UNSOUND) |",
           "|---|---|---|---|---|"]
    for r in rows:
        b = r["ground_truth_bypasses_predicted_as"]
        total = sum(b.values())
        bad = total - b.get("unobserved", 0) - b.get("outside", 0)
        md.append(f"| {r['label']} | {total} | {b.get('unobserved', 0)} | {b.get('outside', 0)} | {bad} |")
    md += ["", "## Cost on the same machine", "",
           "| build | per-fault: suffix emulations | per-fault s | quotient: traced runs | realisation points validated / candidates | quotient: suffix emulations | quotient s | emulation ratio | time ratio |",
           "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        q, f = r["quotient"], r["per_fault"]
        md.append(f"| {r['label']} | {f['emulated_suffix_runs']} | {f['seconds']:.1f} | {q['traced_runs']} | "
                  f"{r['validated_realisation_points']} / {q['candidate_points']} | {q['emulated_suffix_runs']} | "
                  f"{q['seconds']:.1f} | {f['emulated_suffix_runs'] / max(q['emulated_suffix_runs'], 1):.1f}x | "
                  f"{f['seconds'] / q['seconds']:.1f}x |")
    md += ["", "## Why skips fall outside coverage", ""]
    for r in rows:
        md.append(f"- **{r['label']}**: " + "; ".join(f"{v} × {k}" for k, v in
                                                      sorted(r["outside_reasons"].items(), key=lambda kv: -kv[1])))
    md += ["", "## IR sites with no validated realisation point in the binary", ""]
    for r in rows:
        md.append(f"- **{r['label']}**: {len(r['ir_sites_not_realised'])} of {r['ir_sites']} "
                  f"(sites {r['ir_sites_not_realised']})")
    if any(r["unsound_predictions"] for r in rows):
        md += ["", "## UNSOUND predictions", ""]
        for r in rows:
            for u in r["unsound_predictions"][:20]:
                md.append(f"- {r['label']} k={u['k']} `{u['asm']}` predicted {u['predicted']} "
                          f"(site {u['site']}, roots {u['roots']}): wrong for {u['wrong']}, "
                          f"undetected for {u['undetected']}, status {u['status']}")
    out = ROOT / "data" / "binary_quotient_study.md"
    out.write_text("\n".join(md) + "\n")
    print(out.read_text())


if __name__ == "__main__":
    main()

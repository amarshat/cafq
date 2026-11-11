# CAFQ — Algebraic Rejection under test and Certified Algebraic Fault Quotients

**Research-only. Private. Nothing here is a proven cryptographic construction,
a standards-conformant KEM, or production code.**

Two tracks, from the work package of 10 Nov 2026:

1. **Algebraic Rejection (H-AR)** — a comparison-free decapsulation rule that
   feeds a polynomial discrepancy into the KDF. Treated as a hypothesis to
   falsify. **Result: refuted as specified** (see `reports/phase1_toy_findings.md`).
2. **CAFQ** — a certifying algorithm that classifies every single fault in a
   small arithmetic IR as benign / covered / bypass / unknown, attaches a
   checkable algebraic witness, and groups covered faults into classes that
   provably share a detection bound. The first prototype analysed every fault
   separately (`reports/phase2_cafq_results.md`). The **structural quotient**
   derives the same verdicts from one forward and one reverse pass.

**Current decision (11 Nov 2026): PIVOT.** See `NOVELTY_AND_GO_NO_GO.md`.
The structural quotient is sound and cuts total verification work by one to
two orders of magnitude on fault-linear kernels, but its mathematical core is
classical and its guarantees do not survive a second fault or compilation.

## Where to start

| Document | Content |
|---|---|
| `NOVELTY_AND_GO_NO_GO.md` | Decision, evidence, what is and is not original |
| `STRUCTURAL_QUOTIENT_THEORY.md` | Definitions, algorithm, theorems S1–S5 with proofs, counterexamples C1–C4, complexity |
| `PRIOR_ART_COLLISION_REPORT.md` | What CLEAVE, FIRMER, FIVER, classical collapsing and BEC compute; what could not be read |
| `reports/` | Phase 0–2 reports (Algebraic Rejection refuted; first CAFQ prototype) |

## Layout

| Path | Content |
|---|---|
| `research/` | Novelty matrix, threat model, counterexamples, proof obligations, decision log |
| `specs/` | Field and discrepancy, CAFQ semantics, certificate format, KEM games |
| `src/toy/` | GF(2^8), discrepancy, toy FO / H-AR / DFAR KEM, fault hooks, attacks |
| `src/cafq/analyzer.py`, `checker.py`, `baselines.py` | **Baseline**: per-fault symbolic analysis, post-hoc quotient, trusted checker, prefix-cached variant |
| `src/cafq/structural.py`, `structural_checker.py` | **Structural quotient**: adjoint-based generator (untrusted) and its checker (trusted) |
| `src/cafq/circuits.py`, `kernels.py` | Test circuits; cyclic multiplication kernel; memory model of the compiled kernel |
| `src/compiled/kernel.c` | The C kernel used in the instruction-skip study |
| `tests/` | Exhaustive field/challenge checks, attacks, brute-force soundness, certificate tampering for both checkers |
| `tools/` | Report, manifest, benchmark, two-fault and compiled-kernel generators |
| `data/` | Generated tables, certificates, binaries with disassembly, test transcripts |

## Reproduce

```
pip install pytest==9.2.0 unicorn==2.1.4      # Python 3.13.18 was used
python -m pytest                              # about 75 s
python tools/run_structural_benchmarks.py     # A / A' / B / C comparison, about 8 min
python tools/two_fault_study.py               # about 70 s
python tools/compiled_kernel_study.py         # needs gcc 13.3.0, clang 18.1.3, objdump, nm
python tools/phase1_report.py; python tools/run_benchmarks.py   # Phase 1/2 tables
```

Each generated file in `data/` records the source revision, CPU and Python
version it was produced with. Timings differ between machines; counts do not.

## Claims discipline

"Exhaustive" always names the exact domain. "Proved" is used only for the
short theorems in `specs/cafq_semantics.md` and `STRUCTURAL_QUOTIENT_THEORY.md`, whose proofs are written out and
whose instances are brute-force checked; they are not machine-checked.
Everything else is "observed", "hypothesised", "refuted" or "blocked".

# Decision log

## 2026-11-11 — Session 1 (Phases 0, 1, first bounded part of 2)

| # | Decision | Reason |
|---|---|---|
| 1 | Created a dedicated network environment allowing zenodo.org, eprint.iacr.org, csrc.nist.gov, nvlpubs.nist.gov, doi.org, link.springer.com | Phase 0 requires the sources; default environment blocked them |
| 2 | DFAR package inspected outside the repository; nothing copied in | Licence is CC-BY-4.0, but the mandate is to avoid large copied code; provenance kept by hash |
| 3 | DFAR verification suite **not run** | Executing downloaded third-party code was refused by the session's permission policy. Recorded as a blocker, not worked around |
| 4 | **Gate 0:** H-AR is *not* materially identical to DFAR (polynomial-in-KDF vs two cancelling PRF calls), but DFAR has priority on decision-free rejection. H-AR becomes a baseline under test. CAFQ is the primary track | novelty matrix A1 |
| 5 | Toy PKE = 3-dimensional LWE-like scheme mod 251, 8-bit messages, 11-element ciphertext | Smallest object with decryption slack, which is what the attack needs. The 3–6 element range of the work package is used for the standalone discrepancy tests |
| 6 | **Gate 1:** H-AR with exponents from 0 marked **refuted** (CE-2). Shifted variant marked **unproved** | Coordinate-0 PCO and secret-row recovery in the toy, no fault |
| 7 | CAFQ bad event defined on a *wrongness vector* that covers both fault-induced output error and input inconsistency | One definition for fingerprint-checked computations and for the AR consistency check |
| 8 | All polynomials reduced mod `X^q = X` | Makes formal equality coincide with functional equality, so exhaustive tests over GF(4) are meaningful |
| 9 | Checker re-derives polynomials itself instead of trusting the analyzer's | Otherwise the trusted base would include the analyzer's symbolic engine |
| 10 | Added quotient level L3 (`g = u(x)·R^k·h`) beyond the constant-scaling case of the work package | Its preservation theorem is two lines (Theorem 2) and it is where most of the reduction comes from |
| 11 | "Covered, no wrong output" kept as its own bucket and excluded from the headline reduction | Merging false-alarm faults would inflate the comparison against exact collapsing |
| 12 | One test expectation corrected during development: the nonlinear masked checker over GF(256) was first expected to be `unknown`, but random search found a bypass state; the circuit was strengthened (two masks) so that `unknown` is actually exercised | No soundness issue; recorded for transparency |
| 13 | **Gate 2:** passed on toy-ir-v1 with a narrowed originality claim; cost-reduction hypothesis H-C-6 contradicted at this scale | `reports/phase2_cafq_results.md` |
| 14 | Stopped before Phase 3 | Work-package execution boundary; go/no-go in `reports/final_research_assessment.md` |

## 2026-11-11 — Session 2 (structural quotient directive)

| # | Decision | Reason |
|---|---|---|
| 15 | Algebraic Rejection closed for good; counterexamples kept; DFAR stays as prior art | Directive §1 |
| 16 | Baseline preserved: `analyze_fault` split into execution + `classify_observation`, certificates verified byte-identical before/after (SHA-256 over 10 programs) | Needed so other front ends can reuse the same classifier without touching its behaviour |
| 17 | Structural method built on reverse-mode adjoints with formal tags, in separate modules (`structural.py`, `structural_checker.py`) | One pass yields `∂disc/∂v_i` and `∂out_j/∂v_i` for all sites |
| 18 | Fault-linearity decided by a bit-set taint pass; first-order templates refused elsewhere | Counterexamples `square_check` (derivative 0 in characteristic 2, effect `δ²R`) and `nonlinear_trap` (effect `δ(δ+x₁)`) |
| 19 | Added a prefix-cached per-fault baseline (A′) | Comparing only against full re-execution would be a weakened comparator |
| 20 | After the tautological-check kernel showed almost no gain (7.3 s vs 8.5 s), added the unobserved-site rule (`Jd = 0`) with algebraic bypass certificates | The cost was in per-fault bypass search and concrete replay; the structure makes both unnecessary. Recorded because the first measurement was a failure |
| 21 | Class keys are derived by the structural checker, never read from certificates | Removes the "unsound merge" attack surface instead of testing for it |
| 22 | Two-fault cross-check first reported 16–42 "mismatches"; all were bypass-vs-unknown from the incomplete randomised search, none covered-vs-not. Tool now separates the two | Avoids both hiding and overstating a discrepancy |
| 23 | Compiled-kernel emulation: code segments mapped read-only after a skip caused a wild write into code and desynchronised the replay | Found by an internal consistency assertion |
| 24 | Quadratic duplicate detection replaced by a linear one in **both** checkers | It would otherwise have inflated checker time at 22k faults; applied to the baseline too so the comparison is not skewed |
| 25 | Decision recorded in `NOVELTY_AND_GO_NO_GO.md` | Directive §8 |

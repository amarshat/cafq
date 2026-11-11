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

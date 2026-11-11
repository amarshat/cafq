# Phase 2 report — earliest CAFQ feasibility result

Date: 2026-11-11. Evidence: `tests/test_cafq_soundness.py`,
`tests/test_certificate_checker.py`, `data/phase2_benchmarks.md`,
`data/certificates/`. Semantics and proofs: `specs/cafq_semantics.md`.

## What was built

* **toy-ir-v1**: straight-line GF(2^m) programs (`const`, `mov`, `add`,
  `mul`), mutable registers, three fault kinds with exact semantics (skip,
  result-zero, single-bit flip) on every instruction.
* **Analyzer** (untrusted): symbolic propagation per fault, classification,
  witness search, factorisation `g = u(x)·R^k·h(x, R)`, classes at four
  levels.
* **Checker** (trusted, standard library only, shares no code with the
  analyzer): re-derives all polynomials and verifies every claim, the
  manifest, and the soundness of every class.
* **Circuits**: AR discrepancy; schoolbook and 2×2 Karatsuba multipliers with
  an evaluation fingerprint; a 4-point butterfly network with a
  Freivalds-style check (the non-KEM family). The checks themselves are known
  techniques.

## Theorems (written proofs, brute-force-checked instances, not machine-checked)

1. **Per-fault bound.** With a linear or unit witness, a wrong state has at
   most `deg_R g` undetected challenges.
2. **Unit-content quotient.** If `g = u(x)·R^k·h`, the undetected set on every
   wrong state is exactly `roots(h(x,·)) ∪ ({0} if k > 0)`. Faults sharing
   `(k, h)` have identical undetected sets although their outputs differ.
3. **Exact classes.** If `h` has constant coefficients, the conditional
   probability of non-detection is exactly `|Z|/q` for the whole class.

## Soundness evidence

| Check | Domain | Result |
|---|---|---|
| Bound, set equality, benign equality, bypass witnesses vs brute force | Every state × every challenge × every fault, 10 programs over GF(4)/GF(8) | 0 violations |
| No fully-bypassing fault labelled benign/covered | same | 0 violations |
| Exact classes attain their bound | 3 programs over GF(4) | attained |
| GF(256) | 4 or 12 random states (fixed seed) × all 256 challenges × every fault, 4 programs — **sampled in the state** | 0 violations |
| Certificate tampering (20 test functions) | classification, polynomial, witness, factorisation, bound, root set, class keys at each level, manifest, program | all rejected |
| Unsound merges accepted by the checker | all levels | 0 |

## Classification (GF(256); every in-scope fault counted once)

| Program | Faults | Benign | Covered | of which can corrupt output | Bypass | Unknown |
|---|---|---|---|---|---|---|
| AR discrepancy n=4 | 120 | 0 | 0 | 0 | **120** | 0 |
| AR discrepancy n=6 | 180 | 0 | 0 | 0 | **180** | 0 |
| AR discrepancy n=6, exponents from 1 | 190 | 0 | 17 | 17 | 173 | 0 |
| Schoolbook n=2 | 210 | 2 | 208 | 80 | 0 | 0 |
| Schoolbook n=4 | 610 | 2 | 608 | 320 | 0 | 0 |
| Schoolbook n=6 | 1170 | 2 | 1168 | 720 | 0 | 0 |
| Karatsuba 2×2 | 220 | 2 | 218 | 90 | 0 | 0 |
| Butterfly 4 | 550 | 4 | 546 | 150 | 0 | 0 |

"Covered" faults that cannot corrupt the output are checker-region faults:
no wrong result exists, but the detection status may change (false alarm).
`unknown` is 0 on these programs and non-zero on the adversarial
`masked_check` circuit over GF(256), as intended.

## Reduction against exact fault collapsing

Same programs, same fault model. Only covered faults that can corrupt the
output are counted, so false-alarm faults do not inflate the comparison.

| Program | Faults | L1 exact effect (baseline) | L2 constant scaling | L3 unit content | L4 + zero-root merge | Σ naive degree | Σ certified bound |
|---|---|---|---|---|---|---|---|
| Schoolbook n=2 | 80 | 31 | 10 | 3 | 2 | 80 | 60 |
| Schoolbook n=4 | 320 | 96 | 47 | 7 | 2 | 960 | 300 |
| Schoolbook n=6 | 720 | 184 | 107 | 11 | 2 | 3600 | 700 |
| Karatsuba 2×2 | 90 | 64 | 15 | 5 | 4 | 100 | 90 |
| Butterfly 4 | 150 | 94 | 23 | 8 | 7 | 370 | 260 |
| AR n=6, exponents from 1 | 17 | 9 | 9 | 9 | 9 | 101 | 101 |

Two measured effects:

* **Fewer classes.** L3 has 10–17× fewer classes than exact collapsing on the
  multipliers and butterfly network; L4 more. No reduction on the AR circuit.
* **Tighter bounds.** The root-bound numerators summed over faults drop from
  3600 to 700 for schoolbook n=6, because `g = u(x)·R^k` has one root, not
  `k`. For classes with constant `h` the bound is an equality.

Examples of class shapes found (butterfly, GF(256)): `h = 1` (always
detected, or only `r = 0` missed); `h = 1 + R` (missed at `r = 1`);
`h = 1 + 247R + 247R² + R³` (missed at three specific challenges);
and one class with state-dependent `h` (degree bound 3 only).

## Cost (wall-clock, this machine; includes everything)

| Program | Analyzer s | Checker s | Certificates (bytes) | Root sets per fault → per L4 class |
|---|---|---|---|---|
| Schoolbook n=4 | 0.219 | 0.122 | 757,935 | 320 → 2 |
| Schoolbook n=6 | 1.045 | 0.567 | 1,729,771 | 720 → 2 |
| Karatsuba 2×2 | 0.036 | 0.019 | 240,214 | 90 → 4 |
| Butterfly 4 | 0.173 | 0.097 | 673,141 | 140 → 6 |

**There is no free speedup, and at this scale no speedup at all.** Both
analyzer and checker symbolically execute every fault; classes save only the
root enumeration, which is milliseconds over GF(256). The quotient's value
here is the *shape* of the result (few classes, exact probabilities,
explicit bypasses), not time.

## Unproved and uncovered

* Proofs are not machine-checked; checker correctness is tested, not proved.
* Single fault only. Checker faults are "covered" only because no data fault
  accompanies them.
* Ineffective-fault leakage is flagged per certificate and not bounded.
* The witness search is incomplete; failures become `unknown`.
* L3 uses a partial content computation (one coefficient dividing the
  others); a full multivariate GCD could merge more. Soundness unaffected.
* Nothing is at ISA level. No compiler, no binary.
* Novelty against CLEAVE / FIVER / FIRMER / ABFT literature is unassessed.

## Gate 2

| Criterion | Result |
|---|---|
| Zero unsound merges on exhaustive small examples | **Met** |
| All declared sites covered by the manifest, including bypass/unknown | **Met** (checker-enforced) |
| Nontrivial reduction over ordinary exact collapsing on a meaningful circuit | **Met** for class count and bound tightness; **not met** for verification time |

**Decision: proceed, with the originality claim narrowed** to the certified
unit-content quotient and exact class probabilities, and with the explicit
caveat that the underlying mathematics is classical.

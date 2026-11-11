# Phase 0 report — prior art and the DFAR collision

Date: 2026-11-11. Detail: `research/novelty_matrix.md`.

## What was accessed

| Source | Access | Identifier |
|---|---|---|
| DFAR replication package (Zenodo 23511350) | Downloaded; metadata, supplement source, reference kernel and audit notes read | md5 `bcbdf663…04c0` (matches Zenodo), sha256 `dfe67dce…5d5d`, 139 files, licence CC-BY-4.0 (Go sources under the Go licence) |
| FIPS 203 | Algorithm 18 and surrounding text read | PDF sha256 `fe1f12f3…6cac` |
| ePrint 2025/450, 2026/2069, 2026/2239 | Abstracts only | — |
| CLEAVE (FM 2024) | **Not accessed** (redirect to a host outside the allowlist) | — |
| Giorgi–Grenet–Perret du Cray (JSC 2023) | **Not accessed** | — |
| FIVER, FIRMER, StaMAC, ABFT literature | **Not accessed** | — |

## Blockers

1. **DFAR verification suite not executed.** Running downloaded third-party
   code was refused by this session's permission policy. DFAR claims are
   therefore "read", not "reproduced". To lift: allow execution of
   `python3 run_verification_suite.py` from the extracted package, or run it
   yourself and share the output.
2. **DFAR main manuscript not in the package.** Assumptions A1–A5 are known
   only through the supplement's one-sentence summary.
3. **Formal-methods prior art not accessible.** CAFQ's novelty against
   CLEAVE/FIVER/FIRMER cannot be assessed yet.

## Exact collision with DFAR

DFAR decapsulation (supplement, first equation; `reference_dfar_kernel.c`):

    K = K̂(c) ⊕ F_k(E(c, c̄)) ⊕ F_k(E(c, c))

H-AR (work package §2):

    K = KDF(domain, m', c, Σ (c_i − c'_i) ρ^i),   ρ = PRF(z, c)

| | DFAR | H-AR |
|---|---|---|
| Goal | no accept bit, no select | same |
| Cancels on consistent ciphertext | yes (identical PRF inputs) | yes (`D = 0`) |
| Object carrying the inconsistency | the pair `(c, c̄)` as a PRF input | one field element `D` as a KDF input |
| Rejection key for *every* inconsistent `c` | fresh pseudorandom (their exact-equivalence theorem) | **not** in general: predictable when `D` is (CE-1, CE-2) |
| Assumption | PRF; injective pair encoding | PRF, ROM for KDF, large field, non-constant difference polynomial |
| Published proof | supplement §S1 (classical ROM; not machine-checked) | none |
| "Algebraic" content | none in the mechanism (the name refers to XOR cancellation; the proof uses graph linear algebra) | polynomial evaluation over GF(q) |

**Verdict.** The two are not the same construction. They share the idea and
the goal, on which DFAR has priority; "we invented algebraic rejection"
cannot be claimed. H-AR is a different and, as specified, weaker instance.

## Was a flaw found in DFAR's argument?

No. The supplement's chain (cancellation on consistent inputs; disjoint
address pairs per received ciphertext; forest ⇒ independent uniform masks;
PRF hop) was read and no gap was found *at that level of reading*. It was
not machine-checked and the main manuscript was not available. The authors'
own stated limits are material and are reproduced in the toy:

* truncating the distinguishing input, or omitting the final XOR, exposes the
  raw candidate (their table: 200/200; toy: `PREDICTABLE:raw-candidate`);
* outputs under "normal", "omit first" and "omit second" XOR to the raw
  candidate (`test_dfar_combined_fault_identity`);
* on a *valid* ciphertext, omitting one evaluation returns a wrong key — an
  effective-fault observable (toy matrix, `wrong-key`).

## Other findings relevant to scope

* **FIPS 203**: on `c ≠ c′` Algorithm 18 returns `K̄ = J(z‖c)`. H-AR and
  DFAR both differ from this; neither is ML-KEM.
* **ePrint 2026/2069** (abstract): the Booleanisation stage is a single
  point of failure upstream of cmov. Supports the *motivation* for
  flag-free rejection.
* **ePrint 2026/2239** (abstract): one unverified coordinate suffices for
  ML-KEM key recovery. This is the mechanism by which H-AR's coordinate 0
  fails with no fault at all.
* **ePrint 2025/450** (abstract): binds re-encryption to correctness for
  detecting *omitted* verification; stated scope is implementation errors,
  not active faults.

## Gate 0 decision

AR is **not** our invention and is **not** identical to DFAR. It proceeds
only as a baseline under test. CAFQ is the primary invention search.

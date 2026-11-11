# Proof obligations

## Discharged (written proof + exhaustive instance checks; not machine-checked)

| ID | Statement | Proof | Instances |
|---|---|---|---|
| PO-F-1 | GF(2^8) with modulus 0x11B is a field | by exhaustive computation | `tests/test_field.py` |
| PO-D-1 | Consistent pair ⇒ `D = 0` for all ρ | linearity | `test_consistent_ciphertext_gives_zero_for_every_rho` |
| PO-D-2 | Preimage bound for non-constant difference polynomials | `specs/field_and_discrepancy.md` Lemma 2 | `test_preimage_bound_for_nonconstant_difference` |
| PO-C-1 | Per-fault bound | `specs/cafq_semantics.md` Theorem 1 | `test_exhaustive_soundness` |
| PO-C-2 | Unit-content quotient preserves the undetected set | Theorem 2 | same test, set equality |
| PO-C-3 | Exact conditional probability for constant `h` | Corollary 3 | `test_exact_classes_are_tight` |

## Open — H-AR (shifted variant only; exponent-0 variant is refuted)

To claim IND-CCA in the classical ROM for
`K = KDF(m', c, Σ d_i ρ^{i+1})`, `ρ = PRF(z, c)`, `F = GF(q)`:

| ID | Obligation | Status |
|---|---|---|
| PO-AR-1 | Replace `PRF(z, ·)` by a random function `ρ(·)`; loss `Adv^PRF`. Requires `z` independent of decryption, re-encryption and the candidate path | routine; not written |
| PO-AR-2 | For each inconsistent `c`, conditioned on the adversary's view *before it queries the KDF at the right point*, `D` has min-entropy ≥ `log2(q/N)` (Lemma 2: the polynomial is non-constant because exponents start at 1) | plausible; the conditioning must be made precise |
| PO-AR-3 | The adversary's view depends on `ρ(c)` only through KDF outputs at `(m', c, D)`; bound the probability that any of `q_H` random-oracle queries hits that point by `q_H · N / q` per ciphertext, and handle `q_D` ciphertexts adaptively | **the real work**; not done |
| PO-AR-4 | Conclude that rejection keys are independent uniform values indexed by `c`, i.e. ideal implicit rejection; then invoke an FO theorem for that interface | depends on PO-AR-3 |
| PO-AR-5 | Account for `ρ = 0` (universal root) and for repeated queries (same `c`, same key — consistent with ideal rejection) | `1/q` term; not written |
| PO-AR-6 | Parameter condition: `q ≥ 2^λ · N · q_H · q_D` (indicative) and `c` parsed into `GF(q)` elements injectively | not instantiated |

Expected shape if all hold:
`Adv^{IND-CCA}_{AR'} ≤ Adv^{IND-CCA}_{IR} + Adv^{PRF} + q_D (q_H N + 1)/q`.
**This is a conjecture, not a result.** Note that DFAR obtains
`Adv^{IND-CCA}_{IR} + Adv^{PRF}` with no field-size term, so even a completed
proof would not make the polynomial variant preferable for CCA security.

## Open — CAFQ

| ID | Obligation | Status |
|---|---|---|
| PO-C-4 | Machine-check Theorems 1–2 for toy-ir-v1 | not started (no prover in the environment) |
| PO-C-5 | Prove the checker's polynomial procedures correct (reduction mod `X^q − X`, multiplication, coefficient extraction) | tested against an independent implementation only |
| PO-C-6 | Completeness: characterise when a covered fault lacks a linear or unit witness | open; no such fault was met, but none was sought systematically |
| PO-C-7 | Multi-attempt bound under challenge reuse `ρ = PRF(z, c)` | open; the union bound of §5 does not apply |
| PO-C-8 | Two-fault model (data fault + checker fault) | open; expected to turn many "covered, no wrong output" checker faults into bypasses |
| PO-C-9 | Ineffective-fault leakage: bound what `[g_f ≠ 0]` reveals about the state | open; only flagged |
| PO-C-10 | Transfer to an ISA: site map IR ↔ instructions, register/memory aliasing, compiler-merged checker and data paths | not started |
| PO-C-11 | Full content computation (multivariate GCD) so that L3 is the coarsest sound unit-content partition | not implemented; affects reduction only, not soundness |

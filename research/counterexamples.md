# Counterexamples and negative findings

Each item names the executable evidence. "Toy" means the 3-dimensional
mod-251 PKE of `src/toy/kem.py`; its only relevant property is that small
ciphertext perturbations still decrypt, as in ML-KEM and HQC.

## CE-1. Root bound without entropy (mandatory falsifier)

`c − c' = (δ, 0, …, 0)` ⇒ `D_ρ = δ` for all ρ. Min-entropy 0; root
probability 0. Any argument of the form "Pr[D = 0] is small, therefore the
KDF input is unpredictable" is invalid.
*Evidence:* `tests/test_discrepancy.py::test_REGRESSION_constant_difference_has_zero_challenge_entropy`
(all δ ≠ 0, all ρ, N = 3..6);
`tests/test_cafq_soundness.py::test_REGRESSION_constant_term_is_not_challenge_protected`.

## CE-2. H-AR as specified gives a plaintext-checking oracle with no fault

Adversary: pick `m`, compute `c = Enc(pk, m)`, set `c̃ = c + t·e_0`, query
decapsulation, compare the answer with `KDF(m, c̃, c̃_0 ⊕ c_0)`.

If `Dec(sk, c̃) = m` then `c' = c`, the difference is supported on coordinate
0, `D = c̃_0 ⊕ c_0` regardless of ρ, and the prediction matches. Otherwise it
does not (except with hash-collision probability). One query = one PCO answer.

In the toy, binary search over `t` yields the exact decryption noise of
coordinate 0, a linear form in the secret; a few messages give a full-rank
system. Result with key seed `seed-1`: `S[0]` and `E[0]` recovered exactly in
**40 decapsulation queries** (`data/phase1_fault_matrix.md`); the same
succeeds for all three test keys.

The same queries against FO with implicit rejection and against the DFAR
re-implementation return keys that match no prediction.

*Evidence:* `tests/test_toy_kem.py::test_CE2_*`,
`::test_same_queries_reveal_nothing_against_fo_and_dfar`.

*Scope.* Demonstrated on the toy only. The mechanism is independent of the
field size and of the toy's weakness: it needs (a) one ciphertext coordinate
that multiplies `ρ^0`, and (b) a PKE whose decryption tolerates a
perturbation of that coordinate. The claim that this yields key recovery on
ML-KEM rests on ePrint 2026/2239 (abstract only; not reproduced here).

**Consequence: H-AR (exponents from 0) is refuted as an IND-CCA-preserving
transform for noise-tolerant PKEs.**

## CE-3. Small field: every coordinate, every shift

With `q = 256` the adversary tries all 256 values of `D`. This turns any
single-coordinate perturbation into a PCO for both `s = 0` and `s = 1`.
*Evidence:* `test_small_field_enumeration_defeats_every_polynomial_variant`.
This is an artefact of the toy field. It becomes a *requirement*: a
polynomial variant needs `q` so large that `q / (N · #KDF-queries)` is
cryptographically large.

## CE-4. Shifted variant: universal root and `ρ = 1`

With exponents from 1: (a) `ρ = 0` gives `D = 0` for every difference, so
with probability `1/q` per ciphertext the returned key is the predictable
`KDF(m', c, 0)`; (b) the coordinate-0 prediction `D = δ` is right exactly
when `ρ = 1`. *Evidence:* `test_shifted_variant_removes_the_constant_term`,
`test_shifted_ar_blocks_structural_attack_except_when_rho_is_one`.
Both are `1/q` events and vanish for large `q`; they are listed because they
must appear in any proof.

## CE-5. Repetition does not re-randomise

`ρ = PRF(z, c)`. A ciphertext repeated `Q` times is one trial. An
inconsistent ciphertext whose difference polynomial has a root at its own ρ
is accepted with `D = 0` on every repetition (found by search in the toy).
*Evidence:* `test_repeated_ciphertext_reuses_the_challenge`,
`test_inconsistent_ciphertext_at_a_root_is_accepted_every_time`.

## CE-6. Removing the comparison moves the fault surface

Single named faults, message-preserving inconsistent ciphertexts
(`data/phase1_fault_matrix.md`, frozen in `tests/test_fault_models.py`):

| Rule | Faults that make the returned key adversary-computable |
|---|---|
| FO | skip one compare chunk; force flag 0; skip select; checker reads `c` twice |
| H-AR (s = 0) | **none needed on coordinate 0**; skip one contribution; skip one power update; force `D` to 0; checker reads `c` twice; skip marshalling |
| H-AR (s = 1) | skip one contribution; force `D` to 0; checker reads `c` twice; skip marshalling |
| DFAR | checker reads `c` twice; omit final XOR. (Omitting one PRF evaluation does not expose the candidate, but the three outputs N, D1, D2 XOR to it — the authors' own observation) |

No rule eliminates the single-fault PCO. H-AR has at least as many such
faults as FO in this model.

## CE-7. Every single fault in the AR discrepancy circuit has a bypass state

CAFQ on `ar_discrepancy` (GF(256), exponents from 0): for `N ∈ {3, 4, 6}`,
**all** in-scope faults (120 for N = 4, 180 for N = 6) are classified
`bypass`, each with a checker-verified input for which the input is
inconsistent and the faulted discrepancy is 0 for all 256 challenges. Reason:
the adversary controls the input difference, so an additive fault `δR^k` is
cancelled by choosing the difference `δ e_k`, and a dropped or merged term
leaves a direction unverified. With exponents from 1 and `N = 6`, 173 of 190
are bypass. The 17 covered ones are the 16 bit flips on the final
multiplication or on the marshalling move, and the *skip* of the final
multiplication. That last one is instructive: skipping the extra `·R` turns
the shifted circuit back into the exponent-0 circuit. CAFQ correctly calls it
covered (the root bound still holds), yet it re-introduces CE-1/CE-2. A
detection certificate is not a statement about the KDF input.
*Evidence:* `test_ar_discrepancy_every_single_fault_has_a_bypass_state`,
`data/phase2_benchmarks.md`, `data/certificates/ar_discrepancy_n4_shift0.json`.

Reading: the fingerprint protects a *computation* against faults when the
state is honest-but-unknown; it does not protect a *consistency check of
adversarial input* against a fault the adversary also chooses.

## CE-8. A weak checker is never certified

Circuits whose discrepancy is multiplied by a state-dependent mask
(`tests/cafq_helpers.py::masked_check`) are classified bypass (linear mask,
or nonlinear mask over GF(4) where the state space is enumerated) or
**unknown** (nonlinear mask over GF(256), where the bypass set has density
`2^-16` and the search fails). They are never covered.
*Evidence:* `test_weak_checkers_are_never_certified_covered`.

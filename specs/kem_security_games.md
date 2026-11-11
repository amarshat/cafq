# KEM games and rules used in Phase 1

Model: classical random-oracle model, toy instantiation. No QROM statement
is made or implied.

## Rules compared

Let `m' = Dec(sk, c)`, `c' = Enc(pk, m'; G(m'))`.

| Rule | Returned key | Source |
|---|---|---|
| FO, implicit rejection | `K(m', c)` if `c = c'`, else `J(z, c)` | Shape of FIPS 203 Algorithm 18 (p. 34), where the candidate is `G(m'‖h)` and the rejection value is `J(z‖c)` |
| H-AR (work package) | `KDF(m', c, D_ρ(c, c'))`, `ρ = PRF(z, c)`, exponents from 0 | Work package §2 |
| H-AR shifted | same with exponents from 1 | This repository, studied only as a repair attempt |
| DFAR | `K̂(c) ⊕ F_z(E(c, c')) ⊕ F_z(E(c, c))` | Alsawalqah–Abadleh replication package, supplement eq. before §S1; `verification/reference_dfar_kernel.c::dfar_full` |

None of the last three matches FIPS 203 on inconsistent ciphertexts. They are
research profiles only.

## IND-CCA (standard)

Challenger runs `KeyGen`, `(c*, K_0) ← Encaps(pk)`, samples `K_1` uniform and
a bit `b`; the adversary gets `(pk, c*, K_b)` and a decapsulation oracle
refusing `c*`; it outputs `b'`. Advantage `|Pr[b' = b] − 1/2|`.

## Plaintext-checking oracle (PCO)

`PCO(m, c)` returns `[Dec(sk, c) = m]`. For LWE- and code-based PKEs a PCO on
perturbed ciphertexts reveals decryption-noise information and is a standard
route to key recovery. A KEM whose decapsulation oracle lets an adversary
*implement* a PCO is not IND-CCA secure whenever the underlying PKE is not
secure against PCO-assisted attacks.

## What Phase 1 tests

* **Honest correctness** of all three rules (all 256 toy messages, 3 keys).
* **PCO from decapsulation**: can the adversary predict the key returned for
  an inconsistent ciphertext it built from a known `m`? If yes for some
  class of perturbations, one decapsulation query answers one PCO query.
* **Fault variants** of the same question (`data/phase1_fault_matrix.md`).

## What Phase 1 does not test

IND-CCA of FO or DFAR (their published arguments are not re-proved here),
QROM security, multi-fault or adaptive fault oracles, timing.

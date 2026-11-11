# Security questions for H-AR — status after Phase 1

| # | Question (work package §2) | Status | Basis |
|---|---|---|---|
| Q1 | Honest decapsulation preserved? | **Demonstrated in the toy.** For a consistent ciphertext `D = 0` for every ρ, so the KEM is correct whenever the PKE decrypts correctly and re-encryption is deterministic (same condition as FO) | Fact 0; `test_honest_decapsulation_all_messages` |
| Q2 | IND-CCA in the ROM? | **Refuted as specified** (exponents from 0) for PKEs tolerating a perturbation of coordinate 0. **Unproved** for the shifted variant with a cryptographically large field | CE-2; `proof_obligations.md` |
| Q3 | Do rejection keys reveal recovered-message information? | **Yes.** The key for an inconsistent ciphertext is `KDF(m', c, D)`; whenever `D` is predictable the key confirms a guess of `m'` | CE-2, CE-3, CE-4 |
| Q3b | Does domain separation suffice? | **No.** The leak is not a domain collision; it is that `(m', c, D)` is fully known to the adversary | CE-2 |
| Q3c | Which invalid ciphertexts make `D` public? | (i) difference supported on coordinate 0 when exponents start at 0 — always; (ii) any difference when `q` is enumerable; (iii) any difference with probability about `deg/q` (a root, or `ρ ∈ {0, 1}` special cases) | Facts 1–4, CE-3, CE-4 |
| Q4 | Which instruction faults are eliminated, moved or created? | Eliminated: none of the PCO-producing single faults. Moved: flag/select faults become `force_D_zero`, `skip_marshal`. Created: `skip_contribution`, `skip_power_update` (per-coordinate unverified). Unchanged: common-mode checker input | CE-6 |
| Q4b | Can the discrepancy or its KDF input be forced to the honest constant? | **Yes**, by one result-zero or one skipped move | CE-6; `ar_discrepancy` marshal region all bypass (CE-7) |
| Q5 | Extra assumptions from a long-lived `z`? | `ρ = PRF(z, c)` is fixed per ciphertext: repeats are one trial; a root, once hit, is hit forever; PRF security under adaptive chosen `c` is required; any leak of `D` for a known difference polynomial constrains ρ(c) (for that `c` only) | CE-5 |
| Q6 | QROM? | **Not addressed.** No QROM claim | — |
| Q7 | Constant time? | **Not addressed.** Absence of a comparison is not evidence of constant-time behaviour | — |

## Unresolved distinctions

1. Whether a large-field shifted H-AR is IND-CCA in the ROM. A proof sketch
   exists (`proof_obligations.md`, PO-AR-1..5) but it would at best reproduce
   what DFAR gets from a PRF assumption with no field-size condition.
2. Whether the DFAR main manuscript's assumptions A1–A5 hold for the
   compressed variant in all parameter sets (main manuscript not available).
3. Whether CE-2 transfers quantitatively to ML-KEM byte layout (coordinate 0
   is the first byte of the compressed `u`); expected from ePrint 2026/2239,
   not tested.

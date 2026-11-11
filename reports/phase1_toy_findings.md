# Phase 1 report — toy model, counterexamples, proof obligations

Date: 2026-11-11. Evidence: `tests/test_field.py`, `test_discrepancy.py`,
`test_toy_kem.py`, `test_fault_models.py`; `data/phase1_fault_matrix.md`.
Detail: `research/counterexamples.md`, `research/proof_obligations.md`.

## Model

* GF(2^8), modulus 0x11B, two independent multipliers, exhaustively checked.
* Discrepancy `D_ρ = Σ (c_i − c'_i) ρ^{i+s}`, `s ∈ {0, 1}`, N = 3..6.
* Toy FO-style KEM (3-dimensional LWE-like PKE mod 251, 8-bit messages,
  11-element ciphertext; SHA-256 as toy oracle). Insecure by size; used only
  because decryption tolerates small perturbations.
* Three decapsulation rules: FO with implicit rejection, H-AR, and an
  independent re-implementation of DFAR.

## Results

| Claim | Status | Evidence |
|---|---|---|
| Honest ciphertexts decapsulate correctly under all three rules | **Demonstrated** (toy; 256 messages × 3 keys) | `test_honest_decapsulation_all_messages` |
| Constant difference ⇒ `D` independent of ρ, entropy 0 | **Demonstrated** (exhaustive) | CE-1 |
| Non-constant polynomial with roots is accepted on those ρ | **Demonstrated** | Fact 2 |
| "Root bound ⇒ entropy" | **Contradicted**; valid replacement is the preimage bound for *non-constant* polynomials | Lemma 2 |
| H-AR rejection keys are unpredictable | **Contradicted** for exponents from 0 | CE-2 |
| H-AR is IND-CCA for noise-tolerant PKEs | **Refuted as specified**: one decapsulation query answers a plaintext-checking query; 40 queries recover a secret-key row in the toy, with no fault | CE-2 |
| Same queries against FO and DFAR | No prediction matches | `test_same_queries_reveal_nothing_against_fo_and_dfar` |
| Shifted H-AR (`s = 1`) resists the structural attack | **Demonstrated** up to the `ρ = 1` event; `ρ = 0` is a universal root | CE-4 |
| Shifted H-AR is IND-CCA | **Unproved**; six obligations listed; conjectured bound has a `q_D q_H N / q` term that DFAR does not have | PO-AR-1..6 |
| Polynomial variants are safe over GF(256) | **Contradicted** (enumeration of `D`) — toy-size artefact that becomes a field-size requirement | CE-3 |
| Repeated queries re-randomise the check | **Contradicted**: ρ is a function of `c` | CE-5 |
| Removing the comparison removes the single-fault oracle | **Contradicted** in this model | CE-6 |

## Fault matrix (single named faults; inconsistent ciphertext that still decrypts to m)

| Rule | No fault | Faults giving an adversary-computable key |
|---|---|---|
| FO | unpredictable | 4 of 5 |
| H-AR, exponents from 0 | **predictable on coordinate 0** | 5 of 6 |
| H-AR, exponents from 1 | unpredictable | 4 of 6 |
| DFAR (re-implementation) | unpredictable | 2 of 5 (+ 3-output XOR identity) |

Full table: `data/phase1_fault_matrix.md`. These are semantic mutations of
a Python model, not instruction-level faults.

## Honest correctness vs root failure vs key mismatch vs leakage

* *Honest correctness*: holds for all rules.
* *Root-test failure*: probability ≤ `deg/q` per fresh ρ; fixed per `c`.
* *Semantic key mismatch*: `corrupt_m`, and DFAR with one evaluation
  omitted, give a wrong key on valid ciphertexts (observable).
* *Leakage*: the plaintext-checking oracle above. For H-AR it exists
  without any fault.

## Gate 1 decision

**H-AR (exponents from 0): refuted.** **Shifted H-AR: unproved, and no
advantage over DFAR identified.** Algebraic Rejection is closed as an
invention candidate. Its discrepancy circuit is kept as an adversarial test
case for CAFQ, where it yields a further negative result (CE-7).

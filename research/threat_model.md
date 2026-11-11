# Threat model

## Fault models

| Model | Definition | Phase 1 toy KEM (`src/toy/kem.py`) | Phase 2 toy-ir-v1 (`src/cafq/ir.py`) |
|---|---|---|---|
| `fault-free` | No fault | Control row in every matrix | `fault-free` certificate for every program |
| `instruction-skip` | One dynamic instruction not executed; destination keeps its previous value; no effect on PC beyond falling through | Named step skips: `skip_contribution`, `skip_power_update`, `skip_marshal`, `skip_compare_chunk`, `skip_select`, `omit_first_eval`, `omit_second_eval`, `omit_final_xor` | `skip` on every instruction |
| `instruction-result-zero` | One dynamic destination forced to 0 | `force_D_zero`, `force_flag_zero` | `zero` on every instruction |
| `single-bit-flip` | One bit of one register flipped immediately after the writing instruction | `corrupt_m` (one message bit) | `bitflip` on every instruction, every bit |
| `branch-decision-flip` | One branch decision reversed | **Not modelled**: the toy has no data-dependent branch; `skip_select` is the closest analogue | **Out of scope**: straight-line IR has no branches |
| `checker/control fault` | Fault inside challenge derivation, checking, marshalling or KDF | `alias_checker_input` (checker reads the received buffer twice), `skip_marshal`, `force_D_zero` | Every instruction in regions `check` and `marshal`. Challenge *sampling* and the KDF are outside the IR |

Scope of every statement: **one** fault per execution, chosen before the
challenge is sampled, deterministic replay, bounded region. No multi-fault,
no adaptive-fault and no physical-fault claim is made anywhere.

The Phase 1 faults are *named semantic mutations of a Python model*. They are
not instruction-level faults and carry no ISA, compiler or binary hash.
Phase 2 faults are exact at the IR level only.

## Adversary

* Chooses the fault (kind, site, bit) and the state / ciphertext.
* Does not see the challenge before the run completes.
* Phase 1: has the public key and a (possibly faulted) decapsulation oracle;
  never reads `sk` or `z`. Queries may repeat.
* Phase 2: the state `x` may be adversarial (this matters: the AR
  discrepancy circuit is all-bypass *because* the input difference is
  adversarial).

## Observation

| Channel | Phase 1 | Phase 2 |
|---|---|---|
| Returned key | yes | — (output registers) |
| Validity / abort signal | none exists (implicit rejection in all three rules) | detection status `[disc ≠ 0]` |
| Effective vs ineffective fault | visible as `wrong-key` on valid ciphertexts; recorded | flagged per certificate (`status_changed`, `status_depends_on_state`); not bounded |
| Public ciphertext | yes | — |
| Timing, power, EM | **not modelled** | **not modelled** |
| Retries | allowed; same `c` ⇒ same `ρ` | one run per theorem; `Q` runs only with fresh independent challenges |

## Boundary between detection and KEM security

A detection bound (Theorems 1–2 of `specs/cafq_semantics.md`) bounds
`Pr[wrong ∧ undetected]` for one fault, one state, one fresh challenge. It
is not, and does not imply:

* IND-CCA security of any KEM using the checked computation;
* unpredictability of a discrepancy value fed to a KDF (CE-1);
* security when the challenge is reused or derived from adversarial input;
* absence of ineffective-fault leakage;
* constant-time behaviour;
* anything about machine code.

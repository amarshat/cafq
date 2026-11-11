# proofs/

No machine-checked proofs exist yet. This directory records where each
argument currently lives and what kind of evidence backs it.

| Statement | Where | Evidence |
|---|---|---|
| GF(2^8) is a field with the stated modulus | `tests/test_field.py` | Exhaustive: irreducibility by trial division, all pairs, all 2^24 triples |
| Constant difference has zero challenge entropy | `specs/field_and_discrepancy.md` Fact 1 | One-line proof; exhaustive over all rho and all delta |
| Preimage bound (valid replacement for "root bound implies entropy") | `specs/field_and_discrepancy.md` Lemma 2 | Written proof; exhaustive spot families |
| CAFQ per-fault bound (Theorem 1) | `specs/cafq_semantics.md` | Written proof; brute force on GF(4)/GF(8) instances |
| CAFQ quotient preservation (Theorem 2) | `specs/cafq_semantics.md` | Written proof; brute force equality of undetected sets |
| H-AR IND-CCA | — | **Refuted** as specified (`research/counterexamples.md` CE-2) |
| Shifted H-AR IND-CCA | `research/proof_obligations.md` | **Unproved**; obligations listed |

Candidates for mechanisation, in order of value: Theorems 1–2 for toy-ir-v1
(small enough for Lean or Coq), then the checker's polynomial identity test.
SAW/Cryptol were not available in this environment.

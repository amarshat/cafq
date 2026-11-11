# Hypotheses and kill tests

A kill test is an executable experiment whose failure refutes the hypothesis.
Status vocabulary: demonstrated / hypothesised / contradicted / blocked.

## H-AR

| ID | Hypothesis | Kill test | Result |
|---|---|---|---|
| H-AR-1 | Honest ciphertexts decapsulate to the encapsulated key | Any honest `(m, c)` with a different key | **Demonstrated** (toy; all 256 messages, 3 keys) |
| H-AR-2 | Keys returned for inconsistent ciphertexts are unpredictable to the adversary | Adversary predicts the key from `(pk, m, query)` | **Contradicted** for exponents from 0 (CE-2). Contradicted in the toy for any shift by enumeration (CE-3) |
| H-AR-3 | A small root probability implies an unpredictable KDF input | `D(X) = δ` | **Contradicted** (CE-1) |
| H-AR-4 | Removing comparison and select removes the single-fault PCO | Any single fault giving an adversary-computable key | **Contradicted** (CE-6): 5 such faults for H-AR vs 4 for FO in the toy model |
| H-AR-5 | The discrepancy check detects single faults in its own computation | A fault plus an inconsistent input accepted for all challenges | **Contradicted** (CE-7): every in-scope fault |
| H-AR-6 | Shifted, large-field H-AR is IND-CCA in the ROM | A PCO-style distinguisher, or a completed proof | **Hypothesised, unproved.** No attack found beyond `1/q` events (CE-4). No advantage over DFAR identified |
| H-AR-7 | H-AR is the same construction as DFAR | Compare definitions | **Contradicted**: different mechanism (novelty matrix A1) |

## H-CAFQ

| ID | Hypothesis | Kill test | Result |
|---|---|---|---|
| H-C-1 | Every `covered` certificate's bound holds for all states | Brute force: a wrong state with more undetected challenges than `degree_bound` | **Demonstrated** on 10 exhaustive instances over GF(4)/GF(8); sampled states × all challenges on GF(256). Zero violations |
| H-C-2 | Members of an L3/L4 class have identical undetected sets on every wrong state (up to the stated `{0}`) | Brute force inequality of sets | **Demonstrated**, same instances. Zero unsound merges |
| H-C-3 | No fault with a fully-bypassing state is labelled benign or covered | Brute force search for such a state | **Demonstrated** on the exhaustive instances |
| H-C-4 | The checker rejects every false certificate | Tampering: classification, polynomial, witness, factorisation, bound, roots, class keys, manifest, program | **Demonstrated** for the 30 mutation tests written; this is evidence, not a proof of checker soundness |
| H-C-5 | Detection-level quotients give fewer classes than exact-effect collapsing under the same fault model | Class counts L1 vs L2–L4 | **Demonstrated** on fingerprint-checked circuits (e.g. 184 → 11 → 2 for schoolbook n = 6). **Not** on the AR discrepancy circuit (all bypass; no reduction) |
| H-C-6 | The quotient reduces total verification cost | Wall-clock with and without classes | **Contradicted at toy scale**: symbolic derivation per fault dominates; classes save only root enumeration (milliseconds) |
| H-C-7 | The construction is new relative to CLEAVE / FIVER / FIRMER and classical ABFT | Literature comparison | **Blocked**: sources not accessible in this session |
| H-C-8 | The method extends to compiled code at ISA level | An ISA-level instance | **Not attempted** |

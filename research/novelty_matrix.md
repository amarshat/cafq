# Novelty matrix

Access legend: **read** (the cited part was read in full), **abstract**
(landing-page abstract only), **not accessed**. Nothing below is reconstructed
from memory of a paper's body; where a column needs the body and only the
abstract was available, it says so.

## A. Directly related works

### A1. DFAR — Alsawalqah, Abadleh (Zenodo 10.5281/zenodo.23511350, 25 Oct 2026). Access: read (package), main manuscript not in package

| Aspect | What the package says | Where |
|---|---|---|
| Mechanism | `K_DFAR(c) = K̂(c) ⊕ F_k(E(c, c̄(c))) ⊕ F_k(E(c, c))`. Two PRF evaluations on an injective encoding of the ordered pair; they cancel iff `c̄ = c`. No field arithmetic, no polynomial, no challenge | Supplement, opening equation; `verification/reference_dfar_kernel.c::dfar_full` |
| Compressed variant | `a = H(c)`, `t = H(c ⊕ c̄)`, `t0 = H(0)`; `K̂ ⊕ F(a,t) ⊕ F(a,t0)`; costs an extra collision term | Supplement "Hashed-Difference Variant"; `dfar_compressed` |
| Main theorem | With `F` replaced by a random function, the adaptive classical decapsulation transcript is *identically distributed* to ideal implicit rejection; hence `Adv^{IND-CCA}_{DFAR} ≤ Adv^{IND-CCA}_{IR} + Adv^{PRF}_F` | Supplement "Exact Transcript Equivalence", "IND-CCA Hybrid Reduction" |
| Proof device | Support graph: `R(u_i) ⊕ R(v_i)` are jointly uniform iff the edge multigraph is a forest; both addresses contain `c`, so distinct ciphertexts give disjoint edges | Supplement "Support-Graph Characterization", "Received-Ciphertext Matching" |
| Assumptions | A1–A5 of the main paper (summarised in the supplement only): independent deformation key; candidate path independent of `F`; injective domain-separated pair encoding; deterministic reconstruction; total deterministic candidate path | Supplement, first paragraph |
| Model | Classical ROM for the ML-KEM corollary; QROM only as a conditional transfer statement | Supplement "IND-CCA Hybrid Reduction"; `audit/SECURITY_AND_PRIOR_WORK_REVIEW_20261018.txt` §2 |
| Implementation level | C on OpenSSL 3.5.5 ML-KEM (x86-64), Go ML-KEM-768, AArch64 source patch | `source/` |
| Fault model actually measured | Source-level *mutations compiled in* ("compiled-software-fault"), 200 malformed ciphertexts per class and parameter set; metric = returned key equals the raw candidate | Supplement Table "Matched compiled-software-fault outcomes" |
| Fault results reported | Baseline forced-equality / truncated-compare / forced-select: 200/200 exposed. DFAR omit-first-eval, omit-second-eval, corrupt-XOR-byte: 0/200. DFAR truncate-distinguishing-input and omit-final-XOR: **200/200** | same table |
| Stated limits | Not FIPS 203 on malformed ciphertexts; no physical-fault resistance claim; no combined-fault security: `K_N ⊕ K_D1 ⊕ K_D2 = K'` | Supplement §S2–S3; `audit/COMBINED_FAULT_SCOPE_ANALYSIS_20261019.txt` |
| Not covered | Instruction-level or physical faults; ineffective-fault leakage; multi-fault; machine-checked proof; KEM binding properties | as stated by the authors |
| Our status | Mechanism and claims: **read**. Verification suite: **not executed** (running downloaded third-party code was refused by this session's permission policy). Toy re-implementation written from the formula reproduces the qualitative fault table and the combined-fault identity (`tests/test_fault_models.py`) | — |

**Relation to H-AR.** Same goal (no accept bit, no select; cancel on
consistent ciphertexts), different mechanism. DFAR puts the *pair* `(c, c̄)`
through a PRF; H-AR puts a *field-valued polynomial evaluation* of `c − c̄`
through the KDF. DFAR's rejection key is pseudorandom for every inconsistent
ciphertext by construction; H-AR's is not (CE-1, CE-2). DFAR has clear
priority on decision-free rejection by cancellation. H-AR is not identical to
it, and is strictly weaker as specified.

### A2. Verifiable Decapsulation — Glabush, Günther, Hövelmanns, Stebila (ePrint 2025/450). Access: abstract

| Aspect | Abstract-level content |
|---|---|
| Mechanism | Modified FO that binds re-encryption to functionality: an unpredictable *confirmation code* exported from the PKE is embedded in key derivation |
| Guarantee | An implementation that *skips* re-encryption fails basic correctness tests |
| Fault model | Benign implementation errors (missing step). The abstract does not claim security against active fault injection |
| Applied to | ML-KEM and HQC, using entropy lost in compression/truncation |
| Difference from H-AR / CAFQ | Targets detectability of omitted verification by testing, not adversarial faults; does not quotient fault spaces. Theorem statements: body not read |

### A3. FIPS 203. Access: read (Algorithm 18, p. 34)

Decapsulation computes `K̄ ← J(z‖c)` and returns `K̄` when `c ≠ c′`. Any rule
that returns something else on inconsistent ciphertexts (H-AR, DFAR) is not
ML-KEM. The text also notes the comparison flag is secret intermediate data.

### A4. Default Correct (ePrint 2026/2069). Access: abstract

Fault on the *Booleanisation* stage between mismatch accumulation and cmov:
one clock glitch forces the fail flag to 0; demonstrated on Cortex-M4 across
pqm4 / PQClean / reference Kyber at all optimisation levels; full key
recovery via a plaintext-checking oracle; proposes an integrity-checked
Booleanisation. Relevance: motivates removing the flag. It does not show
that removing the flag removes the fault surface, and our Phase 1 matrix
shows it moves (`force_D_zero`, `skip_marshal`, `alias_checker_input`).

### A5. One Unverified Coordinate Is Enough (ePrint 2026/2239). Access: abstract

One unverified ciphertext coordinate suffices for ML-KEM key recovery via
noise measurement and least squares; `O(kn log kn)` observations under a
regularity assumption; a skipped cmov gives a full PCO. Relevance: H-AR's
coordinate 0 is *effectively unverified with no fault* (the returned key is
predictable), and a skipped contribution makes any coordinate unverified.
Our toy attack is the same idea on a 3-dimensional toy; we did not reproduce
their ML-KEM attack.

### A6. CLEAVE (FM 2024). Access: not accessed
### A7. Giorgi–Grenet–Perret du Cray (JSC 2023). Access: not accessed
### A8. FIVER, FIRMER, StaMAC, algebraic fault analysis, masked comparison, ABFT. Access: not accessed

No statement about the content of A6–A8 is made. This is the largest gap in
the novelty assessment: the comparison below is against technique *classes*,
not against these specific systems.

## B. CAFQ against technique classes

Stated from the definitions of the techniques, not from specific papers.

| Technique class | What it identifies | Relation to CAFQ |
|---|---|---|
| Exact fault equivalence / collapsing | Faults with identical faulty behaviour on all inputs | This is CAFQ level L1. Not new. Used as the baseline |
| Fault dominance | Fault A detected whenever B is | Not implemented. L3/L4 classes are equalities of undetected sets, not dominance |
| Group / symmetry reduction | Orbits of faults under automorphisms preserving the experiment | Not implemented. CAFQ classes are not orbits: members can sit at unrelated sites with different output errors |
| Symbolic execution with fault injection | Per-fault symbolic effect, usually discharged per fault | CAFQ's analyzer does exactly this per fault; the difference is what is done *after*: witness, factorisation, class |
| SMT-based verification | Per-fault (or batched) satisfiability of "wrong ∧ undetected" | CAFQ replaces the SAT question by polynomial identities checked by a small checker, and gives a count of undetected challenges rather than a yes/no |
| Compositional circuit verification | Gadget-level properties composed to a circuit | Not implemented. toy-ir-v1 is monolithic |
| Randomised identity testing (Schwartz–Zippel, Freivalds) | Root bound `deg/q` | Theorem 1 is this, per fault. Not new |
| Coding-theory view of fingerprints | Error pattern `e` undetected iff `e(r) = 0` | Corollary 3 is this view applied per fault class. The mathematics is classical |

## C. What could be claimed, and what cannot

**Cannot be claimed:** algebraic rejection; fingerprint checks; fault
collapsing; the root bound.

**Candidate claim (not yet established as new):** a *certifying* procedure
that, for a straight-line arithmetic program with an algebraic checker,
(i) classifies every single fault with a checkable witness, including
explicit bypass states; (ii) factors each discrepancy as `u(x)·R^k·h` and
proves that faults with the same `(k, h)` have identical undetected-challenge
sets on every wrong state, although their outputs differ; (iii) yields exact
conditional detection probabilities for classes with constant `h`.

**If the only difference from prior art turns out to be the packaging of
classical facts with a checker, this is an application/tool contribution,
not a foundational one.** That question cannot be closed without A6–A8.

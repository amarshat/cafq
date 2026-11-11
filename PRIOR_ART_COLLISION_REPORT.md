# Prior-art collision report — structural fault quotients

Date of access: 2026-11-11.

**How to read this report.** Every statement about a paper is backed by text
extracted from its PDF in this session (`pdftotext`), with the section or page
given. Nothing is reconstructed from memory. Access status is one of:

* **full** — all body sections read;
* **partial** — the listed sections read, plus whole-text keyword search;
* **not obtained** — no claim is made about its content.

PDFs are not stored in the repository (third-party material); their SHA-256
digests are listed so the same files can be identified.

The most important limitation comes first.

## 0. What could not be checked — and why it matters most

The structural method's core identity is "a fault at line `i` changes the
output by `δ · ∂out/∂line_i`". Over GF(2) this is, by its name, what the
**Boolean difference** method of test generation is about. Its primary source
(Sellers, Hsiao, Bearnson, 1968) and every exposition of it were unreachable
(IEEE Xplore blocked; no open copy found). The same holds for:

| Literature | Status | Consequence |
|---|---|---|
| Boolean difference / derivative-based test generation | not obtained | Cannot claim the derivative view of fault detection is new. It should be **assumed known** for Boolean circuits |
| Reverse-mode automatic differentiation; AD-based error/soft-error propagation | not obtained (arXiv keyword searches empty; HPC venues blocked) | Cannot claim "one reverse pass gives all fault sensitivities" is new. Reverse-mode AD itself is certainly classical |
| Huang & Abraham 1984 (ABFT); Freivalds 1977 | not obtained (second-hand descriptions only) | Fingerprint checks and their miss probability are treated as known |
| Algebraic fault analysis | not obtained | No comparison |
| Symmetry / automorphism-based fault-space reduction | nothing located | No comparison beyond CLEAVE's round isomorphism |
| VerFI, CINI MINIS | not obtained (ePrint PDFs behind a bot challenge that was not circumvented; ACM/IEEE blocked) | No comparison |
| Giorgi–Grenet–Perret du Cray (JSC 2023) | not obtained | No comparison |

Blocked hosts: ieeexplore.ieee.org, dl.acm.org, export.arxiv.org, www.iacr.org,
hal.univ-grenoble-alpes.fr, idp.springer.com. `eprint.iacr.org/*.pdf` returned
a site-side bot challenge.

**Therefore no novelty claim in this repository rests on "nobody has used
derivatives for fault effects".** The defensible question is narrower: has
anyone combined it with randomised algebraic checks over GF(q), unit-content
classes, exact per-class probabilities and checkable certificates? For the
papers actually read, the answer is no. For the unread literatures, unknown.

## 1. Papers read

| # | Paper | Access | SHA-256 of PDF (prefix) |
|---|---|---|---|
| 1 | Tan, Yang, Song, Chen, Wu — *Compositional Verification of Cryptographic Circuits against Fault Injection Attacks* (CLEAVE) | full, 18 pp. | `f9c10c13da227e21` |
| 2 | Tan, Gao, Song, Chen, Wu — *SAT-based Formal Verification of Fault Injection Countermeasures for Cryptographic Circuits* (FIRMER), TCHES camera-ready; arXiv:2307.00561v1 spot-checked | Sections 1–7 full; appendices skimmed | `92dcc4a1ffbcce1e` |
| 3 | Richter-Brockmann, Rezaei Shahmirzadi, Sasdrich, Moradi, Güneysu — *FIVER*, TCHES 2021(4) 447–473 | Sections 1–6 full | `0aa28d7252dd3b5f` |
| 4 | Sandireddy, Agrawal — *Diagnostic and Detection Fault Collapsing for Multiple Output Circuits* (DATE 2005) | Sections 1–4 full, 5–6 prose | `c58ec3170fd7b20d` |
| 5 | Ko, Burgstaller — *BEC: Bit-Level Static Analysis for Reliability against Soft Errors*, arXiv:2401.05753v1 | partial (abstract, introduction, all text on equivalence classes, pruning, soundness) | `89507a1cd9f4b7eb` |
| 6 | Tollec et al. — *Fault-Resistant Partitioning of Secure CPUs…*, TCHES 2024(4) 179–204 | partial | `8187c3e28e969bae` |
| 7 | Richter-Brockmann, Feldtkeller, Sasdrich, Güneysu — *VERICA*, TCHES 2022(4) 255–284 | partial | `87ab9d33cbe3d032` |
| 8 | Nasahl et al. — *SYNFI*, arXiv:2205.04775v2 | partial | `f93bce3d5bdac41f` |
| 9 | Fang, Zhou, Wang, Wang — *Efficient Symbolic Execution of Software under Fault Attacks*, arXiv:2503.15825v2 | abstract and keyword contexts | `5c5e8472f1b1d1b5` |
| 10 | Napolean, Srivastava, Periathambi — *Syndrome Decoding for Silent Data Corruption…*, arXiv:2609.19743v1 (unrefereed preprint) | abstract and keyword contexts | `d5a64ccaf5fea137` |

Keyword search over the full extracted text of papers 1–9 for *derivative*,
*Jacobian*, *adjoint*, *Schwartz*, *certificate*: zero occurrences in each
(paper 10 has one "derivative", of a Reed–Solomon locator polynomial).

## 2. What their algorithms compute

### 2.1 CLEAVE

* **Model.** Boolean gate-level netlists of round-based circuits; faults are
  bit-set / bit-reset / bit-flip on gate outputs, several per cycle, several
  cycles (Sec. 3.1, Def. 5).
* **Property.** Yes/no: a fault vector is *effective* if for some input the
  outputs differ before the error flag is set (Def. 4); resistant iff none is.
* **Algorithm.** Decompose into single-round sub-circuits, verify each with a
  SAT/SMT or BDD back end (Sec. 4.2–4.4).
* **Structural reductions.** (a) round decomposition with round isomorphism
  ("identical up to the renaming of the primary inputs/outputs, registers and
  vertices", Sec. 4.2; the isomorphism check is skipped in the implementation,
  Sec. 5); (b) *vulnerable gate reduction*: "If the output of a gate g is only
  connected to one vulnerable logic gate g′ … then the gate g can be safely
  added into the blacklist" (Sec. 4.5); (c) fault-type reduction (bit-flip
  alone suffices).
* **Proof model.** Theorem 2: if every single-round sub-circuit is resistant,
  the circuit is (one direction). No certificate, no independent checker.
* **Cost.** NP-completeness of non-resistance (Theorem 1). Reported: 17 of 18
  benchmarks within 200 s compositionally; the monolithic approach handles 12
  within 6 hours (Sec. 1).

### 2.2 FIRMER

* **Model / property.** As CLEAVE (same group); yes/no.
* **Algorithm.** Replace every vulnerable gate by a gadget with fault-control
  inputs; one SAT instance encodes *all* fault vectors (Sec. 4.2–4.3,
  Proposition 3). It does not enumerate faults.
* **Structural reduction.** The fan-out-1 merge, with a theorem (Theorem 2,
  Corollary 1), "computed by a graph traversal". Explicit limit: "the
  vulnerable gate reduction does not consider conditional fault propagation"
  (Sec. 4.4). Effect: "over 70% reduction rate on average" (Sec. 5).
* **Proof model.** UNSAT ⇔ resistant; on failure "only reports one effective
  fault vector" (Sec. 6). No certificate.
* **Cost.** coNP-complete (Theorem 1). 72 of 76 benchmarks in 3 minutes
  (abstract).

### 2.3 FIVER

* **Model.** Gate netlist → DAG → one BDD per node; signals in GF(2).
* **Algorithm.** Enumerates every combination of fault locations and fault
  types and recomputes BDDs on the propagation path: "iterating over four
  nested loops…" (Sec. 4.2).
* **Structural reductions.** Described as relying "on the structural analysis
  of the circuit model while being independent of the functional behavior"
  (Sec. 3.2): (i) re-evaluate only the fan-out cone; (ii) restrict fault
  locations to registers, their drivers and fan-out>1 "sensitive gates"
  (Algorithm 1), valid "only … in the bit-flip model". No soundness theorem in
  the sections read.
* **Quantitative output.** Counts *input assignments* (BDD minterms) for
  which a fault is effective/detected. Not a probability over a random
  challenge.
* **Cost.** Table 1: 91,737,144 fault combinations in 2,937 s without, and
  4,665,200 in 360 s with reduction (CRAFT, one round, 3-bit).

### 2.4 Classical fault collapsing (Sandireddy & Agrawal)

* Defines **equivalence** ("identical output functions"), **structural
  equivalence** ("identifiable from the circuit graph"), **dominance**, and
  **detection equivalence**: "Two faults are called detection equivalent if
  and only if all tests that detect one fault also detect the other fault, not
  necessarily at the same output" (Sec. 3, Definition 4).
* Structural collapsing leaves "about 40 to 60% of all faults" (Sec. 1); the
  paper's own functional method is per-fault ATPG and "should be used only
  with smaller circuits".
* Stuck-at faults, Boolean, no probabilities.

### 2.5 BEC (closest in shape)

* Software level (LLVM IR / RISC-V), single bit flips in registers.
* "The fault index coalescing analysis is a **backward data-flow analysis**
  that … classifies which fault sites result in equivalent program semantics
  when corrupted by a bit flip" (Sec. III-B). For XOR, errors at the operands
  "are propagated" to the result, so the classes are merged.
* Purpose: prune fault-injection campaigns ("up to 30.04 %", abstract).
  "Sound but not necessarily precise".
* Boolean; classes mean *identical effect*; no detection property, no
  probabilities, no certificate.

### 2.6 Others

* **Fault-Resistant Partitioning**: SAT-guided inductive invariant over a
  register partition (Theorem 1); yes/no; faults symbolic in SAT.
* **VERICA**: reuses FIVER's fault engine; "for each valid fault injection a
  separate verification…" (Sec. 6).
* **SYNFI**: "For each fault combination … SYNFI starts a new process"
  (Sec. 3.4); no reduction.
* **Symbolic execution under fault attacks**: path-redundancy pruning.
* **SProbe preprint**: Freivalds check on matrix products with a proven miss
  probability "at most ((N − 1)/p)^3" via Schwartz–Zippel. Output errors only;
  no internal fault sites.

## 3. Comparison

| Feature | CLEAVE | FIRMER | FIVER | Classical collapsing | BEC | This work (C) |
|---|---|---|---|---|---|---|
| Abstraction | Boolean gates | Boolean gates | Boolean gates (BDD) | Boolean gates | bit-level software | word-level arithmetic over GF(2^m), straight-line |
| Fault model | set/reset/flip, multi-fault, multi-cycle | same | same | single stuck-at | single bit flip | single skip / zero / bit flip per instruction; **single fault only** |
| Each fault analysed separately? | no (SAT) / yes (BDD) | no (one SAT) | yes | yes (ATPG) | no | no |
| Structural classes without per-fault solving | round isomorphism; fan-out-1 merge | fan-out-1 merge (theorem) | sensitive-gate restriction (no theorem) | structural equivalence/dominance | yes: backward pass, identical-effect classes | yes: reverse pass, classes by adjoint up to a unit |
| Conditional (data-dependent) propagation | no | explicitly not | no | n/a | no | yes: the adjoint is a polynomial in the state |
| Derivative / adjoint formulation | none found | none found | none found (per-fault golden⊕faulty) | none found | none found | yes |
| Randomised check, hidden challenge | no | no | no | no | no | yes |
| Quantitative result | yes/no | yes/no | counts inputs | no | no | undetected-challenge set per class; exact when `h` is constant |
| Certificate + independent checker | no | no | no | no | no | yes |
| Soundness statement | composition theorem | encoding + reduction theorems | none in body | definitions | "sound" (not checked by us) | written proofs, brute-force-tested, not mechanised |
| Scale demonstrated | AES rounds, up to 34,351 gates | up to 68,703 gates | AES round, ~10^8 fault combinations | 4-bit ALU | benchmarks | **≤ ~2,000 instructions, toy IR** |

## 4. What ours does that those cannot — and the reverse

**They cannot (in the versions read):**

1. Give a *probability* for a randomised algebraic check. Their property is
   deterministic effectiveness; a fingerprint check is "not resistant" in
   their sense whenever one challenge misses. This is a model difference, not
   a weakness: they target deterministic redundancy.
2. Handle *conditional propagation* structurally. FIRMER states it does not;
   FIVER restricts its reduction to bit flips. Our adjoint carries the
   condition as a polynomial.
3. Emit a certificate that a small independent program checks.
4. Certify a site for *every* additive error at once (Theorem S2,
   δ-agnosticism). Their reductions merge fault *locations*, not error values
   (over GF(2) there is only one non-zero error).

**We cannot:**

1. Handle multiple simultaneous faults (their main strength). Our two-fault
   result is one restricted experiment.
2. Handle sequential circuits, registers, clock cycles, gates.
3. Handle anything non-arithmetic: comparisons, selects, table lookups.
4. Approach their scale. Our largest program has about 2,000 instructions.
5. Decide resistance: our witness search is incomplete (`unknown` exists).

**Same idea under different names.**

* Our L1 is their fault equivalence. Our L3/L4 classes are *detection
  equivalence* (Definition 4 of the DATE 2005 paper) specialised to "tests" =
  challenges, conditional on a wrong state.
* The fan-out-1 merge of CLEAVE/FIRMER is the Boolean special case of "the
  adjoint of a value with a single linear use equals the adjoint of its user".
  Our templates extend it through fan-out (sums of adjoints) and through
  multiplications (products with operand values), which is exactly what they
  exclude as "conditional propagation".
* BEC's backward coalescing through XOR is the same reverse pass with
  coefficients restricted to {identical, different}. Ours keeps the
  coefficient.

## 5. Verdict of the collision test

* **Not new:** fault equivalence, detection equivalence, structural collapsing,
  backward data-flow fault-site merging, root-counting bounds for
  fingerprints, reverse-mode differentiation, and (presumed) derivative-based
  detection conditions for Boolean circuits.
* **Not found in anything read:** derivative/adjoint-based fault templates for
  arithmetic programs with a randomised algebraic check; classes "up to a
  unit"; exact per-class non-detection probability; δ-agnostic site
  certificates; an algebraic criterion (`Jd = 0`) for tautological checks;
  independently checkable certificates for any of it.
* **Unresolved:** whether the derivative-based part is anticipated in the
  Boolean-difference, ABFT or automatic-differentiation literatures, which
  were not reachable. Until someone reads those, the honest label is
  **"a new combination, as far as the accessible literature shows; core
  identity presumed classical."**

To close the gap, the following PDFs would need to be supplied: Sellers,
Hsiao & Bearnson (1968) or any textbook chapter on the Boolean difference;
Huang & Abraham (1984); a survey of algebraic fault analysis; VerFI;
CINI MINIS; and any paper on derivative- or AD-based soft-error propagation.

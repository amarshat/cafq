# Research assessment after Phases 0, 1 and the first part of Phase 2

Date: 2026-11-11. This is a falsifiable decision memo, not a success report.

## Decisions

| Gate | Decision | One-line reason |
|---|---|---|
| 0 | H-AR is not DFAR, and is not ours to claim. Baseline under test | DFAR: `K̂ ⊕ F(c,c̄) ⊕ F(c,c)`. H-AR: polynomial discrepancy into a KDF. DFAR has priority on decision-free rejection |
| 1 | **H-AR as specified: refuted.** Shifted H-AR: unproved, no advantage over DFAR. **No-go** as an invention | Coordinate 0 multiplies `ρ^0`: the returned key is predictable, giving a plaintext-checking oracle with no fault |
| 2 | **CAFQ: go**, claim narrowed, cost hypothesis dropped | Sound on every exhaustive instance; 10–17× fewer classes than exact collapsing; no time saving |

## Status of each claim

**Demonstrated** (executed, with the domain stated in the tests)

* GF(2^8) arithmetic; discrepancy facts; zero-entropy constant difference.
* Coordinate-0 plaintext-checking oracle against H-AR and recovery of a
  secret-key row in the toy (40 queries, no fault); FO and DFAR unaffected by
  the same queries.
* Single-fault oracle persists under H-AR and (for two faults) under DFAR.
* Every single fault in the AR discrepancy circuit has a bypass state.
* CAFQ certificates sound against brute force on 10 small-field programs;
  checker rejects all tampering tried; detection-level classes are far fewer
  than exact-effect classes on fingerprint-checked circuits.

**Proved on paper, instance-checked, not machine-checked**

* Preimage bound; CAFQ Theorems 1–2 and Corollary 3.

**Hypothesised**

* Shifted, large-field H-AR is IND-CCA in the ROM (obligations PO-AR-1..6).
* CAFQ transfers to compiled code and to kernels with real fan-out.
* The unit-content quotient is new as a *certified* object.

**Contradicted**

* "Small root probability ⇒ unpredictable KDF input."
* "No comparison ⇒ no single-fault acceptance oracle."
* "The quotient reduces verification time" (at toy scale).

**Blocked**

* Reproduction of DFAR's verification suite (execution of downloaded code
  not permitted in this session).
* Comparison with CLEAVE, FIVER, FIRMER, StaMAC, Giorgi et al. (not
  reachable).
* Machine-checked proofs (no prover / SAW / Cryptol in the environment).

## Skeptical programme-committee review

The strongest reasons this is "known fault collapsing plus Schwartz–Zippel":

1. **Theorem 1 is Schwartz–Zippel**, applied per fault.
2. **L2 is linearity.** A bit flip adds a constant; different bits give
   proportional discrepancies. Any reviewer sees this immediately.
3. **L3 and Corollary 3 are the coding-theory view of a fingerprint**: an
   error pattern `e` escapes iff `e(r) = 0`. That single-coefficient errors
   escape only at `r = 0` is textbook.
4. **The two-class result for schoolbook multiplication is trivial
   structure**: a single fault there corrupts one coefficient.
5. **No proof work is saved where it is expensive.** Symbolic execution is
   still per fault. A real contribution would avoid deriving `g_f` for most
   faults (structural summaries, compositional reasoning); this does not.
6. **Toy scale, toy IR.** No ISA, no memory, no control flow, no compiler.
7. **The AR application failed**, so the method has no flagship use case.
8. **Novelty is unassessed** against the tools most likely to subsume it.

What survives that review:

* The *certified* classification including explicit bypass states and an
  honest `unknown`, checked by a small independent program.
* The unit-content factorisation as a *class invariant with a preservation
  proof*: same undetected set, different outputs. This is a quotient that
  exact-effect collapsing cannot express.
* Exact conditional detection probabilities rather than degree bounds.
* Two negative results with executable evidence: H-AR's rejection keys leak
  without faults, and an evaluation fingerprint cannot protect a consistency
  check of adversarial input against a chosen single fault.

**The publishability sentence of the work package is not yet supported.**
There is a sound certifying algorithm and a quotient with a preservation
theorem and measured class reduction, but not a demonstrated reduction in
proof *work*, not a fair comparison against existing tools, and not a
non-toy instance. Today this is a scoped negative result on H-AR plus a
promising prototype, and should be labelled that way.

## Recommended next steps, in order

1. **Unblock prior art.** Obtain CLEAVE, FIVER, FIRMER and the Giorgi et al.
   paper (PDFs dropped into the workspace are enough). Decide whether L3 is
   already known. This determines whether CAFQ is worth more investment.
2. **Make the quotient save work.** Derive class membership *structurally*
   (from the position of the fault in the dataflow graph) and verify one
   representative per class symbolically, with a cheap per-member check.
   Kill test: checker time must fall below per-fault symbolic checking.
3. **Two-fault model** restricted to (one data fault, one checker fault).
   Expected to convert many checker-region "covered" faults into bypasses.
4. **A kernel with real fan-out**: HQC-style multiplication in
   `GF(2)[x]/(x^n − 1)` with the fingerprint in an extension field, including
   the unreduced-product / folding relation and common-mode buffer faults
   (work-package Phase 3).
5. **One ISA-level instance**: compile a 2×2 multiplier with its check using
   the pinned gcc 13.3.0 and clang 18.1.3 already present, record hashes and
   disassembly, map instructions to IR sites.
6. **Mechanise Theorems 1–2** for toy-ir-v1.
7. **Do not build an H-AR KEM.** If comparison-free rejection is still of
   interest, study DFAR's stated open fault cases (truncated distinguishing
   input, omitted final XOR, combined outputs) with CAFQ-style site
   enumeration on its compiled code, after reproducing its suite.

## Environment record

Python 3.13.18; pytest 9.2.0 (only dependency); gcc 13.3.0 and clang 18.1.3
present but unused. 139 tests pass (`data/transcripts/pytest_2026-11-11.txt`).

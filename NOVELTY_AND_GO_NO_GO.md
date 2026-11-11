# Novelty and go / no-go — structural fault quotients

Date: 2026-11-11. Written to be argued with. Evidence files are named for
every number; nothing here is an estimate.

## Decision: **PIVOT**

Not GO. Not STOP.

* **Why not STOP.** The stop condition "structural class membership requires
  essentially the same work as individual symbolic fault verification" is
  false on the kernels the method is meant for: total cost (generation plus
  independent checking) drops by 9–128× with fault-by-fault identical
  verdicts, and the gap widens with program size.
* **Why not GO.** All three GO conditions must hold. (1) Less total work: yes.
  (2) A nontrivial compositional theorem: **no** — compositionality here *is*
  the chain rule. (3) Meaningfully distinct from prior art: **not
  established** — the core identity (fault effect = injected error × derivative)
  is presumed classical, and the literatures most likely to contain it could
  not be read.
* **The quotient is not a security quotient.** It preserves the set of
  undetected challenges conditional on a wrong output, for one IR-level
  fault and one fresh challenge. It does not preserve attacker observations
  (C3), does not survive a second fault, and does not survive compilation.
  Presenting it as a security-equivalence would be wrong.

**Pivot to:** a certifying *verification-cost* technique for one precisely
scoped detection property, plus a set of negative results, with the claim
"new combination; core mathematics classical" until the prior-art gap is
closed.

---

## 1. What was built

| Deliverable | Where |
|---|---|
| Theory: definitions, algorithm, Theorems S1–S5, counterexamples C1–C4, complexity | `STRUCTURAL_QUOTIENT_THEORY.md` |
| Prior-art collision report | `PRIOR_ART_COLLISION_REPORT.md` |
| Structural quotient prototype, separate from the baseline | `src/cafq/structural.py` |
| Certificate format `cafq-structural-0.2` and independent checker | `src/cafq/structural_checker.py` |
| Three-way benchmark (plus a stronger baseline) | `tools/run_structural_benchmarks.py` → `data/structural_benchmarks.md` |
| Two-fault study | `tools/two_fault_study.py` → `data/two_fault_study.md` |
| Compiled-kernel study | `tools/compiled_kernel_study.py` → `data/compiled_kernel_study.md` |
| Tests | `tests/test_structural.py`, `tests/test_structural_checker.py`, `tests/test_baselines.py` |

The baseline (`analyzer.py`, `checker.py`) is preserved. One function was
split in two with certificates verified byte-identical before and after. The
fault model is unchanged: single skip / result-zero / bit flip at every
instruction.

## 2. The algorithm in one paragraph

Every in-scope fault replaces the value written at one site by that value
plus an injected error `δ`. One forward pass gives the values; one bit-set
pass finds the sites after which everything is affine in that value; one
reverse-mode pass gives, for every such site, `Jd = ∂disc/∂value` and
`Jo = ∂outputs/∂value`. The fault's effect is then exactly `δ·Jo` on the
outputs and `δ·Jd` on the discrepancy. If the check passes on fault-free runs
and `δ` does not depend on the challenge, the undetected challenges on any
wrong state are the roots of `Jd` — a property of the site, shared by every
fault at it and by every site with the same `Jd` up to a unit. Witness,
factorisation and root set are computed once per distinct template; the
checker recomputes the two passes itself and derives class membership rather
than trusting it.

## 3. Decisive measurements

Source: `data/structural_benchmarks.md` (environment, CPU and source revision
recorded there). GF(256). Total = generation + independent checking. A = per
fault, full re-execution. A′ = per fault with prefix caching (the fairer
comparator). B = A with post-hoc classes. C = structural.

| Program | Instrs | Faults | A total s | A′ total s | C total s | A/C | A′/C | Expensive analyses A → C | Sym. instr. executions A → C |
|---|---|---|---|---|---|---|---|---|---|
| schoolbook n=4 | 61 | 610 | 0.347 | 0.315 | 0.0146 | 23.7× | 21.6× | 610 → 22 | 74542 → 244 |
| schoolbook n=6 | 117 | 1170 | 1.451 | 1.350 | 0.0238 | 60.9× | 56.7× | 1170 → 34 | 274014 → 468 |
| schoolbook n=8 | 189 | 1890 | 4.632 | 4.176 | 0.0560 | 82.7× | 74.5× | 1890 → 46 | 714798 → 756 |
| karatsuba 2x2 | 22 | 220 | 0.052 | 0.047 | 0.0051 | 10.2× | 9.1× | 220 → 14 | 9724 → 88 |
| butterfly 4 | 55 | 550 | 0.259 | 0.223 | 0.0142 | 18.3× | 15.7× | 550 → 30 | 60610 → 220 |
| cyclic mul n=5 | 100 | 1000 | 0.855 | 0.700 | 0.0234 | 36.5× | 29.9× | 1000 → 33 | 200200 → 400 |
| cyclic mul n=7 | 168 | 1680 | 2.755 | 2.403 | 0.0486 | 56.7× | 49.4× | 1680 → 47 | 564816 → 672 |
| cyclic mul n=11 | 352 | 3520 | 16.557 | 14.222 | 0.1292 | 128.1× | 110.1× | 3520 → 75 | 2478784 → 1408 |
| cyclic mul n=5, tautological check | 98 | 980 | 7.810 | 7.724 | 0.0222 | 352.5× | 348.6× | 980 → 28 | 192276 → 392 |
| AR discrepancy n=6 (adversarial input) | 18 | 180 | 0.530 | 0.528 | 0.5032 | 1.1× | 1.0× | 180 → 186 | 6516 → 72 |
| masked check, nonlinear (adversarial) | 11 | 110 | 0.052 | 0.050 | 0.0501 | 1.0× | 1.0× | 110 → 14 | 2442 → 44 |
| nonlinear trap (adversarial) | 6 | 60 | 0.015 | 0.015 | 0.0133 | 1.2× | 1.1× | 60 → 12 | 732 → 90 |
| square check (adversarial) | 6 | 60 | 0.164 | 0.162 | 0.1464 | 1.1× | 1.1× | 60 → 22 | 732 → 156 |
| cyclic mul n=17 (C only) | 748 | 7480 | not run | not run | 0.4143 | – | – | – → 117 | – → 2992 |
| cyclic mul n=23 (C only) | 1288 | 12880 | not run | not run | 0.8435 | – | – | – → 159 | – → 5152 |
| cyclic mul n=31 (C only) | 2232 | 22320 | not run | not run | 2.4170 | – | – | – → 215 | – → 8928 |

Reading:

* **Where it wins.** Fault-linear, homogeneous kernels: every multiplier,
  the butterfly network, cyclic multiplication. The speed-up grows with size
  because A is quadratic in program length and C is linear in symbolic
  instruction executions.
* **Where it does not.** The adversarial rows. The AR discrepancy circuit is
  not homogeneous (every fault still needs its own classification and its
  bypass replayed concretely); the nonlinear circuits need per-site runs and
  per-fault classification. There C is within about 20 % of A (ratios 1.0–1.2).
  These rows were not removed.
* **A failure that was fixed, on the record.** The tautological-fold kernel
  first showed no meaningful gain over the baseline, because its 500 bypasses
  were searched and replayed one at a time (timing of that interim run was
  not retained). The unobserved-site rule (`Jd = 0`,
  Theorem S3) replaced that by a point evaluation.
* **Unsound merges: 0. Unclassified faults: 0** beyond the `unknown`s the
  baseline also reports (same faults, same count).
* **Certificates** are 4–8× smaller; peak memory 4–22× lower on the kernels.
* **Not measured:** anything above about 2,200 instructions; any real HQC
  parameter (n = 17,669 is four orders of magnitude more instructions than
  the largest row); any field larger than GF(256).

Complexity (theory §8): A costs `Θ(m·n²)` symbolic instruction executions and
`F` expensive analyses; C costs `2n` and `T` (distinct templates), plus a
bit-set pass and `O(1)` polynomial operations per fault. Wall-clock for C is
nevertheless superlinear on the largest rows (0.41 s at 748 instructions,
2.42 s at 2,232), mostly in the generator; the cause (polynomial sizes,
bit-set width, per-fault bookkeeping) was not profiled.

## 4. What the challenges to the model showed

### 4.1 One data fault plus one checker fault (`data/two_fault_study.md`)

Every pair on four programs, by double-fault symbolic execution.

| Program | Pairs | Still covered | Bypass on some state | of which undetected on every state | Unknown |
|---|---|---|---|---|---|
| Karatsuba 2×2 | 11,700 | 6,659 | 3,444 | 268 | 1,597 |
| Schoolbook n=2 | 10,400 | 5,842 | 3,205 | 304 | 1,353 |
| Cyclic mul n=2 | 18,000 | 10,896 | 5,307 | 384 | 1,797 |
| Butterfly 4 | 60,000 | 56,201 | 3,799 | 406 | 0 |

* The single-fault model labels every checker fault "benign" or "covered, no
  wrong output". With one data fault added, 122–160 of them (of 130–400)
  enable a bypass for at least one data fault on at least one state; none of
  them is harmless for every data fault except 2 in the butterfly network.
* In each program exactly **two** checker faults disable detection of every
  data fault on every state: skipping or zeroing the final write of `disc`.
  They are the two the single-fault model calls **benign**.
* Caveat in the other direction: "bypass on some state" is existential. For
  most pairs the state is special (two error terms cancel); its density was
  not measured. Where the state is secret rather than adversarial, most of
  those 3,000–5,000 pairs may be far less exploitable than the label
  suggests. The 268–406 "undetected on every state" pairs are unconditional.
* The structural method extends: verdicts for skip/zero checker faults were
  re-derived from the checker-mutated program in one pass each; 0
  covered-versus-not disagreements over 20,020 pairs (differences only
  between `bypass` and `unknown`, from the incomplete randomised search).

**Conclusion: the single-fault classification conceals bypasses.** Any use of
these certificates must state the single-fault assumption next to the result.

### 4.2 Compilation (`data/compiled_kernel_study.md`)

One kernel (2×2 Karatsuba with fingerprint, `src/compiled/kernel.c`), x86-64,
emulated; every single dynamic instruction skip × all 256 challenges, one
fixed state.

| Build | Dynamic instrs | Skips with wrong output | Behave like one IR data fault | Not like any single IR data fault | **Bypass** (wrong, undetected for all 256) | Crash |
|---|---|---|---|---|---|---|
| gcc 13.3.0 -O2 | 895 | 171 | 164 | 0 | **7** | 16 |
| clang 18.1.3 -O2 | 459 | 137 | 82 | 48 | **7** | 17 |
| gcc 13.3.0 -O0 | 1,372 | 322 | 302 | 1 | **19** | 40 |

Equivalences broken, by cause:

1. **Input loads are single points of failure.** The source loads each input
   once into a local used by both the multiplication and the check. Skipping
   the load corrupts both coherently: wrong product, check passes for every
   challenge. 4 sites at -O2. The plain IR cannot express this because its
   inputs are not written by any instruction.
2. **Output stores happen after, and independently of, the check.** The check
   reads the register; the caller reads memory. Skipping a store leaves the
   output stale and the check satisfied. 3 sites at -O2.
3. **-O0 adds more of the same**: stack spills and address arithmetic, 19
   bypass sites.
4. **Vectorisation correlates values the IR treats as independent.** clang
   packs several field multiplications — data-path and checker — into shared
   SIMD instructions. 48 skips match no single IR data fault; 12 of them leave
   3, 4 or **129 of 256** challenges undetected, against an IR-level
   single-fault maximum of 2. One machine fault is here a correlated
   data-plus-checker fault, which is exactly the two-fault case of §4.1.
5. **Field multiplication is not atomic.** Inside the bit-serial multiplier a
   skip injects an error that can depend on the challenge when the multiplier
   instance is a checker one.

A positive control: giving the IR explicit load and store instructions
(`karatsuba2_memory_model`) makes the structural analysis report **exactly**
the 4 load and 3 store sites as bypasses, via the unobserved-site theorem —
the same 7 the gcc -O2 emulation found
(`test_memory_model_predicts_the_compiled_kernel_bypasses`). So the method is
not blind to these; the *model* was.

**Conclusion: IR-level certificates say nothing about a binary.** Between 0.8 %
and 1.5 % of single instruction skips in these three builds are complete
bypasses that the IR-level result called impossible.

### 4.3 Leakage, kept separate

Faults in one class differ in everything except the conditional undetected
set (C3): a bit flip at Karatsuba's `m0` is always effective; the result-zero
fault at the same site, same class, is effective iff `a₀b₀ ≠ 0`, so the alarm
reveals that predicate. Structural certificates flag, per fault, whether
effectiveness or alarm status depends on the state. Nothing is bounded.
Correct final arithmetic output is never reported as "secure".

## 5. Skeptical assessment of originality

### 5.1 Certainly not original

| Ingredient | Why |
|---|---|
| Fault as additive error; effect = error × derivative of the output | Chain rule. Over GF(2) this is what the Boolean difference is by name (source not accessed) |
| One reverse pass yields all sensitivities | Reverse-mode automatic differentiation |
| Undetected iff the challenge is a root | Schwartz–Zippel / Freivalds; coding-theory view of a checksum |
| Classes of faults with equal detection behaviour | "Detection equivalence" is defined in the 2005 fault-collapsing paper read |
| Structural merging of fault sites by a backward pass | BEC does it for bit flips in software; CLEAVE/FIRMER merge fan-out-1 gates |
| Compositionality (S4) | The chain rule across a cut |

### 5.2 Not found in anything that was read

1. Templates for a **randomised algebraic check over GF(q)**, where the
   propagation coefficient is a polynomial in the state and challenge.
   CLEAVE, FIRMER and FIVER are Boolean and deterministic; FIRMER states that
   its reduction "does not consider conditional fault propagation".
2. The **δ-agnostic class theorem** (S2): one certificate per site covering
   every challenge-independent corruption of that value.
3. **`Jd = 0` as an algebraic test for a tautological check** (S3), and its
   use to predict load/store bypasses of a compiled kernel from a memory-aware
   IR.
4. **Exact** per-class non-detection probability rather than a degree bound.
5. Certificates in which **class membership is derived by the checker**.
6. The measured structure of single-fault labels under a second fault (§4.1)
   and under three compilations (§4.2).

### 5.3 Why even 5.2 may not be original

* Items 1–2 are a few lines of algebra once the derivative view is adopted.
  A referee who knows the Boolean-difference or ABFT literature may well say
  "folklore, written down for GF(q)".
* Item 3 is close to the ABFT observation that a checksum must be computed
  independently of the data it checks.
* Items 4–5 are engineering.
* The unread literatures (Boolean difference, ABFT originals, automatic
  differentiation for error propagation, algebraic fault analysis, VerFI,
  CINI MINIS) are precisely where a collision would be.

### 5.4 Limits that cap the contribution regardless of novelty

* Single fault. Fault-linear sites only for the fast path. Homogeneous
  programs only for templates.
* The quotient is sound but **not canonical** (C4): it can produce more
  classes than necessary.
* Straight-line arithmetic IR. No memory, control flow, challenge sampling or
  consumer of the check in the theorems.
* Largest instance ≈ 2,200 instructions.
* Proofs on paper; checker tested, not verified.
* Not explored at all: group actions / symmetry (sites related by an index
  shift have templates differing by a power of `R`, which the L4-style merge
  already absorbs; whether a symmetry argument could avoid computing those
  adjoints was not investigated), gadget-level summary reuse beyond the cut
  theorem, structural treatment of non-fault-linear sites beyond one run per
  site.

## 6. Strongest narrower contributions

In decreasing order of confidence that they survive review:

1. **Negative results with executable evidence.**
   (a) Polynomial "algebraic rejection" leaks a plaintext-checking oracle
   without faults. (b) An evaluation fingerprint cannot protect a consistency
   check of adversarial input against one chosen fault. (c) Single-fault
   labels of checker faults are not stable under a second fault; the worst
   offenders are labelled benign. (d) For one compiled kernel under three
   builds, the specific instruction classes that turn an IR-covered design
   into a bypass, including a vectorisation case that exceeds every IR bound.
2. **A certifying, δ-agnostic verification technique** for fingerprint-checked
   arithmetic kernels that is one to two orders of magnitude cheaper than
   per-fault analysis at equal verdicts — positioned as verification
   engineering, citing BEC, FIRMER's Theorem 2 and detection equivalence as
   the nearest relatives.
3. **A design rule with a mechanical test:** every value the caller will read,
   and every input, must have a nonzero adjoint into the discrepancy
   (`Jd ≠ 0` at every load and store site of a memory-aware model). This is
   checkable in one reverse pass.

None of these is "an original algorithmic principle others can reuse" in the
sense the directive asks for. Item 2 is a reusable *technique*.

## 7. What would change the decision

**To GO**, all of:

1. Read the Boolean-difference, ABFT and AD-error-propagation literature and
   find no equivalent of S2/S3 for randomised checks. (Blocked here; needs the
   PDFs.)
2. A theorem that is not the chain rule. Candidates, none attempted:
   a canonical (coarsest) detection quotient with an efficient test for
   state-dependent templates; a class theorem for non-fault-linear sites via
   higher-order (Hasse) templates; multilinear templates for `k` simultaneous
   faults with a class structure on pairs.
3. Validity at ISA level: a memory-aware model whose template classes are
   confirmed by exhaustive emulation on at least one binary — including the
   vectorised build that currently breaks them.
4. One real-size kernel (closed-form templates for cyclic multiplication
   would make HQC-128 size feasible; this was not done).

**To STOP**: if (1) turns up the same construction, or if (3) shows that
template classes at ISA level are no coarser than per-instruction analysis.

## 8. Recommended next step

Supply the unread papers (list at the end of `PRIOR_ART_COLLISION_REPORT.md`).
That is the cheapest experiment with the largest effect on the decision. If
they do not anticipate S2/S3, the next technical step is (3): the memory-aware
model against the clang -O2 binary, because it attacks the weakest point of
the current result. Do not expand to full HQC decapsulation or another KEM
transform before then.

## 9. Reproduction

```
git checkout <revision recorded in data/structural_benchmarks.md>
pip install pytest==9.2.0 unicorn==2.1.4
python -m pytest                              # full suite
python tools/run_structural_benchmarks.py     # table in section 3
python tools/two_fault_study.py               # section 4.1
python tools/compiled_kernel_study.py         # section 4.2 (gcc 13.3.0, clang 18.1.3)
```

Environment of the recorded runs: Python 3.13.18, Linux x86-64, single
thread; CPU and source revision are written into each data file. Compiler
versions, flags and ELF SHA-256 digests are in
`data/compiled_kernel_study.md`; the binaries and disassembly are in
`data/compiled/`.

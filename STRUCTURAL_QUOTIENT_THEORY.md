# Structural Fault Quotients — theory

Status: definitions, algorithm, theorems with written proofs, counterexamples,
complexity. **Machine-checked in Coq (no axioms): Lemma L, Theorem S1, Lemma R,
and the root-set core of Theorem S2** (`proofs/coq/`, `proofs/README.md` lists
exactly what is and is not covered). S3–S5, the Region Theorem of §12, the
witness step and the soundness of the Python checkers are **not**
machine-checked. Every theorem's instances are
tested against full symbolic re-execution and, on small fields, against brute
force over every state, challenge and fault (`tests/test_structural.py`).

Level of all statements: the straight-line IR `toy-ir-v1`
(`specs/cafq_semantics.md` §1). Not C, not machine code; see §10.

The mathematical ingredients are classical: the chain rule, reverse-mode
differentiation, the Boolean-difference view of fault detection, and root
counting. §11 says which parts might be new and which are certainly not.

---

## 1. Setting

A program `P` over `F = GF(q)`, `q = 2^m`, is a list of `n` instructions
(`const`, `mov`, `add`, `mul`) on mutable registers. Read-only registers: the
state `x` and one challenge `R`. `P` declares outputs `out_1..out_o`, a
discrepancy register `disc`, optionally inconsistency registers.

*Site* `i` = instruction `i`. In the fault-free run write

* `v_i(x,R)` — the value instruction `i` writes to its destination;
* `w_i(x,R)` — the value the destination held just before (0 if never written).

All values are polynomial functions, kept reduced modulo `X^q = X`.

**Faults as additive perturbations.** Each in-scope fault `f` at site `i`
replaces `v_i` by `v_i + δ_f` and changes nothing else:

| kind | injected error `δ_f` |
|---|---|
| bit flip of bit `b` | the constant `2^b` |
| result-zero | `v_i` |
| skip | `v_i + w_i` |

(Characteristic 2: `v + v = 0`, and "keep the old value" is `v + (v + w)`.)

**Bad event** (unchanged from `specs/cafq_semantics.md`): `W_f(x,r) ≠ 0` and
`g_f(x,r) = 0`, where `g_f` is the faulted discrepancy and `W_f` the output
error together with the fault-free inconsistency values.

## 2. Fault-linear sites

**Definition.** Site `i` is *fault-linear* if, with everything computed before
site `i` held fixed, every final register value is an affine function of the
value written at site `i`.

**Lemma L (taint criterion).** Let `taint(reg)` be the set of sites the current
value of `reg` depends on through operand chains. If no `mul` instruction after
site `i` has `i` in the taint of *both* operands, then site `i` is
fault-linear.

*Proof.* Induction over the instructions after `i`. Each later value is either
independent of the value `t` written at `i`, or affine in `t` with coefficients
independent of `t`: `mov` and `add` preserve this; `mul` preserves it when at
most one operand depends on `t`, which is the hypothesis. ∎

The criterion is sufficient, not necessary. It is a bit-set dataflow pass: no
polynomial arithmetic.

## 3. Adjoint synthesis

For a final register `Φ` and a fault-linear site `i` define the *adjoint*
`∂_i Φ` as the coefficient of `t` in the affine function `t ↦ Φ`. It does not
depend on `t`.

**Theorem S1 (adjoint synthesis).** Let `i` be fault-linear and let `f` be any
fault whose only effect is to replace `v_i` by `v_i + δ_f`. Then, as functions
of `(x, R)`,

    out_j,f = out_j + δ_f · ∂_i out_j          g_f = g + δ_f · ∂_i disc.

*Proof.* `Φ(t) = α + β t` with `β = ∂_i Φ`; evaluate at `t = v_i + δ_f` and
subtract `Φ(v_i)`. ∎

**Lemma R (reverse pass).** Process instructions `n-1, …, 0` with a map
`adj[reg]`, initialised to a seed `s_Φ` on each observed register `Φ`. At
instruction `i` with destination `d`: let `A = adj[d]`, record `A_i = A`, clear
`adj[d]`, then `mov d,a`: `adj[a] += A`; `add d,a,b`: `adj[a] += A`,
`adj[b] += A`; `mul d,a,b`: `adj[a] += A·val(b)`, `adj[b] += A·val(a)` (operand
values from the fault-free forward pass); `const`: nothing. For every
fault-linear site `i`, `A_i = Σ_Φ s_Φ · ∂_i Φ`.

*Proof.* The chain rule, by downward induction on `i`: when instruction `i` is
reached, `adj[d]` is the sum over all later uses of the version of `d` written
at `i` of (adjoint of the using instruction's result) × (partial derivative of
that instruction in this operand). For fault-linear `i` these partials do not
depend on `t`, so the sum is the coefficient of `t`. ∎

Seeding with distinct formal tags `s_disc = T_d`, `s_{out_j} = T_j` gives all
`Jd_i := ∂_i disc` and `Jo_{i,j} := ∂_i out_j` in **one** pass.

**Counterexample C1 (first order is not enough; characteristic 2 makes it
worse).** `square_check`: the checker computes `y·y`. `∂(y²)/∂y = 2y = 0`, yet
a fault `δ` on `y` changes the discrepancy by `δ²·R`. A first-order template
would call the fault invisible to the checker. `nonlinear_trap`:
`disc = y(y + x₁) + x₀(x₀ + x₁)`; the adjoint is `x₁` but the true effect is
`δ(δ + x₁)`, which vanishes on the states `x₁ = δ`. A first-order template
would certify coverage that does not exist. Both sites fail Lemma L and are
excluded from Theorem S1.
*Evidence:* `test_COUNTEREXAMPLE_first_order_adjoint_is_wrong_at_nonlinear_sites`,
`test_first_order_modes_are_refused_at_nonlinear_sites`.

**Fallback for non-fault-linear sites.** Execute the program once with
`v_i + Δ` for a formal variable `Δ`; the observation is a polynomial in `Δ`
(its Taylor/Hasse expansion); substitute `Δ := δ_f` for each fault at the site.
One symbolic execution per *site* instead of per fault. Such faults then go
through the per-fault classifier; no template theorem is claimed for them.

## 4. Site templates

Call the program *homogeneous* if `g ≡ 0` (the check passes on every
fault-free run) and all inconsistency registers are identically 0. Then
`W_f = E_f = (out_f − out)`.

The *template* of a fault-linear site is the pair `(Jd_i, Jo_i)`.
Write `Jd_i = Σ_d c_d(x) R^d`.

**Site witness.** `Jo_i` is free of `R`, and either constants `M_{j,d}` are
given with `Jo_{i,j} = Σ_d M_{j,d} c_d` for all `j` (linear), or constants
`λ_d` with `Σ_d λ_d c_d = 1` (unit).

**Theorem S2 (template quotient).** Let `P` be homogeneous, `i` fault-linear
with a site witness, and `Jd_i = u(x)·R^k·h(x,R)` with `u` free of `R`. Let `f`
be **any** fault that replaces `v_i` by `v_i + δ` where `δ` does not depend on
`R`. Then for every state `x` with `E_f(x) ≠ 0`:

    { r : g_f(x,r) = 0 }  =  { r : h(x,r) = 0 } ∪ ( {0} if k > 0 ),

a set of at most `deg_R h + [k>0]` elements. If the `R`-coefficients of `h` are
constants, it is the fixed set `Z = roots_F(h) ∪ ({0} if k>0)` and
`Pr_r[undetected | wrong] = |Z|/q` exactly.

*Proof.* By S1, `E_{f,j} = δ·Jo_{i,j}` and `g_f = δ·Jd_i` (`g ≡ 0`). If
`E_f(x) ≠ 0` then `δ(x) ≠ 0` and `Jo_i(x) ≠ 0`. By the site witness not all
`c_d(x)` vanish, so `Jd_i(x,·)` is a nonzero polynomial of degree `< q`, hence
a nonzero function, hence `u(x) ≠ 0`. `δ(x)` and `u(x)` are nonzero scalars and
do not depend on `r`, so `g_f(x,r) = 0 ⇔ r^k h(x,r) = 0`. `h(x,·)` is a nonzero
function of degree `≤ deg_R h < q`. ∎

**What the theorem buys.**

1. *One analysis per template.* Witness, factorisation and root set depend on
   `(Jd_i, Jo_i)` only. Every fault of every kind at every site with that
   template inherits them; class membership is the equality of two
   polynomials the checker computed itself.
2. *δ-agnosticism.* The statement is universally quantified over the injected
   error. It covers the `m + 2` modelled faults per site **and** every other
   corruption of that one value by an `R`-independent error (multi-bit flips,
   stuck-at values, a glitched ALU result). Per-fault enumeration cannot give
   this; it certifies the faults it enumerates.
3. *The content is known, not searched.* Post-hoc quotienting had to discover
   `u` by polynomial division of `g_f` (and failed when `δ` had no common
   factor structure). Here `g_f = δ·Jd_i` exhibits the factor `δ` by
   construction, so structural classes are never finer than post-hoc L3
   classes and can be strictly coarser.

**Theorem S3 (unobserved sites).** Let `g ≡ 0`, `i` fault-linear, `Jd_i ≡ 0`,
and `δ_f`, `Jo_{i,j}` free of `R`. Then `g_f ≡ 0`, and `f` is a bypass at every
state `x*` with `δ_f(x*)·Jo_{i,j}(x*) ≠ 0`; if no such state exists for any
`j`, `f` is benign.

*Proof.* S1 with `Jd_i = 0`. ∎

A bypass is thus certified by one point evaluation instead of `2q` concrete
executions. This is what makes a *tautological* check (one that compares a
result only with data derived from the same corrupted values) visible
structurally: its data sites have `Jd = 0`.

**Sites that do not reach an output.** If `i` is fault-linear and `Jo_i = 0`,
and no inconsistency register is active, no fault at `i` can corrupt an
output. It is benign iff `δ_f·Jd_i ≡ 0`, otherwise "covered, no wrong output"
(detection status may change).

## 5. Compositionality

**Theorem S4 (chain rule across a cut).** Split `P = P₁ ; P₂` after instruction
`c`. Let `L` be the registers live at the cut and `a_w := ∂disc/∂w`
(`w ∈ L`) the adjoints obtained by the reverse pass over `P₂` alone. For every
fault-linear site `i ≤ c`,

    Jd_i = Σ_{w ∈ L} a_w · ∂_i w,

where `∂_i w` is computed inside `P₁` alone. Equivalently: the reverse pass
over `P₁` seeded with `(a_w)_{w∈L}` reproduces the whole-program adjoints.

*Proof.* Lemma R is a single backward recurrence; stopping it at `c` leaves
exactly `adj = (a_w)_{w ∈ L}`. ∎

Consequences:

* **Downstream summary.** Everything a context does to faults in a
  subcomputation is `|L|` polynomials. Changing `P₂` (a different checker)
  requires re-running the reverse pass on `P₂` and then `|P₁|` cheap
  propagation steps; `P₁` is not re-analysed.
* **Local summary.** `∂_i w` for `w` an output of a gadget is a property of
  the gadget. A gadget instantiated many times needs its internal Jacobian
  once.
* *Tested:* `test_adjoints_compose_across_a_cut`.

**Counterexample C2 (classes do not compose, templates do).** The class
invariant `(k, h)` of a composite is not a function of the class invariants
of its parts. Karatsuba's `m0` reaches `p0` (template `1`, class `h = 1`,
`k = 0`) and `p1` (template `R`, class `h = 1`, `k = 1`). Its own template is
the *sum* `1 + R`, class `h = 1 + R`: a new root at `r = 1` that neither part
has. Composition must be done on polynomials (adjoints); the quotient is taken
afterwards. Any scheme that composes class labels is unsound or needs the
labels to *be* the polynomials.

**Corollary S5 (one data fault + one checker fault).** Let `c` be a checker
fault and `P^c` the program with `c` applied. For a data fault `d` at a site
that is fault-linear in `P^c`:
`g_{d,c} = g_c + δ_d · ∂_i^{P^c} disc`. The mixed two-fault analysis therefore
costs one structural pass per checker fault, `O(F_c)` passes, instead of
`F_d · F_c` symbolic executions. *Tested* for skip/zero checker faults against
double-fault symbolic execution (`tools/two_fault_study.py`); results in §9.

## 6. The algorithm

```
STRUCTURAL-QUOTIENT(P, fault kinds)
 1  forward pass:      v_i, w_i, operand values, reference out, g, inc     n symbolic instr
 2  taint pass:        linear[i]                                           n bit-set steps
 3  tagged reverse:    Jd_i, Jo_i for all i                                n symbolic instr
 4  for each fault f at site i with injected error δ_f:
 5     δ_f ≡ 0                                   → benign          [mode delta-zero]
 6     not linear[i]                             → one Δ-run per site, substitute,
                                                   per-fault classifier        [synth]
 7     T ← template(Jd_i, Jo_i), analysed once per distinct pair
 8     Jo_i = 0, no inconsistency active         → benign / covered-no-wrong   [no-reach]
 9     site witness, P homogeneous, δ_f R-free   → covered, bound from T       [template]
10     Jd_i = 0, g ≡ 0, δ_f R-free               → bypass by a point, or benign [unobserved]
11     otherwise: out_f, g_f by S1 (≤ o+1 products), per-fault classifier     [synth]
```

The checker (`src/cafq/structural_checker.py`) repeats steps 1–3 itself,
validates each referenced template once, and for each fault checks the
preconditions of the claimed mode. It derives every fault's class key from the
template it validated; certificates carry no class field.

## 7. Soundness and completeness

**Theorem (soundness of accepted certificates).** If the structural checker
accepts a document for `P`, then every fault's stated classification is true
in the sense of `specs/cafq_semantics.md` §3: benign faults leave the
observation unchanged on all states and challenges; covered faults satisfy the
stated bound on every wrong state; bypass faults have the exhibited state.

*Proof sketch.* Per mode. *delta-zero*: `δ_f ≡ 0` is checked; the faulted run
is the fault-free run. *no-reach*, *template*, *unobserved*: the checker
establishes fault-linearity (Lemma L), computes the adjoints (Lemma R), checks
the mode's hypotheses, and Theorems S1–S3 give the conclusion; for *template*
the site witness and factorisation are verified by the same routine that
verifies per-fault certificates in the baseline checker, applied to
`(Jd_i, Jo_i)`. *synth*: the checker derives `(out_f, g_f)` by S1 at
fault-linear sites and by direct execution elsewhere, then applies the
baseline per-fault checks. ∎

This is a proof on paper about an implementation; the implementation is
tested, not verified.

**No unsound merge is expressible.** Two faults are in one class iff the
checker derived the same `(k, h)` for both from validated templates. A
generator cannot assert membership.

**Completeness, in the only sense claimed.** *Accounting:* the mode decision
is a total case split, so every in-scope fault receives exactly one
certificate, and the checker rejects any document whose fault set differs from
the declared fault space. *Not claimed:* that every coverable fault is
certified covered. Faults reaching step 11 or 6 inherit the incompleteness of
the per-fault witness search and may be `unknown`.

**Counterexample C3 (the quotient is not a security equivalence).** Two faults
in the same class at the same site of the Karatsuba multiplier, site `m0`,
template `1 + R`:

* bit flip: `δ = 1`. The output is wrong on every state.
* result-zero: `δ = a₀b₀`. The output is wrong iff `a₀b₀ ≠ 0`.

Same undetected-challenge set `{1}` on every wrong state — and different
everything else: the *event* "wrong" depends on the secret for one and not
the other; the unconditional non-detection probability over a uniform state
is `1/q` versus `(1 − (2q−1)/q²)/q`; the alarm itself reveals `[a₀b₀ ≠ 0]`
for the zero fault and nothing for the flip; the faulty outputs differ.
Theorem S2 preserves exactly one thing: the conditional undetected set.
*Evidence:* `test_COUNTEREXAMPLE_same_class_different_observations`.

Therefore: a class certificate is a statement about detection conditional on
an effective fault. It is not a statement about attacker observations,
ineffective-fault leakage, or key-recovery advantage. The generator records,
per fault, whether effectiveness or alarm status depends on the state
(`effect_depends_on_state`, `status_depends_on_state`); these are reported
separately and never bounded.

**Counterexample C4 (the unit-content quotient is not the coarsest sound
one).** Equal `(k, h)` is sufficient for equal undetected sets, not necessary.
Over GF(4) with `ω² = ω + 1`: `h₁ = 1 + R` and
`h₂ = (1 + R)(R² + R + ω)` have the same root set `{1}`, because
`R² + R + ω` is irreducible (trace of `ω` is 1). Two sites with these
templates are detection-equivalent and sit in different classes. For
constant-`h` templates the coarsest sound quotient is by the root set `Z`
itself, which the checker already computes; merging by `Z` is sound and was
not implemented. For state-dependent `h` the coarsest quotient is "same root
set for every wrong state", for which no efficient test is offered.
*Evidence:* `test_COUNTEREXAMPLE_unit_content_classes_are_not_the_coarsest_quotient`.

So the algorithm is sound and accounts for every fault, but it is **not
canonical**: it may produce more classes than necessary.

## 8. Complexity

Parameters: `n` instructions; `F = (m+2)·n` faults; `o` outputs; `T` distinct
templates (`T ≤ n`); `n_nl` non-fault-linear sites with `F_nl` faults; `F_s`
faults at fault-linear sites that fit no template (step 11); `X` = cost of one
"expensive analysis" (witness solve + factorisation + root set); `μ` = cost of
one polynomial multiplication at the sizes occurring.

| | symbolic instruction executions | expensive analyses | other |
|---|---|---|---|
| A: per fault, full re-execution | `(F+1)·n = Θ(m n²)` | `F` | — |
| A′: per fault, prefix cached | `≈ (F/2)·n` | `F` | `n` snapshots |
| B: A + post-hoc classes | as A | `F` (root sets: one per class) | — |
| C: structural, generator | `2n + n_nl·n` | `T + F_nl + F_s` | `n` bit-set steps of `n` bits; `≤ (o+1)` products per fault, 0 for template-mode faults with a constant output adjoint |
| C: structural, checker | `2n + F_nl·n` | `T + F_nl + F_s` validations | same |

Checkers for A, A′, B re-execute every fault: `(F+1)·n` again.

On a homogeneous, fully fault-linear program (`n_nl = F_s = 0`):

    cost(A) = Θ(m·n²·μ + m·n·X)      cost(C) = Θ(n·μ' + T·X + F·c)

with `μ'` the multiplication cost for tagged adjoints and `c` a small
constant. The ratio grows like `m·n`.

Honest caveats:

* **Adjoint size.** Tagged adjoints carry up to `o + 1` tag components and can
  be larger than forward values. On the benchmark circuits they are small
  (monomials in `R`, or a Horner evaluation); no bound is proved.
* **Degenerate cases.** If every site is non-fault-linear, C costs `n` Δ-runs:
  a factor `m + 2` better than A, no more. If the program is not homogeneous
  (the AR discrepancy circuit), only the symbolic execution is saved; every
  fault still needs its own classification.
* **`T` can equal `n`.** Then the saving in expensive analyses is the factor
  `m + 2` (faults per site) only.
* **Lower bound.** Any sound method reads the program: `Ω(n)`. C is `O(n)`
  symbolic instruction executions on fault-linear programs, i.e. optimal in
  that count up to a constant; nothing is claimed about polynomial sizes.

Measured values: `data/structural_benchmarks.md`, summarised in
`NOVELTY_AND_GO_NO_GO.md`.

## 9. Quantitative coverage and its limits

* **Single fresh challenge.** For `(f, x)` fixed before `r` is drawn, `r`
  uniform and independent: `Pr[bad] ≤ bound/q`, with equality `|Z|/q`
  conditional on a wrong state for constant-`h` templates.
* **`Q` attempts**: a union bound holds only with a fresh independent
  challenge per attempt (`specs/cafq_semantics.md` §5). Not otherwise.
* **Two faults.** The single-fault labels of checker faults are *not* stable
  under one additional data fault; see `data/two_fault_study.md`. In the four
  programs studied, every or nearly every checker fault labelled "benign" or
  "covered, no wrong output" either disables detection for some data fault on
  some state, or weakens a bound. Exactly two checker faults per program (skip
  or zero of the final discrepancy write) disable detection for every data
  fault on every state — and those two are precisely the checker faults the
  single-fault model labels **benign**: with `g ≡ 0`, not writing `disc`
  changes nothing until a second fault needs detecting.
* **"Bypass" is existential in the state.** For most two-fault pairs the
  bypass state is special (the two error terms cancel). Its density among
  states was not measured; where the state is secret and not adversarial this
  matters.

## 10. Outside the model

Memory, addressing, control flow, the challenge sampler and the consumer of
`disc` are not in the IR. Theorem S2's hypothesis is "the fault's only effect
is an `R`-independent additive error on one IR value". Whether a machine-level
fault satisfies it is an empirical question per binary. The compiled-kernel
study (`data/compiled_kernel_study.md`) enumerates every single dynamic
instruction skip of one compiled kernel and reports those that do not.

## 11. What is and is not new here

Certainly not new: fault effects as additive errors; the chain rule;
reverse-mode differentiation; detection of a line fault through the derivative
of the output with respect to that line (the Boolean difference, over GF(2));
root counting for fingerprints; fault equivalence and detection equivalence.

Possibly new as a combination (see `PRIOR_ART_COLLISION_REPORT.md` for what
could and could not be checked): computing detection-equivalence classes for a
*randomised algebraic check over GF(q)* from one reverse pass, with a
δ-agnostic class theorem (S2), an algebraic criterion for tautological checks
(S3), exact per-class non-detection probabilities, and certificates whose
class membership is derived by an independent checker rather than asserted.

---

## 12. Transport to compiled code: the Region Theorem

Added 16 Nov 2026. Level: one dynamic execution trace of one binary on one
ISA (x86-64 here), single instruction-skip faults. Everything in this section
is conditional on assumptions A1–A3, which are **tested, not proved**.

### 12.1 Setting

Fix a binary, a state `x` and the fault-free dynamic trace `I_0 … I_{N−1}`
(assumed independent of the data; checked). A *location* is a register or a
memory byte. A *definition* is a pair `(k, ℓ)`: instruction `k` writes
location `ℓ`. The **dynamic def-use graph** `G` has the definitions as nodes,
an edge `(k', ℓ') → (k, ℓ)` when `I_k` reads `ℓ'` and `(k', ℓ')` is the
reaching definition, and a sink `OBS` fed by the final definitions of the
observed bytes (outputs and the discrepancy).

A write that may leave part of the old content in place — an 8/16-bit
register write, a conditional move, a partial flag update — is modelled as
also *reading* the old content. Only whitelisted full overwrites kill.

A definition has a **bad use** if some instruction uses it to form a memory
address or to steer control flow.

Let `M` be a memory-aware IR program for the same computation (explicit load
and store sites), with structural site certificates.

A definition `E = (e, ℓ)` is a **realisation point of IR site `i`** if, for
every byte value `v'`, replacing the low byte of `ℓ` by `v'` right after
`I_e` makes the final observation equal to the IR observation with the value
of site `i` replaced by `v'`, and the remaining bits of `ℓ` do not influence
the observation.

### 12.2 Assumptions

* **A1 (graph soundness).** Every dependence of an instruction's effect on a
  location is an edge of `G`, and every address/control use is marked.
* **A2 (realisation).** The definitions used as realisation points are
  realisation points in the sense above, for all values `v'`.
* **A3 (fault semantics).** Skipping `I_k` leaves every location `I_k` would
  have written with its previous content and changes nothing else.

### 12.3 Theorem

**Region Theorem.** Let `k` be a dynamic instruction, `D_k` its definitions
that reach `OBS`. Suppose

1. no definition of `I_k` reaches a bad use;
2. a realisation point `E` of IR site `i` post-dominates every node of `D_k`
   with respect to `OBS`;
3. `E`, and the definitions overwritten by `I_k`, are not reachable from the
   challenge input.

Then under A1–A3 the skip of `I_k` produces exactly the observation of the IR
program `M` with the value of site `i` replaced by `v_i + δ` for some `δ`
that does not depend on the challenge. Consequently the site certificate of
`i` applies verbatim:

* template site: either the output is unchanged, or it is wrong for every
  challenge and the undetected set is exactly `roots(Jd_i(x, ·))`;
* checker-blind site (`Jd_i = 0`, Theorem S3): either unchanged, or wrong and
  undetected for **every** challenge;
* site that does not reach an output: the output is never wrong.

If `D_k` is empty the skip has no effect on the observation; if no definition
of `I_k` reaches an output byte the output is never wrong.

*Proof.* By A3 the faulted run differs from the fault-free run first in the
contents of the locations `I_k` writes. By (1) and A1 no later address or
branch decision changes, so the same instructions execute on the same
locations and the difference propagates only along edges of `G`. By (2) every
path from those definitions to `OBS` passes through `E`, so the final
observation is a function of the fault-free state and of the content of `ℓ`
after `I_e`. By A2 it is the IR observation with site `i` holding the low
byte `v'` of that content; put `δ = v' − v_i`. `v'` is computed from
definitions that are ancestors of `E` and from the stale contents left by the
skip; by (3) none depends on the challenge, hence neither does `δ`. Now
Theorem S2 (or S3, or the no-reach rule) applies, because it holds for every
challenge-independent error at the site. ∎

The bridge is δ-agnosticism: the machine fault need not *be* any IR fault
kind. It only has to be *some* error on one IR value.

### 12.4 Algorithm and what it costs

`src/cafq/binquot.py`: trace on a few training inputs; build `G`; pick
candidate realisation points by value matching against the IR; **validate**
each by injecting 10 errors plus an upper-bits probe for every challenge;
compute post-dominators; classify each skip or report it *outside coverage*
with the reason.

Per-fault emulation costs `N · |challenges|` suffix runs. The quotient costs
`(#candidates) · 11 · |challenges|` suffix runs plus a handful of traced runs.
It wins only when the binary has many instructions per IR value.

### 12.5 Evidence (`data/binary_quotient_study.md`)

Same binaries, state, challenges and fault model as the per-fault ground
truth; a prediction counts as unsound if the ground truth contradicts it.

| Build | Dynamic instrs | Covered | of which assigned to an IR site | Unsound predictions | Complete bypasses: predicted checker-blind / outside / predicted safe |
|---|---|---|---|---|---|
| gcc 13.3.0 -O2 | 895 | 79.7 % | 236 | 0 | 7 / 0 / 0 |
| clang 18.1.3 -O2 | 459 | 68.4 % | 44 | 0 | 5 / 2 / 0 |
| gcc 13.3.0 -O0 | 1,372 | 78.9 % | 390 | 0 | 14 / 5 / 0 |

Among covered skips that corrupt the output (139, 30 and 267 respectively)
every one behaved exactly as predicted: the site's root set for template
sites, all 256 challenges for checker-blind sites.

Cost, same machine: per-fault emulation needed between 0.6× and 2.1× the
suffix emulations of the quotient, and between 1.1× and 2.1× its wall-clock. **This is not a decisive
cost reduction**, and on the vectorised build the quotient performed *more*
emulations than the brute force.

### 12.6 Counterexamples and limits

**Counterexample C5 (A1 is not free: the disassembler's write set is not a
kill set).** The first version took "written" to mean "overwritten". For
`cmovne eax, ebp` the destination is listed as written only, although the old
value survives when the condition is false. The graph lost an edge, a
definition appeared to be post-dominated by an output store, and one skip in
the clang build was predicted checker-blind while the ground truth showed it
detected for 127 of 256 challenges. Found by the ground-truth comparison;
fixed with an explicit kill whitelist; regression test
`test_REGRESSION_conditional_move_does_not_kill_its_destination`.

Lesson: A1 needs a formal ISA semantics, not a disassembler's operand
annotations. Until then the Region Theorem's conclusions on a binary are
exactly as trustworthy as that instruction model.

**Counterexample C6 (fields, not rings).** With a reducible modulus the
arithmetic is a ring with zero divisors and no root bound holds:
`δ·r = 0` has two solutions `r` out of four over `GF(2)[x]/(x²+1)` for
`δ = x+1`. The trusted checker accepted transplanted certificates over such
a modulus until it was made to verify irreducibility
(`tests/test_checker_field_validation.py`). Reported by external review.

Limits of §12 as it stands:

* **A2 is tested for 10 errors on one state.** It is translation validation
  by testing, not a proof.
* **One state.** Predictions and ground truth are both at one fixed state;
  nothing is claimed for others.
* **Coverage is 68–80 %.** Stack and control instructions, loop counters,
  values that feed several IR sites before any single location holds them,
  and everything inside vectorised code are outside.
* **13–16 of 29 IR sites have no realisation point** in the -O2 binaries
  (copies and Horner intermediates that never occupy a location of their
  own); faults there are attributed to a neighbouring site or left outside.
* **Skip faults only**, x86-64 only, emulated only. No ARM, no physical fault.
* **Not a certificate.** There is no independent checker for the binary
  quotient; its output is a prediction table that was compared with brute
  force, nothing more.

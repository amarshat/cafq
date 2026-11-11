# CAFQ semantics, theorems and proofs (toy-ir-v1)

Level of these statements: the IR below. Not C, not LLVM, not machine code.

## 1. Programs and faults

A program `P` over `F = GF(q)`, `q = 2^m`, is a straight-line list of
instructions over mutable registers initialised to 0:

    const dst, imm | mov dst, a | add dst, a, b | mul dst, a, b

Read-only registers: the inputs `x = (x_1..x_n)` (the *state*) and one
*challenge* register `R`. `P` declares output registers `out`, a discrepancy
register `disc`, and optionally inconsistency registers `inc`.

A *fault* is `(kind, site[, bit])` applied to exactly one instruction:

| kind | semantics |
|---|---|
| `skip` | the instruction is not executed; `dst` keeps its previous value |
| `zero` | the instruction's result is replaced by 0 |
| `bitflip` | the instruction executes, then bit `bit` of `dst` is flipped |

The in-scope fault set is every instruction × {skip, zero, bitflip × m bits}.
Programs are straight-line, so static and dynamic sites coincide.

Out of scope (no instruction exists to fault): control flow, memory
addressing, the sampling of `R`, anything consuming `disc`.

Reference implementation: `src/cafq/ir.py::run`. The checker has its own.

## 2. Observation and bad event

`Exec(P, x, r; f)` is the final register map. Write

* `out_f(x, r)`, `g_f(x, r) = disc` for the faulted run, `out_∅`, `g_∅` for
  the fault-free run;
* **wrongness** `W_f(x, r) = (out_f − out_∅) ‖ inc_∅` — the output error
  caused by the fault, together with the fault-free values of the
  inconsistency registers (non-zero means the *input* is inconsistent, as in
  the AR discrepancy circuit).

Modelled observation: `(out_f, [g_f ≠ 0])`. Timing, retries and side channels
are **not** modelled.

**Bad event** for `(f, x, r)`: `W_f(x, r) ≠ 0` and `g_f(x, r) = 0`
("wrong and undetected").

Each register is a polynomial function of `(x, R)`. All polynomials are kept
reduced modulo `X^q = X`, so two reduced polynomials are equal iff they are
equal as functions on `F^{n+1}`; in particular every reduced polynomial has
`R`-degree `< q`.

## 3. Classification

Every in-scope fault receives exactly one of:

* **benign** — `out_f = out_∅` and `g_f = g_∅` as functions.
* **covered** — either `W_f ≡ 0` (no wrong output exists; bound 0; the
  detection status may still change, see §6), or a *witness* below exists.
* **bypass** — a state `x*` is exhibited with `W_f(x*, r) ≠ 0` and
  `g_f(x*, r) = 0` for **all** `r`.
* **unknown** — none of the above was established. No claim.

Write `g_f = Σ_d g_d(x) R^d` (reduced, so `d < q`).

**Linear witness.** `W_f` does not involve `R`, and constants `M_{j,d} ∈ F`
are given with `W_j = Σ_d M_{j,d} g_d` for every component `j`.

**Unit witness.** Constants `λ_d` are given with `Σ_d λ_d g_d = 1`.

## 4. Theorems

**Theorem 1 (per-fault bound).** Let `f` have a linear or unit witness and
let `e = deg_R g_f < q`. For every state `x` with `W_f(x) ≠ 0` (linear) or
every state `x` (unit),

    #{ r ∈ F : g_f(x, r) = 0 } ≤ e.

Consequently, if `(f, x)` is fixed and `r` is uniform on `F` and independent
of `(f, x)`, then `Pr[bad event] ≤ e / q`.

*Proof.* Linear case: if all `g_d(x) = 0` then `W_j(x) = Σ M_{j,d} g_d(x) = 0`
for all `j`, contradicting `W_f(x) ≠ 0`. Unit case: `Σ λ_d g_d(x) = 1` rules
out all `g_d(x) = 0`. Either way `g_f(x, ·)` is a nonzero univariate
polynomial of degree at most `e < q`, so it has at most `e` roots. ∎

**Theorem 2 (unit-content quotient).** Suppose in addition

    g_f = u(x) · R^k · h(x, R)          (as functions; u does not involve R).

Then for every state `x` in the scope of Theorem 1,

    { r : g_f(x, r) = 0 } = { r : h(x, r) = 0 } ∪ ( {0} if k > 0 ),

and the right-hand side has at most `deg_R h + [k > 0]` elements.

*Proof.* For such `x`, `g_f(x, ·)` is not the zero function (Theorem 1), so
`u(x) ≠ 0`. `F` is a field, hence `g_f(x, r) = 0 ⇔ r^k h(x, r) = 0 ⇔
(k > 0 ∧ r = 0) ∨ h(x, r) = 0`. `h(x, ·)` is not the zero function (else
`g_f(x, ·)` would be), and has degree `≤ deg_R h < q`. ∎

**Corollary 3 (exact classes).** If moreover all `R`-coefficients of `h` are
constants, then for every in-scope `x` the undetected set equals the fixed
set `Z = roots_F(h) ∪ ({0} if k > 0)`, and
`Pr[undetected | wrong] = |Z| / q` **exactly**, for every fault whose
certificate has this `(h, [k > 0])`.

Remarks.

1. Theorem 2 can be strictly tighter than Theorem 1: `g = δ·R^5` has
   `e = 5` but `|Z| = 1`.
2. The relation "same `(k, h)`" is the *detection-equivalence* of the work
   package with unit `u(x)`; it is sound because the witness forces
   `u(x) ≠ 0` exactly on the states that matter. It says nothing about the
   outputs, the keys derived from them, or leakage: two faults in one class
   generally produce different wrong outputs.
3. Quotient levels used in the measurements:
   L1 identical `(out_f, g_f)` (ordinary exact-effect collapsing);
   L2 `g_f` equal up to a nonzero constant;
   L3 same `(k, h)`;
   L4 same `(h, [k > 0])`.
   L1 ⊆ L2 ⊆ L3 ⊆ L4 as partitions (each refines the next).

## 5. Adversary and probability model

Theorem 1 is a statement about one fault, one state and one challenge with:

* `(f, x)` fixed before `r` is sampled; `r` uniform on `F`; `r` independent
  of `(f, x)`; the adversary learns nothing about `r` before the run ends.

**`Q` attempts.** If attempt `i` uses a *fresh* `r_i`, uniform and independent
of everything chosen up to and including `(f_i, x_i)` (which may depend on
earlier outcomes), then `Pr[some attempt is bad] ≤ Σ_i e_i / q` by the union
bound applied to the conditional probabilities. This does **not** apply when
the challenge is `ρ = PRF(z, c)`: repeating `c` repeats `ρ`, so `Q` repeats
are one trial, and outcomes on related inputs may leak information about a
reused challenge. No multi-fault statement is made.

## 6. Limits that the classification makes explicit

* **False alarms / ineffective faults.** A covered fault with `W_f ≡ 0` never
  yields a wrong output but can change the detection status. If `g_f`
  depends on `x`, the status is a function of the (possibly secret) state.
  Certificates carry `flags.status_depends_on_state`; nothing is bounded.
* **Checker faults are benign only in the single-fault model.** A fault that
  disables the check without corrupting data is "covered, no wrong output".
  Combined with a second fault it is a bypass. Not analysed.
* **Bypass is a per-state notion.** A fault labelled bypass may be detected
  on other states; a fault labelled covered is covered on all states.
* **Completeness.** The witness search is incomplete (linear/unit witnesses;
  bypass search exact for affine `g_d`, exhaustive for `q^n ≤ 2^16`, random
  otherwise). Failure yields `unknown`, never `covered`.

## 7. Trusted base

`src/cafq/checker.py` (standard library only) re-derives `out_f`, `g_f`, `W_f`
symbolically and verifies: hashes and manifest completeness; benign
equalities; witness identities; the factorisation `g = u·R^k·h` with `u`
free of `R`; bounds; exact root sets by enumeration; bypass states by
concrete execution over all `r`; and, for every class at every level, that
any two members satisfy that level's relation. The analyzer, its polynomial
code and its searches are untrusted.

The written proofs above are not machine-checked. Their instances are
checked by brute force in `tests/test_cafq_soundness.py`.

# proofs/

## Machine-checked (Coq 8.18.0; `proofs/coq/check.sh`; no axioms)

Lean was requested; its toolchain host was not reachable from this
environment, so Coq was used. The statements are assistant-independent.

| Theorem (Coq name) | File | Informal statement | Corresponds to |
|---|---|---|---|
| `tangent_exact` | `Propagation.v` | If two register maps differ by `delta*c` and no later multiplication has both operand coefficients nonzero, they differ by `delta*tangent(c)` after the program. Any commutative ring, any `delta` | core of S1 |
| `taint_sound` | `Propagation.v` | The taint pass over-approximates the tangent's support; "no multiplication with two tainted operands" implies the linearity condition | Lemma L |
| `fault_effect` | `Propagation.v` | Replacing the value written at a site by value + `delta` changes every later register by exactly `delta*J`, `J` independent of `delta` | Theorem S1 |
| `duality`, `reverse_is_forward` | `Propagation.v` | The reverse pass (take destination adjoint, clear it, add it times the partial to each operand) computes that `J` | Lemma R |
| `fault_effect_reverse` | `Propagation.v` | S1 with the reverse-pass adjoint, as the generator and the checker use it | S1 + R |
| `undetected_set` | `Detection.v` | Over a field, with `d != 0`, `u != 0`: the roots of `(d*u)*X^k*h` are `{0 if k>0}` together with the roots of `h` | Theorem 2 / S2 |
| `same_class` | `Detection.v` | Two faults with the same `(k, h)` at a state have the same undetected set there, whatever their injected errors | δ-agnosticism |
| `undetected_bound` | `Detection.v` | Any duplicate-free list of such roots has at most `deg h + [k>0]` elements | Theorems 1–2 |

`Detection.v` uses mathcomp 2.1.0 (`max_poly_roots`). `Propagation.v` uses
the standard library only.

### What the mechanisation does not cover

* **The implementations.** The proofs are about Coq definitions that mirror
  the IR semantics and the reverse pass. Nothing proves the Python generator
  or checker implements them. The link is by tests.
* **Pointwise versus polynomial.** The Coq statements are pointwise in the
  state and challenge. The code compares polynomials reduced modulo
  `X^q = X`; that these represent the same thing uses that GF(q) is a field
  with `q` elements. Argued on paper only.
* **The witness step**: "output wrong at `x`" implies `d != 0` and `u != 0`.
  A linear-combination argument; paper only.
* **Fields.** `Detection.v` assumes a field. The trusted checker now verifies
  that the modulus is irreducible; before the fix described in
  `research/weekly_decision_log.md` (#26) it did not, and accepted a false
  bound.
* **Probability.** No probability space is formalised. The theorems bound
  the *number* of undetected challenges; dividing by `q` for a uniform
  independent challenge is on paper.
* Unobserved-site theorem S3, composition S4 (immediate from `duality`, not
  stated), two-fault corollary S5, and everything about binaries.

## Paper proofs with instance checks

| Statement | Where | Evidence |
|---|---|---|
| GF(2^8) is a field with the stated modulus | `tests/test_field.py` | Exhaustive |
| Preimage bound for non-constant difference polynomials | `specs/field_and_discrepancy.md` Lemma 2 | Written proof; exhaustive families |
| S3, S4, S5; soundness of accepted certificates | `STRUCTURAL_QUOTIENT_THEORY.md` | Written proofs; brute force on small fields; symbolic cross-checks |
| Region theorem for compiled code | `STRUCTURAL_QUOTIENT_THEORY.md` §12 | Written proof under stated assumptions; tested against exhaustive emulation |

## Refuted / unproved

| Statement | Status |
|---|---|
| H-AR IND-CCA | **Refuted** as specified (`research/counterexamples.md` CE-2) |
| Shifted H-AR IND-CCA | **Unproved** (`research/proof_obligations.md`) |

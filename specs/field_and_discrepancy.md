# Field and discrepancy

## Field

`F = GF(2^8) = GF(2)[x] / (x^8 + x^4 + x^3 + x + 1)`, modulus `0x11B`.
Elements are integers 0..255, bit `i` is the coefficient of `x^i`. Addition
and subtraction are XOR. Implementation: `src/toy/gf256.py` (two independent
multipliers). Checks: `tests/test_field.py` (irreducibility; all 65,536
pairs; all 16,777,216 triples for associativity and distributivity).

The CAFQ prototype also uses GF(4), GF(8), GF(16) with moduli `0b111`,
`0b1011`, `0b10011` (`src/cafq/field.py`) so that whole state spaces can be
enumerated.

## Discrepancy

For `c, c' ∈ F^N`, `d = c − c'`, and an exponent offset `s ∈ {0, 1}`:

    D_ρ(c, c') = Σ_{i=0}^{N−1} d_i ρ^{i+s}

`s = 0` is the work-package definition (H-AR). `s = 1` is the "shifted"
variant studied only because of Fact 1.

**Fact 0 (honest path).** `c = c'` gives `D_ρ = 0` for every ρ.

**Fact 1 (zero challenge entropy; mandatory falsifier).** For `s = 0` and
`d = (δ, 0, …, 0)`, `D_ρ = δ` for every ρ. The distribution of `D` over a
uniform ρ is a point mass: min-entropy 0. At the same time `Pr[D = 0] = 0`,
the best possible root bound. A small root probability therefore says nothing
about the entropy of `D`.
*Check:* `test_REGRESSION_constant_difference_has_zero_challenge_entropy`
(all 255 δ, all 256 ρ, N = 3..6).

**Fact 2 (roots exist).** `d = (ab, a+b, 1)` gives `D = (ρ+a)(ρ+b)`, which is
0 for `ρ ∈ {a, b}`. An inconsistent ciphertext with this difference is
treated as consistent for 2 of 256 challenges.

**Lemma 1 (root bound; Schwartz–Zippel, univariate case).** If `d ≠ 0` then
`#{ρ : D_ρ = 0} ≤ deg ≤ N − 1 + s`.

**Lemma 2 (preimage bound; the valid replacement for "roots ⇒ entropy").**
If the polynomial `g(X) = Σ d_i X^{i+s}` is **non-constant** of degree `e`,
then for every `y ∈ F`, `#{ρ : g(ρ) = y} ≤ e`, hence for uniform ρ

    H_∞(D) ≥ log2(q / e).

*Proof.* `g(X) − y` is a nonzero polynomial of degree `e`. ∎
The hypothesis "non-constant" is exactly what Fact 1 violates when `s = 0`.
For `s = 1` every nonzero `d` gives a non-constant `g`, but then `ρ = 0` is a
root of every `g` (Fact 3).

**Fact 3 (universal root of the shifted variant).** For `s = 1`, `ρ = 0`
gives `D = 0` for every `d`. With probability `1/q` over ρ an arbitrary
inconsistent ciphertext is indistinguishable from a consistent one.

**Fact 4 (monomials).** For `d = δ e_i` and `i + s ≥ 1`, `D = δ ρ^{i+s}`
takes `(q−1)/gcd(i+s, q−1)` nonzero values, each `gcd(i+s, q−1)` times. The
entropy of `D` is coordinate dependent.

## What these facts do and do not give

* Lemma 1 bounds the probability that an inconsistent pair is *accepted*.
* Lemma 2 bounds the *predictability of D* for one ciphertext, one uniform
  hidden ρ, and a non-constant difference polynomial.
* Neither is a statement about IND-CCA security, about repeated queries
  (ρ = PRF(z, c) repeats with c), or about faults.
* `q = 256` is a toy size. For any polynomial variant the adversary can
  enumerate all `q` values of `D` unless `q` is cryptographically large
  (`research/counterexamples.md`, CE-3).

"""Discrepancy-polynomial facts, each checked exhaustively over all 256 rho
(and over all field elements where stated)."""
import itertools
import math

import pytest

from toy import gf256 as F
from toy.discrepancy import (difference, discrepancy, min_entropy_bits, roots,
                             value_distribution)

N_RANGE = range(3, 7)  # the 3..6 ciphertext elements the work package asks for


@pytest.mark.parametrize("n", N_RANGE)
def test_consistent_ciphertext_gives_zero_for_every_rho(n):
    c = [(17 * i + 5) % 256 for i in range(n)]
    assert all(discrepancy(c, list(c), rho) == 0 for rho in range(256))


@pytest.mark.parametrize("n", N_RANGE)
def test_REGRESSION_constant_difference_has_zero_challenge_entropy(n):
    """Mandatory falsifier (work package sec. 2 and check 1): for
    c - c' = (delta, 0, ..., 0), D = delta for EVERY rho. Checked for all
    255 nonzero delta."""
    for delta in range(1, 256):
        dist = value_distribution([delta] + [0] * (n - 1))
        assert dist == {delta: 256}
        assert min_entropy_bits(dist) == 0.0
        # ... while the Schwartz-Zippel style root bound is as good as it
        # can be: Pr[D = 0] = 0. Low root probability, zero entropy.
        assert roots([delta] + [0] * (n - 1)) == []


def test_nonconstant_polynomial_with_roots():
    """(X + a)(X + b) = ab + (a+b)X + X^2 has exactly the roots {a, b}."""
    a, b = 0x53, 0xCA
    diff = [F.mul(a, b), a ^ b, 1]
    assert roots(diff) == sorted([a, b])
    # so an inconsistent ciphertext with this difference is *accepted as
    # consistent* (D = 0) for 2 of the 256 challenges.
    assert value_distribution(diff)[0] == 2


@pytest.mark.parametrize("n", N_RANGE)
def test_root_count_never_exceeds_degree_sampled_and_structured(n):
    # all differences supported on values {0,1,2} (3^n of them) ...
    for diff in itertools.product(range(3), repeat=n):
        if any(diff):
            deg = max(i for i, d in enumerate(diff) if d)
            assert len(roots(list(diff))) <= deg
    # ... and the worst case is attained: product of (X + a_i) splits fully.
    poly = [1]
    for a in range(1, n):
        poly = [0] + poly
        for i in range(len(poly) - 1):
            poly[i] ^= F.mul(a, poly[i + 1])
    assert len(roots(poly)) == n - 1


@pytest.mark.parametrize("n", N_RANGE)
def test_preimage_bound_for_nonconstant_difference(n):
    """The VALID replacement for the invalid 'SZ => entropy' step:
    a nonconstant polynomial of degree d takes each value at most d times,
    so H_min(D) >= log2(256/d). Checked on all single- and double-term
    differences with coefficients in {1, 0x1D, 0xFF}."""
    vals = (1, 0x1D, 0xFF)
    for i, j in itertools.combinations_with_replacement(range(n), 2):
        for a in vals:
            for b in vals:
                diff = [0] * n
                diff[i] ^= a
                diff[j] ^= b
                if not any(diff[1:]):
                    continue  # constant (or zero) polynomial: no bound
                deg = max(k for k, d in enumerate(diff) if d)
                dist = value_distribution(diff)
                assert max(dist.values()) <= deg
                assert min_entropy_bits(dist) >= math.log2(256 / deg) - 1e-12


def test_monomial_entropy_depends_on_gcd_with_255():
    """delta * rho^i takes 255/gcd(i,255) nonzero values, each gcd(i,255)
    times: entropy is NOT uniform across coordinates."""
    for i in range(1, 6):
        dist = value_distribution([0] * i + [0x9A])
        g = math.gcd(i, 255)
        assert dist[0] == 1
        assert sorted(set(v for k, v in dist.items() if k)) == [g]


@pytest.mark.parametrize("n", N_RANGE)
def test_shifted_variant_removes_the_constant_term(n):
    """With exponents starting at 1 there is no rho-independent coordinate:
    every single-coordinate difference is a bijection or gcd-to-1 map of rho."""
    for i in range(n):
        dist = value_distribution([0] * i + [0x4E] + [0] * (n - 1 - i), shift=1)
        assert max(dist.values()) <= i + 1
    # but rho = 0 is now a universal root: D = 0 for every difference.
    assert discrepancy([1, 2, 3], [9, 9, 9], 0, shift=1) == 0


def test_difference_rejects_length_mismatch():
    with pytest.raises(ValueError):
        difference([1, 2], [1])

"""The H-AR discrepancy D_rho(c, c') = sum_i (c_i - c'_i) rho^(i+shift) over GF(2^8).

``shift=0`` is the work-package definition. ``shift=1`` is the variant with no
constant term, studied because the constant term is unconditionally
rho-independent (see research/counterexamples.md, CE-1).
"""
from __future__ import annotations

import math
from collections import Counter

from . import gf256 as F


def difference(c: list[int], cp: list[int]) -> list[int]:
    if len(c) != len(cp):
        raise ValueError("length mismatch")
    return [a ^ b for a, b in zip(c, cp)]


def discrepancy(c: list[int], cp: list[int], rho: int, shift: int = 0) -> int:
    d = difference(c, cp)
    return F.poly_eval([0] * shift + d, rho)


def value_distribution(diff: list[int], shift: int = 0) -> Counter:
    """Exact distribution of D over all 256 values of rho."""
    coeffs = [0] * shift + list(diff)
    return Counter(F.poly_eval(coeffs, rho) for rho in range(256))


def min_entropy_bits(dist: Counter) -> float:
    total = sum(dist.values())
    return -math.log2(max(dist.values()) / total)


def roots(diff: list[int], shift: int = 0) -> list[int]:
    coeffs = [0] * shift + list(diff)
    return [rho for rho in range(256) if F.poly_eval(coeffs, rho) == 0]

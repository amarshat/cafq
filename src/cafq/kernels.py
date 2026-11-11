"""Larger arithmetic kernels for the structural-quotient experiments.

cyclic_mul is an HQC-STYLE kernel only in shape: multiplication in
F[x]/(x^n - 1) by schoolbook product followed by cyclic folding, with a
fingerprint derived from the exact unreduced relation

    a(X) b(X) = c(X) + (X^n - 1) * hi(X),   hi(X) = sum_{k>=n} p_k X^(k-n).

HQC works over GF(2) with n = 17669 and a sparse operand; here coefficients
live in GF(2^m), n is tiny, and both operands are dense. GF(2) coefficient
vectors are the states with all inputs in {0, 1}; every 'covered' statement
holds for all states and therefore for those, while a 'bypass' state found
over GF(2^m) need not be binary.
"""
from __future__ import annotations

from .circuits import _horner
from .field import MODULI
from .ir import Instr, Program


def cyclic_mul(n: int, m: int = 8, weak: bool = False) -> Program:
    a = [f"a{i}" for i in range(n)]
    b = [f"b{i}" for i in range(n)]
    p = [f"p{k}" for k in range(2 * n - 1)]
    c = [f"c{k}" for k in range(n)]
    ins = []
    for i in range(n):
        for j in range(n):
            ins.append(Instr("mul", "t", a[i], b[j], "data"))
            ins.append(Instr("add", p[i + j], p[i + j], "t", "data"))
    for k in range(n - 1):
        ins.append(Instr("add", c[k], p[k], p[k + n], "fold"))
    ins.append(Instr("mov", c[n - 1], p[n - 1], None, "fold"))
    # checker
    ins += _horner("ec", c, "R", "check")
    ins += _horner("ehi", p[n:], "R", "check")
    ins.append(Instr("mov", "rn", "R", None, "check"))
    for _ in range(n - 1):
        ins.append(Instr("mul", "rn", "rn", "R", "check"))
    ins.append(Instr("const", "one", 1, None, "check"))
    ins.append(Instr("add", "rn", "rn", "one", "check"))          # R^n - 1
    ins.append(Instr("mul", "ehi", "ehi", "rn", "check"))
    ins.append(Instr("add", "rhs", "ec", "ehi", "check"))
    if weak:
        # TAUTOLOGICAL variant: compares the folded result only against the
        # unreduced product it was folded from. The multiplication itself is
        # not checked at all.
        ins += _horner("lhs", p, "R", "check")
    else:
        ins += _horner("ea", a, "R", "check")
        ins += _horner("eb", b, "R", "check")
        ins.append(Instr("mul", "lhs", "ea", "eb", "check"))
    ins.append(Instr("add", "disc", "lhs", "rhs", "check"))
    name = f"cyclic_mul_n{n}" + ("_weakcheck" if weak else "")
    return Program(name, m, MODULI[m], a + b, "R", ins, c, "disc")

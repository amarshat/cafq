"""Circuit builders for toy-ir-v1. All checks used here are KNOWN techniques
(polynomial-evaluation fingerprints, Freivalds-style linear checks); they are
subjects of analysis, not contributions."""
from __future__ import annotations

from .field import MODULI
from .ir import Instr, Program


def _horner(dst: str, coeffs: list[str], R: str, region: str) -> list[Instr]:
    """dst := sum coeffs[i] * R^i."""
    ins = [Instr("mov", dst, coeffs[-1], None, region)]
    for c in reversed(coeffs[:-1]):
        ins.append(Instr("mul", dst, dst, R, region))
        ins.append(Instr("add", dst, dst, c, region))
    return ins


def ar_discrepancy(n: int, m: int = 8, shift: int = 0) -> Program:
    """The H-AR discrepancy D = sum (c_i + c'_i) R^(i+shift), marshalled into
    the KDF input register. No algebraic output: wrongness is input
    inconsistency (some c_i != c'_i)."""
    c = [f"c{i}" for i in range(n)]
    cp = [f"cp{i}" for i in range(n)]
    w = [f"w{i}" for i in range(n)]
    ins = [Instr("add", w[i], c[i], cp[i], "diff") for i in range(n)]
    ins += _horner("acc", w, "R", "check")
    for _ in range(shift):
        ins.append(Instr("mul", "acc", "acc", "R", "check"))
    ins.append(Instr("mov", "kdf_in", "acc", None, "marshal"))
    return Program(f"ar_discrepancy_n{n}_shift{shift}", m, MODULI[m], c + cp, "R",
                   ins, [], "kdf_in", w)


def _fingerprint(a, b, p, ins) -> list[Instr]:
    ins = list(ins)
    ins += _horner("ea", a, "R", "check")
    ins += _horner("eb", b, "R", "check")
    ins += _horner("ep", p, "R", "check")
    ins.append(Instr("mul", "eab", "ea", "eb", "check"))
    ins.append(Instr("add", "disc", "eab", "ep", "check"))
    return ins


def polymul_schoolbook(n: int, m: int = 8) -> Program:
    """p = a * b (2n-1 coefficients) with fingerprint a(R)b(R) + p(R) == 0."""
    a = [f"a{i}" for i in range(n)]
    b = [f"b{i}" for i in range(n)]
    p = [f"p{k}" for k in range(2 * n - 1)]
    ins = []
    for i in range(n):
        for j in range(n):
            ins.append(Instr("mul", "t", a[i], b[j], "data"))
            ins.append(Instr("add", p[i + j], p[i + j], "t", "data"))
    return Program(f"polymul_schoolbook_n{n}", m, MODULI[m], a + b, "R",
                   _fingerprint(a, b, p, ins), p, "disc")


def polymul_karatsuba2(m: int = 8) -> Program:
    """2x2 Karatsuba: shared intermediates fan out to several outputs."""
    a, b, p = ["a0", "a1"], ["b0", "b1"], ["p0", "p1", "p2"]
    ins = [
        Instr("mul", "m0", "a0", "b0", "data"),
        Instr("mul", "m2", "a1", "b1", "data"),
        Instr("add", "sa", "a0", "a1", "data"),
        Instr("add", "sb", "b0", "b1", "data"),
        Instr("mul", "m1", "sa", "sb", "data"),
        Instr("mov", "p0", "m0", None, "data"),
        Instr("add", "p1", "m1", "m0", "data"),
        Instr("add", "p1", "p1", "m2", "data"),
        Instr("mov", "p2", "m2", None, "data"),
    ]
    return Program("polymul_karatsuba2", m, MODULI[m], a + b, "R",
                   _fingerprint(a, b, p, ins), p, "disc")


def butterfly4(m: int = 8, twiddles: tuple[int, int, int] = (2, 3, 2)) -> Program:
    """Non-KEM family: a 4-point, 2-stage butterfly network (a fixed linear
    map y = T x) with a Freivalds-style check u^T y == (u^T T) x for
    u = (1, R, R^2, R^3). The right-hand side is computed by an independent
    straight-line evaluation of the same map on symbolic weights."""
    q = 1 << m
    w0, w1, w2 = (t % q or 1 for t in twiddles)
    x = [f"x{i}" for i in range(4)]
    y = [f"y{i}" for i in range(4)]
    ins = [Instr("const", "k0", w0, None, "data"),
           Instr("const", "k1", w1, None, "data"),
           Instr("const", "k2", w2, None, "data")]

    def bfly(lo_out, hi_out, lo, hi, k, tmp):
        return [Instr("mul", tmp, hi, k, "data"),
                Instr("add", lo_out, lo, tmp, "data"),
                Instr("add", hi_out, lo_out, hi, "data")]
    # stage 1: (x0,x2) and (x1,x3) with k0
    ins += bfly("s0", "s2", "x0", "x2", "k0", "t")
    ins += bfly("s1", "s3", "x1", "x3", "k0", "t")
    # stage 2: (s0,s1) with k1, (s2,s3) with k2
    ins += bfly("y0", "y1", "s0", "s1", "k1", "t")
    ins += bfly("y2", "y3", "s2", "s3", "k2", "t")
    ins += _horner("lhs", y, "R", "check")
    # transposed network on the weights (1, R, R^2, R^3): v = T^T u
    ins += [Instr("const", "u0", 1, None, "check"),
            Instr("mov", "u1", "R", None, "check"),
            Instr("mul", "u2", "u1", "R", "check"),
            Instr("mul", "u3", "u2", "R", "check"),
            Instr("const", "c0", w0, None, "check"),
            Instr("const", "c1", w1, None, "check"),
            Instr("const", "c2", w2, None, "check")]

    def bfly_T(lo_in, hi_in, lo, hi, k, tmp):
        # forward: lo_out = lo + k*hi ; hi_out = lo_out + hi
        # transpose: lo += lo_in + hi_in ; hi += k*(lo_in+hi_in) + hi_in
        return [Instr("add", tmp, lo_in, hi_in, "check"),
                Instr("mov", lo, tmp, None, "check"),
                Instr("mul", tmp, tmp, k, "check"),
                Instr("add", hi, tmp, hi_in, "check")]
    ins += bfly_T("u0", "u1", "g0", "g1", "c1", "tt")
    ins += bfly_T("u2", "u3", "g2", "g3", "c2", "tt")
    ins += bfly_T("g0", "g2", "v0", "v2", "c0", "tt")
    ins += bfly_T("g1", "g3", "v1", "v3", "c0", "tt")
    ins.append(Instr("const", "rhs", 0, None, "check"))
    for i in range(4):
        ins.append(Instr("mul", "tt", f"v{i}", x[i], "check"))
        ins.append(Instr("add", "rhs", "rhs", "tt", "check"))
    ins.append(Instr("add", "disc", "lhs", "rhs", "check"))
    return Program("butterfly4", m, MODULI[m], x, "R", ins, y, "disc")


ALL_BUILDERS = {
    "ar_discrepancy": ar_discrepancy,
    "polymul_schoolbook": polymul_schoolbook,
    "polymul_karatsuba2": polymul_karatsuba2,
    "butterfly4": butterfly4,
}

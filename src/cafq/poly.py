"""Sparse multivariate polynomials over GF(2^m) for the ANALYZER.

A monomial is a sorted tuple of (variable, exponent) pairs; a polynomial is a
dict monomial -> nonzero coefficient. The trusted checker does not import
this module; it has its own, smaller arithmetic.
"""
from __future__ import annotations

from .field import GF

Mono = tuple
ONE: Mono = ()


class Poly:
    __slots__ = ("F", "t")

    def __init__(self, F: GF, terms: dict | None = None):
        self.F = F
        self.t = {k: v for k, v in (terms or {}).items() if v}

    # -- constructors
    @staticmethod
    def const(F: GF, c: int) -> "Poly":
        return Poly(F, {ONE: c})

    @staticmethod
    def var(F: GF, name: str) -> "Poly":
        return Poly(F, {((name, 1),): 1})

    # -- ring operations
    def __add__(self, o: "Poly") -> "Poly":
        t = dict(self.t)
        for k, v in o.t.items():
            nv = t.get(k, 0) ^ v
            if nv:
                t[k] = nv
            else:
                t.pop(k, None)
        return Poly(self.F, t)

    def __mul__(self, o: "Poly") -> "Poly":
        t: dict = {}
        mul = self.F.mul
        for k1, v1 in self.t.items():
            d1 = dict(k1)
            for k2, v2 in o.t.items():
                d = dict(d1)
                for var, e in k2:
                    d[var] = d.get(var, 0) + e
                k = tuple(sorted(d.items()))
                nv = t.get(k, 0) ^ mul(v1, v2)
                if nv:
                    t[k] = nv
                else:
                    t.pop(k, None)
        return Poly(self.F, t)

    def scale(self, c: int) -> "Poly":
        return Poly(self.F, {k: self.F.mul(v, c) for k, v in self.t.items()})

    def __eq__(self, o) -> bool:
        return isinstance(o, Poly) and self.t == o.t

    def __hash__(self):
        return hash(frozenset(self.t.items()))

    def is_zero(self) -> bool:
        return not self.t

    def is_const(self) -> bool:
        return all(k == ONE for k in self.t)

    def variables(self) -> set:
        return {v for k in self.t for v, _ in k}

    def total_degree(self) -> int:
        return max((sum(e for _, e in k) for k in self.t), default=0)

    def degree_in(self, var: str) -> int:
        return max((dict(k).get(var, 0) for k in self.t), default=0)

    # -- function-level canonical form: x^q == x on GF(q)
    def reduce(self) -> "Poly":
        q = self.F.q
        t: dict = {}
        for k, v in self.t.items():
            nk = tuple((var, e if e < q else (e - 1) % (q - 1) + 1) for var, e in k)
            nv = t.get(nk, 0) ^ v
            if nv:
                t[nk] = nv
            else:
                t.pop(nk, None)
        return Poly(self.F, t)

    def coeffs_in(self, var: str) -> dict[int, "Poly"]:
        """self = sum_d coeff[d] * var^d with coeff[d] free of var."""
        out: dict[int, dict] = {}
        for k, v in self.t.items():
            d = dict(k)
            e = d.pop(var, 0)
            out.setdefault(e, {})[tuple(sorted(d.items()))] = v
        return {e: Poly(self.F, t) for e, t in out.items()}

    def evaluate(self, env: dict[str, int]) -> int:
        acc = 0
        for k, v in self.t.items():
            term = v
            for var, e in k:
                term = self.F.mul(term, self.F.pow(env[var], e))
            acc ^= term
        return acc

    # -- serialisation (canonical: terms sorted)
    def to_json(self) -> list:
        return [[v, [list(p) for p in k]] for k, v in sorted(self.t.items())]

    @staticmethod
    def from_json(F: GF, data: list) -> "Poly":
        return Poly(F, {tuple((a, b) for a, b in k): v for v, k in data})

    def __repr__(self) -> str:
        if not self.t:
            return "0"
        parts = []
        for k, v in sorted(self.t.items()):
            mono = "*".join(var if e == 1 else f"{var}^{e}" for var, e in k)
            parts.append(mono if (v == 1 and mono) else (f"{v}*{mono}" if mono else str(v)))
        return " + ".join(parts)


def _key(mono: Mono, order: list[str]) -> tuple:
    d = dict(mono)
    return tuple(d.get(v, 0) for v in order)


def exact_divide(a: Poly, b: Poly) -> Poly | None:
    """Return c with a == b * c as formal polynomials, or None."""
    if b.is_zero():
        return None
    F = a.F
    order = sorted(a.variables() | b.variables())
    lb = max(b.t, key=lambda k: _key(k, order))
    lb_d, lb_inv = dict(lb), F.inv(b.t[lb])
    rem, quo = Poly(F, a.t), Poly(F)
    while not rem.is_zero():
        la = max(rem.t, key=lambda k: _key(k, order))
        d = dict(la)
        for var, e in lb_d.items():
            if d.get(var, 0) < e:
                return None
            d[var] -= e
        mono = tuple(sorted((v, e) for v, e in d.items() if e))
        term = Poly(F, {mono: F.mul(rem.t[la], lb_inv)})
        quo = quo + term
        rem = rem + term * b
    return quo


def solve_in_span(F: GF, basis: list[Poly], target: Poly) -> list[int] | None:
    """Constants lam with sum lam[i] * basis[i] == target, or None."""
    monos = sorted({k for p in basis + [target] for k in p.t})
    rows = [[p.t.get(mn, 0) for p in basis] + [target.t.get(mn, 0)] for mn in monos]
    sol = gauss(F, rows, len(basis))
    return None if sol is None else sol[0]


def gauss(F: GF, rows: list[list[int]], n: int):
    """Solve rows (augmented, n unknowns) over F. Returns (particular,
    nullspace basis) or None if inconsistent."""
    M = [r[:] for r in rows]
    piv: list[int] = []
    r = 0
    for col in range(n):
        p = next((i for i in range(r, len(M)) if M[i][col]), None)
        if p is None:
            continue
        M[r], M[p] = M[p], M[r]
        inv = F.inv(M[r][col])
        M[r] = [F.mul(x, inv) for x in M[r]]
        for i in range(len(M)):
            if i != r and M[i][col]:
                f = M[i][col]
                M[i] = [x ^ F.mul(f, y) for x, y in zip(M[i], M[r])]
        piv.append(col)
        r += 1
    if any(row[n] for row in M[r:]):
        return None
    part = [0] * n
    for i, col in enumerate(piv):
        part[col] = M[i][n]
    null = []
    for free in (c for c in range(n) if c not in piv):
        vec = [0] * n
        vec[free] = 1
        for i, col in enumerate(piv):
            vec[col] = M[i][free]
        null.append(vec)
    return part, null

"""GF(2^m) for the small m used by the prototype (table driven)."""
from __future__ import annotations

# degree -> irreducible modulus (bit i = coefficient of x^i)
MODULI = {2: 0b111, 3: 0b1011, 4: 0b10011, 8: 0x11B}


class GF:
    def __init__(self, m: int, modulus: int | None = None):
        self.m = m
        self.modulus = MODULI[m] if modulus is None else modulus
        self.q = 1 << m
        self._mul = [[self._slow_mul(a, b) for b in range(self.q)] for a in range(self.q)]
        self._inv = [0] * self.q
        for a in range(1, self.q):
            self._inv[a] = self._mul[a].index(1)

    def _slow_mul(self, a: int, b: int) -> int:
        acc = 0
        for i in range(self.m):
            if (b >> i) & 1:
                acc ^= a << i
        for i in range(2 * self.m - 2, self.m - 1, -1):
            if (acc >> i) & 1:
                acc ^= self.modulus << (i - self.m)
        return acc

    def mul(self, a: int, b: int) -> int:
        return self._mul[a][b]

    def inv(self, a: int) -> int:
        if a == 0:
            raise ZeroDivisionError
        return self._inv[a]

    def pow(self, a: int, n: int) -> int:
        r = 1
        for _ in range(n):
            r = self._mul[r][a]
        return r


_CACHE: dict[tuple[int, int], GF] = {}


def get_field(m: int, modulus: int | None = None) -> GF:
    key = (m, MODULI[m] if modulus is None else modulus)
    if key not in _CACHE:
        _CACHE[key] = GF(*key)
    return _CACHE[key]

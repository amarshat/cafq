"""GF(2^8) arithmetic, two independent implementations.

Field: GF(2)[x] / (x^8 + x^4 + x^3 + x + 1), i.e. modulus 0x11B (the AES
polynomial). Elements are ints 0..255, bit i = coefficient of x^i.

* ``mul_ref``  : shift-and-reduce, straight from the definition.
* ``mul``      : log/antilog tables built from the generator 0x03.

The two are cross-checked exhaustively in tests/test_field.py. Addition and
subtraction are both XOR (characteristic 2).
"""
from __future__ import annotations

MODULUS = 0x11B
ORDER = 256
GENERATOR = 0x03


def add(a: int, b: int) -> int:
    return a ^ b


sub = add


def mul_ref(a: int, b: int) -> int:
    """Carry-less multiply followed by reduction modulo MODULUS."""
    acc = 0
    for i in range(8):
        if (b >> i) & 1:
            acc ^= a << i
    for i in range(14, 7, -1):
        if (acc >> i) & 1:
            acc ^= MODULUS << (i - 8)
    return acc


def _build_tables() -> tuple[list[int], list[int]]:
    exp = [0] * 510
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x = mul_ref(x, GENERATOR)
    if x != 1:
        raise AssertionError("generator does not have order 255")
    for i in range(255, 510):
        exp[i] = exp[i - 255]
    return exp, log


EXP, LOG = _build_tables()


def mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return EXP[LOG[a] + LOG[b]]


def inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("0 has no inverse in GF(256)")
    return EXP[255 - LOG[a]]


def power(a: int, n: int) -> int:
    if n == 0:
        return 1
    if a == 0:
        return 0
    return EXP[(LOG[a] * n) % 255]


def poly_eval(coeffs: list[int], x: int) -> int:
    """Evaluate sum(coeffs[i] * x^i) by Horner's rule."""
    acc = 0
    for c in reversed(coeffs):
        acc = mul(acc, x) ^ c
    return acc

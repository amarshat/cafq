"""Toy FO-style KEM with three decapsulation rules, plus named fault hooks.

RESEARCH TOY. The PKE is a 3-dimensional LWE-like scheme modulo 251 with
ternary secrets; it has no security whatsoever at this size. It exists only
because it has the one property the experiments need: decryption tolerates
small ciphertext perturbations, exactly like ML-KEM and HQC. The "KDF", "G"
and "PRF" are SHA-256 / HMAC-SHA-256 with domain tags, standing in for
random oracles; they are not a recommendation.

Ciphertext layout: c = (v_0..v_{K-1}, u_0..u_{n-1}), one byte each, each
byte read as an element of GF(2^8) by the discrepancy.

Decapsulation rules
  fo    FO with implicit rejection (comparison + select).
  ar    H-AR from the work package: K = KDF(m', c, D_rho(c, c')),
        rho = PRF(z, c). ``shift`` selects the exponent offset.
  dfar  Independent re-implementation of the published DFAR rule
        K = Khat xor F_z(tag|c|c') xor F_z(tag|c|c)   (Alsawalqah-Abadleh,
        Zenodo 10.5281/zenodo.23511350, verification/reference_dfar_kernel.c,
        function dfar_full). Written from the formula, no code copied.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from . import gf256 as F

P = 251          # PKE modulus
N = 3            # LWE dimension
K = 8            # message bits
HALF = 125       # encoding of a 1 bit
CT_LEN = K + N   # 11 field elements


def _h(tag: bytes, *parts: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(len(tag).to_bytes(1, "big") + tag)
    for p in parts:
        h.update(len(p).to_bytes(4, "big") + p)
    return h.digest()


def _ternary(seed: bytes, count: int) -> list[int]:
    out, ctr = [], 0
    while len(out) < count:
        for b in _h(b"toy-expand", seed, ctr.to_bytes(4, "big")):
            if b < 255:               # 255 = 3 * 85: unbiased
                out.append(b % 3 - 1)
        ctr += 1
    return out[:count]


def _uniform(seed: bytes, count: int) -> list[int]:
    out, ctr = [], 0
    while len(out) < count:
        for b in _h(b"toy-uniform", seed, ctr.to_bytes(4, "big")):
            if b < P:
                out.append(b)
        ctr += 1
    return out[:count]


@dataclass(frozen=True)
class PublicKey:
    A: tuple          # N x N, A[i][j]
    B: tuple          # K x N, B[j] = S[j] . A + E[j]

    def encode(self) -> bytes:
        return bytes(x for row in self.A + self.B for x in row)


@dataclass(frozen=True)
class SecretKey:
    S: tuple          # K x N ternary
    E: tuple          # K x N ternary (kept only so tests can check attacks)
    z: bytes          # rejection / challenge secret
    pk: PublicKey


def keygen(seed: bytes) -> tuple[PublicKey, SecretKey]:
    a = _uniform(seed + b"A", N * N)
    A = tuple(tuple(a[i * N + j] for j in range(N)) for i in range(N))
    s = _ternary(seed + b"S", K * N)
    e = _ternary(seed + b"E", K * N)
    S = tuple(tuple(s[j * N:(j + 1) * N]) for j in range(K))
    E = tuple(tuple(e[j * N:(j + 1) * N]) for j in range(K))
    B = tuple(tuple((sum(S[j][i] * A[i][l] for i in range(N)) + E[j][l]) % P
                    for l in range(N)) for j in range(K))
    pk = PublicKey(A, B)
    return pk, SecretKey(S, E, _h(b"toy-z", seed), pk)


@dataclass(frozen=True)
class Coins:
    r: tuple
    e1: tuple
    e2: tuple


def coins_for(pk: PublicKey, m: int) -> Coins:
    t = _ternary(_h(b"toy-G", pk.encode(), bytes([m])), 2 * N + K)
    return Coins(tuple(t[:N]), tuple(t[N:2 * N]), tuple(t[2 * N:]))


def pke_enc(pk: PublicKey, m: int, coins: Coins) -> list[int]:
    u = [(sum(pk.A[i][l] * coins.r[l] for l in range(N)) + coins.e1[i]) % P
         for i in range(N)]
    v = [(sum(pk.B[j][l] * coins.r[l] for l in range(N)) + coins.e2[j]
          + HALF * ((m >> j) & 1)) % P for j in range(K)]
    return v + u


def pke_dec(sk: SecretKey, c: list[int]) -> int:
    v, u = c[:K], c[K:]
    m = 0
    for j in range(K):
        d = (v[j] - sum(sk.S[j][i] * u[i] for i in range(N))) % P
        if 63 <= d <= 188:
            m |= 1 << j
    return m


def enc(pk: PublicKey, m: int) -> list[int]:
    """Deterministic (derandomised) encryption used by FO."""
    return pke_enc(pk, m, coins_for(pk, m))


# ---- key derivation (toy oracles) ----------------------------------------

def kdf_accept(m: int, c: list[int]) -> bytes:
    return _h(b"toy-K-accept", bytes([m]), bytes(c))


def kdf_reject(z: bytes, c: list[int]) -> bytes:
    return _h(b"toy-K-reject", z, bytes(c))


def kdf_ar(m: int, c: list[int], D: int) -> bytes:
    return _h(b"toy-K-ar", bytes([m]), bytes(c), bytes([D]))


def prf_rho(z: bytes, c: list[int]) -> int:
    return _h(b"toy-rho", z, bytes(c))[0]


def prf_dfar(z: bytes, c: list[int], second: list[int]) -> bytes:
    msg = b"\xD1" + len(c).to_bytes(8, "little") + bytes(c) + bytes(second)
    return hmac.new(z, msg, hashlib.sha256).digest()


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encaps(pk: PublicKey, m: int, variant: str) -> tuple[list[int], bytes]:
    c = enc(pk, m)
    if variant in ("fo", "dfar"):
        return c, kdf_accept(m, c)
    if variant == "ar":
        return c, kdf_ar(m, c, 0)
    raise ValueError(variant)


# ---- decapsulation with fault hooks ---------------------------------------

@dataclass
class Fault:
    """One named fault. ``index`` selects the coordinate / step where needed."""
    name: str
    index: int = 0


@dataclass
class Trace:
    m_prime: int = -1
    c_prime: list = field(default_factory=list)
    rho: int = -1
    D: int = -1
    key: bytes = b""


FO_FAULTS = ("skip_compare_chunk", "force_flag_zero", "skip_select",
             "alias_checker_input", "corrupt_m")
AR_FAULTS = ("skip_contribution", "skip_power_update", "force_D_zero",
             "alias_checker_input", "skip_marshal", "corrupt_m")
DFAR_FAULTS = ("omit_first_eval", "omit_second_eval", "alias_checker_input",
               "omit_final_xor", "corrupt_m")


def decaps(sk: SecretKey, c: list[int], variant: str,
           fault: Fault | None = None, shift: int = 0) -> Trace:
    f = fault.name if fault else None
    allowed = {"fo": FO_FAULTS, "ar": AR_FAULTS, "dfar": DFAR_FAULTS}[variant]
    if f is not None and f not in allowed:
        raise ValueError(f"fault {f!r} not defined for variant {variant!r}")
    t = Trace()
    t.m_prime = pke_dec(sk, c)
    if f == "corrupt_m":                     # corrupted decapsulation result
        t.m_prime ^= 1 << (fault.index % K)
    t.c_prime = enc(sk.pk, t.m_prime)
    # common-mode fault: the checker reads the received buffer twice
    cp = list(c) if f == "alias_checker_input" else t.c_prime

    if variant == "fo":
        flag = 0
        for i in range(CT_LEN):
            if f == "skip_compare_chunk" and i == fault.index:
                continue
            flag |= c[i] ^ cp[i]
        fail = 1 if flag else 0
        if f == "force_flag_zero":
            fail = 0
        good, bad = kdf_accept(t.m_prime, c), kdf_reject(sk.z, c)
        t.key = good if (f == "skip_select" or not fail) else bad
        return t

    if variant == "ar":
        t.rho = prf_rho(sk.z, c)
        acc, pw = 0, F.power(t.rho, shift)
        for i in range(CT_LEN):
            if not (f == "skip_contribution" and i == fault.index):
                acc ^= F.mul(c[i] ^ cp[i], pw)
            if not (f == "skip_power_update" and i == fault.index):
                pw = F.mul(pw, t.rho)
        if f == "force_D_zero":
            acc = 0
        t.D = acc
        kdf_in = 0                           # marshalling buffer default
        if f != "skip_marshal":
            kdf_in = acc
        t.key = kdf_ar(t.m_prime, c, kdf_in)
        return t

    if variant == "dfar":
        cand = kdf_accept(t.m_prime, c)
        a = prf_dfar(sk.z, c, cp)
        b = prf_dfar(sk.z, c, c)
        out = cand
        if f != "omit_final_xor":
            if f != "omit_first_eval":
                out = xor(out, a)
            if f != "omit_second_eval":
                out = xor(out, b)
        t.key = out
        return t

    raise ValueError(variant)

"""Chosen-ciphertext experiments against the toy decapsulation rules.

The adversary here has the public key and a decapsulation oracle only. It
never reads sk or z. Everything it "predicts" is computed from values it
chose itself (m, hence the coins, hence c).
"""
from __future__ import annotations

from typing import Callable

from . import kem

Oracle = Callable[[list], bytes]


def perturb(c: list[int], coord: int, t: int) -> list[int]:
    out = list(c)
    out[coord] = (out[coord] + t) % kem.P
    return out


def predicted_ar_key(m: int, c_valid: list[int], c_query: list[int]) -> bytes:
    """What H-AR (shift 0) returns IF the perturbed ciphertext still decrypts
    to m and the difference sits in coordinate 0: then c' = c_valid and
    D = c_query[0] - c_valid[0], independent of the secret rho."""
    return kem.kdf_ar(m, c_query, c_query[0] ^ c_valid[0])


def pc_oracle_coord0(oracle: Oracle, pk: kem.PublicKey, m: int, t: int) -> bool:
    """Plaintext-checking oracle built from one decapsulation query:
    True iff Dec(sk, Enc(m) + t*e_0) == m."""
    c = kem.enc(pk, m)
    q = perturb(c, 0, t)
    return oracle(q) == predicted_ar_key(m, c, q)


def pc_oracle_enumerate(oracle: Oracle, pk: kem.PublicKey, m: int,
                        coord: int, t: int) -> bool:
    """Small-field artefact: with q = 256 the adversary can simply try all
    256 values of D. Works for any coordinate and any exponent shift, and
    disappears for a 128-bit field. Kept separate from the structural
    coordinate-0 attack for that reason."""
    q = perturb(kem.enc(pk, m), coord, t)
    key = oracle(q)
    return any(key == kem.kdf_ar(m, q, D) for D in range(256))


def recover_noise0(oracle: Oracle, pk: kem.PublicKey, m: int) -> tuple[int, int]:
    """Binary-search the largest t in [0,124] that still decrypts to m (m must
    have bit 0 clear). Decryption of bit 0 is correct iff noise + t <= 62, so
    noise_0 = 62 - t_max exactly. Returns (noise_0, number of queries)."""
    assert m & 1 == 0
    lo, hi, queries = 0, 124, 0          # invariant: lo accepted
    while lo < hi:
        mid = (lo + hi + 1) // 2
        queries += 1
        if pc_oracle_coord0(oracle, pk, m, mid):
            lo = mid
        else:
            hi = mid - 1
    return 62 - lo, queries


def _solve_mod_p(rows: list[list[int]], rhs: list[int], p: int) -> list[int] | None:
    n = len(rows[0])
    M = [r[:] + [b] for r, b in zip(rows, rhs)]
    piv_cols, r = [], 0
    for col in range(n):
        piv = next((i for i in range(r, len(M)) if M[i][col] % p), None)
        if piv is None:
            continue
        M[r], M[piv] = M[piv], M[r]
        inv = pow(M[r][col], -1, p)
        M[r] = [(x * inv) % p for x in M[r]]
        for i in range(len(M)):
            if i != r and M[i][col] % p:
                fac = M[i][col]
                M[i] = [(x - fac * y) % p for x, y in zip(M[i], M[r])]
        piv_cols.append(col)
        r += 1
    if len(piv_cols) < n:
        return None
    if any(row[-1] % p for row in M[r:]):
        return None                       # inconsistent
    return [M[i][-1] for i in range(n)]


def recover_secret_row0(oracle: Oracle, pk: kem.PublicKey,
                        max_messages: int = 64) -> tuple[list[int], list[int], int] | None:
    """Recover (S[0], E[0]) from coordinate-0 queries.

    For a ciphertext the adversary built itself it knows r, e1, e2 and
        noise_0 = <E[0], r> - <S[0], e1> + e2[0]   (mod 251),
    a linear equation in the 2N unknown secret coefficients."""
    rows, rhs, total = [], [], 0
    for m in range(0, 256, 2):
        if len(rows) >= max_messages:
            break
        co = kem.coins_for(pk, m)
        noise, q = recover_noise0(oracle, pk, m)
        total += q
        rows.append([-x % kem.P for x in co.e1] + [x % kem.P for x in co.r])
        rhs.append((noise - co.e2[0]) % kem.P)
        sol = _solve_mod_p(rows, rhs, kem.P)
        if sol is not None:
            centred = [x - kem.P if x > kem.P // 2 else x for x in sol]
            return centred[:kem.N], centred[kem.N:], total
    return None

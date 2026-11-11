"""Toy KEM: honest correctness and the chosen-ciphertext experiments.
'All messages' means all 256 messages of the toy message space."""
import pytest

from toy import attacks, kem

SEEDS = [b"seed-1", b"seed-2", b"seed-3"]


@pytest.fixture(scope="module", params=SEEDS)
def keys(request):
    return kem.keygen(request.param)


def oracle(sk, variant, shift=0):
    return lambda c: kem.decaps(sk, c, variant, shift=shift).key


def test_pke_correct_all_messages(keys):
    pk, sk = keys
    assert all(kem.pke_dec(sk, kem.enc(pk, m)) == m for m in range(256))


@pytest.mark.parametrize("variant", ["fo", "ar", "dfar"])
def test_honest_decapsulation_all_messages(keys, variant):
    """Honest-path correctness. This is NOT a security statement."""
    pk, sk = keys
    for m in range(256):
        c, k = kem.encaps(pk, m, variant)
        assert kem.decaps(sk, c, variant).key == k


def test_ar_honest_path_has_zero_discrepancy_for_actual_rho(keys):
    pk, sk = keys
    for m in range(256):
        t = kem.decaps(sk, kem.enc(pk, m), "ar")
        assert t.D == 0 and t.c_prime == kem.enc(pk, m)


def test_CE2_ar_shift0_gives_plaintext_checking_oracle_on_coordinate0(keys):
    """H-AR as specified: a coordinate-0 perturbation that preserves the
    decrypted message returns a key the adversary computes itself."""
    pk, sk = keys
    o = oracle(sk, "ar")
    for m in range(0, 256, 2):
        assert attacks.pc_oracle_coord0(o, pk, m, 3) is True       # still decrypts
        assert attacks.pc_oracle_coord0(o, pk, m, 110) is False    # bit 0 flips


def test_CE2_ar_shift0_secret_row_recovery(keys):
    """The oracle answers are a function of the decryption noise; solving
    the resulting linear system recovers S[0] and E[0] exactly."""
    pk, sk = keys
    res = attacks.recover_secret_row0(oracle(sk, "ar"), pk)
    assert res is not None
    s0, e0, queries = res
    assert tuple(s0) == sk.S[0] and tuple(e0) == sk.E[0]
    assert queries <= 64 * 7


@pytest.mark.parametrize("variant", ["fo", "dfar"])
def test_same_queries_reveal_nothing_against_fo_and_dfar(keys, variant):
    pk, sk = keys
    o = oracle(sk, variant)
    assert not any(attacks.pc_oracle_coord0(o, pk, m, t)
                   for m in range(0, 256, 2) for t in (1, 3, 30, 110))
    assert attacks.recover_secret_row0(o, pk) is None or \
        tuple(attacks.recover_secret_row0(o, pk)[0]) != sk.S[0]


def test_shifted_ar_blocks_structural_attack_except_when_rho_is_one(keys):
    """With exponents starting at 1, D = delta * rho. The coordinate-0
    prediction D = delta is right exactly when rho == 1."""
    pk, sk = keys
    o = oracle(sk, "ar", shift=1)
    for m in range(0, 256, 2):
        q = attacks.perturb(kem.enc(pk, m), 0, 3)
        hit = attacks.pc_oracle_coord0(o, pk, m, 3)
        assert hit == (kem.prf_rho(sk.z, q) == 1)


def test_small_field_enumeration_defeats_every_polynomial_variant(keys):
    """Toy-size artefact, reported separately: with q = 256 all values of D
    can be tried. Any coordinate, any shift."""
    pk, sk = keys
    for shift in (0, 1):
        o = oracle(sk, "ar", shift=shift)
        for coord in (0, 1, 5, 9):
            assert all(attacks.pc_oracle_enumerate(o, pk, m, coord, 2)
                       for m in range(0, 256, 16))
    assert not any(attacks.pc_oracle_enumerate(oracle(sk, "fo"), pk, m, 1, 2)
                   for m in range(0, 256, 16))


def test_repeated_ciphertext_reuses_the_challenge(keys):
    """rho = PRF(z, c): Q repeats of one ciphertext are ONE trial, not Q."""
    pk, sk = keys
    q = attacks.perturb(kem.enc(pk, 0x10), 2, 4)
    traces = [kem.decaps(sk, q, "ar") for _ in range(5)]
    assert len({(t.rho, t.D, t.key) for t in traces}) == 1


def test_inconsistent_ciphertext_at_a_root_is_accepted_every_time(keys):
    """Search two-coordinate perturbations for one whose difference
    polynomial vanishes at its own rho. Such a ciphertext gets D = 0 and the
    'consistent' key on every repetition; nothing re-randomises the test."""
    pk, sk = keys
    found = None
    for m in range(0, 256, 2):
        c = kem.enc(pk, m)
        for t1 in range(1, 30):
            for t2 in range(1, 30):
                q = attacks.perturb(attacks.perturb(c, 1, t1), 2, t2)
                tr = kem.decaps(sk, q, "ar")
                if tr.m_prime == m and tr.D == 0:
                    found = (m, q)
                    break
            if found:
                break
        if found:
            break
    assert found, "expected about 1 in 256 candidates to hit a root"
    m, q = found
    assert q != kem.enc(pk, m)
    for _ in range(3):
        assert kem.decaps(sk, q, "ar").key == kem.kdf_ar(m, q, 0)

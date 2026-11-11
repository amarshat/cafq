"""Exhaustive checks of GF(2^8). 'Exhaustive' means every element / pair /
triple of the 256-element field, as stated per test."""
from toy import gf256 as F

R = range(256)


def test_modulus_is_irreducible():
    # Degree-8 polynomial over GF(2) is irreducible iff it has no factor of
    # degree 1..4. Trial-divide by every such polynomial.
    def polymod(a, m):
        dm = m.bit_length()
        while a.bit_length() >= dm:
            a ^= m << (a.bit_length() - dm)
        return a
    for d in range(2, 32):  # all polynomials of degree 1..4
        assert polymod(F.MODULUS, d) != 0, f"divisible by {d:#x}"


def test_table_mul_matches_reference_all_pairs():
    assert all(F.mul(a, b) == F.mul_ref(a, b) for a in R for b in R)


def test_generator_tables_are_bijective():
    assert sorted(F.EXP[:255]) == list(range(1, 256))
    assert all(F.EXP[F.LOG[a]] == a for a in range(1, 256))


def test_identities_and_commutativity_all_pairs():
    for a in R:
        assert F.mul(a, 1) == a and F.mul(a, 0) == 0 and F.add(a, 0) == a
        assert F.add(a, a) == 0
        for b in R:
            assert F.mul(a, b) == F.mul(b, a)


def test_inverse_all_nonzero():
    assert all(F.mul(a, F.inv(a)) == 1 for a in range(1, 256))


def test_no_zero_divisors_all_pairs():
    assert all(F.mul(a, b) != 0 for a in range(1, 256) for b in range(1, 256))


def test_associativity_and_distributivity_all_triples():
    T = [[F.mul_ref(a, b) for b in R] for a in R]
    for a in R:
        Ta = T[a]
        for b in R:
            ab = Ta[b]
            Tab, Tb = T[ab], T[b]
            for c in R:
                assert Tab[c] == Ta[Tb[c]]
                assert Ta[b ^ c] == ab ^ Ta[c]


def test_power_and_frobenius_all_elements():
    for a in R:
        p, acc = 1, []
        for n in range(0, 258):
            assert F.power(a, n) == p
            p = F.mul(p, a)
        assert F.power(a, 256) == a  # x^q = x as a function


def test_horner_matches_naive():
    coeffs = [0x57, 0x00, 0x83, 0x1A, 0xFF]
    for x in R:
        naive = 0
        for i, c in enumerate(coeffs):
            naive ^= F.mul(c, F.power(x, i))
        assert F.poly_eval(coeffs, x) == naive

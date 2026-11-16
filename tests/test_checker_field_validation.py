"""Trusted-checker input validation.

Regression for a soundness defect reported in external review of revision
c63ccbd: the checker verified only the DEGREE of the modulus, not its
irreducibility. With a reducible modulus the arithmetic is a ring with zero
divisors, where a nonzero polynomial of degree d can have more than d roots,
so every root-count bound the checker certifies is unjustified.

Reproduction (the reviewer's construction): take a genuine certificate set
over GF(4) = GF(2)[x]/(x^2+x+1), change only the program's modulus to a
reducible polynomial, and submit. The certificates must be rejected."""
import itertools
import json

import pytest

from cafq import checker, structural_checker
from cafq import structural as S
from cafq.analyzer import analyze
from cafq.ir import Instr, Program

IRREDUCIBLE = {1: [0b11], 2: [0b111], 3: [0b1011, 0b1101], 4: [0b10011, 0b11001, 0b11111],
               8: [0x11B, 0x11D]}
REDUCIBLE = {2: [0b100, 0b101, 0b110], 3: [0b1000, 0b1001, 0b1111], 4: [0b10101, 0b10001],
             8: [0x100, 0x101, 0x11A]}


def tiny(modulus=0b111):
    """y = x0 ; disc = (y + x0) * R.  A bit flip on y gives g = delta * R."""
    ins = [Instr("mov", "y", "x0", None, "data"),
           Instr("add", "chk", "y", "x0", "check"),
           Instr("mul", "disc", "chk", "R", "check")]
    return Program("tiny", 2, modulus, ["x0"], "R", ins, ["y"], "disc")


def ring_mul(a, b, modulus, m=2):
    acc = 0
    for i in range(m):
        if (b >> i) & 1:
            acc ^= a << i
    for i in range(2 * m - 2, m - 1, -1):
        if (acc >> i) & 1:
            acc ^= modulus << (i - m)
    return acc


def transplant(prog, certs_or_doc, modulus):
    wp = json.loads(json.dumps(prog.to_json()))
    wp["modulus"] = modulus
    sha = __import__("hashlib").sha256(
        json.dumps(wp, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    data = json.loads(json.dumps(certs_or_doc))
    if isinstance(data, list):
        for c in data:
            c["program_sha256"] = sha
    else:
        data["program_sha256"] = sha
    return wp, data


@pytest.mark.parametrize("modulus", REDUCIBLE[2])
def test_the_bound_really_is_false_over_the_reducible_ring(modulus):
    """Why this matters, by brute force: in GF(2)[x]/(modulus) with modulus
    reducible there is an injected error delta for which delta * r == 0 for
    TWO of the four challenges, while the degree-1 certificate claims one."""
    worst = max(sum(ring_mul(d, r, modulus) == 0 for r in range(4)) for d in range(1, 4))
    assert worst == 2
    assert max(sum(ring_mul(d, r, 0b111) == 0 for r in range(4)) for d in range(1, 4)) == 1


@pytest.mark.parametrize("modulus", REDUCIBLE[2])
def test_REGRESSION_baseline_checker_rejects_reducible_modulus(modulus):
    prog = tiny()
    certs = analyze(prog).certificates
    genuine = checker.check(json.loads(json.dumps(prog.to_json())),
                            json.loads(json.dumps(certs)))
    assert genuine["ok"]
    flip = next(c for c in certs if c["site_id"] == "bitflip@0.b1")
    assert flip["classification"] == "covered" and flip["degree_bound"] == 1
    rep = checker.check(*transplant(prog, certs, modulus))
    assert not rep["ok"]
    assert any("irreducible" in e for e in rep["errors"])
    assert not any(v == "pass" for v in rep["results"].values())


@pytest.mark.parametrize("modulus", REDUCIBLE[2])
def test_REGRESSION_structural_checker_rejects_reducible_modulus(modulus):
    prog = tiny()
    doc = S.generate(prog).document
    assert structural_checker.check(json.loads(json.dumps(prog.to_json())),
                                    json.loads(json.dumps(doc)))["ok"]
    rep = structural_checker.check(*transplant(prog, doc, modulus))
    assert not rep["ok"]
    assert any("irreducible" in e for e in rep["errors"])
    assert not any(v == "pass" for v in rep["results"].values())


def test_irreducibility_test_is_exact_for_all_small_degrees():
    """Compare the trusted routine with an independent definition (no
    nontrivial factorisation exists) for EVERY polynomial of degree 1..8."""
    def clmul(a, b):
        acc = 0
        while b:
            if b & 1:
                acc ^= a
            a <<= 1
            b >>= 1
        return acc
    for m in range(1, 9):
        products = set()
        for da in range(1, m // 2 + 1):
            for a in range(1 << da, 1 << (da + 1)):
                for b in range(1 << (m - da), 1 << (m - da + 1)):
                    products.add(clmul(a, b))
        for f in range(1 << m, 1 << (m + 1)):
            assert checker._irreducible(f, m) == (f not in products), (m, bin(f))
    for m, fs in IRREDUCIBLE.items():
        assert all(checker._irreducible(f, m) for f in fs)
    for m, fs in REDUCIBLE.items():
        assert not any(checker._irreducible(f, m) for f in fs)


def bad_programs():
    base = json.loads(json.dumps(tiny().to_json()))

    def variant(**kw):
        p = json.loads(json.dumps(base))
        p.update(kw)
        return p
    yield "degree too high", variant(modulus=0b1011)
    yield "degree too low", variant(modulus=0b11)
    yield "modulus not an int", variant(modulus="7")
    yield "m zero", variant(m=0, modulus=1)
    yield "m too large", variant(m=17, modulus=(1 << 17) | 0b1001)
    yield "m not an int", variant(m=2.0)
    yield "bool as m", variant(m=True, modulus=0b11)
    yield "challenge is an input", variant(inputs=["x0", "R"])
    yield "duplicate inputs", variant(inputs=["x0", "x0"])
    yield "reserved name", variant(inputs=["@o0"])
    yield "reserved challenge", variant(challenge="@d")
    yield "empty name", variant(inputs=[""])
    yield "non-string input", variant(inputs=[3])
    p = variant()
    p["instrs"][0] = ["mov", "x0", "y", None, "data"]
    yield "writes an input", p
    p = variant()
    p["instrs"][0] = ["mov", "R", "x0", None, "data"]
    yield "writes the challenge", p
    p = variant()
    p["instrs"][0] = ["mov", "@t", "x0", None, "data"]
    yield "reserved destination", p
    p = variant()
    p["instrs"][0] = ["xor", "y", "x0", None, "data"]
    yield "unknown op", p
    p = variant()
    p["instrs"][0] = ["mov", "y", 5, None, "data"]
    yield "mov with immediate", p
    p = variant()
    p["instrs"][1] = ["add", "chk", "y", None, "check"]
    yield "add with missing operand", p
    p = variant()
    p["instrs"][0] = ["const", "y", 4, None, "data"]
    yield "immediate out of range", p
    p = variant()
    p["instrs"][0] = ["mov", "y", "x0"]
    yield "short instruction", p
    yield "outputs not a list", variant(outputs="y")
    yield "disc not a string", variant(disc=None)
    yield "unknown ir", variant(ir="toy-ir-v2")
    yield "inconsistency reserved", variant(inconsistency=["@d"])


@pytest.mark.parametrize("label,prog", list(bad_programs()), ids=lambda v: v if isinstance(v, str) else "")
def test_malformed_programs_are_rejected_before_any_proof_checking(label, prog):
    for chk, payload in ((checker.check, []),
                         (structural_checker.check, {"format": "cafq-structural-0.2",
                                                     "faults": [], "templates": {}})):
        rep = chk(prog, payload)
        assert not rep["ok"], label
        assert any(e.startswith("program:") for e in rep["errors"]), (label, rep["errors"][:2])
        assert rep["results"] == {}


def test_valid_programs_still_pass_validation():
    from cafq import circuits as C
    for prog in (C.polymul_karatsuba2(), C.butterfly4(m=2), C.ar_discrepancy(3, m=3),
                 C.polymul_schoolbook(2, m=4)):
        assert checker._validate_program(json.loads(json.dumps(prog.to_json()))) is None


def test_generator_side_also_refuses_non_fields_and_reserved_names():
    """Defence in depth only: the untrusted side is not relied upon."""
    from cafq.field import GF
    for bad in REDUCIBLE[2]:
        with pytest.raises(ValueError):
            GF(2, bad)
        with pytest.raises(ValueError):
            tiny(bad)
    with pytest.raises(ValueError):
        Program("p", 2, 0b111, ["@o0"], "R", [], [], "disc")
    with pytest.raises(ValueError):
        Program("p", 2, 0b111, ["x", "R"], "R", [], [], "disc")

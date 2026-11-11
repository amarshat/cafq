"""Soundness of CAFQ classifications and quotient classes against brute
force. 'Exhaustive' = every state, every challenge, every in-scope fault of
the named program over the named field. Sampled tests say so."""
import random

import pytest

from cafq import circuits as C
from cafq.field import get_field
from cafq.pipeline import certify
from cafq.poly import Poly
from cafq_helpers import fault_of, ground_truth, masked_check, unchecked_output

EXHAUSTIVE = {
    "ar_n2_gf4": lambda: C.ar_discrepancy(2, m=2),
    "ar_n2_shift1_gf4": lambda: C.ar_discrepancy(2, m=2, shift=1),
    "ar_n3_gf4": lambda: C.ar_discrepancy(3, m=2),
    "ar_n2_gf8": lambda: C.ar_discrepancy(2, m=3),
    "schoolbook_n2_gf4": lambda: C.polymul_schoolbook(2, m=2),
    "karatsuba2_gf4": lambda: C.polymul_karatsuba2(m=2),
    "butterfly4_gf4": lambda: C.butterfly4(m=2),
    "masked_lin_gf4": lambda: masked_check(2, False),
    "masked_nl_gf4": lambda: masked_check(2, True),
    "unchecked_output_gf4": lambda: unchecked_output(2),
}


_CACHE = {}


def certified(name):
    """Analyze + check + brute-force each exhaustive program once per run."""
    if name not in _CACHE:
        prog = EXHAUSTIVE[name]()
        analysis, report = certify(prog)
        truth = {c["site_id"]: list(ground_truth(prog, fault_of(c)))
                 for c in analysis.certificates}
        _CACHE[name] = (prog, analysis, report, truth)
    return _CACHE[name]


def verify_against_truth(prog, analysis, states_fn=None, truth_by_site=None):
    """Returns per-classification counts; raises on any unsound claim."""
    F = get_field(prog.m, prog.modulus)
    R = prog.challenge
    seen = {"benign": 0, "covered": 0, "bypass": 0, "unknown": 0}
    tight = 0
    for cert in analysis.certificates:
        fault = fault_of(cert)
        cls = cert["classification"]
        if fault is not None:
            seen[cls] += 1
        quo = cert["quotient"]
        h = Poly.from_json(F, quo["h"]) if quo else None
        worst = 0
        truth = truth_by_site[cert["site_id"]] if truth_by_site else \
            list(ground_truth(prog, fault, states_fn() if states_fn else None))
        for x, wrong_all, wrong_any, und, same in truth:
            if cls == "benign":
                assert same, (cert["site_id"], x)
            elif cls == "covered":
                if cert["wrong_output_possible"] is False:
                    assert not wrong_any, (cert["site_id"], x)
                    continue
                if not wrong_any:
                    continue
                # the certified statement
                assert len(und) <= cert["degree_bound"], (cert["site_id"], x, und)
                worst = max(worst, len(und))
                # the quotient preservation statement: the undetected set
                # is exactly roots(h(x; .)) plus 0 when shift_k > 0
                expect = {r for r in range(F.q) if h.evaluate({**x, R: r}) == 0}
                if quo["shift_k"] > 0:
                    expect.add(0)
                assert und == expect, (cert["site_id"], x, und, expect)
                if quo["exact_roots"] is not None:
                    assert sorted(und) == quo["exact_roots"]
        if cls == "bypass":
            pt = cert["witness"]["point"]
            hit = [t for t in ground_truth(prog, fault, [tuple(pt[v] for v in prog.inputs)])]
            assert hit[0][1] and len(hit[0][3]) == F.q, cert["site_id"]
        if cls == "covered" and cert["wrong_output_possible"] and worst == cert["degree_bound"]:
            tight += 1
    return seen, tight


@pytest.mark.parametrize("name", sorted(EXHAUSTIVE))
def test_exhaustive_soundness(name):
    prog, analysis, report, truth = certified(name)
    assert report["ok"], (report["errors"], [v for v in report["results"].values() if v != "pass"][:3])
    seen, _ = verify_against_truth(prog, analysis, truth_by_site=truth)
    assert sum(seen.values()) == len(prog.fault_space())      # no silent omission
    assert seen == {k: analysis.counts()[k] for k in seen}


@pytest.mark.parametrize("name", sorted(EXHAUSTIVE))
def test_no_bypass_or_unknown_is_hidden_among_covered(name):
    """Converse direction, exhaustively: if brute force finds a state that
    is wrong and undetected for EVERY challenge, the fault must not be
    classified benign or covered."""
    prog, analysis, _, truth = certified(name)
    q = 1 << prog.m
    for cert in analysis.certificates:
        fully_bypassed = any(wrong_all and len(und) == q
                             for _, wrong_all, _, und, _ in truth[cert["site_id"]])
        if fully_bypassed:
            assert cert["classification"] in ("bypass", "unknown"), cert["site_id"]


@pytest.mark.parametrize("name", ["schoolbook_n2_gf4", "karatsuba2_gf4", "butterfly4_gf4"])
def test_exact_classes_are_tight(name):
    """Where exact_roots is certified, the bound is attained (it is an
    equality, not just an upper bound)."""
    prog, analysis, _, truth = certified(name)
    _, tight = verify_against_truth(prog, analysis, truth_by_site=truth)
    exact = sum(1 for c in analysis.certificates
                if c["quotient"] and c["quotient"]["exact_roots"] is not None and c["fault"])
    assert exact > 0 and tight >= exact


@pytest.mark.parametrize("builder", [
    lambda: C.polymul_schoolbook(2), lambda: C.polymul_karatsuba2(),
    lambda: C.butterfly4(), lambda: C.ar_discrepancy(3, shift=1)])
def test_gf256_sampled_states_all_challenges(builder):
    """GF(2^8): random states (fixed seed; 12, or 4 for programs over 30
    instructions) x all 256 challenges x every fault. SAMPLED in the state,
    exhaustive in the challenge."""
    prog = builder()
    rng = random.Random(20261111)
    count = 12 if len(prog.instrs) <= 30 else 4
    states = [tuple(rng.randrange(256) for _ in prog.inputs) for _ in range(count)]
    analysis, report = certify(prog)
    assert report["ok"]
    verify_against_truth(prog, analysis, lambda: states)


def test_weak_checkers_are_never_certified_covered():
    """Adversarial circuits: a discrepancy that vanishes on part of the state
    space must end up bypass (with a checked witness) or unknown."""
    for m in (2, 8):
        for nonlinear in (False, True):
            prog = masked_check(m, nonlinear)
            analysis, report = certify(prog)
            assert report["ok"]
            flips = [c for c in analysis.certificates
                     if c["fault"] and c["fault"]["site"] == 0]   # corrupts y0
            assert flips
            for c in flips:
                assert c["classification"] in ("bypass", "unknown"), c["site_id"]
    # the nonlinear mask over GF(256) is beyond the witness search: it must
    # be reported as unknown, not guessed.
    analysis, _ = certify(masked_check(8, True))
    assert analysis.counts()["unknown"] > 0


def test_unchecked_output_is_bypass():
    prog = unchecked_output(8)
    analysis, report = certify(prog)
    assert report["ok"]
    by_site = {c["site_id"]: c["classification"] for c in analysis.certificates}
    assert by_site["zero@1"] == "bypass"          # y1 is never checked
    assert by_site["bitflip@1.b0"] == "bypass"


def test_REGRESSION_constant_term_is_not_challenge_protected():
    """Work-package check 1 inside CAFQ: for the AR discrepancy with
    difference (delta,0,..,0) the discrepancy does not depend on R at all.
    The fault-free certificate must therefore NOT claim more than the root
    bound, and CAFQ must not present detection as entropy."""
    prog = C.ar_discrepancy(4)
    analysis, _ = certify(prog)
    ff = analysis.certificates[0]
    assert ff["site_id"] == "fault-free" and ff["classification"] == "covered"
    assert ff["degree_bound"] == 3
    F = get_field(8)
    g = Poly.from_json(F, ff["discrepancy_polynomial"])
    env = {v: 0 for v in prog.inputs}
    env["c0"] = 0x2A
    assert {g.evaluate({**env, "R": r}) for r in range(256)} == {0x2A}


def test_ar_discrepancy_every_single_fault_has_a_bypass_state():
    """Finding (not a design goal): in the shift-0 AR discrepancy circuit
    every one of the single faults admits an inconsistent input that the
    faulted check accepts for all challenges."""
    for n in (3, 4, 6):
        analysis, report = certify(C.ar_discrepancy(n))
        assert report["ok"]
        c = analysis.counts()
        assert c["bypass"] == c["sites"] and c["unknown"] == 0

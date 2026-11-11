"""Structural quotient (approach C): exactness of adjoint synthesis, parity
with the per-fault baseline, brute-force soundness, compositionality, and the
counterexamples that delimit the theory."""
import json
import random

import pytest

from cafq import circuits as C
from cafq import structural as S
from cafq import structural_checker as SC
from cafq.analyzer import analyze, symbolic_run
from cafq.field import get_field
from cafq.ir import Program
from cafq.kernels import cyclic_mul
from cafq.poly import Poly
from cafq_helpers import (fault_of, ground_truth, masked_check, nonlinear_trap,
                          square_check, unchecked_output)

PROGRAMS = {
    "ar_n4": lambda: C.ar_discrepancy(4),
    "ar_n4_shift1": lambda: C.ar_discrepancy(4, shift=1),
    "schoolbook_n3": lambda: C.polymul_schoolbook(3),
    "karatsuba2": lambda: C.polymul_karatsuba2(),
    "butterfly4": lambda: C.butterfly4(),
    "butterfly4_gf4": lambda: C.butterfly4(m=2),
    "cyclic_n3": lambda: cyclic_mul(3),
    "cyclic_n3_gf4": lambda: cyclic_mul(3, m=2),
    "cyclic_n4_weak": lambda: cyclic_mul(4, weak=True),
    "masked_nl": lambda: masked_check(8, True),
    "masked_lin_gf4": lambda: masked_check(2, False),
    "unchecked": lambda: unchecked_output(8),
    "square_gf4": lambda: square_check(2),
    "square": lambda: square_check(8),
    "trap_gf4": lambda: nonlinear_trap(2),
    "trap": lambda: nonlinear_trap(8),
}

SMALL = {
    "ar_n2_gf4": lambda: C.ar_discrepancy(2, m=2),
    "schoolbook_n2_gf4": lambda: C.polymul_schoolbook(2, m=2),
    "karatsuba2_gf4": lambda: C.polymul_karatsuba2(m=2),
    "butterfly4_gf4": lambda: C.butterfly4(m=2),
    "cyclic_n2_gf4": lambda: cyclic_mul(2, m=2),
    "cyclic_n2_weak_gf4": lambda: cyclic_mul(2, m=2, weak=True),
    "masked_lin_gf4": lambda: masked_check(2, False),
    "unchecked_gf4": lambda: unchecked_output(2),
    "square_gf4": lambda: square_check(2),
    "trap_gf4": lambda: nonlinear_trap(2),
    "unchecked_gf8": lambda: unchecked_output(3),
}


def wire(prog, doc):
    return json.loads(json.dumps(prog.to_json())), json.loads(json.dumps(doc))


# ---------------------------------------------------------- Theorem S1 ----
@pytest.mark.parametrize("name", sorted(PROGRAMS))
def test_adjoint_synthesis_is_exact_at_every_fault_linear_site(name):
    """out_f = out_ref + delta*Jo and g_f = g_ref + delta*Jd as reduced
    polynomials, for EVERY fault at EVERY fault-linear site, compared with a
    full symbolic re-execution of the faulted program."""
    prog = PROGRAMS[name]()
    F = get_field(prog.m, prog.modulus)
    z = Poly(F)
    P = S.passes(prog)
    ref_d = P.final.get(prog.disc, z).reduce()
    ref_o = [P.final.get(o, z).reduce() for o in prog.outputs]
    checked = 0
    for fault in prog.fault_space():
        if not P.linear[fault.site]:
            continue
        delta = S.delta_of(prog, P, fault)
        st = symbolic_run(prog, fault)
        assert st.get(prog.disc, z).reduce() == (ref_d + delta * P.jd[fault.site]).reduce(), fault
        for j, o in enumerate(prog.outputs):
            assert st.get(o, z).reduce() == (ref_o[j] + delta * P.jo[fault.site][j]).reduce(), fault
        checked += 1
    assert checked > 0


def test_COUNTEREXAMPLE_first_order_adjoint_is_wrong_at_nonlinear_sites():
    """square_check: d(y^2)/dy = 0 in characteristic 2, but the fault effect
    is delta^2 * R != 0. nonlinear_trap: the adjoint is x1 but the effect is
    delta*(delta + x1). The taint pass must flag exactly these sites."""
    for build, site in ((square_check, 0), (nonlinear_trap, 0)):
        prog = build(8)
        F = get_field(8)
        z = Poly(F)
        P = S.passes(prog)
        assert P.linear[site] is False
        fault = next(f for f in prog.fault_space() if f.site == site and f.kind == "bitflip")
        true_g = symbolic_run(prog, fault).get(prog.disc, z).reduce()
        first_order = (P.final.get(prog.disc, z) + S.delta_of(prog, P, fault) * P.jd[site]).reduce()
        assert true_g != first_order
    # every multiplicand-sharing site, and only those, is flagged
    assert S.taint_linear(square_check(8)) == [False, True, False, True, True, True]


@pytest.mark.parametrize("name", ["schoolbook_n3", "karatsuba2", "butterfly4", "cyclic_n3"])
def test_benchmark_circuits_are_entirely_fault_linear(name):
    assert all(S.taint_linear(PROGRAMS[name]()))


# ------------------------------------------------------------ parity ------
@pytest.mark.parametrize("name", sorted(PROGRAMS))
def test_same_verdict_as_per_fault_baseline(name):
    """Identical fault model and programs. Classification and
    wrong_output_possible must agree fault by fault; the certified bound must
    never be weaker than the baseline's."""
    prog = PROGRAMS[name]()
    base = {c["site_id"]: c for c in analyze(prog).certificates if c["fault"]}
    res = S.generate(prog)
    assert {c["site_id"] for c in res.faults} == set(base)          # no omissions
    for c in res.faults:
        b = base[c["site_id"]]
        assert c["classification"] == b["classification"], c["site_id"]
        assert c["wrong_output_possible"] == b["wrong_output_possible"], c["site_id"]
        if c["degree_bound"] is not None:
            assert c["degree_bound"] <= b["degree_bound"], c["site_id"]
    report = SC.check(*wire(prog, res.document))
    assert report["ok"], (report["errors"][:3],
                          [v for v in report["results"].values() if v != "pass"][:3])


@pytest.mark.parametrize("name", ["schoolbook_n3", "karatsuba2", "butterfly4", "cyclic_n3"])
def test_structural_classes_are_coarsenings_of_baseline_L3(name):
    """Every baseline L3 class lies inside one checker-derived structural
    class (structural classes may be coarser, never incomparable)."""
    prog = PROGRAMS[name]()
    base = {c["site_id"]: c for c in analyze(prog).certificates
            if c["fault"] and c["classification"] == "covered" and c["wrong_output_possible"]}
    report = SC.check(*wire(prog, S.generate(prog).document))
    where = {sid: k for k, members in report["classes"].items() for sid in members}
    image = {}
    for sid, c in base.items():
        image.setdefault(c["class_keys"]["L3"], set()).add(where[sid])
    assert all(len(v) == 1 for v in image.values())
    n_struct = len({where[s] for s in base})
    assert n_struct <= len(image)


def test_no_per_fault_symbolic_execution_on_fault_linear_programs():
    """The work counters, not wall-clock: 2 passes over the program, one
    template analysis per distinct template, zero baseline classifications."""
    for build in (lambda: C.polymul_schoolbook(4), C.polymul_karatsuba2, C.butterfly4,
                  lambda: cyclic_mul(4)):
        prog = build()
        res = S.generate(prog)
        w = res.work
        assert w.forward_instr == len(prog.instrs) == w.backward_instr
        assert w.perturbed_instr == 0 and w.baseline_classifications == 0
        assert w.template_analyses == len(res.document["templates"])
        assert w.template_analyses < len(prog.instrs)
        report = SC.check(*wire(prog, res.document))
        assert report["ok"] and report["stats"]["per_fault_executions"] == 0


def test_nonlinear_sites_fall_back_and_are_counted():
    prog = nonlinear_trap(8)
    res = S.generate(prog)
    assert res.work.perturbed_instr == len(prog.instrs)      # one site, one run
    assert res.work.baseline_classifications == 10           # its 10 faults
    report = SC.check(*wire(prog, res.document))
    assert report["ok"] and report["stats"]["per_fault_executions"] == 10


# ------------------------------------------------ brute-force soundness ----
@pytest.mark.parametrize("name", sorted(SMALL))
def test_exhaustive_soundness_of_structural_certificates(name):
    """Every state x every challenge x every fault, by concrete execution.
    The class statement is checked too: on every wrong state the undetected
    set equals roots(h(x,.)) plus {0} when k > 0, with (k, h) taken from the
    TEMPLATE, not from the fault."""
    prog = SMALL[name]()
    F = get_field(prog.m, prog.modulus)
    R, q = prog.challenge, 1 << prog.m
    res = S.generate(prog)
    report = SC.check(*wire(prog, res.document))
    assert report["ok"], report["errors"]
    assert len(res.faults) == len(prog.fault_space())
    T = res.document["templates"]
    for cert in res.faults:
        truth = list(ground_truth(prog, fault_of(cert)))
        cls = cert["classification"]
        if cls == "benign":
            assert all(same for *_, same in truth), cert["site_id"]
        elif cls == "covered" and cert["wrong_output_possible"] is False:
            assert not any(w for _, _, w, _, _ in truth), cert["site_id"]
        elif cls == "covered":
            quo = T[cert["template"]]["quotient"] if cert["mode"] == "template" \
                else cert["quotient"]
            h = Poly.from_json(F, quo["h"])
            for x, _, wrong_any, und, _ in truth:
                if not wrong_any:
                    continue
                assert len(und) <= cert["degree_bound"], (cert["site_id"], x)
                expect = {r for r in range(q) if h.evaluate({**x, R: r}) == 0}
                if quo["shift_k"] > 0:
                    expect.add(0)
                assert und == expect, (cert["site_id"], x)
        elif cls == "bypass":
            pt = cert["witness"]["point"]
            hit = list(ground_truth(prog, fault_of(cert), [tuple(pt[v] for v in prog.inputs)]))[0]
            assert hit[1] and len(hit[3]) == q, cert["site_id"]
        # converse: a fully bypassing state must not hide under benign/covered
        if cls in ("benign", "covered"):
            assert not any(wa and len(und) == q for _, wa, _, und, _ in truth), cert["site_id"]


# ------------------------------------------------------ compositionality ---
@pytest.mark.parametrize("name,cut", [("schoolbook_n3", 18), ("karatsuba2", 9),
                                      ("butterfly4", 15), ("cyclic_n3", 21)])
def test_adjoints_compose_across_a_cut(name, cut):
    """Theorem S4. Split P = P2 after P1 at instruction ``cut``. The adjoints
    of the P1 sites obtained by (i) a reverse pass over P2 alone, yielding one
    polynomial per live register at the cut, then (ii) a reverse pass over P1
    seeded with those, equal the whole-program adjoints. P1 is never
    re-analysed with P2, and P2 is summarised by |live registers| polynomials."""
    prog = PROGRAMS[name]()
    F = get_field(prog.m, prog.modulus)
    val, old, opa, opb, final = S.forward(prog)
    seeds = {prog.disc: Poly.var(F, S.TAG_D)}
    whole, _ = S.backward(prog, opa, opb, seeds)

    p2 = Program("p2", prog.m, prog.modulus, prog.inputs, prog.challenge,
                 prog.instrs[cut:], prog.outputs, prog.disc)
    p1 = Program("p1", prog.m, prog.modulus, prog.inputs, prog.challenge,
                 prog.instrs[:cut], [], prog.disc)
    adj2, summary = S.backward(p2, opa[cut:], opb[cut:], seeds)
    adj1, _ = S.backward(p1, opa[:cut], opb[:cut], summary)
    assert adj1 + adj2 == whole
    live = [r for r, p in summary.items() if not p.is_zero()]
    assert 0 < len(live) <= len(prog.instrs)


def test_unobserved_sites_give_algebraic_bypasses():
    """Theorem S3 on the tautological fold check: the multiplication stage
    has Jd == 0, so its faults are bypasses certified by a point evaluation."""
    prog = cyclic_mul(4, weak=True)
    res = S.generate(prog)
    modes = [c["mode"] for c in res.faults if c["classification"] == "bypass"]
    assert modes and set(modes) == {"unobserved"}
    assert res.work.baseline_classifications == 0
    assert SC.check(*wire(prog, res.document))["ok"]
    sound = S.generate(cyclic_mul(4))
    assert sound.counts()["bypass"] == 0 and sound.counts()["unknown"] == 0


def test_common_mode_fold_fault_is_detected_only_through_the_exact_relation():
    """A fault on a high-half coefficient p_{k+n} corrupts c_k AND hi_k
    coherently. With the exact relation a*b = c + (X^n - 1)*hi its template
    is R^(n+k) (one missed challenge, r = 0)."""
    n = 3
    prog = cyclic_mul(n)
    res = S.generate(prog)
    P = S.passes(prog)
    F = get_field(8)
    # last write to p_{n} in the multiplication stage
    site = max(i for i, ins in enumerate(prog.instrs)
               if ins.dst == f"p{n}" and ins.region == "data")
    assert P.jd[site] == Poly(F, {(("R", n),): 1})
    cert = next(c for c in res.faults if c["site_id"] == f"bitflip@{site}.b0")
    assert cert["classification"] == "covered" and cert["degree_bound"] == 1


def test_COUNTEREXAMPLE_same_class_different_observations():
    """Theory C3: the structural class preserves the conditional undetected
    set and nothing else. Karatsuba site m0 (instruction 0): the bit flip and
    the result-zero fault share template and class, but 'the output is wrong'
    is state-independent for one and secret-dependent for the other, and the
    unconditional non-detection probabilities over a uniform state differ."""
    prog = C.polymul_karatsuba2(m=2)
    q = 4
    res = S.generate(prog)
    report = SC.check(*wire(prog, res.document))
    by = {c["site_id"]: c for c in res.faults}
    flip, zero = by["bitflip@0.b0"], by["zero@0"]
    where = {sid: k for k, members in report["classes"].items() for sid in members}
    assert flip["template"] == zero["template"]
    assert where["bitflip@0.b0"] == where["zero@0"]
    assert flip["flags"]["effect_depends_on_state"] is False
    assert zero["flags"]["effect_depends_on_state"] is True

    stats = {}
    for cert in (flip, zero):
        wrong_states = bad = total = 0
        und_sets = set()
        for x, _, wrong_any, und, _ in ground_truth(prog, fault_of(cert)):
            total += 1
            if wrong_any:
                wrong_states += 1
                und_sets.add(frozenset(und))
                bad += len(und)
        stats[cert["site_id"]] = (wrong_states, total, und_sets, bad / (total * q))
    # identical conditional undetected set on every wrong state ...
    assert stats["bitflip@0.b0"][2] == stats["zero@0"][2] == {frozenset({1})}
    # ... but the set of wrong states differs (all states vs a0*b0 != 0)
    assert stats["bitflip@0.b0"][0] == stats["bitflip@0.b0"][1] == q ** 4
    assert stats["zero@0"][0] == (q - 1) ** 2 * q ** 2
    # ... and so does the unconditional non-detection probability
    assert stats["bitflip@0.b0"][3] == 1 / q
    assert stats["zero@0"][3] == ((q - 1) / q) ** 2 / q


def test_leakage_flags_are_reported_for_every_templated_fault():
    res = S.generate(C.polymul_schoolbook(3))
    flagged = [c for c in res.faults if c["mode"] in ("template", "no-reach")]
    assert flagged and all("flags" in c for c in flagged)
    # bit flips in the data path are always effective; zero/skip are not
    data = [c for c in flagged if c["mode"] == "template"]
    assert all(c["flags"]["effect_depends_on_state"] is (c["fault"]["kind"] != "bitflip")
               for c in data)

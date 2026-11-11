"""The checker must accept genuine certificates and reject every tampered
one. Each mutation below is an attempt to make it certify something false."""
import ast
import copy
import json
import pathlib

import pytest

from cafq import checker
from cafq import circuits as C
from cafq.analyzer import analyze
from cafq.pipeline import certify
from cafq_helpers import masked_check, unchecked_output

SRC = pathlib.Path(checker.__file__)


def wire(prog, certs):
    return json.loads(json.dumps(prog.to_json())), json.loads(json.dumps(certs))


@pytest.fixture(scope="module")
def kara():
    prog = C.polymul_karatsuba2()
    return prog, analyze(prog).certificates


@pytest.fixture(scope="module")
def ar():
    prog = C.ar_discrepancy(4, shift=1)
    return prog, analyze(prog).certificates


def run(prog, certs):
    return checker.check(*wire(prog, certs))


def by_id(certs, sid):
    return next(c for c in certs if c["site_id"] == sid)


def pick(certs, pred):
    return next(c for c in certs if c["fault"] is not None and pred(c))


def test_checker_is_independent_of_the_analyzer():
    tree = ast.parse(SRC.read_text())
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative import in trusted checker"
            mods.add(node.module)
    assert mods <= {"__future__", "hashlib", "json", "time"}, mods


@pytest.mark.parametrize("builder", [
    lambda: C.ar_discrepancy(4), lambda: C.ar_discrepancy(4, shift=1),
    lambda: C.polymul_schoolbook(3), lambda: C.polymul_karatsuba2(),
    lambda: C.butterfly4(), lambda: C.butterfly4(m=2),
    lambda: masked_check(8, True), lambda: unchecked_output(8)])
def test_genuine_certificates_pass(builder):
    analysis, report = certify(builder())
    assert report["ok"], report["errors"]
    assert report["in_scope_faults"] == len(analysis.program.fault_space())
    assert sum(report["counts"].values()) == report["in_scope_faults"]
    assert all(c["checker_result"] == "pass" for c in analysis.certificates)


def test_analyzer_and_checker_hash_the_program_identically(kara):
    prog, certs = kara
    assert run(prog, certs)["ok"]
    assert certs[0]["program_sha256"] == prog.sha256()


# ---------------------------------------------------------- manifest ------
def test_missing_certificate_is_rejected(kara):
    prog, certs = kara
    rep = run(prog, [c for c in certs if c["site_id"] != "skip@3"])
    assert not rep["ok"] and any("skip@3" in e for e in rep["errors"])


def test_duplicate_and_out_of_scope_certificates_are_rejected(kara):
    prog, certs = kara
    assert not run(prog, certs + [copy.deepcopy(certs[5])])["ok"]
    extra = copy.deepcopy(certs[5])
    extra["site_id"] = "skip@999"
    extra["fault"] = {"kind": "skip", "site": 999, "bit": None}
    assert not run(prog, certs + [extra])["ok"]


def test_restricting_the_fault_model_after_the_fact_is_visible(kara):
    """Dropping a whole fault kind from the certificate set fails unless the
    checker is explicitly told the narrower scope."""
    prog, certs = kara
    no_flips = [c for c in certs if not c["fault"] or c["fault"]["kind"] != "bitflip"]
    assert not run(prog, no_flips)["ok"]
    assert checker.check(*wire(prog, no_flips), kinds=("skip", "zero"))["ok"]


def test_wrong_program_is_rejected(kara):
    prog, certs = kara
    other = C.polymul_schoolbook(2)
    assert not run(other, certs)["ok"]
    # forging the hash does not help: the polynomials are re-derived
    forged = copy.deepcopy(certs)
    for c in forged:
        c["program_sha256"] = other.sha256()
    assert not run(other, forged)["ok"]


def test_site_id_must_match_fault(kara):
    prog, certs = kara
    bad = copy.deepcopy(certs)
    a, b = by_id(bad, "zero@0"), by_id(bad, "zero@1")
    a["fault"], b["fault"] = b["fault"], a["fault"]
    assert not run(prog, bad)["ok"]


# ----------------------------------------------------- classification -----
def mutate(certs, sid, fn):
    bad = copy.deepcopy(certs)
    fn(by_id(bad, sid))
    return bad


def test_bypass_cannot_be_relabelled(ar):
    prog, certs = ar
    sid = pick(certs, lambda c: c["classification"] == "bypass")["site_id"]
    cov = pick(certs, lambda c: c["classification"] == "covered")

    def to_benign(c):
        c["classification"] = "benign"

    def to_covered(c):
        for k in ("classification", "wrong_output_possible", "degree_bound",
                  "witness", "quotient", "class_keys"):
            c[k] = copy.deepcopy(cov[k])

    def to_covered_keep_poly(c):
        to_covered(c)
        c["quotient"]["u"] = c["discrepancy_polynomial"]   # try g = g * 1
        c["quotient"]["h"] = [[1, []]]
        c["quotient"]["shift_k"] = 0

    def to_no_wrong(c):
        c["classification"], c["wrong_output_possible"], c["degree_bound"] = "covered", False, 0

    for fn in (to_benign, to_covered, to_covered_keep_poly, to_no_wrong):
        rep = run(prog, mutate(certs, sid, fn))
        assert not rep["ok"] and rep["results"][sid] != "pass", fn.__name__


def test_covered_cannot_be_relabelled_benign(kara):
    prog, certs = kara
    sid = pick(certs, lambda c: c["classification"] == "covered")["site_id"]
    assert not run(prog, mutate(certs, sid, lambda c: c.update(classification="benign")))["ok"]


def test_fault_free_cannot_be_benign(kara):
    prog, certs = kara
    assert not run(prog, mutate(certs, "fault-free",
                                lambda c: c.update(classification="benign")))["ok"]


def test_invalid_bypass_point_is_rejected(ar):
    prog, certs = ar
    c = pick(certs, lambda c: c["classification"] == "bypass")

    def zero_point(c):
        c["witness"]["point"] = {v: 0 for v in prog.inputs}      # consistent input
    assert not run(prog, mutate(certs, c["site_id"], zero_point))["ok"]

    def partial_point(c):
        c["witness"]["point"].pop(prog.inputs[0])
    assert not run(prog, mutate(certs, c["site_id"], partial_point))["ok"]


# ----------------------------------------------------------- bounds -------
def exact_cert(certs, min_roots=1):
    return pick(certs, lambda c: c["quotient"] and c["quotient"]["exact_roots"] is not None
                and len(c["quotient"]["exact_roots"]) >= min_roots)


def test_understated_exact_bound_is_rejected(kara):
    prog, certs = kara
    sid = exact_cert(certs, 2)["site_id"]
    assert not run(prog, mutate(certs, sid, lambda c: c.update(
        degree_bound=c["degree_bound"] - 1)))["ok"]

    def drop_root(c):
        c["quotient"]["exact_roots"] = c["quotient"]["exact_roots"][:-1]
        c["degree_bound"] -= 1
    assert not run(prog, mutate(certs, sid, drop_root))["ok"]


def test_understated_degree_bound_is_rejected(ar):
    prog, certs = ar
    c = pick(certs, lambda c: c["classification"] == "covered"
             and c["quotient"]["exact_roots"] is None)
    assert c["degree_bound"] >= 1
    assert not run(prog, mutate(certs, c["site_id"], lambda c: c.update(
        degree_bound=c["degree_bound"] - 1)))["ok"]


def test_exact_roots_cannot_be_claimed_for_state_dependent_h(ar):
    prog, certs = ar
    c = pick(certs, lambda c: c["classification"] == "covered"
             and c["quotient"]["exact_roots"] is None)

    def claim(c):
        c["quotient"]["exact_roots"] = []
        c["degree_bound"] = 0
    assert not run(prog, mutate(certs, c["site_id"], claim))["ok"]


def test_tampered_witness_polynomial_and_factorisation_are_rejected(kara):
    prog, certs = kara
    c = pick(certs, lambda c: c["classification"] == "covered" and c["wrong_output_possible"]
             and c["witness"]["type"] == "linear")
    other = pick(certs, lambda d: d["classification"] == "covered" and d["wrong_output_possible"]
                 and d["quotient"]["h"] != c["quotient"]["h"])

    def bad_matrix(c):
        row = next(r for r in c["witness"]["matrix"] if any(r))
        i = next(i for i, v in enumerate(row) if v)
        row[i] ^= 1

    def zero_matrix(c):
        c["witness"]["matrix"] = [[0] * len(r) for r in c["witness"]["matrix"]]

    def bad_poly(c):
        c["discrepancy_polynomial"] = other["discrepancy_polynomial"]

    def bad_h(c):
        c["quotient"]["h"] = other["quotient"]["h"]

    def bad_u(c):
        c["quotient"]["u"] = [[1, []]]

    def u_with_challenge(c):
        # push the whole polynomial into "u" so that h = 1 has no roots
        c["quotient"]["u"] = c["discrepancy_polynomial"]
        c["quotient"]["h"] = [[1, []]]
        c["quotient"]["shift_k"] = 0
        c["quotient"]["exact_roots"] = []
        c["degree_bound"] = 0

    def no_wrong(c):
        c["wrong_output_possible"], c["degree_bound"] = False, 0

    for fn in (bad_matrix, zero_matrix, bad_poly, bad_h, bad_u, u_with_challenge, no_wrong):
        if fn is u_with_challenge and c["quotient"]["shift_k"] == 0 and \
                c["quotient"]["h"] == [[1, []]]:
            continue
        rep = run(prog, mutate(certs, c["site_id"], fn))
        assert not rep["ok"], fn.__name__


def test_challenge_dependent_unit_factor_is_rejected(kara):
    prog, certs = kara
    c = pick(certs, lambda c: c["quotient"] and c["quotient"]["shift_k"] > 0)

    def cheat(c):
        c["quotient"]["u"] = c["discrepancy_polynomial"]
        c["quotient"]["h"] = [[1, []]]
        c["quotient"]["shift_k"] = 0
        c["quotient"]["exact_roots"] = []
        c["degree_bound"] = 0
    rep = run(prog, mutate(certs, c["site_id"], cheat))
    assert not rep["ok"] and "challenge" in rep["results"][c["site_id"]]


# ------------------------------------------------- unsound quotients ------
def test_unsound_merges_are_rejected_at_every_level(kara):
    prog, certs = kara
    cov = [c for c in certs if c["fault"] and c["classification"] == "covered"
           and c["wrong_output_possible"]]
    a = cov[0]
    diff_h = next(c for c in cov if c["quotient"]["h"] != a["quotient"]["h"])
    same_h_diff_k = next(c for c in cov if c["quotient"]["h"] == a["quotient"]["h"]
                         and (c["quotient"]["shift_k"] > 0) != (a["quotient"]["shift_k"] > 0))
    nonprop = next(c for c in cov if c["class_keys"]["L2"] != a["class_keys"]["L2"])
    diff_obs = next(c for c in cov if c["class_keys"]["L1"] != a["class_keys"]["L1"])
    cases = [("L4", diff_h), ("L4", same_h_diff_k), ("L3", diff_h),
             ("L3", same_h_diff_k), ("L2", nonprop), ("L1", diff_obs)]
    for lvl, victim in cases:
        bad = mutate(certs, victim["site_id"],
                     lambda c: c["class_keys"].__setitem__(lvl, a["class_keys"][lvl]))
        rep = run(prog, bad)
        assert not rep["ok"] and any("unsound" in e and lvl in e for e in rep["errors"]), lvl


def test_merging_across_classifications_is_rejected(ar):
    prog, certs = ar
    cov = pick(certs, lambda c: c["classification"] == "covered")
    byp = pick(certs, lambda c: c["classification"] == "bypass")
    for lvl in ("L1", "L2", "L3", "L4"):
        bad = mutate(certs, byp["site_id"],
                     lambda c: c["class_keys"].__setitem__(lvl, cov["class_keys"][lvl]))
        assert not run(prog, bad)["ok"]


def test_merging_false_alarm_with_wrong_output_fault_is_rejected(kara):
    prog, certs = kara
    wrong = pick(certs, lambda c: c["classification"] == "covered" and c["wrong_output_possible"])
    alarm = pick(certs, lambda c: c["classification"] == "covered"
                 and c["wrong_output_possible"] is False)
    for lvl in ("L2", "L3", "L4"):
        bad = mutate(certs, wrong["site_id"],
                     lambda c: c["class_keys"].__setitem__(lvl, alarm["class_keys"][lvl]))
        assert not run(prog, bad)["ok"]


def test_missing_class_keys_are_rejected(kara):
    prog, certs = kara
    assert not run(prog, mutate(certs, "zero@0", lambda c: c.update(class_keys=None)))["ok"]


def test_malformed_certificates_fail_closed(kara):
    prog, certs = kara
    sid = pick(certs, lambda c: c["classification"] == "covered"
               and c["wrong_output_possible"])["site_id"]
    for fn in (lambda c: c.pop("witness"), lambda c: c.pop("quotient"),
               lambda c: c.update(discrepancy_polynomial=None),
               lambda c: c.update(classification="safe"),
               lambda c: c.update(degree_bound=None),
               lambda c: c["quotient"].update(u=[[0, []]]),
               lambda c: c["quotient"].update(shift_k=-1)):
        rep = run(prog, mutate(certs, sid, fn))
        assert not rep["ok"] and rep["results"][sid].startswith("fail")


def test_unknown_is_counted_not_passed_off_as_safe():
    prog = masked_check(8, True)
    analysis, report = certify(prog)
    assert report["ok"] and report["counts"]["unknown"] > 0
    assert report["counts"]["unknown"] == analysis.counts()["unknown"]

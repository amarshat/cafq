"""The structural checker must reject every false structural certificate.
Each test tries to make it accept a wrong claim."""
import ast
import copy
import json
import pathlib

import pytest

from cafq import circuits as C
from cafq import structural as S
from cafq import structural_checker as SC
from cafq.kernels import cyclic_mul
from cafq_helpers import nonlinear_trap, square_check, unchecked_output


def wire(prog, doc):
    return json.loads(json.dumps(prog.to_json())), json.loads(json.dumps(doc))


def run(prog, doc, **kw):
    return SC.check(*wire(prog, doc), **kw)


@pytest.fixture(scope="module")
def kara():
    prog = C.polymul_karatsuba2()
    return prog, S.generate(prog).document


@pytest.fixture(scope="module")
def weak():
    prog = cyclic_mul(3, weak=True)
    return prog, S.generate(prog).document


def fault(doc, pred):
    return next(c for c in doc["faults"] if pred(c))


def mutated(doc, sid, fn):
    bad = copy.deepcopy(doc)
    fn(next(c for c in bad["faults"] if c["site_id"] == sid), bad)
    return bad


def rejected(prog, doc, sid=None):
    rep = run(prog, doc)
    assert not rep["ok"]
    if sid is not None:
        assert rep["results"][sid] != "pass", rep["results"][sid]
    return rep


def test_trusted_base_imports():
    tree = ast.parse(pathlib.Path(SC.__file__).read_text())
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            mods.add(node.module)
    assert mods <= {"__future__", "hashlib", "json", "time", "cafq.checker"}, mods


def test_genuine_documents_pass(kara, weak):
    for prog, doc in (kara, weak):
        rep = run(prog, doc)
        assert rep["ok"] and rep["in_scope_faults"] == len(prog.fault_space())
        assert sum(rep["counts"].values()) == rep["in_scope_faults"]


# ------------------------------------------------------------- manifest ---
def test_manifest_and_identity(kara):
    prog, doc = kara
    drop = copy.deepcopy(doc)
    drop["faults"] = [c for c in drop["faults"] if c["site_id"] != "skip@3"]
    assert any("skip@3" in e for e in rejected(prog, drop)["errors"])
    dup = copy.deepcopy(doc)
    dup["faults"].append(copy.deepcopy(dup["faults"][0]))
    rejected(prog, dup)
    noflip = copy.deepcopy(doc)
    noflip["faults"] = [c for c in noflip["faults"] if c["fault"]["kind"] != "bitflip"]
    rejected(prog, noflip)
    assert run(prog, noflip, kinds=("skip", "zero"))["ok"]
    rejected(C.polymul_schoolbook(2), doc)                      # other program
    forged = copy.deepcopy(doc)
    forged["program_sha256"] = C.polymul_schoolbook(2).sha256()
    rejected(C.polymul_schoolbook(2), forged)
    fmt = copy.deepcopy(doc)
    fmt["format"] = "something-else"
    rejected(prog, fmt)


def test_site_and_fault_must_agree(kara):
    prog, doc = kara
    a = fault(doc, lambda c: c["mode"] == "template")
    b = fault(doc, lambda c: c["mode"] == "no-reach" and c["classification"] == "covered")
    rejected(prog, mutated(doc, a["site_id"], lambda c, d: c.update(fault=b["fault"])), a["site_id"])


# ------------------------------------------------------------ templates ---
def test_template_binding_is_checked(kara):
    """A fault cannot borrow the template (and bound) of another site."""
    prog, doc = kara
    by_bound = {}
    for c in doc["faults"]:
        if c["mode"] == "template" and c["wrong_output_possible"]:
            by_bound.setdefault(c["degree_bound"], c)
    assert len(by_bound) >= 2
    lo, hi = by_bound[min(by_bound)], by_bound[max(by_bound)]
    assert lo["template"] != hi["template"]

    def borrow(c, d):
        c["template"], c["degree_bound"] = lo["template"], lo["degree_bound"]
    rep = rejected(prog, mutated(doc, hi["site_id"], borrow), hi["site_id"])
    assert "do not match" in rep["results"][hi["site_id"]]


def test_understated_bound_is_rejected_at_fault_and_template_level(kara):
    prog, doc = kara
    c = fault(doc, lambda c: c["mode"] == "template" and c["degree_bound"] == 2)
    rejected(prog, mutated(doc, c["site_id"], lambda c, d: c.update(degree_bound=1)), c["site_id"])

    def lower_template(c, d):
        t = d["templates"][c["template"]]
        t["degree_bound"] -= 1
        t["quotient"]["exact_roots"] = t["quotient"]["exact_roots"][:-1]
        c["degree_bound"] -= 1
    rep = rejected(prog, mutated(doc, c["site_id"], lower_template), c["site_id"])
    # every fault bound to that template fails, not just one
    tid = c["template"]
    members = [x["site_id"] for x in doc["faults"] if x["template"] == tid and x["mode"] == "template"]
    assert all(rep["results"][s] != "pass" for s in members)


def test_tampered_template_contents_are_rejected(kara):
    prog, doc = kara
    c = fault(doc, lambda c: c["mode"] == "template" and c["wrong_output_possible"])
    other = fault(doc, lambda x: x["mode"] == "template" and x["wrong_output_possible"]
                  and doc["templates"][x["template"]]["quotient"]["h"]
                  != doc["templates"][c["template"]]["quotient"]["h"])
    oq = doc["templates"][other["template"]]

    def T(c, d):
        return d["templates"][c["template"]]

    muts = {
        "swap_h": lambda c, d: T(c, d)["quotient"].update(h=oq["quotient"]["h"]),
        "swap_jd": lambda c, d: T(c, d).update(jd=oq["jd"]),
        "zero_witness": lambda c, d: T(c, d)["witness"].update(
            matrix=[[0] * len(r) for r in T(c, d)["witness"]["matrix"]]),
        "u_is_everything": lambda c, d: (T(c, d)["quotient"].update(
            u=T(c, d)["jd"], h=[[1, []]], shift_k=0, exact_roots=[]),
            T(c, d).update(degree_bound=0), c.update(degree_bound=0)),
        "drop_quotient": lambda c, d: T(c, d).pop("quotient"),
        "kind_downgrade": lambda c, d: T(c, d).update(kind="no-reach"),
        "missing_template": lambda c, d: c.update(template="T999"),
    }
    for name, fn in muts.items():
        if name == "u_is_everything" and T(c, doc)["quotient"]["shift_k"] == 0 \
                and T(c, doc)["quotient"]["h"] == [[1, []]]:
            continue
        rejected(prog, mutated(doc, c["site_id"], fn), c["site_id"])


# ---------------------------------------------------------------- modes ---
def test_delta_zero_cannot_be_claimed_for_a_real_fault(kara):
    prog, doc = kara
    c = fault(doc, lambda c: c["mode"] == "template" and c["wrong_output_possible"])
    rejected(prog, mutated(doc, c["site_id"], lambda c, d: c.update(
        mode="delta-zero", classification="benign", wrong_output_possible=None,
        degree_bound=None)), c["site_id"])


def test_no_reach_cannot_be_claimed_for_a_data_site(kara):
    prog, doc = kara
    c = fault(doc, lambda c: c["mode"] == "template" and c["wrong_output_possible"])
    for cls in ("covered", "benign"):
        rejected(prog, mutated(doc, c["site_id"], lambda c, d: c.update(
            mode="no-reach", classification=cls, wrong_output_possible=False,
            degree_bound=0)), c["site_id"])


def test_wrong_output_cannot_be_denied(kara):
    prog, doc = kara
    c = fault(doc, lambda c: c["mode"] == "template" and c["wrong_output_possible"])
    rejected(prog, mutated(doc, c["site_id"], lambda c, d: c.update(
        wrong_output_possible=False, degree_bound=0)), c["site_id"])
    rejected(prog, mutated(doc, c["site_id"], lambda c, d: c.update(
        classification="benign")), c["site_id"])


def test_status_changing_checker_fault_cannot_be_benign(kara):
    prog, doc = kara
    c = fault(doc, lambda c: c["mode"] == "no-reach" and c["classification"] == "covered"
              and c["fault"]["kind"] == "bitflip")
    rejected(prog, mutated(doc, c["site_id"], lambda c, d: c.update(
        classification="benign")), c["site_id"])


def test_template_mode_is_refused_when_delta_depends_on_the_challenge():
    """An extra output that is a checker value: zero/skip faults there inject
    an R-dependent error, for which the template theorem does not hold."""
    prog = C.polymul_karatsuba2()
    prog2 = type(prog)(prog.name + "_leakyout", prog.m, prog.modulus, prog.inputs,
                       prog.challenge, prog.instrs, prog.outputs + ["ep"], prog.disc)
    doc = S.generate(prog2).document
    assert run(prog2, doc)["ok"]
    victim = fault(doc, lambda c: c["mode"] == "synth" and c["fault"]["kind"] == "zero")
    donor = fault(doc, lambda c: c["mode"] == "template" and c["wrong_output_possible"])

    def claim(c, d):
        for k in ("mode", "template", "classification", "wrong_output_possible", "degree_bound"):
            c[k] = donor[k]
    rejected(prog2, mutated(doc, victim["site_id"], claim), victim["site_id"])


def test_template_mode_is_refused_on_non_homogeneous_programs():
    prog = C.ar_discrepancy(3)
    doc = S.generate(prog).document
    assert run(prog, doc)["ok"]
    assert all(c["mode"] in ("synth", "delta-zero") for c in doc["faults"])
    kdoc = S.generate(C.polymul_karatsuba2()).document
    donor = fault(kdoc, lambda c: c["mode"] == "template" and c["wrong_output_possible"])
    victim = doc["faults"][0]

    def claim(c, d):
        d["templates"]["X"] = copy.deepcopy(kdoc["templates"][donor["template"]])
        c.update(mode="template", template="X", classification="covered",
                 wrong_output_possible=True, degree_bound=donor["degree_bound"])
    rejected(prog, mutated(doc, victim["site_id"], claim), victim["site_id"])


@pytest.mark.parametrize("build", [square_check, nonlinear_trap])
def test_first_order_modes_are_refused_at_nonlinear_sites(build):
    """Soundness guard for the counterexamples: relabelling a fault at a
    non-fault-linear site with any adjoint-based mode must fail."""
    prog = build(8)
    doc = S.generate(prog).document
    assert run(prog, doc)["ok"]
    victim = fault(doc, lambda c: c["fault"]["site"] == 0 and c["mode"] == "synth")
    tid = "T0"
    for mode, cls in (("no-reach", "covered"), ("no-reach", "benign"),
                      ("template", "covered"), ("unobserved", "benign")):
        rep = rejected(prog, mutated(doc, victim["site_id"], lambda c, d: c.update(
            mode=mode, template=tid, classification=cls, wrong_output_possible=False,
            degree_bound=0)), victim["site_id"])
        assert "fault-linear" in rep["results"][victim["site_id"]]


# ------------------------------------------------------------- bypasses ---
def test_unobserved_bypass_needs_a_real_witness(weak):
    prog, doc = weak
    c = fault(doc, lambda c: c["mode"] == "unobserved" and c["classification"] == "bypass")
    rejected(prog, mutated(doc, c["site_id"], lambda c, d: c["witness"].update(
        point={v: 0 for v in prog.inputs})), c["site_id"])
    rejected(prog, mutated(doc, c["site_id"], lambda c, d: c["witness"]["point"].pop(
        prog.inputs[0])), c["site_id"])
    rejected(prog, mutated(doc, c["site_id"], lambda c, d: c.update(
        classification="benign")), c["site_id"])


def test_unobserved_mode_is_refused_where_the_checker_does_observe(kara):
    prog, doc = kara
    c = fault(doc, lambda c: c["mode"] == "template" and c["wrong_output_possible"])
    rejected(prog, mutated(doc, c["site_id"], lambda c, d: c.update(
        mode="unobserved", classification="bypass",
        witness={"type": "bypass-point", "point": {v: 1 for v in prog.inputs},
                 "output_index": 0})), c["site_id"])


def test_bypass_cannot_be_relabelled_covered(weak):
    prog, doc = weak
    byp = fault(doc, lambda c: c["classification"] == "bypass")
    donor = fault(doc, lambda c: c["mode"] == "template" and c["wrong_output_possible"])

    def claim(c, d):
        for k in ("mode", "template", "classification", "wrong_output_possible", "degree_bound"):
            c[k] = donor[k]
    rejected(prog, mutated(doc, byp["site_id"], claim), byp["site_id"])


# ---------------------------------------------------------------- synth ---
def test_synth_certificates_are_fully_rechecked():
    prog = unchecked_output(8)
    prog2 = C.ar_discrepancy(4, shift=1)
    doc = S.generate(prog2).document
    cov = fault(doc, lambda c: c["mode"] == "synth" and c["classification"] == "covered")
    byp = fault(doc, lambda c: c["mode"] == "synth" and c["classification"] == "bypass")
    rejected(prog2, mutated(doc, cov["site_id"], lambda c, d: c.update(
        degree_bound=c["degree_bound"] - 1)), cov["site_id"])
    rejected(prog2, mutated(doc, cov["site_id"], lambda c, d: c.update(
        discrepancy_polynomial=[[1, []]])), cov["site_id"])
    rejected(prog2, mutated(doc, byp["site_id"], lambda c, d: c.update(
        classification="benign")), byp["site_id"])
    rejected(prog2, mutated(doc, byp["site_id"], lambda c, d: c["witness"].update(
        point={v: 0 for v in prog2.inputs})), byp["site_id"])
    assert run(prog, S.generate(prog).document)["ok"]


def test_classes_are_derived_by_the_checker_not_claimed(kara):
    """There is no class field to tamper with: adding one changes nothing."""
    prog, doc = kara
    rep0 = run(prog, doc)
    bad = copy.deepcopy(doc)
    for c in bad["faults"]:
        c["class_keys"] = {"L3": "everything-in-one-class"}
    rep1 = run(prog, bad)
    assert rep1["ok"] and rep1["classes"] == rep0["classes"]
    assert len([k for k in rep0["classes"] if k.startswith("covered|k=")]) == 5


def test_malformed_documents_fail_closed(kara):
    prog, doc = kara
    c = fault(doc, lambda c: c["mode"] == "template" and c["wrong_output_possible"])
    for fn in (lambda c, d: c.pop("mode"), lambda c, d: c.update(mode="magic"),
               lambda c, d: c.update(classification="safe"),
               lambda c, d: c.pop("template"),
               lambda c, d: d["templates"][c["template"]].update(jd=[[0, []]]),
               lambda c, d: d["templates"][c["template"]].update(jo="x")):
        rejected(prog, mutated(doc, c["site_id"], fn), c["site_id"])

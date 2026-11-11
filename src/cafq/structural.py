"""Structural fault quotient (UNTRUSTED generator) -- approach C.

Instead of symbolically re-executing the program once per fault, do

  1. one forward symbolic pass over the fault-free program
     (value written at every site, value overwritten at every site);
  2. one bit-set taint pass (which sites is each value a function of) to
     decide, per site, whether everything downstream is AFFINE in the value
     written there ("fault-linear site");
  3. one reverse-mode (adjoint) pass seeded with formal tags, giving for
     every site i the polynomials
         Jd_i  = d disc   / d value_i
         Jo_ij = d out_j  / d value_i .

For a fault f at a fault-linear site i the faulted observation is then
EXACTLY (structural theory, Theorem S1)
         out_f = out_ref + delta_f * Jo_i ,   g_f = g_ref + delta_f * Jd_i
with delta_f the injected error (bit flip: constant; zero: value_i;
skip: value_i + overwritten value). No per-fault execution is needed.

A site with Jd_i == 0 and Jo_i != 0 is unobserved by the checker: every
fault there with delta_f * Jo_i != 0 is a bypass, certified by one point
evaluation (Theorem S3).

When additionally g_ref == 0, no input-inconsistency registers are active
and delta_f does not involve the challenge, the detection behaviour of f is
a property of the SITE TEMPLATE (Jd_i, Jo_i) alone (Theorem S2): witness,
unit-content factorisation Jd_i = u R^k h and root set are computed once per
distinct template and shared by every fault of every kind at every site
with that template.

Sites that are not fault-linear get one symbolic execution with a formal
perturbation variable (shared by all fault kinds at the site); faults that
fit no template are synthesised from the adjoints and handed to the
baseline classifier. Nothing is silently dropped.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

from .analyzer import Reference, classify_observation
from .field import get_field
from .ir import FAULT_KINDS, Fault, Program
from .poly import Poly, exact_divide, solve_in_span

FORMAT = "cafq-structural-0.2"
TAG_D = "@d"
PERT = "@delta"


def _tag_o(j: int) -> str:
    return f"@o{j}"


@dataclass
class Work:
    """Operation counts, so that 'less work' is not only a wall-clock claim."""
    forward_instr: int = 0          # symbolic instruction executions
    backward_instr: int = 0
    perturbed_instr: int = 0        # executions with a formal perturbation
    per_fault_poly_mul: int = 0     # cheap membership multiplications
    template_analyses: int = 0      # witness + factorisation + roots
    baseline_classifications: int = 0   # faults sent to the per-fault classifier

    def as_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class Passes:
    val: list            # reduced value written by instruction i
    old: list            # reduced value of dst just before instruction i
    opa: list
    opb: list
    final: dict
    linear: list         # fault-linear site?
    jd: list             # d disc / d value_i
    jo: list             # [d out_j / d value_i]


def forward(prog: Program, work: Work | None = None):
    F = get_field(prog.m, prog.modulus)
    zero = Poly(F)
    reg = {v: Poly.var(F, v) for v in prog.inputs + [prog.challenge]}
    val, old, opa, opb = [], [], [], []
    for ins in prog.instrs:
        a = reg.get(ins.a, zero) if isinstance(ins.a, str) else zero
        b = reg.get(ins.b, zero) if ins.b is not None else zero
        if ins.op == "const":
            v = Poly.const(F, ins.a)
        elif ins.op == "mov":
            v = a
        elif ins.op == "add":
            v = a + b
        else:
            v = (a * b).reduce()
        old.append(reg.get(ins.dst, zero))
        opa.append(a)
        opb.append(b)
        val.append(v)
        reg[ins.dst] = v
        if work:
            work.forward_instr += 1
    return val, old, opa, opb, reg


def taint_linear(prog: Program) -> list[bool]:
    """linear[i] is True iff no multiplication downstream of site i has both
    operands depending on the value written at i. Pure bit-set dataflow."""
    taint: dict[str, int] = {}
    nonlinear = 0
    for i, ins in enumerate(prog.instrs):
        ta = taint.get(ins.a, 0) if isinstance(ins.a, str) else 0
        tb = taint.get(ins.b, 0) if ins.b is not None else 0
        if ins.op == "mul":
            nonlinear |= ta & tb
        t = (1 << i)
        if ins.op in ("mov", "add", "mul"):
            t |= ta | tb
        taint[ins.dst] = t
    return [not (nonlinear >> i) & 1 for i in range(len(prog.instrs))]


def backward(prog: Program, opa: list, opb: list, seeds: dict,
             work: Work | None = None) -> tuple[list, dict]:
    """Reverse-mode pass. ``seeds`` maps register -> adjoint polynomial of the
    final value. Returns (adjoint of the value written at each site,
    adjoints of the registers live at program entry)."""
    F = get_field(prog.m, prog.modulus)
    zero = Poly(F)
    adj = dict(seeds)
    out = [zero] * len(prog.instrs)
    for i in range(len(prog.instrs) - 1, -1, -1):
        ins = prog.instrs[i]
        A = adj.pop(ins.dst, zero)
        out[i] = A
        if work:
            work.backward_instr += 1
        if A.is_zero() or ins.op == "const":
            continue
        if ins.op == "mov":
            adj[ins.a] = adj.get(ins.a, zero) + A
        elif ins.op == "add":
            adj[ins.a] = adj.get(ins.a, zero) + A
            adj[ins.b] = adj.get(ins.b, zero) + A
        else:
            adj[ins.a] = adj.get(ins.a, zero) + (A * opb[i]).reduce()
            adj[ins.b] = adj.get(ins.b, zero) + (A * opa[i]).reduce()
    return out, adj


def _split_tags(F, A: Poly, n_out: int) -> tuple[Poly, list[Poly]]:
    jd: dict = {}
    jo: list[dict] = [dict() for _ in range(n_out)]
    for mono, c in A.t.items():
        rest = tuple(p for p in mono if not p[0].startswith("@"))
        tag = next(p[0] for p in mono if p[0].startswith("@"))
        if tag == TAG_D:
            jd[rest] = c
        else:
            jo[int(tag[2:])][rest] = c
    return Poly(F, jd), [Poly(F, t) for t in jo]


def passes(prog: Program, work: Work | None = None) -> Passes:
    F = get_field(prog.m, prog.modulus)
    zero = Poly(F)
    val, old, opa, opb, final = forward(prog, work)
    seeds: dict = {}
    seeds[prog.disc] = Poly.var(F, TAG_D)
    for j, o in enumerate(prog.outputs):
        seeds[o] = seeds.get(o, zero) + Poly.var(F, _tag_o(j))
    adj, _ = backward(prog, opa, opb, seeds, work)
    jd, jo = [], []
    for A in adj:
        d, o = _split_tags(F, A, len(prog.outputs))
        jd.append(d)
        jo.append(o)
    return Passes(val, old, opa, opb, final, taint_linear(prog), jd, jo)


def delta_of(prog: Program, P: Passes, fault: Fault) -> Poly:
    F = get_field(prog.m, prog.modulus)
    if fault.kind == "bitflip":
        return Poly.const(F, 1 << fault.bit)
    if fault.kind == "zero":
        return P.val[fault.site]
    return P.val[fault.site] + P.old[fault.site]


def _unit_content(F, R: str, g: Poly):
    """g = u(x) * R^k * h with the same normalisation as the baseline."""
    coeffs = g.coeffs_in(R)
    degs = sorted(coeffs)
    k = degs[0]
    low = coeffs[k]
    hs = {d: exact_divide(coeffs[d], low) for d in degs}
    if all(v is not None for v in hs.values()):
        u = low
    else:
        lead = max(low.t)
        u = Poly.const(F, low.t[lead])
        inv = F.inv(low.t[lead])
        hs = {d: coeffs[d].scale(inv) for d in degs}
    h = Poly(F)
    for d in degs:
        mono = ((R, d - k),) if d > k else ()
        h = h + hs[d] * Poly(F, {mono: 1})
    h = h.reduce()
    bound = h.degree_in(R) + (1 if k > 0 else 0)
    exact = None
    if all(c.is_const() for c in h.coeffs_in(R).values()):
        exact = sorted({r for r in range(F.q) if h.evaluate({R: r}) == 0}
                       | ({0} if k > 0 else set()))
        bound = len(exact)
    return k, u, h, bound, exact


def analyse_template(prog: Program, jd: Poly, jo: list[Poly]) -> dict:
    """The expensive, once-per-template work."""
    F = get_field(prog.m, prog.modulus)
    R = prog.challenge
    t = {"jd": jd.to_json(), "jo": [p.to_json() for p in jo], "kind": None,
         "witness": None, "quotient": None, "degree_bound": None,
         "jo_has_nonzero_const": any(p.is_const() and not p.is_zero() for p in jo)}
    if all(p.is_zero() for p in jo):
        t["kind"] = "no-reach"
        return t
    if any(R in p.variables() for p in jo):
        t["kind"] = "no-template"
        return t
    if jd.is_zero():
        # the checker does not observe this site at all
        t["kind"] = "unobserved"
        return t
    coeffs = jd.coeffs_in(R)
    degs = sorted(coeffs)
    basis = [coeffs[d] for d in degs]
    rows = [solve_in_span(F, basis, p) for p in jo]
    if all(r is not None for r in rows):
        t["witness"] = {"type": "linear", "degrees": degs, "matrix": rows}
    else:
        lam = solve_in_span(F, basis, Poly.const(F, 1))
        if lam is None:
            t["kind"] = "no-template"
            return t
        t["witness"] = {"type": "unit", "degrees": degs, "lambda": lam}
    k, u, h, bound, exact = _unit_content(F, R, jd)
    t["kind"] = "template"
    t["degree_bound"] = bound
    t["quotient"] = {"shift_k": k, "u": u.to_json(), "h": h.to_json(),
                     "h_text": repr(h), "exact_roots": exact,
                     "naive_degree": jd.degree_in(R)}
    return t


def _perturbed_run(prog: Program, site: int, work: Work):
    """Symbolic run with value_site replaced by value_site + PERT."""
    F = get_field(prog.m, prog.modulus)
    zero = Poly(F)
    reg = {v: Poly.var(F, v) for v in prog.inputs + [prog.challenge]}
    for i, ins in enumerate(prog.instrs):
        if ins.op == "const":
            v = Poly.const(F, ins.a)
        elif ins.op == "mov":
            v = reg.get(ins.a, zero)
        elif ins.op == "add":
            v = reg.get(ins.a, zero) + reg.get(ins.b, zero)
        else:
            v = reg.get(ins.a, zero) * reg.get(ins.b, zero)
        if i == site:
            v = v + Poly.var(F, PERT)
        reg[ins.dst] = v
        work.perturbed_instr += 1
    return reg


def _substitute(F, p: Poly, delta: Poly) -> Poly:
    acc, pw, d = Poly(F), Poly.const(F, 1), 0
    coeffs = p.coeffs_in(PERT)
    for e in sorted(coeffs):
        while d < e:
            pw = (pw * delta).reduce()
            d += 1
        acc = acc + coeffs[e] * pw
    return acc.reduce()


@dataclass
class StructuralResult:
    program: Program
    document: dict
    seconds: float
    work: Work

    @property
    def faults(self) -> list[dict]:
        return self.document["faults"]

    def counts(self) -> dict:
        c = {"sites": 0, "benign": 0, "covered": 0, "covered_wrong_possible": 0,
             "bypass": 0, "unknown": 0}
        for cert in self.faults:
            c["sites"] += 1
            c[cert["classification"]] += 1
            if cert["classification"] == "covered" and cert["wrong_output_possible"]:
                c["covered_wrong_possible"] += 1
        return c


def generate(prog: Program, kinds=FAULT_KINDS, seed: int = 0) -> StructuralResult:
    t0 = time.perf_counter()
    work = Work()
    rng = random.Random(seed)
    F = get_field(prog.m, prog.modulus)
    R, zero = prog.challenge, Poly(F)
    P = passes(prog, work)
    ref = Reference([P.final.get(o, zero).reduce() for o in prog.outputs],
                    P.final.get(prog.disc, zero).reduce(),
                    [P.final.get(w, zero).reduce() for w in prog.inconsistency])
    homogeneous = ref.disc.is_zero() and all(w.is_zero() for w in ref.incons)

    templates: dict[str, dict] = {}
    template_ids: dict = {}

    def template_for(i: int) -> tuple[str, dict]:
        key = (P.jd[i], tuple(P.jo[i]))
        tid = template_ids.get(key)
        if tid is None:
            tid = f"T{len(template_ids)}"
            template_ids[key] = tid
            templates[tid] = analyse_template(prog, P.jd[i], P.jo[i])
            work.template_analyses += 1
        return tid, templates[tid]

    perturbed: dict[int, dict] = {}
    faults: list[dict] = []

    def base(fault: Fault) -> dict:
        return {"site_id": fault.site_id,
                "fault": {"kind": fault.kind, "site": fault.site, "bit": fault.bit},
                "region": prog.instrs[fault.site].region,
                "classification": None, "mode": None, "template": None,
                "wrong_output_possible": None, "degree_bound": None}

    def synth(fault: Fault, outs: list[Poly], g: Poly) -> dict:
        work.baseline_classifications += 1
        full = classify_observation(prog, ref, fault, outs, g, rng)
        cert = base(fault)
        cert["mode"] = "synth"
        for k in ("classification", "wrong_output_possible", "degree_bound",
                  "discrepancy_polynomial", "witness", "quotient", "reason"):
            cert[k] = full[k]
        return cert

    def prod(a: Poly, b: Poly) -> Poly:
        work.per_fault_poly_mul += 1
        return (a * b).reduce()

    for fault in prog.fault_space(kinds):
        i = fault.site
        delta = delta_of(prog, P, fault)
        cert = base(fault)
        if delta.is_zero():
            cert.update(classification="benign", mode="delta-zero")
            faults.append(cert)
            continue
        if not P.linear[i]:
            if i not in perturbed:
                perturbed[i] = _perturbed_run(prog, i, work)
            st = perturbed[i]
            outs = [_substitute(F, st.get(o, zero), delta) for o in prog.outputs]
            g = _substitute(F, st.get(prog.disc, zero), delta)
            faults.append(synth(fault, outs, g))
            continue
        tid, T = template_for(i)
        r_free = R not in delta.variables()
        # Reported, never bounded: is "the output is wrong" / "the alarm
        # fires" a function of the (possibly secret) state?  Exact for the
        # product delta*J whenever one factor is a nonzero constant.
        cert["flags"] = {
            "effect_depends_on_state": any(not p.is_zero() for p in P.jo[i]) and (
                not delta.is_const() or any(not p.is_const() for p in P.jo[i])),
            "status_depends_on_state": (not P.jd[i].is_zero()) and (
                not delta.is_const()
                or any(not c.is_const() for c in P.jd[i].coeffs_in(R).values())),
        }
        if T["kind"] == "no-reach" and all(w.is_zero() for w in ref.incons):
            cert["mode"], cert["template"] = "no-reach", tid
            if P.jd[i].is_zero() or prod(delta, P.jd[i]).is_zero():
                cert["classification"] = "benign"
            else:
                cert.update(classification="covered", wrong_output_possible=False,
                            degree_bound=0)
            faults.append(cert)
            continue
        if T["kind"] == "template" and homogeneous and r_free:
            cert["mode"], cert["template"] = "template", tid
            wrong = T["jo_has_nonzero_const"] or \
                any(not prod(delta, p).is_zero() for p in P.jo[i] if not p.is_zero())
            if wrong:
                cert.update(classification="covered", wrong_output_possible=True,
                            degree_bound=T["degree_bound"])
            elif prod(delta, P.jd[i]).is_zero():
                cert["classification"] = "benign"
            else:
                cert.update(classification="covered", wrong_output_possible=False,
                            degree_bound=0)
            faults.append(cert)
            continue
        if T["kind"] == "unobserved" and ref.disc.is_zero() and r_free:
            # g_f = g_ref + delta * 0 = 0 identically: the fault is a bypass
            # as soon as delta * Jo_j is nonzero at some state (Theorem S3).
            hit = None
            for j, p in enumerate(P.jo[i]):
                if p.is_zero():
                    continue
                pj = prod(delta, p)
                if pj.is_zero():
                    continue
                for _ in range(200):
                    pt = {v: rng.randrange(F.q) for v in prog.inputs}
                    if pj.evaluate(pt):
                        hit = (j, pt)
                        break
                if hit:
                    break
            else:
                cert.update(classification="benign", mode="unobserved", template=tid)
                faults.append(cert)
                continue
            if hit:
                cert.update(classification="bypass", mode="unobserved", template=tid,
                            wrong_output_possible=True,
                            witness={"type": "bypass-point", "point": hit[1],
                                     "output_index": hit[0]})
                faults.append(cert)
                continue
        outs = [(a + prod(delta, p)).reduce() if not p.is_zero() else a
                for a, p in zip(ref.outs, P.jo[i])]
        g = (ref.disc + prod(delta, P.jd[i])).reduce() if not P.jd[i].is_zero() else ref.disc
        faults.append(synth(fault, outs, g))

    doc = {"format": FORMAT, "program_sha256": prog.sha256(),
           "fault_kinds": list(kinds), "templates": templates, "faults": faults}
    return StructuralResult(prog, doc, time.perf_counter() - t0, work)

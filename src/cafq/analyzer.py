"""CAFQ analyzer (UNTRUSTED): symbolic fault propagation, classification,
witness search and quotient construction. Everything it emits is re-checked
by cafq.checker, which shares no code with this module.

Bad event for a fault f at state x and challenge r:
        W_f(x) != 0   and   g_f(x; r) == 0
where g_f is the faulted discrepancy register and W_f ("wrongness") is the
vector (faulted outputs - reference outputs) ++ (reference values of the
declared inconsistency registers).
"""
from __future__ import annotations

import itertools
import random
import time
from dataclasses import dataclass, field

from .field import get_field
from .ir import FAULT_KINDS, Fault, Program
from .poly import Poly, exact_divide, gauss, solve_in_span

CERT_VERSION = "0.1"


def symbolic_run(prog: Program, fault: Fault | None) -> dict[str, Poly]:
    F = get_field(prog.m, prog.modulus)
    zero = Poly(F)
    reg = {v: Poly.var(F, v) for v in prog.inputs + [prog.challenge]}
    for i, ins in enumerate(prog.instrs):
        hit = fault is not None and fault.site == i
        if hit and fault.kind == "skip":
            continue
        if ins.op == "const":
            v = Poly.const(F, ins.a)
        elif ins.op == "mov":
            v = reg.get(ins.a, zero)
        elif ins.op == "add":
            v = reg.get(ins.a, zero) + reg.get(ins.b, zero)
        else:
            v = (reg.get(ins.a, zero) * reg.get(ins.b, zero)).reduce()
        if hit and fault.kind == "zero":
            v = zero
        if hit and fault.kind == "bitflip":
            v = v + Poly.const(F, 1 << fault.bit)
        reg[ins.dst] = v
    return reg


@dataclass
class Reference:
    outs: list[Poly]
    disc: Poly
    incons: list[Poly]


def reference(prog: Program) -> Reference:
    F = get_field(prog.m, prog.modulus)
    st = symbolic_run(prog, None)
    z = Poly(F)
    return Reference([st.get(o, z).reduce() for o in prog.outputs],
                     st.get(prog.disc, z).reduce(),
                     [st.get(w, z).reduce() for w in prog.inconsistency])


def _monic(p: Poly) -> Poly:
    lead = max(p.t)
    return p.scale(p.F.inv(p.t[lead]))


def _find_bypass(prog: Program, W: list[Poly], gi: list[Poly], rng: random.Random,
                 budget: int = 600) -> dict | None:
    """Search a state x with every g_i(x) == 0 (so the faulted discrepancy is
    0 for EVERY challenge) and W(x) != 0 for every challenge."""
    F = get_field(prog.m, prog.modulus)
    q, xs, R = F.q, prog.inputs, prog.challenge
    w_has_r = any(R in w.variables() for w in W)

    def ok(pt: dict) -> bool:
        if any(g.evaluate(pt) for g in gi):
            return False
        rs = range(q) if w_has_r else (0,)
        return all(any(w.evaluate({**pt, R: r}) for w in W) for r in rs)

    def candidates():
        if all(g.total_degree() <= 1 for g in gi) and gi:
            rows = []
            for g in gi:
                row = [0] * (len(xs) + 1)
                for mono, c in g.t.items():
                    if mono == ():
                        row[-1] ^= c
                    else:
                        row[xs.index(mono[0][0])] ^= c
                rows.append(row)
            sol = gauss(F, rows, len(xs))
            if sol is None:
                return
            part, null = sol
            yield part
            for vec in null:
                for c in (1, 2 % q or 1):
                    yield [p ^ F.mul(c, v) for p, v in zip(part, vec)]
            for _ in range(60):
                pt = part[:]
                for vec in null:
                    c = rng.randrange(q)
                    pt = [p ^ F.mul(c, v) for p, v in zip(pt, vec)]
                yield pt
        elif q ** len(xs) <= 1 << 16:
            yield from (list(p) for p in itertools.product(range(q), repeat=len(xs)))
        else:
            for i in range(len(xs)):
                for v in range(1, q):
                    pt = [0] * len(xs)
                    pt[i] = v
                    yield pt
            for _ in range(budget):
                yield [rng.randrange(q) for _ in xs]

    for cand in candidates():
        pt = dict(zip(xs, cand))
        if ok(pt):
            return pt
    return None


def analyze_fault(prog: Program, ref: Reference, fault: Fault | None,
                  rng: random.Random) -> dict:
    F = get_field(prog.m, prog.modulus)
    z = Poly(F)
    st = symbolic_run(prog, fault)
    outs = [st.get(o, z).reduce() for o in prog.outputs]
    g = st.get(prog.disc, z).reduce()
    return classify_observation(prog, ref, fault, outs, g, rng)


def classify_observation(prog: Program, ref: Reference, fault: Fault | None,
                         outs: list[Poly], g: Poly, rng: random.Random) -> dict:
    """Classification, witness search and quotient data for a fault whose
    reduced faulted outputs ``outs`` and discrepancy ``g`` are already known.
    Split out of analyze_fault (behaviour unchanged) so that other front ends
    can supply (outs, g) without a full symbolic re-execution."""
    F = get_field(prog.m, prog.modulus)
    R = prog.challenge
    E = [a + b for a, b in zip(outs, ref.outs)]
    W = E + ref.incons
    region = prog.instrs[fault.site].region if fault else "none"
    cert = {
        "version": CERT_VERSION,
        "program_sha256": prog.sha256(),
        "ir_or_isa": "toy-ir-v1",
        "compiler_and_flags": "not-applicable",
        "fault_model": f"single-dynamic-instruction-{fault.kind}" if fault else "fault-free",
        "observation_model": "output-registers-and-detection-status",
        "challenge_model": f"fresh-hidden-uniform-GF{F.q}",
        "site_id": fault.site_id if fault else "fault-free",
        "fault": {"kind": fault.kind, "site": fault.site, "bit": fault.bit} if fault else None,
        "region": region,
        "classification": None,
        "wrong_output_possible": None,
        "discrepancy_polynomial": g.to_json(),
        "discrepancy_polynomial_text": repr(g),
        "degree_bound": None,
        "preconditions": [],
        "witness": None,
        "quotient": None,
        "flags": {
            "status_changed": g != ref.disc,
            # detection status is a function of the (possibly secret) state:
            # an ineffective-fault observable. Reported, never bounded here.
            "status_depends_on_state": any(not c.is_const() for c in g.coeffs_in(R).values()),
        },
        "class_keys": None,
        "reason": None,
        "proof_artifact": None,
        "checker_result": "not-checked",
    }
    exact_key = repr((outs, g))

    def finish(cls: str, keys: dict | None = None) -> dict:
        cert["classification"] = cls
        base = {"L1": f"{cls}|{exact_key}"}
        for lvl in ("L2", "L3", "L4"):
            base[lvl] = (keys or {}).get(lvl, base["L1"])
        cert["class_keys"] = base
        return cert

    if fault is not None and outs == ref.outs and g == ref.disc:
        cert["discrepancy_polynomial"] = None
        cert["discrepancy_polynomial_text"] = None
        cert["class_keys"] = {l: "benign" for l in ("L1", "L2", "L3", "L4")}
        cert["classification"] = "benign"
        return cert

    if all(w.is_zero() for w in W):
        cert["wrong_output_possible"] = False
        cert["degree_bound"] = 0
        cert["witness"] = {"type": "wrongness-identically-zero"}
        k = "covered|wrong-impossible"
        return finish("covered", {"L2": k, "L3": k, "L4": k})

    cert["wrong_output_possible"] = True
    coeffs = g.coeffs_in(R)
    degs = sorted(coeffs)
    basis = [coeffs[d] for d in degs]
    witness = None
    if not any(R in w.variables() for w in W) and degs:
        rows = [solve_in_span(F, basis, w) for w in W]
        if all(r is not None for r in rows):
            witness = {"type": "linear", "degrees": degs, "matrix": rows}
    if witness is None and degs:
        lam = solve_in_span(F, basis, Poly.const(F, 1))
        if lam is not None:
            witness = {"type": "unit", "degrees": degs, "lambda": lam}

    if witness is None:
        pt = _find_bypass(prog, W, basis, rng)
        if pt is not None:
            cert["witness"] = {"type": "bypass-point", "point": pt}
            cert["reason"] = ("state exists where the output/input is wrong and the "
                              "faulted discrepancy is zero for every challenge")
            return finish("bypass")
        cert["reason"] = "no linear or unit witness and no bypass state found"
        return finish("unknown")

    # ---- covered: build the quotient data  g = u(x) * R^k * h(x; R)
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
    exact_roots = None
    if all(c.is_const() for c in h.coeffs_in(R).values()):
        exact_roots = sorted({r for r in range(F.q) if h.evaluate({R: r}) == 0}
                             | ({0} if k > 0 else set()))
        bound = len(exact_roots)
    cert["witness"] = witness
    cert["degree_bound"] = bound
    cert["quotient"] = {
        "shift_k": k, "u": u.to_json(), "h": h.to_json(), "h_text": repr(h),
        "exact_roots": exact_roots, "naive_degree": g.degree_in(R),
    }
    return finish("covered", {
        "L2": "covered|scale|" + repr(_monic(g)),
        "L3": f"covered|k={k}|" + repr(h),
        "L4": f"covered|zero_root={k > 0}|" + repr(h),
    })


@dataclass
class Analysis:
    program: Program
    certificates: list[dict]
    seconds: float
    classes: dict = field(default_factory=dict)

    def counts(self) -> dict:
        c = {"sites": 0, "benign": 0, "covered": 0, "covered_wrong_possible": 0,
             "bypass": 0, "unknown": 0}
        for cert in self.certificates:
            if cert["fault"] is None:
                continue
            c["sites"] += 1
            c[cert["classification"]] += 1
            if cert["classification"] == "covered" and cert["wrong_output_possible"]:
                c["covered_wrong_possible"] += 1
        return c

    def class_counts(self, only_wrong_possible: bool = False) -> dict:
        out = {}
        for lvl in ("L1", "L2", "L3", "L4"):
            keys = set()
            for cert in self.certificates:
                if cert["fault"] is None:
                    continue
                if only_wrong_possible and not (cert["classification"] == "covered"
                                                and cert["wrong_output_possible"]):
                    continue
                keys.add(cert["class_keys"][lvl])
            out[lvl] = len(keys)
        return out


def analyze(prog: Program, kinds=FAULT_KINDS, seed: int = 0) -> Analysis:
    t0 = time.perf_counter()
    rng = random.Random(seed)
    ref = reference(prog)
    certs = [analyze_fault(prog, ref, None, rng)]
    certs += [analyze_fault(prog, ref, f, rng) for f in prog.fault_space(kinds)]
    return Analysis(prog, certs, time.perf_counter() - t0)

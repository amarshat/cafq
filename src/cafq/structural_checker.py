"""Checker for structural-quotient certificates (format cafq-structural-0.2).

TRUSTED. Standard library plus the baseline trusted checker's primitives
(cafq.checker); nothing from the analyzer, the structural generator or their
polynomial code (enforced by tests/test_structural_checker.py).

It does NOT execute the program once per fault. It performs
  * one forward symbolic pass, one bit-set taint pass and one tagged
    reverse-mode pass of its own (so the adjoints are never taken on trust);
  * one template check per DISTINCT template referenced by a certificate
    (witness identity, factorisation Jd = u R^k h, root set / bound);
  * per fault: mode-specific membership checks that cost at most a few
    polynomial comparisons or multiplications.
Only faults at sites that are not fault-linear are re-executed individually.
Bypasses at sites the checker never observes (Jd == 0) are validated by one
point evaluation; other bypasses by concrete execution over all challenges.

Meaning of a PASS is identical to the baseline checker's (see its
docstring): benign / covered with a bound on undetected challenges for every
wrong state / bypass with a verified state / unknown. Class membership is
never read from the certificate: the checker derives each fault's class key
(k, h) itself from the template it validated.
"""
from __future__ import annotations

import hashlib
import json
import time

from cafq.checker import (KINDS, _Field, _Reject, _check_bypass, _check_covered,
                          _fault_space, _load, _need, _p_add, _p_canon, _p_mul,
                          _p_parse, _p_vars, _site_id)

FORMAT = "cafq-structural-0.2"
_TAG_D = "@d"


def _forward(F, prog):
    reg = {v: {((v, 1),): 1} for v in prog["inputs"] + [prog["challenge"]]}
    val, old, opa, opb = [], [], [], []
    for op, dst, a, b, _region in prog["instrs"]:
        pa = reg.get(a, {}) if isinstance(a, str) else {}
        pb = reg.get(b, {}) if b is not None else {}
        if op == "const":
            _need(isinstance(a, int) and 0 <= a < F.q, "bad immediate")
            v = {(): a} if a else {}
        elif op == "mov":
            v = pa
        elif op == "add":
            v = _p_add(pa, pb)
        elif op == "mul":
            v = _p_mul(F, pa, pb)
        else:
            raise _Reject(f"unknown op {op}")
        old.append(reg.get(dst, {}))
        opa.append(pa)
        opb.append(pb)
        val.append(v)
        reg[dst] = v
    return val, old, opa, opb, reg


def _linear_sites(prog) -> list[bool]:
    taint: dict = {}
    nonlinear = 0
    for i, (op, dst, a, b, _region) in enumerate(prog["instrs"]):
        ta = taint.get(a, 0) if isinstance(a, str) else 0
        tb = taint.get(b, 0) if b is not None else 0
        if op == "mul":
            nonlinear |= ta & tb
        t = 1 << i
        if op in ("mov", "add", "mul"):
            t |= ta | tb
        taint[dst] = t
    return [not (nonlinear >> i) & 1 for i in range(len(prog["instrs"]))]


def _backward(F, prog, opa, opb):
    """Tagged reverse pass: returns per site (Jd, [Jo_j])."""
    adj: dict = {}

    def bump(reg, p):
        adj[reg] = _p_add(adj.get(reg, {}), p)

    bump(prog["disc"], {((_TAG_D, 1),): 1})
    for j, o in enumerate(prog["outputs"]):
        bump(o, {((f"@o{j}", 1),): 1})
    n_out = len(prog["outputs"])
    res = [None] * len(prog["instrs"])
    for i in range(len(prog["instrs"]) - 1, -1, -1):
        op, dst, a, b, _region = prog["instrs"][i]
        A = adj.pop(dst, {})
        jd: dict = {}
        jo = [dict() for _ in range(n_out)]
        for mono, c in A.items():
            tag = next(v for v, _ in mono if v.startswith("@"))
            rest = tuple(p for p in mono if not p[0].startswith("@"))
            (jd if tag == _TAG_D else jo[int(tag[2:])])[rest] = c
        res[i] = (jd, jo)
        if not A or op == "const":
            continue
        if op == "mov":
            bump(a, A)
        elif op == "add":
            bump(a, A)
            bump(b, A)
        else:
            bump(a, _p_mul(F, A, opb[i]))
            bump(b, _p_mul(F, A, opa[i]))
    return res


def _p_eval(F, p: dict, pt: dict) -> int:
    acc = 0
    for mono, c in p.items():
        term = c
        for var, e in mono:
            term = F.mul(term, F.pow(pt[var], e))
        acc ^= term
    return acc


def check(program: dict, document: dict, kinds=KINDS) -> dict:
    t0 = time.perf_counter()
    stats = {"templates_checked": 0, "per_fault_poly_mul": 0,
             "per_fault_executions": 0, "template_faults": 0}
    results: dict[str, str] = {}
    errors: list[str] = []
    class_of: dict[str, str] = {}
    counts = {"benign": 0, "covered": 0, "bypass": 0, "unknown": 0}

    if document.get("format") != FORMAT:
        return {"ok": False, "errors": ["unknown certificate format"], "results": {},
                "counts": counts, "seconds": 0.0, "stats": stats, "classes": {}}

    F = _Field(program["m"], program["modulus"])
    R, q = program["challenge"], 1 << program["m"]
    sha = hashlib.sha256(json.dumps(program, sort_keys=True,
                                    separators=(",", ":")).encode()).hexdigest()
    if document.get("program_sha256") != sha:
        errors.append("program hash mismatch")

    val, old, opa, opb, final = _forward(F, program)
    linear = _linear_sites(program)
    adj = _backward(F, program, opa, opb)
    ref_outs = [final.get(o, {}) for o in program["outputs"]]
    ref_disc = final.get(program["disc"], {})
    ref_inc = [final.get(w, {}) for w in program["inconsistency"]]
    homogeneous = (not ref_disc) and all(not w for w in ref_inc)

    faults = document.get("faults", [])
    expected = set(_fault_space(program, kinds))
    seen = [c.get("site_id") for c in faults]
    for sid in sorted(expected - set(seen)):
        errors.append(f"manifest: no certificate for in-scope fault {sid}")
    for sid in sorted(set(seen) - expected):
        errors.append(f"manifest: certificate for out-of-scope fault {sid}")
    once: set = set()
    twice: set = set()
    for s in seen:
        (twice if s in once else once).add(s)
    for sid in sorted(twice, key=str):
        errors.append(f"manifest: duplicate certificate for {sid}")

    templates = document.get("templates", {})
    checked: dict[str, dict] = {}          # tid -> validated template info

    def template(tid: str) -> dict:
        """Parse and validate a template once."""
        if tid in checked:
            info = checked[tid]
            if "error" in info:
                raise _Reject(info["error"])
            return info
        try:
            T = templates[tid]
            jd = _p_parse(F, T["jd"])
            jo = [_p_parse(F, p) for p in T["jo"]]
            info = {"jd": jd, "jo": jo, "kind": T["kind"]}
            if T["kind"] == "template":
                _need(all(R not in _p_vars(p) for p in jo),
                      "template output adjoint depends on the challenge")
                inner: dict = {}
                # identical obligations to a covered certificate with
                # discrepancy Jd and wrongness Jo
                _check_covered(F, R, q, {"witness": T["witness"], "quotient": T["quotient"],
                                         "degree_bound": T["degree_bound"]}, jd, jo, inner)
                info.update(bound=T["degree_bound"], h=inner["h"], k=inner["k"],
                            zero_root=inner["zero_root"])
            stats["templates_checked"] += 1
        except _Reject as e:
            info = {"error": f"template {tid}: {e}"}
        except (KeyError, TypeError, ValueError, IndexError) as e:
            info = {"error": f"template {tid}: malformed ({type(e).__name__}: {e})"}
        checked[tid] = info
        if "error" in info:
            raise _Reject(info["error"])
        return info

    def delta_of(fault) -> dict:
        i = fault["site"]
        if fault["kind"] == "bitflip":
            return {(): 1 << fault["bit"]}
        if fault["kind"] == "zero":
            return val[i]
        return _p_add(val[i], old[i])

    def mul(a, b):
        stats["per_fault_poly_mul"] += 1
        return _p_mul(F, a, b)

    for cert in faults:
        sid = cert.get("site_id")
        try:
            fault = cert.get("fault")
            _need(fault is not None and _site_id(fault) == sid, "site_id/fault mismatch")
            _need(fault["kind"] in kinds, "fault kind out of scope")
            _need(0 <= fault["site"] < len(program["instrs"]), "site out of range")
            if fault["kind"] == "bitflip":
                _need(isinstance(fault["bit"], int) and 0 <= fault["bit"] < program["m"],
                      "bit out of range")
            i = fault["site"]
            cls, mode = cert.get("classification"), cert.get("mode")
            _need(cls in counts, f"invalid classification {cls!r}")
            delta = delta_of(fault)
            jd_i, jo_i = adj[i]
            key = f"{cls}|{sid}"                 # singleton unless proved otherwise

            if mode == "delta-zero":
                _need(cls == "benign", "delta-zero mode only certifies benign")
                _need(not delta, "injected error is not identically zero")
                key = "benign"

            elif mode in ("no-reach", "template"):
                _need(linear[i], "site is not fault-linear: adjoint synthesis invalid")
                T = template(cert["template"])
                _need(T["jd"] == jd_i and T["jo"] == jo_i,
                      "site adjoints do not match the claimed template")
                if mode == "no-reach":
                    _need(all(not p for p in jo_i), "site reaches an output")
                    _need(all(not w for w in ref_inc), "input-inconsistency registers active")
                    wrong_possible = False
                else:
                    _need(T["kind"] == "template", "template has no validated witness")
                    _need(homogeneous, "program is not homogeneous (g_ref or inc nonzero)")
                    _need(R not in _p_vars(delta), "injected error depends on the challenge")
                    wrong_possible = cert.get("wrong_output_possible") is not False
                    if not wrong_possible or cls == "benign":
                        _need(all(not mul(delta, p) for p in jo_i if p),
                              "an output is corrupted on some state")
                        wrong_possible = False
                if cls == "benign":
                    _need(not wrong_possible, "benign fault can corrupt an output")
                    _need((not jd_i) or not mul(delta, jd_i),
                          "discrepancy changes on some state")
                    key = "benign"
                elif cls == "covered":
                    if wrong_possible:
                        _need(cert.get("wrong_output_possible") is True,
                              "wrong_output_possible must be true")
                        _need(cert.get("degree_bound") == T["bound"],
                              "bound differs from the template's")
                        key = f"covered|k={T['k']}|{T['h']}"
                        stats["template_faults"] += 1
                    else:
                        _need(cert.get("wrong_output_possible") is False
                              and cert.get("degree_bound") == 0,
                              "no-wrong-output fault must have bound 0")
                        key = "covered|wrong-impossible"
                else:
                    raise _Reject(f"mode {mode} cannot certify {cls}")

            elif mode == "unobserved":
                _need(linear[i], "site is not fault-linear: adjoint synthesis invalid")
                _need(not ref_disc, "fault-free discrepancy is not identically zero")
                _need(not jd_i, "the checker observes this site")
                _need(R not in _p_vars(delta), "injected error depends on the challenge")
                if cls == "benign":
                    _need(all(not mul(delta, p) for p in jo_i if p),
                          "an output is corrupted on some state")
                    key = "benign"
                elif cls == "bypass":
                    pt = cert["witness"]["point"]
                    j = cert["witness"]["output_index"]
                    _need(set(pt) == set(program["inputs"]),
                          "bypass point must assign every input")
                    _need(all(isinstance(v, int) and 0 <= v < q for v in pt.values()),
                          "bad point")
                    _need(isinstance(j, int) and 0 <= j < len(jo_i), "bad output index")
                    _need(R not in _p_vars(jo_i[j]), "output adjoint depends on the challenge")
                    _need(F.mul(_p_eval(F, delta, pt), _p_eval(F, jo_i[j], pt)) != 0,
                          "output is not corrupted at the claimed state")
                else:
                    raise _Reject(f"mode unobserved cannot certify {cls}")

            elif mode == "synth":
                if linear[i]:
                    outs = [_p_add(a, mul(delta, p)) if p else a
                            for a, p in zip(ref_outs, jo_i)]
                    g = _p_add(ref_disc, mul(delta, jd_i)) if jd_i else ref_disc
                else:
                    stats["per_fault_executions"] += 1
                    st = _load(F, program, fault, True)
                    outs = [st.get(o, {}) for o in program["outputs"]]
                    g = st.get(program["disc"], {})
                W = [_p_add(a, b) for a, b in zip(outs, ref_outs)] + ref_inc
                if cls == "benign":
                    _need(outs == ref_outs and g == ref_disc,
                          "observation differs from fault-free")
                    key = "benign"
                elif cls == "covered":
                    _need(_p_parse(F, cert["discrepancy_polynomial"]) == g,
                          "claimed discrepancy polynomial is not the faulted one")
                    bound = cert.get("degree_bound")
                    _need(isinstance(bound, int) and bound >= 0, "missing degree bound")
                    if cert.get("wrong_output_possible") is False:
                        _need(all(not w for w in W), "wrongness is not identically zero")
                        _need(bound == 0, "bound must be 0 when no wrong output exists")
                        key = "covered|wrong-impossible"
                    else:
                        inner = {}
                        _check_covered(F, R, q, cert, g, W, inner)
                        key = f"covered|k={inner['k']}|{inner['h']}"
                elif cls == "bypass":
                    _check_bypass(F, program, fault, cert, q)
                # unknown: nothing claimed
            else:
                raise _Reject(f"unknown mode {mode!r}")
            results[sid] = "pass"
            class_of[sid] = key
            counts[cls] += 1
        except _Reject as e:
            results[sid] = f"fail: {e}"
        except (KeyError, TypeError, ValueError, IndexError) as e:
            results[sid] = f"fail: malformed certificate ({type(e).__name__}: {e})"

    classes: dict[str, list[str]] = {}
    for sid, key in class_of.items():
        classes.setdefault(key, []).append(sid)
    ok = not errors and all(v == "pass" for v in results.values())
    return {"ok": ok, "results": results, "errors": errors, "counts": counts,
            "in_scope_faults": len(expected), "classes": classes, "stats": stats,
            "seconds": time.perf_counter() - t0}

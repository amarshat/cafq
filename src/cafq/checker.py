"""CAFQ certificate checker -- the TRUSTED part.

Standard library only; imports nothing from the analyzer, the IR module or
the analyzer's polynomial code (enforced by tests/test_certificate_checker.py).
It re-derives the faulted program's polynomials with its own arithmetic and
then checks every claim in every certificate. It never searches: witnesses,
factorisations and bypass states are supplied by the untrusted analyzer.

What a PASS means, per classification (q = field size, W = wrongness vector,
g = faulted discrepancy, both as functions of state x and challenge r):

  benign   faulted outputs and discrepancy equal the fault-free ones as
           functions (so the modelled observation is unchanged everywhere).
  covered  for EVERY state x with W(x) != 0, the number of challenges r
           with g(x; r) == 0 is at most ``degree_bound`` (exactly
           ``degree_bound`` when ``exact_roots`` is given). Hence for r
           uniform and independent of (x, fault):
               Pr[undetected wrong result] <= degree_bound / q.
  bypass   the supplied state x has W(x) != 0 and g(x; r) == 0 for ALL r.
  unknown  nothing is claimed; counted and reported.

It also checks the manifest (one certificate per in-scope fault, none
missing, none extra) and that every quotient class is sound at its level.
"""
from __future__ import annotations

import hashlib
import json
import time

KINDS = ("skip", "zero", "bitflip")


# ---------------------------------------------------------------- field ----
class _Field:
    def __init__(self, m: int, modulus: int):
        self.m, self.q, self.modulus = m, 1 << m, modulus
        if modulus >> m != 1:
            raise ValueError("modulus degree mismatch")
        self._t = {}

    def mul(self, a: int, b: int) -> int:
        key = (a, b)
        v = self._t.get(key)
        if v is None:
            v = 0
            x = a
            for i in range(self.m):
                if (b >> i) & 1:
                    v ^= x
                x <<= 1
                if x >> self.m:
                    x ^= self.modulus
            self._t[key] = v
        return v

    def pow(self, a: int, n: int) -> int:
        r = 1
        for _ in range(n):
            r = self.mul(r, a)
        return r


# ----------------------------------------------- reduced polynomials -------
# dict: monomial (sorted tuple of (var, exp), 1 <= exp < q) -> nonzero coeff.
# Always kept reduced modulo x^q = x, so equality of dicts is equality of
# functions on GF(q)^n.

def _p_add(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        nv = out.get(k, 0) ^ v
        if nv:
            out[k] = nv
        else:
            out.pop(k, None)
    return out


def _p_mul(F: _Field, a: dict, b: dict) -> dict:
    out: dict = {}
    q = F.q
    for k1, v1 in a.items():
        for k2, v2 in b.items():
            d = dict(k1)
            for var, e in k2:
                e = d.get(var, 0) + e
                d[var] = e if e < q else (e - 1) % (q - 1) + 1
            k = tuple(sorted(d.items()))
            nv = out.get(k, 0) ^ F.mul(v1, v2)
            if nv:
                out[k] = nv
            else:
                out.pop(k, None)
    return out


def _p_parse(F: _Field, data) -> dict:
    out: dict = {}
    for coeff, mono in data:
        if not (isinstance(coeff, int) and 0 < coeff < F.q):
            raise ValueError("bad coefficient")
        term = {(): coeff}
        for var, e in mono:
            if not (isinstance(e, int) and e >= 1):
                raise ValueError("bad exponent")
            for _ in range(e):
                term = _p_mul(F, term, {((var, 1),): 1})
        out = _p_add(out, term)
    return out


def _p_coeffs(p: dict, var: str) -> dict:
    out: dict = {}
    for k, v in p.items():
        d = dict(k)
        e = d.pop(var, 0)
        out.setdefault(e, {})[tuple(sorted(d.items()))] = v
    return out


def _p_vars(p: dict) -> set:
    return {v for k in p for v, _ in k}


def _p_scale(F: _Field, p: dict, c: int) -> dict:
    return {k: F.mul(v, c) for k, v in p.items()} if c else {}


def _p_canon(p: dict) -> str:
    return json.dumps(sorted([list(map(list, k)), v] for k, v in p.items()))


# ------------------------------------------------------- interpreters ------
def _load(F: _Field, prog: dict, fault, sym: bool, env=None) -> dict:
    """One interpreter, two algebras: reduced polynomials or field elements."""
    if sym:
        reg = {v: {((v, 1),): 1} for v in prog["inputs"] + [prog["challenge"]]}
        zero, const = {}, (lambda c: {(): c} if c else {})
        add, mul = _p_add, (lambda a, b: _p_mul(F, a, b))
    else:
        reg = dict(env)
        zero, const = 0, (lambda c: c)
        add, mul = (lambda a, b: a ^ b), F.mul
    for i, (op, dst, a, b, _region) in enumerate(prog["instrs"]):
        hit = fault is not None and fault["site"] == i
        if hit and fault["kind"] == "skip":
            continue
        if op == "const":
            if not (isinstance(a, int) and 0 <= a < F.q):
                raise ValueError("bad immediate")
            v = const(a)
        elif op == "mov":
            v = reg.get(a, zero)
        elif op == "add":
            v = add(reg.get(a, zero), reg.get(b, zero))
        elif op == "mul":
            v = mul(reg.get(a, zero), reg.get(b, zero))
        else:
            raise ValueError(f"unknown op {op}")
        if hit and fault["kind"] == "zero":
            v = zero
        if hit and fault["kind"] == "bitflip":
            v = add(v, const(1 << fault["bit"]))
        reg[dst] = v
    return reg


def _fault_space(prog: dict, kinds) -> list[str]:
    ids = []
    for site in range(len(prog["instrs"])):
        for k in kinds:
            if k == "bitflip":
                ids += [f"{k}@{site}.b{b}" for b in range(prog["m"])]
            else:
                ids.append(f"{k}@{site}")
    return ids


def _site_id(fault) -> str:
    s = f"{fault['kind']}@{fault['site']}"
    return s if fault.get("bit") is None else f"{s}.b{fault['bit']}"


class _Reject(Exception):
    pass


def _need(cond: bool, msg: str):
    if not cond:
        raise _Reject(msg)


# ------------------------------------------------------------ checking -----
def check(program: dict, certificates: list[dict], kinds=KINDS) -> dict:
    t0 = time.perf_counter()
    F = _Field(program["m"], program["modulus"])
    R, q = program["challenge"], 1 << program["m"]
    sha = hashlib.sha256(json.dumps(program, sort_keys=True,
                                    separators=(",", ":")).encode()).hexdigest()
    ref = _load(F, program, None, True)
    ref_outs = [ref.get(o, {}) for o in program["outputs"]]
    ref_disc = ref.get(program["disc"], {})
    ref_inc = [ref.get(w, {}) for w in program["inconsistency"]]

    results: dict[str, str] = {}
    derived: dict[str, dict] = {}
    errors: list[str] = []

    expected = set(_fault_space(program, kinds)) | {"fault-free"}
    seen: list[str] = [c.get("site_id") for c in certificates]
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

    for cert in certificates:
        sid = cert.get("site_id")
        try:
            _need(cert.get("program_sha256") == sha, "program hash mismatch")
            fault = cert.get("fault")
            if sid == "fault-free":
                _need(fault is None, "fault-free certificate carries a fault")
            else:
                _need(fault is not None and _site_id(fault) == sid, "site_id/fault mismatch")
                _need(fault["kind"] in kinds, "fault kind out of scope")
                _need(0 <= fault["site"] < len(program["instrs"]), "site out of range")
                if fault["kind"] == "bitflip":
                    _need(0 <= fault["bit"] < program["m"], "bit out of range")
            st = _load(F, program, fault, True)
            outs = [st.get(o, {}) for o in program["outputs"]]
            g = st.get(program["disc"], {})
            W = [_p_add(a, b) for a, b in zip(outs, ref_outs)] + ref_inc
            info = {"outs": outs, "g": g, "W": W, "cls": cert.get("classification")}
            derived[sid] = info
            cls = cert.get("classification")

            if cls == "benign":
                _need(fault is not None, "fault-free cannot be 'benign'")
                _need(outs == ref_outs and g == ref_disc,
                      "observation differs from fault-free")
            elif cls == "covered":
                _need(_p_parse(F, cert["discrepancy_polynomial"]) == g,
                      "claimed discrepancy polynomial is not the faulted one")
                bound = cert.get("degree_bound")
                _need(isinstance(bound, int) and bound >= 0, "missing degree bound")
                if cert.get("wrong_output_possible") is False:
                    _need(all(not w for w in W), "wrongness is not identically zero")
                    _need(bound == 0, "bound must be 0 when no wrong output exists")
                    info["wrong"] = False
                else:
                    info["wrong"] = True
                    _check_covered(F, R, q, cert, g, W, info)
            elif cls == "bypass":
                _check_bypass(F, program, fault, cert, q)
            elif cls == "unknown":
                pass
            else:
                raise _Reject(f"invalid classification {cls!r}")
            results[sid] = "pass"
        except _Reject as e:
            results[sid] = f"fail: {e}"
        except (KeyError, TypeError, ValueError, IndexError) as e:
            results[sid] = f"fail: malformed certificate ({type(e).__name__}: {e})"

    errors += _check_classes(F, certificates, derived, results)

    counts = {"benign": 0, "covered": 0, "bypass": 0, "unknown": 0}
    for cert in certificates:
        if cert.get("site_id") != "fault-free" and cert.get("classification") in counts:
            counts[cert["classification"]] += 1
    ok = not errors and all(v == "pass" for v in results.values())
    return {"ok": ok, "results": results, "errors": errors, "counts": counts,
            "in_scope_faults": len(expected) - 1,
            "seconds": time.perf_counter() - t0}


def _check_covered(F, R, q, cert, g, W, info):
    coeffs = _p_coeffs(g, R)
    wit = cert["witness"]
    degs = wit["degrees"]
    _need(len(set(degs)) == len(degs), "repeated witness degree")
    basis = [coeffs.get(d, {}) for d in degs]
    if wit["type"] == "linear":
        _need(len(wit["matrix"]) == len(W), "witness matrix has wrong shape")
        for row, w in zip(wit["matrix"], W):
            _need(len(row) == len(basis), "witness row has wrong length")
            acc: dict = {}
            for lam, b in zip(row, basis):
                _need(isinstance(lam, int) and 0 <= lam < q, "bad witness scalar")
                acc = _p_add(acc, _p_scale(F, b, lam))
            _need(acc == w, "linear witness does not reproduce the wrongness vector")
    elif wit["type"] == "unit":
        acc = {}
        for lam, b in zip(wit["lambda"], basis):
            _need(isinstance(lam, int) and 0 <= lam < q, "bad witness scalar")
            acc = _p_add(acc, _p_scale(F, b, lam))
        _need(acc == {(): 1}, "unit witness does not sum to 1")
    else:
        raise _Reject(f"unknown witness type {wit['type']!r}")

    quo = cert["quotient"]
    k = quo["shift_k"]
    _need(isinstance(k, int) and k >= 0, "bad shift")
    u, h = _p_parse(F, quo["u"]), _p_parse(F, quo["h"])
    _need(R not in _p_vars(u), "unit factor u depends on the challenge")
    prod = _p_mul(F, u, h)
    for _ in range(k):
        prod = _p_mul(F, prod, {((R, 1),): 1})
    _need(prod == g, "g != u * R^k * h")
    hc = _p_coeffs(h, R)
    deg_h = max(hc) if hc else 0
    zero_root = 1 if k > 0 else 0
    bound = cert["degree_bound"]
    if quo.get("exact_roots") is not None:
        _need(all(set(c) <= {()} for c in hc.values()),
              "exact roots claimed but h has state-dependent coefficients")
        roots = set()
        for r in range(q):
            acc = 0
            for d, c in hc.items():
                acc ^= F.mul(c[()], F.pow(r, d))
            if acc == 0:
                roots.add(r)
        if zero_root:
            roots.add(0)
        _need(sorted(roots) == quo["exact_roots"], "exact root set is wrong")
        _need(bound == len(roots), "bound does not equal the exact root count")
    else:
        _need(bound >= deg_h + zero_root, "degree bound too small")
    info["h"], info["zero_root"], info["k"] = _p_canon(h), bool(zero_root), k


def _check_bypass(F, program, fault, cert, q):
    pt = cert["witness"]["point"]
    _need(set(pt) == set(program["inputs"]), "bypass point must assign every input")
    _need(all(isinstance(v, int) and 0 <= v < q for v in pt.values()), "bad point")
    for r in range(q):
        env = {**pt, program["challenge"]: r}
        good = _load(F, program, None, False, env)
        bad = _load(F, program, fault, False, env)
        wrong = any(good.get(o, 0) != bad.get(o, 0) for o in program["outputs"]) or \
            any(good.get(w, 0) != 0 for w in program["inconsistency"])
        _need(wrong, f"state is not wrong at challenge {r}")
        _need(bad.get(program["disc"], 0) == 0, f"detected at challenge {r}")


def _proportional(F, a: dict, b: dict) -> bool:
    if set(a) != set(b) or not a:
        return a == b
    k0 = next(iter(a))
    # c with c * a[k0] == b[k0]
    c = next(x for x in range(1, F.q) if F.mul(x, a[k0]) == b[k0])
    return all(F.mul(c, a[k]) == b[k] for k in a)


def _check_classes(F, certificates, derived, results) -> list[str]:
    """A class at level L is sound iff any two members satisfy that level's
    relation. Checked against the checker's own derived polynomials."""
    errors = []
    groups: dict[tuple, list[str]] = {}
    for cert in certificates:
        sid = cert.get("site_id")
        if sid == "fault-free" or results.get(sid) != "pass":
            continue
        keys = cert.get("class_keys")
        if not isinstance(keys, dict) or set(keys) != {"L1", "L2", "L3", "L4"}:
            errors.append(f"classes: {sid} has no class keys")
            continue
        for lvl, key in keys.items():
            groups.setdefault((lvl, key), []).append(sid)
    for (lvl, key), members in groups.items():
        a = derived[members[0]]
        for sid in members[1:]:
            b = derived[sid]
            same_obs = a["outs"] == b["outs"] and a["g"] == b["g"]
            if a["cls"] != b["cls"]:
                ok = False
            elif a["cls"] != "covered":
                ok = same_obs                      # only exact merging allowed
            elif not a["wrong"] or not b["wrong"]:
                # L1 is exact-effect; above it, 'no wrong output possible'
                # is itself the (trivially shared) guarantee.
                ok = same_obs if lvl == "L1" else (not a["wrong"] and not b["wrong"])
            elif lvl == "L1":
                ok = same_obs
            elif lvl == "L2":
                ok = _proportional(F, a["g"], b["g"])
            elif lvl == "L3":
                ok = a["h"] == b["h"] and a["k"] == b["k"]
            else:
                ok = a["h"] == b["h"] and a["zero_root"] == b["zero_root"]
            if not ok:
                errors.append(f"classes: unsound {lvl} merge of {members[0]} and {sid}")
    return errors

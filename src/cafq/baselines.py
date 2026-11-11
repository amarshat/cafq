"""A stronger per-fault baseline, so the structural method is not compared
against a weakened comparator.

``analyze`` (cafq.analyzer) re-executes the WHOLE program for every fault.
``analyze_prefix_cached`` executes the fault-free program once, snapshots the
register map before every instruction, and re-executes only the suffix from
the fault site. It produces exactly the same certificates.
"""
from __future__ import annotations

import random
import time

from .analyzer import Analysis, Reference, classify_observation
from .field import get_field
from .ir import FAULT_KINDS, Program
from .poly import Poly


def analyze_prefix_cached(prog: Program, kinds=FAULT_KINDS, seed: int = 0) -> Analysis:
    t0 = time.perf_counter()
    rng = random.Random(seed)
    F = get_field(prog.m, prog.modulus)
    zero = Poly(F)

    def step(reg, i, fault):
        ins = prog.instrs[i]
        hit = fault is not None and fault.site == i
        if hit and fault.kind == "skip":
            return
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

    reg = {v: Poly.var(F, v) for v in prog.inputs + [prog.challenge]}
    snaps = []
    for i in range(len(prog.instrs)):
        snaps.append(dict(reg))
        step(reg, i, None)
    ref = Reference([reg.get(o, zero).reduce() for o in prog.outputs],
                    reg.get(prog.disc, zero).reduce(),
                    [reg.get(w, zero).reduce() for w in prog.inconsistency])
    certs = [classify_observation(prog, ref, None, ref.outs, ref.disc, rng)]
    executed = len(prog.instrs)
    for fault in prog.fault_space(kinds):
        r = dict(snaps[fault.site])
        for i in range(fault.site, len(prog.instrs)):
            step(r, i, fault)
        executed += len(prog.instrs) - fault.site
        outs = [r.get(o, zero).reduce() for o in prog.outputs]
        g = r.get(prog.disc, zero).reduce()
        certs.append(classify_observation(prog, ref, fault, outs, g, rng))
    a = Analysis(prog, certs, time.perf_counter() - t0)
    a.classes["symbolic_instr"] = executed
    return a

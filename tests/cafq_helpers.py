"""Shared test helpers: adversarial circuits and brute-force ground truth.

Ground truth uses only cafq.ir.run (concrete execution). It shares no code
with the analyzer's symbolic engine or with the checker."""
import itertools

from cafq.field import MODULI
from cafq.ir import Fault, Instr, Program, run


def masked_check(m=2, nonlinear=False):
    """A deliberately WEAK checker: the discrepancy is multiplied by a
    state-dependent mask, so it vanishes on part of the state space.
      y0 = x0*x1 ; disc = (y0 + x0*x1) * mask
      mask = x2            (linear variant: zero when x2 == 0)
      mask = (x2*x3 + 1) + R*(x4*x5 + 1)
                           (nonlinear variant: identically zero in R only
                            when x2*x3 == 1 and x4*x5 == 1, a 1/q^2 fraction
                            of states that random search will not hit)"""
    ins = [Instr("mul", "y0", "x0", "x1", "data"),
           Instr("mul", "chk", "x0", "x1", "check"),
           Instr("add", "chk", "chk", "y0", "check")]
    if nonlinear:
        ins += [Instr("const", "one", 1, None, "check"),
                Instr("mul", "mask", "x2", "x3", "check"),
                Instr("add", "mask", "mask", "one", "check"),
                Instr("mul", "m2", "x4", "x5", "check"),
                Instr("add", "m2", "m2", "one", "check"),
                Instr("mul", "m2", "m2", "R", "check"),
                Instr("add", "mask", "mask", "m2", "check")]
    else:
        ins += [Instr("mov", "mask", "x2", None, "check")]
    ins += [Instr("mul", "disc", "chk", "mask", "check")]
    return Program(f"masked_check_{'nl' if nonlinear else 'lin'}", m, MODULI[m],
                   ["x0", "x1", "x2", "x3"] + (["x4", "x5"] if nonlinear else []),
                   "R", ins, ["y0"], "disc")


def unchecked_output(m=2):
    """Two outputs, only one of them covered by the fingerprint."""
    ins = [Instr("mul", "y0", "x0", "x1", "data"),
           Instr("add", "y1", "x0", "x1", "data"),
           Instr("mul", "chk", "x0", "x1", "check"),
           Instr("add", "chk", "chk", "y0", "check"),
           Instr("mul", "disc", "chk", "R", "check")]
    return Program("unchecked_output", m, MODULI[m], ["x0", "x1"], "R", ins,
                   ["y0", "y1"], "disc")


def fault_of(cert):
    f = cert["fault"]
    return None if f is None else Fault(f["kind"], f["site"], f["bit"])


def ground_truth(prog: Program, fault, states=None):
    """For every state x (all of them unless ``states`` is given) return
    (x, wrong_for_all_r, wrong_for_some_r, undetected_set, same_observation)."""
    q = 1 << prog.m
    if states is None:
        states = itertools.product(range(q), repeat=len(prog.inputs))
    for xs in states:
        env = dict(zip(prog.inputs, xs))
        und, wrongs, same = set(), [], True
        for r in range(q):
            env[prog.challenge] = r
            good = run(prog, env)
            bad = run(prog, env, fault)
            wrong = any(good.get(o, 0) != bad.get(o, 0) for o in prog.outputs) or \
                any(good.get(w, 0) for w in prog.inconsistency)
            wrongs.append(wrong)
            if bad.get(prog.disc, 0) == 0:
                und.add(r)
            if any(good.get(o, 0) != bad.get(o, 0) for o in prog.outputs) or \
                    good.get(prog.disc, 0) != bad.get(prog.disc, 0):
                same = False
        yield dict(zip(prog.inputs, xs)), all(wrongs), any(wrongs), und, same

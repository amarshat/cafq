"""Compiler-aware fault quotient on a compiled kernel (x86-64, emulated).

UNTRUSTED research prototype. It needs unicorn and capstone and is therefore
kept out of the core package imports.

Question: can the IR-level site certificates be TRANSPORTED to machine-level
instruction skips without emulating every skip?

Method (Region Theorem, STRUCTURAL_QUOTIENT_THEORY.md section 12):

  1. Trace the fault-free binary once per training input, recording for each
     dynamic instruction the locations it reads and writes (registers via
     capstone, memory bytes via emulator hooks) and the values written.
  2. Build the dynamic def-use graph over definition nodes (instruction,
     location), with a sink for the observed output bytes.
  3. Find REALISATION POINTS: definition nodes whose low byte equals an IR
     value on every training input, and VALIDATE each by injection: perturb
     that location by several errors delta and check, for every challenge,
     that the final observation is exactly  out + delta*Jo_i ,  delta*Jd_i
     for one IR site i (and that the upper bits of the location are dead).
  4. A skip of dynamic instruction k is assigned to IR site i iff
       (a) no perturbed value reaches an address or control use,
       (b) one validated realisation point E of site i post-dominates every
           live definition of k in the def-use graph,
       (c) E and the stale contents k leaves behind do not depend on the
           challenge.
     Then the skip is SOME challenge-independent error on IR value i, so the
     delta-agnostic site certificate applies: no wrong output, or wrong
     output with exactly the site's undetected-challenge set.
     Skips whose definitions cannot reach an output byte are predicted to
     never corrupt the output. Everything else is OUTSIDE COVERAGE.

Assumptions that are tested, not proved: the def-use graph over-approximates
the real data flow (depends on capstone's operand model); the suffix after a
realisation point realises the IR suffix for ALL values of that location
(tested for the injected errors only, on one state).
"""
from __future__ import annotations

import struct
import time
from collections import Counter
from dataclasses import dataclass, field

from capstone import CS_AC_WRITE, CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from unicorn import (UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MODE_64,
                     UC_PROT_EXEC, UC_PROT_READ, Uc, UcError)
from unicorn import x86_const as UX

from . import structural
from .field import get_field
from .ir import Program

STACK, STACK_SZ, IN, OUTB, SENT = 0x7000000, 0x10000, 0x8000000, 0x8001000, 0x9000000
CONTROL = {"ret", "call", "jmp", "leave", "push", "pop"}
# instructions whose register destination (>= 32 bit) is completely replaced
FULL_MOVES = {"mov", "movzx", "movsx", "movsxd", "movabs", "lea", "movd", "movq",
              "movdqa", "movdqu", "movaps", "movups"}
# instructions that define every status flag a later reader could consume
FLAG_KILLERS = {"add", "sub", "xor", "and", "or", "cmp", "test", "neg"}


# ------------------------------------------------------------ registers ----
def _canon_table() -> dict[str, str]:
    t = {}
    for b in "abcd":
        for n in (f"{b}l", f"{b}h", f"{b}x", f"e{b}x", f"r{b}x"):
            t[n] = f"r{b}x"
    for b in ("si", "di", "bp", "sp"):
        for n in (f"{b}l", b, f"e{b}", f"r{b}"):
            t[n] = f"r{b}"
    for i in range(8, 16):
        for suf in ("b", "w", "d", ""):
            t[f"r{i}{suf}"] = f"r{i}"
    for i in range(32):
        t[f"xmm{i}"] = t[f"ymm{i}"] = f"xmm{i}"
    t["eflags"] = t["rflags"] = "flags"
    t["rip"] = t["eip"] = "rip"
    return t


CANON = _canon_table()


def _uc_reg(name: str):
    if name == "flags":
        return UX.UC_X86_REG_EFLAGS
    return getattr(UX, "UC_X86_REG_" + name.upper())


@dataclass
class Decoded:
    mnemonic: str
    text: str
    reads: frozenset        # canonical registers read as data
    addr_reads: frozenset   # canonical registers used to form a memory address
    writes: frozenset       # canonical registers written
    control: bool
    steer: frozenset = frozenset()   # registers whose value steers control flow


class Decoder:
    def __init__(self):
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self.cache: dict[int, Decoded] = {}

    def decode(self, mu, pc: int, size: int) -> Decoded:
        d = self.cache.get(pc)
        if d is not None:
            return d
        ins = next(self.md.disasm(bytes(mu.mem_read(pc, size)), pc))
        rr, rw = ins.regs_access()
        reads = {CANON.get(ins.reg_name(r)) for r in rr}
        writes = {CANON.get(ins.reg_name(r)) for r in rw}
        addr = set()
        if ins.mnemonic.startswith("nop") or ins.mnemonic in ("endbr64",):
            # multi-byte NOPs carry a memory operand that is never accessed
            d = Decoded(ins.mnemonic, f"{ins.mnemonic} {ins.op_str}".strip(),
                        frozenset(), frozenset(), frozenset(), False, frozenset())
            self.cache[pc] = d
            return d
        is_lea = ins.mnemonic == "lea"
        for op in ins.operands:
            if op.type == X86_OP_MEM and not is_lea:
                for r in (op.mem.base, op.mem.index):
                    if r:
                        addr.add(CANON.get(ins.reg_name(r)))
            if op.type == X86_OP_REG and (op.access & CS_AC_WRITE) and op.size < 4:
                # 8/16-bit writes keep the rest of the register: a read too
                reads.add(CANON.get(ins.reg_name(op.reg)))
        # KILL MODEL. capstone's write set does not say whether a write
        # replaces the old content. Conditional moves, partial-flag updates
        # (inc/dec), variable-count shifts and anything not listed below may
        # leave (part of) the old content in place; such a write is treated
        # as a read of the old content as well. Only whitelisted full
        # overwrites kill the previous definition.
        full_reg_writes = set()
        if ins.mnemonic in FULL_MOVES or ins.mnemonic == "pop":
            for op in ins.operands:
                if op.type == X86_OP_REG and (op.access & CS_AC_WRITE) and op.size >= 4:
                    full_reg_writes.add(CANON.get(ins.reg_name(op.reg)))
        for w in list(writes):
            if w in ("flags", "rip", None):
                continue
            if w not in full_reg_writes:
                reads.add(w)
        if "flags" in writes:
            imm_shift = ins.mnemonic in ("shl", "sal", "shr", "sar") and \
                any(op.type == X86_OP_IMM and op.imm != 0 for op in ins.operands)
            if not (ins.mnemonic in FLAG_KILLERS or imm_shift):
                reads.add("flags")
        reads.discard(None)
        writes.discard(None)
        addr.discard(None)
        addr.discard("rip")
        reads.discard("rip")
        control = ins.mnemonic in CONTROL or ins.mnemonic.startswith("j") \
            or "rip" in writes or "rsp" in writes
        writes.discard("rip")
        steer = set()
        if control:
            # which register reads steer execution: the stack pointer and flags
            # (and any register of an indirect jump/call); the value a push
            # saves or a pop restores is plain data
            steer = set(reads) | set(addr)
            if ins.mnemonic in ("push", "pop"):
                steer = {"rsp"}
        d = Decoded(ins.mnemonic, f"{ins.mnemonic} {ins.op_str}".strip(),
                    frozenset(reads - addr), frozenset(addr), frozenset(writes), control,
                    frozenset(steer))
        self.cache[pc] = d
        return d


# ------------------------------------------------------------- machine -----
def load_segments(elf_bytes: bytes):
    phoff, = struct.unpack_from("<Q", elf_bytes, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", elf_bytes, 0x36)
    segs = []
    for i in range(phnum):
        p_type, p_flags, p_offset, p_vaddr, _pa, p_filesz, p_memsz, _al = \
            struct.unpack_from("<IIQQQQQQ", elf_bytes, phoff + i * phentsize)
        if p_type == 1 and p_memsz:
            segs.append((p_vaddr, elf_bytes[p_offset:p_offset + p_filesz], p_memsz, p_flags))
    return segs


class Emu:
    WIN = 0x800

    def __init__(self, elf_bytes: bytes, entry: int):
        self.segs = load_segments(elf_bytes)
        self.entry = entry
        self.sp = STACK + STACK_SZ - 0x1000

    def fresh(self, state, r):
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        for vaddr, data, memsz, _f in self.segs:
            base = vaddr & ~0xFFF
            size = ((vaddr + memsz + 0xFFF) & ~0xFFF) - base
            try:
                mu.mem_map(base, size)
            except UcError:
                pass
            mu.mem_write(vaddr, data)
        for vaddr, data, memsz, flags in self.segs:
            if not flags & 2:
                base = vaddr & ~0xFFF
                size = ((vaddr + memsz + 0xFFF) & ~0xFFF) - base
                mu.mem_protect(base, size, UC_PROT_READ | UC_PROT_EXEC)
        mu.mem_map(STACK, STACK_SZ)
        mu.mem_map(IN, 0x2000)
        mu.mem_map(SENT, 0x1000)
        mu.mem_write(IN, bytes(state) + bytes([r]))
        mu.mem_write(OUTB, bytes(4))
        mu.mem_write(self.sp, struct.pack("<Q", SENT))
        mu.reg_write(UX.UC_X86_REG_RSP, self.sp)
        mu.reg_write(UX.UC_X86_REG_RDI, IN)
        mu.reg_write(UX.UC_X86_REG_RSI, OUTB)
        return mu

    def save(self, mu):
        return (mu.context_save(), bytes(mu.mem_read(self.sp - self.WIN, self.WIN + 0x100)),
                bytes(mu.mem_read(IN, 8)), bytes(mu.mem_read(OUTB, 4)))

    def restore(self, mu, snap):
        ctx, stack, inb, outb = snap
        mu.context_restore(ctx)
        mu.mem_write(self.sp - self.WIN, stack)
        mu.mem_write(IN, inb)
        mu.mem_write(OUTB, outb)


@dataclass
class Trace:
    pcs: list                # (pc, size)
    dec: list                # Decoded per dynamic instruction
    mem_r: list              # set of byte addresses read
    mem_w: list              # set of byte addresses written
    values: list             # {location: low byte written} per dynamic instruction
    out: bytes


def trace(emu: Emu, dec: Decoder, state, r) -> Trace:
    mu = emu.fresh(state, r)
    pcs, decs, mem_r, mem_w, values = [], [], [], [], []

    def flush():
        if not decs:
            return
        v = values[-1]
        for reg in decs[-1].writes:
            if reg != "flags" and not reg.startswith("xmm"):
                v[reg] = mu.reg_read(_uc_reg(reg)) & 0xFF
        for a in mem_w[-1]:
            v[("mem", a)] = mu.mem_read(a, 1)[0]

    def on_code(u, addr, size, ud):
        flush()
        pcs.append((addr, size))
        decs.append(dec.decode(u, addr, size))
        mem_r.append(set())
        mem_w.append(set())
        values.append({})

    def on_mem(u, access, addr, size, value, ud):
        tgt = mem_w[-1] if access == 17 else mem_r[-1]     # UC_MEM_WRITE == 17
        for i in range(size):
            tgt.add(addr + i)

    mu.hook_add(UC_HOOK_CODE, on_code)
    mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, on_mem)
    mu.emu_start(emu.entry, SENT)
    flush()
    return Trace(pcs, decs, mem_r, mem_w, values, bytes(mu.mem_read(OUTB, 4)))


# ------------------------------------------------------- def-use graph -----
OBS = "OBS"


@dataclass
class Graph:
    """Nodes are definitions (k, location); k = -1 for initial contents."""
    succ: dict = field(default_factory=dict)        # node -> set(node | OBS)
    bad_use: set = field(default_factory=set)       # node read as address/control
    writes: list = field(default_factory=list)      # per k: list of nodes
    prev_def: dict = field(default_factory=dict)    # node -> node overwritten by it
    r_taint: set = field(default_factory=set)
    reach_out: set = field(default_factory=set)     # reaches OUT[0..2]
    reach_obs: set = field(default_factory=set)     # reaches any observed byte
    bad_reach: set = field(default_factory=set)     # reaches an address/control use
    ipdom: dict = field(default_factory=dict)
    depth: dict = field(default_factory=dict)


def build_graph(t: Trace) -> Graph:
    g = Graph()
    last: dict = {}

    def cur(loc):
        n = last.get(loc)
        if n is None:
            n = (-1, loc)
            last[loc] = n
            g.succ.setdefault(n, set())
        return n

    for k, d in enumerate(t.dec):
        data_reads = [cur(r) for r in d.reads] + [cur(("mem", a)) for a in t.mem_r[k]]
        addr_reads = [cur(r) for r in d.addr_reads]
        if d.control:
            for r in d.steer:
                g.bad_use.add(cur(r))
            if d.mnemonic == "ret":
                for a in t.mem_r[k]:                 # the return address
                    g.bad_use.add(cur(("mem", a)))
        for n in addr_reads:
            g.bad_use.add(n)
        nodes = []
        for loc in list(d.writes) + [("mem", a) for a in t.mem_w[k]]:
            n = (k, loc)
            g.succ.setdefault(n, set())
            g.prev_def[n] = cur(loc)
            nodes.append(n)
        for src in data_reads:
            g.succ[src].update(nodes)
        if any(src in g.r_taint for src in data_reads) or \
                any(src == (-1, ("mem", IN + 4)) for src in data_reads):
            g.r_taint.update(nodes)
        for n in nodes:
            last[n[1]] = n
        g.writes.append(nodes)
    for j in range(4):
        n = cur(("mem", OUTB + j))
        g.succ[n].add(OBS)
        g.reach_obs.add(n)
        if j < 3:
            g.reach_out.add(n)

    order = sorted(g.succ, key=lambda n: n[0], reverse=True)
    for n in order:                       # reverse topological (successors have larger k)
        for s in g.succ[n]:
            if s == OBS:
                continue
            if s in g.reach_out:
                g.reach_out.add(n)
            if s in g.reach_obs:
                g.reach_obs.add(n)
            if s in g.bad_reach:
                g.bad_reach.add(n)
        if n in g.bad_use:
            g.bad_reach.add(n)

    # immediate post-dominators with respect to OBS, on live nodes only
    g.depth[OBS] = 0

    def lca(a, b):
        while a != b:
            if g.depth[a] < g.depth[b]:
                a, b = b, a
            a = g.ipdom[a]
        return a

    for n in order:
        if n not in g.reach_obs:
            continue
        live = [s for s in g.succ[n] if s == OBS or s in g.reach_obs]
        p = live[0]
        for s in live[1:]:
            p = lca(p, s)
        g.ipdom[n] = p
        g.depth[n] = g.depth[p] + 1
    g.lca = lca
    return g


# ------------------------------------------------- IR side: site templates --
@dataclass
class SiteTemplates:
    prog: Program
    kinds: list              # per IR site: 'template' | 'unobserved' | 'no-reach' | 'other'
    jo: list                 # per site: tuple of field elements at the state
    jd: list                 # per site: tuple over all challenges
    roots: list              # per site: frozenset of challenges with Jd == 0
    values: list             # per training input: list of IR values per site


def site_templates(prog: Program, state_env: dict, training_envs: list[dict]) -> SiteTemplates:
    F = get_field(prog.m, prog.modulus)
    res = structural.generate(prog)
    P = structural.passes(prog)
    T = res.document["templates"]
    by_site = {}
    for c in res.faults:
        by_site.setdefault(c["fault"]["site"], set()).add(
            (c["mode"], T[c["template"]]["kind"] if c.get("template") else None))
    kinds, jo, jd, roots = [], [], [], []
    for i in range(len(prog.instrs)):
        modes = {m for m, _ in by_site.get(i, ())}
        if not P.linear[i]:
            kinds.append("other")
        elif "template" in modes:
            kinds.append("template")
        elif "unobserved" in modes:
            kinds.append("unobserved")
        elif modes <= {"no-reach", "delta-zero"}:
            kinds.append("no-reach")
        else:
            kinds.append("other")
        jo.append(tuple(p.evaluate(state_env) for p in P.jo[i]))
        row = tuple(P.jd[i].evaluate({**state_env, prog.challenge: r}) for r in range(F.q))
        jd.append(row)
        roots.append(frozenset(r for r, v in enumerate(row) if v == 0))
    vals = []
    for env in training_envs:
        reg = dict(env)
        per_site = []
        for ins in prog.instrs:
            reg = _step(F, reg, ins)
            per_site.append(reg[ins.dst])
        vals.append(per_site)
    return SiteTemplates(prog, kinds, jo, jd, roots, vals)


def _step(F, reg: dict, ins) -> dict:
    reg = dict(reg)
    if ins.op == "const":
        v = ins.a
    elif ins.op == "mov":
        v = reg.get(ins.a, 0)
    elif ins.op == "add":
        v = reg.get(ins.a, 0) ^ reg.get(ins.b, 0)
    else:
        v = F.mul(reg.get(ins.a, 0), reg.get(ins.b, 0))
    reg[ins.dst] = v
    return reg


# --------------------------------------------------------- the quotient ----
DELTAS = [1, 2, 4, 8, 16, 32, 64, 128, 0x53, 0xFF]


@dataclass
class Result:
    predictions: list            # per dynamic instruction: dict
    realised: dict               # node -> IR site
    stats: dict


def analyse(elf_bytes: bytes, entry: int, prog: Program, input_names: list[str],
            state: tuple, training: list[tuple], challenges=range(256)) -> Result:
    """Predict the outcome class of every single dynamic instruction skip."""
    t0 = time.perf_counter()
    F = get_field(prog.m, prog.modulus)
    emu, dec = Emu(elf_bytes, entry), Decoder()
    stats = Counter()

    def env_of(st, r):
        e = dict(zip(input_names, st))
        e[prog.challenge] = r
        return e

    # 1. traces (the first training input must use the analysed state)
    if tuple(training[0][0]) != tuple(state):
        raise ValueError("training[0] must be the analysed state")
    traces = [trace(emu, dec, st, r) for st, r in training]
    stats["traced_runs"] = len(traces)
    t = traces[0]
    for other in traces[1:]:
        if [p for p, _ in other.pcs] != [p for p, _ in t.pcs]:
            raise RuntimeError("dynamic trace depends on the input; out of scope")
        if other.mem_r != t.mem_r or other.mem_w != t.mem_w:
            raise RuntimeError("memory addresses depend on the input; out of scope")
    g = build_graph(t)

    # 2. IR templates at the analysed state, IR values on the training inputs
    st_env = dict(zip(input_names, state))
    S = site_templates(prog, st_env, [env_of(s, r) for s, r in training])

    # 3. candidate realisation points by value matching
    candidates: dict = {}
    for k in range(len(t.pcs)):
        for node in g.writes[k]:
            loc = node[1]
            if loc == "flags" or (isinstance(loc, str) and loc.startswith("xmm")):
                continue
            if node in g.r_taint or node not in g.reach_obs:
                continue
            seq = tuple(tr.values[k].get(loc) for tr in traces)
            sites = [i for i in range(len(prog.instrs))
                     if tuple(v[i] for v in S.values) == seq]
            if sites:
                candidates[node] = sites
    stats["candidate_points"] = len(candidates)

    # 4. validate candidates by injection (all challenges, fixed state)
    by_k: dict = {}
    for node in candidates:
        by_k.setdefault(node[0], []).append(node)
    observed: dict = {node: {} for node in candidates}     # node -> {(delta, r): out bytes}
    high_ok: dict = {node: True for node in candidates}
    n_dyn = len(t.pcs)

    def run_to_end(mu, start):
        try:
            if start != SENT:
                mu.emu_start(start, SENT, count=20 * n_dyn)
            if start != SENT and mu.reg_read(UX.UC_X86_REG_RIP) != SENT:
                return None
            return bytes(mu.mem_read(OUTB, 4))
        except UcError:
            return None

    def poke(mu, loc, xor):
        if isinstance(loc, tuple):
            mu.mem_write(loc[1], bytes([mu.mem_read(loc[1], 1)[0] ^ (xor & 0xFF)]))
        else:
            rid = _uc_reg(loc)
            mu.reg_write(rid, mu.reg_read(rid) ^ xor)

    last_k = max(by_k) if by_k else -1
    for r in challenges:
        mu = emu.fresh(state, r)
        ref = None                      # fault-free observation for this challenge
        for k, (pc, size) in enumerate(t.pcs):
            if k > last_k:
                break
            mu.emu_start(pc, SENT, count=1)
            nxt = t.pcs[k + 1][0] if k + 1 < n_dyn else SENT
            if k not in by_k:
                continue
            snap = emu.save(mu)
            if ref is None:
                ref = run_to_end(mu, nxt)
                emu.restore(mu, snap)
                stats["injection_runs"] += 1
            for node in by_k[k]:
                for delta in DELTAS:
                    poke(mu, node[1], delta)
                    observed[node][(delta, r)] = run_to_end(mu, nxt)
                    emu.restore(mu, snap)
                    stats["injection_runs"] += 1
                if not isinstance(node[1], tuple):
                    poke(mu, node[1], 0xA5C3_5A00)          # bits 8..31 only
                    if run_to_end(mu, nxt) != ref:
                        high_ok[node] = False
                    emu.restore(mu, snap)
                    stats["injection_runs"] += 1

    realised: dict = {}
    for node, sites in candidates.items():
        if not high_ok[node]:
            stats["rejected_upper_bits_live"] += 1
            continue
        match = None
        for i in range(len(prog.instrs)):
            if S.kinds[i] == "other":
                continue
            ok = True
            for (delta, r), out in observed[node].items():
                if out is None:
                    ok = False
                    break
                exp_out = bytes(a ^ F.mul(delta, j) for a, j in zip(t.out[:3], S.jo[i]))
                if out[:3] != exp_out or out[3] != F.mul(delta, S.jd[i][r]):
                    ok = False
                    break
            if ok:
                match = i
                break
        if match is None:
            stats["rejected_no_matching_site"] += 1
        else:
            realised[node] = match
    stats["validated_points"] = len(realised)

    # 5. predictions
    preds = []
    for k, d in enumerate(t.dec):
        nodes = g.writes[k]
        live = [n for n in nodes if n in g.reach_obs]
        p = {"k": k, "pc": t.pcs[k][0], "asm": d.text, "class": None, "site": None,
             "reason": None}
        if d.control:
            p.update({"class": "outside", "reason": "control or stack instruction"})
        elif any(n in g.bad_reach for n in nodes):
            p.update({"class": "outside", "reason": "perturbed value reaches an address/control use"})
        elif not live:
            p.update({"class": "no-effect", "reason": "no written location reaches an observed byte"})
        elif not any(n in g.reach_out for n in live):
            p.update({"class": "no-wrong-output",
                      "reason": "reaches only the discrepancy byte"})
        else:
            dom = live[0]
            for n in live[1:]:
                dom = g.lca(dom, n)
            E = dom
            while E != OBS and E not in realised:
                E = g.ipdom[E]
            stale_r = any(g.prev_def[n] in g.r_taint for n in nodes)
            if E == OBS:
                p.update({"class": "outside",
                          "reason": "no validated realisation point post-dominates the fault"})
            elif stale_r:
                p.update({"class": "outside",
                          "reason": "stale content left by the skip depends on the challenge"})
            else:
                i = realised[E]
                p["site"] = i
                p["realised_at"] = E[0]
                kind = S.kinds[i]
                if kind == "template":
                    p.update({"class": "template", "roots": sorted(S.roots[i]),
                              "reason": f"IR site {i} ({prog.instrs[i].region})"})
                elif kind == "unobserved":
                    p.update({"class": "unobserved",
                              "reason": f"IR site {i} ({prog.instrs[i].region}): checker blind"})
                else:
                    p.update({"class": "no-wrong-output",
                              "reason": f"IR site {i} does not reach an output"})
        preds.append(p)
    stats["seconds"] = time.perf_counter() - t0
    stats["dynamic_instructions"] = n_dyn
    return Result(preds, realised, dict(stats))


def consistent(pred: dict, status: Counter, wrong_r: set, U: set, n_ch: int) -> bool | None:
    """Is the exhaustive ground truth consistent with the prediction?
    None for outside-coverage predictions (nothing was claimed)."""
    cls = pred["class"]
    if cls == "outside":
        return None
    if status["ok"] < n_ch:
        return False                         # a covered skip must not crash
    if cls == "no-effect" or cls == "no-wrong-output":
        return not wrong_r
    if cls == "template":
        return (not wrong_r) or (len(wrong_r) == n_ch and U == set(pred["roots"]))
    if cls == "unobserved":
        return (not wrong_r) or (len(wrong_r) == n_ch and len(U) == n_ch)
    return False

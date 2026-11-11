#!/usr/bin/env python3
"""Compiled-kernel study: does the IR-level structural quotient survive
compilation? (It is not expected to; the point is to find out HOW it breaks.)

For each build (compiler, flags) of src/compiled/kernel.c:
  * record compiler version, flags, ELF sha256 and disassembly (data/compiled/);
  * emulate the function (Unicorn, x86-64) and, for one fixed state and for
    every challenge r in the stated set, skip EVERY dynamic instruction once
    (run k instructions, advance RIP past the next one, continue);
  * per dynamic site, compute over the challenges:
        wrong      output bytes differ from the true product
        undetected out[3] == 0
    and the set U of challenges that are wrong AND undetected.

IR prediction for a single corrupted data value in this program: U is one of
the four class root sets {}, {0}, {1}, {0,1} (data/certificates: classes
h = 1 / 1+R, with or without the zero root). A machine-level skip whose U is
anything else is NOT equivalent to any single IR data fault. Those sites are
listed with their disassembly.

Fault model here: single dynamic instruction skip at ISA level, x86-64,
emulated. No claim about physical faults or other ISAs.

Writes data/compiled_kernel_study.{json,md} and data/compiled/*.
"""
import hashlib
import json
import pathlib
import struct
import subprocess
import sys
import time
from collections import Counter

from unicorn import (UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64, UC_PROT_EXEC, UC_PROT_READ, Uc,
                     UcError)
from unicorn.x86_const import UC_X86_REG_RDI, UC_X86_REG_RIP, UC_X86_REG_RSI, UC_X86_REG_RSP

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from toy import gf256 as G  # noqa: E402

SRC = ROOT / "src" / "compiled" / "kernel.c"
OUT = ROOT / "data" / "compiled"
BUILDS = [  # (label, compiler, opt, challenges, disc-cell initial values)
    ("gcc-O2", "gcc", "-O2", list(range(256)), (0x00, 0xA5)),
    ("clang-O2", "clang", "-O2", list(range(256)), (0x00,)),
    ("gcc-O0", "gcc", "-O0", list(range(256)), (0x00,)),
]
STATE = (0x53, 0xCA, 0x1D, 0x9E)          # a0, a1, b0, b1 (fixed, recorded)
IR_ROOT_SETS = [frozenset(), frozenset({0}), frozenset({1}), frozenset({0, 1})]
STACK, STACK_SZ, IN, OUTB, SENT = 0x7000000, 0x10000, 0x8000000, 0x8001000, 0x9000000


def build(label, cc, opt):
    elf = OUT / f"kernel-{label}.elf"
    flags = [opt, "-ffreestanding", "-fno-stack-protector", "-fno-pic", "-no-pie",
             "-nostdlib", "-static", "-fcf-protection=none", "-Wl,-e,kernel",
             "-Wl,--build-id=none"]
    subprocess.run([cc, *flags, "-o", str(elf), str(SRC)], check=True)
    ver = subprocess.run([cc, "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    dis = subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(elf)],
                         capture_output=True, text=True).stdout
    (OUT / f"kernel-{label}.dis").write_text(dis)
    sym = subprocess.run(["nm", str(elf)], capture_output=True, text=True).stdout
    entry = next(int(l.split()[0], 16) for l in sym.splitlines() if l.split()[-1] == "kernel")
    return elf, ver, " ".join(flags), entry, dis


def load_segments(elf: pathlib.Path):
    b = elf.read_bytes()
    phoff, = struct.unpack_from("<Q", b, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", b, 0x36)
    segs = []
    for i in range(phnum):
        p_type, p_flags, p_offset, p_vaddr, _pa, p_filesz, p_memsz, _al = \
            struct.unpack_from("<IIQQQQQQ", b, phoff + i * phentsize)
        if p_type == 1 and p_memsz:
            segs.append((p_vaddr, b[p_offset:p_offset + p_filesz], p_memsz, p_flags))
    return segs


def expected(state, r):
    a0, a1, b0, b1 = state
    p0, p2 = G.mul(a0, b0), G.mul(a1, b1)
    p1 = G.mul(a0, b1) ^ G.mul(a1, b0)
    return bytes([p0, p1, p2])


class Machine:
    """One emulator instance per (state, challenge). The fault-free run is
    advanced one instruction at a time; before each instruction the CPU
    context and the writable memory windows are snapshotted, the skip run is
    executed from the snapshot, and the snapshot is restored."""
    WIN = 0x800                     # stack window saved/restored around sp

    def __init__(self, elf, entry):
        self.entry = entry
        self.segs = load_segments(elf)

    def fresh(self, state, r, disc_init):
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        for vaddr, data, memsz, _flags in self.segs:
            base = vaddr & ~0xFFF
            size = ((vaddr + memsz + 0xFFF) & ~0xFFF) - base
            try:
                mu.mem_map(base, size)
            except UcError:
                pass
            mu.mem_write(vaddr, data)
        for vaddr, data, memsz, flags in self.segs:
            if not flags & 2:           # not writable in the ELF: a wild write must fault
                base = vaddr & ~0xFFF
                size = ((vaddr + memsz + 0xFFF) & ~0xFFF) - base
                mu.mem_protect(base, size, UC_PROT_READ | UC_PROT_EXEC)
        mu.mem_map(STACK, STACK_SZ)
        mu.mem_map(IN, 0x2000)
        mu.mem_map(SENT, 0x1000)
        mu.mem_write(IN, bytes(state) + bytes([r]))
        mu.mem_write(OUTB, bytes([0, 0, 0, disc_init]))
        self.sp = STACK + STACK_SZ - 0x1000
        mu.mem_write(self.sp, struct.pack("<Q", SENT))
        mu.reg_write(UC_X86_REG_RSP, self.sp)
        mu.reg_write(UC_X86_REG_RDI, IN)
        mu.reg_write(UC_X86_REG_RSI, OUTB)
        return mu

    def trace(self, state, r):
        mu = self.fresh(state, r, 0)
        pcs = []
        mu.hook_add(UC_HOOK_CODE, lambda u, addr, size, ud: pcs.append((addr, size)))
        mu.emu_start(self.entry, SENT)
        return pcs, bytes(mu.mem_read(OUTB, 4))

    def _save(self, mu):
        return (mu.context_save(), bytes(mu.mem_read(self.sp - self.WIN, self.WIN + 0x100)),
                bytes(mu.mem_read(IN, 8)), bytes(mu.mem_read(OUTB, 4)))

    def _restore(self, mu, snap):
        ctx, stack, inb, outb = snap
        mu.context_restore(ctx)
        mu.mem_write(self.sp - self.WIN, stack)
        mu.mem_write(IN, inb)
        mu.mem_write(OUTB, outb)

    def all_skips(self, state, r, pcs, disc_init):
        """Yield (status, out) for the skip of each dynamic instruction."""
        mu = self.fresh(state, r, disc_init)
        n = len(pcs)
        for k, (pc, size) in enumerate(pcs):
            snap = self._save(mu)
            nxt = pc + size
            try:
                if nxt != SENT:
                    mu.emu_start(nxt, SENT, count=20 * n)
                if mu.reg_read(UC_X86_REG_RIP) != SENT and nxt != SENT:
                    res = ("timeout", None)
                else:
                    res = ("ok", bytes(mu.mem_read(OUTB, 4)))
            except UcError:
                res = ("crash", None)
            yield res
            self._restore(mu, snap)
            if k + 1 < n:
                mu.emu_start(pc, SENT, count=1)        # advance the fault-free run
                assert mu.reg_read(UC_X86_REG_RIP) == pcs[k + 1][0]


def study(label, cc, opt, challenges, disc_inits):
    t0 = time.perf_counter()
    elf, ver, flags, entry, dis = build(label, cc, opt)
    M = Machine(elf, entry)
    pcs, ref_out = M.trace(STATE, challenges[0])
    n_dyn = len(pcs)
    assert ref_out[:3] == expected(STATE, 0) and ref_out[3] == 0, "fault-free run is wrong"
    for r in challenges:                      # trace must not depend on r
        p2, o2 = M.trace(STATE, r)
        assert [a for a, _ in p2] == [a for a, _ in pcs] and o2[3] == 0
    text = {}
    for line in dis.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0].strip().endswith(":"):
            try:
                text[int(parts[0].strip()[:-1], 16)] = parts[-1].strip()
            except ValueError:
                pass
    results = {}
    for disc_init in disc_inits:
        per_site = [(Counter(), set(), set(), set()) for _ in range(n_dyn)]
        for r in challenges:
            exp = expected(STATE, r)
            for k, (st, out) in enumerate(M.all_skips(STATE, r, pcs, disc_init)):
                status, U, wrong_r, alarm_r = per_site[k]
                status[st] += 1
                if st != "ok":
                    continue
                if out[:3] != exp:
                    wrong_r.add(r)
                    if out[3] == 0:
                        U.add(r)
                elif out[3] != 0:
                    alarm_r.add(r)
        sites = []
        for k, (status, U, wrong_r, alarm_r) in enumerate(per_site):
            n_ok = status["ok"]
            if n_ok < len(challenges):
                cat = "crash-or-timeout" if n_ok == 0 else "mixed-crash"
            elif not wrong_r:
                cat = "no-wrong-output:false-alarm" if alarm_r else "no-effect"
            elif len(U) == len(challenges):
                cat = "BYPASS:wrong-and-undetected-for-every-challenge"
            elif frozenset(U) in [s & frozenset(challenges) for s in IR_ROOT_SETS] \
                    and len(wrong_r) == len(challenges):
                cat = "ir-like:U-is-an-IR-class-root-set"
            else:
                cat = "NOT-IR-LIKE:other-undetected-set"
            sites.append({"k": k, "pc": pcs[k][0], "asm": text.get(pcs[k][0], "?"),
                          "category": cat, "undetected": len(U), "wrong": len(wrong_r),
                          "U": sorted(U) if len(U) <= 4 else None})
        results[f"disc_init=0x{disc_init:02X}"] = sites
    return {"label": label, "compiler": ver, "flags": flags,
            "elf_sha256": hashlib.sha256(elf.read_bytes()).hexdigest(),
            "source_sha256": hashlib.sha256(SRC.read_bytes()).hexdigest(),
            "dynamic_instructions": n_dyn, "static_instructions": len({a for a, _ in pcs}),
            "challenges": len(challenges), "state": list(STATE),
            "results": results, "seconds": time.perf_counter() - t0}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    only = sys.argv[1:]
    rows = [study(*b) for b in BUILDS if not only or b[0] in only]
    if only:
        for r in rows:
            for key, sites in r["results"].items():
                print(r["label"], key, r["dynamic_instructions"], f"{r['seconds']:.0f}s",
                      dict(Counter(s["category"] for s in sites)))
        return
    (ROOT / "data" / "compiled_kernel_study.json").write_text(json.dumps(rows, indent=1) + "\n")
    md = ["# Compiled-kernel study (generated by tools/compiled_kernel_study.py)", "",
          "Kernel: `src/compiled/kernel.c` (2x2 Karatsuba + fingerprint, the toy-ir-v1 program "
          "`polymul_karatsuba2`). ISA: x86-64, emulated with Unicorn. Fault model: ONE dynamic "
          f"instruction skipped. State (a0,a1,b0,b1) = {tuple(hex(v) for v in STATE)}, fixed. "
          "'Exhaustive' below means: every dynamic instruction of the function x every listed challenge, "
          "for that one state.", "",
          "| build | compiler | flags | ELF sha256 | dynamic instrs | static instrs | challenges |",
          "|---|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['label']} | {r['compiler']} | `{r['flags']}` | `{r['elf_sha256'][:16]}…` | "
                  f"{r['dynamic_instructions']} | {r['static_instructions']} | {r['challenges']} |")
    cats = ["no-effect", "no-wrong-output:false-alarm", "ir-like:U-is-an-IR-class-root-set",
            "NOT-IR-LIKE:other-undetected-set", "BYPASS:wrong-and-undetected-for-every-challenge",
            "mixed-crash", "crash-or-timeout"]
    md += ["", "## Outcome of every dynamic instruction skip", "",
           "| build | disc cell initial value | " + " | ".join(cats) + " |",
           "|---|---|" + "---|" * len(cats)]
    for r in rows:
        for key, sites in r["results"].items():
            c = Counter(s["category"] for s in sites)
            md.append(f"| {r['label']} | {key.split('=')[1]} | " + " | ".join(str(c.get(k, 0)) for k in cats) + " |")
    md += ["", "## Size of the undetected set among skips that corrupt the output", "",
           "IR-level single-fault bound for this program: at most 2 undetected challenges "
           "(classes: 0, 1, 1, 2). 'wrong for only some r' means the output corruption itself "
           "depends on the challenge, which no data-region IR fault can do.", "",
           "| build | skips with a wrong output | |U|=0 | |U|=1 | |U|=2 | 2<|U|<all | |U|=all (bypass) | wrong for only some r |",
           "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        key = next(iter(r["results"]))
        ws = [s for s in r["results"][key] if s["wrong"] > 0 and "crash" not in s["category"]]
        n = r["challenges"]
        md.append(f"| {r['label']} | {len(ws)} | {sum(s['undetected'] == 0 for s in ws)} | "
                  f"{sum(s['undetected'] == 1 for s in ws)} | {sum(s['undetected'] == 2 for s in ws)} | "
                  f"{sum(2 < s['undetected'] < n for s in ws)} | {sum(s['undetected'] == n for s in ws)} | "
                  f"{sum(s['wrong'] < n for s in ws)} |")
    md += ["", "## Skips that are not equivalent to any single IR data fault", "",
           "Grouped by instruction text; count = dynamic occurrences."]
    for r in rows:
        key = next(iter(r["results"]))
        md += ["", f"### {r['label']} ({key})", "", "| category | instruction | dynamic occurrences | first pc |",
               "|---|---|---|---|"]
        grp = Counter()
        first = {}
        for s in r["results"][key]:
            if s["category"].startswith(("BYPASS", "NOT-IR-LIKE")):
                grp[(s["category"].split(":")[0], s["asm"])] += 1
                first.setdefault((s["category"].split(":")[0], s["asm"]), s["pc"])
        for (cat, asm), n in sorted(grp.items(), key=lambda kv: (kv[0][0], -kv[1])):
            md.append(f"| {cat} | `{asm}` | {n} | {first[(cat, asm)]:#x} |")
    out = ROOT / "data" / "compiled_kernel_study.md"
    out.write_text("\n".join(md) + "\n")
    print(out.read_text()[:6000])


if __name__ == "__main__":
    main()

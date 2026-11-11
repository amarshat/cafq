"""toy-ir-v1: straight-line arithmetic programs over GF(2^m), and the exact
semantics of the three in-scope fault kinds.

Registers are mutable and initialised to 0. Inputs and the challenge are
read-only registers. Because programs are straight-line, every static
instruction executes exactly once: static site == dynamic site.

Instructions
  const dst, imm      dst := imm
  mov   dst, a        dst := a
  add   dst, a, b     dst := a + b      (XOR)
  mul   dst, a, b     dst := a * b      (field multiply)

Faults (single, at instruction index ``site``)
  skip     the instruction is not executed; dst keeps its previous value
  zero     the instruction's result is replaced by 0
  bitflip  the instruction executes, then bit ``bit`` of dst is flipped

Out of scope for toy-ir-v1 (no instruction exists to fault): branches,
memory addressing, the challenge sampler, anything after ``disc``.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .field import get_field

OPS = ("const", "mov", "add", "mul")
FAULT_KINDS = ("skip", "zero", "bitflip")


@dataclass(frozen=True)
class Instr:
    op: str
    dst: str
    a: str | int | None = None
    b: str | None = None
    region: str = "data"

    def to_json(self):
        return [self.op, self.dst, self.a, self.b, self.region]


@dataclass(frozen=True)
class Fault:
    kind: str
    site: int
    bit: int | None = None

    @property
    def site_id(self) -> str:
        s = f"{self.kind}@{self.site}"
        return s if self.bit is None else f"{s}.b{self.bit}"


@dataclass
class Program:
    name: str
    m: int                       # field is GF(2^m)
    modulus: int
    inputs: list[str]
    challenge: str
    instrs: list[Instr]
    outputs: list[str]           # registers whose corruption is a "wrong output"
    disc: str                    # register tested against 0 by the checker
    # registers whose FAULT-FREE value being nonzero means "input is
    # inconsistent" (used when wrongness comes from the input, as in AR)
    inconsistency: list[str] = field(default_factory=list)

    def __post_init__(self):
        ro = set(self.inputs) | {self.challenge}
        for i, ins in enumerate(self.instrs):
            if ins.op not in OPS:
                raise ValueError(f"instr {i}: unknown op {ins.op}")
            if ins.dst in ro:
                raise ValueError(f"instr {i}: writes read-only register {ins.dst}")

    def to_json(self) -> dict:
        return {
            "ir": "toy-ir-v1", "name": self.name, "m": self.m, "modulus": self.modulus,
            "inputs": self.inputs, "challenge": self.challenge,
            "instrs": [i.to_json() for i in self.instrs],
            "outputs": self.outputs, "disc": self.disc,
            "inconsistency": self.inconsistency,
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.to_json(), sort_keys=True, separators=(",", ":")).encode()

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @staticmethod
    def from_json(d: dict) -> "Program":
        return Program(d["name"], d["m"], d["modulus"], d["inputs"], d["challenge"],
                       [Instr(*i) for i in d["instrs"]], d["outputs"], d["disc"],
                       d["inconsistency"])

    def fault_space(self, kinds=FAULT_KINDS) -> list[Fault]:
        out = []
        for site in range(len(self.instrs)):
            for k in kinds:
                if k == "bitflip":
                    out += [Fault(k, site, b) for b in range(self.m)]
                else:
                    out.append(Fault(k, site))
        return out


def run(prog: Program, env: dict[str, int], fault: Fault | None = None) -> dict[str, int]:
    """Concrete execution. ``env`` gives every input and the challenge."""
    F = get_field(prog.m, prog.modulus)
    reg: dict[str, int] = dict(env)
    for i, ins in enumerate(prog.instrs):
        hit = fault is not None and fault.site == i
        if hit and fault.kind == "skip":
            continue
        if ins.op == "const":
            v = ins.a
        elif ins.op == "mov":
            v = reg.get(ins.a, 0)
        elif ins.op == "add":
            v = reg.get(ins.a, 0) ^ reg.get(ins.b, 0)
        else:
            v = F.mul(reg.get(ins.a, 0), reg.get(ins.b, 0))
        if hit and fault.kind == "zero":
            v = 0
        if hit and fault.kind == "bitflip":
            v ^= 1 << fault.bit
        reg[ins.dst] = v
    return reg

"""Compiler-aware quotient on a real binary (skipped without gcc, unicorn,
capstone). The decisive assertions: no prediction is contradicted by the
exhaustive emulation, and no complete bypass is predicted safe."""
import pathlib
import shutil
import sys

import pytest

pytest.importorskip("unicorn")
pytest.importorskip("capstone")
if shutil.which("gcc") is None:
    pytest.skip("gcc not installed", allow_module_level=True)

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import binary_quotient_study as BQ  # noqa: E402
from capstone import CS_ARCH_X86, CS_MODE_64, Cs  # noqa: E402

from cafq import binquot  # noqa: E402


class _Mem:
    def __init__(self, code):
        self.code = code

    def mem_read(self, addr, size):
        return self.code[:size]


def decode(code: bytes):
    return binquot.Decoder().decode(_Mem(code), 0x1000, len(code))


def test_REGRESSION_conditional_move_does_not_kill_its_destination():
    """Found by the ground-truth comparison on the clang -O2 build: the
    disassembler lists eax of `cmovne eax, ebp` as written only. Treating
    that as an overwrite dropped a data-flow edge and produced one wrong
    prediction. A conditional write must also read the old content."""
    d = decode(b"\x0f\x45\xc5")                       # cmovne eax, ebp
    assert d.mnemonic == "cmovne"
    assert "rax" in d.writes and "rax" in d.reads and "flags" in d.reads


def test_kill_model_basics():
    assert "rbx" not in decode(b"\xbb\x08\x00\x00\x00").reads      # mov ebx, 8: full overwrite
    assert "rdx" not in decode(b"\x89\xea").reads                 # mov edx, ebp
    assert "rbx" in decode(b"\x40\x30\xf3").reads                 # xor bl, sil: partial write
    d = decode(b"\x0f\x1f\x44\x00\x00")                           # nopl 0x0(%rax,%rax,1)
    assert not d.reads and not d.addr_reads and not d.writes
    lea = decode(b"\x8d\x04\x00")                                 # lea eax, [rax + rax]
    assert "rax" in lea.reads and not lea.addr_reads              # arithmetic, not an address
    pop = decode(b"\x5d")                                         # pop rbp
    assert pop.control and pop.steer == frozenset({"rsp"})


@pytest.fixture(scope="module")
def gcc_o2():
    return BQ.study("gcc-O2", "gcc", "-O2")


def test_no_unsound_prediction_on_gcc_O2(gcc_o2):
    assert gcc_o2["unsound_predictions"] == []


def test_every_complete_bypass_is_predicted_or_left_unclaimed(gcc_o2):
    b = gcc_o2["ground_truth_bypasses_predicted_as"]
    assert sum(b.values()) == 7
    assert set(b) <= {"unobserved", "outside"}
    assert b.get("unobserved", 0) == 7            # 4 input loads + 3 output stores


def test_every_skip_is_accounted_for(gcc_o2):
    p = gcc_o2["predicted"]
    assert sum(p.values()) == gcc_o2["dynamic_instructions"]
    assert p["outside"] > 0                       # coverage is not total and says so
    assert sum(gcc_o2["outside_reasons"].values()) == p["outside"]


def test_templates_carry_real_content(gcc_o2):
    """Not vacuous: a substantial number of covered skips do corrupt the
    output, and for each the undetected set equalled the IR site's root set
    (that is what 'not unsound' means for the template class)."""
    assert gcc_o2["predicted"]["template"] > 100
    assert gcc_o2["covered_skips_that_corrupt_output"] > 50

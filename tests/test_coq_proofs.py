"""Run the Coq proofs when Coq is installed (skipped otherwise). A pass
means the files compile and the main theorems depend on no axioms."""
import pathlib
import shutil
import subprocess

import pytest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "proofs" / "coq" / "check.sh"


@pytest.mark.skipif(shutil.which("coqc") is None, reason="coqc not installed")
def test_coq_proofs_compile_without_axioms():
    r = subprocess.run(["sh", str(SCRIPT)], capture_output=True, text=True, timeout=900)
    assert r.returncode == 0, r.stderr[-2000:]
    # one line per Print Assumptions: Propagation (1) + Detection (2)
    assert r.stdout.count("Closed under the global context") == 3, r.stdout
    assert "Axioms:" not in r.stdout

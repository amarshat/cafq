"""The prefix-cached baseline must be the same analysis, only cheaper."""
import pytest

from cafq import circuits as C
from cafq.analyzer import analyze
from cafq.baselines import analyze_prefix_cached
from cafq.kernels import cyclic_mul
from cafq_helpers import masked_check, nonlinear_trap


@pytest.mark.parametrize("build", [
    lambda: C.ar_discrepancy(4, shift=1), lambda: C.polymul_schoolbook(3),
    C.polymul_karatsuba2, lambda: C.butterfly4(m=2), lambda: cyclic_mul(3),
    lambda: masked_check(8, True), lambda: nonlinear_trap(8)])
def test_prefix_cached_baseline_matches_full_reexecution(build):
    prog = build()
    assert analyze_prefix_cached(prog).certificates == analyze(prog).certificates

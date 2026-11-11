"""Fault-scenario matrix for the three toy decapsulation rules.

Outcomes are frozen here so that any change in behaviour is visible. They
are observations of this toy model under single named faults, not proofs."""
import pytest

from toy import kem, scenarios

CASES = ["valid", "inv-coord0-small", "inv-coord1-small", "inv-coord0-large"]
H, W, U = "honest", "wrong-key", "unpredictable"
RAW, D0, DD = "PREDICTABLE:raw-candidate", "PREDICTABLE:ar-D=0", "PREDICTABLE:ar-D=delta"

EXPECTED = {
    # FO baseline: every checker fault yields the raw candidate (PC oracle).
    ("fo", "none"): [H, U, U, U],
    ("fo", "skip_compare_chunk"): [H, RAW, RAW, U],
    ("fo", "force_flag_zero"): [H, RAW, RAW, U],
    ("fo", "skip_select"): [H, RAW, RAW, U],
    ("fo", "alias_checker_input"): [H, RAW, RAW, U],
    ("fo", "corrupt_m"): [W, U, U, U],
    # H-AR as specified: PREDICTABLE with NO fault on coordinate 0 (CE-2).
    ("ar(shift=0)", "none"): [H, DD, U, U],
    ("ar(shift=0)", "skip_contribution"): [H, D0, D0, U],
    ("ar(shift=0)", "skip_power_update"): [H, DD, DD, U],
    ("ar(shift=0)", "force_D_zero"): [H, D0, D0, U],
    ("ar(shift=0)", "alias_checker_input"): [H, D0, D0, U],
    ("ar(shift=0)", "skip_marshal"): [H, D0, D0, U],
    ("ar(shift=0)", "corrupt_m"): [W, U, U, U],
    # DFAR re-implementation: agrees with the authors' own fault table.
    ("dfar", "none"): [H, U, U, U],
    ("dfar", "omit_first_eval"): [W, U, U, U],
    ("dfar", "omit_second_eval"): [W, U, U, U],
    ("dfar", "alias_checker_input"): [H, RAW, RAW, U],
    ("dfar", "omit_final_xor"): [H, RAW, RAW, U],
    ("dfar", "corrupt_m"): [W, U, U, U],
}

EXPECTED_SHIFT1 = {
    ("ar(shift=1)", "none"): [H, U, U, U],
    ("ar(shift=1)", "skip_contribution"): [H, D0, D0, U],
    ("ar(shift=1)", "skip_power_update"): [H, U, U, U],
    ("ar(shift=1)", "force_D_zero"): [H, D0, D0, U],
    ("ar(shift=1)", "alias_checker_input"): [H, D0, D0, U],
    ("ar(shift=1)", "skip_marshal"): [H, D0, D0, U],
    ("ar(shift=1)", "corrupt_m"): [W, U, U, U],
}


def table(rows):
    out = {}
    for r in rows:
        out.setdefault((r["variant"], r["fault"]), {})[r["case"]] = r["outcome"]
    return {k: [v[c] for c in CASES] for k, v in out.items()}


@pytest.fixture(scope="module")
def sk():
    return kem.keygen(b"seed-1")[1]


def test_matrix_shift0(sk):
    assert table(scenarios.matrix(sk, shift=0)) == EXPECTED


def test_matrix_shift1(sk):
    got = table(scenarios.matrix(sk, shift=1))
    assert {k: v for k, v in got.items() if k[0].startswith("ar")} == EXPECTED_SHIFT1


def test_matrix_is_stable_across_keys_and_messages():
    # rho-dependent cells could differ with probability ~1/256 per cell;
    # the chosen seeds/messages are recorded so the run is reproducible.
    for seed in (b"seed-2", b"seed-3"):
        s = kem.keygen(seed)[1]
        for m in (0x00, 0x5A, 0xFE):
            assert table(scenarios.matrix(s, m=m, shift=0)) == EXPECTED


def test_every_declared_fault_is_exercised(sk):
    rows = scenarios.matrix(sk)
    seen = {(r["variant"].split("(")[0], r["fault"]) for r in rows}
    for variant, names in (("fo", kem.FO_FAULTS), ("ar", kem.AR_FAULTS),
                           ("dfar", kem.DFAR_FAULTS)):
        for n in names + ("none",):
            assert (variant, n) in seen


def test_undeclared_fault_is_rejected(sk):
    with pytest.raises(ValueError):
        kem.decaps(sk, [0] * kem.CT_LEN, "fo", kem.Fault("skip_marshal"))


def test_no_single_checker_fault_is_eliminated_by_ar(sk):
    """Gate-1 evidence: for every FO checker fault that exposes the raw
    candidate there is an AR checker fault that exposes a predictable key."""
    t = table(scenarios.matrix(sk))
    fo_bad = [k for k, v in t.items() if k[0] == "fo" and RAW in v]
    ar_bad = [k for k, v in t.items() if k[0].startswith("ar") and k[1] != "none"
              and (D0 in v or DD in v)]
    assert len(fo_bad) == 4 and len(ar_bad) == 5


def test_dfar_combined_fault_identity(sk):
    """K_N xor K_D1 xor K_D2 = raw candidate (the DFAR authors' own
    observation, audit/COMBINED_FAULT_SCOPE_ANALYSIS_20261019.txt):
    three outputs for one inconsistent ciphertext expose the candidate."""
    from toy.attacks import perturb
    q = perturb(kem.enc(sk.pk, 0x5A), 1, 3)
    kn = kem.decaps(sk, q, "dfar").key
    k1 = kem.decaps(sk, q, "dfar", kem.Fault("omit_first_eval")).key
    k2 = kem.decaps(sk, q, "dfar", kem.Fault("omit_second_eval")).key
    assert kem.xor(kem.xor(kn, k1), k2) == kem.kdf_accept(0x5A, q)

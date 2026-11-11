"""Phase 1 fault-scenario matrix: every (variant, fault, ciphertext case) is
executed and classified by what the *adversary* can do with the returned key.

Classification of the returned key
  honest            valid ciphertext, key equals the encapsulated key
  wrong-key         valid ciphertext, key differs (observable failure)
  unpredictable     invalid ciphertext, key matches nothing the adversary
                    can compute from (pk, its own m, its own query)
  PREDICTABLE:<how> invalid ciphertext, key equals a value the adversary
                    computes itself => one query is a plaintext-checking
                    oracle answer "Dec(query) == m".
"""
from __future__ import annotations

from . import kem
from .attacks import perturb

CASES = {
    # name: (coordinate, offset)  -- None = honest valid ciphertext
    "valid": None,
    "inv-coord0-small": (0, 3),     # still decrypts to m
    "inv-coord1-small": (1, 3),     # still decrypts to m
    "inv-coord0-large": (0, 100),   # decrypts to m with bit 0 flipped
}


def fault_list(variant: str, coord: int) -> list[kem.Fault | None]:
    """Faults aligned with the perturbed coordinate (the adversary's best
    choice in a single-fault model)."""
    out: list[kem.Fault | None] = [None]
    names = {"fo": kem.FO_FAULTS, "ar": kem.AR_FAULTS, "dfar": kem.DFAR_FAULTS}[variant]
    for n in names:
        if n == "skip_power_update":
            out.append(kem.Fault(n, max(coord - 1, 0)))
        elif n == "corrupt_m":
            out.append(kem.Fault(n, 7))
        else:
            out.append(kem.Fault(n, coord))
    return out


def adversary_candidates(m: int, c_valid: list[int], q: list[int]) -> dict[str, bytes]:
    delta = 0
    for a, b in zip(c_valid, q):
        delta ^= a ^ b              # single perturbed coordinate => its XOR diff
    return {
        "raw-candidate": kem.kdf_accept(m, q),
        "ar-D=0": kem.kdf_ar(m, q, 0),
        "ar-D=delta": kem.kdf_ar(m, q, delta),
    }


def classify(sk: kem.SecretKey, variant: str, fault: kem.Fault | None,
             case: str, m: int, shift: int = 0) -> str:
    c, k_honest = kem.encaps(sk.pk, m, variant)
    spec = CASES[case]
    if spec is None:
        key = kem.decaps(sk, c, variant, fault, shift).key
        return "honest" if key == k_honest else "wrong-key"
    q = perturb(c, *spec)
    key = kem.decaps(sk, q, variant, fault, shift).key
    for how, cand in adversary_candidates(m, c, q).items():
        if key == cand:
            return f"PREDICTABLE:{how}"
    return "unpredictable"


def matrix(sk: kem.SecretKey, m: int = 0x5A, shift: int = 0) -> list[dict]:
    rows = []
    for variant in ("fo", "ar", "dfar"):
        seen = set()
        for case, spec in CASES.items():
            coord = spec[0] if spec else 0
            for fault in fault_list(variant, coord):
                name = fault.name if fault else "none"
                rows.append({
                    "variant": variant if variant != "ar" else f"ar(shift={shift})",
                    "fault": name,
                    "fault_index": fault.index if fault else None,
                    "case": case,
                    "outcome": classify(sk, variant, fault, case, m, shift),
                })
    return rows

"""Attacker-change tests (mutations): the same attack, changed to dodge detection.

Each mutation keeps the attacker's goal the same, so the ground truth stays "attack" BY
CONSTRUCTION. We then measure which detectors still catch it.

  M0  control            no change
  M1  name_in_name       the key owner's name sits inside the creator's name (fools a text filter)
  M2  delay_use          the key is first used long after the time window
  M3  delay_key          the key is created long after the rights grant (outside the window)
  M4  shuffle_order      records appear in random order in the file
  M5  duplicate_records  every record appears twice
  M6  drop_source        the first-use event has no source address or tool name
  M7  known_first        the key is first used once from the owner's usual address, then from the
                         attacker's address
  M8  poison_baseline    the attacker's address is made to look "usual" for the owner beforehand
  M9  approved_role      the key is made through an approved automation role

The PREDICTIONS table was written BEFORE the first run (see docs/EVALUATION.md). After a run,
the tool reports every cell where the measured result differs from the prediction.
"""
import copy
import random

from cloudtrace.evaluation import scenarios as sc

DETECTORS = ("ct", "ct_any", "b1", "b2", "b2x", "b3")
A1, A2, A3, A4 = ("attack_cross_new_ip", "attack_cross_creator_ip", "attack_grant_key",
                  "attack_self_key")

NAMES = {
    "M0": "control (no change)", "M1": "owner name inside creator name",
    "M2": "key first used after the window", "M3": "key created after the grant window",
    "M4": "records in random order", "M5": "every record duplicated",
    "M6": "first use has no address/tool", "M7": "first use from owner's usual address",
    "M8": "attacker address added to owner's history", "M9": "key made via approved role",
}


def _opts(rng: random.Random, m: str) -> dict:
    return {
        "M1": {"target_in_creator_name": True},
        "M2": {"use_delay": rng.randint(130, 400)},
        "M3": {"key_gap": rng.randint(90, 180)},
        "M6": {"drop_use_source": True},
        "M7": {"known_first": True},
        "M8": {"poison_baseline": True},
        "M9": {"via_role": True},
    }.get(m, {})


def build_opts(rng: random.Random, m: str) -> dict:
    return _opts(rng, m)


def post_process(records: list, m: str, rng: random.Random) -> list:
    """Record-level changes (M4, M5) applied to the finished log."""
    records = copy.deepcopy(records)
    if m == "M5":
        records = records + copy.deepcopy(records)
    if m in ("M4", "M5"):
        rng.shuffle(records)
    return records


APPLIES = {
    "M0": (A1, A2, A3, A4), "M1": (A1, A2, A3), "M2": (A1, A2, A3, A4), "M3": (A3,),
    "M4": (A1, A2, A3, A4), "M5": (A1, A2, A3, A4), "M6": (A1, A2, A3), "M7": (A1, A2, A3),
    "M8": (A1, A2, A3), "M9": (A1, A2, A3),
}


def _p(ct, ct_any, b1, b2, b2x, b3):
    return dict(zip(DETECTORS, (ct, ct_any, b1, b2, b2x, b3), strict=True))


T, F = True, False
_CONTROL = _p(T, T, T, T, T, F)
_NO_CT_FOR_CHECK2 = _p(F, T, T, T, T, F)  # Check 1 low note remains; Check 2 is evaded

# What we expect each detector to catch, written before running anything.
# For attack_grant_key, Check 3 still fires even when Check 2 is evaded.
PREDICTIONS = {}
for kind in (A1, A2, A3):
    check3_saves = kind == A3
    evaded = _p(check3_saves, T, T, T, T, F)
    PREDICTIONS[("M0", kind)] = _CONTROL
    PREDICTIONS[("M1", kind)] = _p(T, T, F, T, T, F)  # only the text filter B1 is fooled
    PREDICTIONS[("M2", kind)] = evaded
    PREDICTIONS[("M4", kind)] = _CONTROL
    PREDICTIONS[("M5", kind)] = _CONTROL
    PREDICTIONS[("M6", kind)] = evaded
    PREDICTIONS[("M7", kind)] = evaded
    PREDICTIONS[("M8", kind)] = evaded
    PREDICTIONS[("M9", kind)] = _p(F, F, T, T, F, F)  # CloudTrace trusts approved roles
PREDICTIONS[("M3", A3)] = _CONTROL  # Check 2 still fires on the new address
PREDICTIONS[("M0", A4)] = _p(F, F, F, F, F, T)  # self-made key: only B3 is built for this
PREDICTIONS[("M2", A4)] = _p(F, F, F, F, F, F)  # B3 needs the use within one hour
PREDICTIONS[("M4", A4)] = _p(F, F, F, F, F, T)
PREDICTIONS[("M5", A4)] = _p(F, F, F, F, F, T)

assert set(PREDICTIONS) == {(m, k) for m, kinds in APPLIES.items() for k in kinds}
assert all(k in sc.ATTACK_KINDS for _, k in PREDICTIONS)

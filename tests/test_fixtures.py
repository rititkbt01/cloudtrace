"""Checks the hand-made test cases themselves (format, vocabulary, safety of the data)."""
import ipaddress
import json
import re

import pytest
from helpers import SEVERITY_BANDS, case_dirs, load_case

CHECKS = {"quality", "check1", "check2", "check3"}
VERDICTS = {"ALERT", "IGNORED", "NOT_CHECKED"}
REASONS = {
    "check1": {"KEY_FOR_OTHER_ACCOUNT", "SELF_KEY", "SELF_KEY_IMPLICIT",
               "ALLOW_LISTED_ROLE", "FAILED_CALL", "TARGET_UNKNOWN"},
    "check2": {"KEY_USED_FROM_NEW_SOURCE", "SOURCE_ALREADY_SEEN", "OUTSIDE_WINDOW",
               "MISSING_KEY_ID"},
    "check3": {"GRANT_THEN_CREDENTIAL"},
}
VERDICT_REASON_RULES = {"ALERT": {"KEY_FOR_OTHER_ACCOUNT", "KEY_USED_FROM_NEW_SOURCE",
                                   "GRANT_THEN_CREDENTIAL"},
                        "NOT_CHECKED": {"MISSING_KEY_ID"}}
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
CASES = case_dirs()
IDS = [c.name for c in CASES]


def test_there_are_eleven_cases():
    assert len(CASES) == 11


@pytest.mark.parametrize("cdir", CASES, ids=IDS)
def test_case_structure(cdir):
    case, events = load_case(cdir)
    for field in ("case_id", "title", "ground_truth", "category", "applies_to_checks",
                  "description", "config", "expected"):
        assert field in case, f"{field} missing"
    assert case["ground_truth"] in {"attack", "normal"}
    assert case["category"] in {"attack", "normal", "edge", "known_limitation"}
    assert set(case["applies_to_checks"]) <= CHECKS
    assert case["case_id"].lower() == cdir.name.split("_")[0]
    assert isinstance(events, list) and events


@pytest.mark.parametrize("cdir", CASES, ids=IDS)
def test_expected_verdicts_are_valid(cdir):
    case, events = load_case(cdir)
    ids = {e["eventID"] for e in events}
    for v in case["expected"]["verdicts"]:
        assert v["check"] in case["applies_to_checks"]
        assert v["event_id"] in ids, f"{v['event_id']} not in events"
        assert v["verdict"] in VERDICTS
        assert v["reason"] in REASONS[v["check"]]
        if v["verdict"] == "ALERT":
            assert v["reason"] in VERDICT_REASON_RULES["ALERT"]
            lo, hi = SEVERITY_BANDS[v["severity"]]
            assert lo <= v["score"] <= hi, "score does not match severity band"
            assert sum(v["score_breakdown"].values()) == v["score"]
        else:
            assert "severity" not in v


@pytest.mark.parametrize("cdir", CASES, ids=IDS)
def test_event_ids_unique_except_declared_duplicates(cdir):
    case, events = load_case(cdir)
    ids = [e["eventID"] for e in events]
    dupes = len(ids) - len(set(ids))
    declared = case["expected"].get("quality", {}).get("duplicates_removed", 0)
    assert dupes == declared


@pytest.mark.parametrize("cdir", CASES, ids=IDS)
def test_data_is_synthetic(cdir):
    """Safety guard: nothing that looks like a real key, address or account."""
    _, events = load_case(cdir)
    text = json.dumps(events)
    for e in events:
        assert e["recipientAccountId"] == "123456789012"
        assert any(ipaddress.ip_address(e["sourceIPAddress"]) in n for n in DOC_NETS)
    for m in re.findall(r"\b(?:AKIA|ASIA)[A-Z0-9]+", text):
        assert "EXAMPLE" in m, f"key-like value without EXAMPLE: {m}"
    assert "@" not in text, "possible email address in fixture"

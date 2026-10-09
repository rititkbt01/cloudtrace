"""Proves the comparison helper itself works, so a failing contract test can be trusted."""
from helpers import compare

V = {"check": "check1", "event_id": "x-001", "verdict": "ALERT",
     "reason": "KEY_FOR_OTHER_ACCOUNT", "severity": "low", "score": 1}


def test_identical_results_have_no_problems():
    assert compare([V], [dict(V)], {"check1"}) == []


def test_missing_verdict_is_reported():
    assert compare([V], [], {"check1"}) == [f"missing verdict {('check1', 'x-001')}"]


def test_extra_verdict_is_reported():
    assert "unexpected verdict" in compare([], [V], {"check1"})[0]


def test_wrong_field_is_reported():
    wrong = dict(V, severity="high")
    assert "severity" in compare([V], [wrong], {"check1"})[0]


def test_checks_not_built_yet_are_ignored():
    assert compare([V], [], set()) == []

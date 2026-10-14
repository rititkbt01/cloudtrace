"""Check 3 edge cases beyond the hand-made fixtures."""
from scenario import ADMIN_POLICY, create_key, grant

from cloudtrace.engine import analyze

ADMIN_IP = "203.0.113.10"


def check3(records, config=None):
    return [v for v in analyze(records, config)["verdicts"] if v["check"] == "check3"]


def test_grant_then_key_is_medium_4():
    (row,) = check3([grant(1, 0, "admin-a", "svc-b", ADMIN_IP),
                     create_key(2, 20, "admin-a", "svc-b", ADMIN_IP)])
    assert (row["event_id"], row["score"], row["severity"]) == ("s-002", 4, "medium")
    assert row["evidence"]["grant_event_id"] == "s-001" and row["evidence"]["minutes_between"] == 20


def test_window_edge_is_inclusive():
    assert check3([grant(1, 0, "a", "svc-b", ADMIN_IP), create_key(2, 60, "a", "svc-b", ADMIN_IP)])
    assert not check3([grant(1, 0, "a", "svc-b", ADMIN_IP), create_key(2, 61, "a", "svc-b", ADMIN_IP)])


def test_key_before_grant_is_not_a_match():
    assert not check3([create_key(1, 0, "a", "svc-b", ADMIN_IP), grant(2, 10, "a", "svc-b", ADMIN_IP)])


def test_grant_to_a_different_user_is_not_a_match():
    assert not check3([grant(1, 0, "a", "bob", ADMIN_IP), create_key(2, 10, "a", "svc-b", ADMIN_IP)])


def test_weaker_policy_is_not_a_match():
    weak = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    assert not check3([grant(1, 0, "a", "svc-b", ADMIN_IP, policy=weak),
                       create_key(2, 10, "a", "svc-b", ADMIN_IP)])


def test_elevated_policies_setting_is_used():
    weak = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    records = [grant(1, 0, "a", "svc-b", ADMIN_IP, policy=weak),
               create_key(2, 10, "a", "svc-b", ADMIN_IP)]
    assert check3(records, {"elevated_policies": [weak]})
    assert not check3(records, {"elevated_policies": [ADMIN_POLICY.replace("Administrator", "X")]})


def test_failed_grant_is_not_a_match():
    assert not check3([grant(1, 0, "a", "svc-b", ADMIN_IP, error="AccessDenied"),
                       create_key(2, 10, "a", "svc-b", ADMIN_IP)])


def test_self_key_after_grant_is_not_a_match():
    assert not check3([grant(1, 0, "svc-b", "svc-b", ADMIN_IP),
                       create_key(2, 10, "svc-b", "svc-b", ADMIN_IP)])


def test_most_recent_grant_is_reported():
    (row,) = check3([grant(1, 0, "a", "svc-b", ADMIN_IP), grant(2, 15, "a", "svc-b", ADMIN_IP),
                     create_key(3, 20, "a", "svc-b", ADMIN_IP)])
    assert row["evidence"]["grant_event_id"] == "s-002"


def test_user_name_match_ignores_case():
    assert check3([grant(1, 0, "a", "SVC-B", ADMIN_IP), create_key(2, 10, "a", "svc-b", ADMIN_IP)])

"""Check 2 edge cases beyond the hand-made fixtures."""
import pytest
from scenario import baseline, create_key, event, use, user

from cloudtrace.engine import analyze

SVC_IP, ADMIN_IP, NEW_IP = "198.51.100.25", "203.0.113.10", "192.0.2.50"


def log(*parts):
    return [e for p in parts for e in (p if isinstance(p, list) else [p])]


def check2(records, config=None):
    return [v for v in analyze(records, config)["verdicts"] if v["check"] == "check2"]


def base_log(use_minutes=40, use_ip=NEW_IP, count=3, **kw):
    return log(baseline("svc-b", SVC_IP, count=count), create_key(10, 30, "admin-a", "svc-b",
               ADMIN_IP), use(11, use_minutes, "svc-b", use_ip, **kw))


def test_new_address_is_a_finding_without_creator_bonus():
    (row,) = check2(base_log())
    assert (row["verdict"], row["score"], row["severity"]) == ("ALERT", 5, "high")
    assert "creator_source" not in row["score_breakdown"]


def test_creator_address_adds_three_points():
    (row,) = check2(base_log(use_ip=ADMIN_IP))
    assert row["score"] == 8 and "creator_source" in row["score_breakdown"]


def test_window_edge_is_inclusive():
    assert check2(base_log(use_minutes=90))[0]["verdict"] == "ALERT"  # exactly 60 minutes
    assert check2(base_log(use_minutes=91))[0]["reason"] == "OUTSIDE_WINDOW"


def test_window_setting_is_used():
    rows = check2(base_log(use_minutes=50), {"window_minutes": 10})
    assert rows[0]["reason"] == "OUTSIDE_WINDOW"


def test_too_few_earlier_events_is_not_checked_not_guessed():
    (row,) = check2(base_log(count=2))
    assert (row["verdict"], row["reason"]) == ("NOT_CHECKED", "BASELINE_TOO_SMALL")


def test_baseline_setting_is_used():
    (row,) = check2(base_log(count=2), {"baseline_min_events": 2})
    assert row["verdict"] == "ALERT"


def test_new_tool_from_known_address_is_not_new_source():
    (row,) = check2(base_log(use_ip=SVC_IP, ua="curl/8.5.0"))
    assert (row["verdict"], row["reason"]) == ("IGNORED", "SOURCE_ALREADY_SEEN")


def test_only_events_before_creation_count_as_usual():
    """An address first seen AFTER the key was created must not make that address 'usual'."""
    records = log(baseline("svc-b", SVC_IP), create_key(10, 30, "admin-a", "svc-b", ADMIN_IP),
                  event(11, 31, "ListBuckets", "svc-b", NEW_IP, source="s3.amazonaws.com"),
                  use(12, 40, "svc-b", NEW_IP))
    assert check2(records)[0]["verdict"] == "ALERT"


def test_only_the_owners_events_count_as_usual():
    records = log(baseline("svc-b", SVC_IP), baseline("bob", NEW_IP, start_n=20),
                  create_key(50, 30, "admin-a", "svc-b", ADMIN_IP), use(51, 40, "svc-b", NEW_IP))
    assert check2(records)[0]["verdict"] == "ALERT"


def test_owner_name_match_ignores_case():
    records = log(baseline("Svc-B", SVC_IP), create_key(10, 30, "admin-a", "svc-b", ADMIN_IP),
                  use(11, 40, "svc-b", SVC_IP))
    assert check2(records)[0]["reason"] == "SOURCE_ALREADY_SEEN"


def test_only_the_first_use_is_judged():
    records = base_log() + [use(12, 45, "svc-b", ADMIN_IP)]
    assert len(check2(records)) == 1


def test_key_never_used_gives_no_row():
    records = log(baseline("svc-b", SVC_IP), create_key(10, 30, "admin-a", "svc-b", ADMIN_IP))
    assert check2(records) == []


def test_self_key_is_not_followed():
    records = log(baseline("svc-b", SVC_IP), create_key(10, 30, "svc-b", "svc-b", SVC_IP),
                  use(11, 40, "svc-b", NEW_IP))
    assert check2(records) == []


def test_approved_role_key_is_not_followed():
    role = {"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/ci/s",
            "sessionContext": {"sessionIssuer": {"userName": "ci"}}}
    key = event(10, 30, "CreateAccessKey", "x", ADMIN_IP, ident=role, request={"userName": "svc-b"},
                response={"accessKey": {"accessKeyId": "AKIAEXAMPLENEWKEY01", "userName": "svc-b"}})
    records = log(baseline("svc-b", SVC_IP), key, use(11, 40, "svc-b", NEW_IP))
    assert check2(records, {"allowed_roles": ["ci"]}) == []


def test_missing_key_id_only_when_no_event_is_linked():
    unlinked = event(11, 40, "GetCallerIdentity", "svc-b", NEW_IP, source="sts.amazonaws.com",
                     ident={**user("svc-b"), "accessKeyId": ""})
    base = log(baseline("svc-b", SVC_IP), create_key(10, 30, "admin-a", "svc-b", ADMIN_IP))
    (row,) = check2(base + [unlinked])
    assert (row["verdict"], row["reason"]) == ("NOT_CHECKED", "MISSING_KEY_ID")
    both = base + [unlinked, use(12, 45, "svc-b", NEW_IP)]
    assert [r["reason"] for r in check2(both)] == ["KEY_USED_FROM_NEW_SOURCE"]


def test_unlinked_event_outside_window_is_ignored_silently():
    unlinked = event(11, 200, "GetCallerIdentity", "svc-b", NEW_IP, source="sts.amazonaws.com",
                     ident={**user("svc-b"), "accessKeyId": ""})
    base = log(baseline("svc-b", SVC_IP), create_key(10, 30, "admin-a", "svc-b", ADMIN_IP))
    assert check2(base + [unlinked]) == []


def test_alert_explains_itself():
    (row,) = check2(base_log())
    ev = row["evidence"]
    assert ev["known_sources"] == [SVC_IP] and ev["baseline_events"] == 3
    assert ev["minutes_after_creation"] == 10.0 and ev["key_made_for"] == "svc-b"
    assert "did not use" in row["explanation"]


@pytest.mark.parametrize("shuffle", [True, False])
def test_log_order_does_not_change_the_result(shuffle):
    records = base_log()
    if shuffle:
        records = list(reversed(records))
    assert [r["reason"] for r in check2(records)] == ["KEY_USED_FROM_NEW_SOURCE"]

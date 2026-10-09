"""Check 1 edge cases beyond the hand-made fixtures."""
from cloudtrace.engine import analyze

ARN = "arn:aws:iam::123456789012:user/{}"


def create(n, caller="admin-a", request=..., response_user="svc-b", error=None,
           ident=None, role=None):
    ident = ident or {"type": "IAMUser", "arn": ARN.format(caller), "userName": caller,
                      "accessKeyId": "AKIAEXAMPLEADMINA01"}
    if role:
        ident = {"type": "AssumedRole", "arn": f"arn:aws:sts::123456789012:assumed-role/{role}/s",
                 "sessionContext": {"sessionIssuer": {"userName": role}}}
    req = {"userName": "svc-b"} if request is ... else request
    r = {"eventID": f"e-{n}", "eventTime": "2026-01-01T10:00:00Z", "eventName": "CreateAccessKey",
         "eventSource": "iam.amazonaws.com", "sourceIPAddress": "203.0.113.10",
         "userAgent": "t", "userIdentity": ident, "requestParameters": req,
         "responseElements": None if error else {"accessKey": {
             "accessKeyId": "AKIAEXAMPLENEWKEY01", "userName": response_user}}}
    if error:
        r["errorCode"] = error
    return r


def verdict(record, config=None):
    (row,) = analyze([record], config)["verdicts"]
    return row


def test_self_key_ignores_name_case():
    row = verdict(create(1, caller="Alice", request={"userName": "alice"}, response_user="alice"))
    assert (row["verdict"], row["reason"]) == ("IGNORED", "SELF_KEY")


def test_self_key_with_path_in_arn():
    ident = {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/team/alice",
             "userName": "alice", "accessKeyId": "AKIAEXAMPLEADMINA01"}
    row = verdict(create(1, request={"userName": "alice"}, response_user="alice", ident=ident))
    assert row["reason"] == "SELF_KEY"


def test_role_not_on_list_alerts():
    row = verdict(create(1, role="ci-deploy"), {"allowed_roles": ["other-role"]})
    assert row["verdict"] == "ALERT" and row["score"] == 1 and row["severity"] == "low"


def test_role_on_list_is_ignored():
    row = verdict(create(1, role="ci-deploy"), {"allowed_roles": ["ci-deploy"]})
    assert row["reason"] == "ALLOW_LISTED_ROLE"


def test_target_unknown_is_not_checked_not_guessed():
    row = verdict(create(1, request=None, response_user=None, role="ci-deploy"))
    assert (row["verdict"], row["reason"]) == ("NOT_CHECKED", "TARGET_UNKNOWN")


def test_failed_call_wins_over_everything():
    row = verdict(create(1, error="AccessDenied"))
    assert row["reason"] == "FAILED_CALL"


def test_every_row_explains_itself():
    row = verdict(create(1))
    assert row["explanation"] and row["evidence"]["target_user"] == "svc-b"
    assert row["score_breakdown"] == {"cross_identity": 1}


def test_other_events_get_no_rows():
    other = create(1)
    other["eventName"] = "ListUsers"
    assert analyze([other])["verdicts"] == []

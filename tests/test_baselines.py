"""B1 (the re-implemented SigmaHQ rule) and its comparison with Check 1."""
import pytest
from helpers import case_dirs, load_case

from cloudtrace.baselines import b1_backdoor_keys, compare_with_check1
from cloudtrace.engine import analyze

# How many alerts the published rule logic gives on the RAW records of each case.
B1_EXPECTED = {
    "c01": 1,
    "c02": 0,  # caller's ARN contains the target name -> filtered
    "c03": 0,
    "c04": 1,  # approved role: B1 has no allow-list
    "c05": 1,
    "c06": 1,
    "c07": 1,
    "c08": 1,
    "c09": 2,  # B1 sees the duplicated record twice
    "c10": 1,  # failed call: no user name in the reply, so the filter cannot match
    "c11": 1,
}


@pytest.mark.parametrize("cdir", case_dirs(), ids=lambda c: c.name)
def test_b1_on_each_case(cdir):
    _, records = load_case(cdir)
    assert len(b1_backdoor_keys(records)) == B1_EXPECTED[cdir.name[:3]]


def rec(caller_arn, target, eid="x-1", name="CreateAccessKey", source="iam.amazonaws.com"):
    return {"eventID": eid, "eventTime": "2026-01-01T10:00:00Z", "eventSource": source,
            "eventName": name, "userIdentity": {"arn": caller_arn},
            "responseElements": {"accessKey": {"userName": target}}}


def test_b1_only_looks_at_create_access_key_in_iam():
    arn = "arn:aws:iam::123456789012:user/a"
    assert b1_backdoor_keys([rec(arn, "b", name="ListUsers")]) == []
    assert b1_backdoor_keys([rec(arn, "b", source="s3.amazonaws.com")]) == []
    assert len(b1_backdoor_keys([rec(arn, "b")])) == 1


def test_b1_matching_ignores_case():
    assert b1_backdoor_keys([rec("arn:aws:iam::123456789012:user/Alice", "alice")]) == []


def test_b1_name_inside_name_hides_an_attack_but_check1_sees_it():
    """Known weakness of the published filter: 'admin' appears inside 'admin-a'."""
    arn = "arn:aws:iam::123456789012:user/admin-a"
    record = {"eventID": "e-1", "eventTime": "2026-01-01T10:00:00Z",
              "eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey",
              "sourceIPAddress": "203.0.113.10",
              "userIdentity": {"type": "IAMUser", "arn": arn, "userName": "admin-a"},
              "requestParameters": {"userName": "admin"},
              "responseElements": {"accessKey": {"accessKeyId": "AKIAEXAMPLENEWKEY01",
                                                 "userName": "admin"}}}
    b1 = b1_backdoor_keys([record])
    c1 = [v for v in analyze([record])["verdicts"] if v["check"] == "check1"]
    assert b1 == [] and c1[0]["verdict"] == "ALERT"
    (row,) = compare_with_check1(b1, c1)
    assert row["category"] == "check1_only"


def test_comparison_categories_on_fixtures():
    def categories(prefix):
        case, records = load_case(next(c for c in case_dirs() if c.name.startswith(prefix)))
        c1 = [v for v in analyze(records, case["config"])["verdicts"] if v["check"] == "check1"]
        return [r["category"] for r in compare_with_check1(b1_backdoor_keys(records), c1)]
    assert categories("c01") == ["both_alert"]
    assert categories("c03") == ["both_silent"]
    assert categories("c04") == ["b1_only"]  # approved role
    assert categories("c10") == ["b1_only"]  # failed call
    assert categories("c02") == ["both_silent"]

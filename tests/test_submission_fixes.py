"""Regression cases discovered in the submission review, independent of generator templates."""
import copy
import json
import tomllib
from pathlib import Path

import pytest
from helpers import FIXTURES
from scenario import ACC, NEWKEY, baseline, create_key, grant, use

from cloudtrace import __version__, cli, engine, report, tuning
from cloudtrace.evaluation import public

KNOWN, CREATOR, NEW = "198.51.100.25", "203.0.113.10", "192.0.2.50"
OTHER_ACCOUNT = "1" * 12


def records():
    return baseline("svc-b", KNOWN) + [create_key(10, 30, "admin-a", "svc-b", CREATOR),
                                      use(11, 40, "svc-b", NEW)]


def rows(data, check):
    return [r for r in engine.analyze(data)["verdicts"] if r["check"] == check]


def change_scope(event, account=OTHER_ACCOUNT, partition="aws"):
    ident = event["userIdentity"]
    ident["arn"] = ident["arn"].replace(f":{ACC}:", f":{account}:")
    ident["arn"] = ident["arn"].replace("arn:aws:", f"arn:{partition}:")
    ident["accountId"] = account
    event["recipientAccountId"] = account


def test_other_account_history_cannot_supply_a_baseline():
    data = records()
    for e in data[:3]:
        change_scope(e)
    assert rows(data, "check2")[0]["reason"] == "BASELINE_TOO_SMALL"


def test_other_account_known_address_cannot_suppress_an_alert():
    data = records()
    other = use(20, 25, "svc-b", NEW)
    change_scope(other)
    assert rows(data + [other], "check2")[0]["reason"] == "KEY_USED_FROM_NEW_SOURCE"


def test_other_partition_history_cannot_supply_a_baseline():
    data = records()
    for e in data[:3]:
        change_scope(e, ACC, "aws-us-gov")
    assert rows(data, "check2")[0]["reason"] == "BASELINE_TOO_SMALL"


def test_conflicting_caller_account_is_not_trusted_as_owner_history():
    data = records()
    for e in data[:3]:
        e["userIdentity"]["accountId"] = OTHER_ACCOUNT
    assert rows(data, "check2")[0]["reason"] == "BASELINE_TOO_SMALL"


def test_approved_full_role_arn_does_not_trust_the_same_name_in_another_account():
    data = records()[-2]
    role_arn = f"arn:aws:iam::{ACC}:role/ci-deploy"
    ident = {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACC}:assumed-role/ci-deploy/s",
             "sessionContext": {"sessionIssuer": {"userName": "ci-deploy", "arn": role_arn}}}
    data["userIdentity"] = ident
    cfg = {"allowed_roles": [role_arn]}
    assert engine.analyze([data], cfg)["verdicts"][0]["reason"] == "ALLOW_LISTED_ROLE"
    change_scope(data)
    ident["sessionContext"]["sessionIssuer"]["arn"] = role_arn.replace(ACC, OTHER_ACCOUNT)
    assert engine.analyze([data], cfg)["verdicts"][0]["reason"] == "KEY_FOR_OTHER_ACCOUNT"


def test_other_account_grant_cannot_raise_a_medium_finding():
    g = grant(1, 0, "admin-a", "svc-b", CREATOR)
    change_scope(g)
    assert rows([g, create_key(2, 20, "admin-a", "svc-b", CREATOR)], "check3") == []


def test_creation_signed_by_a_new_key_is_also_a_use_of_that_key():
    data = records()[:-1]
    chained = create_key(11, 40, "svc-b", "svc-c", NEW, key="AKIAEXAMPLECHAIN01")
    chained["userIdentity"]["accessKeyId"] = NEWKEY
    result = engine.analyze(data + [chained])
    key = next(k for k in result["key_history"] if k["key_id"] == NEWKEY)
    assert [u["event_id"] for u in key["uses"]] == [chained["eventID"]]
    assert rows(data + [chained], "check2")[0]["score"] == 5


def test_wrong_account_cannot_supply_use_of_a_key():
    data = records()
    change_scope(data[-1])
    assert rows(data, "check2") == []
    assert engine.analyze(data)["key_history"][0]["uses"] == []


def test_unknown_creator_cannot_earn_cross_identity_points():
    data = records()
    data[-2]["userIdentity"] = {}
    result = engine.analyze(data)
    assert [(r["verdict"], r["reason"]) for r in result["verdicts"]] == [
        ("NOT_CHECKED", "CALLER_UNKNOWN")]
    assert all("score" not in r for r in result["verdicts"])


def test_conflicting_request_and_response_targets_are_not_guessed():
    data = records()
    data[-2]["responseElements"]["accessKey"]["userName"] = "another-user"
    assert rows(data, "check1")[0]["reason"] == "TARGET_UNKNOWN"


def test_missing_created_key_id_has_an_explicit_lineage_break():
    data = records()
    del data[-2]["responseElements"]["accessKey"]["accessKeyId"]
    assert rows(data, "check2")[0]["reason"] == "CREATED_KEY_ID_MISSING"
    assert report.build(data)["summary"]["lineage_break_decisions"] == 1


@pytest.mark.parametrize("field,value", [
    ("sourceIPAddress", {}), ("sourceIPAddress", ["bad"]), ("sourceIPAddress", 42),
    ("userAgent", {}), ("userAgent", 42),
])
def test_wrong_optional_types_are_counted_without_crashing(field, value):
    data = records()
    data[-1][field] = value
    before = copy.deepcopy(data)
    result = engine.analyze(data)
    assert result["quality"]["invalid_fields"][field] == 1
    assert data == before
    if field == "sourceIPAddress":
        assert rows(data, "check2")[0]["reason"] == "MISSING_SOURCE_IP"


def test_wrong_key_id_type_cannot_crash_lineage():
    data = records()
    data[-1]["userIdentity"]["accessKeyId"] = {}
    assert rows(data, "check2")[0]["reason"] == "MISSING_KEY_ID"


def test_wrong_error_code_type_is_unusable_not_successful():
    data = records()
    data[-2]["errorCode"] = {"unexpected": "value"}
    result = engine.analyze(data)
    assert result["quality"]["unusable"][0]["reason"] == "INVALID_ERROR_CODE"
    assert result["verdicts"] == []


@pytest.mark.parametrize("request_value", [[], {"userName": []}])
def test_invalid_target_data_cannot_become_an_implicit_self_key(request_value):
    data = records()
    data[-2]["requestParameters"] = request_value
    assert rows(data, "check1")[0]["reason"] == "TARGET_UNKNOWN"


def test_equal_timestamp_events_do_not_supply_earlier_history():
    data = records()
    for e in data[:3]:
        e["eventTime"] = data[-2]["eventTime"]
    assert rows(data, "check2")[0]["reason"] == "BASELINE_TOO_SMALL"


def test_public_evaluation_credits_a_use_event_finding(tmp_path):
    path = tmp_path / "events.json"
    path.write_text(json.dumps(records()), encoding="utf-8")
    result = public.run_t3(path, {"svc-b": "test technique"})
    assert result["detectors"]["ct"]["caught"] == 1


def test_public_evaluation_credits_b3_use_event_and_counts_story_once(tmp_path):
    data = baseline("svc-b", KNOWN) + [create_key(10, 30, "svc-b", "svc-b", KNOWN),
                                      use(11, 40, "svc-b", NEW), use(12, 45, "svc-b", NEW)]
    path = tmp_path / "events.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    result = public.run_t3(path, {"svc-b": "test technique"})
    assert result["detectors"]["b3"]["caught"] == 1
    assert result["detectors"]["ct"]["caught"] == 0


def test_public_evaluation_deduplicates_and_excludes_unusable_creations(tmp_path):
    data = records()
    invalid = copy.deepcopy(data[-2])
    del invalid["eventID"]
    path = tmp_path / "events.json"
    path.write_text(json.dumps(data + [data[-2], invalid]), encoding="utf-8")
    result = public.run_t3(path, {"svc-b": "test technique"})
    assert result["labelled_attacks"] == result["key_creations"] == 1
    assert result["duplicates_removed"] == 1
    assert result["detectors"]["ct"]["caught"] == 1


def test_input_usability_is_separate_from_rule_evaluability():
    path = next(FIXTURES.glob("c11*/events.json"))
    data = json.loads(path.read_text())["Records"]
    result = report.build(data)
    s = result["summary"]
    assert s["input_usability_percent"] == 100
    assert s["rule_evaluability_percent"] == 50
    assert s["lineage_break_decisions"] == 1
    assert "Evidence incomplete" in report.to_markdown(result)


def test_no_candidates_does_not_imply_complete_evaluation():
    summary = report.build([])["summary"]
    assert summary["rule_evaluability_percent"] is None
    assert summary["key_creation_resolution_percent"] is None


def test_package_and_runtime_versions_agree():
    root = Path(__file__).resolve().parent.parent
    project = tomllib.loads((root / "pyproject.toml").read_text())
    assert project["project"]["version"] == __version__


def test_tune_late_key_reports_window_effect_without_labels():
    data = records()
    data[-1] = use(11, 210, "svc-b", NEW)
    result = tuning.analyze(data)
    assert result["first_use_minutes"]["median"] == 180
    assert result["windows"][60]["medium_plus_findings"] == 0
    assert result["windows"][240]["medium_plus_findings"] == 1
    text = tuning.render(result)
    assert "not attack labels" in text
    for value in ["svc-b", "admin-a", NEWKEY, KNOWN, NEW, CREATOR]:
        assert value not in text


def test_tune_preserves_supplied_settings_and_is_repeatable():
    data = records()
    cfg = {"window_minutes": 75, "baseline_min_events": 4}
    a, b = tuning.analyze(data, cfg), tuning.analyze(data, cfg)
    assert a == b
    assert 75 in a["windows"] and 4 in a["histories"]
    assert a["windows"][75]["not_checked_decisions"] == 1
    assert a["histories"][3]["medium_plus_findings"] == 1


def test_tune_no_use_and_empty_input():
    assert tuning.analyze([])["first_use_minutes"] is None
    assert tuning.analyze(records()[:-1])["keys_without_observed_use"] == 1


def test_tune_cli_stdout_file_and_bad_input(tmp_path, capsys):
    path = tmp_path / "input.json"
    path.write_text(json.dumps(records()), encoding="utf-8")
    assert cli.main(["tune", str(path)]) == 0
    text = capsys.readouterr().out
    out = tmp_path / "sub" / "guide.md"
    assert cli.main(["tune", str(path), "--out", str(out)]) == 0
    assert out.read_text() == text
    assert cli.main(["tune", str(tmp_path / "missing")]) == 2


def test_tune_cli_invalid_config_has_a_plain_error(tmp_path, capsys):
    config = tmp_path / "invalid.toml"
    config.write_text('window_minutes = "bad"', encoding="utf-8")
    path = next(FIXTURES.glob("c07*/events.json"))
    assert cli.main(["tune", str(path), "--config", str(config)]) == 2
    error = capsys.readouterr().err
    assert "window_minutes" in error and "Traceback" not in error


def test_committed_tune_example_matches_the_command(capsys):
    root = Path(__file__).resolve().parent.parent
    path = next(FIXTURES.glob("c07*/events.json"))
    assert cli.main(["tune", str(path)]) == 0
    assert capsys.readouterr().out == (root / "results/tune/c07_tune.md").read_text()

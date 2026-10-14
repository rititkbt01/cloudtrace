"""Tests for the generator, the attacker-change tests, B2/B3 and the scoring."""
import copy
import ipaddress
import json
import random
import re

import pytest
from helpers import FIXTURES

from cloudtrace import baselines, cli, scoring
from cloudtrace.evaluation import detectors, generator, metrics, mutations, run, scenarios

DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
RESULTS = FIXTURES.parent.parent / "results" / "eval"


# ---- generator --------------------------------------------------------------------------------
def test_same_seed_gives_same_log_and_different_seed_differs():
    a, _ = generator.generate(7)
    b, _ = generator.generate(7)
    c, _ = generator.generate(8)
    assert a == b and a != c


def test_scale_and_labels_follow_the_counts():
    records, scs = generator.generate(1)
    counts = generator.DEFAULT_COUNTS
    assert len(scs) == sum(counts.values())
    assert sum(s.attack for s in scs) == sum(n for k, n in counts.items() if k.startswith("attack"))
    assert sum(s.attack for s in scs) >= 20
    attack_ids = {e for s in scs if s.attack for e in s.event_ids}
    assert len(records) - len(attack_ids) >= 100  # normal events


def test_event_ids_are_unique_and_scenario_events_exist():
    records, scs = generator.generate(2)
    ids = [r["eventID"] for r in records]
    assert len(ids) == len(set(ids))
    for s in scs:
        assert s.event_ids and set(s.event_ids) <= set(ids)


def test_log_is_in_time_order():
    records, _ = generator.generate(3)
    times = [r["eventTime"] for r in records]
    assert times == sorted(times)


@pytest.mark.parametrize("seed", [1, 2])
def test_generated_data_is_synthetic(seed):
    records, _ = generator.generate(seed)
    text = json.dumps(records)
    for r in records:
        assert r["recipientAccountId"] == "123456789012"
        if r.get("sourceIPAddress"):
            assert any(ipaddress.ip_address(r["sourceIPAddress"]) in n for n in DOC_NETS)
    for m in re.findall(r"\b(?:AKIA|ASIA)[A-Z0-9]+", text):
        assert "EXAMPLE" in m
    assert "@" not in text


def test_every_kind_can_be_built():
    for kind in scenarios.ALL_KINDS:
        log = scenarios.Log("x")
        rng = random.Random(1)
        s = scenarios.build(kind, log, rng, scenarios.Allocator(rng), scenarios.BASE_TIME)
        assert s.event_ids and s.attack == kind.startswith("attack")


# ---- mutations --------------------------------------------------------------------------------
def build(kind, m, seed=1):
    rng = random.Random(seed)
    log = scenarios.Log("x")
    s = scenarios.build(kind, log, rng, scenarios.Allocator(rng), scenarios.BASE_TIME,
                        mutations.build_opts(rng, m))
    return log.records, s


def test_predictions_cover_exactly_the_applicable_cells():
    assert set(mutations.PREDICTIONS) == {(m, k) for m, ks in mutations.APPLIES.items()
                                          for k in ks}


def test_m1_owner_name_sits_inside_creator_name():
    records, _ = build("attack_cross_new_ip", "M1")
    c = next(r for r in records if r["eventName"] == "CreateAccessKey")
    target = c["requestParameters"]["userName"]
    assert target in c["userIdentity"]["arn"] and target != c["userIdentity"]["userName"]


def test_m6_removes_source_fields_from_the_first_use_only():
    records, s = build("attack_cross_new_ip", "M6")
    first_use = next(r for r in records if r["eventID"] == s.event_ids[1])
    assert "sourceIPAddress" not in first_use and "userAgent" not in first_use


def test_m9_creates_the_key_through_the_approved_role():
    records, _ = build("attack_cross_new_ip", "M9")
    c = next(r for r in records if r["eventName"] == "CreateAccessKey")
    assert c["userIdentity"]["type"] == "AssumedRole"
    assert c["userIdentity"]["sessionContext"]["sessionIssuer"]["userName"] == scenarios.APPROVED_ROLE


def test_m4_m5_do_not_change_the_input_and_do_what_they_say():
    records, _ = build("attack_cross_new_ip", "M0")
    before = copy.deepcopy(records)
    dup = mutations.post_process(records, "M5", random.Random(1))
    shuf = mutations.post_process(records, "M4", random.Random(1))
    assert records == before
    assert len(dup) == 2 * len(records) and len(shuf) == len(records)
    assert [r["eventID"] for r in shuf] != [r["eventID"] for r in records]


def test_all_attacker_change_results_match_the_predictions_written_first():
    cells = run.run_t4(variants=4)
    wrong = [(k, d) for k, c in cells.items() for d, ok in c["matches_prediction"].items() if not ok]
    assert wrong == []


# ---- B2 / B3 ----------------------------------------------------------------------------------
def create(caller, target, ua="aws-cli/2.15", error=None, key="AKIAEXAMPLENEWKEY01", minutes=0,
           ident_type="IAMUser", eid="e-1"):
    ident = {"type": ident_type, "arn": f"arn:aws:iam::123456789012:user/{caller}",
             "userName": caller, "accessKeyId": "AKIAEXAMPLEADMINA01"}
    r = {"eventID": eid, "eventTime": f"2026-01-01T10:{minutes:02d}:00Z",
         "eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey", "userAgent": ua,
         "userIdentity": ident, "recipientAccountId": "123456789012",
         "requestParameters": {"userName": target} if target else None,
         "responseElements": None if error else {"accessKey": {"accessKeyId": key,
                                                               "userName": target or caller}}}
    if error:
        r["errorCode"] = error
    return r


def test_b2_flags_different_names_and_is_case_sensitive():
    assert len(baselines.b2_cross_user([create("admin-a", "svc-b")])) == 1
    assert len(baselines.b2_cross_user([create("Alice", "alice")])) == 1  # exact comparison
    assert baselines.b2_cross_user([create("alice", "alice")]) == []


def test_b2_skips_failed_calls_implicit_targets_and_automation_tools():
    assert baselines.b2_cross_user([create("a", "b", error="AccessDenied")]) == []
    assert baselines.b2_cross_user([create("a", None)]) == []
    for ua in ("Terraform/1.7", "pulumi-cli", "Ansible-core 2.16"):
        assert baselines.b2_cross_user([create("a", "b", ua=ua)]) == []


def use(minutes, key="AKIAEXAMPLENEWKEY01", who="alice", eid="u-1"):
    return {"eventID": eid, "eventTime": f"2026-01-01T{10 + minutes // 60:02d}:{minutes % 60:02d}:00Z",
            "eventSource": "sts.amazonaws.com", "eventName": "GetCallerIdentity",
            "recipientAccountId": "123456789012",
            "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::123456789012:user/{who}",
                             "userName": who, "accessKeyId": key}}


def test_b3_needs_self_made_key_used_within_one_hour():
    mk = create("alice", "alice")
    assert len(baselines.b3_self_key_used([mk, use(30)])) == 1
    assert len(baselines.b3_self_key_used([mk, use(60)])) == 1  # exactly one hour
    assert baselines.b3_self_key_used([mk, use(61)]) == []
    assert baselines.b3_self_key_used([mk]) == []
    assert baselines.b3_self_key_used([create("alice", None), use(5)])  # name left out = self
    assert baselines.b3_self_key_used([create("admin", "alice"), use(5)]) == []  # made by other
    assert baselines.b3_self_key_used([create("alice", "alice", error="AccessDenied"), use(5)]) == []


def test_b3_ignores_log_order():
    mk = create("alice", "alice")
    assert len(baselines.b3_self_key_used([use(30), mk])) == 1


# ---- scoring, detectors and results -------------------------------------------------------------
def test_scoring_weights_are_frozen():
    """Weights were fixed before any public log is scored. Changing them is a deliberate act."""
    assert scoring.WEIGHTS == {"cross_identity": 1, "first_use_in_window": 2, "new_source": 2,
                               "creator_source": 3, "elevated_grant": 3}
    assert scoring.BANDS == ((5, "high"), (3, "medium"), (1, "low"))


def test_pool_adds_counts_and_keeps_ranges():
    parts = []
    for seed in (1, 2):
        records, scs = generator.generate(seed)
        parts.append(metrics.score_t2(records, scs, detectors.run_all(records)))
    pooled = metrics.pool(parts)
    assert pooled["ct"]["n_in_scope"] == 2 * parts[0]["ct"]["n_in_scope"]
    assert pooled["ct"]["recall_in_scope_range"][0] <= pooled["ct"]["recall_in_scope"] <= \
        pooled["ct"]["recall_in_scope_range"][1]


def test_committed_results_are_up_to_date():
    t2, t4 = run.run_t2(), run.run_t4()
    assert (RESULTS / "RESULTS.md").read_text(encoding="utf-8") == run.render(t2, t4)
    assert json.loads((RESULTS / "results.json").read_text(encoding="utf-8")) == json.loads(
        json.dumps({"t2": t2, "t4": t4}))


def test_cli_evaluate_writes_files(tmp_path, capsys):
    assert cli.main(["evaluate", "--out", str(tmp_path), "--seeds", "1", "--variants", "1"]) == 0
    assert (tmp_path / "RESULTS.md").read_text(encoding="utf-8").startswith("# CloudTrace")
    assert "results.json" in capsys.readouterr().out

"""Stage 11: the false-alarm cost of Check 2 version 2 is measured, and the measurement can be trusted."""
import random
from pathlib import Path

from cloudtrace import engine
from cloudtrace.evaluation import check2_cost as cost
from cloudtrace.evaluation import detectors, generator, run
from cloudtrace.evaluation import scenarios as sc

RESULT = Path(__file__).resolve().parent.parent / "results" / "eval" / "CHECK2_COST.md"
WRITTEN_BEFORE_THE_RUN = {  # kind: (version 1 flags, version 2 flags) out of 40
    "attack_new_first": (40, 40),
    "attack_known_then_new": (0, 40),
    "benign_one_known_address": (0, 0),
    "benign_two_known_addresses": (0, 0),
    "benign_known_then_new_address": (0, 40),
}


def test_committed_result_is_up_to_date():
    assert RESULT.read_text(encoding="utf-8") == cost.render(cost.run_cost())


def test_each_story_kind_behaves_as_predicted():
    d = cost.run_stories()
    for kind, (v1, v2) in WRITTEN_BEFORE_THE_RUN.items():
        assert (d[kind]["n"], d[kind]["v1"], d[kind]["v2"]) == (40, v1, v2), kind


def test_version_2_never_flags_fewer_stories_than_version_1():
    for seed in (1, 2):
        for kind in cost.KINDS:
            records, stories = cost._extra_stories(seed, kind, 8, 0)
            records = sorted(records, key=lambda r: r["eventTime"])
            _, one = cost._flags(records, stories, 1)
            _, two = cost._flags(records, stories, 2)
            assert all(b or not a for (a, _), (b, _) in zip(one, two, strict=True)), kind


def test_frozen_version_1_reproduces_the_first_run_result():
    """Only attacker-change test M7 differed in the first run, and only on the two cross stories."""
    two = run.run_t4(5)
    with cost.using_check2_v1():
        one = run.run_t4(5)
    differ = sorted(k for k in one if one[k]["caught"] != two[k]["caught"])
    assert differ == ["M7|attack_cross_creator_ip", "M7|attack_cross_new_ip"]
    assert all(one[k]["caught"]["ct"] == 0 for k in differ)


def test_both_versions_agree_on_the_main_generated_mix():
    records, _ = generator.generate(1)
    two = detectors.run_all(records)["ct"]["events"]
    with cost.using_check2_v1():
        one = detectors.run_all(records)["ct"]["events"]
    assert one == two


def test_mix_with_no_extra_stories_matches_the_main_results():
    row = cost.run_mix(extra_per_seed=(0,))[0]
    t2 = run.run_t2()["ct"]
    assert row["v2"]["normal_flagged"] == t2["fp_scenarios"] == row["v1"]["normal_flagged"]
    assert row["v2"]["false_alarms_per_1000"] == t2["false_alarms_per_1000_normal_events"]


def test_each_extra_story_adds_exactly_one_false_alarm_in_version_2_only():
    base, plus = cost.run_mix(extra_per_seed=(0, 3))
    assert plus["extra"] == 15
    assert plus["v1"]["normal_flagged"] == base["v1"]["normal_flagged"]
    assert plus["v2"]["normal_flagged"] == base["v2"]["normal_flagged"] + 15


def test_the_second_new_address_is_a_high_finding():
    rng = random.Random("one")
    ips = sc.doc_ips()
    rng.shuffle(ips)
    log = sc.Log(prefix="t")
    cost._build("benign_known_then_new_address", log, rng, ips, sc.BASE_TIME, "9001")
    rows = engine.analyze(log.records)["verdicts"]
    alerts = [r for r in rows if r["verdict"] == "ALERT" and r["reason"] == "KEY_USED_FROM_NEW_SOURCE"]
    assert len(alerts) == 1 and alerts[0]["score"] == 5 and alerts[0]["severity"] == "high"


def test_switching_to_version_1_is_undone_afterwards():
    saved = engine.check2
    with cost.using_check2_v1():
        assert engine.check2 is cost.check2_v1
    assert engine.check2 is saved

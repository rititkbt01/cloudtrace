import json

import pytest
from helpers import case_dirs, load_case

from cloudtrace import report


def build(prefix, **kw):
    case, records = load_case(next(c for c in case_dirs() if c.name.startswith(prefix)))
    return report.build(records, case["config"], input_name="events.json", **kw)


def test_summary_counts_c01():
    s = build("c01")["summary"]
    assert s["records_read"] == 5 and s["usable_events"] == 5 and s["coverage_percent"] == 100.0
    assert s["alerts"] == {"high": 0, "medium": 0, "low": 1}
    assert s["candidate_events"] == 1


def test_summary_counts_ignored_and_not_checked():
    assert build("c02")["summary"]["ignored"] == 1
    assert build("c10")["summary"]["ignored"] == 1


def test_c09_report_shows_the_data_problems():
    r = build("c09")
    assert r["quality"]["duplicates_removed"] == 1 and r["quality"]["reordered"] is True
    md = report.to_markdown(r)
    assert "Duplicates removed: 1" in md and "out of time order: yes" in md


def test_json_round_trips_and_has_the_main_parts():
    data = json.loads(report.to_json(build("c01")))
    assert {"tool", "version", "input", "settings", "summary", "quality", "verdicts",
            "key_history", "baseline_b1"} <= set(data)


def test_baseline_can_be_left_out():
    assert "baseline_b1" not in build("c01", baseline=False)
    assert "single-event rule" not in report.to_markdown(build("c01", baseline=False))


def test_markdown_has_all_sections_and_careful_wording():
    md = report.to_markdown(build("c01"))
    for heading in ("## Summary", "## Findings to review", "## Decision record",
                    "## Log quality", "## Key history", "## Notes and limits"):
        assert heading in md
    assert "please review" in md.lower()
    assert "attack confirmed" in md  # only inside the sentence saying it is NOT claimed
    assert "- A finding means 'please review', not 'attack confirmed'" in md


def test_no_findings_message():
    md = report.to_markdown(build("c02"))
    assert "No findings." in md and "does not mean the account is safe" in md


def test_output_is_identical_every_time():
    assert report.to_markdown(build("c06")) == report.to_markdown(build("c06"))
    assert report.to_json(build("c06")) == report.to_json(build("c06"))


def test_pipe_characters_do_not_break_tables():
    assert report._cell("a|b") == "a\\|b"


@pytest.mark.parametrize("cdir", case_dirs(), ids=lambda c: c.name)
def test_every_case_makes_a_report(cdir):
    case, records = load_case(cdir)
    assert report.to_markdown(report.build(records, case["config"], cdir.name))


def test_highest_severity():
    assert report.highest_severity(build("c01")) == "low"
    assert report.highest_severity(build("c02")) is None

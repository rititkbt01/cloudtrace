import copy

import pytest
from helpers import case_dirs, load_case

from cloudtrace.ingest import load_records
from cloudtrace.quality import clean


def rec(n, time="2026-01-01T10:00:00Z", **over):
    r = {"eventID": f"t-{n}", "eventTime": time, "eventName": "ListBuckets",
         "eventSource": "s3.amazonaws.com", "sourceIPAddress": "192.0.2.1",
         "userAgent": "test",
         "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/a",
                          "accessKeyId": "AKIAEXAMPLEKEY00001"}}
    r.update(over)
    return r


@pytest.mark.parametrize("cdir", case_dirs(), ids=lambda c: c.name)
def test_fixture_quality_matches_expected(cdir):
    """C09 must report 1 duplicate and reordering; every other case must be clean."""
    case, records = load_case(cdir)
    events, report = clean(records)
    want = case["expected"].get("quality", {"duplicates_removed": 0, "reordered": False})
    assert report.duplicates_removed == want["duplicates_removed"]
    assert report.reordered == want["reordered"]
    assert report.conflicting_duplicates == 0
    assert report.unusable == []
    assert [e.time for e in events] == sorted(e.time for e in events)


def test_c09_cleans_to_same_events_as_c01():
    c01 = next(c for c in case_dirs() if c.name.startswith("c01"))
    c09 = next(c for c in case_dirs() if c.name.startswith("c09"))
    a, _ = clean(load_records(c01 / "events.json"))
    b, _ = clean(load_records(c09 / "events.json"))
    assert [e.name for e in a] == [e.name for e in b]
    assert [e.time for e in a] == [e.time for e in b]


def test_empty_access_key_becomes_none_and_is_counted():
    c11 = next(c for c in case_dirs() if c.name.startswith("c11"))
    events, report = clean(load_records(c11 / "events.json"))
    assert events[-1].access_key_id is None
    assert report.missing_fields["userIdentity.accessKeyId"] == 1


def test_unusable_records_are_listed_with_reasons():
    bad_time = rec(3, time="yesterday")
    no_id = rec(4)
    del no_id["eventID"]
    events, report = clean([rec(1), "oops", bad_time, no_id])
    assert len(events) == 1
    reasons = {u["index"]: u["reason"] for u in report.unusable}
    assert reasons == {1: "NOT_AN_OBJECT", 2: "BAD_EVENT_TIME", 3: "MISSING_EVENT_ID"}
    assert report.total_records == 4 and report.usable_events == 1


def test_conflicting_duplicate_is_flagged():
    a = rec(1)
    b = copy.deepcopy(a)
    b["eventName"] = "DeleteBucket"
    events, report = clean([a, b])
    assert len(events) == 1 and events[0].name == "ListBuckets"  # first copy kept
    assert report.duplicates_removed == 1 and report.conflicting_duplicates == 1


def test_time_zone_offsets_are_converted_to_utc():
    events, _ = clean([rec(1, time="2026-01-01T12:00:00+02:00")])
    assert events[0].time.isoformat() == "2026-01-01T10:00:00+00:00"


def test_equal_times_keep_file_order():
    events, report = clean([rec(2), rec(1)])
    assert [e.event_id for e in events] == ["t-2", "t-1"]
    assert report.reordered is False


def test_report_range_and_missing_fields():
    r = rec(2, time="2026-01-01T11:00:00Z")
    del r["userAgent"]
    _, report = clean([r, rec(1)])
    assert report.time_start == "2026-01-01T10:00:00Z"
    assert report.time_end == "2026-01-01T11:00:00Z"
    assert report.missing_fields == {"userAgent": 1}


def test_empty_input():
    events, report = clean([])
    assert events == [] and report.time_start is None and report.reordered is False


def test_input_records_are_not_modified():
    records = [rec(2, time="2026-01-01T11:00:00Z"), rec(1)]
    snapshot = copy.deepcopy(records)
    clean(records)
    assert records == snapshot

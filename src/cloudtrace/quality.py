"""Step 2: the log quality check.

Takes raw records and returns clean, time-sorted events plus a plain report that says
what was wrong with the input. Nothing is silently dropped: every removed or unusable
record is counted and explained.

What it does, in order:
  1. Rejects records that cannot be used at all (no event ID, time, name or source).
  2. Removes duplicates (same eventID); keeps the first copy.
  3. Sorts by time (stable, so equal times keep their file order).
  4. Counts important fields that are missing (they limit what the checks can do).
"""
from dataclasses import dataclass, field
from datetime import UTC, datetime
from itertools import pairwise

REQUIRED = ("eventID", "eventTime", "eventName", "eventSource")
# Fields the checks rely on. Missing ones are counted, not treated as errors.
WATCHED = ("userIdentity.arn", "userIdentity.accessKeyId", "sourceIPAddress", "userAgent")


@dataclass
class Event:
    event_id: str
    time: datetime  # always timezone-aware UTC
    source: str  # e.g. "iam.amazonaws.com"
    name: str  # e.g. "CreateAccessKey"
    identity_type: str | None  # e.g. "IAMUser", "AssumedRole"
    identity_arn: str | None
    access_key_id: str | None  # empty string is turned into None
    source_ip: str | None
    user_agent: str | None
    error_code: str | None
    request: dict
    response: dict
    raw: dict = field(repr=False, default_factory=dict)


@dataclass
class QualityReport:
    total_records: int = 0
    usable_events: int = 0
    duplicates_removed: int = 0
    conflicting_duplicates: int = 0  # same ID but different content: a data problem
    reordered: bool = False
    unusable: list = field(default_factory=list)  # {"index", "event_id", "reason"}
    missing_fields: dict = field(default_factory=dict)  # field name -> count
    time_start: str | None = None
    time_end: str | None = None

    def as_dict(self) -> dict:
        return {
            "total_records": self.total_records,
            "usable_events": self.usable_events,
            "duplicates_removed": self.duplicates_removed,
            "conflicting_duplicates": self.conflicting_duplicates,
            "reordered": self.reordered,
            "unusable": list(self.unusable),
            "missing_fields": dict(self.missing_fields),
            "time_start": self.time_start,
            "time_end": self.time_end,
        }


def _parse_time(text) -> datetime | None:
    if not isinstance(text, str):
        return None
    try:
        t = datetime.fromisoformat(text)
    except ValueError:
        return None
    if t.tzinfo is None:  # CloudTrail always uses UTC ("Z"); assume UTC if no zone given
        t = t.replace(tzinfo=UTC)
    return t.astimezone(UTC)


def _dig(record: dict, dotted: str):
    cur = record
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _to_event(record: dict, time: datetime) -> Event:
    ident = record.get("userIdentity")
    ident = ident if isinstance(ident, dict) else {}
    request = record.get("requestParameters")
    response = record.get("responseElements")
    return Event(
        event_id=record["eventID"],
        time=time,
        source=record["eventSource"],
        name=record["eventName"],
        identity_type=ident.get("type") or None,
        identity_arn=ident.get("arn") or None,
        access_key_id=ident.get("accessKeyId") or None,
        source_ip=record.get("sourceIPAddress") or None,
        user_agent=record.get("userAgent") or None,
        error_code=record.get("errorCode") or None,
        request=request if isinstance(request, dict) else {},
        response=response if isinstance(response, dict) else {},
        raw=record,
    )


def _unusable_reason(record, index):
    """Return a reason code if the record cannot be used, otherwise (None, time)."""
    if not isinstance(record, dict):
        return "NOT_AN_OBJECT", None
    for name, code in (("eventID", "MISSING_EVENT_ID"), ("eventTime", "MISSING_EVENT_TIME"),
                       ("eventName", "MISSING_EVENT_NAME"), ("eventSource", "MISSING_EVENT_SOURCE")):
        if not record.get(name) or not isinstance(record.get(name), str):
            return code, None
    t = _parse_time(record["eventTime"])
    if t is None:
        return "BAD_EVENT_TIME", None
    return None, t


def clean(records: list) -> tuple[list[Event], QualityReport]:
    """Run the quality check. Returns (events sorted by time, report)."""
    report = QualityReport(total_records=len(records))
    seen: dict[str, dict] = {}
    kept: list[Event] = []

    for index, record in enumerate(records):
        reason, time = _unusable_reason(record, index)
        if reason:
            event_id = record.get("eventID") if isinstance(record, dict) else None
            report.unusable.append({"index": index, "event_id": event_id, "reason": reason})
            continue
        if record["eventID"] in seen:
            report.duplicates_removed += 1
            if record != seen[record["eventID"]]:
                report.conflicting_duplicates += 1
            continue
        seen[record["eventID"]] = record
        kept.append(_to_event(record, time))
        for name in WATCHED:
            value = _dig(record, name)
            if value is None or value == "":
                report.missing_fields[name] = report.missing_fields.get(name, 0) + 1

    times = [e.time for e in kept]
    report.reordered = any(a > b for a, b in pairwise(times))
    kept.sort(key=lambda e: e.time)  # stable sort
    report.usable_events = len(kept)
    if kept:
        report.time_start = kept[0].time.isoformat().replace("+00:00", "Z")
        report.time_end = kept[-1].time.isoformat().replace("+00:00", "Z")
    return kept, report

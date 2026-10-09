"""Baselines: existing single-event detection logic, re-implemented so we can compare.

B1 re-implements the public SigmaHQ rule "AWS IAM Backdoor Users Keys"
(id 0a5177f4-6ca9-44c2-aacf-d3f3d8b6e4d2, author faloker, level medium). As published, it says:

    selection: eventSource = iam.amazonaws.com AND eventName = CreateAccessKey
    filter:    userIdentity.arn contains responseElements.accessKey.userName
    condition: selection and not filter

i.e. alert on every key creation unless the caller's ARN contains the name of the user the key
was made for. This is a plain re-implementation for comparison, not the Sigma engine itself.

Choices we had to make (and state openly):
  * Sigma text matching is case-insensitive, so we compare case-insensitively.
  * If the response has no user name (for example a failed call), the filter cannot match,
    so the event alerts.
  * The baseline reads the RAW records exactly as given: no sorting, no duplicate removal,
    no failed-call handling. That is how a single-event rule behaves on a raw log.
"""

B1_NAME = "B1 (SigmaHQ: AWS IAM Backdoor Users Keys)"


def _get(d, *path):
    for p in path:
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


def b1_backdoor_keys(records: list) -> list[dict]:
    """Return one row for every raw record the rule would alert on."""
    rows = []
    for r in records:
        if not isinstance(r, dict):
            continue
        if r.get("eventSource") != "iam.amazonaws.com" or r.get("eventName") != "CreateAccessKey":
            continue
        arn = _get(r, "userIdentity", "arn")
        target = _get(r, "responseElements", "accessKey", "userName")
        filtered = (isinstance(arn, str) and isinstance(target, str) and target != ""
                    and target.casefold() in arn.casefold())
        if not filtered:
            rows.append({"rule": "B1", "event_id": r.get("eventID"),
                         "time": r.get("eventTime"), "caller": arn, "target_user": target})
    return rows


def compare_with_check1(b1_rows: list[dict], check1_rows: list[dict]) -> list[dict]:
    """Line up B1 and Check 1 event by event and say where they disagree, and why."""
    b1_count: dict = {}
    for row in b1_rows:
        key = row["event_id"] or "(no event id)"
        b1_count[key] = b1_count.get(key, 0) + 1
    c1 = {row["event_id"]: row for row in check1_rows}
    out = []
    for event_id in sorted(set(c1) | set(b1_count)):
        row = c1.get(event_id)
        b1_flag = b1_count.get(event_id, 0) > 0
        c1_flag = bool(row and row["verdict"] == "ALERT")
        verdict = row["verdict"] if row else "NOT_EVALUATED"
        reason = row["reason"] if row else "NOT_USABLE_RECORD"
        if b1_flag and c1_flag:
            category, note = "both_alert", "Both flag this event."
        elif not b1_flag and not c1_flag:
            category, note = "both_silent", "Neither flags this event."
        elif b1_flag:
            category = "b1_only"
            note = f"B1 alerts; Check 1 says {verdict} / {reason}."
        else:
            category = "check1_only"
            note = ("Check 1 alerts; B1's name filter hid it (the target's name appears "
                    "inside the caller's ARN).")
        out.append({"event_id": event_id, "b1_alerts": b1_count.get(event_id, 0),
                    "check1_verdict": verdict, "check1_reason": reason,
                    "category": category, "note": note})
    return out

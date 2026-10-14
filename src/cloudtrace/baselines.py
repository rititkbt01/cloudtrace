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


# ---------------------------------------------------------------------------------------------
# B2 and B3: Elastic prebuilt detection rules, as read on 13 Oct 2026.
#   B2: the "current" documentation page, rule version 16 (severity High, risk 73).
#   B3: documentation page for 8.19.29.
# Only the rule LOGIC is re-implemented. Scheduling details (runs every 5 minutes, 6- or
# 35-minute look-back, 100-alert cap) are properties of running the rule live and are ignored
# when replaying a whole log file at once. That is stated in docs/EVALUATION.md.
# ---------------------------------------------------------------------------------------------

B2_NAME = "B2 (Elastic: AWS IAM User Created Access Keys For Another User)"
B2_IGNORED_TOOLS = ("terraform", "pulumi", "ansible")  # user-agent texts the rule excludes
B3_NAME = "B3 (Elastic: AWS IAM User Self-Created Access Key Subsequently Used)"
USE_WINDOW_SECONDS = 3600  # seconds: B3 requires first use within one hour of creation


def _caller_name(r: dict) -> str | None:
    """The caller name the way Elastic's `user.name` would be: user name, else the ARN's last part."""
    ident = r.get("userIdentity")
    name = _get(ident, "userName")
    if isinstance(name, str) and name:
        return name
    arn = _get(ident, "arn")
    if isinstance(arn, str) and arn:
        return arn.rsplit("/", 1)[-1]
    return None


def b2_cross_user(records: list, exclude_roles: tuple = ()) -> list[dict]:
    """B2: successful CreateAccessKey where caller name != target user name (exact comparison).

    As published (version 16) the rule skips events whose user agent, lower-cased, contains
    terraform, pulumi or ansible. It has no list of approved roles; `exclude_roles` exists only
    for the fair-comparison variant "B2 with the same approved roles excluded". If the request
    names no user, the target is empty and the comparison cannot be true, so it is not flagged.
    """
    rows = []
    for r in records:
        if not isinstance(r, dict):
            continue
        if r.get("eventSource") != "iam.amazonaws.com" or r.get("eventName") != "CreateAccessKey":
            continue
        if r.get("errorCode"):
            continue
        target = _get(r, "requestParameters", "userName")
        caller = _caller_name(r)
        if not isinstance(target, str) or not target or caller is None:
            continue
        agent = r.get("userAgent")
        if isinstance(agent, str) and any(t in agent.lower() for t in B2_IGNORED_TOOLS):
            continue
        if caller != target:
            role = _get(r, "userIdentity", "sessionContext", "sessionIssuer", "userName")
            if role in exclude_roles:
                continue
            rows.append({"rule": "B2", "event_id": r.get("eventID"), "time": r.get("eventTime"),
                         "caller": caller, "target_user": target})
    return rows


def _time(r: dict):
    from datetime import datetime
    try:
        return datetime.fromisoformat(r["eventTime"])
    except (KeyError, TypeError, ValueError):
        return None


def b3_self_key_used(records: list) -> list[dict]:
    """B3: an IAM user creates a key for themselves, then that key is used within one hour.

    Creation: successful CreateAccessKey by an IAMUser, request names no user or the caller
    itself, response key ID starts with AKIA. Use: any other event by an IAMUser signed with that
    key (CreateAccessKey calls excluded). Grouped by (account, user ARN, key ID); alerts when the
    earliest use is after the earliest creation and at most 3,600 seconds later. No address or
    user-agent condition. Raw records are read as given.
    """
    created: dict = {}
    used: dict = {}
    for r in records:
        if not isinstance(r, dict) or _time(r) is None:
            continue
        ident = r.get("userIdentity") if isinstance(r.get("userIdentity"), dict) else {}
        if ident.get("type") != "IAMUser":
            continue
        acct = r.get("recipientAccountId") or ident.get("accountId")
        arn = ident.get("arn")
        is_create = (r.get("eventSource") == "iam.amazonaws.com"
                     and r.get("eventName") == "CreateAccessKey")
        if is_create:
            if r.get("errorCode"):
                continue
            target = _get(r, "requestParameters", "userName")
            new_key = _get(r, "responseElements", "accessKey", "accessKeyId")
            self_made = (target is None) or (target == _caller_name(r))
            if self_made and isinstance(new_key, str) and new_key.startswith("AKIA"):
                created.setdefault((acct, arn, new_key), []).append(r)
        else:
            key = ident.get("accessKeyId")
            if isinstance(key, str) and key.startswith("AKIA"):
                used.setdefault((acct, arn, key), []).append(r)
    rows = []
    for group, creations in created.items():
        uses = used.get(group)
        if not uses:
            continue
        first_creation = min(creations, key=_time)
        first_use = min(uses, key=_time)
        gap = (_time(first_use) - _time(first_creation)).total_seconds()
        if 0 < gap <= USE_WINDOW_SECONDS:
            rows.append({"rule": "B3", "event_id": first_use.get("eventID"),
                         "creation_event_id": first_creation.get("eventID"),
                         "time": first_use.get("eventTime"), "caller": group[1],
                         "key_id": group[2], "seconds_to_first_use": gap})
    return rows

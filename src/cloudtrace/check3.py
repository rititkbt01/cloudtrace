"""Check 3: strong rights granted to an identity, then a key created for it by someone else.

Looks at every key creation that Check 1 flagged. If, within the window (default 60 minutes)
BEFORE that key was created, a strong policy (setting `elevated_policies`) was successfully
attached to the same identity, the key creation gets a medium-or-higher finding.
If several grants match, the most recent one is reported.

Only attachment of a named policy (AttachUserPolicy) is looked at; inline policies are not.
"""
from datetime import timedelta

from cloudtrace import lineage
from cloudtrace.quality import Event
from cloudtrace.rows import iso, make_row

CHECK = "check3"


def run(events: list[Event], config: dict, check1_rows: list[dict]) -> list[dict]:
    window = timedelta(minutes=config["window_minutes"])
    by_id = {e.event_id: i for i, e in enumerate(events)}
    rows = []
    for c1 in check1_rows:
        if c1["verdict"] != "ALERT":
            continue
        key_index = by_id[c1["event_id"]]
        key_event = events[key_index]
        target = c1["evidence"]["target_user"]
        grant = None
        for e in reversed(events[:key_index]):  # most recent first
            if key_event.time - e.time > window:
                break
            if (e.source == lineage.IAM and e.name == "AttachUserPolicy" and not e.error_code
                    and e.account_id == key_event.account_id
                    and e.partition == key_event.partition
                    and e.request.get("policyArn") in config["elevated_policies"]
                    and isinstance(e.request.get("userName"), str)
                    and lineage.same_user(e.request["userName"], target)):
                grant = e
                break
        if grant is None:
            continue
        minutes = round((key_event.time - grant.time).total_seconds() / 60, 1)
        rows.append(make_row(
            CHECK, key_event, "ALERT", "GRANT_THEN_CREDENTIAL",
            f"{target} was given {grant.request['policyArn']} {minutes} minutes before a new "
            "access key was created for them by a different identity.",
            {"grant_event_id": grant.event_id, "grant_time": iso(grant),
             "policy_arn": grant.request["policyArn"], "granted_by": grant.identity_arn,
             "minutes_between": minutes, "key_made_for": target,
             "new_key_id": c1["evidence"]["new_key_id"]},
            points=["cross_identity", "elevated_grant"]))
    return rows

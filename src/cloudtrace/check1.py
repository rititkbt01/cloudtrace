"""Check 1: was an access key created for a different identity?

Every CreateAccessKey event gets a decision. The first rule that applies wins:

  1. The call failed (errorCode set)                 -> IGNORED   FAILED_CALL
  2. We cannot tell who the key was for              -> NOT_CHECKED TARGET_UNKNOWN
  3. The key is for the caller themselves            -> IGNORED   SELF_KEY / SELF_KEY_IMPLICIT
  4. The caller is an approved automation role       -> IGNORED   ALLOW_LISTED_ROLE
  5. Otherwise                                       -> ALERT     KEY_FOR_OTHER_ACCOUNT

By itself this is only a low-severity note (1 point). It becomes more serious when
Check 2 or Check 3 find more evidence about the same key.
"""
from cloudtrace import lineage, scoring
from cloudtrace.quality import Event

CHECK = "check1"


def _row(e: Event, verdict: str, reason: str, why: str, evidence: dict, breakdown=None) -> dict:
    row = {"check": CHECK, "event_id": e.event_id, "verdict": verdict, "reason": reason,
           "explanation": why, "evidence": evidence}
    if breakdown is not None:
        points, total, band = scoring.score(breakdown)
        row.update(severity=band, score=total, score_breakdown=points)
    return row


def run(events: list[Event], config: dict) -> list[dict]:
    rows = []
    for e in events:
        if not lineage.is_create_access_key(e):
            continue
        target, how = lineage.resolve_target(e)
        caller = e.identity_arn
        evidence = {"time": e.time.isoformat().replace("+00:00", "Z"), "caller": caller,
                    "target_user": target, "target_known_from": how, "source_ip": e.source_ip,
                    "new_key_id": lineage.created_key_id(e)}
        if e.error_code:
            rows.append(_row(e, "IGNORED", "FAILED_CALL",
                             f"The call failed ({e.error_code}), so no key was created.",
                             evidence))
            continue
        if target is None:
            rows.append(_row(e, "NOT_CHECKED", "TARGET_UNKNOWN",
                             "The log does not show who the key was made for.", evidence))
            continue
        me = lineage.caller_user_name(e)
        if me and lineage.same_user(me, target):
            if how == "request":
                rows.append(_row(e, "IGNORED", "SELF_KEY",
                                 f"{me} created a key for themselves (user name given).", evidence))
            else:
                rows.append(_row(e, "IGNORED", "SELF_KEY_IMPLICIT",
                                 f"{me} created a key and left the user name out; "
                                 "AWS then uses the caller, so the key is for themselves.",
                                 evidence))
            continue
        if e.role_name and e.role_name in config["allowed_roles"]:
            rows.append(_row(e, "IGNORED", "ALLOW_LISTED_ROLE",
                             f"Role '{e.role_name}' is on the approved list.", evidence))
            continue
        who = me or caller or "an unknown caller"
        rows.append(_row(e, "ALERT", "KEY_FOR_OTHER_ACCOUNT",
                         f"{who} created an access key for a different identity ({target}).",
                         evidence, breakdown=["cross_identity"]))
    return rows

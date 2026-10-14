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

from cloudtrace import lineage
from cloudtrace.quality import Event
from cloudtrace.rows import make_row

CHECK = "check1"


def run(events: list[Event], config: dict) -> list[dict]:
    rows = []
    for e in events:
        if not lineage.is_create_access_key(e):
            continue
        target, how = lineage.resolve_target(e)
        caller = e.identity_arn
        evidence = {
            "caller": caller,
            "target_user": target,
            "target_known_from": how,
            "source_ip": e.source_ip,
            "new_key_id": lineage.created_key_id(e),
        }
        if e.error_code:
            rows.append(
                make_row(
                    CHECK,
                    e,
                    "IGNORED",
                    "FAILED_CALL",
                    f"The call failed ({e.error_code}), so no key was created.",
                    evidence,
                )
            )
            continue
        if target is None:
            rows.append(
                make_row(
                    CHECK,
                    e,
                    "NOT_CHECKED",
                    "TARGET_UNKNOWN",
                    "The log does not show who the key was made for.",
                    evidence,
                )
            )
            continue
        me = lineage.caller_user_name(e)
        if me and lineage.same_user(me, target):
            if how == "request":
                rows.append(
                    make_row(
                        CHECK,
                        e,
                        "IGNORED",
                        "SELF_KEY",
                        f"{me} created a key for themselves (user name given).",
                        evidence,
                    )
                )
            else:
                rows.append(
                    make_row(
                        CHECK,
                        e,
                        "IGNORED",
                        "SELF_KEY_IMPLICIT",
                        f"{me} created a key and left the user name out; "
                        "AWS then uses the caller, so the key is for themselves.",
                        evidence,
                    )
                )
            continue
        if e.role_name and e.role_name in config["allowed_roles"]:
            rows.append(
                make_row(
                    CHECK,
                    e,
                    "IGNORED",
                    "ALLOW_LISTED_ROLE",
                    f"Role '{e.role_name}' is on the approved list.",
                    evidence,
                )
            )
            continue
        who = me or caller or "an unknown caller"
        rows.append(
            make_row(
                CHECK,
                e,
                "ALERT",
                "KEY_FOR_OTHER_ACCOUNT",
                f"{who} created an access key for a different identity ({target}).",
                evidence,
                points=["cross_identity"],
            )
        )
    return rows

"""Check 2: was a newly created key first used from an address its owner never used before?

Which keys are followed: keys that Check 1 flagged (made by one identity for a different one).
Key history tells us when each key was created and where it was first used.

Version 2 (Stage 7): every distinct source address used with the key inside the window is judged
once, at its first use. (Version 1 judged only the very first use, which an attacker could dodge by
first using the key once from the owner's usual address; see attacker-change test M7.)

  1. No use inside the window (first use is later)            -> IGNORED     OUTSIDE_WINDOW
  2. The owner has too few earlier events to know "usual"     -> NOT_CHECKED BASELINE_TOO_SMALL
  Then, for each address used inside the window:
  3. The event has no source address                          -> NOT_CHECKED MISSING_SOURCE_IP
  4. The address was already used by the owner before         -> IGNORED     SOURCE_ALREADY_SEEN
  5. Otherwise                                                -> ALERT       KEY_USED_FROM_NEW_SOURCE

If no event is signed with the key, but the owner has an event in the window whose key ID is
empty (so it cannot be linked), the result is NOT_CHECKED / MISSING_KEY_ID on that event.
A key that is never used in the log gets no Check 2 row.

"Usual address" means: source addresses of the owner's events BEFORE the key was created,
in this log only. "New" is judged by address only (the browser/tool name is kept as evidence).
"""
from datetime import datetime, timedelta

from cloudtrace import lineage
from cloudtrace.quality import Event
from cloudtrace.rows import iso, make_row

CHECK = "check2"


def _is_owner(e: Event, key) -> bool:
    return lineage.owner_matches(e, key.target_user, key.account_id, key.partition)


def _minutes_after(use, created_at) -> float:
    return round((datetime.fromisoformat(use.time) - created_at).total_seconds() / 60, 1)


def _evidence(base: dict, created_at, use, **more) -> dict:
    return {**base, "minutes_after_creation": _minutes_after(use, created_at),
            "source_ip": use.source_ip, "user_agent": use.user_agent, **more}


def run(events: list[Event], config: dict, history: dict, check1_rows: list[dict]) -> list[dict]:
    window = timedelta(minutes=config["window_minutes"])
    by_id = {e.event_id: i for i, e in enumerate(events)}
    rows = []
    for c1 in check1_rows:
        if c1["verdict"] != "ALERT":
            continue
        key_id = c1["evidence"]["new_key_id"]
        if not key_id:
            rows.append(make_row(
                CHECK, events[by_id[c1["event_id"]]], "NOT_CHECKED", "CREATED_KEY_ID_MISSING",
                "The creation response has no usable new key ID, so its later use cannot be linked.",
                {"key_created_event_id": c1["event_id"],
                 "key_made_for": c1["evidence"]["target_user"]}))
            continue
        key = history.get(key_id)
        if key is None:
            continue
        owner = key.target_user
        created_at = events[by_id[key.created_event_id]].time
        created_index = by_id[key.created_event_id]

        if key.uses:
            first = key.uses[0]
            in_window = [u for u in key.uses
                         if datetime.fromisoformat(u.time) - created_at <= window]
            base = {"key_id": key_id, "key_created_event_id": key.created_event_id,
                    "key_created_at": key.created_time, "key_made_for": owner,
                    "creator_ip": key.creator_ip}

            if not in_window:
                rows.append(make_row(
                    CHECK, events[by_id[first.event_id]], "IGNORED", "OUTSIDE_WINDOW",
                    f"The key was first used {_minutes_after(first, created_at)} minutes after it was created, "
                    f"which is later than the {config['window_minutes']}-minute window.",
                    _evidence(base, created_at, first)))
                continue
            earlier = [e for e in events[:created_index] if _is_owner(e, key) and e.source_ip
                       and e.time < created_at]
            known = sorted({e.source_ip for e in earlier})
            history_facts = {"known_sources": known, "baseline_events": len(earlier)}
            if len(earlier) < config["baseline_min_events"]:
                rows.append(make_row(
                    CHECK, events[by_id[in_window[0].event_id]], "NOT_CHECKED",
                    "BASELINE_TOO_SMALL",
                    f"{owner} has only {len(earlier)} earlier event(s) in this log "
                    f"(needs {config['baseline_min_events']}), so their usual addresses "
                    "are not known.", _evidence(base, created_at, in_window[0], **history_facts)))
                continue
            judged = set()  # each address (or "no address") is judged once, at its first use
            for use in in_window:
                if use.source_ip in judged:
                    continue
                judged.add(use.source_ip)
                use_event = events[by_id[use.event_id]]
                ev = _evidence(base, created_at, use, **history_facts)
                if not use.source_ip:
                    rows.append(make_row(
                        CHECK, use_event, "NOT_CHECKED", "MISSING_SOURCE_IP",
                        "An event signed with the key has no source address, so we cannot "
                        "say whether it is new. The tool does not guess.", ev))
                elif use.source_ip in known:
                    rows.append(make_row(
                        CHECK, use_event, "IGNORED", "SOURCE_ALREADY_SEEN",
                        f"The key was used from {use.source_ip}, which {owner} already used "
                        "earlier in this log.", ev))
                else:
                    points = ["cross_identity", "first_use_in_window", "new_source"]
                    word = "first used" if use is first else "also used"
                    why = (f"The key made for {owner} was {word} {_minutes_after(use, created_at)} minutes "
                           f"after it was created, from {use.source_ip}, an address {owner} did "
                           f"not use in the {len(earlier)} earlier events of this log.")
                    if use.source_ip == key.creator_ip:
                        points.append("creator_source")
                        why += " It is the same address that created the key."
                    rows.append(make_row(CHECK, use_event, "ALERT", "KEY_USED_FROM_NEW_SOURCE",
                                         why, ev, points=points))
            continue

        # No event is signed with this key. Look for owner events that cannot be linked.
        for e in events[created_index + 1:]:
            if e.time - created_at > window:
                break
            if e.access_key_id is None and _is_owner(e, key):
                rows.append(make_row(
                    CHECK, e, "NOT_CHECKED", "MISSING_KEY_ID",
                    f"This event by {owner} came {round((e.time - created_at).total_seconds() / 60, 1)} "
                    "minutes after a key was created for them, but its key ID is empty, so it "
                    "cannot be linked to the new key. The tool does not guess.",
                    {"key_id": key_id, "key_created_event_id": key.created_event_id,
                     "key_made_for": owner, "source_ip": e.source_ip, "created_at": iso(e)}))
                break
    return rows

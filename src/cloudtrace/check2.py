"""Check 2: was a newly created key first used from an address its owner never used before?

Which keys are followed: keys that Check 1 flagged (made by one identity for a different one).
Key history tells us when each key was created and where it was first used.

For each followed key, the first event signed with that key is judged. The first rule that
applies wins:

  1. First use is later than the window (default 60 min)      -> IGNORED     OUTSIDE_WINDOW
  2. The owner has too few earlier events to know "usual"     -> NOT_CHECKED BASELINE_TOO_SMALL
  3. The address was already used by the owner before         -> IGNORED     SOURCE_ALREADY_SEEN
  4. Otherwise                                                -> ALERT       KEY_USED_FROM_NEW_SOURCE

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


def _is_owner(e: Event, owner: str) -> bool:
    me = lineage.caller_user_name(e)
    return bool(me) and lineage.same_user(me, owner)


def run(events: list[Event], config: dict, history: dict, check1_rows: list[dict]) -> list[dict]:
    window = timedelta(minutes=config["window_minutes"])
    by_id = {e.event_id: i for i, e in enumerate(events)}
    rows = []
    for c1 in check1_rows:
        if c1["verdict"] != "ALERT":
            continue
        key_id = c1["evidence"]["new_key_id"]
        key = history.get(key_id)
        if key is None:
            continue
        owner = key.target_user
        created_at = events[by_id[key.created_event_id]].time
        created_index = by_id[key.created_event_id]

        if key.uses:
            use = key.uses[0]
            use_event = events[by_id[use.event_id]]
            minutes = round((datetime.fromisoformat(use.time) - created_at).total_seconds() / 60, 1)
            base_evidence = {"key_id": key_id, "key_created_event_id": key.created_event_id,
                             "key_created_at": key.created_time, "key_made_for": owner,
                             "minutes_after_creation": minutes, "source_ip": use.source_ip,
                             "user_agent": use.user_agent, "creator_ip": key.creator_ip}
            if datetime.fromisoformat(use.time) - created_at > window:
                rows.append(make_row(
                    CHECK, use_event, "IGNORED", "OUTSIDE_WINDOW",
                    f"The key was first used {minutes} minutes after it was created, which is "
                    f"later than the {config['window_minutes']}-minute window.", base_evidence))
                continue
            earlier = [e for e in events[:created_index] if _is_owner(e, owner) and e.source_ip]
            known = sorted({e.source_ip for e in earlier})
            base_evidence.update(known_sources=known, baseline_events=len(earlier))
            if len(earlier) < config["baseline_min_events"]:
                rows.append(make_row(
                    CHECK, use_event, "NOT_CHECKED", "BASELINE_TOO_SMALL",
                    f"{owner} has only {len(earlier)} earlier event(s) in this log "
                    f"(needs {config['baseline_min_events']}), so their usual addresses "
                    "are not known.", base_evidence))
                continue
            if use.source_ip in known:
                rows.append(make_row(
                    CHECK, use_event, "IGNORED", "SOURCE_ALREADY_SEEN",
                    f"The key was first used from {use.source_ip}, which {owner} already used "
                    "earlier in this log.", base_evidence))
                continue
            points = ["cross_identity", "first_use_in_window", "new_source"]
            why = (f"The key made for {owner} was first used {minutes} minutes after it was "
                   f"created, from {use.source_ip}, an address {owner} did not use in the "
                   f"{len(earlier)} earlier events of this log.")
            if use.source_ip and use.source_ip == key.creator_ip:
                points.append("creator_source")
                why += " It is the same address that created the key."
            rows.append(make_row(CHECK, use_event, "ALERT", "KEY_USED_FROM_NEW_SOURCE", why,
                                 base_evidence, points=points))
            continue

        # No event is signed with this key. Look for owner events that cannot be linked.
        for e in events[created_index + 1:]:
            if e.time - created_at > window:
                break
            if e.access_key_id is None and _is_owner(e, owner):
                rows.append(make_row(
                    CHECK, e, "NOT_CHECKED", "MISSING_KEY_ID",
                    f"This event by {owner} came {round((e.time - created_at).total_seconds() / 60, 1)} "
                    "minutes after a key was created for them, but its key ID is empty, so it "
                    "cannot be linked to the new key. The tool does not guess.",
                    {"key_id": key_id, "key_created_event_id": key.created_event_id,
                     "key_made_for": owner, "source_ip": e.source_ip, "created_at": iso(e)}))
                break
    return rows

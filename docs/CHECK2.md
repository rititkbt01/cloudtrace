# Check 2: new key first used from a new address

**Question:** was a key that someone else created first used from an address its owner never used before?
**Why it matters:** a stolen or planted key is often first used from the attacker's own address.
(MITRE ATT&CK T1098.001, "Additional Cloud Credentials". This is a clue, not proof.)

## Which keys are followed
Keys that Check 1 flagged (made by one identity for a different one). Self-made keys, keys made by
approved roles and failed calls are not followed. Key history supplies when each key was created
and which later events were signed with it.

## Definitions (stated, not hidden)
- **Window:** `window_minutes` after the key was created (default 60, inclusive).
- **Usual address:** source addresses of the owner's events **before** the key was created, in this
  log only. Judged by address only; the tool name (user agent) is kept as evidence.
- **Enough history:** the owner needs at least `baseline_min_events` earlier events (default 3).
- Only the **first** event signed with the key is judged.

## Decision order (first match wins)
| # | Condition | Verdict | Reason |
|---|---|---|---|
| 1 | First use is later than the window | IGNORED | OUTSIDE_WINDOW |
| 2 | Owner has too few earlier events | NOT_CHECKED | BASELINE_TOO_SMALL |
| 3 | Address was already used by the owner | IGNORED | SOURCE_ALREADY_SEEN |
| 4 | Otherwise | ALERT | KEY_USED_FROM_NEW_SOURCE |

If nothing is signed with the key but the owner has an event in the window whose key ID is empty,
the result is NOT_CHECKED / MISSING_KEY_ID on that event. A key never used in the log gets no row.

## Points (frozen weights, see `scoring.py`)
cross_identity 1 (always) + first_use_in_window 2 + new_source 2, plus creator_source 3 when the key is
first used from the same address that created it. C01 = 8 (high), C06 = 5 (high).

## Known false positives
Owner travels or changes network; a new office or VPN; short logs (everything looks new, hence the
minimum history rule).

## Known evasions and limits
- Waiting longer than the window (case C07). The evasion tests measure this.
- Using the key first from an address the owner already uses, then switching later (only the first use is judged).
- Events with an empty key ID cannot be linked (NOT_CHECKED, never guessed).
- Failed calls by the owner before the key was created still count as "seen" addresses.
- Console logins (no key ID) in the window can show as MISSING_KEY_ID when the key is otherwise unused.

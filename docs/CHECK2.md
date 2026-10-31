# Check 2: new key used from a new address

**Question:** was a key that someone else created used, soon after, from an address its owner never used before?
**Why it matters:** a stolen or planted key is often first used from the attacker's own address.
(MITRE ATT&CK T1098.001, "Additional Cloud Credentials". This is a clue, not proof.)

## Which keys are followed
Keys that Check 1 flagged (made by one identity for a different one). Self-made keys, keys made by
approved roles and failed calls are not followed. Key history supplies when each key was created
and which later events were signed with it.

## Definitions (stated, not hidden)
- **Window:** `window_minutes` after the key was created (default 60, inclusive).
- **Usual address:** source addresses of the owner's events **before** the key was created, in this
  log only, for the same IAM user, AWS account and partition. Equal timestamps do not count as earlier
  history. Judged by address only; the tool name (user agent) is kept as evidence.
- **Enough history:** the owner needs at least `baseline_min_events` earlier events (default 3).
- Version 2 (Stage 7): every **distinct address** that uses the key inside the window is judged once, at its first use there.
  Version 1 judged only the very first use, so an attacker could use the key once from the owner's usual address and
  then switch (attacker-change test M7). Version 1 results are kept in `results/eval/RESULTS_run1_first_use_only.md`.

## Decision order (first match wins)
| # | Condition | Verdict | Reason |
|---|---|---|---|
| 0 | Creation response lacks a usable new key ID | NOT_CHECKED | CREATED_KEY_ID_MISSING |
| 1 | No use inside the window (the first use is later) | IGNORED | OUTSIDE_WINDOW |
| 2 | Owner has too few earlier events | NOT_CHECKED | BASELINE_TOO_SMALL |
| 3 | Then, for each address used inside the window: the event has no source address | NOT_CHECKED | MISSING_SOURCE_IP |
| 4 | Address was already used by the owner | IGNORED | SOURCE_ALREADY_SEEN |
| 5 | Otherwise | ALERT | KEY_USED_FROM_NEW_SOURCE |

If nothing is signed with the key but the owner has an event in the window whose key ID is empty,
the result is NOT_CHECKED / MISSING_KEY_ID on that event. A key never used in the log gets no row.

## Points (frozen weights, see `scoring.py`)
cross_identity 1 (always) + first_use_in_window 2 + new_source 2, plus creator_source 3 when the key is
used from the same address that created it. C01 = 8 (high), C06 = 5 (high).

## Known false positives
Owner travels or changes network; a new office or VPN; short logs (everything looks new, hence the
minimum history rule). Version 2 adds one more: a person who uses the key from their usual address and then from a second new
address inside the window (phone, VPN) is flagged, because the attack in test M7 looks the same. Measured in
`results/eval/CHECK2_COST.md`: one extra false alarm per such normal story.

## Known evasions and limits
- Waiting longer than the window (case C07). The evasion tests measure this.
- An address the attacker planted in the owner's earlier history (M8) counts as "usual".
- A new address is judged once; later uses from the same address are not judged again.
- Events with an empty key ID cannot be linked (NOT_CHECKED, never guessed).
- Failed calls by the owner before the key was created still count as "seen" addresses.
- Console logins (no key ID) in the window can show as MISSING_KEY_ID when the key is otherwise unused.

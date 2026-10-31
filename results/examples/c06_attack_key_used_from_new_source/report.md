# CloudTrace report

- Input: `c06_attack_key_used_from_new_source/events.json`
- Tool version: 1.1.1
- Time range in log: 2026-01-01T09:10:00Z to 2026-01-01T10:10:00Z
- Records read: 5; usable: 5 (input usability 100.0%)
- Events judged by the checks: 2

- Evaluated rule decisions: 2/2 (excludes NOT_CHECKED; multiple checks may judge one event)
- Resolved key creations: 1/1; lineage-break decisions: 0

## Summary

| Result | Count |
|---|---|
| Findings, high | 1 |
| Findings, medium | 0 |
| Findings, low | 1 |
| Ignored (with reason) | 0 |
| Not checked (with reason) | 0 |

## Findings to review

### [HIGH] KEY_USED_FROM_NEW_SOURCE - event c06-005

- Check: check2
- Time: 2026-01-01T10:10:00Z
- Why: The key made for svc-b was first used 10.0 minutes after it was created, from 192.0.2.50, an address svc-b did not use in the 3 earlier events of this log.
- Score: 5 (cross_identity 1, first_use_in_window 2, new_source 2)
- Next step for a person: Check with the key's owner whether the new address is theirs. If not, review other activity from that address and consider disabling the key.

### [LOW] KEY_FOR_OTHER_ACCOUNT - event c06-004

- Check: check1
- Time: 2026-01-01T10:00:00Z
- Why: admin-a created an access key for a different identity (svc-b).
- Score: 1 (cross_identity 1)
- Next step for a person: Ask the creator and the key's owner whether this key was expected. If not, review what the key was used for and consider disabling it.

## Decision record (why each candidate did or did not alert)

| Check | Event | Time | Result | Reason | Explanation |
|---|---|---|---|---|---|
| check1 | c06-004 | 2026-01-01T10:00:00Z | ALERT | KEY_FOR_OTHER_ACCOUNT | admin-a created an access key for a different identity (svc-b). |
| check2 | c06-005 | 2026-01-01T10:10:00Z | ALERT | KEY_USED_FROM_NEW_SOURCE | The key made for svc-b was first used 10.0 minutes after it was created, from 192.0.2.50, an address svc-b did not use in the 3 earlier events of this log. |

## Log quality

- Duplicates removed: 0 (conflicting copies: 0)
- Events were out of time order: no
- Unusable records: 0

## Key history

| Key | Created (event) | Created by | Made for | First use |
|---|---|---|---|---|
| AKIAEXAMPLENEWKEY01 | 2026-01-01T10:00:00Z (c06-004) | arn:aws:iam::123456789012:user/admin-a | svc-b | 2026-01-01T10:10:00Z from 192.0.2.50 |

## Comparison with a single-event rule: B1 (SigmaHQ: AWS IAM Backdoor Users Keys)

The single-event rule raised 1 alert(s) on the raw log.

| Event | B1 alerts | Check 1 | Agreement |
|---|---|---|---|
| c06-004 | 1 | ALERT / KEY_FOR_OTHER_ACCOUNT | Both flag this event. |

## Notes and limits

- Results come from the log file you supplied only. 'Usual' addresses mean 'seen earlier in this log', so a short log makes many things look new.
- A finding means 'please review', not 'attack confirmed'. No finding does not mean safe: CloudTrail does not record everything, and time windows can be waited out.
- CloudTrace only reads files. It never connects to a cloud account or changes anything.

# CloudTrace report

- Input: `c08_attack_admin_grant_then_key/events.json`
- Tool version: 1.1.1
- Time range in log: 2026-01-01T10:00:00Z to 2026-01-01T10:20:00Z
- Records read: 2; usable: 2 (input usability 100.0%)
- Events judged by the checks: 1

- Evaluated rule decisions: 2/2 (excludes NOT_CHECKED; multiple checks may judge one event)
- Resolved key creations: 1/1; lineage-break decisions: 0

## Summary

| Result | Count |
|---|---|
| Findings, high | 0 |
| Findings, medium | 1 |
| Findings, low | 1 |
| Ignored (with reason) | 0 |
| Not checked (with reason) | 0 |

## Findings to review

### [MEDIUM] GRANT_THEN_CREDENTIAL - event c08-002

- Check: check3
- Time: 2026-01-01T10:20:00Z
- Why: svc-b was given arn:aws:iam::aws:policy/AdministratorAccess 20.0 minutes before a new access key was created for them by a different identity.
- Score: 4 (cross_identity 1, elevated_grant 3)
- Next step for a person: Check that the rights grant and the new key were both approved. If not, review the identity's recent activity.

### [LOW] KEY_FOR_OTHER_ACCOUNT - event c08-002

- Check: check1
- Time: 2026-01-01T10:20:00Z
- Why: admin-a created an access key for a different identity (svc-b).
- Score: 1 (cross_identity 1)
- Next step for a person: Ask the creator and the key's owner whether this key was expected. If not, review what the key was used for and consider disabling it.

## Decision record (why each candidate did or did not alert)

| Check | Event | Time | Result | Reason | Explanation |
|---|---|---|---|---|---|
| check1 | c08-002 | 2026-01-01T10:20:00Z | ALERT | KEY_FOR_OTHER_ACCOUNT | admin-a created an access key for a different identity (svc-b). |
| check3 | c08-002 | 2026-01-01T10:20:00Z | ALERT | GRANT_THEN_CREDENTIAL | svc-b was given arn:aws:iam::aws:policy/AdministratorAccess 20.0 minutes before a new access key was created for them by a different identity. |

## Log quality

- Duplicates removed: 0 (conflicting copies: 0)
- Events were out of time order: no
- Unusable records: 0

## Key history

| Key | Created (event) | Created by | Made for | First use |
|---|---|---|---|---|
| AKIAEXAMPLENEWKEY01 | 2026-01-01T10:20:00Z (c08-002) | arn:aws:iam::123456789012:user/admin-a | svc-b | not used in this log |

## Comparison with a single-event rule: B1 (SigmaHQ: AWS IAM Backdoor Users Keys)

The single-event rule raised 1 alert(s) on the raw log.

| Event | B1 alerts | Check 1 | Agreement |
|---|---|---|---|
| c08-002 | 1 | ALERT / KEY_FOR_OTHER_ACCOUNT | Both flag this event. |

## Notes and limits

- Results come from the log file you supplied only. 'Usual' addresses mean 'seen earlier in this log', so a short log makes many things look new.
- A finding means 'please review', not 'attack confirmed'. No finding does not mean safe: CloudTrail does not record everything, and time windows can be waited out.
- CloudTrace only reads files. It never connects to a cloud account or changes anything.

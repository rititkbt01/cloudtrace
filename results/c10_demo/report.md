# CloudTrace report

- Input: `events.json`
- Tool version: 0.1.0
- Time range in log: 2026-01-01T10:00:00Z to 2026-01-01T10:00:00Z
- Records read: 1; usable: 1 (100.0%)
- Key-creation events examined: 1

## Summary

| Result | Count |
|---|---|
| Findings, high | 0 |
| Findings, medium | 0 |
| Findings, low | 0 |
| Ignored (with reason) | 1 |
| Not checked (with reason) | 0 |

## Findings to review

No findings. This does not mean the account is safe (see Notes and limits).

## Decision record (why each candidate did or did not alert)

| Check | Event | Time | Result | Reason | Explanation |
|---|---|---|---|---|---|
| check1 | c10-001 | 2026-01-01T10:00:00Z | IGNORED | FAILED_CALL | The call failed (AccessDenied), so no key was created. |

## Log quality

- Duplicates removed: 0 (conflicting copies: 0)
- Events were out of time order: no
- Unusable records: 0

## Key history

No keys were created successfully in this log.

## Comparison with a single-event rule: B1 (SigmaHQ: AWS IAM Backdoor Users Keys)

The single-event rule raised 1 alert(s) on the raw log.

| Event | B1 alerts | Check 1 | Agreement |
|---|---|---|---|
| c10-001 | 1 | IGNORED / FAILED_CALL | B1 alerts; Check 1 says IGNORED / FAILED_CALL. |

## Notes and limits

- Results come from the log file you supplied only. 'Usual' addresses mean 'seen earlier in this log', so a short log makes many things look new.
- A finding means 'please review', not 'attack confirmed'. No finding does not mean safe: CloudTrail does not record everything, and time windows can be waited out.
- CloudTrace only reads files. It never connects to a cloud account or changes anything.

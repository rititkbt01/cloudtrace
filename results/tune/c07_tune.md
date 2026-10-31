# CloudTrace settings guide

Tool version 1.1.1.

- Records read: 5; usable: 5
- Keys tracked: 1; observed use: 1; no observed use: 0
- First observed use after creation (minutes): minimum 180.0, median 180.0, maximum 180.0

Counts describe observations in this log. They are not attack labels, false-positive rates or recommended settings.

## Time window in minutes

| Setting | Medium+ findings | Distinct flagged events | NOT_CHECKED decisions | Check 2 outside-window decisions |
|---|---|---|---|---|
| 15 | 0 | 0 | 0 | 1 |
| 30 | 0 | 0 | 0 | 1 |
| 60 (current) | 0 | 0 | 0 | 1 |
| 120 | 0 | 0 | 0 | 1 |
| 240 | 1 | 1 | 0 | 0 |
| 480 | 1 | 1 | 0 | 0 |
| 1440 | 1 | 1 | 0 | 0 |

## Earlier owner events required

| Setting | Medium+ findings | Distinct flagged events | NOT_CHECKED decisions | Check 2 outside-window decisions |
|---|---|---|---|---|
| 1 | 0 | 0 | 0 | 1 |
| 3 (current) | 0 | 0 | 0 | 1 |
| 5 | 0 | 0 | 0 | 1 |
| 7 | 0 | 0 | 0 | 1 |
| 9 | 0 | 0 | 0 | 1 |

## Interpretation

- One setting changes at a time. Other supplied settings remain fixed.
- The time window affects both Check 2 use correlation and Check 3 grant correlation.
- Check 2 examines cross-identity keys not excluded by an approved-role exception. Self-created keys remain outside Check 2 scope.
- Findings are rows; several findings can refer to one event. NOT_CHECKED is uncertainty.
- No observed use means no linked event in this file, not that the key was never used. The end of the log limits observation.
- Timing summaries cover all tracked keys, including self-created and excluded keys. Finding counts follow the actual detector scope.
- Without labels these tables cannot identify attacks, false alarms or an optimal setting.
- Only counts and durations are printed. Analysis reads files without contacting AWS.

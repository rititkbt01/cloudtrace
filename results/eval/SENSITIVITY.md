# Settings sensitivity (generated logs, T2)

Seeds [1, 2, 3, 4, 5], all added up. One setting changes at a time; the other stays at its default. 'CloudTrace (medium and above)' is counted, as in RESULTS.md.

### Time window (minutes)

| window_minutes | Attacks caught | Normal stories flagged | Attacks it said 'not checked' |
|---|---|---|---|
| 15 | 52/120 | 15/270 | 0 |
| 30 | 96/120 | 34/270 | 0 |
| 60 (default) | 120/120 | 50/270 | 0 |
| 120 | 120/120 | 50/270 | 0 |
| 240 | 120/120 | 50/270 | 0 |

### Earlier events needed before 'usual addresses' are trusted

| baseline_min_events | Attacks caught | Normal stories flagged | Attacks it said 'not checked' |
|---|---|---|---|
| 1 | 120/120 | 50/270 | 0 |
| 3 (default) | 120/120 | 50/270 | 0 |
| 5 | 103/120 | 41/270 | 17 |
| 7 | 79/120 | 29/270 | 41 |
| 9 | 40/120 | 20/270 | 80 |

## How to read this

- The defaults (60 minutes, 3 events) were chosen before this table existed and were not changed after seeing it.
- A shorter window misses attacks whose first use comes later. Going above 60 minutes changes nothing here because the generated stories use the key 2 to 40 minutes after it is made; on real logs a longer window may also let in more look-alike normal cases.
- A higher history requirement makes CloudTrace say 'not checked' more often (accounts with little history), which loses attacks but never invents alerts.
- These are generated logs. They show how the settings behave, not the best values for a real organisation.

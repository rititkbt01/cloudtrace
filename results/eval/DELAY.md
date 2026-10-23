# Delayed key use versus the time window (generated logs)

Each cell: stories flagged by CloudTrace (medium and above) out of 20. The shipped window is 60 minutes. The same stories are run for every window; only `window_minutes` changes.

### Attack: key made for someone else, first used from a new address

| First use after | window 30 min | window 60 min | window 120 min | window 240 min | window 480 min | window 1440 min |
|---|---|---|---|---|---|---|
| 10 min | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 |
| 30 min | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 |
| 60 min | 0/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 |
| 90 min | 0/20 | 0/20 | 20/20 | 20/20 | 20/20 | 20/20 |
| 120 min | 0/20 | 0/20 | 20/20 | 20/20 | 20/20 | 20/20 |
| 240 min | 0/20 | 0/20 | 0/20 | 20/20 | 20/20 | 20/20 |
| 480 min | 0/20 | 0/20 | 0/20 | 0/20 | 20/20 | 20/20 |
| 1440 min | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 | 20/20 |

### Look-alike normal story: key handed to a colleague, first used from a new address

| First use after | window 30 min | window 60 min | window 120 min | window 240 min | window 480 min | window 1440 min |
|---|---|---|---|---|---|---|
| 10 min | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 |
| 30 min | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 |
| 60 min | 0/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 |
| 90 min | 0/20 | 0/20 | 20/20 | 20/20 | 20/20 | 20/20 |
| 120 min | 0/20 | 0/20 | 20/20 | 20/20 | 20/20 | 20/20 |
| 240 min | 0/20 | 0/20 | 0/20 | 20/20 | 20/20 | 20/20 |
| 480 min | 0/20 | 0/20 | 0/20 | 0/20 | 20/20 | 20/20 |
| 1440 min | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 | 20/20 |

## How to read this

- A key first used **after** the window is not judged by Check 2, so the attack is not flagged (Check 1 still leaves a low note). The result is the same for the attack and for the normal story, because the log shows nothing else that tells them apart.
- A longer window catches slower attackers, but it also flags a colleague who is slow to use a key from a new address. In our generated normal stories the first use is always within 40 minutes, so a longer window costs nothing here (see SENSITIVITY.md). Real hand-overs may be slower; that is an assumption we cannot check without real normal logs.
- A very patient attacker (longer than any window we would accept) cannot be caught by this check.
- Generated logs only. This describes how the setting behaves, not a recommended value.

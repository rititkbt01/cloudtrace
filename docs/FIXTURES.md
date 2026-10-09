# Test cases (fixtures)

These are the hand-made test cases for CloudTrace. They were written **before any detection code**.
The expected answers are the promise the code must keep. If the code and a case disagree, we
look at the case first and decide who is right. We never edit a case just to make the code pass.

All data is **synthetic**: made-up account `123456789012`, made-up keys that contain `EXAMPLE`,
and addresses only from the three documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x).
Tests enforce this.

## Folder layout

```
data/fixtures/c01_.../
    events.json   the log (same layout as a real CloudTrail file: {"Records": [ ... ]})
    case.json     the settings and the expected answers
```

## case.json fields

| Field | Meaning |
|---|---|
| `case_id`, `title`, `description` | Name and plain-language story |
| `ground_truth` | What really happened in the story: `attack` or `normal` |
| `category` | `attack`, `normal`, `edge` (odd data), or `known_limitation` (tool is expected to miss it) |
| `applies_to_checks` | Which parts must be built before this case can pass: `quality`, `check1`, `check2`, `check3` |
| `config` | Settings used for this case (window, baseline size, approved roles, elevated policies) |
| `expected.verdicts` | The decision record the tool must produce |
| `expected.quality` | (only C09) what the log quality check must report |

`ground_truth` is reality. `expected` is what the tool should output under its stated rules.
They differ in C07: it is a real attack, but the 60-minute window means Check 2 must say
`IGNORED / OUTSIDE_WINDOW`. We keep it on purpose to measure how much a patient attacker weakens the check.

## The people and addresses

| Name | Role in the stories | Address |
|---|---|---|
| admin-a | administrator | 203.0.113.10 |
| svc-b | service account | 198.51.100.25 |
| bob | colleague | 198.51.100.77 |
| ci-deploy | approved automation role | 192.0.2.20 |
| (stranger) | an address nobody used before | 192.0.2.50 |

## Decision record: what each verdict row means

Each row is `check`, `event_id`, `verdict`, `reason` (and for alerts: `severity`, `score`, `score_breakdown`).

| Verdict | Reasons used |
|---|---|
| `ALERT` | `KEY_FOR_OTHER_ACCOUNT` (check1), `KEY_USED_FROM_NEW_SOURCE` (check2), `GRANT_THEN_CREDENTIAL` (check3) |
| `IGNORED` | `SELF_KEY`, `SELF_KEY_IMPLICIT`, `ALLOW_LISTED_ROLE`, `FAILED_CALL` (check1); `SOURCE_ALREADY_SEEN`, `OUTSIDE_WINDOW` (check2) |
| `NOT_CHECKED` | `MISSING_KEY_ID` (check2) |

## Severity: evidence points

Severity is the sum of points for the evidence found. It is not a guess.

| Evidence | Points |
|---|---|
| `cross_identity` key made for a different account | 1 |
| `first_use_in_window` new key used within the window | 2 |
| `new_source` address never seen for that account in this log | 2 |
| `creator_source` the key is used from the creator's own address | 3 |
| `elevated_grant` strong rights granted just before | 3 |

Bands: 1 to 2 = low, 3 to 4 = medium, 5 or more = high. The tool must always print the
breakdown. These weights are frozen before scoring any public log (decided in Stage 6).

## Assumptions fixed by these cases

- **Window:** 60 minutes after the key is created.
- **Baseline:** "usual address" means addresses seen for that account **before the key was created**,
  needing at least `baseline_min_events` earlier events (set to **3** here; the plan said 5 and
  we will settle the final number in Stage 3 once the tool runs).
- **Check 1 alone** gives only a *low* note (score 1). A real alert for review needs medium or
  higher, so evaluation will count medium and above as "alerts".
- Time is UTC. Events may arrive out of order and with duplicates; the quality step fixes this first.

## Cases

| ID | Events | Story | Truth | Checks needed | Expected result |
|---|---|---|---|---|---|
| C01 | 5 | Key for another account, first used from the creator's address | attack | check1, check2 | check1 low (1); check2 high (8) |
| C02 | 1 | Self key, name given | normal | check1 | IGNORED SELF_KEY |
| C03 | 1 | Self key, name left out (AWS uses the caller) | normal | check1 | IGNORED SELF_KEY_IMPLICIT |
| C04 | 1 | Approved automation role creates a key | normal | check1 | IGNORED ALLOW_LISTED_ROLE |
| C05 | 5 | Key handed to bob, bob uses it from his usual address | normal | check1, check2 | check1 low (1); check2 IGNORED SOURCE_ALREADY_SEEN |
| C06 | 5 | Key used within window from a never-seen address | attack | check1, check2 | check1 low (1); check2 high (5) |
| C07 | 5 | Attacker waits 3 hours | attack (known limit) | check1, check2 | check1 low (1); check2 IGNORED OUTSIDE_WINDOW |
| C08 | 2 | Admin rights granted, then a key created | attack | check1, check3 | check1 low (1); check3 medium (4) |
| C09 | 6 | C01 with a duplicate record and wrong order | attack | quality, check1, check2 | same as C01; 1 duplicate removed; reordered |
| C10 | 1 | Key creation refused by AWS | normal | check1 | IGNORED FAILED_CALL |
| C11 | 5 | Event after key creation has an empty key ID | attack | check1, check2 | check1 low (1); check2 NOT_CHECKED MISSING_KEY_ID |

## How the tests use them

- `tests/test_fixtures.py` checks the cases themselves (format, allowed words, points add up, data is synthetic).
- `tests/test_helpers.py` proves the comparison helper works.
- `tests/test_engine_contract.py` runs the tool on every case and compares to the expected answers.
  Cases whose checks are not built yet show as **xfail** (expected to fail), so the test run stays
  green. When you finish a check, add its name to `IMPLEMENTED` in `tests/helpers.py`; from then on
  its cases must really pass.

## The tool's promised entry point (built from Stage 3)

```python
from cloudtrace.engine import analyze
result = analyze(records, config)   # records: list of CloudTrail records
result["verdicts"]                  # list of rows as described above
result["quality"]                   # {"duplicates_removed": int, "reordered": bool, ...}
```

## Rule: labels before code

Expected answers are written first. We never change an expected answer only to make a test pass.
If a case is wrong, we fix the case, explain why in the commit message, and note it in the daily log.

## Added in Stage 3: reason `TARGET_UNKNOWN`

Check 1 returns `NOT_CHECKED / TARGET_UNKNOWN` when the log does not show who a key was made for
(no user name in the request or the reply, and the caller is not an IAM user). No fixture covers it yet; it is
covered by `tests/test_check1.py`. The tool says "not checked" instead of guessing.

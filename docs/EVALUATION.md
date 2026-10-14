# Evaluation method

Goal: measure CloudTrace honestly, next to existing single-event rules, on data whose labels do not
come from the tool being tested. Run everything with:

```
cloudtrace evaluate --out results/eval
```
This writes `results/eval/RESULTS.md` (tables) and `results/eval/results.json` (all numbers).
Same seeds give identical results. A test fails if the committed results are out of date.

## Test tiers
| Tier | What | Labels come from | Status |
|---|---|---|---|
| T1 | 11 hand-made cases (`data/fixtures`) | Written by hand before the code | Done (Stage 1) |
| T2 | Seeded generated logs: normal noise plus injected attacks | The generator (what each scenario was built to be) | Done (Stage 6) |
| T3 | Public log (Stratus Red Team CloudTrail data) | Technique names in the dataset | Stage 7 |
| T4 | Attacker-change tests (mutations M1-M9) | Known by construction | Done (Stage 6) |

## What is judged
- **Unit:** one *scenario* (one key story). A detector *flags* it if it alerts on any event of the story.
- **CloudTrace (medium+)** counts findings of score 3 or more as alerts (bands: 1-2 low, 3-4 medium, 5+ high).
  A Check 1 note alone (score 1) is shown separately as "CloudTrace (any finding)".
- **Metrics:** attacks caught (recall), benign scenarios flagged, precision, false alarms per 1,000 normal
  events, events to review, "not checked" count, and how many B1 alerts on normal events CloudTrace explained.
- **Scoring weights are frozen** (`tests/test_evaluation.py` fails if they change) before any public log is scored.

## Detectors compared
| Name | What it is |
|---|---|
| CloudTrace | This tool: Checks 1-3 with the `ci-deploy` role approved |
| B1 | SigmaHQ "AWS IAM Backdoor Users Keys" (see BASELINES.md) |
| B2 | Elastic "IAM User Created Access Keys For Another User", version 16 (High, risk 73): successful `CreateAccessKey` where caller name differs from target name; skips user agents containing terraform, pulumi or ansible |
| B2 + approved roles excluded | B2 with the same approved role excluded, so the allow-list is compared fairly |
| B3 | Elastic "IAM User Self-Created Access Key Subsequently Used": self-made key, used within one hour (page for 8.19.29) |

All three are re-implementations of the published rule logic, replayed on a whole file. Live scheduling
(runs every 5 minutes, look-back time, 100-alert cap) is not modelled. Rule pages read on 13 Oct 2026;
re-check them before you quote versions in the final report.

## T2 scenarios (per seed; five seeds are added up)
| Kind | Truth | Count | Story |
|---|---|---|---|
| attack_cross_new_ip | attack | 8 | Admin makes a key for a user; first used from an unknown address |
| attack_cross_creator_ip | attack | 8 | Same, first used from the admin's own address |
| attack_grant_key | attack | 8 | Admin rights granted, key made, key used from a new address |
| attack_self_key | attack (outside CloudTrace scope) | 8 | Compromised user makes a key for themselves, uses it from a new address |
| benign_self_rotation | normal | 12 | User rotates their own key and tests it |
| benign_handover_usual_ip | normal | 12 | Key for a colleague, used from their usual address |
| benign_handover_new_ip | normal, look-alike | 6 | Key for a colleague, first used from a new address |
| benign_automation | normal | 8 | Approved automation role makes the key |
| benign_onboarding | normal, look-alike | 4 | New user: admin rights granted, key made, first used from a new address |
| benign_failed | normal | 4 | Key creation refused |
| benign_unused_key | normal | 8 | Key for a colleague, never used |

The mix, and especially the number of look-alike benign cases, are **our assumptions**, not measured real-world rates.
Precision and false alarms move directly with that assumption. The self-made-key attack is included on purpose:
it is what B3 is built for, and CloudTrace does not claim to cover it.

## T4 attacker-change tests
Same attack, changed to dodge detection. Ground truth stays "attack" by construction.
| Change | What changes |
|---|---|
| M1 | Key owner's name sits inside the creator's name (fools a text filter) |
| M2 | Key first used after the window |
| M3 | Key created after the grant window (attack_grant_key only) |
| M4 | Records in random order |
| M5 | Every record duplicated |
| M6 | First-use event has no address or tool name |
| M7 | First use once from the owner's usual address, then from the attacker's |
| M8 | Attacker's address added to the owner's earlier history |
| M9 | Key made through an approved automation role |

### Predictions written before the first run
- Control: CloudTrace, B1 and both B2 variants catch cross-identity attacks; B3 does not; for self-made keys only B3 does.
- M1: only B1 is fooled. M4 and M5: no detector changes its catch (B1/B2 raise duplicate alerts on M5).
- M2, M6, M7, M8: CloudTrace's Check 2 is evaded; Check 1 still gives a low note ("any finding" still catches);
  attack_grant_key is still caught at medium+ because Check 3 does not depend on Check 2. B1/B2 still alert (they do not look at use).
- M3: attack_grant_key is still caught through Check 2.
- M9: CloudTrace and "B2 + approved roles excluded" miss it (they trust the role); B1 and plain B2 still alert.
- Self-made key: only B3 catches it, and only if used within an hour (M2 evades it).
The tool prints every cell where the result differs from these predictions.

## What the first full run shows (see RESULTS.md for the numbers)
- Every measured cell matched the prediction. That confirms the code does what the design says; it does not make
  the design good.
- On T2, all three cross-identity detectors catch every in-scope attack. The difference is in false alarms:
  CloudTrace (medium+) flags far fewer normal scenarios than B1 or B2, and records a reason for those it ignores.
- Where CloudTrace is weaker: patient attackers (M2), a first use from a known address (M7), a poisoned history (M8),
  and approved-role abuse (M9). These are reported, not hidden.
- M6 shows the "do not guess" rule: with the first-use address missing, Check 2 says NOT_CHECKED rather than alerting or staying silent.

## Limits (state these in the report)
- **Circularity.** The attacks are written by us to resemble what the checks look for, so 100% recall on T2 shows the
  code works as designed, not that it finds real attacks. T3 (public data) and T4 reduce this; they do not remove it.
- Synthetic data cannot prove real-world performance.
- Baselines are our re-implementations of published logic, not the vendors' products.
- Only first use is judged by Check 2. Evaluating every use in the window would catch M7; that is a possible Stage 7 decision
  made on these numbers, and any change is re-run through the same tests.

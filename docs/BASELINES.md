# Baselines (existing detection logic we compare against)

A baseline is someone else's detection idea, re-implemented here so CloudTrace can be compared
with it on the same logs. We do not claim to beat commercial tools; we only compare the specific
patterns tested.

## B1 - SigmaHQ "AWS IAM Backdoor Users Keys"

- Source: SigmaHQ rule `rules/cloud/aws/cloudtrail/aws_iam_backdoor_users_keys.yml`
  (id `0a5177f4-6ca9-44c2-aacf-d3f3d8b6e4d2`, author faloker, status test, level medium).
- Logic as published: alert on `CreateAccessKey` from `iam.amazonaws.com`
  **unless** the caller's `userIdentity.arn` contains `responseElements.accessKey.userName`.
- The rule's own false-positive note says the filter cannot cover every naming variant.
- **To do yourself:** open the rule file on GitHub and confirm these lines match
  `src/cloudtrace/baselines.py` before quoting B1 in the report. (I read it on 9 Oct 2026;
  the rule may be updated later.)

### Choices we made (and state openly)
| Choice | Why |
|---|---|
| Case-insensitive name match | Sigma text matching ignores case by default |
| No user name in the reply (for example a failed call) means the filter cannot match, so B1 alerts | The rule text does not say; this is the natural reading |
| B1 reads the raw records: no sorting, no duplicate removal | That is how a single-event rule sees a raw log |
| No allow-list in B1 | The published rule has none |

### Where B1 and Check 1 differ (shown by the hand-made cases)
| Case | B1 | Check 1 | Why |
|---|---|---|---|
| C04 approved automation role | alerts | IGNORED (ALLOW_LISTED_ROLE) | B1 has no allow-list |
| C09 duplicate record | alerts twice | one decision | B1 does not remove duplicates |
| C10 failed call | alerts | IGNORED (FAILED_CALL) | B1 does not look at `errorCode` |
| `admin-a` creates a key for `admin` (unit test) | silent | ALERT | "admin" appears inside the ARN of "admin-a", so B1's text filter hides a real cross-identity key |

## B2 - Elastic "AWS IAM User Created Access Keys For Another User"
- Documentation page read on 13 Oct 2026: rule version 16, severity High, risk score 73, ES|QL, look-back 6 minutes,
  max 100 alerts per run.
- Logic: successful `CreateAccessKey` from `iam.amazonaws.com` where `user.name != user.target.name`;
  skips events whose lower-cased user agent contains terraform, pulumi or ansible.
- **Our choices:** exact (case-sensitive) comparison; if the request names no user the target is empty so nothing is flagged;
  no list of approved roles (so we also show "B2 with the same approved roles excluded"); live scheduling ignored.
- An older page (8.19.9) showed version 8, severity Medium and no user-agent exclusion, so always cite the version.

## B3 - Elastic "AWS IAM User Self-Created Access Key Subsequently Used"
- Documentation page for 8.19.29 read on 13 Oct 2026, ES|QL, 35-minute look-back, max 100 alerts per run.
- Logic: an IAM user creates a key for themselves (user name left out or equal to the caller; new key ID starts with AKIA),
  then any other event signed with that key (not `CreateAccessKey`) occurs after the creation and within 3,600 seconds.
  Grouped by account, user ARN and key ID. No address or user-agent condition.
- **Our choices:** replay on a whole file; first use after first creation; raw records as given.

**To do yourself:** open both Elastic pages and confirm the versions and logic above before quoting them.

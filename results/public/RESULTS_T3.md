# T3: public log result (totals only)

Tool version 1.1.1. Source: Invictus Incident Response, Sigma-AWS (GitHub), MIT licence. The log files are not stored in this repository and nothing from them (accounts, users, addresses, event IDs) is printed here.

## The log

- Files read: 55; records read: 2900; usable: 2900
- Time range: 2023-07-10T11:42:18Z to 2023-07-10T12:37:50Z
- Duplicates removed: 0; out of order: yes
- Missing fields: userIdentity.accessKeyId (85), userIdentity.arn (77)
- Successful key creations: 2 (labelled attacks: 2; not labelled: 0)
- Keys followed: 2; never used later in the log: 2
- Labelled techniques: aws.persistence.iam-backdoor-user, aws.persistence.iam-create-admin-user

## Result

| Detector | Labelled attacks caught | Other key creations flagged |
|---|---|---|
| CloudTrace (medium+) | 1/2 | 0 |
| CloudTrace (any finding) | 2/2 | 0 |
| B1 Sigma | 2/2 | 0 |
| B2 Elastic cross-user | 2/2 | 0 |
| B2 + approved roles excluded | 2/2 | 0 |
| B3 Elastic self-key used | 0/2 | 0 |

## What CloudTrace decided (counts)

- ALERT GRANT_THEN_CREDENTIAL: 1
- ALERT KEY_FOR_OTHER_ACCOUNT: 2

## Reading this honestly

- Only 2 labelled key creations exist in this log. Percentages would mislead, so counts are shown.
- The log contains attack techniques only. It has no normal key stories, so precision and false alarms cannot be measured from it; that is what the generated logs (T2) are for.
- A key that is never used later in the log gives Check 2 nothing to judge, so it can only reach medium through Check 3.
- Labels come from the Stratus Red Team technique pages, not from any detector. B1, B2 and B3 are re-implementations of published rule logic.
- The log was first opened to check its format. No setting or weight was changed afterwards.

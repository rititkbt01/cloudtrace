# Public data (T3)

CloudTrace is also scored on one public log, so the results do not rest only on logs we made ourselves.

## Source and licence
- **Dataset:** Sigma-AWS by Invictus Incident Response (https://github.com/invictus-ir/Sigma-AWS), folder `CloudTrail`.
  It holds CloudTrail records produced by running the AWS techniques of Stratus Red Team.
- **Licence:** MIT (stated in the repository's LICENSE file). Copyright 2023 Invictus Incident Response.
- **Version used:** commit `f0d55993fb575f747cee13069adeaa999c940b14` (12 July 2023).
- **Size:** 55 files, 2,900 records, about 55 minutes of activity on 10 July 2023.

## Rules we follow
- The log files are **downloaded by you and kept outside Git**: they go in `data/public/`, which `.gitignore` excludes.
  The MIT licence would allow copying, but the records contain real-looking account numbers, user names and addresses, so we do not.
- The program only reads them. Nothing is changed and nothing is sent anywhere.
- The result file contains **totals only**: no account number, user name, address or event ID from the log.

## How to run it
```
git clone https://github.com/invictus-ir/Sigma-AWS data/public/Sigma-AWS
git -C data/public/Sigma-AWS checkout f0d55993fb575f747cee13069adeaa999c940b14
cloudtrace evaluate-public data/public/Sigma-AWS/CloudTrail --out results/public
```
The same command on the same commit always writes the same `results/public/RESULTS_T3.md`.

## How the labels were made
The labels come from the Stratus Red Team technique pages, not from any detector, and were fixed before scoring:
- `aws.persistence.iam-backdoor-user`: another identity creates an access key for the user `stratus-red-team-backdoor-u-user`.
- `aws.persistence.iam-create-admin-user`: a user `malicious-iam-user` is given AdministratorAccess and an access key.

Both are attacks. The log contains no other successful key creation and no normal key stories.

## What this result can and cannot show
- It shows that the tool reads real-format CloudTrail files and handles the data quality problems they contain
  (records out of order, missing fields).
- With only two labelled key creations it is a **spot check**, not a measurement of detection rates.
- It cannot measure false alarms, because the log has no normal key stories.
- The log was first opened to check its format. No setting or weight was changed afterwards.

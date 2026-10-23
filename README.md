# CloudTrace

**CloudTrace reads cloud activity logs, finds risky changes to access keys, and explains every decision.**
It is a small, free, read-only Python tool made for the CyberFox Society Cybersecurity R&D Internship
(project area: Security Operations & Detection Engineering). Version 1.0.0.

## The problem in plain words

An *access key* is a secret code that lets a program sign in to a cloud account. When an attacker gets into
an account, one common trick is to create a new key for some account, so they can come back later even
after the first break-in is found. Existing detection rules can flag "a key was created", but they look
at one log line at a time, raise many false alarms on normal administrator work, and do not explain
themselves.

CloudTrace follows each new key from the moment it is created to its first use, applies three simple checks,
and **gives a reason for every decision**, including the decisions not to alert.

## Quick start (about five minutes, no cloud account needed)

Python 3.11 or newer is needed.

```
python -m venv .venv
.venv\Scripts\activate            # Windows (Git Bash: source .venv/Scripts/activate)
pip install -r requirements-dev.txt
pip install -e .
pytest -q                          # all tests should pass
cloudtrace analyze data/fixtures/c01_attack_key_for_other_used_from_creator_source/events.json
```

You will see a report like this (made-up data):

```
[HIGH] KEY_USED_FROM_NEW_SOURCE - event c01-005
Why: The key made for svc-b was first used 4.0 minutes after it was created, from 203.0.113.10,
     an address svc-b did not use in the 3 earlier events of this log. It is the same address
     that created the key.
Score: 8 (cross_identity 1, first_use_in_window 2, new_source 2, creator_source 3)
Next step for a person: Check with the key's owner whether the new address is theirs. ...
```

More commands, options and exit codes are in [docs/USAGE.md](docs/USAGE.md).

## The three checks

| Check | Question | Result |
|---|---|---|
| 1 | Did one identity create an access key for a *different* identity? | Low note only (too common alone) |
| 2 | Was that key used, within 60 minutes, from an address its owner never used earlier in the log? | Adds evidence; high if used from the creator's own address |
| 3 | Was the account given administrator rights just before the key was created? | Medium |

Severity is a sum of named evidence points that are printed in the report. There is no machine learning.
When the log does not contain what a check needs, the result is **NOT_CHECKED** with a reason; the tool never guesses.

## What was measured

All numbers are in `results/`. Details and caveats are in [docs/EVALUATION.md](docs/EVALUATION.md).

- **Generated logs (430 stories, 5 seeds):** CloudTrace caught 120 of 120 in-scope attacks and wrongly flagged
  50 of 270 normal stories. Rules rebuilt from SigmaHQ and Elastic caught the same attacks but flagged 150 to 210.
- **Attacker-change tests:** CloudTrace still caught the attack when records were shuffled or duplicated, or when an
  attacker hid the owner's name inside the creator's name or first used the key from the owner's usual address. It was
  evaded by waiting past the window, by hiding the address (it says "not checked"), by planting an address in the
  owner's history, and by using an approved automation role.
- **Public log (Stratus Red Team data, 2 attacks):** CloudTrace caught 1 of 2 at medium or above, and both when
  low notes are counted. The log has no normal key stories, so it is a spot check only.
- **Settings:** the 60-minute window and 3-event history were fixed in advance; [results/eval/SENSITIVITY.md](results/eval/SENSITIVITY.md) shows how results change with them.

## Limits (please read)

- Generated attacks resemble what the checks look for, so good results on them show the code works as designed,
  not that it finds real attacks. Real-world performance is **not** claimed.
- "New address" means new *in the log you give it*; a short log makes many things look new.
- A key that is made but never used gets only a low note from Check 1 (Check 3 is the only way to reach medium).
- The rebuilt comparison rules are re-implementations of published logic on a whole file, not the vendors' products.
- A finding means "please review", never "attack confirmed". No finding does not mean safe.

## Safety and ethics

Only made-up data and one openly licensed public log are used. The tool only reads files, never connects to
a cloud account and never changes anything. Nothing from the public log is stored in this repository.
See [ETHICS.md](ETHICS.md).

## What is in this folder

| Folder or file | What it holds |
|---|---|
| `src/cloudtrace` | The program |
| `tests` | Automated tests (including a scanner for credential-like text and real-looking data) |
| `data/fixtures` | 11 hand-made test cases, each with the expected answer, written before the code |
| `rules/default.toml` | The four settings: time window, history needed, approved roles, strong-rights list |
| `docs` | One page per check, test cases, data quality, comparison rules, usage, evaluation, public data |
| `results` | Example reports, evaluation tables, and the public-log totals |

## Re-creating the results

```
cloudtrace evaluate --out results/eval
cloudtrace evaluate-public data/public/Sigma-AWS/CloudTrail --out results/public   # needs the download in docs/PUBLIC_DATA.md
```

The same seeds always give the same numbers.

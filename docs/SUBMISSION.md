# Submission checklist and evidence

## Reproduce the corrected project

Use Python 3.11 or newer. Create a virtual environment and activate it:

```sh
python -m venv .venv
```

Linux/macOS:

```sh
source .venv/bin/activate
```

Windows Git Bash:

```sh
source .venv/Scripts/activate
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Then:

```sh
python -m pip install -r requirements-dev.txt
python -m pip install -e .
python -m pytest -q
python -m ruff check .
cloudtrace analyze data/fixtures/c01_attack_key_for_other_used_from_creator_source/events.json
cloudtrace tune data/fixtures/c07_attack_use_delayed_past_window/events.json
cloudtrace evaluate --out results/eval
```

The public evaluation is separate. Download the pinned dataset using docs/PUBLIC_DATA.md, then:

```sh
cloudtrace evaluate-public data/public/Sigma-AWS/CloudTrail --out results/public
```

From a fresh checkout, run python tools/fresh_check.py. It creates a temporary environment,
installs dependencies and the package, runs tests/lint/demo/tuning, and compares generated tables.
Use its actual result, date, OS and Python version; a script's existence is not a successful run.

## Report and presentation updates

- State version 1.1.1, the exact passing test count, and the final Git commit/release link.
- Replace the GitHub and fresh-check placeholders with actual evidence.
- Explain that the implemented scope is narrower than the original brief: Checks 2 and 3 require
  cross-identity creation; Check 2 judges IP only; Check 3 covers AttachUserPolicy then access-key
  creation, not inline/group policies or login profiles. The proposed MFA score is not implemented.
- Distinguish in-scope synthetic recall (120/120) from overall synthetic recall (120/160), subject
  to the regenerated results. Self-created-key attacks remain outside the implemented checks.
- Label precision as story-level and the normalized false-alarm count as event-level. Explain
  that B3 precision includes its 40 detected self-created-key attacks.
- Include the Check 2 v2 trade-off study. It measures synthetic cost, not real-world frequency.
- Describe the public data as attack simulation with no labelled benign key stories. A missing
  observed use is limited by the file's observation period.
- Update slide notes as well as visible slides. Standardize the intern's official name.
- Do not claim measured analyst time savings, complete ablations, independent holdout testing,
  confidence intervals or production readiness. See docs/EVALUATION.md.

The corrected source does not change the previously uploaded Word report or PowerPoint deck.
Those artifacts must be aligned with the final verification evidence before submission.

## Apply the corrected source to the existing GitHub repository

Keep the existing checkout and its history. Copy the corrected project files over it, including
.github/workflows/ci.yml. The source archive deliberately omits .git, virtual environments, caches
and public dataset logs. Review git status and git diff, run the commands above, then commit and
push. Do not replace the existing .git directory. Choose the final release tag after the checks pass.

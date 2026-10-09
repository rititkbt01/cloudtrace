# Using CloudTrace

## One-time setup (in the project folder, venv active)
```
pip install -e .
```
This installs the `cloudtrace` command. Without it you can still run `python -m cloudtrace ...` from
the project folder with `PYTHONPATH=src` set.

## Analyze a log
```
cloudtrace analyze data/fixtures/c01_attack_key_for_other_used_from_creator_source/events.json
```
Prints a readable report. Useful options:

| Option | Meaning |
|---|---|
| `--out results/c01` | Write `report.md` and `report.json` into that folder |
| `--format json` | Print JSON instead of the readable report (when `--out` is not used) |
| `--config rules/default.toml` | Use your own settings (window, approved roles, ...) |
| `--no-baseline` | Leave out the comparison with the single-event rule B1 |
| `--fail-on medium` | Exit with code 1 if any finding is medium or higher (for scripts and CI) |

The input can be a `.json` / `.json.gz` CloudTrail file or a folder of them.

## Exit codes
`0` finished, `1` findings at or above `--fail-on`, `2` a problem with the input or settings
(a plain message is printed, no traceback).

## What the report contains
Summary counts, findings to review (with score breakdown and a next step for a person), the full
decision record (why each candidate did or did not alert), log quality, key history, and the
comparison with B1. The same input always gives the same report.

## Safety
CloudTrace only reads the files you give it. It never connects to a cloud account and never
changes the input. Use only synthetic or properly licensed public logs (see ETHICS.md).

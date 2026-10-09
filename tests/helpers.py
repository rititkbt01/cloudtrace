"""Shared helpers for the fixture tests."""
import json
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "data" / "fixtures"

# Checks that are built. Add a name here when you finish building that check.
# Stage 3 adds "quality" and "check1"; Stage 5 adds "check2" and "check3".
IMPLEMENTED = set()

SEVERITY_BANDS = {"low": (1, 2), "medium": (3, 4), "high": (5, 99)}


def case_dirs():
    return sorted(p for p in FIXTURES.iterdir() if p.is_dir())


def load_case(case_dir):
    case = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    raw = json.loads((case_dir / "events.json").read_text(encoding="utf-8"))
    # Same layout as a real CloudTrail log file: {"Records": [ ... ]}
    return case, raw["Records"]


def _key(v):
    return (v["check"], v["event_id"])


def compare(expected_verdicts, actual_verdicts, implemented):
    """Return a list of problems. Empty list means the tool matched the expected results.

    Only checks listed in `implemented` are compared.
    A missing verdict, an extra verdict, or any different field is a problem.
    """
    exp = {_key(v): v for v in expected_verdicts if v["check"] in implemented}
    act = {_key(v): v for v in actual_verdicts if v["check"] in implemented}
    problems = []
    for k in sorted(exp.keys() - act.keys()):
        problems.append(f"missing verdict {k}")
    for k in sorted(act.keys() - exp.keys()):
        problems.append(f"unexpected verdict {k}")
    for k in sorted(exp.keys() & act.keys()):
        for field, want in exp[k].items():
            got = act[k].get(field)
            if got != want:
                problems.append(f"{k} field '{field}': expected {want!r}, got {got!r}")
    return problems

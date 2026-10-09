"""The contract: for every hand-made case, the tool must produce exactly the expected verdicts.

Only the parts that are built (listed in helpers.IMPLEMENTED) are compared, and they must match
exactly. If a case also needs parts that are not built yet, it is then marked 'xfail'
(expected to fail), so the test run stays green while still showing what is left to do.
When you build a check, add it to IMPLEMENTED; from then on its cases must really pass.
"""
import pytest
from helpers import IMPLEMENTED, case_dirs, compare, load_case

from cloudtrace.engine import analyze

CASES = case_dirs()


@pytest.mark.parametrize("cdir", CASES, ids=[c.name for c in CASES])
def test_engine_matches_expected(cdir):
    case, events = load_case(cdir)
    needed = set(case["applies_to_checks"])
    built = needed & IMPLEMENTED
    if built:
        result = analyze(events, case["config"])
        problems = compare(case["expected"]["verdicts"], result["verdicts"], IMPLEMENTED)
        want_quality = case["expected"].get("quality")
        if want_quality and "quality" in IMPLEMENTED:
            for k, want in want_quality.items():
                got = result["quality"].get(k)
                if got != want:
                    problems.append(f"quality '{k}': expected {want!r}, got {got!r}")
        assert not problems, "; ".join(problems)
    if needed - IMPLEMENTED:
        pytest.xfail(f"not built yet: {sorted(needed - IMPLEMENTED)}")

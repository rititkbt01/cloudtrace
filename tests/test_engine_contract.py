"""The contract: for every hand-made case, the tool must produce exactly the expected verdicts.

Until a check is built (listed in helpers.IMPLEMENTED) its cases are marked 'xfail'
(expected to fail). That keeps the test run green while still showing what is left to do.
When you build a check, add it to IMPLEMENTED and its cases must then really pass.
"""
import pytest
from helpers import IMPLEMENTED, case_dirs, compare, load_case

CASES = case_dirs()


@pytest.mark.parametrize("cdir", CASES, ids=[c.name for c in CASES])
def test_engine_matches_expected(cdir):
    case, events = load_case(cdir)
    needed = set(case["applies_to_checks"])
    if not needed <= IMPLEMENTED:
        pytest.xfail(f"not built yet: {sorted(needed - IMPLEMENTED)}")
    from cloudtrace.engine import analyze

    result = analyze(events, case["config"])
    problems = compare(case["expected"]["verdicts"], result["verdicts"], IMPLEMENTED)
    q = case["expected"].get("quality")
    if q and "quality" in IMPLEMENTED:
        for k, want in q.items():
            if result["quality"].get(k) != want:
                problems.append(f"quality '{k}': expected {want!r}, got {result['quality'].get(k)!r}")
    assert not problems, "; ".join(problems)

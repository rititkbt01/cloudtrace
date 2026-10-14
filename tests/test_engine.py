import copy

from helpers import case_dirs, load_case

from cloudtrace.engine import analyze


def test_result_has_all_parts():
    case, records = load_case(next(c for c in case_dirs() if c.name.startswith("c01")))
    result = analyze(records, case["config"])
    assert set(result) == {"verdicts", "quality", "key_history", "config"}
    assert result["quality"]["total_records"] == 5
    assert len(result["key_history"]) == 1


def test_input_is_not_modified():
    case, records = load_case(next(c for c in case_dirs() if c.name.startswith("c09")))
    before = copy.deepcopy(records)
    analyze(records, case["config"])
    assert records == before


def test_same_input_gives_same_output():
    case, records = load_case(next(c for c in case_dirs() if c.name.startswith("c06")))
    assert analyze(records, case["config"]) == analyze(records, case["config"])


def test_c09_gives_same_check1_decision_as_c01():
    def check1(prefix):
        case, records = load_case(next(c for c in case_dirs() if c.name.startswith(prefix)))
        return [(v["verdict"], v["reason"], v["score"])
                for v in analyze(records, case["config"])["verdicts"]]
    assert check1("c09") == check1("c01")


def test_c01_is_high_and_c05_is_not():
    def top(prefix):
        case, records = load_case(next(c for c in case_dirs() if c.name.startswith(prefix)))
        rows = analyze(records, case["config"])["verdicts"]
        return max((r["score"] for r in rows if r["verdict"] == "ALERT"), default=0)
    assert top("c01") == 8 and top("c06") == 5 and top("c08") == 4 and top("c05") == 1


def test_rows_are_in_time_order():
    case, records = load_case(next(c for c in case_dirs() if c.name.startswith("c09")))
    times = [r["evidence"]["time"] for r in analyze(records, case["config"])["verdicts"]]
    assert times == sorted(times)

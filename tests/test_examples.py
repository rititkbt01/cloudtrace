"""The sample reports in results/examples must match what the tool produces today."""
import json

import pytest
from helpers import FIXTURES

from cloudtrace import report
from cloudtrace.ingest import load_records

EXAMPLES = FIXTURES.parent.parent / "results" / "examples"


@pytest.mark.parametrize("edir", sorted(EXAMPLES.iterdir()), ids=lambda p: p.name)
def test_example_reports_are_up_to_date(edir):
    case = json.loads((FIXTURES / edir.name / "case.json").read_text(encoding="utf-8"))
    built = report.build(load_records(FIXTURES / edir.name / "events.json"), case["config"],
                         input_name=f"{edir.name}/events.json")
    assert (edir / "report.md").read_text(encoding="utf-8") == report.to_markdown(built)
    assert (edir / "report.json").read_text(encoding="utf-8") == report.to_json(built)

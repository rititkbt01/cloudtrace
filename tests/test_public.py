"""T3 runner: totals only, labels from a table, nothing from the log is copied into the output."""
import json
import shutil

import pytest
from helpers import FIXTURES

from cloudtrace import cli
from cloudtrace.evaluation import public

C08 = FIXTURES / "c08_attack_admin_grant_then_key" / "events.json"
C05 = FIXTURES / "c05_normal_handover_used_from_usual_source" / "events.json"
LABELS = {"svc-b": "made-up technique"}


@pytest.fixture
def folder(tmp_path):
    d = tmp_path / "log"
    d.mkdir()
    shutil.copy(C08, d / "a.json")
    return d


def test_labelled_attack_is_counted(folder):
    t3 = public.run_t3(folder, techniques=LABELS)
    assert t3["records"] == 2 and t3["key_creations"] == 1 and t3["labelled_attacks"] == 1
    assert t3["detectors"]["ct"]["caught"] == 1       # Check 3 gives medium
    assert t3["detectors"]["b1"]["caught"] == 1
    assert t3["detectors"]["b3"]["caught"] == 0
    assert t3["techniques"] == ["made-up technique"]


def test_unlabelled_key_creations_are_not_counted_as_attacks(folder):
    t3 = public.run_t3(folder, techniques={})
    assert t3["labelled_attacks"] == 0 and t3["other_key_creations"] == 1
    assert t3["detectors"]["b1"]["other_key_creations_flagged"] == 1


def test_key_never_used_is_reported(folder):
    t3 = public.run_t3(folder, techniques=LABELS)
    assert t3["keys_tracked"] == 1 and t3["keys_never_used"] == 1


def test_output_contains_totals_only(folder, tmp_path):
    out = tmp_path / "out"
    public.run(folder, out)
    text = (out / "RESULTS_T3.md").read_text(encoding="utf-8")
    raw = C08.read_text(encoding="utf-8")
    for secret in ("123456789012", "203.0.113", "admin-a", "svc-b"):
        assert secret in raw      # the input really contains them ...
        assert secret not in text  # ... and the output never does


def test_same_input_same_output(folder, tmp_path):
    public.run(folder, tmp_path / "a")
    public.run(folder, tmp_path / "b")
    assert (tmp_path / "a" / "RESULTS_T3.md").read_text(encoding="utf-8") == \
        (tmp_path / "b" / "RESULTS_T3.md").read_text(encoding="utf-8")


def test_command_writes_file(folder, tmp_path, capsys):
    code = cli.main(["evaluate-public", str(folder), "--out", str(tmp_path / "o")])
    assert code == 0 and (tmp_path / "o" / "RESULTS_T3.md").exists()
    assert "records" in capsys.readouterr().out


def test_command_reports_missing_folder(tmp_path, capsys):
    code = cli.main(["evaluate-public", str(tmp_path / "nope")])
    assert code == 2 and "cloudtrace:" in capsys.readouterr().err


def test_normal_case_has_no_labelled_attack(tmp_path):
    d = tmp_path / "n"
    d.mkdir()
    shutil.copy(C05, d / "a.json")
    t3 = public.run_t3(d, techniques=LABELS)
    assert t3["labelled_attacks"] == 0
    json.dumps(t3)  # plain numbers and text only

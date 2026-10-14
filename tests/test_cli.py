import json

import pytest
from helpers import FIXTURES, case_dirs

from cloudtrace import cli

C01 = next(c for c in case_dirs() if c.name.startswith("c01")) / "events.json"


def test_prints_markdown_by_default(capsys):
    assert cli.main(["analyze", str(C01)]) == 0
    assert "# CloudTrace report" in capsys.readouterr().out


def test_prints_json_when_asked(capsys):
    assert cli.main(["analyze", str(C01), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["tool"] == "cloudtrace"


def test_writes_both_report_files(tmp_path, capsys):
    out = tmp_path / "results"
    assert cli.main(["analyze", str(C01), "--out", str(out)]) == 0
    assert (out / "report.md").read_text(encoding="utf-8").startswith("# CloudTrace report")
    assert json.loads((out / "report.json").read_text(encoding="utf-8"))["input"] == "events.json"
    assert "Report written" in capsys.readouterr().out


def test_input_file_is_not_changed(tmp_path):
    before = C01.read_bytes()
    cli.main(["analyze", str(C01), "--out", str(tmp_path)])
    assert C01.read_bytes() == before


def test_missing_file_exits_2_with_message_not_traceback(capsys):
    assert cli.main(["analyze", "no_such_file.json"]) == 2
    assert "does not exist" in capsys.readouterr().err


def test_bad_config_exits_2(tmp_path, capsys):
    bad = tmp_path / "bad.toml"
    bad.write_text("window_minutes = 0\n")
    assert cli.main(["analyze", str(C01), "--config", str(bad)]) == 2
    assert "window_minutes" in capsys.readouterr().err


def test_config_file_is_used(tmp_path, capsys):
    cfg = tmp_path / "c.toml"
    cfg.write_text('allowed_roles = ["ci-deploy"]\n')
    c04 = next(c for c in case_dirs() if c.name.startswith("c04")) / "events.json"
    assert cli.main(["analyze", str(c04), "--config", str(cfg), "--format", "json"]) == 0
    verdicts = json.loads(capsys.readouterr().out)["verdicts"]
    assert verdicts[0]["reason"] == "ALLOW_LISTED_ROLE"


def test_default_settings_file_is_valid(capsys):
    default = FIXTURES.parent.parent / "rules" / "default.toml"
    assert cli.main(["analyze", str(C01), "--config", str(default)]) == 0


C05 = next(c for c in case_dirs() if c.name.startswith("c05")) / "events.json"


@pytest.mark.parametrize("path,level,code", [
    (C05, "low", 1), (C05, "medium", 0), (C05, "high", 0),  # C05 has only a low finding
    (C01, "low", 1), (C01, "medium", 1), (C01, "high", 1),  # C01 has a high finding
])
def test_fail_on(path, level, code):
    assert cli.main(["analyze", str(path), "--fail-on", level]) == code


def test_no_findings_never_fails():
    c02 = next(c for c in case_dirs() if c.name.startswith("c02")) / "events.json"
    assert cli.main(["analyze", str(c02), "--fail-on", "low"]) == 0


def test_no_baseline_flag(capsys):
    cli.main(["analyze", str(C01), "--no-baseline"])
    assert "single-event rule" not in capsys.readouterr().out

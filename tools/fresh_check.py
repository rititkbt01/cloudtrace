"""Fresh-environment check for CloudTrace.

Run it inside a NEW clone of the repository, with nothing installed yet:

    git clone <your repository URL> cloudtrace_fresh
    cd cloudtrace_fresh
    python tools/fresh_check.py

It builds a brand-new virtual environment in a temporary folder, installs the project from
scratch (pip needs the internet), then runs the tests, the style check and the main commands,
and compares the regenerated result tables with the committed ones. It prints PASS or FAIL for
every step and writes the summary to fresh_check_result.txt (OS, Python version, date; no
personal paths). It changes nothing outside the temporary folder and that one file.

Option --skip-install uses the Python you started it with instead of a new environment. It is only
for trying the script itself; it is not a fresh-environment test.
"""
import argparse
import datetime
import os
import platform
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
C01 = "data/fixtures/c01_attack_key_for_other_used_from_creator_source/events.json"
RESULT_FILES = ("RESULTS.md", "results.json", "SENSITIVITY.md", "DELAY.md", "CHECK2_COST.md")


def run(cmd, cwd=ROOT):
    """Run a command; return (exit code, combined output as text)."""
    done = subprocess.run([str(c) for c in cmd], cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", check=False,
                          env={**os.environ, "PYTHONUTF8": "1"})
    return done.returncode, (done.stdout or "") + (done.stderr or "")


def venv_python(folder: Path) -> Path:
    return folder / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


class Report:
    def __init__(self):
        self.rows = []

    def step(self, name: str, ok: bool, note: str = ""):
        self.rows.append((name, ok, note))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({note})" if note else ""), flush=True)
        return ok

    @property
    def passed(self) -> bool:
        return all(ok for _, ok, _ in self.rows)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fresh-environment check for CloudTrace")
    ap.add_argument("--skip-install", action="store_true",
                    help="use this Python instead of a new environment (not a fresh test)")
    args = ap.parse_args(argv)
    rep = Report()
    rep.step("Python is 3.11 or newer", sys.version_info >= (3, 11), platform.python_version())
    need = ("pyproject.toml", "requirements-dev.txt", "README.md", "ETHICS.md", "rules/default.toml",
            C01)
    missing = [n for n in need if not (ROOT / n).is_file()]
    rep.step("Key files are in the clone", not missing, "missing: " + ", ".join(missing)
             if missing else "")
    req = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8").lower() \
        if (ROOT / "requirements-dev.txt").is_file() else ""
    rep.step("requirements-dev.txt lists pytest and ruff", "pytest" in req and "ruff" in req)

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        if args.skip_install:
            py = Path(sys.executable)
        else:
            venv.EnvBuilder(with_pip=True, clear=True).create(tmp / "venv")
            py = venv_python(tmp / "venv")
            code, out = run([py, "-m", "pip", "install", "-r", "requirements-dev.txt"])
            rep.step("pip install -r requirements-dev.txt", code == 0, "" if code == 0 else out[-300:])
            code, out = run([py, "-m", "pip", "install", "-e", "."])
            rep.step("pip install -e . (installs the cloudtrace command)", code == 0,
                     "" if code == 0 else out[-300:])
        code, out = run([py, "-m", "cloudtrace", "--help"])
        rep.step("cloudtrace --help", code == 0 and "analyze" in out)
        code, out = run([py, "-m", "pytest", "-q"])
        tail = out.strip().splitlines()[-1] if out.strip() else ""
        rep.step("pytest -q (all tests)", code == 0, tail)
        code, out = run([py, "-m", "ruff", "check", "."])
        rep.step("ruff check . (style)", code == 0, out.strip().splitlines()[-1] if out.strip() else "")
        code, out = run([py, "-m", "cloudtrace", "analyze", C01])
        rep.step("analyze sample case C01 (expects a HIGH finding)", code == 0 and "[HIGH]" in out)
        code, out = run([py, "-m", "cloudtrace", "analyze", C01, "--fail-on", "high"])
        rep.step("analyze --fail-on high exits with code 1 on C01", code == 1 and "[HIGH]" in out)
        c07 = next((ROOT / "data/fixtures").glob("c07*/events.json"), None)
        example = ROOT / "results/tune/c07_tune.md"
        if c07 and example.is_file():
            code, out = run([py, "-m", "cloudtrace", "tune", c07])
            rep.step("tune on case C07 matches the committed example",
                     code == 0 and out == example.read_text(encoding="utf-8"))
        else:
            rep.step("tune on case C07 matches the committed example", False, "files missing")
        out_dir = tmp / "eval"
        code, _ = run([py, "-m", "cloudtrace", "evaluate", "--out", out_dir])
        rep.step("evaluate runs", code == 0)
        for name in RESULT_FILES:
            fresh, kept = out_dir / name, ROOT / "results/eval" / name
            same = (fresh.is_file() and kept.is_file()
                    and fresh.read_text(encoding="utf-8") == kept.read_text(encoding="utf-8"))
            rep.step(f"regenerated {name} equals the committed file", same)

    verdict = "ALL STEPS PASSED" if rep.passed else "SOME STEPS FAILED"
    lines = [f"CloudTrace fresh-environment check: {verdict}",
             f"Date: {datetime.datetime.now(datetime.UTC).date().isoformat()}   OS: {platform.system()} {platform.release()}"
             f"   Python: {platform.python_version()}"
             + ("   (--skip-install: NOT a fresh environment)" if args.skip_install else ""), ""]
    lines += [f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({note})" if note else "")
              for name, ok, note in rep.rows]
    text = "\n".join(lines) + "\n"
    (ROOT / "fresh_check_result.txt").write_text(text, encoding="utf-8")
    print("\n" + lines[0] + "\nSummary written to fresh_check_result.txt")
    return 0 if rep.passed else 1


if __name__ == "__main__":
    sys.exit(main())

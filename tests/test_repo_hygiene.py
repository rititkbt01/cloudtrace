"""Repository hygiene: no credential-like text, no real-looking data, no public log in Git.

This is the project's secret scanner. It runs with every `pytest` (and so on every GitHub push).
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache", "node_modules",
             "build", "dist"}
TEXT_SUFFIXES = {".py", ".md", ".json", ".toml", ".yml", ".yaml", ".txt", ".cfg", ".ini"}

ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b")
SECRET_KEY = re.compile(r"(?i)secret[_-]?(?:access[_-]?)?key[\"'\s:=]+[A-Za-z0-9/+=]{40}\b")
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
TOKENS = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|xox[baprs]-[A-Za-z0-9-]{10,})\b")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ACCOUNT_ID = re.compile(r"(?<!\d)\d{12}(?!\d)")
DOC_RANGES = ("192.0.2.", "198.51.100.", "203.0.113.")
MADE_UP_ACCOUNT = "123456789012"


def secrets_in(text: str) -> list[str]:
    """Credential-like strings. Made-up keys must contain the word EXAMPLE (AWS's own convention)."""
    found = [m for m in ACCESS_KEY.findall(text) if "EXAMPLE" not in m]
    found += [m.group(0) for m in SECRET_KEY.finditer(text) if "EXAMPLE" not in m.group(0)]
    found += PRIVATE_KEY.findall(text) + TOKENS.findall(text)
    return found


def real_looking_data_in(text: str) -> list[str]:
    """Addresses outside the three documentation ranges, and account numbers other than the made-up one."""
    found = [ip for ip in IPV4.findall(text) if not ip.startswith(DOC_RANGES)]
    found += [a for a in ACCOUNT_ID.findall(text) if a != MADE_UP_ACCOUNT]
    return found


def _all_text_files():
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT)
        if (path.is_file() and path.suffix in TEXT_SUFFIXES and not set(rel.parts) & SKIP_DIRS
                and rel.parts[:2] != ("data", "public")
                and not any(part.endswith(".egg-info") for part in rel.parts)):
            yield path


def test_scanner_catches_a_real_looking_key():
    fake = "AKIA" + "ABCDEFGHIJKLMNOP"
    assert secrets_in(f"key = {fake}") == [fake]
    assert secrets_in("key = AKIAEXAMPLENEWKEY01") == []
    assert secrets_in("-----BEGIN " + "RSA PRIVATE KEY-----") != []
    token = "ghp_" + "a" * 36
    assert secrets_in(token) == [token]


def test_scanner_catches_real_looking_data():
    assert real_looking_data_in("from 8.8.8.8") == ["8.8.8.8"]
    assert real_looking_data_in("from 203.0.113.10 account 123456789012") == []
    assert real_looking_data_in("account 218000000000") == ["218000000000"]


def test_no_credential_like_text_anywhere():
    bad = {str(p.relative_to(ROOT)): secrets_in(p.read_text(encoding="utf-8", errors="ignore"))
           for p in _all_text_files()}
    assert {k: v for k, v in bad.items() if v} == {}


def test_results_and_data_hold_only_made_up_values():
    bad = {}
    for folder in ("results", "data"):
        for path in (ROOT / folder).rglob("*"):
            rel = path.relative_to(ROOT)
            if path.is_file() and path.suffix in TEXT_SUFFIXES and rel.parts[:2] != ("data", "public"):
                hits = real_looking_data_in(path.read_text(encoding="utf-8", errors="ignore"))
                if hits:
                    bad[str(rel)] = hits[:3]
    assert bad == {}


def test_public_log_is_ignored_by_git():
    gitignore = ROOT / ".gitignore"
    if not gitignore.exists():
        pytest.skip("no .gitignore in this copy")
    assert "data/public" in gitignore.read_text(encoding="utf-8")


def test_no_public_log_file_is_tracked():
    if not (ROOT / ".git").exists() or shutil.which("git") is None:
        pytest.skip("not a Git checkout")
    done = subprocess.run(["git", "ls-files", "--", "data/public"], cwd=ROOT, capture_output=True,
                          text=True, timeout=30, check=False)
    if done.returncode != 0:
        pytest.skip("git could not list files")
    assert done.stdout.strip() == ""

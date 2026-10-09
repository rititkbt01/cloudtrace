"""Step 1: read CloudTrace input files into a plain list of records.

Accepted input:
  * a CloudTrail file:   {"Records": [ ... ]}    (.json or .json.gz)
  * a plain list file:   [ ... ]                  (.json or .json.gz)
  * a folder containing such files (read in file-name order)

This step only reads. It does not judge, sort or clean anything (that is quality.py).
The tool is read-only: it never writes to or changes the input files.
"""
import gzip
import json
from pathlib import Path


class IngestError(Exception):
    """The input could not be read. The message is written for a human."""


def _read_one(path: Path) -> list:
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as f:
                text = f.read()
        else:
            text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, EOFError, gzip.BadGzipFile) as err:
        raise IngestError(f"Cannot read {path.name}: {err}") from err
    try:
        data = json.loads(text)
    except json.JSONDecodeError as err:
        raise IngestError(f"{path.name} is not valid JSON (line {err.lineno}): {err.msg}") from err
    if isinstance(data, dict):
        if "Records" not in data:
            raise IngestError(f'{path.name}: expected a "Records" list but none was found')
        data = data["Records"]
    if not isinstance(data, list):
        raise IngestError(f"{path.name}: expected a list of records")
    return data


def load_records(path) -> list:
    """Return all records found at `path` (a file or a folder) as a list."""
    path = Path(path)
    if not path.exists():
        raise IngestError(f"Path does not exist: {path}")
    if path.is_dir():
        files = sorted(p for p in path.iterdir() if p.name.endswith((".json", ".json.gz")))
        if not files:
            raise IngestError(f"No .json or .json.gz files found in {path}")
        records = []
        for f in files:
            records.extend(_read_one(f))
        return records
    return _read_one(path)

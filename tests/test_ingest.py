import gzip
import json

import pytest
from helpers import FIXTURES, case_dirs

from cloudtrace.ingest import IngestError, load_records

REC = {"eventID": "x-1", "eventTime": "2026-01-01T00:00:00Z"}


def test_reads_cloudtrail_layout():
    path = FIXTURES / "c01_attack_key_for_other_used_from_creator_source" / "events.json"
    assert len(load_records(path)) == 5


@pytest.mark.parametrize("cdir", case_dirs(), ids=lambda c: c.name)
def test_every_fixture_can_be_read(cdir):
    assert load_records(cdir / "events.json")


def test_reads_plain_list(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps([REC]))
    assert load_records(tmp_path / "a.json") == [REC]


def test_reads_gzip(tmp_path):
    with gzip.open(tmp_path / "a.json.gz", "wt", encoding="utf-8") as f:
        json.dump({"Records": [REC, REC]}, f)
    assert len(load_records(tmp_path / "a.json.gz")) == 2


def test_reads_folder_in_name_order(tmp_path):
    (tmp_path / "b.json").write_text(json.dumps({"Records": [{"eventID": "B"}]}))
    (tmp_path / "a.json").write_text(json.dumps({"Records": [{"eventID": "A"}]}))
    (tmp_path / "notes.txt").write_text("ignore me")
    assert [r["eventID"] for r in load_records(tmp_path)] == ["A", "B"]


def test_missing_path_gives_clear_error(tmp_path):
    with pytest.raises(IngestError, match="does not exist"):
        load_records(tmp_path / "nope.json")


def test_bad_json_gives_clear_error(tmp_path):
    (tmp_path / "a.json").write_text("{not json")
    with pytest.raises(IngestError, match="not valid JSON"):
        load_records(tmp_path / "a.json")


def test_dict_without_records_gives_clear_error(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps({"hello": 1}))
    with pytest.raises(IngestError, match="Records"):
        load_records(tmp_path / "a.json")


def test_empty_folder_gives_clear_error(tmp_path):
    with pytest.raises(IngestError, match="No .json"):
        load_records(tmp_path)


def test_input_file_is_not_changed(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps({"Records": [REC]}))
    before = p.read_bytes()
    load_records(p)
    assert p.read_bytes() == before

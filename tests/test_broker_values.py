"""Values pwn-broker really writes: what it may leave empty builds, what it never does still fails."""

from __future__ import annotations

import re

import pytest

from fixtures import (
    _box_fields, _box_lines, add_members, file_record, make_archive, manifest_bytes, write_raw_archive,
)  # fmt: skip
from pwn_report import ReportError, build_model, build_report


@pytest.mark.parametrize("field", ["os", "difficulty"])
def test_an_empty_field_pwn_broker_allows_builds(tmp_path, field):
    # pwn-broker's new-box questions store os and difficulty as typed, so pressing Enter leaves ""
    fixture = make_archive(tmp_path / "a.tar.gz", full=True, box={field: ""})
    model = build_model(fixture.path)
    assert model == fixture.model and model["box"][field] == ""


def test_an_empty_field_reads_not_recorded(tmp_path):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True, box={"os": "", "difficulty": ""})
    build_report(fixture.path, tmp_path / "out")
    text = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    assert "- OS: Not recorded\n" in text and "- Difficulty: Not recorded\n" in text


@pytest.mark.parametrize("field", ["id", "name", "platform", "status"])
def test_fields_pwn_broker_never_leaves_empty_still_must_not_be(tmp_path, field):
    fixture = make_archive(tmp_path / "good.tar.gz", full=True)
    members = dict(fixture.members)
    box_toml = members["box.toml"].decode("utf-8")
    emptied = re.sub(rf'(?m)^{field} = "[^"]*"$', f'{field} = ""', box_toml, count=1)
    assert emptied != box_toml
    members["box.toml"] = emptied.encode("utf-8")
    # the manifest lists box.toml by size and SHA-256, so it is listed again as changed
    records = [
        file_record("box.toml", members["box.toml"]) if record.path == "box.toml" else record
        for record in fixture.records
    ]
    members["manifest.toml"] = manifest_bytes(records, kind=fixture.kind)
    bad = write_raw_archive(tmp_path / "bad.tar.gz", lambda tar: add_members(tar, members))
    with pytest.raises(ReportError, match=rf"box\.toml {field}"):
        build_model(bad)


def test_the_fixture_box_lines_follow_the_overrides():
    assert _box_lines(_box_fields({"os": ""})) == [
        'name = "forest"',
        'platform = "htb"',
        'os = ""',
        'difficulty = "easy"',
    ]

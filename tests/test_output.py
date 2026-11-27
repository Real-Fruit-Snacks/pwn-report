"""H06/H08/H10/H13 output behavior and A01-A04/A09 integrity checks."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tomllib
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from urllib.parse import unquote

import pytest

import pwn_report.output as output_module
from pwn_report import ReportError, build_report

from fixtures import (
    CREDS_CANARY,
    LISTS_CANARY,
    NOTES,
    UNLISTED_CANARY,
    canonical_json,
    make_archive,
    sha256,
)

SELECTION = """schema = 1

[[rule]]
path = "targets/dc01/loot/SAM.bak"
include = true

[[rule]]
path = "targets/dc01/recordings/session.cast"
include = true

[[rule]]
path = "targets/dc01/scans/nmap.txt"
include = false

[[rule]]
path = "screenshots/root.png"
caption = "Caption {{7*7}} ${CANARY} stays **literal**"
alt_text = "Alt text <em>unchanged</em>"
target_refs = ["dc01"]
"""


def _tree_bytes(root: Path):
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _make_selection(tmp_path):
    path = tmp_path / "selection.toml"
    path.write_text(SELECTION, encoding="utf-8", newline="\n")
    return path


def _assert_links_resolve(root: Path):
    pattern = re.compile(r"(?<!\\)\[[^\]\n]*(?<!\\)\]\(([^)\s]+)\)")
    for markdown in root.rglob("*.md"):
        text = markdown.read_text(encoding="utf-8")
        for match in pattern.finditer(text):
            relative = unquote(match.group(1))
            assert not relative.startswith(("/", "http:", "https:"))
            target = markdown.parent.joinpath(*PurePosixPath(relative).parts)
            assert target.is_file(), (markdown, relative)


def _assert_checksums(root: Path):
    files = _tree_bytes(root)
    rows = (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    parsed = []
    for row in rows:
        digest, separator, relative = row.partition("  ")
        assert separator == "  "
        assert re.fullmatch(r"[0-9a-f]{64}", digest)
        assert relative in files
        assert hashlib.sha256(files[relative]).hexdigest() == digest
        parsed.append(relative)
    assert parsed == sorted(set(files) - {"SHA256SUMS"})
    assert len(parsed) == len(set(parsed))
    assert "SHA256SUMS" not in parsed


def test_h06_h08_a01_a02_selected_output_notes_links_and_checksums(tmp_path):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    selection = _make_selection(tmp_path)
    archive_before = fixture.path.read_bytes()
    selection_before = selection.read_bytes()
    destination = tmp_path / "forest.report"

    model = build_report(fixture.path, destination, selection)
    files = _tree_bytes(destination)
    copied_evidence = {
        item["output"]["path"]
        for item in model["evidence"]
        if item["output"]["copied"]
    }
    expected = {"report.md", "report.json", "report.toml", "SHA256SUMS", "evidence/notes.md"} | copied_evidence
    assert set(files) == expected
    assert "evidence/targets/dc01/scans/nmap.txt" not in files
    assert "evidence/targets/dc01/loot/SAM.bak" in files
    assert "evidence/targets/dc01/recordings/session.cast" in files

    assert files["report.json"] == canonical_json(model)
    assert json.loads(files["report.json"]) == model
    assert files["evidence/notes.md"] == NOTES
    assert "Résumé — 森林".encode("utf-8") in files["evidence/notes.md"]
    for item in model["evidence"]:
        if item["output"]["copied"]:
            assert files[item["output"]["path"]] == fixture.members[item["path"]]

    markdown = files["report.md"].decode("utf-8")
    assert "Caption {{7\\*7}} ${CANARY} stays \\*\\*literal\\*\\*" in markdown
    assert "Alt text &lt;em&gt;unchanged&lt;/em&gt;" in markdown
    assert "no summary or generated narrative" in markdown
    assert "[Open archived notes](evidence/notes.md)" in markdown
    _assert_links_resolve(destination)
    _assert_checksums(destination)

    metadata_bytes = files["report.toml"]
    metadata = tomllib.loads(metadata_bytes.decode("utf-8"))
    assert list(metadata) == [
        "generator",
        "generator_version",
        "schema_version",
        "profile",
        "box_id",
        "archive_kind",
        "source_archive_sha256",
        "selection_sha256",
        "status",
    ]
    assert metadata == {
        "generator": "pwn-report",
        "generator_version": "0.1.1",
        "schema_version": 1,
        "profile": "private-technical",
        "box_id": model["box"]["id"],
        "archive_kind": "exported",
        "source_archive_sha256": sha256(archive_before),
        "selection_sha256": sha256(selection_before),
        "status": "draft",
    }
    assert metadata_bytes.endswith(b"\n") and b"\r" not in metadata_bytes
    assert files["report.md"].endswith(b"\n") and b"\r" not in files["report.md"]

    # held-back locations are named with their counts; their contents and the files inside never appear
    forbidden = (CREDS_CANARY, LISTS_CANARY, UNLISTED_CANARY, b"lists/passwords.txt", b"unlisted.txt")
    for relative, data in files.items():
        for canary in forbidden:
            assert canary not in data, (relative, canary)
        assert str(tmp_path).encode("utf-8") not in data
    assert fixture.path.read_bytes() == archive_before
    assert selection.read_bytes() == selection_before


def test_default_omitted_content_is_not_emitted_but_its_index_remains(tmp_path):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    destination = tmp_path / "report"
    model = build_report(fixture.path, destination)
    files = _tree_bytes(destination)
    for path, canary in (
        ("targets/dc01/loot/SAM.bak", b"LOOT-CONTENT-CANARY"),
        ("targets/dc01/recordings/session.cast", b"RECORDING-CONTENT-CANARY"),
    ):
        item = next(item for item in model["evidence"] if item["path"] == path)
        assert not item["output"]["copied"] and "path" not in item["output"]
        assert "evidence/" + path not in files
        assert path.encode() in files["report.json"]
        assert path.encode() in files["report.md"]
        for data in files.values():
            assert canary not in data


def test_h10_identical_inputs_produce_identical_complete_trees(tmp_path):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    selection = _make_selection(tmp_path)
    first = tmp_path / "first.report"
    second = tmp_path / "second.report"
    build_report(fixture.path, first, selection)
    build_report(fixture.path, second, selection)
    assert _tree_bytes(first) == _tree_bytes(second)


def test_h13_output_is_cwd_and_path_style_independent(tmp_path, monkeypatch):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    selection = _make_selection(tmp_path)
    absolute = tmp_path / "absolute.report"
    model = build_report(fixture.path.resolve(), absolute, selection.resolve())
    expected = _tree_bytes(absolute)

    monkeypatch.chdir(tmp_path)
    relative = tmp_path / "relative.report"
    relative_model = build_report(Path("source/forest.tar.gz"), Path("relative.report"), Path("selection.toml"))
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.chdir(other)
    string_path = tmp_path / "string.report"
    string_model = build_report(str(fixture.path.resolve()), str(string_path), str(selection.resolve()))

    assert relative_model == string_model == model
    assert _tree_bytes(relative) == expected
    assert _tree_bytes(string_path) == expected


def test_a03_existing_output_directory_is_refused_before_building(tmp_path, monkeypatch):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    destination = tmp_path / "report"
    destination.mkdir()
    (destination / "report.md").write_bytes(b"edited\n")
    (destination / "keep.bin").write_bytes(b"\x00\xff")
    before = _tree_bytes(destination)
    mtimes = {path: path.stat().st_mtime_ns for path in destination.rglob("*")}

    def unexpected_build(*args):
        raise AssertionError("model building started despite existing output")

    monkeypatch.setattr(output_module, "build_model", unexpected_build)
    with pytest.raises(ReportError, match="already exists"):
        build_report(fixture.path, destination)
    assert _tree_bytes(destination) == before
    assert {path: path.stat().st_mtime_ns for path in destination.rglob("*")} == mtimes


def test_a04_existing_output_file_is_preserved(tmp_path):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    destination = tmp_path / "report"
    destination.write_bytes(b"do not replace\n")
    before = destination.stat().st_mtime_ns
    with pytest.raises(ReportError, match="already exists"):
        build_report(fixture.path, destination)
    assert destination.read_bytes() == b"do not replace\n"
    assert destination.stat().st_mtime_ns == before


def test_free_space_boundary_passes_at_equality_and_fails_one_byte_short(tmp_path, monkeypatch):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    selection = _make_selection(tmp_path)
    reference = tmp_path / "reference.report"
    build_report(fixture.path, reference, selection)
    required = sum(len(data) for data in _tree_bytes(reference).values())

    equal = tmp_path / "equal.report"
    monkeypatch.setattr(
        output_module.shutil, "disk_usage", lambda path: SimpleNamespace(free=required)
    )
    build_report(fixture.path, equal, selection)
    assert _tree_bytes(equal) == _tree_bytes(reference)

    short = tmp_path / "short.report"
    monkeypatch.setattr(
        output_module.shutil, "disk_usage", lambda path: SimpleNamespace(free=required - 1)
    )

    def unexpected_copy(*args, **kwargs):
        raise AssertionError("evidence copying started without enough free space")

    monkeypatch.setattr(output_module, "_copy_member", unexpected_copy)
    with pytest.raises(ReportError, match="insufficient free space"):
        build_report(fixture.path, short, selection)
    assert not short.exists()
    assert not list(tmp_path.glob(".short.report.tmp-*"))

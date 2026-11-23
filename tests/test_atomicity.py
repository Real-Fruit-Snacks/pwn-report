"""A05-A12 failure atomicity, source preservation, and no-execution checks."""

from __future__ import annotations

import hashlib
import importlib
import os
import subprocess
from pathlib import Path

import pytest

import pwn_report.output as output_module
from pwn_report import ReportError, build_report

from fixtures import make_archive


def _tree(root: Path):
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in root.rglob("*")
        if path.is_file()
    }


def _assert_no_residue(tmp_path: Path, destination: Path):
    assert not os.path.lexists(destination)
    assert not list(tmp_path.glob(f".{destination.name}.tmp-*"))


def _inputs(tmp_path):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    selection = tmp_path / "selection.toml"
    selection.write_bytes(b"schema = 1\n")
    return fixture, selection


@pytest.mark.parametrize(
    ("target", "exception"),
    [
        ("validate_model", ReportError("injected validation failure")),
        ("_render_markdown", ValueError("injected render failure")),
        ("_copy_member", OSError("injected copy failure")),
        ("_checksum_bytes", ReportError("injected checksum failure")),
        ("_validate_staging", OSError("injected output validation failure")),
    ],
)
def test_a05_staging_failures_leave_no_output_or_temp_residue(tmp_path, monkeypatch, target, exception):
    fixture, selection = _inputs(tmp_path)
    archive_before = fixture.path.read_bytes()
    selection_before = selection.read_bytes()
    destination = tmp_path / "report"

    def fail(*args, **kwargs):
        raise exception

    monkeypatch.setattr(output_module, target, fail)
    with pytest.raises((ReportError, ValueError, OSError)):
        build_report(fixture.path, destination, selection)
    _assert_no_residue(tmp_path, destination)
    assert fixture.path.read_bytes() == archive_before
    assert selection.read_bytes() == selection_before


def test_a06_final_rename_failure_removes_staging_and_partial_output(tmp_path, monkeypatch):
    fixture, selection = _inputs(tmp_path)
    archive_before = fixture.path.read_bytes()
    destination = tmp_path / "report"

    def fail_rename(self, target):
        raise OSError("injected final rename failure")

    monkeypatch.setattr(Path, "rename", fail_rename)
    with pytest.raises(ReportError, match="cannot build report"):
        build_report(fixture.path, destination, selection)
    _assert_no_residue(tmp_path, destination)
    assert fixture.path.read_bytes() == archive_before


def test_a07_existing_edited_report_is_never_replaced_during_commit(tmp_path, monkeypatch):
    fixture, selection = _inputs(tmp_path)
    destination = tmp_path / "report"
    destination.mkdir()
    (destination / "report.md").write_bytes(b"human edit\n")
    before = _tree(destination)

    def unexpected_rename(self, target):
        raise AssertionError("rename was attempted with an existing output")

    monkeypatch.setattr(Path, "rename", unexpected_rename)
    with pytest.raises(ReportError, match="already exists"):
        build_report(fixture.path, destination, selection)
    assert _tree(destination) == before


def test_a08_keyboard_interrupt_during_copy_cleans_staging_and_preserves_inputs(tmp_path, monkeypatch):
    fixture, selection = _inputs(tmp_path)
    archive_before = fixture.path.read_bytes()
    selection_before = selection.read_bytes()
    existing = tmp_path / "existing.report"
    existing.mkdir()
    (existing / "edited.txt").write_bytes(b"keep me\n")
    existing_before = _tree(existing)
    destination = tmp_path / "report"

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(output_module, "_copy_member", interrupt)
    with pytest.raises(KeyboardInterrupt):
        build_report(fixture.path, destination, selection)
    _assert_no_residue(tmp_path, destination)
    assert fixture.path.read_bytes() == archive_before
    assert selection.read_bytes() == selection_before
    assert _tree(existing) == existing_before


def test_a09_success_and_failure_do_not_create_or_modify_source_side_files(tmp_path, monkeypatch):
    fixture, selection = _inputs(tmp_path)
    source_before = _tree(fixture.path.parent)
    selection_before = (selection.read_bytes(), selection.stat().st_mtime_ns)
    destinations = tmp_path / "destinations"
    destinations.mkdir()

    build_report(fixture.path, destinations / "success.report", selection)
    assert _tree(fixture.path.parent) == source_before
    assert (selection.read_bytes(), selection.stat().st_mtime_ns) == selection_before

    def fail(*args, **kwargs):
        raise OSError("injected copy failure")

    monkeypatch.setattr(output_module, "_copy_member", fail)
    with pytest.raises(ReportError):
        build_report(fixture.path, destinations / "failure.report", selection)
    assert _tree(fixture.path.parent) == source_before
    assert (selection.read_bytes(), selection.stat().st_mtime_ns) == selection_before
    assert not (destinations / "failure.report").exists()


def test_a10_archived_code_and_templates_are_never_executed(tmp_path, monkeypatch):
    fixture, selection = _inputs(tmp_path)
    destination = tmp_path / "report"

    def unexpected_execution(*args, **kwargs):
        raise AssertionError("report generation attempted code or shell execution")

    monkeypatch.setattr(subprocess, "run", unexpected_execution)
    monkeypatch.setattr(subprocess, "Popen", unexpected_execution)
    monkeypatch.setattr(os, "system", unexpected_execution)
    monkeypatch.setattr(os, "popen", unexpected_execution)
    monkeypatch.setattr(importlib, "import_module", unexpected_execution)
    build_report(fixture.path, destination, selection)
    assert not list(tmp_path.rglob("ARCHIVE_CODE_EXECUTED"))
    assert not (tmp_path / "ARCHIVE_CODE_EXECUTED").exists()
    assert (destination / "evidence/targets/dc01/exploits/poc.py").read_bytes() == fixture.members[
        "targets/dc01/exploits/poc.py"
    ]
    assert b"{{7*7}}" in (destination / "evidence/notes.md").read_bytes()
    assert b"49\n\nPrivate NOTE-CANARY" not in (destination / "evidence/notes.md").read_bytes()


def test_a12_staging_is_a_sibling_of_the_final_output(tmp_path, monkeypatch):
    fixture, selection = _inputs(tmp_path)
    destination = tmp_path / "output" / "report"
    destination.parent.mkdir()
    original_mkdtemp = output_module.tempfile.mkdtemp
    observed = {}

    def recording_mkdtemp(*, prefix, dir):
        observed["prefix"] = prefix
        observed["dir"] = dir
        path = original_mkdtemp(prefix=prefix, dir=dir)
        observed["stage"] = path
        return path

    monkeypatch.setattr(output_module.tempfile, "mkdtemp", recording_mkdtemp)
    build_report(fixture.path, destination, selection)
    assert Path(observed["dir"]) == destination.parent
    assert Path(observed["stage"]).parent == destination.parent
    assert Path(observed["stage"]).parent != fixture.path.parent
    assert not Path(observed["stage"]).exists()
    assert observed["prefix"] == ".report.tmp-"

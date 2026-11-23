"""Reports build from archives that pwn-broker's own code makes, finished and exported.

Skipped unless PWN_REPORT_BROKER_SRC names a pwn-broker checkout. PWN_REPORT_BROKER_PYTHON is the
Python that has pwn-broker's dependencies (default: this one); CI installs pwn-broker into the
same environment. The archives are made by tests/broker/make_archives.py."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from pwn_report import build_report

HERE = Path(__file__).resolve().parent
BROKER = os.environ.get("PWN_REPORT_BROKER_SRC")
pytestmark = pytest.mark.skipif(not BROKER, reason="needs PWN_REPORT_BROKER_SRC, a pwn-broker checkout")

# the contents of the held-back files make_archives.py writes
HELD_BACK_CANARIES = (b"CRED-SECRET-CANARY", b"CREDS-FOLDER-CANARY", b"TOOLDATA-CANARY")


@pytest.fixture(scope="module")
def archives(tmp_path_factory, request):
    # the suite blocks the network for every test; making the archives uses none, but runs in
    # its own process with pwn-broker's Python, before any test's block applies
    out = tmp_path_factory.mktemp("broker")
    python = os.environ.get("PWN_REPORT_BROKER_PYTHON", sys.executable)
    done = subprocess.run(
        [python, str(HERE / "broker" / "make_archives.py"), str(out)],
        capture_output=True, text=True, timeout=600, env={**os.environ, "PWN_REPORT_BROKER_SRC": BROKER},
    )  # fmt: skip
    assert done.returncode == 0, done.stdout + done.stderr
    found = dict(line.split(" ", 1) for line in done.stdout.splitlines())
    assert set(found) == {"empty", "exported", "finished"}
    return {name: Path(path) for name, path in found.items()}


def _tree(root: Path) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()}


@pytest.mark.parametrize("name", ["empty", "exported", "finished"])
def test_a_report_builds_twice_byte_for_byte(archives, tmp_path, name):
    archive = archives[name]
    before = archive.read_bytes()
    build_report(archive, tmp_path / "one")
    build_report(archive, tmp_path / "two")
    assert _tree(tmp_path / "one") == _tree(tmp_path / "two")
    assert archive.read_bytes() == before


@pytest.mark.parametrize("name", ["exported", "finished"])
def test_the_full_box_holds_back_its_credential_material(archives, tmp_path, name):
    model = build_report(archives[name], tmp_path / "out")
    held = {group["path"]: group["files"] for group in model["held_back"]}
    assert set(held) == {"creds.toml", "lists/", "targets/dc01/creds/", "tooldata/"}
    for relative, data in _tree(tmp_path / "out").items():
        for canary in HELD_BACK_CANARIES:
            assert canary not in data, (relative, canary)


@pytest.mark.parametrize("name", ["exported", "finished"])
def test_the_full_box_indexes_every_kind(archives, tmp_path, name):
    model = build_report(archives[name], tmp_path / "out")
    kinds = {item["kind"] for item in model["evidence"]}
    assert kinds == {"scans", "screenshots", "exploits", "loot", "recordings", "files", "upload"}
    assert [flag["name"] for flag in model["flags"]] == ["root", "user"]
    assert [target["name"] for target in model["targets"]] == ["dc01"]
    assert model["source"]["archive"]["kind"] == name
    assert "notes" in model


def test_the_empty_box_reads_not_recorded(archives, tmp_path):
    model = build_report(archives["empty"], tmp_path / "out")
    assert model["box"]["os"] == "" and model["box"]["difficulty"] == ""
    assert model["targets"] == [] and model["evidence"] == []
    text = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    assert "- OS: Not recorded\n" in text and "- Difficulty: Not recorded\n" in text


def test_the_timeline_crosses_the_clock_change_in_order(archives, tmp_path):
    from datetime import datetime

    model = build_report(archives["finished"], tmp_path / "out")
    instants = [datetime.fromisoformat(event["at"]) for event in model["timeline"]]
    assert instants == sorted(instants)

"""Archive limits: boundary acceptance, early rejection, and bounded reads."""

from __future__ import annotations

import io
import tarfile
from dataclasses import replace

import pytest

from pwn_report import ReportError, build_model
from pwn_report import report as report_module

from fixtures import BOX_ID, make_archive, manifest_bytes, sha256, write_archive

EVIDENCE = "targets/dc01/scans/nmap.txt"


def _measurements(fixture):
    with tarfile.open(fixture.path, "r:gz") as tar:
        members = tar.getmembers()
    names = [len(member.name.encode("utf-8")) for member in members]
    return {
        "MAX_ENTRIES": len(members),
        "MAX_NAME_BYTES": max(names),
        "MAX_NAMES_BYTES": sum(names),
        "MAX_TOML_BYTES": len(fixture.manifest_bytes),
        "MAX_SMALL_TOML_BYTES": len(fixture.members["box.toml"]),
    }


def test_real_archive_constants_match_the_contract():
    assert report_module.READ_BYTES == 64 * 1024
    assert report_module.ENTRY_HEADER_BYTES == 16 * 1024
    assert report_module.HEADER_ROOM == 2048
    assert report_module.HEADER_LINES == 16
    assert report_module.MAX_ENTRIES == 300_000
    assert report_module.MAX_NAME_BYTES == 4096
    assert report_module.MAX_NAMES_BYTES == 64 * 1024 * 1024
    assert report_module.MAX_TOML_BYTES == 64 * 1024 * 1024


@pytest.mark.parametrize(
    "constant",
    ["MAX_ENTRIES", "MAX_NAME_BYTES", "MAX_NAMES_BYTES", "MAX_TOML_BYTES", "MAX_SMALL_TOML_BYTES"],
)
def test_archive_limit_accepts_boundary_and_rejects_one_below(tmp_path, monkeypatch, constant):
    fixture = make_archive(tmp_path / "source.tar.gz")
    original = fixture.path.read_bytes()
    boundary = _measurements(fixture)[constant]

    monkeypatch.setattr(report_module, constant, boundary)
    assert build_model(fixture.path) == fixture.model

    monkeypatch.setattr(report_module, constant, boundary - 1)
    with pytest.raises(ReportError):
        build_model(fixture.path)
    assert fixture.path.read_bytes() == original


def test_entry_limit_stops_before_reading_remaining_members(tmp_path, monkeypatch):
    fixture = make_archive(tmp_path / "source.tar.gz", full=True)
    seen = []
    real_check = report_module._check_member

    def checked(member):
        seen.append(member.name)
        real_check(member)

    monkeypatch.setattr(report_module, "_check_member", checked)
    monkeypatch.setattr(report_module, "MAX_ENTRIES", 3)
    with pytest.raises(ReportError, match="too many entries"):
        build_model(fixture.path)
    assert len(seen) == 4


def test_capped_read_enforces_chunk_header_and_reset_boundaries(monkeypatch):
    stream = report_module._Capped(io.BytesIO(b"abcdef"))
    with pytest.raises(ReportError, match="read request"):
        stream.read(report_module.READ_BYTES + 1)

    monkeypatch.setattr(report_module, "ENTRY_HEADER_BYTES", 4)
    assert stream.read(4) == b"abcd"
    with pytest.raises(ReportError, match="header"):
        stream.read(1)
    # The rejected read consumed `e` before reporting the excessive header.
    stream.next_entry()
    assert stream.read(1) == b"f"
    stream.entries_read()
    assert stream.read(1) == b""


class _Counter:
    def __init__(self, entry_bytes, entry_lines):
        self.entry_bytes = entry_bytes
        self.entry_lines = entry_lines
        self.finished = False

    def next_entry(self):
        self.entry_bytes = 0
        self.entry_lines = 0

    def entries_read(self):
        self.finished = True


class _OneEntryTar:
    def __init__(self, member, counter):
        self.member = member
        self.fileobj = counter
        self.pax_headers = {}

    def __iter__(self):
        return iter((self.member,))


@pytest.mark.parametrize("field", ["entry_bytes", "entry_lines"])
@pytest.mark.parametrize("over", [False, True], ids=["at-boundary", "one-over"])
def test_per_member_header_room_and_lines(field, over):
    member = tarfile.TarInfo(BOX_ID)
    member.type = tarfile.DIRTYPE
    name_bytes = len(BOX_ID.encode("utf-8"))
    values = {
        "entry_bytes": report_module.HEADER_ROOM + 2 * name_bytes,
        "entry_lines": report_module.HEADER_LINES + 2 * member.name.count("\n"),
    }
    if over:
        values[field] += 1
    counter = _Counter(**values)
    tar = _OneEntryTar(member, counter)

    if over:
        with pytest.raises(ReportError, match="header"):
            report_module._members(tar)
    else:
        root, members = report_module._members(tar)
        assert root == BOX_ID and set(members) == {BOX_ID}
        assert counter.finished


def test_large_evidence_uses_bounded_reads_and_verifies_every_chunk(tmp_path, monkeypatch):
    fixture = make_archive(tmp_path / "source" / "source.tar.gz", full=True)
    members = dict(fixture.members)
    large = bytes(range(256)) * 600 + b"final-chunk"
    assert len(large) > 2 * report_module.READ_BYTES
    members[EVIDENCE] = large
    records = [
        replace(record, size=len(large), sha256=sha256(large)) if record.path == EVIDENCE else record
        for record in fixture.records
    ]
    members["manifest.toml"] = manifest_bytes(records, kind=fixture.kind)
    archive = write_archive(tmp_path / "large.tar.gz", members)

    requested = []
    real_read = report_module._Capped.read

    def observed(self, size=-1):
        requested.append(size)
        return real_read(self, size)

    monkeypatch.setattr(report_module._Capped, "read", observed)
    model = build_model(archive)
    evidence = next(item for item in model["evidence"] if item["path"] == EVIDENCE)
    assert evidence["size"] == len(large)
    assert evidence["sha256"] == sha256(large)
    assert requested and max(requested) <= report_module.READ_BYTES

    from pwn_report import build_report

    destination = tmp_path / "large.report"
    build_report(archive, destination)
    assert (destination / "evidence" / EVIDENCE).read_bytes() == large
    assert max(requested) <= report_module.READ_BYTES

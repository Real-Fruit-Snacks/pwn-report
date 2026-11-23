"""A .tar.gz cannot seek back without decompressing again from its start, so members are
read in archive order: a fixed number of seeks back, however many files the archive holds."""

from __future__ import annotations

from pathlib import PurePosixPath

import pytest

from fixtures import BOX_ID, add_bytes, add_dir, file_record, make_archive, manifest_bytes, write_raw_archive
from pwn_report import build_model, build_report, report


def _reversed_archive(tmp_path, count: int):
    """The full fixture plus `count` screenshots, packed in reverse path order."""
    base = make_archive(tmp_path / "base.tar.gz", full=True)
    members = {path: data for path, data in base.members.items() if path != "manifest.toml"}
    for index in range(count):
        members[f"targets/dc01/screenshots/shot-{index:03}.png"] = b"\x89PNG\r\n\x1a\n" + bytes([index])
    listed = {record.path: record for record in base.records}
    records = []
    for path, data in sorted(members.items()):
        if path in listed:
            records.append(listed[path])
        elif path.startswith("targets/dc01/screenshots/shot-"):
            records.append(file_record(path, data, target="dc01", first_seen=listed["targets/dc01/scans/nmap.txt"].first_seen))
    members["manifest.toml"] = manifest_bytes(records, kind=base.kind)

    def write(tar):
        add_dir(tar, BOX_ID)
        folders = set()
        for path in members:
            parent = PurePosixPath(path).parent
            while parent != PurePosixPath("."):
                folders.add(parent.as_posix())
                parent = parent.parent
        for folder in sorted(folders, key=lambda name: (name.count("/"), name)):
            add_dir(tar, f"{BOX_ID}/{folder}")
        for path in sorted(members, reverse=True):
            add_bytes(tar, f"{BOX_ID}/{path}", members[path])

    return write_raw_archive(tmp_path / f"reversed-{count}.tar.gz", write)


@pytest.fixture
def backward_seeks(monkeypatch):
    seen = []
    original = report._Capped.seek

    def spy(self, *args):
        before = self.tell()
        after = original(self, *args)
        if after < before:
            seen.append((before, after))
        return after

    monkeypatch.setattr(report._Capped, "seek", spy)
    return seen


def test_no_backward_seek_per_member_while_hashing_or_copying(tmp_path, backward_seeks):
    counts = []
    for count in (5, 60):
        archive = _reversed_archive(tmp_path, count)
        backward_seeks.clear()
        build_report(archive, tmp_path / f"out-{count}")
        counts.append(len(backward_seeks))
    # listing every member first ends at the archive's last byte, so a few seeks back are unavoidable;
    # one per member is not, and 55 more members must not add any
    assert counts[0] == counts[1], counts
    assert counts[1] <= 6, counts


def test_the_archive_is_opened_twice(tmp_path, monkeypatch):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    opened = []
    original = report._open

    def counting(archive):
        opened.append(archive)
        return original(archive)

    monkeypatch.setattr(report, "_open", counting)
    monkeypatch.setattr("pwn_report.output._open", counting)
    build_report(fixture.path, tmp_path / "out")
    # once to build the model, once to copy the evidence
    assert len(opened) == 2


def test_the_model_records_the_notes_size(tmp_path):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    model = build_model(fixture.path)
    assert model["notes"]["size"] == len(fixture.members["notes.md"])



def test_the_evidence_list_is_walked_a_fixed_number_of_times(tmp_path, monkeypatch):
    # finding each copied file's SHA-256 by walking all the evidence made the build grow with the
    # square of the files copied: 30,000 took a minute, 60,000 nearly five
    from pwn_report import output

    walks = []

    class Counted(list):
        def __iter__(self):
            walks.append(1)
            return super().__iter__()

    real_build_model = output.build_model

    def counted_model(*args, **kwargs):
        model = real_build_model(*args, **kwargs)
        model["evidence"] = Counted(model["evidence"])
        return model

    monkeypatch.setattr(output, "build_model", counted_model)
    counts = []
    for count in (5, 60):
        archive = _reversed_archive(tmp_path, count)
        walks.clear()
        build_report(archive, tmp_path / f"out-{count}")
        counts.append(len(walks))
    assert counts[0] == counts[1], counts

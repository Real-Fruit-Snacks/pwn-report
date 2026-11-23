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



def test_building_the_model_decompresses_the_archive_twice_at_most(tmp_path, monkeypatch):
    # once to list the members, once to read the files the report uses. With two targets, reading
    # each target.toml in a pass of its own went back to the first one and decompressed everything
    # before it again: here a big screenshot at the box's root, and a big scan between the two
    # target.toml files, wider than any read buffer, so the step back to the first is a real one
    import gzip
    import hashlib

    from fixtures import BOX_ID, NOW, _target_toml, _toml_value, add_members

    base = make_archive(tmp_path / "base.tar.gz", full=True)
    members = {path: data for path, data in base.members.items() if path != "manifest.toml"}
    big = b"".join(hashlib.sha256(str(n).encode()).digest() for n in range(40_000))
    second = _target_toml().replace(b'name = "dc01"', b'name = "web01"').replace(b"10.10.10.161", b"10.10.10.162")
    second = second.replace(b'hostnames = ["forest.htb.local"]', b"hostnames = []")
    between = b"".join(hashlib.sha256(f"web01-{n}".encode()).digest() for n in range(40_000))
    extra = {
        "screenshots/big.png": big,
        "targets/web01/target.toml": second,
        "targets/web01/scans/big.bin": between,
    }
    members.update(extra)
    records = list(base.records) + [
        file_record("screenshots/big.png", big),
        file_record("targets/web01/target.toml", second, target="web01"),
        file_record("targets/web01/scans/big.bin", between, target="web01", first_seen=NOW),
    ]
    members["manifest.toml"] = manifest_bytes(sorted(records, key=lambda r: r.path), kind=base.kind)
    archive = write_raw_archive(tmp_path / "big.tar.gz", lambda tar: add_members(tar, members))
    size = len(gzip.decompress(archive.read_bytes()))
    read = []
    original = gzip._GzipReader.read

    def counting(self, size=-1):
        # every byte gzip decompresses, also when a backward seek makes it start again
        data = original(self, size)
        read.append(len(data))
        return data

    monkeypatch.setattr(gzip._GzipReader, "read", counting)
    model = build_model(archive)
    assert [target["name"] for target in model["targets"]] == ["dc01", "web01"]
    assert sum(read) <= 2.2 * size, (sum(read), size)


def test_the_target_files_are_not_all_held_in_memory_at_once(tmp_path, monkeypatch):
    # each target.toml may be up to 1 MiB; holding every one's bytes until the end cost a MiB a
    # target, so a small archive of many padded targets took hundreds of MiB. The limit on the
    # target files together is raised here, so only the reading is measured
    import tracemalloc

    from fixtures import _target_toml, add_members

    monkeypatch.setattr(report, "MAX_TARGETS_BYTES", 64 * 1024 * 1024)

    base = make_archive(tmp_path / "base.tar.gz", full=True)
    members = {path: data for path, data in base.members.items() if path != "manifest.toml"}
    records = list(base.records)
    padding = b"# " + b"x" * 999_000 + b"\n"
    for number in range(24):
        name = f"t{number:02d}"
        data = _target_toml().replace(b'name = "dc01"', f'name = "{name}"'.encode()) + padding
        members[f"targets/{name}/target.toml"] = data
        records.append(file_record(f"targets/{name}/target.toml", data, target=name))
    members["manifest.toml"] = manifest_bytes(sorted(records, key=lambda r: r.path), kind=base.kind)
    archive = write_raw_archive(tmp_path / "many.tar.gz", lambda tar: add_members(tar, members))
    tracemalloc.start()
    try:
        model = build_model(archive)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert len(model["targets"]) == 25
    assert peak < 12_000_000, peak

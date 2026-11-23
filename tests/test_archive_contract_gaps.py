"""Remaining R01-R12 corruption, portability, metadata, and tar-header cases."""

from __future__ import annotations

import gzip
import io
import tarfile
from dataclasses import replace

import pytest

from pwn_report import ReportError, build_model, build_report

from fixtures import (
    BOX_ID,
    add_bytes,
    add_dir,
    add_members,
    file_record,
    make_archive,
    manifest_bytes,
    sha256,
    write_archive,
    write_raw_archive,
)

TARGET = "targets/dc01/target.toml"


def _reject_atomically(path, tmp_path, match=None):
    before = path.read_bytes()
    with pytest.raises(ReportError, match=match):
        build_model(path)
    assert path.read_bytes() == before
    destination = tmp_path / "rejected.report"
    with pytest.raises(ReportError, match=match):
        build_report(path, destination)
    assert not destination.exists()
    assert not list(tmp_path.glob(".rejected.report.tmp-*"))
    assert path.read_bytes() == before


@pytest.mark.parametrize("mutation", ["plain", "truncated-gzip", "truncated-tar", "member-data"])
def test_r01_corrupt_and_truncated_archives_are_rejected_atomically(tmp_path, mutation):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    original = fixture.path.read_bytes()
    archive = tmp_path / "corrupt.tar.gz"
    if mutation == "plain":
        archive.write_bytes(b"not a gzip stream or tar archive")
    elif mutation == "truncated-gzip":
        archive.write_bytes(original[: len(original) // 2])
    else:
        plain = gzip.decompress(original)
        if mutation == "truncated-tar":
            plain = plain[:1024]
        else:
            marker = fixture.members["targets/dc01/scans/nmap.txt"]
            offset = plain.index(marker)
            plain = plain[: offset + 2]
        with archive.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
                zipped.write(plain)
    _reject_atomically(archive, tmp_path)


def test_r02_manifest_as_directory_is_rejected(tmp_path):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz")
    members = dict(fixture.members)
    members.pop("manifest.toml")

    def write(tar):
        add_members(tar, members)
        add_dir(tar, f"{BOX_ID}/manifest.toml")

    archive = write_raw_archive(tmp_path / "manifest-directory.tar.gz", write)
    _reject_atomically(archive, tmp_path, "manifest.toml is missing")


def test_r03_excessive_toml_nesting_is_a_controlled_error(tmp_path):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz")
    members = dict(fixture.members)
    depth = 2000
    members["manifest.toml"] = b"schema = 1\nvalue = " + b'{"a":' * depth + b"1" + b"}" * depth
    archive = write_archive(tmp_path / "deep.toml.tar.gz", members)
    _reject_atomically(archive, tmp_path, "manifest.toml cannot be read")


def test_r08_listed_directory_row_is_rejected(tmp_path):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz")
    members = dict(fixture.members)
    records = list(fixture.records)
    records.append(file_record("listed-folder", b""))
    members["manifest.toml"] = manifest_bytes(records, kind=fixture.kind)

    def write(tar):
        add_members(tar, members)
        add_dir(tar, f"{BOX_ID}/listed-folder")

    archive = write_raw_archive(tmp_path / "listed-directory.tar.gz", write)
    _reject_atomically(archive, tmp_path, "listed-folder is missing")


@pytest.mark.parametrize("field", ["ips", "hostnames"])
def test_r11_nonunique_target_addresses_are_rejected(tmp_path, field):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    members = dict(fixture.members)
    old = b'["10.10.10.161"]' if field == "ips" else b'["forest.htb.local"]'
    new = b'["10.10.10.161", "10.10.10.161"]' if field == "ips" else b'["forest.htb.local", "forest.htb.local"]'
    members[TARGET] = members[TARGET].replace(old, new, 1)
    records = [
        replace(record, size=len(members[TARGET]), sha256=sha256(members[TARGET]))
        if record.path == TARGET
        else record
        for record in fixture.records
    ]
    members["manifest.toml"] = manifest_bytes(records, kind=fixture.kind)
    archive = write_archive(tmp_path / f"duplicate-{field}.tar.gz", members)
    _reject_atomically(archive, tmp_path, "contains duplicates")


@pytest.mark.parametrize("root", ["C:", "bad\\root", "bad\nroot"], ids=["drive", "backslash", "control"])
def test_nonportable_box_roots_are_rejected(tmp_path, root):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz")

    def write(tar):
        add_dir(tar, root)
        add_bytes(tar, f"{root}/box.toml", fixture.members["box.toml"])
        add_bytes(tar, f"{root}/manifest.toml", fixture.members["manifest.toml"])

    archive = write_raw_archive(tmp_path / "bad-root.tar.gz", write)
    _reject_atomically(archive, tmp_path)


def _mutate_header(source: bytes, member_name: str, offset: int, value: bytes) -> bytes:
    data = bytearray(source)
    for position in range(0, len(data) - 511, 512):
        block = data[position : position + 512]
        name = bytes(block[:100]).split(b"\0", 1)[0].decode("utf-8", "surrogateescape").rstrip("/")
        if name != member_name:
            continue
        data[position + offset : position + offset + len(value)] = value
        data[position + 148 : position + 156] = b"        "
        checksum = tarfile.calc_chksums(bytes(data[position : position + 512]))[0]
        data[position + 148 : position + 156] = b"%06o\0 " % checksum
        return bytes(data)
    raise AssertionError(f"member header not found: {member_name}")


def _write_plain(destination, plain):
    with destination.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
            zipped.write(plain)
    return destination


@pytest.mark.parametrize(
    ("member", "offset", "width", "number", "match"),
    [
        (BOX_ID, 124, 12, 1, "invalid size"),
        (f"{BOX_ID}/box.toml", 124, 12, -1, None),
        (f"{BOX_ID}/box.toml", 108, 8, -1, "invalid owner|cannot build"),
        (f"{BOX_ID}/box.toml", 116, 8, -1, "invalid owner|cannot build"),
    ],
    ids=["nonzero-directory-size", "negative-file-size", "negative-uid", "negative-gid"],
)
def test_tar_size_and_owner_headers_are_validated(tmp_path, member, offset, width, number, match):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz")
    plain = gzip.decompress(fixture.path.read_bytes())
    mutated = _mutate_header(plain, member, offset, tarfile.itn(number, width, tarfile.GNU_FORMAT))
    archive = _write_plain(tmp_path / "bad-header.tar.gz", mutated)
    _reject_atomically(archive, tmp_path, match)


def test_global_pax_header_is_rejected(tmp_path):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz")

    def write(tar):
        value = b"comment=global-canary-value\n"
        payload = f"{len(value) + 3} ".encode("ascii") + value
        assert len(payload) == 31
        info = tarfile.TarInfo("pax_global_header")
        info.type = tarfile.XGLTYPE
        info.size = len(payload)
        info.mtime = 0
        tar.addfile(info, io.BytesIO(payload))
        add_members(tar, fixture.members)

    archive = write_raw_archive(tmp_path / "global-pax.tar.gz", write)
    _reject_atomically(archive, tmp_path, "global extended header")

"""Defects found in review, each pinned by the input that showed it."""

from __future__ import annotations

import gzip
import hashlib
import zlib

import pytest

from fixtures import BOX_ID, NOW, _toml_value, add_members, file_record, make_archive, manifest_bytes, write_raw_archive
from pwn_report import ReportError, build_model, build_report, cli


def _flipped_inside_the_deflate_stream(tmp_path):
    """An archive whose deflate stream breaks inside a large member's data, past every header:
    tarfile wraps a zlib error met while reading headers, but not one met while reading data."""
    fixture = make_archive(tmp_path / "good.tar.gz", full=True)
    members = {path: data for path, data in fixture.members.items() if path != "manifest.toml"}
    # incompressible, so its data fills most of the compressed stream
    big = b"".join(hashlib.sha256(str(n).encode()).digest() for n in range(12_000))
    members["targets/dc01/scans/zz-big.bin"] = big
    listed = {record.path: record for record in fixture.records}
    records = sorted(
        [*listed.values(), file_record("targets/dc01/scans/zz-big.bin", big, target="dc01")],
        key=lambda record: record.path,
    )
    members["manifest.toml"] = manifest_bytes(records, kind=fixture.kind)
    good = write_raw_archive(tmp_path / "big.tar.gz", lambda tar: add_members(tar, members))
    data = good.read_bytes()
    # from three quarters of the way in, the first change that zlib itself rejects
    for offset in range(len(data) * 3 // 4, len(data) - 16):
        mutated = bytearray(data)
        mutated[offset] ^= 0xFF
        try:
            gzip.decompress(bytes(mutated))
        except zlib.error:
            path = tmp_path / "flipped.tar.gz"
            path.write_bytes(bytes(mutated))
            return path
        except Exception:
            continue
    pytest.fail("no offset gave a zlib error")


def test_a_corrupt_deflate_stream_is_a_report_error(tmp_path):
    archive = _flipped_inside_the_deflate_stream(tmp_path)
    with pytest.raises(ReportError):
        build_model(archive)
    with pytest.raises(ReportError):
        build_report(archive, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_a_corrupt_deflate_stream_is_one_fail_line(tmp_path, capsys):
    archive = _flipped_inside_the_deflate_stream(tmp_path)
    assert cli.main(["build", str(archive)]) == 1
    err = capsys.readouterr().err
    assert err.startswith("fail  ") and err.count("\n") == 1 and "Traceback" not in err


def test_a_time_out_of_range_is_a_report_error(tmp_path):
    # year 1 at +05:00 has no UTC instant; pwn-broker never writes it, a hand-made archive can
    box_toml = (
        "schema = 1\n"
        f'id = "{BOX_ID}"\n'
        'name = "forest"\nplatform = "htb"\nos = "windows"\ndifficulty = "easy"\nstatus = "active"\n'
        f"started = {_toml_value(NOW)}\n"
        '\n[flags.user]\nvalue = "U"\nat = 0001-01-01T00:00:00+05:00\n'
    ).encode("utf-8")
    members = {"box.toml": box_toml}
    members["manifest.toml"] = manifest_bytes([file_record("box.toml", box_toml)])
    archive = write_raw_archive(tmp_path / "old.tar.gz", lambda tar: add_members(tar, members))
    with pytest.raises(ReportError):
        build_model(archive)


def test_an_unexpected_error_is_one_fail_line(tmp_path, capsys, monkeypatch):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)

    def broken(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(cli, "build_report", broken)
    assert cli.main(["build", str(fixture.path)]) == 1
    assert capsys.readouterr().err == "fail  unexpected error: RuntimeError: boom\n"

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



def _with_listed(tmp_path, extra: dict[str, bytes], *, targets: dict[str, str] | None = None, name="extra"):
    """The full fixture plus extra listed files; `targets` gives each extra file's target field."""
    fixture = make_archive(tmp_path / f"{name}-base.tar.gz", full=True)
    members = {path: data for path, data in fixture.members.items() if path != "manifest.toml"}
    members.update(extra)
    records = list(fixture.records) + [
        file_record(path, data, target=(targets or {}).get(path, ""), first_seen=NOW) for path, data in extra.items()
    ]
    members["manifest.toml"] = manifest_bytes(sorted(records, key=lambda r: r.path), kind=fixture.kind)
    return write_raw_archive(tmp_path / f"{name}.tar.gz", lambda tar: add_members(tar, members))


def test_a_folder_under_targets_with_no_target_toml_is_listed_as_other(tmp_path):
    path = "targets/old/loot/hashes.txt"
    archive = _with_listed(tmp_path, {path: b"OLD-TARGET-CANARY"}, targets={path: "old"})
    model = build_report(archive, tmp_path / "out")
    assert path in model["other"] and path not in {item["path"] for item in model["evidence"]}


def test_listed_names_with_a_backslash_or_a_control_character_are_other_and_never_read(tmp_path, monkeypatch):
    import tarfile

    odd = {
        "targets/dc01/loot/dir\\file.txt": b"BACKSLASH-CANARY",
        "targets/dc01/scans/bad\x1bname.txt": b"ESC-CANARY",
    }
    archive = _with_listed(tmp_path, odd, targets={path: "dc01" for path in odd})
    opened = []
    real = tarfile.TarFile.extractfile

    def observed(self, member):
        opened.append(member.name if isinstance(member, tarfile.TarInfo) else str(member))
        return real(self, member)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", observed)
    model = build_report(archive, tmp_path / "out")
    assert set(odd) <= set(model["other"])
    assert not any(name.endswith(tuple(odd)) for name in opened)
    text = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    # Markdown escapes the backslash; the control character is shown as ?
    assert "- targets/dc01/loot/dir\\\\file.txt\n" in text
    assert "- targets/dc01/scans/bad?name.txt\n" in text
    assert "\x1b" not in text
    for data in (path.read_bytes() for path in (tmp_path / "out").rglob("*") if path.is_file()):
        assert b"BACKSLASH-CANARY" not in data and b"ESC-CANARY" not in data


@pytest.mark.parametrize(
    "path",
    ["../escape.txt", "targets/dc01/scans/..\\..\\escape.txt", "/abs.txt", "C:/drive.txt"],
    ids=["parent", "backslash-parent", "absolute", "drive"],
)
def test_a_path_that_leaves_the_box_fails_and_is_named(tmp_path, path):
    base = make_archive(tmp_path / "b.tar.gz", full=True)
    members = {p: d for p, d in base.members.items() if p != "manifest.toml"}
    members["manifest.toml"] = manifest_bytes([*base.records, file_record(path, b"x")], kind=base.kind)
    bad = write_raw_archive(tmp_path / "bad.tar.gz", lambda tar: add_members(tar, members))
    with pytest.raises(ReportError) as raised:
        build_model(bad)
    assert repr(path) in str(raised.value)


def test_a_held_back_error_names_the_location_not_the_file(tmp_path):
    base = make_archive(tmp_path / "b.tar.gz", full=True)
    members = {p: d for p, d in base.members.items() if p != "manifest.toml"}
    records = [
        file_record("lists/passwords.txt", b"a different size") if record.path == "lists/passwords.txt" else record
        for record in base.records
    ]
    members["manifest.toml"] = manifest_bytes(records, kind=base.kind)
    bad = write_raw_archive(tmp_path / "bad.tar.gz", lambda tar: add_members(tar, members))
    with pytest.raises(ReportError) as raised:
        build_model(bad)
    assert "lists/" in str(raised.value) and "passwords.txt" not in str(raised.value)


def test_control_and_format_characters_never_reach_report_md(tmp_path):
    base = make_archive(tmp_path / "b.tar.gz", full=True)
    selection = tmp_path / "pick.toml"
    # a TOML escape in the file, so the caption holds a real ESC and a right-to-left override
    selection.write_text(
        "schema = 1\n[[rule]]\npath = 'targets/dc01/scans/nmap.txt'\n"
        'caption = "seen \\u001b[31mred\\u202e here"\n',
        encoding="utf-8",
    )
    build_report(base.path, tmp_path / "out", selection)
    text = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    assert "\x1b" not in text and "\u202e" not in text
    assert "- Caption: seen ?\\[31mred? here\n" in text

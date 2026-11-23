"""Defects found in review, each pinned by the input that showed it."""

from __future__ import annotations

import gzip
import os
import sys
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



@pytest.mark.parametrize(
    "path, part",
    [
        ("evidence/targets/aux/scans/nmap.txt", "aux"),
        ("evidence/targets/dc01/scans/CON.txt", "CON.txt"),
        ("evidence/targets/dc01/scans/com1", "com1"),
        ("evidence/targets/dc01/scans/report.", "report."),
        ("evidence/targets/dc01/scans/trailing ", "trailing "),
        ("evidence/targets/dc01/scans/a:b.txt", "a:b.txt"),
        ("evidence/targets/dc01/scans/what?.txt", "what?.txt"),
    ],
)
def test_names_windows_refuses_are_named(path, part):
    from pwn_report import output

    problem = output._unwritable([path], windows=True, folds_case=False)
    assert problem is not None and repr(part) in problem and path.removeprefix("evidence/") in problem
    assert output._unwritable([path], windows=False, folds_case=False) is None


def test_files_that_differ_only_in_case_are_named_together():
    from pwn_report import output

    paths = ["evidence/targets/dc01/scans/Nmap.txt", "evidence/targets/dc01/scans/nmap.txt"]
    problem = output._unwritable(paths, windows=False, folds_case=True)
    assert problem is not None
    assert "targets/dc01/scans/Nmap.txt" in problem and "targets/dc01/scans/nmap.txt" in problem
    assert "differ only in case" in problem
    assert output._unwritable(paths, windows=False, folds_case=False) is None


def test_folders_that_differ_only_in_case_are_named_together():
    from pwn_report import output

    paths = ["evidence/targets/DC01/scans/a.txt", "evidence/targets/dc01/scans/b.txt"]
    problem = output._unwritable(paths, windows=False, folds_case=True)
    assert problem is not None and "targets/DC01" in problem and "targets/dc01" in problem


def test_names_that_differ_only_in_unicode_form_are_named_together():
    from pwn_report import output

    composed, decomposed = "evidence/scans/café.txt", "evidence/scans/café.txt"
    assert output._unwritable([composed, decomposed], windows=False, folds_case=True) is not None


@pytest.mark.skipif(os.name != "nt" and sys.platform != "darwin", reason="only a case-folding file system clashes")
def test_a_case_clash_fails_before_anything_is_written(tmp_path):
    clash = {"targets/dc01/scans/Ports.txt": b"UPPER", "targets/dc01/scans/ports.txt": b"LOWER"}
    archive = _with_listed(tmp_path, clash, targets={path: "dc01" for path in clash}, name="clash")
    with pytest.raises(ReportError, match="differ only in case"):
        build_report(archive, tmp_path / "out")
    assert not (tmp_path / "out").exists()
    assert not list(tmp_path.glob(".out.tmp-*"))



def test_a_staging_copy_that_cannot_be_removed_is_named(tmp_path, monkeypatch):
    from pwn_report import output

    fixture = make_archive(tmp_path / "a.tar.gz", full=True)

    def failing(*args, **kwargs):
        raise ReportError("checked and wrong")

    monkeypatch.setattr(output, "_validate_staging", failing)
    monkeypatch.setattr(output.shutil, "rmtree", lambda *args, **kwargs: None)
    with pytest.raises(ReportError) as raised:
        build_report(fixture.path, tmp_path / "out")
    left = list(tmp_path.glob(".out.tmp-*"))
    assert len(left) == 1
    message = str(raised.value)
    assert message.startswith("checked and wrong; ")
    assert f"a partial copy was left at {left[0]}" in message and "delete it" in message


def test_the_ok_line_survives_an_encoding_that_cannot_hold_the_path(tmp_path, monkeypatch):
    import io

    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    out_dir = tmp_path / "café"
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="ascii", newline="\n")
    monkeypatch.setattr(sys, "stdout", stream)
    assert cli.main(["build", str(fixture.path), "-o", str(out_dir)]) == 0
    stream.flush()
    line = raw.getvalue().decode("ascii")
    assert line.startswith("ok    report ") and line.endswith("caf\\xe9\n")
    assert (out_dir / "report.md").is_file()


def test_each_evidence_heading_is_its_path(tmp_path):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    model = build_report(fixture.path, tmp_path / "out")
    text = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    scan = next(item for item in model["evidence"] if item["path"] == "targets/dc01/scans/nmap.txt")
    block = text[text.index("#### targets/dc01/scans/nmap.txt\n"):]
    assert block.split("\n")[2] == f"- ID: {scan['id'].replace('_', chr(92) + '_')}"
    assert "#### ev" not in text and "- Path: " not in text



def _entry(text: str, path: str) -> list[str]:
    """The lines of one evidence entry in report.md, from its heading to the next blank line."""
    escaped = path.replace("_", "\\_")
    start = text.index(f"#### {escaped}\n")
    return text[start:].split("\n\n", 2)[1].split("\n")


def test_each_entry_says_in_words_what_happened_to_its_file(tmp_path):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    selection = tmp_path / "pick.toml"
    selection.write_text(
        "schema = 1\n"
        "[[rule]]\npath = 'targets/dc01/loot/SAM.bak'\ninclude = true\n"
        "[[rule]]\npath = 'targets/dc01/exploits/poc.py'\ninclude = false\n",
        encoding="utf-8",
    )
    build_report(fixture.path, tmp_path / "out", selection)
    text = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    assert "- Decision: " not in text
    expect = {
        "targets/dc01/scans/nmap.txt": "- File: [copied](evidence/targets/dc01/scans/nmap.txt)",
        "targets/dc01/loot/SAM.bak": "- File: [copied](evidence/targets/dc01/loot/SAM.bak), as the selection asks",
        "targets/dc01/exploits/poc.py": "- File: not copied; the selection leaves it out",
        "targets/dc01/recordings/session.cast": "- File: not copied; recordings are indexed only unless a selection includes them",
        "targets/dc01/files/notes.txt": "- File: not copied; files/ is indexed only unless a selection includes it",
        "targets/dc01/upload/winpeas.exe": "- File: not copied; upload/ is indexed only unless a selection includes it",
    }
    for path, line in expect.items():
        assert line in _entry(text, path), (path, _entry(text, path))


def test_loot_left_out_by_default_says_so(tmp_path):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    build_report(fixture.path, tmp_path / "out")
    text = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    assert "- File: not copied; loot is indexed only unless a selection includes it" in _entry(
        text, "targets/dc01/loot/SAM.bak"
    )


def test_the_timeline_names_files_by_path_alone(tmp_path):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    build_report(fixture.path, tmp_path / "out")
    text = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    timeline = text[text.index("## Timeline\n"):text.index("## Evidence index\n")]
    assert "File first seen: targets/dc01/scans/nmap.txt\n" in timeline
    assert "ev\\_" not in timeline



@pytest.mark.parametrize("odd", ["dir/name\nwith a break.txt", "dir/esc\x1b[31m.txt", "dir/rtl‮.txt"])
def test_the_fail_line_is_one_line_with_no_control_or_format_character(tmp_path, capsys, odd):
    # a listed file missing from the archive fails naming its path as listed; a crafted name must
    # not break the line in two or reach the terminal as an escape, since pwn-broker prints it
    base = make_archive(tmp_path / "b.tar.gz", full=True)
    members = {p: d for p, d in base.members.items() if p != "manifest.toml"}
    members["manifest.toml"] = manifest_bytes([*base.records, file_record(odd, b"x")], kind=base.kind)
    bad = write_raw_archive(tmp_path / "bad.tar.gz", lambda tar: add_members(tar, members))
    assert cli.main(["build", str(bad)]) == 1
    err = capsys.readouterr().err
    assert err.startswith("fail  ") and err.count("\n") == 1 and err.endswith("\n")
    assert "\x1b" not in err and "‮" not in err and "?" in err



def test_an_interrupt_whose_staging_copy_cannot_be_removed_names_it(tmp_path, capsys, monkeypatch):
    from pwn_report import output

    fixture = make_archive(tmp_path / "a.tar.gz", full=True)

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(output, "_validate_staging", interrupted)
    monkeypatch.setattr(output.shutil, "rmtree", lambda *args, **kwargs: None)
    assert cli.main(["build", str(fixture.path), "-o", str(tmp_path / "out")]) == 130
    left = list(tmp_path.glob(".out.tmp-*"))
    assert len(left) == 1
    err = capsys.readouterr().err
    assert err == f"fail  interrupted; a partial copy was left at {left[0]}: delete it, it holds copied evidence\n"

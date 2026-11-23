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



@pytest.mark.parametrize("value", ["a\x7fb", "\x00\x1f", "a b", 'q"b\\s', "café"])
def test_report_toml_strings_are_valid_toml(value):
    import tomllib

    from pwn_report import output

    assert tomllib.loads("k = " + output._toml_string(value))["k"] == value


@pytest.mark.parametrize("odd", ["a\x85b.txt", "a\x9bb.txt", "a b.txt", "a b.txt"])
def test_names_with_a_c1_control_or_a_line_separator_are_other(tmp_path, odd):
    path = f"targets/dc01/scans/{odd}"
    archive = _with_listed(tmp_path, {path: b"ODD-NAME-CANARY"}, targets={path: "dc01"})
    model = build_report(archive, tmp_path / "out")
    assert path in model["other"] and path not in {item["path"] for item in model["evidence"]}
    text = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    assert "- targets/dc01/scans/a?b.txt\n" in text
    for data in (f.read_bytes() for f in (tmp_path / "out").rglob("*") if f.is_file()):
        assert b"ODD-NAME-CANARY" not in data
    assert not any(odd in f.name for f in (tmp_path / "out").rglob("*"))


@pytest.mark.parametrize("odd", ["dir/sep x.txt", "dir/par x.txt", "dir/nel\x85x.txt"])
def test_a_line_separator_never_splits_the_fail_line(tmp_path, capsys, odd):
    base = make_archive(tmp_path / "b.tar.gz", full=True)
    members = {p: d for p, d in base.members.items() if p != "manifest.toml"}
    members["manifest.toml"] = manifest_bytes([*base.records, file_record(odd, b"x")], kind=base.kind)
    bad = write_raw_archive(tmp_path / "bad.tar.gz", lambda tar: add_members(tar, members))
    assert cli.main(["build", str(bad)]) == 1
    err = capsys.readouterr().err
    assert len(err.splitlines()) == 1 and "?" in err


def test_box_toml_must_be_listed(tmp_path):
    base = make_archive(tmp_path / "b.tar.gz", full=True)
    members = {p: d for p, d in base.members.items() if p != "manifest.toml"}
    records = [record for record in base.records if record.path != "box.toml"]
    members["manifest.toml"] = manifest_bytes(records, kind=base.kind)
    bad = write_raw_archive(tmp_path / "bad.tar.gz", lambda tar: add_members(tar, members))
    with pytest.raises(ReportError, match="box.toml is not listed in manifest.toml"):
        build_model(bad)


def test_a_tilde_cannot_strike_text_through(tmp_path):
    base = make_archive(tmp_path / "b.tar.gz", full=True)
    selection = tmp_path / "pick.toml"
    selection.write_text("schema = 1\n[[rule]]\npath = 'targets/dc01/scans/nmap.txt'\ncaption = '~~gone~~'\n", encoding="utf-8")
    build_report(base.path, tmp_path / "out", selection)
    text = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    assert "- Caption: \\~\\~gone\\~\\~\n" in text


def test_a_file_and_a_folder_of_one_name_are_named_together():
    from pwn_report import output

    problem = output._unwritable(
        ["evidence/targets/dc01/scans/collide", "evidence/targets/dc01/scans/collide/sub.txt"],
        windows=False, folds_case=False,
    )  # fmt: skip
    assert problem is not None
    assert "targets/dc01/scans/collide" in problem and "targets/dc01/scans/collide/sub.txt" in problem


@pytest.mark.parametrize("value", ["a\x7fb", "a\x85b", "a b"])
def test_the_validator_refuses_what_the_reader_refuses(value):
    from pwn_report import report, validate

    assert not report.is_portable(value)
    with pytest.raises(ReportError):
        validate._path(value, "path")



@pytest.mark.parametrize("name", ["CON", "aux.report", "report.", "report ", "a:b"])
def test_a_report_folder_name_windows_refuses_is_refused_by_name(name):
    from pwn_report import output

    problem = output._unwritable_output(name, windows=True)
    assert problem is not None and repr(name) in problem and "-o" in problem
    assert output._unwritable_output(name, windows=False) is None
    assert output._unwritable_output("2026-11-14_htb_forest.finished.report", windows=True) is None


@pytest.mark.skipif(os.name != "nt", reason="Windows refuses these names")
@pytest.mark.parametrize("name", ["CON", "NUL", "report."])
def test_on_windows_such_a_folder_is_never_made(tmp_path, name):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    with pytest.raises(ReportError, match="one Windows refuses or changes; give another with -o"):
        build_report(fixture.path, tmp_path / name)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar.gz"]



@pytest.mark.parametrize("held", ["lists/SECRET-INNER-NAME", "targets/dc01/creds/SECRET-INNER-NAME", "tooldata/x/SECRET-INNER-NAME"])
@pytest.mark.parametrize("shape", ["link", "duplicate"])
def test_a_member_error_inside_a_held_back_place_names_the_place(tmp_path, held, shape):
    import tarfile

    base = make_archive(tmp_path / "b.tar.gz", full=True)

    def write(tar):
        add_members(tar, {p: d for p, d in base.members.items()})
        if shape == "link":
            info = tarfile.TarInfo(f"{BOX_ID}/{held}")
            info.type = tarfile.SYMTYPE
            info.linkname = "x"
            tar.addfile(info)
        else:
            for _ in range(2):
                info = tarfile.TarInfo(f"{BOX_ID}/{held}")
                info.size = 1
                import io

                tar.addfile(info, io.BytesIO(b"x"))

    bad = write_raw_archive(tmp_path / "bad.tar.gz", write)
    with pytest.raises(ReportError) as raised:
        build_model(bad)
    message = str(raised.value)
    assert "SECRET-INNER-NAME" not in message
    group = held.split("/SECRET")[0]
    group = group if group.startswith("targets/") else group.split("/")[0]
    assert group in message, message


def test_one_byte_is_one_byte(tmp_path):
    path = "targets/dc01/scans/one.txt"
    archive = _with_listed(tmp_path, {path: b"x"}, targets={path: "dc01"})
    build_report(archive, tmp_path / "out")
    text = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    entry = text[text.index("#### targets/dc01/scans/one.txt"):]
    assert "- Size: 1 byte\n" in entry.split("\n\n#### ")[0]
    assert "bytes" in text  # every other file is larger than one byte


@pytest.mark.skipif(os.name == "nt", reason="Windows ends a process on SIGTERM with no handler run")
@pytest.mark.parametrize("name", ["SIGTERM", "SIGHUP"])
def test_a_signal_to_stop_cleans_up_like_ctrl_c(tmp_path, capsys, monkeypatch, name):
    import signal
    import time

    from pwn_report import output

    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    number = getattr(signal, name)
    before = signal.getsignal(number)

    def stopped(*args, **kwargs):
        os.kill(os.getpid(), number)
        time.sleep(5)

    monkeypatch.setattr(output, "_validate_staging", stopped)
    assert cli.main(["build", str(fixture.path), "-o", str(tmp_path / "out")]) == 130
    assert capsys.readouterr().err == "fail  interrupted; no report was written\n"
    assert not (tmp_path / "out").exists() and not list(tmp_path.glob(".out.tmp-*"))
    assert signal.getsignal(number) == before


@pytest.mark.skipif(os.name == "nt", reason="Windows gives a folder no mode bits")
def test_the_report_folder_is_its_owners_alone(tmp_path):
    # the staging folder is made 0700 and renamed into place, so the evidence is never open to others
    import stat

    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    build_report(fixture.path, tmp_path / "out")
    assert stat.S_IMODE((tmp_path / "out").stat().st_mode) == 0o700


@pytest.mark.parametrize(
    "spelled",
    [
        "{box}/lists//SECRET-INNER-NAME",
        "{box}/lists/./SECRET-INNER-NAME",
        "./{box}/lists/SECRET-INNER-NAME",
        "{box}/scans/../lists/SECRET-INNER-NAME",
        "{box}/targets/dc01//creds/SECRET-INNER-NAME",
        "{box}\\tooldata\\SECRET-INNER-NAME",
        "{box}/lists/SECRET-INNER-NAME/..",
        "{box}/lists/SECRET-INNER-NAME/../../../x",
        "{box}/targets/dc01/creds/SECRET-INNER-NAME/..",
        "C:/{box}/lists/SECRET-INNER-NAME",
        "C:\\{box}\\lists\\SECRET-INNER-NAME",
        "{box}/targets/a:b/creds/SECRET-INNER-NAME",
        "{box}/LISTS/SECRET-INNER-NAME",
        "{box}/creds.toml/SECRET-INNER-NAME",
        "lists/SECRET-INNER-NAME",
    ],
)
def test_an_odd_spelling_of_a_held_back_place_is_still_named_by_the_place(tmp_path, spelled):
    # a member name is never used as a path, so these are only names; but an error about one names
    # the place it spells, never the file inside it
    import tarfile

    base = make_archive(tmp_path / "b.tar.gz", full=True)
    name = spelled.format(box=BOX_ID)

    def write(tar):
        add_members(tar, dict(base.members))
        info = tarfile.TarInfo(name)
        info.type = tarfile.SYMTYPE
        info.linkname = "x"
        tar.addfile(info)

    bad = write_raw_archive(tmp_path / "bad.tar.gz", write)
    with pytest.raises(ReportError) as raised:
        build_model(bad)
    message = str(raised.value)
    assert "SECRET-INNER-NAME" not in message, message
    assert any(place in message.casefold() for place in ("lists/", "tooldata/", "creds/", "creds.toml/")), message


def _sentinel(signum, frame) -> None:
    """A handler a test sets itself, to see that it is the one put back."""


def _stop_signals() -> list:
    import signal

    return [getattr(signal, name) for name in ("SIGINT", "SIGTERM", "SIGHUP") if hasattr(signal, name)]


@pytest.fixture
def own_handlers():
    import signal

    saved = {number: signal.getsignal(number) for number in _stop_signals()}
    for number in saved:
        signal.signal(number, _sentinel)
    yield
    for number, handler in saved.items():
        signal.signal(number, handler)


def _junk_archive(tmp_path):
    path = tmp_path / "junk.tar.gz"
    path.write_bytes(b"not an archive")
    return path


@pytest.mark.parametrize("good", [True, False], ids=["built", "failed"])
def test_the_handlers_are_put_back_as_they_were(tmp_path, own_handlers, good):
    import signal

    archive = make_archive(tmp_path / "a.tar.gz", full=True).path if good else _junk_archive(tmp_path)
    assert cli.main(["build", str(archive), "-o", str(tmp_path / "out")]) == (0 if good else 1)
    assert [signal.getsignal(number) for number in _stop_signals()] == [_sentinel] * len(_stop_signals())


@pytest.mark.parametrize("good", [True, False], ids=["built", "failed"])
def test_the_line_is_printed_with_the_handlers_put_back(tmp_path, own_handlers, monkeypatch, good):
    # a stop that lands while the line is printed meets the caller's own handler, not one that
    # raises out of main with a traceback
    import signal

    seen = []
    real = cli._say

    def say(text, stream):
        seen.append([signal.getsignal(number) for number in _stop_signals()] == [_sentinel] * len(_stop_signals()))
        real(text, stream)

    monkeypatch.setattr(cli, "_say", say)
    archive = make_archive(tmp_path / "a.tar.gz", full=True).path if good else _junk_archive(tmp_path)
    cli.main(["build", str(archive), "-o", str(tmp_path / "out")])
    assert seen == [True]


@pytest.mark.skipif(os.name == "nt", reason="Windows ends a process on SIGTERM with no handler run")
@pytest.mark.parametrize("name", ["SIGINT", "SIGTERM", "SIGHUP"])
def test_a_second_stop_cannot_cut_the_cleanup_short(tmp_path, capsys, monkeypatch, name):
    import shutil
    import signal
    import time

    from pwn_report import output

    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    number = getattr(signal, name)
    real_rmtree = shutil.rmtree

    def stopped(*args, **kwargs):
        os.kill(os.getpid(), number)
        time.sleep(5)

    def rmtree(*args, **kwargs):
        os.kill(os.getpid(), number)  # pressed again, or the timeout's second SIGTERM
        return real_rmtree(*args, **kwargs)

    monkeypatch.setattr(output, "_validate_staging", stopped)
    monkeypatch.setattr(output.shutil, "rmtree", rmtree)
    assert cli.main(["build", str(fixture.path), "-o", str(tmp_path / "out")]) == 130
    assert capsys.readouterr().err == "fail  interrupted; no report was written\n"
    assert not (tmp_path / "out").exists() and not list(tmp_path.glob(".out.tmp-*"))


@pytest.mark.skipif(os.name == "nt", reason="Windows has no SIGHUP and ends a process on SIGTERM")
@pytest.mark.parametrize("name", ["SIGINT", "SIGTERM", "SIGHUP"])
def test_a_signal_the_caller_ignores_stays_ignored(tmp_path, capsys, monkeypatch, name):
    # nohup ignores SIGHUP, and a shell ignores SIGINT for a job it starts in the background
    import signal

    from pwn_report import output

    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    number = getattr(signal, name)
    real = output._validate_staging

    def checked(*args, **kwargs):
        os.kill(os.getpid(), number)
        return real(*args, **kwargs)

    monkeypatch.setattr(output, "_validate_staging", checked)
    before = signal.signal(number, signal.SIG_IGN)
    try:
        assert cli.main(["build", str(fixture.path), "-o", str(tmp_path / "out")]) == 0
        assert signal.getsignal(number) == signal.SIG_IGN
    finally:
        signal.signal(number, before)
    assert capsys.readouterr().out == f"ok    report {tmp_path / 'out'}\n"


def test_a_stop_just_after_the_rename_still_reports_the_report(tmp_path, capsys, monkeypatch):
    import pathlib

    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    real = pathlib.Path.rename

    def renamed(self, target):
        result = real(self, target)
        raise KeyboardInterrupt  # the stop lands once the report is in place

    monkeypatch.setattr(pathlib.Path, "rename", renamed)
    assert cli.main(["build", str(fixture.path), "-o", str(tmp_path / "out")]) == 0
    captured = capsys.readouterr()
    assert captured.out == f"ok    report {tmp_path / 'out'}\n" and captured.err == ""
    assert (tmp_path / "out" / "report.md").is_file()


@pytest.mark.parametrize(
    "row",
    [
        "lists//SECRET-INNER-NAME",
        "lists/./SECRET-INNER-NAME",
        "lists/../lists/SECRET-INNER-NAME",
        "targets/dc01/creds//SECRET-INNER-NAME",
        "tooldata/../tooldata/SECRET-INNER-NAME",
        "lists/SECRET-INNER-NAME/..",
        "/lists/SECRET-INNER-NAME",
    ],
)
def test_a_refused_manifest_row_in_a_held_back_place_is_named_by_the_place(tmp_path, row):
    base = make_archive(tmp_path / "b.tar.gz", full=True)
    members = {path: data for path, data in base.members.items() if path != "manifest.toml"}
    members["manifest.toml"] = manifest_bytes([*base.records, file_record(row, b"x")], kind=base.kind)
    bad = write_raw_archive(tmp_path / "bad.tar.gz", lambda tar: add_members(tar, members))
    with pytest.raises(ReportError) as raised:
        build_model(bad)
    message = str(raised.value)
    assert "SECRET-INNER-NAME" not in message, message
    assert any(place in message for place in ("lists/", "tooldata/", "targets/dc01/creds/")), message


def test_a_selection_file_name_with_a_line_separator_is_refused(tmp_path):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    selection = tmp_path / "pick ed.toml"
    selection.write_bytes(b"schema = 1\n")
    with pytest.raises(ReportError, match="selection filename is not portable"):
        build_model(fixture.path, selection)


def test_a_stop_while_the_handlers_are_set_is_one_line(tmp_path, capsys, monkeypatch, own_handlers):
    import signal

    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    real = signal.signal
    calls = []

    def setting(number, handler):
        previous = real(number, handler)
        calls.append(number)
        if len(calls) == 1:
            raise KeyboardInterrupt  # the stop lands once the first handler is set
        return previous

    monkeypatch.setattr(cli.signal, "signal", setting)
    try:
        status = cli.main(["build", str(fixture.path), "-o", str(tmp_path / "out")])
    except KeyboardInterrupt:
        pytest.fail("a stop while the handlers were set escaped main")
    assert status == 130
    assert capsys.readouterr().err == "fail  interrupted; no report was written\n"
    assert not (tmp_path / "out").exists() and not list(tmp_path.glob(".out.tmp-*"))

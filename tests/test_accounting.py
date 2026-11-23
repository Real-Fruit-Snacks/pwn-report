"""Every file the manifest lists is accounted for: indexed, held back, metadata, or other.

files/ and upload/ inside a target are indexed and copied only by selection; creds.toml, lists/,
targets/*/creds/ and tooldata/ hold credential material and are never read, only counted."""

from __future__ import annotations

import tarfile
import tomllib

import pytest

from fixtures import (
    CREDS_CANARY, CREDS_FOLDER_CANARY, FILES_CANARY, LISTS_CANARY, STRAY_CANARY, TOOLDATA_CANARY,
    UPLOAD_CANARY, make_archive,
)  # fmt: skip
from pwn_report import ReportError, build_model, build_report

HELD_BACK_FILES = {
    "creds.toml": CREDS_CANARY,
    "lists/passwords.txt": LISTS_CANARY,
    "targets/dc01/creds/admin.ccache": CREDS_FOLDER_CANARY,
    "tooldata/netexec/nxc.db": TOOLDATA_CANARY,
}


def _tree(root):
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def _selection(tmp_path, text):
    path = tmp_path / "selection.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_files_and_upload_are_indexed_not_copied(tmp_path):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    model = build_report(fixture.path, tmp_path / "out")
    rows = {item["path"]: item for item in model["evidence"]}
    files, upload = rows["targets/dc01/files/notes.txt"], rows["targets/dc01/upload/winpeas.exe"]
    assert (files["kind"], files["target"], files["output"]) == (
        "files", "dc01", {"copied": False, "reason": "default-exclude-files"}
    )
    assert (upload["kind"], upload["target"], upload["output"]) == (
        "upload", "dc01", {"copied": False, "reason": "default-exclude-upload"}
    )
    tree = _tree(tmp_path / "out")
    assert not any(path.startswith(("evidence/targets/dc01/files/", "evidence/targets/dc01/upload/")) for path in tree)
    assert all(FILES_CANARY not in data and UPLOAD_CANARY not in data for data in tree.values())


def test_a_selection_can_include_files_and_upload(tmp_path):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    selection = _selection(
        tmp_path,
        "schema = 1\n"
        "[[rule]]\npath = 'targets/dc01/files/notes.txt'\ninclude = true\n"
        "[[rule]]\npath = 'targets/dc01/upload/winpeas.exe'\ninclude = true\n",
    )
    model = build_report(fixture.path, tmp_path / "out", selection)
    rows = {item["path"]: item for item in model["evidence"]}
    for path in ("targets/dc01/files/notes.txt", "targets/dc01/upload/winpeas.exe"):
        assert rows[path]["output"] == {"copied": True, "reason": "selection-include", "path": "evidence/" + path}
        assert (tmp_path / "out" / "evidence" / path).read_bytes() == fixture.members[path]


def test_held_back_material_is_counted_and_never_opened(tmp_path, monkeypatch):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    opened = []
    real_extractfile = tarfile.TarFile.extractfile

    def observed(self, member):
        opened.append(member.name if isinstance(member, tarfile.TarInfo) else str(member))
        return real_extractfile(self, member)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", observed)
    model = build_report(fixture.path, tmp_path / "out")
    assert opened
    for path in HELD_BACK_FILES:
        assert not any(name.endswith("/" + path) for name in opened), path
    assert model["held_back"] == [
        {"path": "creds.toml", "files": 1},
        {"path": "lists/", "files": 1},
        {"path": "targets/dc01/creds/", "files": 1},
        {"path": "tooldata/", "files": 1},
    ]
    for relative, data in _tree(tmp_path / "out").items():
        for path, canary in HELD_BACK_FILES.items():
            assert canary not in data, (relative, path)
        # a held-back folder is named with its count; the files inside it are not named
        for inner in ("passwords.txt", "admin.ccache", "nxc.db"):
            assert inner.encode() not in data, (relative, inner)


@pytest.mark.parametrize("path", list(HELD_BACK_FILES))
def test_a_selection_naming_held_back_material_fails(tmp_path, path):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    selection = _selection(tmp_path, f"schema = 1\n[[rule]]\npath = '{path}'\ninclude = true\n")
    with pytest.raises(ReportError, match="held back"):
        build_model(fixture.path, selection)


def test_every_listed_file_is_accounted_for(tmp_path):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    model = build_model(fixture.path)
    listed = {row["path"] for row in tomllib.loads(fixture.manifest_bytes.decode("utf-8"))["file"]}
    evidence = {item["path"] for item in model["evidence"]}
    held = {path for path in listed for group in model["held_back"] if path == group["path"] or path.startswith(group["path"]) and group["path"].endswith("/")}
    metadata = {"box.toml", "notes.md", "targets/dc01/target.toml"}
    other = set(model["other"])
    assert evidence | held | (metadata & listed) | other == listed
    assert not (evidence & held) and not (evidence & other) and not (held & other)
    assert model["other"] == ["stray.txt"]
    assert sum(group["files"] for group in model["held_back"]) == len(held)


def test_the_report_shows_held_back_and_other(tmp_path):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    build_report(fixture.path, tmp_path / "out")
    text = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    section = text[text.index("## Not in the index\n"):text.index("## Notes\n")]
    assert "- creds.toml: held back\n" in section
    assert "- lists/: 1 file, held back\n" in section
    assert "- targets/dc01/creds/: 1 file, held back\n" in section
    assert "- tooldata/: 1 file, held back\n" in section
    assert "- stray.txt\n" in section
    assert STRAY_CANARY.decode() not in text


def test_a_box_with_nothing_held_back_or_other_says_so(tmp_path):
    fixture = make_archive(tmp_path / "a.tar.gz")
    model = build_report(fixture.path, tmp_path / "out")
    assert model["held_back"] == [] and model["other"] == []
    text = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    assert "## Not in the index\n\nNo files are held back or outside the index.\n" in text


def test_the_review_status_says_what_is_never_read_and_what_is_kept():
    from pwn_report.output import PRIVACY_NOTE

    assert PRIVACY_NOTE == (
        "It never reads `creds.toml`, `lists/`, `targets/*/creds/` or `tooldata/`. "
        "`notes.md` and every copied file are as they were and can hold passwords; keep this report private."
    )

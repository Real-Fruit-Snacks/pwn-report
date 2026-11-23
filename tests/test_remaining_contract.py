"""Small remaining boundary cases from the archive and privacy checklist."""

from __future__ import annotations

import tarfile

import pytest

from pwn_report import ReportError, build_report
from pwn_report import report as report_module

from fixtures import BOX_ID, file_record, make_archive, manifest_bytes, write_archive


def test_listed_files_and_upload_folders_are_ignored_and_never_opened(tmp_path, monkeypatch):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    members = dict(fixture.members)
    additions = {
        "targets/dc01/files/private.txt": b"FILES-FOLDER-CANARY",
        "upload/root.txt": b"UPLOAD-FOLDER-CANARY",
    }
    members.update(additions)
    records = list(fixture.records)
    records.extend(
        (
            file_record("targets/dc01/files/private.txt", additions["targets/dc01/files/private.txt"], target="dc01"),
            file_record("upload/root.txt", additions["upload/root.txt"]),
        )
    )
    members["manifest.toml"] = manifest_bytes(records, kind=fixture.kind)
    archive = write_archive(tmp_path / "unsupported-folders.tar.gz", members)
    opened = []
    real_extractfile = tarfile.TarFile.extractfile

    def observed(self, member):
        name = member.name if isinstance(member, tarfile.TarInfo) else str(member)
        opened.append(name)
        return real_extractfile(self, member)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", observed)
    destination = tmp_path / "report"
    model = build_report(archive, destination)
    paths = {item["path"] for item in model["evidence"]}
    assert not any("/files/" in path or path.startswith("upload/") for path in paths)
    assert not any("/files/" in name or name.endswith("/upload/root.txt") for name in opened)
    for output in destination.rglob("*"):
        if output.is_file():
            data = output.read_bytes()
            assert b"FILES-FOLDER-CANARY" not in data
            assert b"UPLOAD-FOLDER-CANARY" not in data


@pytest.mark.parametrize("member_type", [b"s", tarfile.REGTYPE, tarfile.DIRTYPE], ids=["socket", "regular-link-target", "directory-link-target"])
def test_socket_and_link_target_bearing_members_are_rejected(tmp_path, member_type):
    info = tarfile.TarInfo(f"{BOX_ID}/unsafe")
    info.type = member_type
    info.linkname = "" if member_type == b"s" else "../../outside"
    info.size = 0
    with pytest.raises(ReportError):
        report_module._check_member(info)


def test_negative_size_and_excessive_owner_are_rejected_directly():
    negative = tarfile.TarInfo(f"{BOX_ID}/negative")
    negative.size = -1
    with pytest.raises(ReportError, match="invalid size"):
        report_module._check_member(negative)

    for field in ("uid", "gid"):
        info = tarfile.TarInfo(f"{BOX_ID}/owner")
        setattr(info, field, report_module.MAX_OWNER + 1)
        with pytest.raises(ReportError, match="invalid owner"):
            report_module._check_member(info)


def test_multibyte_member_name_limit_counts_utf8_bytes():
    at_boundary = tarfile.TarInfo("é" * 2048)
    assert len(at_boundary.name.encode("utf-8")) == report_module.MAX_NAME_BYTES
    report_module._check_member(at_boundary)

    over = tarfile.TarInfo("é" * 2048 + "a")
    assert len(over.name.encode("utf-8")) == report_module.MAX_NAME_BYTES + 1
    with pytest.raises(ReportError, match="exceeds 4096 bytes"):
        report_module._check_member(over)


def test_surrogate_and_noncanonical_model_paths_fail_cleanly():
    with pytest.raises(ReportError, match="valid Unicode"):
        report_module._relative_path("screenshots/\udcff.png", "evidence")
    for path in ("", ".", "./proof.png", "screenshots//proof.png", "screenshots/../proof.png", "C:/proof.png"):
        with pytest.raises(ReportError, match="portable relative path|nonempty string"):
            report_module._relative_path(path, "evidence")

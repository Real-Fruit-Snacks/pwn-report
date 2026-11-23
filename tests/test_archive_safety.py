"""Archive-member safety: traversal, links, and ambiguous box roots."""

from __future__ import annotations

import os
import tarfile

import pytest

from pwn_report import ReportError, build_model

from fixtures import BOX_ID, add_bytes, add_dir, add_members, make_archive, write_raw_archive


def _reject(path, match):
    before = path.read_bytes()
    with pytest.raises(ReportError, match=match):
        build_model(path)
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "name",
    [
        "../escape.txt",
        f"{BOX_ID}/../escape.txt",
        f"{BOX_ID}/../../escape.txt",
        "/absolute.txt",
        pytest.param(
            f"{BOX_ID}\\..\\escape.txt",
            marks=pytest.mark.skipif(os.sep != "\\", reason="backslash is a path separator only on Windows"),
        ),
    ],
    ids=["outside-root", "parent", "two-parents", "absolute", "windows-backslash"],
)
def test_escaping_or_absolute_members_are_rejected(tmp_path, name):
    source = make_archive(tmp_path / "source" / "source.tar.gz")
    original = source.path.read_bytes()

    def write(tar):
        add_members(tar, source.members)
        add_bytes(tar, name, b"must never escape")

    archive = write_raw_archive(tmp_path / "mutated" / "traversal.tar.gz", write)
    _reject(archive, "escapes its box root")
    assert source.path.read_bytes() == original
    assert not (tmp_path / "escape.txt").exists()


@pytest.mark.parametrize("member_type", [tarfile.SYMTYPE, tarfile.LNKTYPE], ids=["symlink", "hardlink"])
def test_link_members_are_rejected_without_creating_links(tmp_path, member_type):
    source = make_archive(tmp_path / "source" / "source.tar.gz")
    original = source.path.read_bytes()

    def write(tar):
        add_members(tar, source.members)
        info = tarfile.TarInfo(f"{BOX_ID}/linked-evidence")
        info.type = member_type
        info.linkname = "../../outside"
        info.mtime = 0
        info.mode = 0o777
        tar.addfile(info)

    archive = write_raw_archive(tmp_path / "mutated" / "link.tar.gz", write)
    _reject(archive, "is not a regular file or folder")
    assert source.path.read_bytes() == original
    assert not (tmp_path / "linked-evidence").exists()


def test_multiple_box_roots_are_rejected(tmp_path):
    source = make_archive(tmp_path / "source" / "source.tar.gz")
    original = source.path.read_bytes()

    def write(tar):
        add_members(tar, source.members)
        add_dir(tar, "another-box")
        add_bytes(tar, "another-box/manifest.toml", source.manifest_bytes)

    archive = write_raw_archive(tmp_path / "mutated" / "two-roots.tar.gz", write)
    _reject(archive, "exactly one box root")
    assert source.path.read_bytes() == original


def test_bare_top_level_file_is_rejected(tmp_path):
    source = make_archive(tmp_path / "source" / "source.tar.gz")
    original = source.path.read_bytes()

    def write(tar):
        add_bytes(tar, BOX_ID, b"root is a file, not a folder")
        add_bytes(tar, f"{BOX_ID}/box.toml", source.members["box.toml"])
        add_bytes(tar, f"{BOX_ID}/manifest.toml", source.manifest_bytes)

    archive = write_raw_archive(tmp_path / "mutated" / "bare-file.tar.gz", write)
    _reject(archive, "one regular box-root folder")
    assert source.path.read_bytes() == original

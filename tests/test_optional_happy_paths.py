"""H03/H04 archive kinds and H14's manifest without a file collection."""

from __future__ import annotations

import tomllib

import pytest

from pwn_report import ReportError, build_model

from fixtures import LATER, make_archive, write_archive


def test_h03_finished_archive_preserves_finished_time_without_publishing(tmp_path):
    fixture = make_archive(
        tmp_path / "forest.finished.tar.gz",
        full=True,
        kind="finished",
        finished=LATER,
    )
    original = fixture.path.read_bytes()

    model = build_model(fixture.path)
    assert model == fixture.model
    assert model["source"]["archive"]["kind"] == "finished"
    assert model["box"]["finished"] == LATER.isoformat()
    assert model["status"] == "draft"
    assert model["findings"] == []
    assert "published" not in model
    assert fixture.path.read_bytes() == original


@pytest.mark.parametrize(
    ("kind", "finished"),
    [("exported", LATER), ("finished", None)],
    ids=["exported-with-finished-time", "finished-without-finished-time"],
)
def test_h04_archive_kind_does_not_impose_a_finished_time(tmp_path, kind, finished):
    fixture = make_archive(tmp_path / f"{kind}.tar.gz", kind=kind, finished=finished)
    original = fixture.path.read_bytes()

    model = build_model(fixture.path)
    assert model == fixture.model
    assert model["source"]["archive"]["kind"] == kind
    if finished is None:
        assert "finished" not in model["box"]
    else:
        assert model["box"]["finished"] == finished.isoformat()
    assert model["status"] == "draft"
    assert fixture.path.read_bytes() == original


def test_h14_manifest_without_file_key_is_refused_for_its_unlisted_box_toml(tmp_path):
    # pwn-broker always lists box.toml; a manifest with no file rows lists nothing, so the box's own
    # facts would be used unchecked
    source = make_archive(tmp_path / "source" / "source.tar.gz")
    members = dict(source.members)
    head, remainder = source.manifest_bytes.split(b"[box]\n", 1)
    box_fields = remainder.split(b"\n[[file]]", 1)[0]
    manifest = head + b"[box]\n" + box_fields
    assert "file" not in tomllib.loads(manifest.decode("utf-8"))
    members["manifest.toml"] = manifest
    archive = write_archive(tmp_path / "without-file-key.tar.gz", members)
    original = archive.read_bytes()
    with pytest.raises(ReportError, match="box.toml is not listed in manifest.toml"):
        build_model(archive)
    assert archive.read_bytes() == original

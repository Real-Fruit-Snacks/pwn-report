"""First rejection tranche: manifests, altered evidence, and duplicate rows."""

from __future__ import annotations

import pytest

from pwn_report import ReportError, build_model
from pwn_report import report as report_module

from fixtures import make_archive, manifest_bytes, write_archive

EVIDENCE = "targets/dc01/scans/nmap.txt"


def _reject(path, match):
    before = path.read_bytes()
    with pytest.raises(ReportError, match=match):
        build_model(path)
    assert path.read_bytes() == before


@pytest.mark.parametrize("subfolder", [False, True], ids=["missing", "subfolder-only"])
def test_missing_root_manifest_is_rejected(tmp_path, subfolder):
    source = make_archive(tmp_path / "source" / "source.tar.gz")
    original = source.path.read_bytes()
    members = dict(source.members)
    manifest = members.pop("manifest.toml")
    if subfolder:
        members["nested/manifest.toml"] = manifest
    archive = write_archive(tmp_path / "mutated" / "bad.tar.gz", members)

    _reject(archive, "manifest.toml is missing from the archive")
    assert source.path.read_bytes() == original


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        ("content", "checksum differs from manifest.toml"),
        ("size", "size differs from manifest.toml"),
        ("missing", "is missing from the archive"),
    ],
)
def test_altered_or_missing_evidence_is_rejected(tmp_path, mutation, match):
    source = make_archive(tmp_path / "source" / "source.tar.gz", full=True)
    original = source.path.read_bytes()
    members = dict(source.members)
    records = list(source.records)

    if mutation == "content":
        replacement = b"XXX scan\n"
        assert len(replacement) == len(members[EVIDENCE])
        members[EVIDENCE] = replacement
    elif mutation == "size":
        members[EVIDENCE] += b"changed"
    else:
        del members[EVIDENCE]

    # The manifest continues to claim the original evidence record.
    members["manifest.toml"] = manifest_bytes(records, kind=source.kind)
    assert members["manifest.toml"] == source.manifest_bytes
    archive = write_archive(tmp_path / "mutated" / f"{mutation}.tar.gz", members)

    _reject(archive, match)
    assert source.path.read_bytes() == original


def test_duplicate_manifest_row_fails_before_evidence_hashing(tmp_path, monkeypatch):
    source = make_archive(tmp_path / "source" / "source.tar.gz", full=True)
    original = source.path.read_bytes()
    members = dict(source.members)
    records = list(source.records)
    index = next(index for index, record in enumerate(records) if record.path == EVIDENCE)
    records.insert(index + 1, records[index])
    members["manifest.toml"] = manifest_bytes(records, kind=source.kind)
    archive = write_archive(tmp_path / "mutated" / "duplicate.tar.gz", members)

    def no_content_hashing(*args, **kwargs):
        raise AssertionError("evidence hashing began before the duplicate was rejected")

    monkeypatch.setattr(report_module, "_member_sha", no_content_hashing)
    _reject(archive, f"{EVIDENCE} is listed twice in manifest.toml")
    assert source.path.read_bytes() == original

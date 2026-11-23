"""Malformed manifests and archive/box/target metadata consistency."""

from __future__ import annotations

from dataclasses import replace

import pytest

from pwn_report import ReportError, build_model

from fixtures import BOX_ID, LATER, NOW, PACKED, make_archive, manifest_bytes, sha256, write_archive

BOX_PATH = "box.toml"
TARGET_PATH = "targets/dc01/target.toml"


def _reject(path, match):
    before = path.read_bytes()
    with pytest.raises(ReportError, match=match):
        build_model(path)
    assert path.read_bytes() == before


def _replace_once(data: bytes, old: bytes, new: bytes) -> bytes:
    assert data.count(old) == 1
    return data.replace(old, new, 1)


def _without_file_rows(manifest: bytes):
    head, remainder = manifest.split(b"[box]\n", 1)
    box_fields = remainder.split(b"\n[[file]]", 1)[0]
    return head, box_fields


def _write_with_records(source, destination, members, records, *, finished=None):
    members["manifest.toml"] = manifest_bytes(records, kind=source.kind, finished=finished)
    return write_archive(destination, members)


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        ("invalid-toml", "manifest.toml cannot be read"),
        ("invalid-utf8", "manifest.toml cannot be read"),
        ("wrong-schema", "manifest.toml schema must be schema 1"),
        ("invalid-kind", "kind must be finished or exported"),
        ("invalid-packed", "packed must be an offset-aware datetime"),
        ("file-not-list", "file must be a list"),
        ("row-not-table", "must be a table"),
        ("missing-box", "box must be a table"),
    ],
)
def test_malformed_manifest_documents_are_rejected(tmp_path, mutation, match):
    source = make_archive(tmp_path / "source" / "source.tar.gz")
    original = source.path.read_bytes()
    members = dict(source.members)
    manifest = source.manifest_bytes

    if mutation == "invalid-toml":
        manifest = b"= not valid TOML"
    elif mutation == "invalid-utf8":
        manifest = b"\xff\xfe\x00"
    elif mutation == "wrong-schema":
        manifest = _replace_once(manifest, b"schema = 1", b"schema = 2")
    elif mutation == "invalid-kind":
        manifest = _replace_once(manifest, b'kind = "exported"', b'kind = "unknown"')
    elif mutation == "invalid-packed":
        manifest = _replace_once(manifest, f"packed = {PACKED.isoformat()}".encode(), b'packed = "yesterday"')
    elif mutation in {"file-not-list", "row-not-table"}:
        head, box_fields = _without_file_rows(manifest)
        value = b'"not-a-list"' if mutation == "file-not-list" else b"[1]"
        manifest = head + b"file = " + value + b"\n\n[box]\n" + box_fields
    elif mutation == "missing-box":
        head = manifest.split(b"[box]\n", 1)[0]
        rows = b"[[file]]" + manifest.split(b"\n[[file]]", 1)[1]
        manifest = head + rows

    members["manifest.toml"] = manifest
    archive = write_archive(tmp_path / "mutated" / f"{mutation}.tar.gz", members)
    _reject(archive, match)
    assert source.path.read_bytes() == original


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"path": 3}, "path must be a nonempty string"),
        ({"path": "../escape"}, "portable relative path"),
        ({"target": 5}, "target must be a string"),
        ({"first_seen": "yesterday"}, "first_seen must be an offset-aware datetime"),
        ({"size": -1}, "size must be a nonnegative integer"),
        ({"size": True}, "size must be a nonnegative integer"),
        ({"mtime": float("nan")}, "mtime must be a finite number"),
        ({"mtime": 10**400}, "mtime must be a finite number"),
        ({"sha256": 5}, "sha256 must be a nonempty string"),
        ({"sha256": ""}, "sha256 must be a nonempty string"),
        ({"sha256": "A" * 64}, "sha256 must be a lowercase SHA-256"),
    ],
)
def test_malformed_manifest_file_rows_are_rejected(tmp_path, changes, match):
    source = make_archive(tmp_path / "source" / "source.tar.gz")
    original = source.path.read_bytes()
    members = dict(source.members)
    records = [replace(source.records[0], **changes)]
    archive = _write_with_records(source, tmp_path / "mutated" / "bad-row.tar.gz", members, records)
    _reject(archive, match)
    assert source.path.read_bytes() == original


@pytest.mark.parametrize("field", ["name", "started", "finished"])
def test_manifest_box_facts_must_match_box_toml(tmp_path, field):
    finished = LATER if field == "finished" else None
    source = make_archive(tmp_path / "source" / "source.tar.gz", finished=finished)
    original = source.path.read_bytes()
    members = dict(source.members)

    if field == "name":
        members["manifest.toml"] = _replace_once(source.manifest_bytes, b'name = "forest"', b'name = "other"')
    elif field == "started":
        members["manifest.toml"] = _replace_once(
            source.manifest_bytes,
            f"started = {NOW.isoformat()}".encode(),
            f"started = {LATER.isoformat()}".encode(),
        )
    else:
        # box.toml says finished; the regenerated manifest omits that fact.
        members["manifest.toml"] = manifest_bytes(source.records, kind=source.kind, finished=None)

    archive = write_archive(tmp_path / "mutated" / f"box-{field}.tar.gz", members)
    _reject(archive, f"box {field} differs from box.toml")
    assert source.path.read_bytes() == original


def _updated_metadata_archive(source, destination, members, path, data):
    members[path] = data
    records = [
        replace(record, size=len(data), sha256=sha256(data)) if record.path == path else record
        for record in source.records
    ]
    return _write_with_records(source, destination, members, records)


@pytest.mark.parametrize("field", ["box_id", "box", "name"])
def test_target_identity_must_match_its_box_and_path(tmp_path, field):
    source = make_archive(tmp_path / "source" / "source.tar.gz", full=True)
    original = source.path.read_bytes()
    members = dict(source.members)
    target = members[TARGET_PATH]
    replacements = {
        "box_id": (f'box_id = "{BOX_ID}"'.encode(), b'box_id = "other-id"'),
        "box": (b'box = "forest"', b'box = "other"'),
        "name": (b'name = "dc01"', b'name = "web1"'),
    }
    target = _replace_once(target, *replacements[field])
    archive = _updated_metadata_archive(
        source,
        tmp_path / "mutated" / f"target-{field}.tar.gz",
        members,
        TARGET_PATH,
        target,
    )
    _reject(archive, "target identity differs from its box or path")
    assert source.path.read_bytes() == original


@pytest.mark.parametrize("path", [BOX_PATH, TARGET_PATH], ids=["box", "target"])
def test_metadata_schema_version_must_match(tmp_path, path):
    source = make_archive(tmp_path / "source" / "source.tar.gz", full=True)
    original = source.path.read_bytes()
    members = dict(source.members)
    data = _replace_once(members[path], b"schema = 1", b"schema = 2")
    archive = _updated_metadata_archive(source, tmp_path / "mutated" / "schema.tar.gz", members, path, data)
    _reject(archive, f"{path} schema must be schema 1")
    assert source.path.read_bytes() == original

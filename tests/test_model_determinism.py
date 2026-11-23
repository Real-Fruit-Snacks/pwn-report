"""H05 and model-only H11/H12/H13/H15 determinism coverage."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from pwn_report import build_model

from fixtures import (
    BOX_ID,
    NOW,
    UNLISTED_CANARY,
    canonical_json,
    file_record,
    make_archive,
    manifest_bytes,
    sha256,
    write_archive,
)

BOX_PATH = "box.toml"
DC_TARGET = "targets/dc01/target.toml"
DB_TARGET = "targets/db01/target.toml"
EVIDENCE = "targets/dc01/scans/nmap.txt"


def _write(source, destination, members, records):
    members["manifest.toml"] = manifest_bytes(records, kind=source.kind)
    return write_archive(destination, members)


def _projection(model):
    return {key: model[key] for key in ("box", "flags", "targets", "timeline", "evidence", "findings")}


def _event_key(event):
    return (
        event["at"],
        event["kind"],
        json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"),
    )


def _multi_target_archive(source, destination, *, reverse):
    members = dict(source.members)
    members[BOX_PATH] += (
        f'\n[flags.zzz]\nvalue = "ZZZ-PRIVATE"\nat = {NOW.isoformat()}\n'
        f'\n[flags.aaa]\nvalue = "AAA-PRIVATE"\nat = {NOW.isoformat()}\n'
    ).encode("utf-8")
    members[DB_TARGET] = (
        "schema = 1\n"
        f'box_id = "{BOX_ID}"\n'
        'box = "forest"\n'
        'name = "db01"\n'
        'ips = ["10.10.10.162"]\n'
        "hostnames = []\n"
        'scope = "internal"\n'
        f"added = {NOW.isoformat()}\n"
    ).encode("utf-8")
    records = [
        replace(record, size=len(members[BOX_PATH]), sha256=sha256(members[BOX_PATH]))
        if record.path == BOX_PATH
        else record
        for record in source.records
    ]
    records.insert(0, file_record(DB_TARGET, members[DB_TARGET], target="db01"))
    if reverse:
        records.reverse()
    return _write(source, destination, members, records)


def test_h05_targets_flags_and_equal_time_events_have_total_ordering(tmp_path):
    source = make_archive(tmp_path / "source" / "source.tar.gz", full=True)
    first_path = _multi_target_archive(source, tmp_path / "first.tar.gz", reverse=False)
    second_path = _multi_target_archive(source, tmp_path / "second.tar.gz", reverse=True)

    first = build_model(first_path)
    second = build_model(second_path)
    assert [target["name"] for target in first["targets"]] == ["db01", "dc01"]
    assert first["targets"][0]["ips"] == ["10.10.10.162"]
    assert [flag["name"] for flag in first["flags"]] == ["aaa", "root", "user", "zzz"]
    assert first["timeline"] == sorted(first["timeline"], key=_event_key)

    for kind, reference in (("target_added", "target"), ("flag_recorded", "flag"), ("file_first_seen", "evidence_id")):
        references = [event[reference] for event in first["timeline"] if event["kind"] == kind]
        assert len(references) == len(set(references))

    # Manifest insertion order changes provenance bytes, never these derived records.
    assert _projection(first) == _projection(second)


def test_h11_manifest_reordering_preserves_ids_and_derived_order(tmp_path):
    source = make_archive(tmp_path / "source" / "source.tar.gz", full=True)
    reordered = list(reversed(source.records))
    members = dict(source.members)
    archive = _write(source, tmp_path / "reordered.tar.gz", members, reordered)

    original_model = build_model(source.path)
    reordered_model = build_model(archive)
    assert _projection(reordered_model) == _projection(original_model)
    assert reordered_model["notes"] == original_model["notes"]
    assert [item["id"] for item in reordered_model["evidence"]] == [item["id"] for item in original_model["evidence"]]
    assert reordered_model["source"]["manifest"] != original_model["source"]["manifest"]
    assert reordered_model["source"]["archive"]["sha256"] != original_model["source"]["archive"]["sha256"]


def test_h12_evidence_id_inputs_are_explicit_and_unrelated_ids_stay_stable(tmp_path):
    source = make_archive(tmp_path / "source" / "source.tar.gz", full=True)
    base = build_model(source.path)
    base_ids = {item["path"]: item["id"] for item in base["evidence"]}

    # Content changes affect only that evidence item.
    members = dict(source.members)
    members[EVIDENCE] = b"changed scan contents\n"
    records = [
        replace(record, size=len(members[EVIDENCE]), sha256=sha256(members[EVIDENCE]))
        if record.path == EVIDENCE
        else record
        for record in source.records
    ]
    content_model = build_model(_write(source, tmp_path / "content.tar.gz", members, records))
    for item in content_model["evidence"]:
        if item["path"] == EVIDENCE:
            assert item["id"] != base_ids[EVIDENCE]
        else:
            assert item["id"] == base_ids[item["path"]]

    # Path changes affect only the moved item.
    renamed = "targets/dc01/scans/renamed.txt"
    members = dict(source.members)
    members[renamed] = members.pop(EVIDENCE)
    records = [replace(record, path=renamed) if record.path == EVIDENCE else record for record in source.records]
    path_model = build_model(_write(source, tmp_path / "path.tar.gz", members, records))
    path_ids = {item["path"]: item["id"] for item in path_model["evidence"]}
    assert path_ids[renamed] != base_ids[EVIDENCE]
    for path, identifier in base_ids.items():
        if path != EVIDENCE:
            assert path_ids[path] == identifier

    # Box identity is an ID input, so every evidence ID changes together.
    new_box_id = "2026-11-15_htb_forest"
    members = dict(source.members)
    members[BOX_PATH] = members[BOX_PATH].replace(f'id = "{BOX_ID}"'.encode(), f'id = "{new_box_id}"'.encode(), 1)
    members[DC_TARGET] = members[DC_TARGET].replace(
        f'box_id = "{BOX_ID}"'.encode(), f'box_id = "{new_box_id}"'.encode(), 1
    )
    records = [
        replace(record, size=len(members[record.path]), sha256=sha256(members[record.path]))
        if record.path in {BOX_PATH, DC_TARGET}
        else record
        for record in source.records
    ]
    members["manifest.toml"] = manifest_bytes(records, kind=source.kind).replace(
        f'id = "{BOX_ID}"'.encode(), f'id = "{new_box_id}"'.encode(), 1
    )
    box_archive = write_archive(tmp_path / "box-id.tar.gz", members)
    box_model = build_model(box_archive)
    assert box_model["box"]["id"] == new_box_id
    assert all(item["id"] != base_ids[item["path"]] for item in box_model["evidence"])


def test_h13_absolute_and_relative_paths_are_cwd_independent(tmp_path, monkeypatch):
    fixture = make_archive(tmp_path / "archive" / "forest.tar.gz", full=True)
    absolute_model = build_model(fixture.path.resolve())

    monkeypatch.chdir(fixture.path.parent)
    relative_model = build_model(Path(fixture.path.name))
    other = tmp_path / "other-cwd"
    other.mkdir()
    monkeypatch.chdir(other)
    string_model = build_model(str(fixture.path.resolve()))

    assert absolute_model == relative_model == string_model == fixture.model
    encoded = canonical_json(absolute_model)
    assert str(tmp_path).encode("utf-8") not in encoded


def test_h15_unlisted_extra_and_notes_are_not_indexed(tmp_path):
    source = make_archive(tmp_path / "source" / "source.tar.gz", full=True)
    members = dict(source.members)  # notes.md and unlisted.txt remain archived but unlisted.
    records = [record for record in source.records if record.path != "notes.md"]
    archive = _write(source, tmp_path / "unlisted-notes.tar.gz", members, records)

    base = build_model(source.path)
    model = build_model(archive)
    assert "notes" not in model
    assert "unlisted.txt" not in {item["path"] for item in model["evidence"]}
    assert model["evidence"] == base["evidence"]
    assert model["targets"] == base["targets"]
    assert model["flags"] == base["flags"]
    assert model["timeline"] == base["timeline"]
    assert UNLISTED_CANARY not in canonical_json(model)

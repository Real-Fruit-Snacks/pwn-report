"""Section 7 schema and semantic-contract mutations on minimal and full models."""

from __future__ import annotations

import math
from copy import deepcopy
from dataclasses import replace

import pytest

from pwn_report import ReportError, build_model, validate_model

from fixtures import canonical_json, make_archive, manifest_bytes, sha256, write_archive

SCAN = "targets/dc01/scans/nmap.txt"
LOOT = "targets/dc01/loot/SAM.bak"
ROOT_SCREENSHOT = "screenshots/root.png"
TARGET = "targets/dc01/target.toml"
DELETE = object()


def _minimal(tmp_path):
    return deepcopy(make_archive(tmp_path / "minimal.tar.gz").model)


def _full(tmp_path):
    return deepcopy(make_archive(tmp_path / "full.tar.gz", full=True).model)


def _set(model, path, value):
    target = model
    for part in path[:-1]:
        target = target[part]
    if value is DELETE:
        del target[path[-1]]
    else:
        target[path[-1]] = value


def _reject(model):
    with pytest.raises(ReportError):
        validate_model(model)


def _evidence(model, path=SCAN):
    return next(item for item in model["evidence"] if item["path"] == path)


def test_independently_constructed_minimal_and_full_models_are_valid(tmp_path):
    minimal = _minimal(tmp_path)
    full = _full(tmp_path)
    assert validate_model(minimal) is minimal
    assert validate_model(full) is full
    assert canonical_json(minimal).endswith(b"\n")
    assert canonical_json(full).endswith(b"\n")


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("schema_version",), 2),
        (("schema_version",), True),
        (("schema_version",), DELETE),
        (("profile",), "public"),
        (("profile",), []),
        (("status",), "reviewed"),
        (("status",), 1),
        (("findings",), [{"id": "finding-1"}]),
        (("findings",), {}),
        (("unknown",), True),
        (("credentials",), {}),
        (("narrative",), "invented"),
        (("review",), "approved"),
        (("box",), DELETE),
        (("evidence",), DELETE),
        (("box", "unknown"), "value"),
        (("box", "id"), ""),
        (("box", "started"), "2026-11-14 12:00:00+02:00"),
        (("box", "started"), "2026-11-14T12:00:00"),
        (("box", "finished"), "not-a-time"),
        (("box", "source", "path"), "/machine/box.toml"),
        (("box", "source", "sha256"), "A" * 64),
        (("source", "unknown"), {}),
        (("source", "archive", "kind"), "other"),
        (("source", "archive", "kind"), []),
        (("source", "archive", "packed"), "yesterday"),
        (("source", "archive", "sha256"), "abc"),
        (("source", "manifest", "path"), "../manifest.toml"),
        (("source", "selection"), {"name": "/tmp/selection.toml", "sha256": "0" * 64}),
        (("source", "selection"), {"name": "selection.toml", "sha256": "bad"}),
        (("flags",), {}),
        (("targets",), {}),
        (("timeline",), {}),
        (("evidence",), {}),
    ],
    ids=lambda value: str(value) if isinstance(value, tuple) else None,
)
def test_top_level_box_and_provenance_schema_mutations(tmp_path, path, value):
    model = _minimal(tmp_path)
    _set(model, path, value)
    _reject(model)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("box_id", "different-box"),
        ("box", "different-name"),
        ("name", ""),
        ("ips", "10.10.10.161"),
        ("scope", ""),
        ("added", "2026-11-14"),
        ("unknown", True),
    ],
)
def test_target_structure_and_box_ownership_mutations(tmp_path, field, value):
    model = _full(tmp_path)
    model["targets"][0][field] = value
    _reject(model)


@pytest.mark.parametrize("source_path", ["other/target.toml", "/targets/dc01/target.toml", "targets\\dc01\\target.toml"])
def test_target_source_must_match_identity_and_be_portable(tmp_path, source_path):
    model = _full(tmp_path)
    model["targets"][0]["source"]["path"] = source_path
    _reject(model)


def test_duplicate_target_names_and_target_order_are_rejected(tmp_path):
    model = _full(tmp_path)
    duplicate = deepcopy(model["targets"][0])
    model["targets"].append(duplicate)
    _reject(model)

    model = _full(tmp_path)
    second = deepcopy(model["targets"][0])
    second["name"] = "aaa"
    second["source"]["path"] = "targets/aaa/target.toml"
    model["targets"].append(second)
    model["targets"].reverse()
    # Remove the old target event; add a source-consistent event for the new target.
    model["timeline"] = [event for event in model["timeline"] if event["kind"] != "target_added"]
    for target in model["targets"]:
        model["timeline"].append(
            {"at": target["added"], "kind": "target_added", "target": target["name"], "source": target["source"]}
        )
    _reject(model)


def test_duplicate_flag_names_and_flag_source_mismatch_are_rejected(tmp_path):
    model = _full(tmp_path)
    model["flags"].append(deepcopy(model["flags"][0]))
    _reject(model)

    model = _full(tmp_path)
    model["flags"][0]["source"]["path"] = "other.toml"
    _reject(model)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", "bad-id"),
        ("sha256", "A" * 64),
        ("sha256", "abc"),
        ("size", -1),
        ("size", True),
        ("mtime", math.nan),
        ("mtime", math.inf),
        ("mtime", "0"),
        ("first_seen", "2026-11-14T12:15:00"),
        ("path", "/absolute/path"),
        ("path", "../escape"),
        ("path", "targets\\dc01\\scans\\nmap.txt"),
        ("path", "targets/dc01//scans/nmap.txt"),
        ("kind", "other"),
        ("target_refs", ["missing"]),
        ("target_refs", ["dc01", "dc01"]),
        ("caption", ""),
        ("alt_text", 1),
        ("severity", "high"),
    ],
)
def test_evidence_structure_path_number_and_reference_mutations(tmp_path, field, value):
    model = _full(tmp_path)
    _evidence(model)[field] = value
    _reject(model)


def test_evidence_id_must_be_derived_not_merely_well_formed(tmp_path):
    model = _full(tmp_path)
    item = _evidence(model)
    replacement = "0" if item["id"][-1] != "0" else "1"
    item["id"] = item["id"][:-1] + replacement
    _reject(model)


@pytest.mark.parametrize("field", ["path", "sha256"])
def test_evidence_source_must_match_its_own_path_and_hash(tmp_path, field):
    model = _full(tmp_path)
    item = _evidence(model)
    item["source"][field] = "other" if field == "path" else "0" * 64
    _reject(model)


def test_copied_and_omitted_output_decisions_are_internally_consistent(tmp_path):
    model = _full(tmp_path)
    del _evidence(model, ROOT_SCREENSHOT)["output"]["path"]
    _reject(model)

    model = _full(tmp_path)
    _evidence(model, ROOT_SCREENSHOT)["output"]["reason"] = "unknown"
    _reject(model)

    model = _full(tmp_path)
    _evidence(model, ROOT_SCREENSHOT)["output"]["reason"] = []
    _reject(model)

    model = _full(tmp_path)
    _evidence(model, ROOT_SCREENSHOT)["output"]["copied"] = 1
    _reject(model)

    model = _full(tmp_path)
    _evidence(model, LOOT)["output"]["path"] = "evidence/" + LOOT
    _reject(model)

    model = _full(tmp_path)
    _evidence(model, ROOT_SCREENSHOT)["output"]["reason"] = "selection-include"
    _reject(model)


def test_duplicate_evidence_and_output_paths_are_rejected(tmp_path):
    model = _full(tmp_path)
    model["evidence"].append(deepcopy(model["evidence"][0]))
    _reject(model)

    model = _full(tmp_path)
    first = _evidence(model, ROOT_SCREENSHOT)
    second = deepcopy(first)
    second["path"] = "screenshots/second.png"
    second["sha256"] = "0" * 64
    second["source"] = {"path": second["path"], "sha256": second["sha256"]}
    # Keep a valid derived ID while deliberately reusing the first output path.
    import hashlib

    payload = f"pwn-report\0evidence\0v1\0{model['box']['id']}\0{second['path']}\0{second['sha256']}".encode()
    second["id"] = "ev_" + hashlib.sha256(payload).hexdigest()
    second["output"]["path"] = first["output"]["path"]
    model["evidence"].append(second)
    model["evidence"].sort(key=lambda item: item["path"])
    _reject(model)


@pytest.mark.parametrize(
    "mutation",
    ["mixed-target-flag", "missing-target", "extra-property", "dangling-target", "dangling-evidence", "kind-not-string", "invalid-time", "duplicate"],
)
def test_timeline_variant_reference_and_uniqueness_mutations(tmp_path, mutation):
    model = _full(tmp_path)
    target_index = next(index for index, event in enumerate(model["timeline"]) if event["kind"] == "target_added")
    event = model["timeline"][target_index]
    if mutation == "mixed-target-flag":
        event["flag"] = "root"
    elif mutation == "missing-target":
        del event["target"]
    elif mutation == "extra-property":
        event["severity"] = "high"
    elif mutation == "dangling-target":
        event["target"] = "missing"
    elif mutation == "dangling-evidence":
        evidence_event = next(event for event in model["timeline"] if event["kind"] == "file_first_seen")
        evidence_event["evidence_id"] = "ev_" + "0" * 64
    elif mutation == "kind-not-string":
        event["kind"] = []
    elif mutation == "invalid-time":
        event["at"] = "not-a-time"
    else:
        model["timeline"].append(deepcopy(event))
    _reject(model)


def test_timeline_must_match_source_times_sources_and_canonical_order(tmp_path):
    model = _full(tmp_path)
    event = next(event for event in model["timeline"] if event["kind"] == "target_added")
    event["at"] = model["box"]["finished"] if "finished" in model["box"] else "2026-11-14T12:01:00+02:00"
    _reject(model)

    model = _full(tmp_path)
    event = next(event for event in model["timeline"] if event["kind"] == "target_added")
    event["source"] = deepcopy(event["source"])
    event["source"]["sha256"] = "0" * 64
    _reject(model)

    model = _full(tmp_path)
    model["timeline"].reverse()
    _reject(model)


def test_notes_paths_are_fixed_and_unknown_nested_properties_fail(tmp_path):
    model = _full(tmp_path)
    model["notes"]["report_path"] = "notes.md"
    _reject(model)

    model = _full(tmp_path)
    model["notes"]["source"]["path"] = "other.md"
    _reject(model)

    model = _full(tmp_path)
    model["notes"]["summary"] = "not allowed"
    _reject(model)


def test_evidence_of_a_target_with_no_target_toml_is_listed_as_other(tmp_path):
    # a folder under targets/ is a target only with its target.toml; files in one without it are
    # listed by path, so one stray folder never costs the whole report
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    members = dict(fixture.members)
    del members[TARGET]
    records = [record for record in fixture.records if record.path != TARGET]
    members["manifest.toml"] = manifest_bytes(records, kind=fixture.kind)
    archive = write_archive(tmp_path / "dangling-target.tar.gz", members)
    model = build_model(archive)
    assert model["targets"] == []
    assert not any(item["target"] == "dc01" for item in model["evidence"])
    assert "targets/dc01/scans/nmap.txt" in model["other"]

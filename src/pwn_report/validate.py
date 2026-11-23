"""Standard-library structural and semantic validation for canonical v1 models."""

from __future__ import annotations

import hashlib
import math
import re
from datetime import datetime

from .report import (
    ALL_KINDS, DEFAULT_OMITTED, MAY_BE_EMPTY, METADATA, ReportError, _event_key, _evidence_location,
    held_back_group, is_target_toml,
)  # fmt: skip

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_ID = re.compile(r"^ev_[0-9a-f]{64}$")
_DATETIME = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
_MISSING = object()
_HELD_BACK_PATH = re.compile(r"^(?:creds\.toml|lists/|tooldata/|targets/[^/]+/creds/)$")


def _fail(label: str, message: str) -> None:
    raise ReportError(f"{label} {message}")


def _object(value, label: str, required: set[str], optional: set[str] | None = None) -> dict:
    if not isinstance(value, dict):
        _fail(label, "must be an object")
    optional = optional or set()
    missing = required - set(value)
    unknown = set(value) - required - optional
    if missing:
        _fail(label, f"is missing required properties: {', '.join(sorted(missing))}")
    if unknown:
        _fail(label, f"contains unsupported properties: {', '.join(sorted(unknown))}")
    return value


def _string(value, label: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value):
        _fail(label, f"must be a {'string' if empty else 'nonempty string'}")
    try:
        value.encode("utf-8")
    except UnicodeError:
        _fail(label, "must contain valid Unicode")
    return value


def _integer(value, label: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(label, "must be an integer")
    if minimum is not None and value < minimum:
        _fail(label, f"must be at least {minimum}")
    return value


def _number(value, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(label, "must be a number")
    try:
        converted = float(value)
    except (ValueError, OverflowError):
        _fail(label, "must be finite")
    if not math.isfinite(converted):
        _fail(label, "must be finite")
    return converted


def _sha256(value, label: str) -> str:
    _string(value, label)
    if not _SHA256.fullmatch(value):
        _fail(label, "must be a lowercase SHA-256")
    return value


def _path(value, label: str) -> str:
    _string(value, label)
    parts = value.split("/")
    if (
        value.startswith("/")
        or "\\" in value
        or value.endswith("/")
        or (len(value) >= 2 and value[0].isalpha() and value[1] == ":")
        or any(part in {"", ".", ".."} for part in parts)
        or any(ord(character) < 32 for character in value)
    ):
        _fail(label, "must be a portable relative path")
    return value


def _datetime(value, label: str) -> str:
    _string(value, label)
    if not _DATETIME.fullmatch(value):
        _fail(label, "must be an RFC 3339 datetime with seconds and an offset")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail(label, "must be a valid datetime")
    if parsed.utcoffset() is None:
        _fail(label, "must have a valid offset")
    return value


def _source(value, label: str) -> dict:
    _object(value, label, {"path", "sha256"})
    _path(value["path"], f"{label}.path")
    _sha256(value["sha256"], f"{label}.sha256")
    return value


def _strings(value, label: str, *, unique: bool = True, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list):
        _fail(label, "must be an array")
    for index, item in enumerate(value):
        _string(item, f"{label}[{index}]", empty=not nonempty)
    if unique and len(set(value)) != len(value):
        _fail(label, "must not contain duplicates")
    return value


def _evidence_id(box_id: str, path: str, digest: str) -> str:
    payload = b"\0".join(
        (b"pwn-report", b"evidence", b"v1", box_id.encode(), path.encode(), digest.encode("ascii"))
    )
    return "ev_" + hashlib.sha256(payload).hexdigest()


def validate_model(model: dict) -> dict:
    """Validate schema 1 structure, canonical ordering, and all internal references."""
    _object(
        model,
        "model",
        {
            "schema_version", "profile", "status", "box", "source", "flags", "targets", "timeline",
            "evidence", "findings", "held_back", "other",
        },  # fmt: skip
        {"notes"},
    )
    if _integer(model["schema_version"], "model.schema_version") != 1:
        _fail("model.schema_version", "must be 1")
    if model["profile"] != "private-technical" or not isinstance(model["profile"], str):
        _fail("model.profile", "must be 'private-technical'")
    if model["status"] != "draft" or not isinstance(model["status"], str):
        _fail("model.status", "must be 'draft'")

    box = _object(
        model["box"],
        "model.box",
        {"id", "name", "platform", "os", "difficulty", "status", "started", "source"},
        {"finished"},
    )
    for field in ("id", "name", "platform", "os", "difficulty", "status"):
        _string(box[field], f"model.box.{field}", empty=field in MAY_BE_EMPTY)
    _datetime(box["started"], "model.box.started")
    if "finished" in box:
        _datetime(box["finished"], "model.box.finished")
    box_source = _source(box["source"], "model.box.source")
    if box_source["path"] != "box.toml":
        _fail("model.box.source.path", "must be 'box.toml'")

    provenance = _object(model["source"], "model.source", {"archive", "manifest"}, {"selection"})
    archive = _object(provenance["archive"], "model.source.archive", {"kind", "packed", "sha256"})
    if not isinstance(archive["kind"], str) or archive["kind"] not in {"finished", "exported"}:
        _fail("model.source.archive.kind", "must be 'finished' or 'exported'")
    _datetime(archive["packed"], "model.source.archive.packed")
    _sha256(archive["sha256"], "model.source.archive.sha256")
    manifest_source = _source(provenance["manifest"], "model.source.manifest")
    if manifest_source["path"] != "manifest.toml":
        _fail("model.source.manifest.path", "must be 'manifest.toml'")
    if "selection" in provenance:
        selection = _object(provenance["selection"], "model.source.selection", {"name", "sha256"})
        name = _string(selection["name"], "model.source.selection.name")
        if name in {".", ".."} or "/" in name or "\\" in name or any(ord(c) < 32 for c in name):
            _fail("model.source.selection.name", "must be a portable basename")
        _sha256(selection["sha256"], "model.source.selection.sha256")

    flags = model["flags"]
    if not isinstance(flags, list):
        _fail("model.flags", "must be an array")
    flag_by_name = {}
    for index, flag in enumerate(flags):
        label = f"model.flags[{index}]"
        _object(flag, label, {"name", "value", "at", "source"})
        name = _string(flag["name"], f"{label}.name")
        _string(flag["value"], f"{label}.value", empty=True)
        _datetime(flag["at"], f"{label}.at")
        source = _source(flag["source"], f"{label}.source")
        if source != box_source:
            _fail(f"{label}.source", "must match the box source")
        if name in flag_by_name:
            _fail(label, f"duplicates flag {name!r}")
        flag_by_name[name] = flag
    if [flag["name"] for flag in flags] != sorted(flag_by_name):
        _fail("model.flags", "must be sorted by name")

    targets = model["targets"]
    if not isinstance(targets, list):
        _fail("model.targets", "must be an array")
    target_by_name = {}
    for index, target in enumerate(targets):
        label = f"model.targets[{index}]"
        _object(target, label, {"box_id", "box", "name", "ips", "hostnames", "scope", "added", "source"})
        name = _string(target["name"], f"{label}.name")
        if target["box_id"] != box["id"] or target["box"] != box["name"]:
            _fail(label, "must belong to the model box")
        _string(target["box_id"], f"{label}.box_id")
        _string(target["box"], f"{label}.box")
        _strings(target["ips"], f"{label}.ips", unique=False)
        _strings(target["hostnames"], f"{label}.hostnames", unique=False)
        _string(target["scope"], f"{label}.scope")
        _datetime(target["added"], f"{label}.added")
        source = _source(target["source"], f"{label}.source")
        if source["path"] != f"targets/{name}/target.toml":
            _fail(f"{label}.source.path", "must match the target name")
        if name in target_by_name:
            _fail(label, f"duplicates target {name!r}")
        target_by_name[name] = target
    if [target["name"] for target in targets] != sorted(target_by_name):
        _fail("model.targets", "must be sorted by name")

    evidence = model["evidence"]
    if not isinstance(evidence, list):
        _fail("model.evidence", "must be an array")
    evidence_by_id = {}
    evidence_paths = set()
    output_paths = set()
    for index, item in enumerate(evidence):
        label = f"model.evidence[{index}]"
        _object(
            item,
            label,
            {"id", "path", "target", "target_refs", "first_seen", "size", "mtime", "sha256", "kind", "output", "source"},
            {"caption", "alt_text"},
        )
        identifier = _string(item["id"], f"{label}.id")
        if not _EVIDENCE_ID.fullmatch(identifier):
            _fail(f"{label}.id", "must be a valid evidence ID")
        path = _path(item["path"], f"{label}.path")
        digest = _sha256(item["sha256"], f"{label}.sha256")
        if identifier != _evidence_id(box["id"], path, digest):
            _fail(f"{label}.id", "does not match its box, path, and content hash")
        location = _evidence_location(path)
        if location is None or location[1] not in ALL_KINDS:
            _fail(f"{label}.path", "is not a supported evidence path")
        expected_target, expected_kind = location
        if item["kind"] != expected_kind or not isinstance(item["kind"], str):
            _fail(f"{label}.kind", "must match its evidence path")
        _string(item["target"], f"{label}.target", empty=True)
        if item["target"] != expected_target:
            _fail(f"{label}.target", "must match its evidence path")
        if expected_target and expected_target not in target_by_name:
            _fail(f"{label}.target", "references an unknown target")
        references = _strings(item["target_refs"], f"{label}.target_refs", nonempty=True)
        if references != sorted(references):
            _fail(f"{label}.target_refs", "must be sorted")
        if set(references) - set(target_by_name):
            _fail(f"{label}.target_refs", "references an unknown target")
        if expected_target and expected_target not in references:
            _fail(f"{label}.target_refs", "must include the original target")
        _datetime(item["first_seen"], f"{label}.first_seen")
        _integer(item["size"], f"{label}.size", minimum=0)
        _number(item["mtime"], f"{label}.mtime")
        for field in ("caption", "alt_text"):
            if field in item:
                _string(item[field], f"{label}.{field}")
        source = _source(item["source"], f"{label}.source")
        if source != {"path": path, "sha256": digest}:
            _fail(f"{label}.source", "must match the evidence path and hash")
        output = _object(item["output"], f"{label}.output", {"copied", "reason"}, {"path"})
        if not isinstance(output["copied"], bool):
            _fail(f"{label}.output.copied", "must be boolean")
        reason = output["reason"]
        if not isinstance(reason, str):
            _fail(f"{label}.output.reason", "must be a string")
        if output["copied"]:
            if reason not in {"default-include", "selection-include"}:
                _fail(f"{label}.output.reason", "is invalid for copied evidence")
            if output.get("path", _MISSING) == _MISSING:
                _fail(f"{label}.output.path", "is required for copied evidence")
            if _path(output["path"], f"{label}.output.path") != "evidence/" + path:
                _fail(f"{label}.output.path", "must match the evidence path")
            if output["path"] in output_paths:
                _fail(f"{label}.output.path", "is duplicated")
            output_paths.add(output["path"])
        else:
            if reason not in {*DEFAULT_OMITTED.values(), "selection-exclude"}:
                _fail(f"{label}.output.reason", "is invalid for omitted evidence")
            if "path" in output:
                _fail(f"{label}.output.path", "must be absent for omitted evidence")
        if not isinstance(reason, str):
            _fail(f"{label}.output.reason", "must be a string")
        if reason.startswith("selection-") and "selection" not in provenance:
            _fail(f"{label}.output.reason", "requires selection provenance")
        if identifier in evidence_by_id or path in evidence_paths:
            _fail(label, "duplicates an evidence ID or path")
        evidence_by_id[identifier] = item
        evidence_paths.add(path)
    if [item["path"] for item in evidence] != sorted(evidence_paths):
        _fail("model.evidence", "must be sorted by path")

    expected_timeline = [
        {"at": flag["at"], "kind": "flag_recorded", "flag": flag["name"], "source": flag["source"]}
        for flag in flags
    ]
    expected_timeline.extend(
        {"at": target["added"], "kind": "target_added", "target": target["name"], "source": target["source"]}
        for target in targets
    )
    expected_timeline.extend(
        {"at": item["first_seen"], "kind": "file_first_seen", "evidence_id": item["id"], "source": item["source"]}
        for item in evidence
    )
    expected_timeline.sort(key=_event_key)
    timeline = model["timeline"]
    if not isinstance(timeline, list):
        _fail("model.timeline", "must be an array")
    allowed = {
        "target_added": {"at", "kind", "target", "source"},
        "flag_recorded": {"at", "kind", "flag", "source"},
        "file_first_seen": {"at", "kind", "evidence_id", "source"},
    }
    for index, event in enumerate(timeline):
        label = f"model.timeline[{index}]"
        if (
            not isinstance(event, dict)
            or not isinstance(event.get("kind"), str)
            or event.get("kind") not in allowed
        ):
            _fail(label, "has an unknown timeline variant")
        kind = event["kind"]
        _object(event, label, allowed[kind])
        _datetime(event["at"], f"{label}.at")
        reference_field = {"target_added": "target", "flag_recorded": "flag", "file_first_seen": "evidence_id"}[kind]
        _string(event[reference_field], f"{label}.{reference_field}")
        _source(event["source"], f"{label}.source")
        reference_exists = (
            event[reference_field] in target_by_name
            if kind == "target_added"
            else event[reference_field] in flag_by_name
            if kind == "flag_recorded"
            else event[reference_field] in evidence_by_id
        )
        if not reference_exists:
            _fail(f"{label}.{reference_field}", "is a dangling reference")
    if timeline != expected_timeline:
        _fail("model.timeline", "must contain exactly the canonically ordered source events")

    held_back = model["held_back"]
    if not isinstance(held_back, list):
        _fail("model.held_back", "must be an array")
    for index, group in enumerate(held_back):
        label = f"model.held_back[{index}]"
        _object(group, label, {"path", "files"})
        path = _string(group["path"], f"{label}.path")
        if not _HELD_BACK_PATH.fullmatch(path):
            _fail(f"{label}.path", "is not a held-back location")
        # the shape is right; the target name in targets/<t>/creds/ must also be portable
        _path(path.rstrip("/"), f"{label}.path")
        _integer(group["files"], f"{label}.files", minimum=1)
    paths = [group["path"] for group in held_back]
    if paths != sorted(set(paths)):
        _fail("model.held_back", "must be sorted by path without duplicates")
    other = _strings(model["other"], "model.other", nonempty=True)
    for index, path in enumerate(other):
        _path(path, f"model.other[{index}]")
        if (
            _evidence_location(path) is not None
            or held_back_group(path) is not None
            or path in METADATA
            or is_target_toml(path)
        ):
            _fail(f"model.other[{index}]", "is evidence, held back or metadata, not other")
    if other != sorted(other):
        _fail("model.other", "must be sorted")

    if not isinstance(model["findings"], list) or model["findings"]:
        _fail("model.findings", "must be an empty array in schema version 1")
    if "notes" in model:
        notes = _object(model["notes"], "model.notes", {"source", "report_path", "size"})
        _integer(notes["size"], "model.notes.size", minimum=0)
        source = _source(notes["source"], "model.notes.source")
        if source["path"] != "notes.md":
            _fail("model.notes.source.path", "must be 'notes.md'")
        if notes["report_path"] != "evidence/notes.md":
            _fail("model.notes.report_path", "must be 'evidence/notes.md'")
    return model

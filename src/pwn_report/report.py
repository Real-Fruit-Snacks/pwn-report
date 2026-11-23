"""Build and validate the canonical v1 model from one Broker archive.

The parser accepts an optional selection, never modifies either source input, and
never extracts archived members to the filesystem or executes archived content.
Rendering and atomic evidence copying live in :mod:`pwn_report.output`.
"""

from __future__ import annotations

import gzip
import hashlib
import math
import os
import tarfile
import tomllib
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

SCHEMA_VERSION = 1
MAX_ENTRIES = 300_000
MAX_NAME_BYTES = 4096
MAX_NAMES_BYTES = 64 * 1024 * 1024
MAX_TOML_BYTES = 64 * 1024 * 1024
MAX_SMALL_TOML_BYTES = 1024 * 1024
MAX_OWNER = 2**32 - 1
READ_BYTES = 64 * 1024
ENTRY_HEADER_BYTES = 16 * 1024
HEADER_ROOM = 2048
HEADER_LINES = 16
EVIDENCE_KINDS = frozenset({"scans", "loot", "screenshots", "recordings", "exploits"})
# pwn-broker stores a new box's os and difficulty as typed, so pressing Enter leaves them empty
MAY_BE_EMPTY = frozenset({"os", "difficulty"})


class ReportError(Exception):
    """An archive cannot be converted into a valid canonical model."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while piece := handle.read(READ_BYTES):
            digest.update(piece)
    return digest.hexdigest()


class _Capped:
    """Bound decompressed reads and account for each tar member's headers."""

    def __init__(self, handle):
        self._handle = handle
        self.entry_bytes = 0
        self.entry_lines = 0
        self._headers = True

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0 or size > READ_BYTES:
            raise ReportError("archive read request exceeds the 64 KiB chunk limit")
        data = self._handle.read(size)
        if self._headers:
            self.entry_bytes += len(data)
            self.entry_lines += data.count(b"\n")
            if self.entry_bytes > ENTRY_HEADER_BYTES:
                raise ReportError("archive has too much header data for one entry")
        return data

    def next_entry(self) -> None:
        self.entry_bytes = 0
        self.entry_lines = 0

    def entries_read(self) -> None:
        self._headers = False

    def seek(self, *args) -> int:
        return self._handle.seek(*args)

    def tell(self) -> int:
        return self._handle.tell()


@contextmanager
def _open(archive: Path):
    with gzip.GzipFile(archive, "rb") as unzipped:
        with tarfile.open(fileobj=_Capped(unzipped), mode="r:", copybufsize=READ_BYTES) as tar:
            yield tar


def _text(value, label: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise ReportError(f"{label} must be a {'string' if empty else 'nonempty string'}")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise ReportError(f"{label} must contain valid Unicode") from exc
    return value


def _schema(value, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value != SCHEMA_VERSION:
        raise ReportError(f"{label} must be schema {SCHEMA_VERSION}")
    return value


def _time(value, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ReportError(f"{label} must be an offset-aware datetime")
    return value


def _size(value, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReportError(f"{label} must be a nonnegative integer")
    return value


def _mtime(value, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReportError(f"{label} must be a finite number")
    try:
        converted = float(value)
    except (OverflowError, ValueError) as exc:
        raise ReportError(f"{label} must be a finite number") from exc
    if not math.isfinite(converted):
        raise ReportError(f"{label} must be a finite number")
    return converted


def _checksum(value, label: str) -> str:
    value = _text(value, label)
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ReportError(f"{label} must be a lowercase SHA-256")
    return value


def _relative_path(value, label: str) -> str:
    value = _text(value, label)
    parts = value.split("/")
    if (
        value.startswith("/")
        or "\\" in value
        or value.endswith("/")
        or (len(value) >= 2 and value[0].isalpha() and value[1] == ":")
        or any(part in {"", ".", ".."} for part in parts)
        or any(ord(character) < 32 for character in value)
    ):
        raise ReportError(f"{label} is not a portable relative path")
    return value


def _source(path: str, digest: str) -> dict[str, str]:
    return {"path": path, "sha256": digest}


def _toml(data: bytes, label: str) -> dict:
    try:
        value = tomllib.loads(data.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ReportError(f"{label} cannot be read: {exc}") from exc
    if not isinstance(value, dict):
        raise ReportError(f"{label} must be a TOML table")
    return value


def _member_bytes(tar: tarfile.TarFile, member: tarfile.TarInfo, limit: int, label: str) -> bytes:
    if not member.isreg() or member.size > limit:
        raise ReportError(f"{label} is not a regular file within its size limit")
    handle = tar.extractfile(member)
    if handle is None:
        raise ReportError(f"{label} cannot be read")
    # ExFileObject's BufferedReader can prefetch io.DEFAULT_BUFFER_SIZE bytes
    # (128 KiB on Kali's Python 3.14). Read its raw stream to preserve the cap.
    reader = getattr(handle, "raw", handle)
    pieces = []
    remaining = member.size
    with handle:
        while remaining:
            piece = reader.read(min(READ_BYTES, remaining))
            if not piece:
                raise ReportError(f"{label} ends inside its archived data")
            pieces.append(piece)
            remaining -= len(piece)
    return b"".join(pieces)


def _member_sha(tar: tarfile.TarFile, member: tarfile.TarInfo, label: str) -> str:
    handle = tar.extractfile(member)
    if handle is None:
        raise ReportError(f"{label} cannot be read")
    reader = getattr(handle, "raw", handle)
    digest = hashlib.sha256()
    with handle:
        while piece := reader.read(READ_BYTES):
            digest.update(piece)
    return digest.hexdigest()


def _check_member(member: tarfile.TarInfo) -> None:
    name = member.name
    if (
        name.startswith("/")
        or (len(name) >= 2 and name[0].isalpha() and name[1] == ":")
        or (os.sep == "\\" and "\\" in name)
        or ".." in name.split("/")
    ):
        raise ReportError(f"archive entry {name!r} escapes its box root")
    try:
        name_bytes = len(name.encode("utf-8", "surrogateescape"))
    except UnicodeError as exc:
        raise ReportError("archive entry name cannot be encoded") from exc
    if name_bytes > MAX_NAME_BYTES:
        raise ReportError(f"archive entry name exceeds {MAX_NAME_BYTES} bytes")
    if not (member.isreg() or member.isdir()):
        raise ReportError(f"archive entry {name!r} is not a regular file or folder")
    if member.linkname or member.issparse():
        raise ReportError(f"archive entry {name!r} names a link or sparse file")
    if member.size < 0 or (member.isdir() and member.size):
        raise ReportError(f"archive entry {name!r} has an invalid size")
    if not (0 <= member.uid <= MAX_OWNER and 0 <= member.gid <= MAX_OWNER):
        raise ReportError(f"archive entry {name!r} has an invalid owner")


def _members(tar: tarfile.TarFile) -> tuple[str, dict[str, tarfile.TarInfo]]:
    by_name = {}
    names_bytes = 0
    for member in tar:
        if tar.pax_headers:
            raise ReportError("archive has a global extended header")
        _check_member(member)
        if member.name in by_name:
            raise ReportError(f"archive entry {member.name!r} is duplicated")
        name_bytes = len(member.name.encode("utf-8", "surrogateescape"))
        if tar.fileobj.entry_bytes > HEADER_ROOM + 2 * name_bytes:
            raise ReportError("archive entry has more header bytes than its name allows")
        if tar.fileobj.entry_lines > HEADER_LINES + 2 * member.name.count("\n"):
            raise ReportError("archive entry has more header lines than its name allows")
        member.pax_headers = {}
        member.uname = ""
        member.gname = ""
        names_bytes += name_bytes
        if len(by_name) >= MAX_ENTRIES or names_bytes > MAX_NAMES_BYTES:
            raise ReportError("archive has too many entries or member-name bytes")
        by_name[member.name] = member
        tar.fileobj.next_entry()
    tar.fileobj.entries_read()
    roots = {name.split("/", 1)[0] for name in by_name}
    if len(roots) != 1:
        raise ReportError("archive must contain exactly one box root")
    root = roots.pop()
    if not root or root in {".", ".."} or root not in by_name or not by_name[root].isdir():
        raise ReportError("archive must contain one regular box-root folder")
    _relative_path(root, "archive box root")
    if any(name != root and not name.startswith(root + "/") for name in by_name):
        raise ReportError("archive contains a member outside its box root")
    return root, by_name


def _record(row, label: str) -> dict:
    if not isinstance(row, dict):
        raise ReportError(f"{label} must be a table")
    return {
        "path": _relative_path(row.get("path"), f"{label}.path"),
        "target": _text(row.get("target"), f"{label}.target", empty=True),
        "first_seen": _time(row.get("first_seen"), f"{label}.first_seen"),
        "size": _size(row.get("size"), f"{label}.size"),
        "mtime": _mtime(row.get("mtime"), f"{label}.mtime"),
        "sha256": _checksum(row.get("sha256"), f"{label}.sha256"),
    }


def _evidence_location(path: str) -> tuple[str, str] | None:
    parts = PurePosixPath(path).parts
    if len(parts) >= 4 and parts[0] == "targets" and parts[2] in EVIDENCE_KINDS:
        return parts[1], parts[2]
    if len(parts) >= 2 and parts[0] in EVIDENCE_KINDS:
        return "", parts[0]
    return None


def _evidence_id(box_id: str, path: str, digest: str) -> str:
    payload = b"\0".join(
        (b"pwn-report", b"evidence", b"v1", box_id.encode(), path.encode(), digest.encode("ascii"))
    )
    return "ev_" + _sha(payload)


def _compact_json(value: dict) -> bytes:
    import json

    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _event_key(event: dict) -> tuple:
    """Order by the instant an event happened: as text, 01:10-05:00 would sort before the
    earlier 01:30-04:00 on the night the clocks go back. Ties keep a fixed, total order."""
    instant = datetime.fromisoformat(event["at"].replace("Z", "+00:00")).astimezone(timezone.utc)
    return (instant, event["at"], event["kind"], _compact_json(event))


def _string_list(value, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ReportError(f"{label} must be a list of strings")
    if len(set(value)) != len(value):
        raise ReportError(f"{label} contains duplicates")
    return list(value)


def _external_bytes(path: Path, limit: int, label: str) -> bytes:
    data = bytearray()
    with path.open("rb") as handle:
        while True:
            piece = handle.read(min(READ_BYTES, limit + 1 - len(data)))
            if not piece:
                break
            data.extend(piece)
            if len(data) > limit:
                raise ReportError(f"{label} exceeds its {limit}-byte limit")
    return bytes(data)


def _selection_rules(data: dict) -> dict[str, dict]:
    if set(data) - {"schema", "rule"}:
        raise ReportError("selection contains unsupported top-level fields")
    _schema(data.get("schema"), "selection schema")
    raw_rules = data.get("rule", [])
    if not isinstance(raw_rules, list):
        raise ReportError("selection rule must be a list of tables")
    rules = {}
    allowed = {"path", "include", "caption", "alt_text", "target_refs"}
    for index, raw in enumerate(raw_rules):
        label = f"selection rule[{index}]"
        if not isinstance(raw, dict):
            raise ReportError(f"{label} must be a table")
        if set(raw) - allowed:
            raise ReportError(f"{label} contains unsupported fields")
        path = _relative_path(raw.get("path"), f"{label}.path")
        if path in rules:
            raise ReportError(f"selection lists {path} more than once")
        rule = {"path": path}
        if "include" in raw:
            if not isinstance(raw["include"], bool):
                raise ReportError(f"{label}.include must be boolean")
            rule["include"] = raw["include"]
        for field in ("caption", "alt_text"):
            if field in raw:
                rule[field] = _text(raw[field], f"{label}.{field}")
        if "target_refs" in raw:
            references = _string_list(raw["target_refs"], f"{label}.target_refs")
            rule["target_refs"] = [_text(item, f"{label}.target_refs item") for item in references]
        rules[path] = rule
    return rules


def _build_model(archive: Path, selection: Path | None) -> dict:
    archive_digest = _file_sha(archive)
    selection_rules = {}
    selection_source = None
    if selection is not None:
        selection_bytes = _external_bytes(selection, MAX_SMALL_TOML_BYTES, "selection")
        selection_data = _toml(selection_bytes, "selection")
        selection_rules = _selection_rules(selection_data)
        name = _text(selection.name, "selection filename")
        if name in {".", ".."} or "/" in name or "\\" in name or any(ord(c) < 32 for c in name):
            raise ReportError("selection filename is not portable")
        selection_source = {"name": name, "sha256": _sha(selection_bytes)}
    with _open(archive) as tar:
        root, members = _members(tar)

        def member(path: str) -> tarfile.TarInfo:
            found = members.get(f"{root}/{path}")
            if found is None or not found.isreg():
                raise ReportError(f"{path} is missing from the archive")
            return found

        manifest_member = member("manifest.toml")
        manifest_bytes = _member_bytes(tar, manifest_member, MAX_TOML_BYTES, "manifest.toml")
        manifest = _toml(manifest_bytes, "manifest.toml")
        _schema(manifest.get("schema"), "manifest.toml schema")
        kind = manifest.get("kind")
        if kind not in {"finished", "exported"}:
            raise ReportError("manifest.toml kind must be finished or exported")
        packed = _time(manifest.get("packed"), "manifest.toml packed")

        box_member = member("box.toml")
        box_bytes = _member_bytes(tar, box_member, MAX_SMALL_TOML_BYTES, "box.toml")
        box_data = _toml(box_bytes, "box.toml")
        _schema(box_data.get("schema"), "box.toml schema")
        hashes = {"manifest.toml": _sha(manifest_bytes), "box.toml": _sha(box_bytes)}

        raw_rows = manifest.get("file", [])
        if not isinstance(raw_rows, list):
            raise ReportError("manifest.toml file must be a list")
        records = {}
        for index, row in enumerate(raw_rows):
            record = _record(row, f"manifest.toml file[{index}]")
            path = record["path"]
            if path in records:
                raise ReportError(f"{path} is listed twice in manifest.toml")
            archived = member(path)
            if archived.size != record["size"]:
                raise ReportError(f"{path} size differs from manifest.toml")
            records[path] = record

        manifest_box = manifest.get("box")
        if not isinstance(manifest_box, dict):
            raise ReportError("manifest.toml box must be a table")
        box = {}
        for field in ("id", "name", "platform", "os", "difficulty", "status"):
            box[field] = _text(box_data.get(field), f"box.toml {field}", empty=field in MAY_BE_EMPTY)
        box["started"] = _time(box_data.get("started"), "box.toml started")
        if "finished" in box_data:
            box["finished"] = _time(box_data["finished"], "box.toml finished")
        for field in ("id", "name", "platform", "os", "difficulty", "started", "finished"):
            if (field in manifest_box) != (field in box_data) or (
                field in box_data and manifest_box[field] != box_data[field]
            ):
                raise ReportError(f"manifest.toml box {field} differs from box.toml")
        for field in ("id", "name", "platform", "os", "difficulty"):
            _text(manifest_box.get(field), f"manifest.toml box {field}", empty=field in MAY_BE_EMPTY)

        used = {"box.toml"}
        target_paths = []
        evidence_rows = []
        for path, record in records.items():
            parts = PurePosixPath(path).parts
            if len(parts) == 3 and parts[0] == "targets" and parts[2] == "target.toml":
                if record["target"] != parts[1]:
                    raise ReportError(f"{path} target differs from its path")
                target_paths.append(path)
                used.add(path)
            location = _evidence_location(path)
            if location is not None:
                target, _ = location
                if record["target"] != target:
                    raise ReportError(f"{path} target differs from its path")
                evidence_rows.append((path, record, location))
                used.add(path)
        evidence_paths = {path for path, _, _ in evidence_rows}
        for path in selection_rules:
            if path not in evidence_paths:
                raise ReportError(f"selection references unknown, unlisted, or unsupported evidence: {path}")
        if "notes.md" in records:
            used.add("notes.md")
        if "manifest.toml" in records:
            used.add("manifest.toml")

        # archive order: a .tar.gz read backwards decompresses again from its start
        for path in sorted(used, key=lambda name: member(name).offset_data):
            if path not in hashes:
                hashes[path] = _member_sha(tar, member(path), path)
            if path in records and hashes[path] != records[path]["sha256"]:
                raise ReportError(f"{path} checksum differs from manifest.toml")

        box_source = _source("box.toml", hashes["box.toml"])
        box_model = {field: value.isoformat() if isinstance(value, datetime) else value for field, value in box.items()}
        box_model["source"] = box_source

        raw_flags = box_data.get("flags", {})
        if not isinstance(raw_flags, dict):
            raise ReportError("box.toml flags must be a table")
        flags = []
        for name in sorted(raw_flags):
            flag = raw_flags[name]
            if not isinstance(flag, dict):
                raise ReportError(f"box.toml flag {name!r} must be a table")
            flags.append(
                {
                    "name": _text(name, "flag name"),
                    "value": _text(flag.get("value"), f"flag {name} value", empty=True),
                    "at": _time(flag.get("at"), f"flag {name} at").isoformat(),
                    "source": box_source,
                }
            )

        targets = []
        for path in sorted(target_paths, key=lambda name: member(name).offset_data):
            target_bytes = _member_bytes(tar, member(path), MAX_SMALL_TOML_BYTES, path)
            data = _toml(target_bytes, path)
            _schema(data.get("schema"), f"{path} schema")
            expected_name = PurePosixPath(path).parts[1]
            target = {
                "box_id": _text(data.get("box_id"), f"{path} box_id"),
                "box": _text(data.get("box"), f"{path} box"),
                "name": _text(data.get("name"), f"{path} name"),
                "ips": _string_list(data.get("ips"), f"{path} ips"),
                "hostnames": _string_list(data.get("hostnames"), f"{path} hostnames"),
                "scope": _text(data.get("scope"), f"{path} scope"),
                "added": _time(data.get("added"), f"{path} added").isoformat(),
                "source": _source(path, hashes[path]),
            }
            if target["box_id"] != box["id"] or target["box"] != box["name"] or target["name"] != expected_name:
                raise ReportError(f"{path} target identity differs from its box or path")
            targets.append(target)
        targets.sort(key=lambda target: target["name"])
        if len({target["name"] for target in targets}) != len(targets):
            raise ReportError("target names are duplicated")
        target_names = {target["name"] for target in targets}
        for rule in selection_rules.values():
            unknown = set(rule.get("target_refs", [])) - target_names
            if unknown:
                raise ReportError(f"selection references unknown targets: {', '.join(sorted(unknown))}")

        evidence = []
        for path, record, (target, evidence_kind) in evidence_rows:
            rule = selection_rules.get(path, {})
            if "include" in rule:
                copied = rule["include"]
                reason = "selection-include" if copied else "selection-exclude"
            else:
                copied = evidence_kind in {"scans", "screenshots", "exploits"}
                reason = "default-include" if copied else {
                    "loot": "default-exclude-loot",
                    "recordings": "default-exclude-recording",
                }[evidence_kind]
            output = {"copied": copied, "reason": reason}
            if copied:
                output["path"] = "evidence/" + path
            item = {
                "id": _evidence_id(box["id"], path, hashes[path]),
                "path": path,
                "target": target,
                "target_refs": sorted(set(([target] if target else []) + rule.get("target_refs", []))),
                "first_seen": record["first_seen"].isoformat(),
                "size": record["size"],
                "mtime": record["mtime"],
                "sha256": hashes[path],
                "kind": evidence_kind,
                "output": output,
                "source": _source(path, hashes[path]),
            }
            for field in ("caption", "alt_text"):
                if field in rule:
                    item[field] = rule[field]
            evidence.append(item)
        evidence.sort(key=lambda item: item["path"])

        timeline = [
            {"at": flag["at"], "kind": "flag_recorded", "flag": flag["name"], "source": flag["source"]}
            for flag in flags
        ]
        timeline.extend(
            {"at": target["added"], "kind": "target_added", "target": target["name"], "source": target["source"]}
            for target in targets
        )
        timeline.extend(
            {
                "at": item["first_seen"],
                "kind": "file_first_seen",
                "evidence_id": item["id"],
                "source": item["source"],
            }
            for item in evidence
        )
        timeline.sort(key=_event_key)

        model = {
            "schema_version": SCHEMA_VERSION,
            "profile": "private-technical",
            "status": "draft",
            "box": box_model,
            "source": {
                "archive": {"kind": kind, "packed": packed.isoformat(), "sha256": archive_digest},
                "manifest": _source("manifest.toml", hashes["manifest.toml"]),
            },
            "flags": flags,
            "targets": targets,
            "timeline": timeline,
            "evidence": evidence,
            "findings": [],
        }
        if "notes.md" in records:
            model["notes"] = {
                "source": _source("notes.md", hashes["notes.md"]),
                "report_path": "evidence/notes.md",
                "size": records["notes.md"]["size"],
            }
        if selection_source is not None:
            model["source"]["selection"] = selection_source
        # Imported lazily to keep the low-level archive parser independent at module load.
        from .validate import validate_model

        return validate_model(model)


def build_model(
    archive: str | os.PathLike[str],
    selection: str | os.PathLike[str] | None = None,
) -> dict:
    """Return the canonical v1 model without modifying source inputs."""
    path = Path(archive)
    selection_path = Path(selection) if selection is not None else None
    try:
        return _build_model(path, selection_path)
    except ReportError:
        raise
    except (OSError, EOFError, tarfile.TarError, ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise ReportError(f"{path}: cannot build report model: {exc}") from exc

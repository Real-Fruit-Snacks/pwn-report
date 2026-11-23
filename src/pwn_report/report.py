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
import zlib
import tomllib
import unicodedata
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

SCHEMA_VERSION = 1
MAX_ENTRIES = 300_000
MAX_NAME_BYTES = 4096
MAX_NAMES_BYTES = 64 * 1024 * 1024
MAX_TOML_BYTES = 64 * 1024 * 1024
MAX_SMALL_TOML_BYTES = 1024 * 1024
# all of a box's target.toml files together: a real one is a few hundred bytes, so this holds
# thousands of targets, and every address and host name in them is kept, so without it a small
# crafted archive of many full targets took gigabytes
MAX_TARGETS_BYTES = 4 * 1024 * 1024
MAX_OWNER = 2**32 - 1
READ_BYTES = 64 * 1024
ENTRY_HEADER_BYTES = 16 * 1024
HEADER_ROOM = 2048
HEADER_LINES = 16
EVIDENCE_KINDS = frozenset({"scans", "loot", "screenshots", "recordings", "exploits"})
# indexed only inside a target, and copied only when a selection includes them
TARGET_ONLY_KINDS = frozenset({"files", "upload"})
ALL_KINDS = EVIDENCE_KINDS | TARGET_ONLY_KINDS
COPIED_BY_DEFAULT = frozenset({"scans", "screenshots", "exploits"})
DEFAULT_OMITTED = {
    "loot": "default-exclude-loot",
    "recordings": "default-exclude-recording",
    "files": "default-exclude-files",
    "upload": "default-exclude-upload",
}
# the box's own files, read for the report itself rather than indexed
METADATA = frozenset({"box.toml", "notes.md", "manifest.toml"})
HELD_BACK_MESSAGE = (
    "creds.toml, lists/, targets/*/creds/ and tooldata/ hold credential material and are never read"
)
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


def _leaves_the_box(value: str) -> bool:
    """Absolute, on a drive, or climbing out with .. by either separator."""
    return (
        value.startswith(("/", "\\"))
        or (len(value) >= 2 and value[0].isalpha() and value[1] == ":")
        or ".." in value.replace("\\", "/").split("/")
        or "\0" in value
    )


# a control character (C0, DEL or C1), a format character, or a line or paragraph separator:
# each is more than text to a terminal, to str.splitlines, or to a reader looking at a name
UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


def has_unsafe_character(value: str) -> bool:
    return any(unicodedata.category(character) in UNSAFE_CATEGORIES for character in value)


def shown(value: str) -> str:
    """The value with each unsafe character replaced by ?."""
    return "".join("?" if unicodedata.category(character) in UNSAFE_CATEGORIES else character for character in value)


def is_portable(value: str) -> bool:
    """A relative path that means the same file on every system: / only, no empty, . or ..
    parts, no unsafe character."""
    return not (
        _leaves_the_box(value)
        or "\\" in value
        or value.endswith("/")
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or has_unsafe_character(value)
    )


def _relative_path(value, label: str) -> str:
    value = _text(value, label)
    if not is_portable(value):
        raise ReportError(f"{label} is not a portable relative path")
    return value


def _listed_path(value, label: str) -> str:
    """A manifest row's path: refused only if it leaves the box. A name with a backslash or a
    control character is listed as other and never read."""
    value = _text(value, label)
    if _leaves_the_box(value) or any(part in {"", "."} for part in value.split("/")):
        # a row in a held-back folder, however spelled, is named by the folder, never the file
        prefix = _held_back_prefix(value)
        named = f"a path in {prefix}" if prefix else repr(value)
        raise ReportError(f"manifest.toml lists {named}, which is not a portable relative path inside the box")
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


# the parts that name a held-back place: an error never prints what follows one in a name
_HELD_BACK_PARTS = frozenset({"creds", "creds.toml", "lists", "tooldata"})


def _held_back_prefix(name: str) -> str | None:
    """The name up to its first part that names a held-back place, in any case and by either
    slash, when anything follows that part; None when none does. Empty and . parts are left out
    of it. Only for naming a place in an error, so no file inside one is named however its name
    is spelled; never used as a path."""
    parts = name.replace("\\", "/").split("/")
    for index, part in enumerate(parts):
        # a drive letter before, or a stream name after, can be glued on with a colon:
        # C:lists, lists:x; the name is cut after the held-back piece itself
        pieces = part.split(":")
        for at, piece in enumerate(pieces):
            if piece.casefold() not in _HELD_BACK_PARTS:
                continue
            if at == len(pieces) - 1 and index == len(parts) - 1:
                return None  # the place itself, with nothing inside it to hide
            kept = [kept for kept in parts[:index] if kept not in {"", "."}]
            return "/".join([*kept, ":".join(pieces[: at + 1])]) + "/"
    return None


def _entry_label(name: str) -> str:
    """How an error names a member: by its name, or only up to a held-back place in it."""
    prefix = _held_back_prefix(name)
    return f"in {prefix}" if prefix else repr(name)


def _target(path: str, data: bytes, digest: str, box: dict) -> dict:
    """The record of one target from its target.toml, already checked against the manifest."""
    parsed = _toml(data, path)
    _schema(parsed.get("schema"), f"{path} schema")
    target = {
        "box_id": _text(parsed.get("box_id"), f"{path} box_id"),
        "box": _text(parsed.get("box"), f"{path} box"),
        "name": _text(parsed.get("name"), f"{path} name"),
        # kept as recorded: pwn-broker splits what was typed and stores a repeat too
        "ips": _string_list(parsed.get("ips"), f"{path} ips", unique=False),
        "hostnames": _string_list(parsed.get("hostnames"), f"{path} hostnames", unique=False),
        "scope": _text(parsed.get("scope"), f"{path} scope"),
        "added": _time(parsed.get("added"), f"{path} added").isoformat(),
        "source": _source(path, digest),
    }
    if target["box_id"] != box["id"] or target["box"] != box["name"] or target["name"] != PurePosixPath(path).parts[1]:
        raise ReportError(f"{path} target identity differs from its box or path")
    return target


def _check_member(member: tarfile.TarInfo) -> None:
    name = member.name
    entry = _entry_label(name)
    # the same rule on every system, so an archive builds or fails the same everywhere; a member
    # name is never used as a path, only a portable manifest path is
    if _leaves_the_box(name):
        raise ReportError(f"archive entry {entry} escapes its box root")
    try:
        name_bytes = len(name.encode("utf-8", "surrogateescape"))
    except UnicodeError as exc:
        raise ReportError("archive entry name cannot be encoded") from exc
    if name_bytes > MAX_NAME_BYTES:
        raise ReportError(f"archive entry name exceeds {MAX_NAME_BYTES} bytes")
    if not (member.isreg() or member.isdir()):
        raise ReportError(f"archive entry {entry} is not a regular file or folder")
    if member.linkname or member.issparse():
        raise ReportError(f"archive entry {entry} names a link or sparse file")
    if member.size < 0 or (member.isdir() and member.size):
        raise ReportError(f"archive entry {entry} has an invalid size")
    if not (0 <= member.uid <= MAX_OWNER and 0 <= member.gid <= MAX_OWNER):
        raise ReportError(f"archive entry {entry} has an invalid owner")


def _members(tar: tarfile.TarFile) -> tuple[str, dict[str, tarfile.TarInfo]]:
    by_name = {}
    names_bytes = 0
    for member in tar:
        if tar.pax_headers:
            raise ReportError("archive has a global extended header")
        _check_member(member)
        if member.name in by_name:
            raise ReportError(f"archive entry {_entry_label(member.name)} is duplicated")
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
        "path": _listed_path(row.get("path"), f"{label}.path"),
        "target": _text(row.get("target"), f"{label}.target", empty=True),
        "first_seen": _time(row.get("first_seen"), f"{label}.first_seen"),
        "size": _size(row.get("size"), f"{label}.size"),
        "mtime": _mtime(row.get("mtime"), f"{label}.mtime"),
        "sha256": _checksum(row.get("sha256"), f"{label}.sha256"),
    }


def held_back_group(path: str) -> str | None:
    """The held-back location a path is in: creds.toml, lists/, targets/<t>/creds/ or tooldata/.
    A target folder whose name is not portable is not one pwn-broker made, so not a creds folder."""
    parts = path.split("/")
    if path == "creds.toml":
        return "creds.toml"
    if len(parts) >= 2 and parts[0] in {"lists", "tooldata"}:
        return parts[0] + "/"
    if len(parts) >= 4 and parts[0] == "targets" and parts[2] == "creds" and is_portable(parts[1]):
        return f"targets/{parts[1]}/creds/"
    return None


def is_target_toml(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return len(parts) == 3 and parts[0] == "targets" and parts[2] == "target.toml"


def _evidence_location(path: str) -> tuple[str, str] | None:
    parts = PurePosixPath(path).parts
    if len(parts) >= 4 and parts[0] == "targets" and parts[2] in ALL_KINDS:
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


def _string_list(value, label: str, *, unique: bool = True) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ReportError(f"{label} must be a list of strings")
    if unique and len(set(value)) != len(value):
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
        if name in {".", ".."} or "/" in name or "\\" in name or has_unsafe_character(name):
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
            group = held_back_group(path) or _held_back_prefix(path)
            named = f"a file in {group}" if group else path
            if path in records:
                raise ReportError(f"{named} is listed twice in manifest.toml")
            archived = members.get(f"{root}/{path}")
            if archived is None or not archived.isreg():
                raise ReportError(f"{named} is missing from the archive")
            if archived.size != record["size"]:
                raise ReportError(f"{named} size differs from manifest.toml")
            records[path] = record
        # the box's own facts are used, so they are checked like any file the report uses
        if "box.toml" not in records:
            raise ReportError("box.toml is not listed in manifest.toml")

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
        held_counts: dict[str, int] = {}
        other = []
        # the targets the box has: a folder under targets/ without its target.toml is not one
        target_names = {
            PurePosixPath(path).parts[1] for path in records if is_portable(path) and is_target_toml(path)
        }
        # every listed file is one of: held back, a target's target.toml, evidence, metadata, other
        for path, record in records.items():
            group = held_back_group(path)
            if group is not None:
                # counted from the manifest alone: never hashed, read or copied
                held_counts[group] = held_counts.get(group, 0) + 1
                continue
            if not is_portable(path):
                # a backslash or a control character: listed by name, never read
                other.append(path)
                continue
            if is_target_toml(path):
                if record["target"] != PurePosixPath(path).parts[1]:
                    raise ReportError(f"{path} target differs from its path")
                target_paths.append(path)
                used.add(path)
                continue
            location = _evidence_location(path)
            if location is not None and location[0] and location[0] not in target_names:
                other.append(path)
                continue
            if location is not None:
                target, _ = location
                if record["target"] != target:
                    raise ReportError(f"{path} target differs from its path")
                evidence_rows.append((path, record, location))
                used.add(path)
            elif path not in METADATA:
                other.append(path)
        evidence_paths = {path for path, _, _ in evidence_rows}
        for path in selection_rules:
            if held_back_group(path) is not None:
                raise ReportError(f"selection names {path}, which is held back: {HELD_BACK_MESSAGE}")
            if path not in evidence_paths:
                raise ReportError(f"selection references unknown, unlisted, or unsupported evidence: {path}")
        if "notes.md" in records:
            used.add("notes.md")
        if "manifest.toml" in records:
            used.add("manifest.toml")

        # from the manifest's sizes, which the members have: refused before any is read
        if sum(records[path]["size"] for path in target_paths) > MAX_TARGETS_BYTES:
            raise ReportError(f"the target.toml files together exceed {MAX_TARGETS_BYTES} bytes")

        # archive order: a .tar.gz read backwards decompresses again from its start
        targets = []
        is_target = set(target_paths)
        for path in sorted(used, key=lambda name: member(name).offset_data):
            target_bytes = None
            if path in is_target:
                # read in this pass, in archive order, and parsed once checked, keeping only its
                # record: a pass of its own went back to the first target's, and keeping every
                # one's bytes to the end cost up to a MiB a target
                target_bytes = _member_bytes(tar, member(path), MAX_SMALL_TOML_BYTES, path)
                hashes[path] = _sha(target_bytes)
            elif path not in hashes:
                hashes[path] = _member_sha(tar, member(path), path)
            if path in records and hashes[path] != records[path]["sha256"]:
                raise ReportError(f"{path} checksum differs from manifest.toml")
            if target_bytes is not None:
                targets.append(_target(path, target_bytes, hashes[path], box))

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
                copied = evidence_kind in COPIED_BY_DEFAULT
                reason = "default-include" if copied else DEFAULT_OMITTED[evidence_kind]
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
            "held_back": [{"path": group, "files": held_counts[group]} for group in sorted(held_counts)],
            "other": sorted(other),
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
    # zlib.error comes through raw when the deflate stream breaks inside a member's data, and
    # OverflowError from a time that has no UTC instant
    except (
        OSError, EOFError, tarfile.TarError, zlib.error, ValueError, TypeError, UnicodeError,
        RecursionError, OverflowError,
    ) as exc:  # fmt: skip
        raise ReportError(f"{path}: cannot build report model: {exc}") from exc

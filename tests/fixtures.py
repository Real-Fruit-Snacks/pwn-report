"""Deterministic, test-only Broker archives and canonical-model oracles.

Nothing here imports Broker or implements the future pwn-report CLI. The expected
model is deliberately built from known fixture facts for comparison with a future
production implementation.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

BOX_ID = "2026-11-14_htb_forest"
NOW = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone(timedelta(hours=2)))
FIRST_SEEN = datetime(2026, 11, 14, 12, 15, 0, tzinfo=timezone(timedelta(hours=2)))
LATER = datetime(2026, 11, 14, 12, 30, 0, tzinfo=timezone(timedelta(hours=2)))
PACKED = datetime(2026, 11, 14, 13, 0, 0, tzinfo=timezone(timedelta(hours=2)))
EVIDENCE_KINDS = frozenset({"scans", "loot", "screenshots", "recordings", "exploits"})
# indexed only inside a target, and copied only when a selection includes them
TARGET_ONLY_KINDS = frozenset({"files", "upload"})

NOTES = (
    "# Forest notes\n\nPrivate NOTE-CANARY; {{7*7}} stays data.\n\n"
    "**Résumé — 森林** keeps UTF-8 and [proof](targets/dc01/screenshots/proof.png) as Markdown.\n"
).encode("utf-8")
POC = b'raise RuntimeError("ARCHIVE_CODE_EXECUTED")\n'
UNLISTED_CANARY = b"UNLISTED-CONTENT-CANARY"
CREDS_CANARY = b"CRED-ROOT-CANARY"
LISTS_CANARY = b"LIST-CONTENT-CANARY"
CREDS_FOLDER_CANARY = b"CREDS-FOLDER-CANARY"
TOOLDATA_CANARY = b"TOOLDATA-CANARY"
FILES_CANARY = b"FILES-FOLDER-CANARY"
UPLOAD_CANARY = b"UPLOAD-FOLDER-CANARY"
STRAY_CANARY = b"STRAY-FILE-CANARY"
# held back like creds.toml: never read, never copied, never selectable; only counted
HELD_BACK = ("creds.toml", "lists/", "targets/dc01/creds/", "tooldata/")
# the box fields make_archive can override, as pwn-broker writes them by default
BOX_FIELDS = {"name": "forest", "platform": "htb", "os": "windows", "difficulty": "easy"}


@dataclass(frozen=True)
class FileRecord:
    path: str
    target: str
    first_seen: datetime
    size: int
    mtime: float
    sha256: str


@dataclass(frozen=True)
class ArchiveFixture:
    path: Path
    kind: str
    members: dict[str, bytes]
    records: tuple[FileRecord, ...]
    model: dict

    @property
    def manifest_bytes(self) -> bytes:
        return self.members["manifest.toml"]

    @property
    def archive_sha256(self) -> str:
        return sha256(self.path.read_bytes())


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def evidence_id(path: str, content_sha256: str, *, box_id: str = BOX_ID) -> str:
    payload = b"\0".join(
        (
            b"pwn-report",
            b"evidence",
            b"v1",
            box_id.encode("utf-8"),
            path.encode("utf-8"),
            content_sha256.encode("ascii"),
        )
    )
    # The domain prefix includes the trailing NUL represented by the join above.
    return "ev_" + sha256(payload)


def canonical_json(model: dict) -> bytes:
    return (json.dumps(model, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def file_record(
    path: str,
    data: bytes,
    *,
    target: str = "",
    first_seen: datetime = NOW,
    mtime: float = 0.0,
) -> FileRecord:
    return FileRecord(
        path=path,
        target=target,
        first_seen=first_seen,
        size=len(data),
        mtime=mtime,
        sha256=sha256(data),
    )


def _info(name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = _info(name)
    info.mode = 0o644
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def add_dir(tar: tarfile.TarFile, name: str) -> None:
    info = _info(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    tar.addfile(info)


def _toml_value(value) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str):
        # JSON and TOML basic strings share the escapes used by these fixtures.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    raise TypeError(f"unsupported fixture TOML value: {type(value).__name__}")


def _box_fields(box: dict[str, str] | None) -> dict[str, str]:
    unknown = set(box or {}) - set(BOX_FIELDS)
    if unknown:
        raise ValueError(f"make_archive cannot override {sorted(unknown)}")
    return {**BOX_FIELDS, **(box or {})}


def _box_lines(fields: dict[str, str]) -> list[str]:
    return [f"{key} = {_toml_value(fields[key])}" for key in ("name", "platform", "os", "difficulty")]


def _box_toml(*, full: bool, finished: datetime | None, box: dict[str, str] | None = None) -> bytes:
    lines = [
        "schema = 1",
        f"id = {_toml_value(BOX_ID)}",
        *_box_lines(_box_fields(box)),
        'status = "active"',
        f"started = {_toml_value(NOW)}",
    ]
    if finished is not None:
        lines.append(f"finished = {_toml_value(finished)}")
    if full:
        for name, value, at in (
            ("user", "USER-FLAG-PRIVATE-CANARY", NOW),
            ("root", "ROOT-FLAG-PRIVATE-CANARY", LATER),
        ):
            lines.extend(
                (
                    "",
                    f"[flags.{name}]",
                    f"value = {_toml_value(value)}",
                    f"at = {_toml_value(at)}",
                )
            )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _target_toml(box_name: str = "forest") -> bytes:
    lines = [
        "schema = 1",
        f"box_id = {_toml_value(BOX_ID)}",
        f"box = {_toml_value(box_name)}",
        'name = "dc01"',
        'ips = ["10.10.10.161"]',
        'hostnames = ["forest.htb.local"]',
        'scope = "external"',
        f"added = {_toml_value(NOW)}",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _manifest_toml(
    records: list[FileRecord], *, kind: str, finished: datetime | None, box: dict[str, str] | None = None
) -> bytes:
    lines = [
        "schema = 1",
        f"kind = {_toml_value(kind)}",
        f"packed = {_toml_value(PACKED)}",
        "",
        "[box]",
        f"id = {_toml_value(BOX_ID)}",
        *_box_lines(_box_fields(box)),
        f"started = {_toml_value(NOW)}",
    ]
    if finished is not None:
        lines.append(f"finished = {_toml_value(finished)}")
    for record in records:
        lines.extend(
            (
                "",
                "[[file]]",
                f"path = {_toml_value(record.path)}",
                f"target = {_toml_value(record.target)}",
                f"first_seen = {_toml_value(record.first_seen)}",
                f"size = {_toml_value(record.size)}",
                f"mtime = {_toml_value(record.mtime)}",
                f"sha256 = {_toml_value(record.sha256)}",
            )
        )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _evidence_location(path: str) -> tuple[str, str] | None:
    parts = PurePosixPath(path).parts
    if len(parts) >= 4 and parts[0] == "targets" and parts[2] in EVIDENCE_KINDS | TARGET_ONLY_KINDS:
        return parts[1], parts[2]
    if len(parts) >= 2 and parts[0] in EVIDENCE_KINDS:
        return "", parts[0]
    return None


def _source(members: dict[str, bytes], path: str) -> dict[str, str]:
    return {"path": path, "sha256": sha256(members[path])}


def _compact_json(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _held_back_group(path: str) -> str | None:
    parts = PurePosixPath(path).parts
    if path == "creds.toml":
        return "creds.toml"
    if parts[0] in {"lists", "tooldata"} and len(parts) >= 2:
        return parts[0] + "/"
    if len(parts) >= 4 and parts[0] == "targets" and parts[2] == "creds":
        return f"targets/{parts[1]}/creds/"
    return None


def _held_back(records: list[FileRecord]) -> list[dict]:
    counts: dict[str, int] = {}
    for record in records:
        group = _held_back_group(record.path)
        if group is not None:
            counts[group] = counts.get(group, 0) + 1
    return [{"path": path, "files": counts[path]} for path in sorted(counts)]


def _is_metadata(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return path in {"box.toml", "notes.md", "manifest.toml"} or (
        len(parts) == 3 and parts[0] == "targets" and parts[2] == "target.toml"
    )


def _other(records: list[FileRecord]) -> list[str]:
    return sorted(
        record.path
        for record in records
        if _evidence_location(record.path) is None
        and _held_back_group(record.path) is None
        and not _is_metadata(record.path)
    )


def _expected_model(
    members: dict[str, bytes],
    records: list[FileRecord],
    *,
    full: bool,
    kind: str,
    finished: datetime | None,
    archive_sha256: str,
    box_fields: dict[str, str] | None = None,
) -> dict:
    fields = _box_fields(box_fields)
    box = {
        "id": BOX_ID,
        **fields,
        "status": "active",
        "started": NOW.isoformat(),
        "source": _source(members, "box.toml"),
    }
    if finished is not None:
        box["finished"] = finished.isoformat()

    flags = []
    targets = []
    if full:
        flags = sorted(
            (
                {
                    "name": "user",
                    "value": "USER-FLAG-PRIVATE-CANARY",
                    "at": NOW.isoformat(),
                    "source": _source(members, "box.toml"),
                },
                {
                    "name": "root",
                    "value": "ROOT-FLAG-PRIVATE-CANARY",
                    "at": LATER.isoformat(),
                    "source": _source(members, "box.toml"),
                },
            ),
            key=lambda flag: flag["name"],
        )
        targets = [
            {
                "box_id": BOX_ID,
                "box": fields["name"],
                "name": "dc01",
                "ips": ["10.10.10.161"],
                "hostnames": ["forest.htb.local"],
                "scope": "external",
                "added": NOW.isoformat(),
                "source": _source(members, "targets/dc01/target.toml"),
            }
        ]

    evidence = []
    for record in records:
        location = _evidence_location(record.path)
        if location is None:
            continue
        target, evidence_kind = location
        copied = evidence_kind in {"scans", "screenshots", "exploits"}
        reason = "default-include" if copied else {
            "loot": "default-exclude-loot",
            "recordings": "default-exclude-recording",
            "files": "default-exclude-files",
            "upload": "default-exclude-upload",
        }[evidence_kind]
        output = {"copied": copied, "reason": reason}
        if copied:
            output["path"] = "evidence/" + record.path
        evidence.append(
            {
                "id": evidence_id(record.path, record.sha256),
                "path": record.path,
                "target": target,
                "target_refs": [target] if target else [],
                "first_seen": record.first_seen.isoformat(),
                "size": record.size,
                "mtime": record.mtime,
                "sha256": record.sha256,
                "kind": evidence_kind,
                "output": output,
                "source": _source(members, record.path),
            }
        )
    evidence.sort(key=lambda item: item["path"])

    timeline = [
        {
            "at": flag["at"],
            "kind": "flag_recorded",
            "flag": flag["name"],
            "source": flag["source"],
        }
        for flag in flags
    ]
    timeline.extend(
        {
            "at": target["added"],
            "kind": "target_added",
            "target": target["name"],
            "source": target["source"],
        }
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
    timeline.sort(
        key=lambda event: (
            datetime.fromisoformat(event["at"]).astimezone(timezone.utc),
            event["at"],
            event["kind"],
            _compact_json(event),
        )
    )

    model = {
        "schema_version": 1,
        "profile": "private-technical",
        "status": "draft",
        "box": box,
        "source": {
            "archive": {
                "kind": kind,
                "packed": PACKED.isoformat(),
                "sha256": archive_sha256,
            },
            "manifest": _source(members, "manifest.toml"),
        },
        "flags": flags,
        "targets": targets,
        "timeline": timeline,
        "evidence": evidence,
        "findings": [],
        "held_back": _held_back(records),
        "other": _other(records),
    }
    if full:
        model["notes"] = {
            "source": _source(members, "notes.md"),
            "report_path": "evidence/notes.md",
            "size": len(members["notes.md"]),
        }
    return model


def manifest_bytes(
    records, *, kind: str = "exported", finished: datetime | None = None, box: dict[str, str] | None = None
) -> bytes:
    """Serialize records for mutation tests without importing a TOML writer."""
    return _manifest_toml(list(records), kind=kind, finished=finished, box=box)


def write_raw_archive(destination: Path, write) -> Path:
    """Let safety tests construct tar metadata without creating filesystem members."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as tar:
                write(tar)
    return destination


def add_members(tar: tarfile.TarFile, members: dict[str, bytes]) -> None:
    """Add the standard root and a regular-file member map to an open tar."""
    add_dir(tar, BOX_ID)
    directories = set()
    for path in members:
        parent = PurePosixPath(path).parent
        while parent != PurePosixPath("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    for directory in sorted(directories, key=lambda name: (name.count("/"), name)):
        add_dir(tar, f"{BOX_ID}/{directory}")
    for path in sorted(members):
        add_bytes(tar, f"{BOX_ID}/{path}", members[path])


def write_archive(destination: Path, members: dict[str, bytes]) -> Path:
    """Write an arbitrary member map under the standard root for mutation tests."""
    return write_raw_archive(destination, lambda tar: add_members(tar, members))


def make_archive(
    destination: Path,
    *,
    full: bool = False,
    kind: str = "exported",
    finished: datetime | None = None,
    box: dict[str, str] | None = None,
) -> ArchiveFixture:
    """Write one deterministic synthetic archive and return its golden model."""
    members = {"box.toml": _box_toml(full=full, finished=finished, box=box)}
    if full:
        members.update(
            {
                "targets/dc01/target.toml": _target_toml(_box_fields(box)["name"]),
                "notes.md": NOTES,
                "targets/dc01/scans/nmap.txt": b"SYN scan\n",
                "targets/dc01/screenshots/proof.png": b"\x89PNG\r\n\x1a\nSYNTHETIC",
                "targets/dc01/exploits/poc.py": POC,
                "targets/dc01/loot/SAM.bak": b"LOOT-CONTENT-CANARY",
                "targets/dc01/recordings/session.cast": b"RECORDING-CONTENT-CANARY",
                "screenshots/root.png": b"\x89PNG\r\n\x1a\nROOT-SCREENSHOT",
                # listed, as real pwn-broker lists them
                "creds.toml": CREDS_CANARY,
                "lists/passwords.txt": LISTS_CANARY,
                "targets/dc01/creds/admin.ccache": CREDS_FOLDER_CANARY,
                "tooldata/netexec/nxc.db": TOOLDATA_CANARY,
                "targets/dc01/files/notes.txt": FILES_CANARY,
                "targets/dc01/upload/winpeas.exe": UPLOAD_CANARY,
                "stray.txt": STRAY_CANARY,
            }
        )

    records = []
    for path in sorted(members):
        location = _evidence_location(path)
        target = path.split("/")[1] if path.startswith("targets/") else ""
        first_seen = FIRST_SEEN if location is not None else NOW
        records.append(file_record(path, members[path], target=target, first_seen=first_seen))

    if full:
        # This exercises the unlisted boundary without entering records.
        members["unlisted.txt"] = UNLISTED_CANARY
    members["manifest.toml"] = manifest_bytes(records, kind=kind, finished=finished, box=box)
    write_archive(destination, members)

    model = _expected_model(
        members,
        records,
        full=full,
        kind=kind,
        finished=finished,
        archive_sha256=sha256(destination.read_bytes()),
        box_fields=box,
    )
    return ArchiveFixture(destination, kind, members, tuple(records), model)

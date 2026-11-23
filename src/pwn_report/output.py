"""Deterministic private-report rendering and atomic output commits."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tarfile
import zlib
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, quote

from . import __version__
from .report import READ_BYTES, ReportError, _file_sha, _members, _open, build_model
from .validate import validate_model

GENERATOR_VERSION = __version__
# what the report never reads, and what it keeps as it was; the README quotes it word for word
PRIVACY_NOTE = (
    "It never reads `creds.toml`, `lists/`, `targets/*/creds/` or `tooldata/`. "
    "`notes.md` and copied scans are as they were and can hold passwords; keep this report private."
)
_LINK = re.compile(r"(?<!\\)\[[^\]\n]*(?<!\\)\]\(([^)\s]+)\)")
_CHECKSUM_ROW = re.compile(r"^([0-9a-f]{64})  (.+)$")


def _canonical_json(model: dict) -> bytes:
    return (
        json.dumps(model, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _metadata_toml(model: dict) -> bytes:
    source = model["source"]
    archive = source["archive"]
    lines = [
        'generator = "pwn-report"',
        f"generator_version = {_toml_string(GENERATOR_VERSION)}",
        f"schema_version = {model['schema_version']}",
        f"profile = {_toml_string(model['profile'])}",
        f"box_id = {_toml_string(model['box']['id'])}",
        f"archive_kind = {_toml_string(archive['kind'])}",
        f"source_archive_sha256 = {_toml_string(archive['sha256'])}",
    ]
    if "selection" in source:
        lines.append(f"selection_sha256 = {_toml_string(source['selection']['sha256'])}")
    lines.append(f"status = {_toml_string(model['status'])}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _md_text(value: str) -> str:
    """Keep source strings as literal inline Markdown data, including HTML-like text."""
    value = value.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    for character in ("\\", "`", "*", "_", "[", "]", "|"):
        value = value.replace(character, "\\" + character)
    return value


def _md_link(path: str) -> str:
    return quote(path, safe="/", encoding="utf-8", errors="strict")


def _render_markdown(model: dict) -> bytes:
    box = model["box"]
    lines = [
        f"# {_md_text(box['name'])} — private technical report",
        "",
        "## Review status",
        "",
        "**Draft / unreviewed.** No publication approval, severity rating, or finding validity is implied.",
        "",
        PRIVACY_NOTE,
        "",
        "## Box summary",
        "",
        f"- Name: {_md_text(box['name'])}",
        f"- Platform: {_md_text(box['platform'])}",
        f"- OS: {_md_text(box['os'] or 'Not recorded')}",
        f"- Difficulty: {_md_text(box['difficulty'] or 'Not recorded')}",
        f"- Status: {_md_text(box['status'])}",
        f"- Started: {_md_text(box['started'])}",
    ]
    if "finished" in box:
        lines.append(f"- Finished: {_md_text(box['finished'])}")
    lines.extend((f"- Archive kind: {_md_text(model['source']['archive']['kind'])}", "", "## Targets", ""))
    if not model["targets"]:
        lines.append("No targets are recorded.")
    for target in model["targets"]:
        lines.extend(
            (
                f"### {_md_text(target['name'])}",
                "",
                f"- Scope: {_md_text(target['scope'])}",
                f"- Addresses: {_md_text(', '.join(target['ips']) or 'None recorded')}",
                f"- Hostnames: {_md_text(', '.join(target['hostnames']) or 'None recorded')}",
                f"- Added: {_md_text(target['added'])}",
                "",
            )
        )
    if model["targets"]:
        lines.pop()
    lines.extend(("", "## Flags", ""))
    if not model["flags"]:
        lines.append("No flags are recorded.")
    for flag in model["flags"]:
        lines.append(f"- {_md_text(flag['name'])}: {_md_text(flag['value'])} — {_md_text(flag['at'])}")
    lines.extend(("", "## Timeline", ""))
    if not model["timeline"]:
        lines.append("No timeline events are recorded.")
    evidence_by_id = {item["id"]: item for item in model["evidence"]}
    for event in model["timeline"]:
        at = _md_text(event["at"])
        if event["kind"] == "target_added":
            detail = f"Target added: {_md_text(event['target'])}"
        elif event["kind"] == "flag_recorded":
            detail = f"Flag recorded: {_md_text(event['flag'])}"
        else:
            item = evidence_by_id[event["evidence_id"]]
            detail = f"File first seen: {_md_text(item['path'])} ({_md_text(item['id'])})"
        lines.append(f"- {at} — {detail}")

    lines.extend(("", "## Evidence index", ""))
    if not model["evidence"]:
        lines.append("No evidence is recorded.")
    groups: dict[tuple[str, str], list[dict]] = {}
    for item in model["evidence"]:
        groups.setdefault((item["target"], item["kind"]), []).append(item)
    for (target, kind), items in sorted(groups.items()):
        lines.extend((f"### {_md_text(target or 'Unassigned')} / {_md_text(kind)}", ""))
        for item in items:
            output = item["output"]
            lines.extend(
                (
                    f"#### {_md_text(item['id'])}",
                    "",
                    f"- Path: {_md_text(item['path'])}",
                    f"- Target references: {_md_text(', '.join(item['target_refs']) or 'None')}",
                    f"- First seen: {_md_text(item['first_seen'])}",
                    f"- Size: {item['size']} bytes",
                    f"- SHA-256: {_md_text(item['sha256'])}",
                    f"- Decision: {_md_text(output['reason'])}",
                )
            )
            if output["copied"]:
                lines.append(f"- File: [Open copied evidence]({_md_link(output['path'])})")
            else:
                lines.append("- File: Indexed only; not copied by the evidence policy.")
            if "caption" in item:
                lines.append(f"- Caption: {_md_text(item['caption'])}")
            if "alt_text" in item:
                lines.append(f"- Alt text: {_md_text(item['alt_text'])}")
            lines.append("")
    if lines[-1] != "":
        lines.append("")
    lines.extend(("## Not in the index", ""))
    if not model["held_back"] and not model["other"]:
        lines.extend(("No files are held back or outside the index.", ""))
    if model["held_back"]:
        lines.extend(("Held back, never read or copied:", ""))
        for group in model["held_back"]:
            count = group["files"]
            if group["path"].endswith("/"):
                lines.append(f"- {_md_text(group['path'])}: {count} file{'' if count == 1 else 's'}, held back")
            else:
                lines.append(f"- {_md_text(group['path'])}: held back")
        lines.append("")
    if model["other"]:
        lines.extend(("Listed in the archive, outside the index:", ""))
        lines.extend(f"- {_md_text(path)}" for path in model["other"])
        lines.append("")
    lines.extend(("## Notes", ""))
    if "notes" in model:
        lines.append(f"[Open archived notes]({_md_link(model['notes']['report_path'])})")
        lines.append("")
        lines.append("Notes are copied unchanged; no summary or generated narrative is supplied.")
    else:
        lines.append("No listed notes file is recorded.")
    return ("\n".join(lines).rstrip("\n") + "\n").encode("utf-8")


def _output_path(root: Path, relative: str) -> Path:
    return root.joinpath(*PurePosixPath(relative).parts)


def _copy_member(
    tar: tarfile.TarFile,
    member: tarfile.TarInfo,
    destination: Path,
    *,
    size: int,
    sha256: str,
    label: str,
) -> None:
    if not member.isreg() or member.size != size:
        raise ReportError(f"{label} changed before evidence copying")
    source = tar.extractfile(member)
    if source is None:
        raise ReportError(f"{label} cannot be read for evidence copying")
    reader = getattr(source, "raw", source)
    digest = hashlib.sha256()
    remaining = size
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source, destination.open("xb") as output:
        while remaining:
            piece = reader.read(min(READ_BYTES, remaining))
            if not piece:
                raise ReportError(f"{label} ends inside its archived data")
            output.write(piece)
            digest.update(piece)
            remaining -= len(piece)
    if digest.hexdigest() != sha256:
        raise ReportError(f"{label} checksum changed before evidence copying")


def _checksum_bytes(files: dict[str, bytes], copied: set[str], stage: Path) -> bytes:
    rows = []
    for path in sorted(set(files) | copied):
        digest = hashlib.sha256(files[path]).hexdigest() if path in files else _file_sha(_output_path(stage, path))
        rows.append(f"{digest}  {path}\n")
    return "".join(rows).encode("utf-8")


def _required_bytes(files: dict[str, bytes], copied_sizes: dict[str, int]) -> int:
    output_paths = set(files) | set(copied_sizes)
    checksum_size = sum(64 + 2 + len(path.encode("utf-8")) + 1 for path in output_paths)
    return sum(map(len, files.values())) + sum(copied_sizes.values()) + checksum_size


def _validate_links(stage: Path, markdown: bytes) -> None:
    text = markdown.decode("utf-8")
    for match in _LINK.finditer(text):
        encoded = match.group(1)
        try:
            relative = unquote(encoded, encoding="utf-8", errors="strict")
        except (UnicodeError, ValueError) as exc:
            raise ReportError(f"rendered link {encoded!r} is not valid UTF-8") from exc
        parts = relative.split("/")
        if (
            not relative
            or relative.startswith("/")
            or "\\" in relative
            or (len(relative) >= 2 and relative[0].isalpha() and relative[1] == ":")
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise ReportError(f"rendered link {encoded!r} is not a safe relative path")
        target = _output_path(stage, relative)
        if not target.is_file() or target.is_symlink():
            raise ReportError(f"rendered link {encoded!r} does not resolve to a copied file")


def _validate_staging(stage: Path, model: dict, files: dict[str, bytes], copied: dict[str, str]) -> None:
    expected = set(files) | set(copied) | {"SHA256SUMS"}
    actual = {
        path.relative_to(stage).as_posix()
        for path in stage.rglob("*")
        if path.is_file()
    }
    if actual != expected:
        raise ReportError("staged output file set differs from the report model")
    for relative, data in files.items():
        if _output_path(stage, relative).read_bytes() != data:
            raise ReportError(f"staged {relative} differs from its deterministic rendering")
    for relative, source_path in copied.items():
        copied_path = _output_path(stage, relative)
        if not copied_path.is_file() or copied_path.is_symlink():
            raise ReportError(f"staged asset {relative} is not a regular file")
        expected_hash = model["notes"]["source"]["sha256"] if source_path == "notes.md" else next(
            item["sha256"] for item in model["evidence"] if item["source"]["path"] == source_path
        )
        if _file_sha(copied_path) != expected_hash:
            raise ReportError(f"staged asset {relative} has the wrong checksum")
    _validate_links(stage, files["report.md"])
    sums = _output_path(stage, "SHA256SUMS").read_bytes().decode("utf-8")
    rows = sums.splitlines()
    if not sums.endswith("\n") or len(rows) != len(expected) - 1:
        raise ReportError("SHA256SUMS is incomplete or lacks its final LF")
    seen = []
    for row in rows:
        match = _CHECKSUM_ROW.fullmatch(row)
        if match is None:
            raise ReportError("SHA256SUMS contains an invalid row")
        digest, relative = match.groups()
        if relative == "SHA256SUMS" or relative not in expected:
            raise ReportError("SHA256SUMS covers an unknown or forbidden path")
        if _file_sha(_output_path(stage, relative)) != digest:
            raise ReportError(f"SHA256SUMS checksum differs for {relative}")
        seen.append(relative)
    if seen != sorted(expected - {"SHA256SUMS"}) or len(seen) != len(set(seen)):
        raise ReportError("SHA256SUMS paths are not complete, unique, and sorted")


def _build_report(archive: Path, output: Path, selection: Path | None) -> dict:
    if os.path.lexists(output):
        raise ReportError(f"output already exists and will not be replaced: {output}")
    if not output.parent.is_dir():
        raise ReportError(f"output parent is not an existing directory: {output.parent}")

    model = validate_model(build_model(archive, selection))
    files = {
        "report.json": _canonical_json(model),
        "report.md": _render_markdown(model),
        "report.toml": _metadata_toml(model),
    }
    copied: dict[str, str] = {}
    copied_sizes: dict[str, int] = {}
    for item in model["evidence"]:
        if item["output"]["copied"]:
            relative = item["output"]["path"]
            copied[relative] = item["source"]["path"]
            copied_sizes[relative] = item["size"]
    if "notes" in model:
        copied[model["notes"]["report_path"]] = "notes.md"
        copied_sizes[model["notes"]["report_path"]] = model["notes"]["size"]

    required = _required_bytes(files, copied_sizes)
    free = shutil.disk_usage(output.parent).free
    if required > free:
        raise ReportError(f"insufficient free space: {required} bytes required, {free} available")

    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.tmp-", dir=output.parent))
    try:
        (stage / "evidence").mkdir()
        for relative, data in files.items():
            _output_path(stage, relative).write_bytes(data)
        with _open(archive) as tar:
            root, members = _members(tar)
            wanted = []
            for relative, source_path in copied.items():
                member = members.get(f"{root}/{source_path}")
                if member is None:
                    raise ReportError(f"{source_path} disappeared before evidence copying")
                wanted.append((member.offset_data, relative, source_path, member))
            # archive order, so the gzip stream is only read forwards
            for _offset, relative, source_path, member in sorted(wanted, key=lambda row: (row[0], row[1])):
                expected_hash = model["notes"]["source"]["sha256"] if source_path == "notes.md" else next(
                    item["sha256"] for item in model["evidence"] if item["source"]["path"] == source_path
                )
                _copy_member(
                    tar,
                    member,
                    _output_path(stage, relative),
                    size=copied_sizes[relative],
                    sha256=expected_hash,
                    label=source_path,
                )
        _output_path(stage, "SHA256SUMS").write_bytes(_checksum_bytes(files, set(copied), stage))
        _validate_staging(stage, model, files, copied)
        if _file_sha(archive) != model["source"]["archive"]["sha256"]:
            raise ReportError("source archive changed during report generation")
        if selection is not None and _file_sha(selection) != model["source"]["selection"]["sha256"]:
            raise ReportError("selection changed during report generation")
        if os.path.lexists(output):
            raise ReportError(f"output appeared during generation and will not be replaced: {output}")
        stage.rename(output)
        stage = None
        return model
    finally:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)


def build_report(
    archive: str | os.PathLike[str],
    output: str | os.PathLike[str],
    selection: str | os.PathLike[str] | None = None,
) -> dict:
    """Build a deterministic report directory, refusing every existing output."""
    archive_path = Path(archive)
    output_path = Path(output)
    selection_path = Path(selection) if selection is not None else None
    try:
        return _build_report(archive_path, output_path, selection_path)
    except ReportError:
        raise
    # zlib.error comes through raw when the deflate stream breaks inside a member's data, and
    # OverflowError from a time that has no UTC instant
    except (
        OSError, EOFError, tarfile.TarError, zlib.error, ValueError, TypeError, UnicodeError,
        RecursionError, OverflowError,
    ) as exc:  # fmt: skip
        raise ReportError(f"{output_path}: cannot build report: {exc}") from exc

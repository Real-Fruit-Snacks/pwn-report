"""Deterministic private-report rendering and atomic output commits."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
import zlib
import tempfile
import unicodedata
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, quote

from . import __version__
from .report import READ_BYTES, UNSAFE_CATEGORIES, ReportError, _file_sha, _members, _open, build_model, shown
from .validate import validate_model

GENERATOR_VERSION = __version__
# what the report never reads, and what it keeps as it was; the README quotes it word for word
PRIVACY_NOTE = (
    "It never reads `creds.toml`, `lists/`, `targets/*/creds/` or `tooldata/`. "
    "`notes.md` and every copied file are as they were and can hold passwords; keep this report private."
)
_LINK = re.compile(r"(?<!\\)\[[^\]\n]*(?<!\\)\]\(([^)\s]+)\)")
# what starts a numbered list: up to nine digits, a . or a ), then a space or the end of the line
_LIST_NUMBER = re.compile(r"^([0-9]{1,9})([.)])(?= |$)")
_CHECKSUM_ROW = re.compile(r"^([0-9a-f]{64})  (.+)$")
# device names Windows reserves in every folder, with or without an extension
_WINDOWS_RESERVED = re.compile(r"^(?:con|prn|aux|nul|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3])(?:\..*)?$", re.I)
_WINDOWS_REFUSED = frozenset('<>:"|?*')
NEXT_STEP = "exclude one with a selection rule, or build the report on Linux"


def _escaped(text: str, beyond_ffff) -> str:
    """Text that json.dumps wrote with ensure_ascii off, with each unsafe character it leaves as
    it is (DEL, a C1 control, a format character such as a right-to-left override, a line or
    paragraph separator) written as its \\u escape. json.dumps has already escaped the controls
    below a space inside strings, so a line break still there is the layout's own and stays.

    The characters to escape are found among the distinct ones in the text, and one pass
    replaces them: str.translate took minutes over a report of many such characters."""
    unsafe = sorted(
        character
        for character in set(text)
        if character >= "\x7f" and unicodedata.category(character) in UNSAFE_CATEGORIES
    )
    if not unsafe:
        return text
    escapes = {
        character: beyond_ffff(ord(character)) if ord(character) > 0xFFFF else f"\\u{ord(character):04x}"
        for character in unsafe
    }
    return re.sub("[" + "".join(unsafe) + "]", lambda found: escapes[found.group()], text)


def _surrogate_pair(code: int) -> str:
    # JSON has four hex digits only, so a character past U+FFFF is two escapes; TOML has \U
    code -= 0x10000
    return f"\\u{0xD800 | (code >> 10):04x}\\u{0xDC00 | (code & 0x3FF):04x}"


def _canonical_json(model: dict) -> bytes:
    """The model as JSON that is safe to print: text in any script is written as it is, and a
    control or format character as an escape, which loads back as the character it was."""
    text = json.dumps(model, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2) + "\n"
    return _escaped(text, _surrogate_pair).encode("utf-8")


def _toml_string(value: str) -> str:
    # JSON's string escapes are TOML's too, except that JSON leaves DEL and the other unsafe
    # characters raw: TOML forbids DEL, and none of them should reach a terminal
    return _escaped(json.dumps(value, ensure_ascii=False), lambda code: f"\\U{code:08x}")


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
    """Keep source strings as literal inline Markdown data, including HTML-like text. A control
    or format character (an escape sequence, a right-to-left override) is shown as ?, so
    reading report.md in a terminal cannot run one and a name cannot disguise itself.

    A value is also the first thing in a list item (a flag's name, a path outside the index) and
    the last in a heading, where more than inline Markdown counts: there `# x` is a heading,
    `- x`, `+ x` and `1. x` are lists, `---` is a rule, four spaces are a code block, and
    `x ##` loses its end. So `#` is escaped wherever it is, and so is what the value starts
    with when that could start a block; a space at either end, which Markdown drops or counts
    as indentation, is written as `&#32;`. A tab is a control character, so it is ? by then."""
    value = value.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    value = shown(value)
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    for character in ("\\", "`", "*", "_", "[", "]", "|", "~", "#"):
        value = value.replace(character, "\\" + character)
    if value.startswith(("-", "+", "=")):
        value = "\\" + value
    else:
        value = _LIST_NUMBER.sub(r"\1\\\2", value)
    if value.startswith(" "):
        value = "&#32;" + value[1:]
    if value.endswith(" "):
        value = value[:-1] + "&#32;"
    return value


def _md_link(path: str) -> str:
    return quote(path, safe="/", encoding="utf-8", errors="strict")


# what report.md says for each reason report.json records; the codes stay in report.json
_LEFT_OUT = {
    "default-exclude-loot": "loot is indexed only unless a selection includes it",
    "default-exclude-recording": "recordings are indexed only unless a selection includes them",
    "default-exclude-files": "files/ is indexed only unless a selection includes it",
    "default-exclude-upload": "upload/ is indexed only unless a selection includes it",
    "selection-exclude": "the selection leaves it out",
}


def _file_line(output: dict) -> str:
    # the link text is fixed: an archived name inside a link's brackets could hide the link from
    # _validate_links, and the entry's heading already names the file
    if output["copied"]:
        link = f"[copied]({_md_link(output['path'])})"
        return f"{link}, as the selection asks" if output["reason"] == "selection-include" else link
    return f"not copied; {_LEFT_OUT[output['reason']]}"


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
            detail = f"File first seen: {_md_text(item['path'])}"
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
                    f"#### {_md_text(item['path'])}",
                    "",
                    f"- ID: {_md_text(item['id'])}",
                    f"- Target references: {_md_text(', '.join(item['target_refs']) or 'None')}",
                    f"- First seen: {_md_text(item['first_seen'])}",
                    f"- Size: {item['size']} {'byte' if item['size'] == 1 else 'bytes'}",
                    f"- SHA-256: {_md_text(item['sha256'])}",
                )
            )
            lines.append(f"- File: {_file_line(output)}")
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


def _source_name(relative: str) -> str:
    return relative.removeprefix("evidence/")


def _unwritable(relatives: list[str], *, windows: bool, folds_case: bool) -> str | None:
    """Why this system cannot hold these output paths, naming the files, or None.

    Windows refuses its device names (CON, aux.txt, com1), a name ending in a dot or a space,
    and the characters <>:"|?*. A case-folding file system (Windows, macOS) holds two names
    that differ only in case, or only in Unicode form, as one: their files or folders would merge.
    """
    files = set(relatives)
    for relative in sorted(relatives):
        parts = relative.split("/")
        for depth in range(1, len(parts)):
            folder = "/".join(parts[:depth])
            if folder in files:
                return (
                    f"{_source_name(folder)} is a file and also the folder of {_source_name(relative)}, "
                    f"which no file system can hold; {NEXT_STEP.split(', or ')[0]}"
                )
    if windows:
        for relative in sorted(relatives):
            for part in relative.split("/"):
                if _WINDOWS_RESERVED.match(part) or part.endswith((".", " ")) or _WINDOWS_REFUSED & set(part):
                    return (
                        f"{_source_name(relative)} cannot be written here: Windows refuses the name {part!r}; "
                        f"{NEXT_STEP}"
                    )
    if folds_case:
        seen: dict[str, str] = {}
        for relative in sorted(relatives):
            parts = relative.split("/")
            for depth in range(1, len(parts) + 1):
                name = "/".join(parts[:depth])
                key = unicodedata.normalize("NFC", name).casefold()
                if seen.setdefault(key, name) != name:
                    return (
                        f"{_source_name(seen[key])} and {_source_name(name)} differ only in case or in "
                        f"Unicode form, which this system's file names cannot tell apart; {NEXT_STEP}"
                    )
    return None


def _unwritable_output(name: str, *, windows: bool) -> str | None:
    """Why the report folder's own name cannot be made here, or None: Windows makes CON a device,
    and drops a trailing dot or space, so the folder would not be the one asked for."""
    if windows and (_WINDOWS_RESERVED.match(name) or name.endswith((".", " ")) or _WINDOWS_REFUSED & set(name)):
        return f"the report folder's name {name!r} is one Windows refuses or changes; give another with -o"
    return None


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


def _validate_staging(
    stage: Path, model: dict, files: dict[str, bytes], copied: dict[str, str], sha_by_path: dict[str, str]
) -> None:
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
        expected_hash = sha_by_path[source_path]
        if _file_sha(copied_path) != expected_hash:
            raise ReportError(f"staged asset {relative} has the wrong checksum")
    _validate_links(stage, files["report.md"])
    sums = _output_path(stage, "SHA256SUMS").read_bytes().decode("utf-8")
    rows = sums[:-1].split("\n") if sums.endswith("\n") else sums.split("\n")
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


def _build_report(archive: Path, output: Path, selection: Path | None, placed: list) -> dict:
    # first: on Windows NUL and CON exist in every folder, so they would read as an existing output
    problem = _unwritable_output(output.name, windows=os.name == "nt")
    if problem is not None:
        raise ReportError(problem)
    if os.path.lexists(output):
        raise ReportError(f"output already exists and will not be replaced: {output}")
    if not output.parent.is_dir():
        raise ReportError(f"output parent is not an existing directory: {output.parent}")

    model = validate_model(build_model(archive, selection))
    # each copied file's SHA-256 by its path, made once: a walk of all the evidence per file
    # made the build grow with the square of the files copied
    sha_by_path = {item["source"]["path"]: item["sha256"] for item in model["evidence"]}
    if "notes" in model:
        sha_by_path["notes.md"] = model["notes"]["source"]["sha256"]
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

    problem = _unwritable(
        sorted(set(files) | set(copied) | {"SHA256SUMS"}),
        windows=os.name == "nt",
        folds_case=os.name == "nt" or sys.platform == "darwin",
    )
    if problem is not None:
        raise ReportError(problem)
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
                expected_hash = sha_by_path[source_path]
                _copy_member(
                    tar,
                    member,
                    _output_path(stage, relative),
                    size=copied_sizes[relative],
                    sha256=expected_hash,
                    label=source_path,
                )
        _output_path(stage, "SHA256SUMS").write_bytes(_checksum_bytes(files, set(copied), stage))
        _validate_staging(stage, model, files, copied, sha_by_path)
        if _file_sha(archive) != model["source"]["archive"]["sha256"]:
            raise ReportError("source archive changed during report generation")
        if selection is not None and _file_sha(selection) != model["source"]["selection"]["sha256"]:
            raise ReportError("selection changed during report generation")
        if os.path.lexists(output):
            raise ReportError(f"output appeared during generation and will not be replaced: {output}")
        stage.rename(output)
        placed.append(output)
        return model
    except Exception as exc:
        # the staging folder holds copied evidence and the notes: one that cannot be removed is
        # named, never left behind in silence
        if _remove_stage(stage):
            raise ReportError(
                f"{exc}; a partial copy was left at {stage}: delete it, it holds copied evidence"
            ) from exc
        raise
    except BaseException as exc:
        if not isinstance(exc, KeyboardInterrupt):
            _remove_stage(stage)
            raise
        if not os.path.lexists(stage) and os.path.isdir(output):
            # the stop landed between the rename and the return: the report is whole and in place
            if not placed:
                placed.append(output)
            return model
        left = _remove_stage(stage)
        raise Interrupted(stage if left else None) from exc


class Interrupted(KeyboardInterrupt):
    """A stop that the build handled: no report was written by it. `left` names its staging folder
    when that could not be removed, and is None when it was."""

    def __init__(self, left: Path | None) -> None:
        super().__init__(str(left) if left is not None else "")
        self.left = left


def _remove_stage(stage: Path) -> bool:
    """Remove the staging folder; True if any of it is still there. A stop that lands during the
    removal, after a failure or a first stop, does not cut it short: the removal is run again (the
    command ignores every stop after its first, so the next run finishes), and then the stop goes
    on, naming the folder if any of it is left."""
    stopped = None
    left = True  # unless a removal is seen through to its end, the folder is named
    for _attempt in range(3):
        try:
            shutil.rmtree(stage, ignore_errors=True)
            left = os.path.lexists(stage)
            break
        except KeyboardInterrupt as exc:
            stopped = exc
    if stopped is not None:
        raise Interrupted(stage if left else None) from stopped
    return left


def build_report(
    archive: str | os.PathLike[str],
    output: str | os.PathLike[str],
    selection: str | os.PathLike[str] | None = None,
    *,
    placed: list | None = None,
) -> dict:
    """Build a deterministic report directory, refusing every existing output.

    `placed`, if given, has the output path added to it at the moment the report is renamed into
    place. A caller that is stopped then knows whether this call wrote the report: a folder at
    the output says nothing, since another run can have put one there."""
    archive_path = Path(archive)
    output_path = Path(output)
    selection_path = Path(selection) if selection is not None else None
    try:
        return _build_report(archive_path, output_path, selection_path, [] if placed is None else placed)
    except ReportError:
        raise
    # zlib.error comes through raw when the deflate stream breaks inside a member's data, and
    # OverflowError from a time that has no UTC instant
    except (
        OSError, EOFError, tarfile.TarError, zlib.error, ValueError, TypeError, UnicodeError,
        RecursionError, OverflowError,
    ) as exc:  # fmt: skip
        raise ReportError(f"{output_path}: cannot build report: {exc}") from exc

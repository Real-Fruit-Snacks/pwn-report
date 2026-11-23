"""The pwn-report command.

Success prints one line to stdout, `ok    report <folder>`, and exits 0. Any failure prints one
line to stderr, `fail  <reason>`, and exits 1; a usage error exits 2. pwn-broker runs this
command at finish and relies on exactly these lines and statuses.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .output import build_report
from .report import ReportError

_SUFFIX = ".tar.gz"


def default_output(archive: Path) -> Path:
    """Beside the archive: its name with .tar.gz replaced by .report, or with .report added."""
    name = archive.name
    stem = name[: -len(_SUFFIX)] if name.endswith(_SUFFIX) and len(name) > len(_SUFFIX) else name
    return archive.with_name(stem + ".report")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwn-report",
        description="Build a private, evidence-linked report from a pwn-broker archive.",
    )
    parser.add_argument("--version", action="version", version=f"pwn-report {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="build")
    build = commands.add_parser(
        "build",
        help="build a report folder from one finished or exported archive",
        description="Build a report folder from one finished or exported pwn-broker archive. "
        "An existing folder is never replaced.",
    )
    build.add_argument("archive", type=Path, help="a <box>.finished.tar.gz or <box>.exported.tar.gz")
    build.add_argument(
        "-o", "--output", type=Path, help="the report folder to create (default: beside the archive, NAME.report)"
    )
    build.add_argument("--select", type=Path, metavar="FILE", help="a selection file: captions and evidence to include")
    return parser


def _fail(message: str) -> int:
    print(f"fail  {message}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    archive: Path = args.archive
    if not archive.is_file():
        return _fail(f"no archive at {archive}")
    if args.select is not None and not args.select.is_file():
        return _fail(f"no selection file at {args.select}")
    output = args.output if args.output is not None else default_output(archive)
    try:
        build_report(archive, output, args.select)
    except KeyboardInterrupt:
        # build_report removes its staging folder on the way out, so nothing is left behind
        print("fail  interrupted; no report was written", file=sys.stderr)
        return 130
    except (ReportError, OSError) as exc:
        return _fail(str(exc))
    print(f"ok    report {output}")
    return 0

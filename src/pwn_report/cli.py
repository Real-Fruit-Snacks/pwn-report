"""The pwn-report command.

Success prints one line to stdout, `ok    report <folder>`, and exits 0. Any failure prints one
line to stderr, `fail  <reason>`, and exits 1; a usage error exits 2. pwn-broker runs this
command at finish and relies on exactly these lines and statuses.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
from pathlib import Path

from . import __version__
from .output import Interrupted, build_report
from .report import ReportError, shown

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


def _say(text: str, stream) -> None:
    """One line, whatever the stream's encoding: a character it cannot hold is escaped, so a
    report already written is never reported as a failure because its path cannot be printed.
    A control or format character, which only a crafted name can bring, is shown as ?: a line
    break would split the line in two and an escape sequence would reach the terminal."""
    text = shown(text)
    try:
        print(text, file=stream)
    except UnicodeEncodeError:
        encoding = getattr(stream, "encoding", None) or "ascii"
        print(text.encode(encoding, "backslashreplace").decode(encoding), file=stream)


def _fail(message: str) -> int:
    _say(f"fail  {message}", sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    archive: Path = args.archive
    if not archive.is_file():
        return _fail(f"no archive at {archive}")
    if args.select is not None and not args.select.is_file():
        return _fail(f"no selection file at {args.select}")
    output = args.output if args.output is not None else default_output(archive)
    # build_report never replaces a folder: if none is here now and a report is after a stop, it
    # was renamed into place whole
    existed = os.path.lexists(output)
    previous: dict = {}
    try:
        try:
            # inside the try: a stop that lands while they are set is one line too
            _stop_on_signals(previous)
            build_report(archive, output, args.select)
        finally:
            # before any line is printed: a stop from here on meets the caller's own handler, not
            # one that raises out of main with a traceback
            _put_back(previous)
    except KeyboardInterrupt as exc:
        # a stop the build handled wrote no report of its own; only one that landed outside it,
        # as build_report returned, can find this build's report in place
        left = getattr(exc, "left", None)
        if isinstance(exc, Interrupted) or existed or not _is_report(output):
            # build_report removes its staging folder on the way out; one it could not remove is named
            if left is not None:
                _say(f"fail  interrupted; a partial copy was left at {left}: delete it, it holds copied evidence", sys.stderr)
            else:
                _say("fail  interrupted; no report was written", sys.stderr)
            return 130
        # the stop landed once the report was in place: it is whole, and reported as written
    except (ReportError, OSError) as exc:
        return _fail(str(exc))
    except Exception as exc:
        # a bug must still end in one line, not a traceback, for whoever runs this command
        return _fail(f"unexpected error: {type(exc).__name__}: {exc}")
    _say(f"ok    report {output}", sys.stdout)
    return 0


def _is_report(output: Path) -> bool:
    """A report folder renamed into place: one with the files only a whole report has."""
    return output.is_dir() and (output / "SHA256SUMS").is_file() and (output / "report.toml").is_file()


def _stop_on_signals(previous: dict) -> None:
    """Ctrl-C (SIGINT), SIGTERM (pwn-broker's timeout, a kill) and SIGHUP (a closed terminal or SSH
    session) end the build with KeyboardInterrupt, so its staging folder is removed; by default
    SIGTERM and SIGHUP end it on the spot. The first stop wins and the rest are ignored from then
    on, so a second cannot cut the removal short. A signal the caller ignores, as nohup ignores
    SIGHUP, stays ignored, and one whose handler Python cannot put back is left alone. Each
    handler replaced is recorded in previous, to be put back."""

    def stop(signum, frame) -> None:
        # only the handlers still this one: one already put back is the caller's again
        for number in previous:
            if signal.getsignal(number) is stop:
                signal.signal(number, signal.SIG_IGN)
        raise KeyboardInterrupt

    for name in ("SIGINT", "SIGTERM", "SIGHUP"):
        number = getattr(signal, name, None)
        if number is None:
            continue
        try:
            current = signal.getsignal(number)
            if current is None or current == signal.SIG_IGN:
                continue
            previous[number] = signal.signal(number, stop)
        except (ValueError, OSError):
            # not the main thread, as when a program imports and calls main: leave its handlers
            pass


def _put_back(previous: dict) -> None:
    """Put the caller's handlers back. A stop that lands meanwhile is let go, each handler is tried
    up to three times, and the rest are put back all the same: the build is over, so it has
    nothing left to stop, and the line about the build, the one naming a staging copy left behind
    included, still has to be printed."""
    for number, handler in previous.items():
        for _attempt in range(3):
            try:
                signal.signal(number, handler)
                break
            except KeyboardInterrupt:
                continue

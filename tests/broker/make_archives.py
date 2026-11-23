"""Make finished and exported archives with pwn-broker's own code, for test_broker_compat.py.

Usage: make_archives.py <out-dir>, with PWN_REPORT_BROKER_SRC naming a pwn-broker checkout. Prints
one line per archive: `<name> <path>`. Everything happens inside <out-dir>: the install folder, the
home with its boxes, and the archives. Nothing is pinged, no /etc/hosts is touched, no note window
opens, and no network is used.

The boxes are made the way the prompt makes them: create_box and add_target, the box's own note,
`flag user`, `flag root` and `cred add` through pwn-broker's command dispatcher, files written into
the folders where tools and the user put them, then export_box and finish_box.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(os.environ["PWN_REPORT_BROKER_SRC"]) / "src"))

import pwn_broker.shell  # noqa: E402,F401  (importing it fills the command registry)
from pwn_broker import boxes, lifecycle, session as sessions, setup  # noqa: E402
from pwn_broker.config import Settings  # noqa: E402
from pwn_broker.console import FakeConsole  # noqa: E402
from pwn_broker.paths import AppPaths  # noqa: E402
from pwn_broker.shell.commands import dispatch  # noqa: E402

# the night the clocks go back: US Eastern time is -04:00 until 06:00 UTC on 2026-11-01 and -05:00
# after, so a box worked across it records times in both offsets, as a real one can
STARTED = datetime(2026, 11, 1, 0, 30, tzinfo=timezone(timedelta(hours=-4)))
CLOCKS_GO_BACK = datetime(2026, 11, 1, 6, 0, tzinfo=timezone.utc)
SUMMER, WINTER = timezone(timedelta(hours=-4)), timezone(timedelta(hours=-5))

# what a report must never contain: the contents of held-back files
CANARIES = {
    "cred": "CRED-SECRET-CANARY",
    "creds_folder": "CREDS-FOLDER-CANARY",
    "tooldata": "TOOLDATA-CANARY",
}


def _clock(start: datetime):
    """25 minutes a call, each moment in the offset the wall clock showed then."""
    instants = iter(start + timedelta(minutes=25 * n) for n in range(10_000))

    def now() -> datetime:
        instant = next(instants)
        return instant.astimezone(SUMMER if instant < CLOCKS_GO_BACK else WINTER)

    return now


def _session(paths: AppPaths, box, clock):
    session = sessions.load_session(paths, Settings(), FakeConsole(), box, clock)
    return session


def _run(session, line: str, *answers: str) -> None:
    session.console = FakeConsole(list(answers))
    dispatch(session, line)
    failed = [text for kind, text in session.console.lines if kind == "fail"]
    if failed:
        raise SystemExit(f"{line}: {failed}")


def _write(box, relative: str, data: bytes) -> None:
    path = box.path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _export(session) -> Path:
    archive = lifecycle.export_box(session, fix=lambda folder: 0)
    if archive is None:
        raise SystemExit(f"export failed: {session.console.lines}")
    return archive


def _finish(session) -> Path:
    # finish this box? yes; remove working folder? no
    session.console = FakeConsole(["y", "n"])
    archive = lifecycle.finish_box(
        session, unsaved=lambda box: False, close=lambda paths, box: False, fix=lambda folder: 0
    )
    if archive is None:
        raise SystemExit(f"finish failed: {session.console.lines}")
    return archive


def empty_box(paths: AppPaths) -> Path:
    """No targets, nothing typed at os and difficulty: pwn-broker stores both as ""."""
    clock = _clock(STARTED)
    box = boxes.create_box(
        paths, name="lame", platform="htb", day=STARTED.date(), os_name="", difficulty="", now=clock()
    )
    sessions.write_new_note(paths, box, [])
    return _finish(_session(paths, box, clock))


def full_box(paths: AppPaths) -> tuple[Path, Path]:
    clock = _clock(STARTED)
    box = boxes.create_box(
        paths, name="forest", platform="htb", day=STARTED.date(), os_name="windows", difficulty="easy", now=clock()
    )
    target = boxes.add_target(
        box, [], ips=["10.10.10.161"], hostnames=["forest.htb.local"], scope="external", name="dc01", now=clock()
    )
    sessions.write_new_note(paths, box, [target])
    session = _session(paths, box, clock)
    for relative, data in {
        "targets/dc01/scans/nmap-quick.txt": b"PORT    STATE SERVICE\n88/tcp  open  kerberos-sec\n",
        "targets/dc01/screenshots/bloodhound.png": b"\x89PNG\r\n\x1a\nSCREENSHOT",
        "targets/dc01/exploits/exploit.py": b'raise RuntimeError("ARCHIVE_CODE_EXECUTED")\n',
        "targets/dc01/loot/ntds.dit": b"LOOT-CONTENT",
        "targets/dc01/recordings/2026-11-01_0100.cast": b'{"version": 2}\n',
        "targets/dc01/files/users.txt": b"svc-alfresco\n",
        "targets/dc01/upload/winPEASx64.exe": b"MZ",
        "targets/dc01/creds/administrator.ccache": CANARIES["creds_folder"].encode(),
        "screenshots/root.png": b"\x89PNG\r\n\x1a\nROOT",
        "tooldata/netexec/nxc.db": CANARIES["tooldata"].encode(),
    }.items():
        _write(box, relative, data)
    _run(session, "flag user", "USER-FLAG-VALUE")
    _run(session, "cred add", "svc-alfresco", "htb.local", CANARIES["cred"], "", "", "")
    _run(session, "flag root", "ROOT-FLAG-VALUE")
    exported = _export(session)
    finished = _finish(session)
    return exported, finished


def main(argv: list[str]) -> int:
    out = Path(argv[1]).resolve()
    paths = AppPaths(opt=out / "opt", home=out / "home")
    setup.install_data(paths)
    print(f"empty {empty_box(paths)}")
    exported, finished = full_box(paths)
    print(f"exported {exported}")
    print(f"finished {finished}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

"""The pwn-report command: one plain line on success or failure, and the exit status that says which.

pwn-broker runs this command at finish and reads exactly these lines and statuses."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from fixtures import make_archive
from pwn_report import __version__, cli

ROOT = Path(__file__).resolve().parent.parent


def test_default_output_is_beside_the_archive():
    assert cli.default_output(Path("w/2026-11-14_htb_forest.finished.tar.gz")) == Path(
        "w/2026-11-14_htb_forest.finished.report"
    )
    assert cli.default_output(Path("w/x.tgz")) == Path("w/x.tgz.report")


def test_build_prints_one_ok_line(tmp_path, capsys):
    fixture = make_archive(tmp_path / "2026-11-14_htb_forest.exported.tar.gz", full=True)
    assert cli.main(["build", str(fixture.path)]) == 0
    out, err = capsys.readouterr()
    expected = tmp_path / "2026-11-14_htb_forest.exported.report"
    assert out == f"ok    report {expected}\n" and err == ""
    assert (expected / "report.md").is_file()


def test_build_with_output_and_select(tmp_path, capsys):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    selection = tmp_path / "pick.toml"
    selection.write_text("schema = 1\n[[rule]]\npath = 'targets/dc01/loot/SAM.bak'\ninclude = true\n", encoding="utf-8")
    out_dir = tmp_path / "mine"
    assert cli.main(["build", str(fixture.path), "-o", str(out_dir), "--select", str(selection)]) == 0
    assert capsys.readouterr().out == f"ok    report {out_dir}\n"
    assert (out_dir / "evidence" / "targets" / "dc01" / "loot" / "SAM.bak").is_file()


def _corrupt(tmp_path):
    path = tmp_path / "corrupt.tar.gz"
    path.write_bytes(b"this is not a gzip stream")
    return path


@pytest.mark.parametrize(
    "case, expect",
    [
        ("missing archive", "no archive at "),
        ("existing output", "output already exists and will not be replaced"),
        ("missing output parent", "output parent is not an existing directory"),
        ("corrupt archive", "cannot build report model"),
        ("missing selection", "no selection file at "),
    ],
)
def test_a_failure_is_one_fail_line(tmp_path, capsys, case, expect):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    args = ["build", str(fixture.path)]
    if case == "missing archive":
        args = ["build", str(tmp_path / "nope.tar.gz")]
    elif case == "existing output":
        (tmp_path / "a.report").mkdir()
    elif case == "missing output parent":
        args += ["-o", str(tmp_path / "no" / "such" / "out")]
    elif case == "corrupt archive":
        args = ["build", str(_corrupt(tmp_path))]
    elif case == "missing selection":
        args += ["--select", str(tmp_path / "nope.toml")]
    assert cli.main(args) == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert err.count("\n") == 1 and err.startswith("fail  ") and expect in err, err
    assert "Traceback" not in err


def test_an_interrupt_is_one_line_and_leaves_nothing(tmp_path, capsys, monkeypatch):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "build_report", interrupted)
    assert cli.main(["build", str(fixture.path)]) == 130
    assert capsys.readouterr().err == "fail  interrupted; no report was written\n"
    assert not (tmp_path / "a.report").exists()


def test_version(capsys):
    with pytest.raises(SystemExit) as stopped:
        cli.main(["--version"])
    assert stopped.value.code == 0
    assert capsys.readouterr().out == f"pwn-report {__version__}\n"


@pytest.mark.parametrize("args", [[], ["build"], ["nonsense"]])
def test_usage_error_exits_2(args):
    with pytest.raises(SystemExit) as stopped:
        cli.main(args)
    assert stopped.value.code == 2


def test_python_dash_m():
    import pwn_report

    # the pwn_report these tests import: src/ in a checkout, the installed wheel in a release's run
    env = {**os.environ, "PYTHONPATH": str(Path(pwn_report.__file__).resolve().parents[1])}
    done = subprocess.run(
        [sys.executable, "-m", "pwn_report", "--version"], capture_output=True, text=True, env=env, timeout=60
    )
    assert done.returncode == 0 and done.stdout == f"pwn-report {__version__}\n"

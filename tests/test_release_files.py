"""release/check_wheel.py: a release publishes a pure wheel holding the package and nothing else."""

from __future__ import annotations

import importlib.util
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("check_wheel", ROOT / "release" / "check_wheel.py")
check_wheel = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_wheel)

VERSION = "0.1.0"


def _wheel(tmp_path, *, name=f"pwn_report-{VERSION}-py3-none-any.whl", extra=None, tag="py3-none-any",
           version=VERSION, entry="pwn-report = pwn_report.cli:main", drop=(), requires=""):  # fmt: skip
    info = f"pwn_report-{VERSION}.dist-info"
    files = {
        "pwn_report/__init__.py": f'__version__ = "{version}"\n',
        "pwn_report/__main__.py": "",
        "pwn_report/cli.py": "def main(argv=None):\n    return 0\n",
        "pwn_report/output.py": "",
        "pwn_report/report.py": "",
        "pwn_report/validate.py": "",
        f"{info}/METADATA": f"Metadata-Version: 2.4\nName: pwn-report\nVersion: {version}\n{requires}",
        f"{info}/WHEEL": f"Wheel-Version: 1.0\nGenerator: hatchling 1.33.0\nRoot-Is-Purelib: true\nTag: {tag}\n",
        f"{info}/entry_points.txt": f"[console_scripts]\n{entry}\n",
        f"{info}/licenses/LICENSE": "MIT License\n",
        f"{info}/RECORD": "",
    }
    for key in drop:
        files.pop(key)
    files.update(extra or {})
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as archive:
        for member, data in files.items():
            archive.writestr(member, data)
    return path


def test_check_wheel_accepts_a_pure_wheel_of_the_package(tmp_path):
    assert check_wheel.problems(_wheel(tmp_path), VERSION) == []


@pytest.mark.parametrize(
    "change, expect",
    [
        ({"extra": {"evil.py": "print(1)\n"}}, "evil.py"),
        ({"extra": {"pwn_report/_speedups.cpython-313-x86_64-linux-gnu.so": "ELF"}}, "_speedups"),
        ({"extra": {"pwn_report/__pycache__/cli.cpython-313.pyc": "x"}}, ".pyc"),
        ({"tag": "cp313-cp313-linux_x86_64"}, "Tag"),
        ({"name": f"pwn_report-{VERSION}-cp313-cp313-linux_x86_64.whl"}, "file name"),
        ({"version": "0.2.0"}, "0.2.0"),
        ({"entry": "pwn-report = pwn_report.other:main"}, "entry point"),
        ({"drop": ["pwn_report/cli.py"]}, "pwn_report/cli.py"),
        ({"requires": "Requires-Dist: requests>=2\n"}, "Requires-Dist"),
    ],
    ids=[
        "extra-module", "compiled", "bytecode", "platform-tag", "file-name", "version", "entry-point",
        "missing-module", "a-dependency",
    ],
)
def test_check_wheel_refuses_anything_else(tmp_path, change, expect):
    found = check_wheel.problems(_wheel(tmp_path, **change), VERSION)
    assert found and any(expect in problem for problem in found), found


def test_check_wheel_prints_one_line_and_exits_with_the_result(tmp_path, capsys):
    assert check_wheel.main([str(_wheel(tmp_path)), VERSION]) == 0
    assert capsys.readouterr().out == f"ok    pwn_report-{VERSION}-py3-none-any.whl is a pure wheel of pwn_report {VERSION}\n"
    (tmp_path / "bad").mkdir()
    bad = _wheel(tmp_path / "bad", extra={"evil.py": ""})
    assert check_wheel.main([str(bad), VERSION]) == 1
    assert capsys.readouterr().out.startswith("fail  ")


def test_check_wheel_refuses_a_member_named_twice(tmp_path):
    import warnings

    path = _wheel(tmp_path)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # zipfile warns about the duplicate it is asked to write
        with zipfile.ZipFile(path, "a") as archive:
            archive.writestr("pwn_report/cli.py", "def main(argv=None):\n    return 1\n")
    found = check_wheel.problems(path, VERSION)
    assert any("more than once" in problem for problem in found), found


def test_check_wheel_accepts_a_dependency_only_an_extra_brings(tmp_path):
    path = _wheel(tmp_path, requires="Requires-Dist: pytest>=8; extra == 'dev'\n")
    assert check_wheel.problems(path, VERSION) == []


def test_check_wheel_reads_metadata_headers_not_the_readme_after_them(tmp_path):
    readme = "Description-Content-Type: text/markdown\n\n# pwn-report\n\nRequires-Dist: prose in the README\n"
    assert check_wheel.problems(_wheel(tmp_path, requires=readme), VERSION) == []
    (tmp_path / "other").mkdir()
    wrong = _wheel(tmp_path / "other", version="9.9.9", requires="\nVersion: 0.1.0\n")
    found = check_wheel.problems(wrong, VERSION)
    assert any("Version: 9.9.9" in problem for problem in found), found

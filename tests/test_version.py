"""The package has one version, and everything that reports one reads it."""

import tomllib
from pathlib import Path

import pwn_report
from pwn_report import output

ROOT = Path(__file__).resolve().parent.parent


def test_one_version_everywhere():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "version" not in data["project"] and "version" in data["project"]["dynamic"]
    assert data["tool"]["hatch"]["version"]["path"] == "src/pwn_report/__init__.py"
    assert pwn_report.__version__ == "0.1.0"
    assert output.GENERATOR_VERSION == pwn_report.__version__

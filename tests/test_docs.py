"""The documents say what the code does: links resolve, the privacy line is the report's own,
the command line is the command's, and the install lines name the current version."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from pwn_report import __version__, cli
from pwn_report.output import PRIVACY_NOTE

ROOT = Path(__file__).resolve().parent.parent
DOCS = [ROOT / "README.md", ROOT / "CHANGELOG.md", ROOT / "SECURITY.md", ROOT / "CONTRIBUTING.md",
        *sorted((ROOT / "docs").glob("*.md"))]  # fmt: skip
# a Markdown link or image to a relative target, not inside a code block
_LINK = re.compile(r"\]\((?!https?://|mailto:|#)([^)\s]+)\)")


def _prose(text: str) -> str:
    return re.sub(r"```.*?```", "", text, flags=re.S)


@pytest.mark.parametrize("doc", DOCS, ids=[doc.relative_to(ROOT).as_posix() for doc in DOCS])
def test_every_relative_link_resolves(doc):
    for target in _LINK.findall(_prose(doc.read_text(encoding="utf-8"))):
        path = (doc.parent / target.split("#", 1)[0]).resolve()
        assert path.exists(), f"{doc.name} links to {target}, which does not exist"


def test_the_readme_quotes_the_reports_privacy_line():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert PRIVACY_NOTE in readme


def test_the_command_line_in_the_docs_is_the_commands():
    usage = "pwn-report build <archive> [-o <folder>] [--select <file>]"
    for doc in (ROOT / "README.md", ROOT / "docs" / "guide.md"):
        assert usage in doc.read_text(encoding="utf-8"), doc.name
    build = cli._parser()._subparsers._group_actions[0].choices["build"]
    options = {option for action in build._actions for option in action.option_strings}
    assert {"-o", "--output", "--select"} <= options


def test_the_install_lines_name_this_version():
    for doc in (ROOT / "README.md", ROOT / "docs" / "guide.md"):
        text = doc.read_text(encoding="utf-8")
        named = set(re.findall(r"releases/download/v([0-9.]+)/", text)) | set(re.findall(r"pwn_report-([0-9.]+)-py3", text))
        assert named == {__version__}, (doc.name, named)


def test_the_changelog_has_this_version():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert re.search(rf"^## v{re.escape(__version__)}( \(unreleased\))?$", text, re.M)

"""The project page shows what the code does: its session and its report.md lines are the ones
docs/art/make-panel.py takes from a real build, its privacy line is the report's own, its install
lines name this version, and it links the other three pwn pages."""

from __future__ import annotations

import html
import importlib.util
import re
from pathlib import Path

import pytest

from pwn_report import __version__
from pwn_report.output import PRIVACY_NOTE

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
PAGE = (DOCS / "index.html").read_text(encoding="utf-8")

_spec = importlib.util.spec_from_file_location("make_panel", DOCS / "art" / "make-panel.py")
make_panel = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(make_panel)


@pytest.fixture(scope="module")
def run():
    return make_panel.real_run()


def _block(cls: str) -> str:
    (found,) = re.findall(rf'<pre class="{cls}"[^>]*><code>(.*?)</code></pre>', PAGE, re.S)
    return found


def _text(fragment: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", fragment))


def test_the_session_is_the_real_run(run):
    lines = re.findall(r'<span class="ln( [a-z ]+)?"[^>]*>(.*?)</span>\n', _block("screen") + "\n", re.S)
    shown = [_text(body) for kind, body in lines if "end" not in kind]
    assert shown == make_panel.transcript(run)


def test_each_checklist_step_is_ticked_by_the_line_that_proves_it(run):
    steps = dict(re.findall(r'<span class="ln[^"]*" data-step="(\d)">(.*?)</span>', _block("screen")))
    assert {step: _text(body) for step, body in steps.items()} == {
        "2": run["ok"], "3": run["fail"], "4": run["held"][-1],
    }
    assert re.findall(r'<li data-step="(\d)"', PAGE) == ["2", "3", "4"]


def test_the_report_md_lines_are_the_real_reports_in_order(run):
    lines = _block("md-buf").split("\n")
    shown = [_text(line) for line in lines if 'class="eob"' not in line]
    report = iter(run["markdown"].splitlines())
    for line in shown:
        assert any(line == candidate for candidate in report), f"{line!r} is not in report.md, in this order"
    assert sum('class="eob"' in line for line in lines) >= 1


def test_the_page_says_the_reports_privacy_line():
    prose = " ".join(_text(PAGE.replace(_block("md-buf"), "")).split())
    assert PRIVACY_NOTE.replace("`", "") in prose
    assert PRIVACY_NOTE in _text(_block("md-buf"))


def test_the_install_lines_name_this_version():
    named = set(re.findall(r"releases/download/v([0-9.]+)/", PAGE)) | set(re.findall(r"pwn_report-([0-9.]+)-py3", PAGE))
    assert named == {__version__}
    assert f"pwn-report {__version__}" in PAGE


def test_the_tabs_link_the_four_pages():
    (nav,) = re.findall(r'<ul class="tabs">(.*?)</ul>', PAGE, re.S)
    tabs = re.findall(r'<a class="t-([a-z]+)" href="([^"]+)"( aria-current="page")?>([A-Za-z]+)<small>', nav)
    base = "https://real-fruit-snacks.github.io/"
    assert tabs == [
        ("broker", base + "pwn-broker/", "", "Broker"),
        ("shop", base + "pwn-shop/", "", "Shop"),
        ("books", base + "pwn-playbooks/", "", "Playbooks"),
        ("report", "./", ' aria-current="page"', "Report"),
    ]
    assert f'<link rel="canonical" href="{base}pwn-report/">' in PAGE


def test_every_file_the_page_and_its_sheet_use_is_there():
    used = re.findall(r'(?:href|src)="(?!https?:|#|\./|mailto:)([^"]+)"', PAGE)
    used += re.findall(r"url\(([^)]+)\)", (DOCS / "styles.css").read_text(encoding="utf-8"))
    assert used
    for name in used:
        assert (DOCS / name).is_file(), name


def test_the_readme_panel_is_there():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    panels = re.findall(r'(?:srcset|src)="(docs/assets/panel-[a-z]+\.svg)"', readme)
    assert sorted(panels) == ["docs/assets/panel-dark.svg", "docs/assets/panel-light.svg"]
    for name in panels:
        assert (ROOT / name).is_file(), name

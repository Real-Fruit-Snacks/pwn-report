"""docs/art/make-panel.py: the same bytes on every run, the committed SVG files are its output, and
its check mode fails when they are not."""

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("fontTools") is None or importlib.util.find_spec("brotli") is None,
    reason="needs docs/art/requirements.txt (fonttools and brotli)",
)

PANELS = ("panel-dark.svg", "panel-light.svg")


def run(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(root / "docs" / "art" / "make-panel.py"), *args],
        cwd=root, capture_output=True, text=True, timeout=300,
    )  # fmt: skip


def draw(root: Path) -> dict[str, bytes]:
    done = run(root)
    assert done.returncode == 0, done.stdout + done.stderr
    return {name: (root / "docs" / "assets" / name).read_bytes() for name in PANELS}


@pytest.fixture
def copy(tmp_path):
    """The script, its fonts, this checkout's pwn-report and the suite's archive builder, in a
    folder of their own."""
    for part in ("docs/art", "docs/fonts", "src/pwn_report"):
        shutil.copytree(ROOT / part, tmp_path / part, ignore=shutil.ignore_patterns("__pycache__"))
    (tmp_path / "tests").mkdir()
    shutil.copy(ROOT / "tests" / "fixtures.py", tmp_path / "tests" / "fixtures.py")
    (tmp_path / "docs" / "assets").mkdir()
    return tmp_path


def test_the_script_writes_the_same_bytes_twice(copy):
    assert draw(copy) == draw(copy)


def test_the_committed_panels_are_what_the_script_writes(copy):
    drawn = draw(copy)
    for name in PANELS:
        assert drawn[name] == (ROOT / "docs" / "assets" / name).read_bytes(), name


def test_the_check_passes_on_fresh_panels_and_fails_on_stale_ones(copy):
    draw(copy)
    assert run(copy, "--check").returncode == 0
    stale = copy / "docs" / "assets" / "panel-light.svg"
    stale.write_bytes(stale.read_bytes().replace(b'role="img"', b'role="image"', 1))
    done = run(copy, "--check")
    assert done.returncode == 1
    assert done.stderr == "fail  docs/assets/panel-light.svg is out of date: run python docs/art/make-panel.py\n"
    assert b'role="image"' in stale.read_bytes(), "the check must not rewrite the panel"
    stale.unlink()
    assert run(copy, "--check").returncode == 1

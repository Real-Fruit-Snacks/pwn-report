"""The workflows' own checks, run as GitHub runs a step: its script in bash with pipefail."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
# on Windows, bash on the PATH may be WSL's, which cannot read these paths; the steps run on Linux
BASH = None if os.name == "nt" else shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None, reason="the workflows' steps run in bash on Linux and macOS")


def _step(workflow: str, name: str) -> str:
    """The `run: |` script of the step with this name, as the runner gets it."""
    lines = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8").splitlines()
    start = next(index for index, line in enumerate(lines) if line.strip() == f"- name: {name}")
    run = next(index for index in range(start + 1, len(lines)) if lines[index].strip() == "run: |")
    indent = None
    body = []
    for line in lines[run + 1 :]:
        if line.strip():
            depth = len(line) - len(line.lstrip())
            if indent is None:
                indent = depth
            if depth < indent:
                break
        body.append(line[indent:] if line.strip() else "")
    return "\n".join(body) + "\n"


def _run(tmp_path: Path, script: str, env: dict[str, str]) -> subprocess.CompletedProcess:
    path = tmp_path / "step.sh"
    path.write_text(script, encoding="utf-8")
    runner = tmp_path / "runner"
    runner.mkdir(exist_ok=True)
    return subprocess.run(
        [BASH, "--noprofile", "--norc", "-eo", "pipefail", str(path)],
        cwd=tmp_path,
        env={**os.environ, "RUNNER_TEMP": str(runner), **env},
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(
    "heading, event, ref_type, publishes",
    [
        ("## v0.1.0 (unreleased)", "push", "tag", False),
        ("## v0.1.0", "push", "tag", True),
        ("## v0.1.0 (unreleased)", "workflow_dispatch", "branch", True),
        ("## v0.1.0 (unreleased)\n\nNotes.\n\n## v0a1b0", "push", "tag", False),
    ],
    ids=["tag-unreleased", "tag-released", "dry-run-unreleased", "tag-heading-as-a-pattern"],
)
def test_a_tag_is_refused_while_the_changelog_says_unreleased(tmp_path, heading, event, ref_type, publishes):
    (tmp_path / "CHANGELOG.md").write_text(f"# Changelog\n\n{heading}\n\nThe first release.\n", encoding="utf-8")
    result = _run(
        tmp_path,
        _step("release.yml", "Notes from CHANGELOG.md"),
        {"VERSION": "0.1.0", "GITHUB_EVENT_NAME": event, "GITHUB_REF_TYPE": ref_type},
    )
    assert (result.returncode == 0) is publishes, result.stdout + result.stderr


@pytest.mark.parametrize(
    "summary, passes",
    [("3 passed in 0.50s", True), ("1 passed, 2 skipped in 0.50s", False)],
    ids=["ran", "skipped"],
)
def test_the_panel_job_fails_when_its_tests_skip(tmp_path, summary, passes):
    # python stands in for pip and pytest: the job's own lines decide what a skip does
    stand_in = f'python() {{ if [ "$2" = pytest ]; then echo "{summary}"; fi; }}\n'
    result = _run(tmp_path, stand_in + _step("ci.yml", "The panel's tests"), {})
    assert (result.returncode == 0) is passes, result.stdout + result.stderr

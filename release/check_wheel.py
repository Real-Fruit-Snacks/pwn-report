"""Check that a built wheel is the one a release may publish: pure Python, pwn_report only.

Usage: python release/check_wheel.py <wheel> <version>. Prints one line, `ok    ...` or
`fail  ...` with every problem found, and exits 0 or 1. Standard library only.
"""

from __future__ import annotations

import re
import sys
import zipfile
from pathlib import Path

PACKAGE = "pwn_report"
ENTRY_POINT = "pwn-report = pwn_report.cli:main"
# the modules the wheel must hold; anything else under pwn_report/ is a surprise too
MODULES = ("__init__.py", "__main__.py", "cli.py", "output.py", "report.py", "validate.py")


def problems(wheel: Path, version: str) -> list[str]:
    found = []
    expected_name = f"{PACKAGE}-{version}-py3-none-any.whl"
    if wheel.name != expected_name:
        found.append(f"the file name is {wheel.name}, not {expected_name}")
    info = f"{PACKAGE}-{version}.dist-info"
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        for name in sorted({name for name in names if names.count(name) > 1}):
            found.append(f"{name} is in the wheel more than once")
        for name in names:
            top = name.split("/", 1)[0]
            if top not in {PACKAGE, info}:
                found.append(f"{name} is outside {PACKAGE}/ and {info}/")
            elif name.endswith((".pyc", ".pyo")) or "/__pycache__/" in f"/{name}":
                found.append(f"{name} is compiled bytecode (.pyc)")
            elif top == PACKAGE and not re.fullmatch(rf"{PACKAGE}/[a-z_]+\.py", name):
                found.append(f"{name} is not a plain Python module")
        for module in MODULES:
            if f"{PACKAGE}/{module}" not in names:
                found.append(f"{PACKAGE}/{module} is missing")
        extra = sorted({name for name in names if name.startswith(f"{PACKAGE}/")} - {f"{PACKAGE}/{m}" for m in MODULES})
        for name in extra:
            if not any(name in problem for problem in found):
                found.append(f"{name} is not one of the package's modules")

        def text(member: str) -> str:
            try:
                return archive.read(f"{info}/{member}").decode("utf-8")
            except KeyError:
                found.append(f"{info}/{member} is missing")
                return ""

        wheel_file = text("WHEEL").splitlines()
        tags = [line.split(":", 1)[1].strip() for line in wheel_file if line.startswith("Tag:")]
        if tags != ["py3-none-any"]:
            found.append(f"WHEEL's Tag is {tags}, not ['py3-none-any']")
        if "Root-Is-Purelib: true" not in wheel_file:
            found.append("WHEEL does not say Root-Is-Purelib: true")
        # the headers only: the README follows them, after the first blank line, as the description
        metadata = text("METADATA").split("\n\n", 1)[0].splitlines()
        # standard library only: no dependency every install brings; an extra's (dev) is optional
        for line in metadata:
            if line.startswith("Requires-Dist:") and "extra ==" not in line:
                found.append(f"METADATA names a dependency, {line!r}")
        if f"Version: {version}" not in metadata:
            stated = next((line for line in metadata if line.startswith("Version:")), "no Version line")
            found.append(f"METADATA says {stated}, not Version: {version}")
        if ENTRY_POINT not in text("entry_points.txt").splitlines():
            found.append(f"entry_points.txt has no entry point {ENTRY_POINT!r}")
    return found


def main(argv: list[str]) -> int:
    wheel, version = Path(argv[0]), argv[1]
    found = problems(wheel, version)
    if found:
        print(f"fail  {wheel.name}: " + "; ".join(found))
        return 1
    print(f"ok    {wheel.name} is a pure wheel of {PACKAGE} {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

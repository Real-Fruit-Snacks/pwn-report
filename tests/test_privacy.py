"""Privacy-origin read instrumentation and literal template/Markdown handling."""

from __future__ import annotations

import re
import tarfile
from dataclasses import replace
from pathlib import PurePosixPath
from urllib.parse import unquote

from pwn_report import build_model, build_report

from fixtures import make_archive, manifest_bytes, sha256, write_archive

BOX = "box.toml"
SCAN = "targets/dc01/scans/nmap.txt"
TEMPLATE_SCAN = "targets/dc01/scans/${CANARY}-{{braces}}-[proof].txt"


def _tree_bytes(root):
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_forbidden_unlisted_origins_are_never_opened(tmp_path, monkeypatch):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    destination = tmp_path / "report"
    opened = []
    real_extractfile = tarfile.TarFile.extractfile

    def observed(self, member):
        name = member.name if isinstance(member, tarfile.TarInfo) else str(member)
        opened.append(name)
        return real_extractfile(self, member)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", observed)
    build_report(fixture.path, destination)
    assert opened
    for forbidden in ("creds.toml", "lists/passwords.txt", "unlisted.txt"):
        assert not any(name.endswith("/" + forbidden) for name in opened), forbidden
    files = _tree_bytes(destination)
    assert all(b"CRED-ROOT-CANARY" not in data for data in files.values())
    assert all(b"LIST-CONTENT-CANARY" not in data for data in files.values())
    assert all(b"UNLISTED-CONTENT-CANARY" not in data for data in files.values())


def test_unknown_box_extra_metadata_never_enters_model_or_outputs(tmp_path):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    members = dict(fixture.members)
    members[BOX] += b'\n[extra]\nprivate = "BOX-EXTRA-CANARY"\n'
    records = [
        replace(record, size=len(members[BOX]), sha256=sha256(members[BOX]))
        if record.path == BOX
        else record
        for record in fixture.records
    ]
    members["manifest.toml"] = manifest_bytes(records, kind=fixture.kind)
    archive = write_archive(tmp_path / "extra.tar.gz", members)
    destination = tmp_path / "report"

    model = build_report(archive, destination)
    assert "extra" not in model["box"]
    assert build_model(archive) == model
    for relative, data in _tree_bytes(destination).items():
        assert b"BOX-EXTRA-CANARY" not in data, relative
        assert b'"extra"' not in data, relative


def test_portable_template_filename_and_payloads_stay_literal(tmp_path):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    members = dict(fixture.members)
    members[TEMPLATE_SCAN] = members.pop(SCAN)
    records = [replace(record, path=TEMPLATE_SCAN) if record.path == SCAN else record for record in fixture.records]
    members["manifest.toml"] = manifest_bytes(records, kind=fixture.kind)
    archive = write_archive(tmp_path / "templates.tar.gz", members)
    selection = tmp_path / "selection.toml"
    selection.write_text(
        "schema = 1\n"
        "[[rule]]\n"
        f"path = '{TEMPLATE_SCAN}'\n"
        "caption = '{{7*7}} ${CANARY} {% include \"x\" %} [link](https://example.invalid) <b>bold</b>'\n"
        "alt_text = '**literal** {{7*7}} <img src=x>'\n",
        encoding="utf-8",
    )
    destination = tmp_path / "report"
    model = build_report(archive, destination, selection)
    item = next(item for item in model["evidence"] if item["path"] == TEMPLATE_SCAN)
    assert item["caption"] == '{{7*7}} ${CANARY} {% include "x" %} [link](https://example.invalid) <b>bold</b>'
    output = destination.joinpath(*PurePosixPath(item["output"]["path"]).parts)
    assert output.read_bytes() == fixture.members[SCAN]

    markdown = (destination / "report.md").read_text(encoding="utf-8")
    assert "49" not in item["caption"]
    assert "{% include \"x\" %}" in markdown
    assert "&lt;b&gt;bold&lt;/b&gt;" in markdown
    assert re.search(r"(?<!\\)\]\(https://example\.invalid\)", markdown) is None
    assert "49\n" not in markdown.split("Caption:", 1)[1].splitlines()[0]
    pattern = re.compile(r"(?<!\\)\[[^\]\n]*(?<!\\)\]\(([^)\s]+)\)")
    links = [unquote(match.group(1)) for match in pattern.finditer(markdown)]
    assert item["output"]["path"] in links
    for relative in links:
        assert destination.joinpath(*PurePosixPath(relative).parts).is_file()

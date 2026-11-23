"""H08/H09 selection effects, validation, provenance, and input preservation."""

from __future__ import annotations

import hashlib
from copy import deepcopy

import pytest

from pwn_report import ReportError, build_model

from fixtures import make_archive, sha256

LOOT = "targets/dc01/loot/SAM.bak"
RECORDING = "targets/dc01/recordings/session.cast"
SCAN = "targets/dc01/scans/nmap.txt"
ROOT_SCREENSHOT = "screenshots/root.png"


def _selection(tmp_path, text="schema = 1\n", *, name="selection.toml"):
    path = tmp_path / name
    path.write_bytes(text.encode("utf-8"))
    return path


def _evidence(model, path):
    return next(item for item in model["evidence"] if item["path"] == path)


def test_h08_selection_metadata_reasons_references_and_source_preservation(tmp_path):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    selection = _selection(
        tmp_path,
        """schema = 1

[[rule]]
path = "targets/dc01/loot/SAM.bak"
include = true

[[rule]]
path = "targets/dc01/recordings/session.cast"
include = true

[[rule]]
path = "targets/dc01/scans/nmap.txt"
include = false

[[rule]]
path = "screenshots/root.png"
caption = "Caption {{7*7}} stays **literal**"
alt_text = "Alt text <em>unchanged</em>"
target_refs = ["dc01"]
""",
    )
    archive_before = hashlib.sha256(fixture.path.read_bytes()).hexdigest()
    selection_before = hashlib.sha256(selection.read_bytes()).hexdigest()

    model = build_model(fixture.path, selection)
    by_path = {item["path"]: item for item in model["evidence"]}
    assert by_path[LOOT]["output"] == {
        "copied": True,
        "reason": "selection-include",
        "path": "evidence/" + LOOT,
    }
    assert by_path[RECORDING]["output"] == {
        "copied": True,
        "reason": "selection-include",
        "path": "evidence/" + RECORDING,
    }
    assert by_path[SCAN]["output"] == {"copied": False, "reason": "selection-exclude"}

    root = by_path[ROOT_SCREENSHOT]
    assert root["caption"] == "Caption {{7*7}} stays **literal**"
    assert root["alt_text"] == "Alt text <em>unchanged</em>"
    assert root["target"] == ""
    assert root["target_refs"] == ["dc01"]
    assert root["output"]["reason"] == "default-include"
    assert model["source"]["selection"] == {
        "name": selection.name,
        "sha256": selection_before,
    }
    assert str(tmp_path) not in repr(model["source"])
    assert hashlib.sha256(fixture.path.read_bytes()).hexdigest() == archive_before
    assert hashlib.sha256(selection.read_bytes()).hexdigest() == selection_before


def test_h09_empty_selection_only_adds_provenance(tmp_path):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    selection = _selection(tmp_path)
    without = build_model(fixture.path)
    with_empty = build_model(fixture.path, selection)

    expected = deepcopy(without)
    expected["source"]["selection"] = {
        "name": selection.name,
        "sha256": sha256(selection.read_bytes()),
    }
    assert with_empty == expected
    changed = deepcopy(with_empty)
    del changed["source"]["selection"]
    assert changed == without


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("schema = 2\n", "selection schema"),
        ("schema = true\n", "selection schema"),
        ("", "selection schema"),
        ("= invalid\n", "selection cannot be read"),
        ("schema = 1\nrule = 1\n", "must be a list"),
        ("schema = 1\nrule = [1]\n", "must be a table"),
        ("schema = 1\n[[rule]]\n", "path must be a nonempty string"),
        ("schema = 1\n[[rule]]\npath = 1\n", "path must be a nonempty string"),
        ("schema = 1\n[[rule]]\npath = 'screenshots/root.png'\ninclude = 1\n", "include must be boolean"),
        ("schema = 1\n[[rule]]\npath = 'screenshots/root.png'\ncaption = 1\n", "caption must be a nonempty string"),
        ("schema = 1\n[[rule]]\npath = 'screenshots/root.png'\nalt_text = ''\n", "alt_text must be a nonempty string"),
        ("schema = 1\n[[rule]]\npath = 'screenshots/root.png'\ntarget_refs = 'dc01'\n", "must be a list of strings"),
        ("schema = 1\n[[rule]]\npath = 'screenshots/root.png'\ntarget_refs = ['dc01', 'dc01']\n", "contains duplicates"),
        ("schema = 1\n[[rule]]\npath = 'screenshots/root.png'\ntarget_refs = ['']\n", "must be a nonempty string"),
        ("schema = 1\n[[rule]]\npath = 'screenshots/root.png'\ntarget_refs = ['missing']\n", "unknown targets"),
    ],
)
def test_selection_document_and_rule_types_are_rejected(tmp_path, text, match):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    selection = _selection(tmp_path, text)
    archive_before = fixture.path.read_bytes()
    selection_before = selection.read_bytes()
    with pytest.raises(ReportError, match=match):
        build_model(fixture.path, selection)
    assert fixture.path.read_bytes() == archive_before
    assert selection.read_bytes() == selection_before


@pytest.mark.parametrize(
    "path",
    [
        "/screenshots/root.png",
        "../screenshots/root.png",
        "screenshots/../screenshots/root.png",
        "./screenshots/root.png",
        "screenshots//root.png",
        "screenshots/root.png/",
        r"screenshots\root.png",
        "C:/screenshots/root.png",
        "creds.toml",
        "lists/passwords.txt",
        "unlisted.txt",
        "notes.md",
        "targets/dc01/files/private.txt",
        "upload/root.txt",
        "targets/dc01/scans/missing.txt",
        "targets/missing/scans/nmap.txt",
    ],
)
def test_selection_rejects_nonportable_unknown_and_forbidden_paths(tmp_path, path):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    escaped = path.replace("'", "''")
    selection = _selection(tmp_path, f"schema = 1\n[[rule]]\npath = '{escaped}'\ninclude = true\n")
    with pytest.raises(ReportError):
        build_model(fixture.path, selection)


def test_duplicate_selection_path_is_rejected(tmp_path):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    selection = _selection(
        tmp_path,
        "schema = 1\n"
        "[[rule]]\npath = 'screenshots/root.png'\ninclude = true\n"
        "[[rule]]\npath = 'screenshots/root.png'\ninclude = false\n",
    )
    with pytest.raises(ReportError, match="more than once"):
        build_model(fixture.path, selection)


@pytest.mark.parametrize(
    ("location", "field"),
    [
        ("top", "findings"),
        ("top", "public"),
        ("rule", "severity"),
        ("rule", "review"),
        ("rule", "narrative"),
        ("rule", "template"),
        ("rule", "finding_refs"),
        ("rule", "target"),
    ],
)
def test_selection_rejects_deferred_or_fact_overriding_fields(tmp_path, location, field):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    value = "[]" if field in {"findings", "finding_refs"} else "true" if field == "public" else "'literal'"
    if location == "top":
        text = f"schema = 1\n{field} = {value}\n"
    else:
        text = f"schema = 1\n[[rule]]\npath = 'screenshots/root.png'\n{field} = {value}\n"
    selection = _selection(tmp_path, text)
    with pytest.raises(ReportError, match="unsupported"):
        build_model(fixture.path, selection)


def test_unknown_evidence_fails_before_archived_content_hashing(tmp_path, monkeypatch):
    fixture = make_archive(tmp_path / "source" / "forest.tar.gz", full=True)
    selection = _selection(tmp_path, "schema = 1\n[[rule]]\npath = 'creds.toml'\n")

    def unexpected_hash(*args):
        raise AssertionError("archived content was hashed before selection validation")

    monkeypatch.setattr("pwn_report.report._member_sha", unexpected_hash)
    with pytest.raises(ReportError, match="unknown, unlisted, or unsupported"):
        build_model(fixture.path, selection)

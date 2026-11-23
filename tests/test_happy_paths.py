"""H01/H02 golden-fixture tests; production CLI integration is intentionally later."""

from __future__ import annotations

import hashlib
import json
import tarfile
import tomllib

from pwn_report import build_model

from fixtures import (
    BOX_ID,
    CREDS_CANARY,
    FIRST_SEEN,
    LATER,
    LISTS_CANARY,
    NOW,
    PACKED,
    UNLISTED_CANARY,
    canonical_json,
    make_archive,
    sha256,
)


def _source(fixture, path):
    return {"path": path, "sha256": sha256(fixture.members[path])}


def _expected_box(fixture):
    return {
        "id": BOX_ID,
        "name": "forest",
        "platform": "htb",
        "os": "windows",
        "difficulty": "easy",
        "status": "active",
        "started": NOW.isoformat(),
        "source": _source(fixture, "box.toml"),
    }


def _expected_provenance(fixture):
    return {
        "archive": {
            "kind": "exported",
            "packed": PACKED.isoformat(),
            "sha256": sha256(fixture.path.read_bytes()),
        },
        "manifest": _source(fixture, "manifest.toml"),
    }


def _event_key(event):
    return (
        event["at"],
        event["kind"],
        json.dumps(event, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8"),
    )


def test_h01_minimal_exported_fixture_and_golden_model(tmp_path):
    first = make_archive(tmp_path / "one" / "forest.exported.tar.gz")
    second = make_archive(tmp_path / "two" / "renamed.tar.gz")

    # Destination names and gzip timestamps cannot affect fixture bytes or provenance.
    assert first.path.read_bytes() == second.path.read_bytes()
    assert first.model == second.model
    assert build_model(first.path) == first.model
    assert build_model(second.path) == second.model

    with tarfile.open(first.path, "r:gz") as tar:
        assert tar.getnames() == [BOX_ID, f"{BOX_ID}/box.toml", f"{BOX_ID}/manifest.toml"]
        manifest = tomllib.loads(tar.extractfile(f"{BOX_ID}/manifest.toml").read().decode("utf-8"))

    assert manifest["schema"] == 1
    assert manifest["kind"] == "exported"
    assert manifest["packed"] == PACKED
    assert manifest["box"] == {
        "id": BOX_ID,
        "name": "forest",
        "platform": "htb",
        "os": "windows",
        "difficulty": "easy",
        "started": NOW,
    }
    assert len(manifest["file"]) == 1
    row = manifest["file"][0]
    assert set(row) == {"path", "target", "first_seen", "size", "mtime", "sha256"}
    assert row == {
        "path": "box.toml",
        "target": "",
        "first_seen": NOW,
        "size": len(first.members["box.toml"]),
        "mtime": 0.0,
        "sha256": sha256(first.members["box.toml"]),
    }

    assert first.model == {
        "schema_version": 1,
        "profile": "private-technical",
        "status": "draft",
        "box": _expected_box(first),
        "source": _expected_provenance(first),
        "flags": [],
        "targets": [],
        "timeline": [],
        "evidence": [],
        "findings": [],
        "held_back": [],
        "other": [],
    }
    assert "finished" not in first.model["box"]
    assert "notes" not in first.model
    assert "selection" not in first.model["source"]

    encoded = canonical_json(first.model)
    assert encoded.endswith(b"\n") and not encoded.endswith(b"\n\n")
    assert json.loads(encoded) == first.model
    assert str(tmp_path).encode("utf-8") not in encoded


def test_h02_full_exported_fixture_and_golden_model(tmp_path):
    first = make_archive(tmp_path / "one" / "forest.exported.tar.gz", full=True)
    second = make_archive(tmp_path / "two" / "renamed.tar.gz", full=True)
    original_archive = first.path.read_bytes()

    assert original_archive == second.path.read_bytes()
    assert first.model == second.model
    assert build_model(first.path) == first.model
    assert build_model(second.path) == second.model

    manifest = tomllib.loads(first.manifest_bytes.decode("utf-8"))
    listed = {row["path"] for row in manifest["file"]}
    # as real pwn-broker does, the manifest lists creds.toml and lists/; they are held back, not unlisted
    assert listed == set(first.members) - {"manifest.toml", "unlisted.txt"}
    assert len(first.records) == 16
    assert all(set(row) == {"path", "target", "first_seen", "size", "mtime", "sha256"} for row in manifest["file"])

    model = first.model
    assert model["schema_version"] == 1
    assert model["profile"] == "private-technical"
    assert model["status"] == "draft"
    assert model["box"] == _expected_box(first)
    assert model["source"] == _expected_provenance(first)
    assert model["findings"] == []
    assert "finished" not in model["box"]
    assert "selection" not in model["source"]

    assert model["flags"] == [
        {
            "name": "root",
            "value": "ROOT-FLAG-PRIVATE-CANARY",
            "at": LATER.isoformat(),
            "source": _source(first, "box.toml"),
        },
        {
            "name": "user",
            "value": "USER-FLAG-PRIVATE-CANARY",
            "at": NOW.isoformat(),
            "source": _source(first, "box.toml"),
        },
    ]
    assert model["targets"] == [
        {
            "box_id": BOX_ID,
            "box": "forest",
            "name": "dc01",
            "ips": ["10.10.10.161"],
            "hostnames": ["forest.htb.local"],
            "scope": "external",
            "added": NOW.isoformat(),
            "source": _source(first, "targets/dc01/target.toml"),
        }
    ]
    assert model["notes"] == {
        "source": _source(first, "notes.md"),
        "report_path": "evidence/notes.md",
        "size": len(first.members["notes.md"]),
    }

    policies = {
        "screenshots/root.png": ("screenshots", "", True, "default-include"),
        "targets/dc01/exploits/poc.py": ("exploits", "dc01", True, "default-include"),
        "targets/dc01/files/notes.txt": ("files", "dc01", False, "default-exclude-files"),
        "targets/dc01/loot/SAM.bak": ("loot", "dc01", False, "default-exclude-loot"),
        "targets/dc01/recordings/session.cast": ("recordings", "dc01", False, "default-exclude-recording"),
        "targets/dc01/scans/nmap.txt": ("scans", "dc01", True, "default-include"),
        "targets/dc01/screenshots/proof.png": ("screenshots", "dc01", True, "default-include"),
        "targets/dc01/upload/winpeas.exe": ("upload", "dc01", False, "default-exclude-upload"),
    }
    assert [item["path"] for item in model["evidence"]] == sorted(policies)

    for item in model["evidence"]:
        path = item["path"]
        kind, target, copied, reason = policies[path]
        digest = sha256(first.members[path])
        # Independent test-oracle calculation; do not call the fixture's ID helper here.
        payload = f"pwn-report\0evidence\0v1\0{BOX_ID}\0{path}\0{digest}".encode("utf-8")
        expected_id = "ev_" + hashlib.sha256(payload).hexdigest()
        output = {"copied": copied, "reason": reason}
        if copied:
            output["path"] = "evidence/" + path
        assert item == {
            "id": expected_id,
            "path": path,
            "target": target,
            "target_refs": [target] if target else [],
            "first_seen": FIRST_SEEN.isoformat(),
            "size": len(first.members[path]),
            "mtime": 0.0,
            "sha256": digest,
            "kind": kind,
            "output": output,
            "source": _source(first, path),
        }

    expected_events = [
        {
            "at": target["added"],
            "kind": "target_added",
            "target": target["name"],
            "source": target["source"],
        }
        for target in model["targets"]
    ]
    expected_events.extend(
        {
            "at": flag["at"],
            "kind": "flag_recorded",
            "flag": flag["name"],
            "source": flag["source"],
        }
        for flag in model["flags"]
    )
    expected_events.extend(
        {
            "at": item["first_seen"],
            "kind": "file_first_seen",
            "evidence_id": item["id"],
            "source": item["source"],
        }
        for item in model["evidence"]
    )
    expected_events.sort(key=_event_key)
    assert model["timeline"] == expected_events
    assert len(model["timeline"]) == 11
    assert model["held_back"] == [
        {"path": "creds.toml", "files": 1},
        {"path": "lists/", "files": 1},
        {"path": "targets/dc01/creds/", "files": 1},
        {"path": "tooldata/", "files": 1},
    ]
    assert model["other"] == ["stray.txt"]
    assert {event["kind"] for event in model["timeline"]} == {"target_added", "flag_recorded", "file_first_seen"}

    encoded = canonical_json(model)
    assert json.loads(encoded) == model
    for canary in (UNLISTED_CANARY, CREDS_CANARY, LISTS_CANARY):
        assert canary not in encoded
    assert str(tmp_path).encode("utf-8") not in encoded
    assert first.path.read_bytes() == original_archive

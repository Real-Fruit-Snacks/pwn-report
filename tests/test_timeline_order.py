"""The timeline is in the order things happened, also across a change of clock offset."""

from __future__ import annotations

from fixtures import BOX_ID, NOW, _toml_value, add_members, file_record, manifest_bytes, write_raw_archive
from pwn_report import build_model, build_report

# The night the clocks go back: 01:30 at -04:00 is 05:30 UTC, and the later 01:10 at -05:00 is 06:10 UTC.
TARGET_ADDED = "2026-11-01T01:30:00-04:00"
FLAG_AT = "2026-11-01T01:10:00-05:00"


def _archive(tmp_path):
    box_toml = (
        "schema = 1\n"
        f'id = "{BOX_ID}"\n'
        'name = "forest"\nplatform = "htb"\nos = "windows"\ndifficulty = "easy"\nstatus = "active"\n'
        f"started = {_toml_value(NOW)}\n"
        f"\n[flags.user]\nvalue = \"USER-FLAG\"\nat = {FLAG_AT}\n"
    ).encode("utf-8")
    target_toml = (
        "schema = 1\n"
        f'box_id = "{BOX_ID}"\n'
        'box = "forest"\nname = "dc01"\nips = ["10.10.10.161"]\nhostnames = []\nscope = "external"\n'
        f"added = {TARGET_ADDED}\n"
    ).encode("utf-8")
    members = {"box.toml": box_toml, "targets/dc01/target.toml": target_toml}
    records = [
        file_record("box.toml", box_toml),
        file_record("targets/dc01/target.toml", target_toml, target="dc01"),
    ]
    members["manifest.toml"] = manifest_bytes(records)
    return write_raw_archive(tmp_path / "dst.tar.gz", lambda tar: add_members(tar, members))


def test_events_across_a_clock_change_sort_by_instant(tmp_path):
    archive = _archive(tmp_path)
    model = build_model(archive)
    assert [event["kind"] for event in model["timeline"]] == ["target_added", "flag_recorded"]
    # the times are kept exactly as recorded, offsets and all
    assert [event["at"] for event in model["timeline"]] == [TARGET_ADDED, FLAG_AT]

    build_report(archive, tmp_path / "one")
    build_report(archive, tmp_path / "two")
    assert (tmp_path / "one" / "report.json").read_bytes() == (tmp_path / "two" / "report.json").read_bytes()
    text = (tmp_path / "one" / "report.md").read_text(encoding="utf-8")
    assert text.index("Target added: dc01") < text.index("Flag recorded: user")

"""A string from the archive stays text in every file of a report: in report.md wherever a line
puts it, the start of a list item and the end of a heading included, and in report.json and
report.toml when it holds a character a terminal would act on."""

from __future__ import annotations

import itertools
import json
import tomllib
import unicodedata

import pytest

from fixtures import NOW, _toml_value, add_members, file_record, make_archive, manifest_bytes, write_raw_archive
from pwn_report import build_report
from pwn_report.output import _canonical_json, _md_text, _metadata_toml, _toml_string
from pwn_report.report import UNSAFE_CATEGORIES, shown

LIST_ITEM = [
    "bullet_list_open", "list_item_open", "paragraph_open", "inline", "paragraph_close", "list_item_close",
    "bullet_list_close",
]  # fmt: skip
HEADING = ["heading_open", "inline", "heading_close"]
# every place _render_markdown puts a value: what is before it, what is after it, the blocks the line is
PLACES = [
    ("- ", "", LIST_ITEM),
    ("- ", ": V — 2026-11-14T12:00:00+02:00", LIST_ITEM),
    ("- Caption: ", "", LIST_ITEM),
    ("# ", " — private technical report", HEADING),
    ("#### ", "", HEADING),
]
# each starts a block, or ends a heading early, when it is the first thing in a list item or the last in a heading
BLOCK_STARTS = [
    "# Reviewed and approved", "###### six", "#", "a #", "a ##", "- -", "-", "---", "- - -", "-- -", "- x",
    "+ x", "+", "1. x", "1) x", "7.", "7)", "123456789. x", "    indented", "     five", " x", "x ", "x  ", " ",
    "  ", "===", "=", "> quote", ">", "* * *", "* x", "___", "```", "~~~ x", "<div>", "<!-- x -->", "[a]: /url",
    "[^1]: note", "- [ ] task", "| a | b |", "&#35; x", "&gt; x", "\\- x", "1\\. x", "a\nb", "\n# x", "\tx",
    ": x", "10.10.10.5", "2026-11-14T12:00:00+02:00", "1.x", "1234567890. x", "nmap-quick.txt", "a - b",
]  # fmt: skip


@pytest.fixture(scope="module")
def parse():
    """A CommonMark parser, with the tables and the strikethrough that GitHub adds."""
    markdown_it = pytest.importorskip("markdown_it", reason="needs markdown-it-py, which the dev extra installs")
    return markdown_it.MarkdownIt("commonmark").enable(["table", "strikethrough"]).parse


def _as_text(value: str) -> str:
    """What a reader should see for a value: itself, on one line, with each unsafe character as ?."""
    return shown(value.replace("\r\n", " ").replace("\r", " ").replace("\n", " "))


def _parsed(parse, source: str) -> tuple[list[str], str]:
    """The blocks a line of Markdown is, and its text if all of it is text."""
    tokens = parse(source + "\n")
    inline = [token for token in tokens if token.type == "inline"]
    pieces = [(child.type, child.content) for token in inline for child in token.children]
    assert {kind for kind, _ in pieces} <= {"text"}, (source, pieces)
    return [token.type for token in tokens], "".join(content for _, content in pieces)


@pytest.mark.parametrize(
    "value, written",
    [
        ("# Reviewed and approved", "\\# Reviewed and approved"),
        ("a ##", "a \\#\\#"),
        ("- -", "\\- -"),
        ("---", "\\---"),
        ("+ x", "\\+ x"),
        ("===", "\\==="),
        ("1. x", "1\\. x"),
        ("1) x", "1\\) x"),
        ("7.", "7\\."),
        ("    indented", "&#32;   indented"),
        ("x ", "x&#32;"),
        (" ", "&#32;"),
        ("> quote", "&gt; quote"),
        ("* * *", "\\* \\* \\*"),
        ("\tx", "?x"),
        # none of these starts a block, so none is touched
        ("10.10.10.5", "10.10.10.5"),
        ("2026-11-14T12:00:00+02:00", "2026-11-14T12:00:00+02:00"),
        ("nmap-quick.txt", "nmap-quick.txt"),
        ("1.x", "1.x"),
        ("1234567890. x", "1234567890. x"),
        ("a - b", "a - b"),
    ],
)
def test_what_would_start_a_block_is_escaped_and_nothing_else(value, written):
    assert _md_text(value) == written


@pytest.mark.parametrize("value", BLOCK_STARTS)
def test_a_value_is_text_wherever_a_line_puts_it(parse, value):
    for before, after, blocks in PLACES:
        source = before + _md_text(value) + after
        assert "\n" not in source
        assert _parsed(parse, source) == (blocks, before[before.index(" ") + 1 :] + _as_text(value) + after), source


def test_every_short_run_of_markdowns_own_characters_is_text(parse):
    # every value of up to three of the characters a block or its end is made of
    alphabet = "#-+=1.) x>*_"
    for length in (1, 2, 3):
        for characters in itertools.product(alphabet, repeat=length):
            value = "".join(characters)
            for before, after, blocks in (PLACES[0], PLACES[1], PLACES[4]):
                source = before + _md_text(value) + after
                assert _parsed(parse, source) == (blocks, before[before.index(" ") + 1 :] + value + after), source


def _archive(tmp_path, name: str, *, box: dict | None = None, flags=(), targets=(), extra=()):
    """The full fixture with more flags, targets and listed files at the box's root."""
    base = make_archive(tmp_path / f"{name}-base.tar.gz", full=True, box=box)
    members = {path: data for path, data in base.members.items() if path not in {"manifest.toml", "unlisted.txt"}}
    for flag in flags:
        members["box.toml"] += f'\n[flags.{_toml_value(flag)}]\nvalue = "V"\nat = {_toml_value(NOW)}\n'.encode()
    for target in targets:
        members[f"targets/{target}/target.toml"] = members["targets/dc01/target.toml"].replace(
            b'name = "dc01"', f"name = {_toml_value(target)}".encode()
        )
    members.update({path: b"x" for path in extra})
    kept = {record.path: record for record in base.records if record.path != "box.toml"}
    records = [
        kept.get(path) or file_record(path, data, target=path.split("/")[1] if path.startswith("targets/") else "")
        for path, data in sorted(members.items())
    ]
    members["manifest.toml"] = manifest_bytes(records, kind=base.kind, box=box)
    return write_raw_archive(tmp_path / f"{name}.tar.gz", lambda tar: add_members(tar, members))


def _items_after(tokens, line: str) -> list[str]:
    """The text of each item of the list that follows a heading or a paragraph."""
    start = next(i for i, token in enumerate(tokens) if token.type == "inline" and token.content == line)
    opened = next(i for i in range(start, len(tokens)) if tokens[i].type == "bullet_list_open")
    closed = next(i for i in range(opened, len(tokens)) if tokens[i].type == "bullet_list_close")
    return ["".join(child.content for child in token.children) for token in tokens[opened:closed] if token.type == "inline"]


def test_names_that_start_a_block_change_no_block_of_report_md(tmp_path, parse):
    hostile = {
        "box": {"name": "# Approved"},
        "flags": ["# Severity: critical", "1. first"],
        "targets": ["- web01"],
        "extra": ["# Reviewed and approved", "- -", "---", "1. x", "    indented", "+ plus", "trailing ##"],
    }
    plain = {
        "box": {"name": "Approved"},
        "flags": ["severity", "first"],
        "targets": ["web01"],
        "extra": ["reviewed", "a", "b", "c", "d", "e", "f"],
    }
    blocks = {}
    for name, given in (("hostile", hostile), ("plain", plain)):
        model = build_report(_archive(tmp_path, name, **given), tmp_path / f"{name}.report")
        assert set(given["extra"]) <= set(model["other"])
        tokens = parse((tmp_path / f"{name}.report" / "report.md").read_text(encoding="utf-8"))
        blocks[name] = [(token.type, token.tag, token.level) for token in tokens if token.type != "inline"]
        if name == "plain":
            continue
        headings = [
            (tokens[i].tag, "".join(child.content for child in tokens[i + 1].children))
            for i, token in enumerate(tokens)
            if token.type == "heading_open"
        ]
        assert [text for tag, text in headings if tag == "h1"] == ["# Approved — private technical report"]
        assert [text for tag, text in headings if tag == "h2"] == [
            "Review status", "Box summary", "Targets", "Flags", "Timeline", "Evidence index", "Not in the index",
            "Notes",
        ]  # fmt: skip
        assert ("h3", "- web01") in headings
        assert _items_after(tokens, "Listed in the archive, outside the index:") == model["other"]
        flags = [f"{flag['name']}: {flag['value']} — {flag['at']}" for flag in model["flags"]]
        assert flags[0].startswith("# Severity: critical: ") and flags[1].startswith("1. first: ")
        assert _items_after(tokens, "Flags") == flags
    assert blocks["hostile"] == blocks["plain"]
    assert not {"hr", "code_block", "fence", "ordered_list_open", "blockquote_open", "html_block"} & {
        kind for kind, _, _ in blocks["hostile"]
    }


UNSAFE = [
    "del\x7f", "csi\x9b31m", "nel\x85", "rtl\u202e", "zwj\u200d", "bom\ufeff", "soft\xadhyphen", "line\u2028",
    "paragraph\u2029", "tag\U000e0001", "all\x7f\x9b\u202e\u2028\U000e0001 together",
]  # fmt: skip
READABLE = "café Résumé 森林 Ω 😀 \" \\ / plain"


def _raw_unsafe(text: str) -> list[str]:
    """The unsafe characters in a written file, its own line breaks aside."""
    return [character for character in text if character != "\n" and unicodedata.category(character) in UNSAFE_CATEGORIES]


@pytest.mark.parametrize("value", UNSAFE, ids=[value.encode("unicode_escape").decode() for value in UNSAFE])
def test_report_json_writes_an_unsafe_character_as_an_escape_that_loads_back(value):
    model = {"box": {"name": value}, "other": [value, READABLE], value: 1}
    written = _canonical_json(model)
    text = written.decode("utf-8")
    assert _raw_unsafe(text) == []
    assert json.loads(written) == model
    # the rest is as readable as it was, and the layout is json.dumps' own
    assert READABLE.replace("\\", "\\\\").replace('"', '\\"') in text
    assert written.isascii() is False and text.endswith("\n}\n") and text.startswith('{\n  "')


def test_report_json_without_an_unsafe_character_is_byte_for_byte_what_it_was(tmp_path):
    fixture = make_archive(tmp_path / "a.tar.gz", full=True)
    expected = json.dumps(fixture.model, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2) + "\n"
    assert _canonical_json(fixture.model) == expected.encode("utf-8")


@pytest.mark.parametrize("value", UNSAFE, ids=[value.encode("unicode_escape").decode() for value in UNSAFE])
def test_report_toml_writes_an_unsafe_character_as_an_escape_that_loads_back(tmp_path, value):
    written = _toml_string(value + READABLE)
    assert _raw_unsafe(written) == []
    assert tomllib.loads(f"v = {written}\n") == {"v": value + READABLE}
    assert "café Résumé 森林 Ω 😀" in written
    model = json.loads(json.dumps(make_archive(tmp_path / "a.tar.gz", full=True).model))
    model["box"]["id"] = value
    metadata = _metadata_toml(model)
    assert _raw_unsafe(metadata.decode("utf-8")) == []
    assert tomllib.loads(metadata.decode("utf-8"))["box_id"] == value


def test_no_unsafe_character_from_an_archive_reaches_a_file_of_the_report_raw(tmp_path):
    name = "for\x9b31mest\u202e"
    archive = _archive(tmp_path, "odd", box={"name": name}, flags=["fl\x9bag\u202e"], extra=["stray\x9b2Jname\u202etxt"])
    model = build_report(archive, tmp_path / "out")
    assert model["box"]["name"] == name and "stray\x9b2Jname\u202etxt" in model["other"]
    for written in ("report.json", "report.md", "report.toml", "SHA256SUMS"):
        text = (tmp_path / "out" / written).read_text(encoding="utf-8")
        assert _raw_unsafe(text) == [], written
    assert json.loads((tmp_path / "out" / "report.json").read_bytes()) == model
    assert '"name": "for\\u009b31mest\\u202e"' in (tmp_path / "out" / "report.json").read_text(encoding="utf-8")

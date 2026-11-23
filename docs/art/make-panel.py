"""Draw the README's animated panel: docs/assets/panel-dark.svg and panel-light.svg.

usage:
    python docs/art/make-panel.py            write the two panels
    python docs/art/make-panel.py --check    exit 1 if either is not what this script draws

The panel acts out one report in a 19 s loop. On the left, a terminal: cd ~/pwn-broker/wrapped,
pwn-report build on a finished archive, the same command again, then grep held in the report's
report.md. On the right, the wrapped/ folder as the build leaves it: the report is written into a
hidden folder beside the archive, each file in the order the build writes it, muted while it is
only staged, and once every file and checksum is right the folder is renamed into place and its
files turn to ink, all at once. The second build changes nothing there: an existing report is
never replaced. When grep reads report.md, report.md lights up.

Nothing on the panel is typed by hand. The script makes the full test archive the suite uses
(tests/fixtures.py: box forest, target dc01, finished) in a folder of its own, runs this
checkout's pwn-report command on it twice from that folder, and takes from that run the ok and
fail lines, the hidden folder's name, the files in the order they are written, and the lines of
report.md that grep held finds. The hidden folder's name ends in random characters, which are cut
with an ellipsis, and evidence/ is shown from the moment the hidden folder is, as the build makes
both at once. The build takes milliseconds; here each file takes STEP seconds, so it can be seen.
The terminal is COLS columns wide and wraps a long line the way a terminal does.

The SVG's base styles are the moment after grep, with the report in place and report.md lit,
which is what a viewer that skips the animation shows.

Text is converted to paths from the page's own fonts (docs/fonts), because an SVG shown through
<img> can't load fonts. Run from the repo root:

    python -m pip install -r docs/art/requirements.txt
    python docs/art/make-panel.py

real_run() and transcript() need no fonts: tests/test_page.py uses them to check that the project
page shows the same session.
"""
import argparse
import contextlib
import io
import os
import shutil
import importlib.util
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FONTS = HERE.parent / "fonts"
PANELS = {theme: HERE.parent / "assets" / f"panel-{theme}.svg" for theme in ("dark", "light")}
sys.path.insert(0, str(ROOT / "tests"))
if importlib.util.find_spec("pwn_report") is None:
    # run from a checkout with nothing installed: this checkout's src/. When pwn_report can be
    # imported already (pytest, an installed wheel), it is left alone, so a release's run tests
    # its wheel and not this checkout
    sys.path.insert(0, str(ROOT / "src"))

import fixtures  # noqa: E402  (the suite's own archive builder)
from pwn_report import cli, output  # noqa: E402  (this checkout's pwn-report)

# RFS Nightshift and Dayshift, as in the other pwn panels, with Raspberry for a failure
THEMES = {
    "dark": dict(plate="#1A1D24", glass="#070809", line="#262A33", ink="#E8E6E1", mute="#8A8F99",
                 ember="#FF6A3D", mint="#3DDC97", fault="#F06292"),
    "light": dict(plate="#FFFFFF", glass="#ECEAE4", line="#D6D3CB", ink="#1A1B1E", mute="#666A73",
                  ember="#C03B0A", mint="#15794D", fault="#B0306A"),
}

W, H = 1000, 430
CYCLE = 19.0        # seconds
TYPE = 0.045        # per typed character (BRAND.md section 8)
GAP = 0.12          # between two printed lines
STEP = 0.15         # between two files the build writes
FADE = 0.25         # a row on the right appearing or changing
EASE = "cubic-bezier(.2,.7,.2,1)"
STILL = 17.4        # the moment the base styles show
OUT_AT = 18.3       # everything fades out, then the loop starts again

MONO = "ibm-plex-mono-latin-400-normal.woff2"
MONO_B = "ibm-plex-mono-latin-600-normal.woff2"
CUT = "…"
COLS = 56
PROMPT = "$ "
WRAPPED = "~/pwn-broker/wrapped"
GREP = "held"
STATUS = {"ok": "mint", "fail": "fault"}   # the word pwn-report starts its one line with

# Layout
LX, RX, TOP, BOTTOM = 40, 568, 76, 404       # left window from LX, right window from RX to W - 40
L_SIZE, L_PAD, L_FIRST, L_PITCH = 14, 18, 104, 23
R_SIZE, R_PAD, R_FIRST, R_PITCH, R_INDENT = 13, 16, 104, 23, 16


def _fail(message):
    sys.exit(f"fail  make-panel: {message}")


def real_run():
    """Build the report from the full test archive, twice, in a folder of its own, and read it.

    Returns the archive's and the report's names, the line each build printed, the hidden
    folder's name with its random end cut, the report's files in the order the build wrote them,
    report.md, and the lines of it that hold GREP."""
    work = Path(tempfile.mkdtemp())
    start = os.getcwd()
    wrapped = work / "wrapped"
    wrapped.mkdir()
    archive = f"{fixtures.BOX_ID}.finished.tar.gz"
    fixtures.make_archive(wrapped / archive, full=True, kind="finished")
    report = cli.default_output(Path(archive)).name

    # watch the build: the hidden folder it makes, and each file it writes there, in order
    stages, writes = [], []
    mkdtemp, output_path = tempfile.mkdtemp, output._output_path

    def watched_mkdtemp(*args, **kwargs):
        path = mkdtemp(*args, **kwargs)
        stages.append(Path(path))
        return path

    def watched_output_path(root, relative):
        if stages and Path(root) == stages[0] and relative not in writes:
            writes.append(relative)
        return output_path(root, relative)

    said = []
    try:
        os.chdir(wrapped)
        tempfile.mkdtemp, output._output_path = watched_mkdtemp, watched_output_path
        for status, stream in ((0, "stdout"), (1, "stderr")):
            streams = {"stdout": io.StringIO(), "stderr": io.StringIO()}
            with contextlib.redirect_stdout(streams["stdout"]), contextlib.redirect_stderr(streams["stderr"]):
                code = cli.main(["build", archive])
            lines = streams[stream].getvalue().splitlines()
            other = streams["stderr" if stream == "stdout" else "stdout"].getvalue()
            if code != status or len(lines) != 1 or other:
                _fail(f"pwn-report build exited {code}, printing {streams['stdout'].getvalue()!r} "
                      f"and {streams['stderr'].getvalue()!r}")
            said.append(lines[0])
        folder = wrapped / report
        markdown = (folder / "report.md").read_text(encoding="utf-8")
        files = sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file())
    finally:
        tempfile.mkdtemp, output._output_path = mkdtemp, output_path
        os.chdir(start)
        shutil.rmtree(work)

    if len(stages) != 1:
        _fail(f"the build made {len(stages)} hidden folders, not one")
    stage = stages[0].name
    if not stage.startswith(f".{report}.tmp-"):
        _fail(f"the hidden folder is {stage!r}, not .{report}.tmp-...")
    if sorted(writes) != files:
        _fail(f"the build wrote {writes}, but the report holds {files}")
    held = [line for line in markdown.splitlines() if GREP in line]
    if not held:
        _fail(f"no line of report.md holds {GREP!r}")
    return {
        "archive": archive,
        "report": report,
        "ok": said[0],
        "fail": said[1],
        "staging": f".{report}.tmp-{CUT}",
        "writes": writes,
        "markdown": markdown,
        "held": held,
    }


def session(run):
    """What the terminal shows, in order: ("cmd", what is typed) or ("out", a line printed)."""
    build = f"pwn-report build {run['archive']}"
    return [
        ("cmd", f"cd {WRAPPED}"),
        ("cmd", build),
        ("out", run["ok"]),
        ("cmd", build),
        ("out", run["fail"]),
        ("cmd", f"cd {run['report']}"),
        ("cmd", f"grep {GREP} report.md"),
        *[("out", line) for line in run["held"]],
    ]


def transcript(run):
    """The terminal's lines, unwrapped, as the project page shows them, without the last prompt."""
    return [PROMPT + text if kind == "cmd" else text for kind, text in session(run)]


def plan(run):
    """The session with its times, and the folder on the right with when each part changes.

    The session is ("cmd", typed, prompt shown at, typing starts at) and ("out", line, printed
    at), ending with the empty prompt the cursor rests on. The folder is (depth, layers), a layer
    being (from, text, colour, face): each is shown from its time until the next layer's."""
    timed, t, last = [], 0.0, None
    t_stage = t_rename = t_lit = None
    t_write = {}
    for kind, text in session(run):
        if kind == "cmd":
            t += 0.3 if last == "out" else 0.15 if last == "cmd" else 0.0
            wait = 0.5 if last is None else 0.4
            timed.append(("cmd", text, t, t + wait))
            t += wait + max(len(text) - 1, 0) * TYPE + 0.25
        else:
            if text == run["ok"]:
                # the build: the hidden folder with evidence/ in it, each file as it is written,
                # SHA256SUMS last, the checks, and the rename; then its one line
                t_stage = t
                t_write = {rel: t_stage + STEP * (i + 1) for i, rel in enumerate(run["writes"])}
                t_rename = t_stage + STEP * (len(run["writes"]) + 2)
                t = t_rename + 0.15
            if text in run["held"] and t_lit is None:
                t_lit = t
            timed.append(("out", text, t))
            t += GAP
        last = kind
    t += 0.3
    timed.append(("cmd", "", t, None))

    folder = [
        (0, [(0.0, run["archive"], "ink", MONO)]),
        (0, [(t_stage, run["staging"], "mute", MONO), (t_rename, run["report"] + "/", "ink", MONO_B)]),
    ]
    made = set()
    for rel in run["writes"]:
        top, _, rest = rel.partition("/")
        if rest and top not in made:
            made.add(top)
            folder.append((1, [(t_stage, top + "/", "mute", MONO), (t_rename, top + "/", "ink", MONO)]))
        name = rest or top
        layers = [(t_write[rel], name, "mute", MONO), (t_rename, name, "ink", MONO)]
        if rel == "report.md":
            layers.append((t_lit, name, "ember", MONO_B))
        folder.append((2 if rest else 1, layers))
    return timed, folder, t


def pieces(line):
    """A printed line as (text, colour): pwn-report's status word in its colour, the rest in ink;
    any other output muted (BRAND.md section 9)."""
    word = line.split(" ", 1)[0]
    if word in STATUS:
        return [(word, STATUS[word]), (line[len(word):], "ink")]
    return [(line, "mute")]


def wrap(parts):
    """A line as a COLS-wide terminal shows it: rows of [column, text, colour] runs."""
    chars = [(ch, colour) for text, colour in parts for ch in text]
    rows = []
    for start in range(0, max(len(chars), 1), COLS):
        runs = []
        for i, (ch, colour) in enumerate(chars[start:start + COLS]):
            if runs and runs[-1][2] == colour:
                runs[-1][1] += ch
            else:
                runs.append([i, ch, colour])
        rows.append(runs)
    return rows


_fonts = {}
_glyphs = {}   # (font, glyph name) -> (id, path in font units); drawn once in <defs>, reused by <use>


def font(name):
    if name not in _fonts:
        from fontTools.ttLib import TTFont
        _fonts[name] = TTFont(str(FONTS / name))
    return _fonts[name]


def char_w(size, fname=MONO):
    f = font(fname)
    return f.getGlyphSet()[f.getBestCmap()[ord("0")]].width * size / f["head"].unitsPerEm


def text(s, x, y, size, fname, fill):
    """Path for `s` with its baseline at y."""
    from fontTools.pens.svgPathPen import SVGPathPen
    f = font(fname)
    gs, cmap, upm = f.getGlyphSet(), f.getBestCmap(), f["head"].unitsPerEm
    k = size / upm
    uses = []
    pen_x = x
    for ch in s:
        if ord(ch) not in cmap:
            _fail(f"{fname} has no glyph for {ch!r}")
        n = cmap[ord(ch)]
        key = (fname, n)
        if key not in _glyphs:
            pen = SVGPathPen(gs, ntos=lambda v: "%g" % round(v, 1))
            gs[n].draw(pen)
            _glyphs[key] = (f"g{len(_glyphs)}", pen.getCommands())
        gid, d = _glyphs[key]
        if d:
            uses.append(f'<use href="#{gid}" transform="matrix({k:.5f} 0 0 {-k:.5f} {pen_x:.2f} {y:.2f})"/>')
        pen_x += gs[n].width * k
    return f'<g fill="{fill}">{"".join(uses)}</g>'


def pct(t):
    return f"{t / CYCLE * 100:.3f}%"


class Anim:
    """Collects the keyframes and the still-frame styles, one class per animated element."""

    def __init__(self):
        self.css, self.rules, self.base = [], [], []

    def toggle(self, name, start):
        """Shown from `start` to the end of the loop, switched on at once (a terminal printing)."""
        self.base.append(f".{name}{{opacity:{int(start <= STILL)}}}")
        if start <= 0:
            return
        self.css.append(f"@keyframes {name}{{0%{{opacity:0}}{pct(start)}{{opacity:1}}100%{{opacity:1}}}}")
        self.rules.append(f".{name}{{animation:{name} {CYCLE}s step-end infinite}}")

    def fade(self, name, changes, init=0):
        """Opacity that eases to each (t, value) in turn, over FADE."""
        value, still = init, init
        frames = [f"0%{{opacity:{init}}}"]
        for t, v in changes:
            frames.append(f"{pct(t)}{{opacity:{value};animation-timing-function:{EASE}}}")
            frames.append(f"{pct(t + FADE)}{{opacity:{v}}}")
            value = v
            if t <= STILL:
                still = v
        frames.append(f"100%{{opacity:{value}}}")
        self.base.append(f".{name}{{opacity:{still}}}")
        if changes:
            self.css.append(f"@keyframes {name}{{{''.join(frames)}}}")
            self.rules.append(f".{name}{{animation:{name} {CYCLE}s linear infinite}}")

    def style(self):
        return f"<style>{''.join(self.base)}@media (prefers-reduced-motion:no-preference){{{''.join(self.css)}{''.join(self.rules)}}}</style>"


def check_layout(timed, folder, end):
    """Stop if a command would wrap, a piece leaves its window, or the loop runs out of time."""
    cw, rcw = char_w(L_SIZE), char_w(R_SIZE)
    if LX + L_PAD + COLS * cw > RX - 20 - L_PAD:
        _fail(f"{COLS} columns run past the right edge of the terminal")
    rows = 0
    for item in timed:
        if item[0] == "cmd":
            if len(PROMPT + item[1]) > COLS:
                _fail(f"{PROMPT + item[1]!r} is longer than the terminal's {COLS} columns")
            rows += 1
        else:
            rows += len(wrap(pieces(item[1])))
    if L_FIRST + (rows - 1) * L_PITCH + L_SIZE * 0.25 > BOTTOM:
        _fail("the session is taller than its window")
    for r, (depth, layers) in enumerate(folder):
        x0 = RX + R_PAD + depth * R_INDENT
        for _, s, _, _ in layers:
            if x0 + len(s) * rcw > W - 40 - R_PAD:
                _fail(f"{s!r} runs past the right edge of the folder")
        if R_FIRST + r * R_PITCH + R_SIZE * 0.25 > BOTTOM:
            _fail(f"row {r} of the folder is below its window")
    if not end + 1.5 < STILL < OUT_AT < CYCLE - 0.5:
        _fail(f"the session ends at {end:.2f} s, too late for a still frame at {STILL} s")


def draw(theme, timed, folder):
    c = THEMES[theme]
    a = Anim()
    run = []                      # everything that plays, inside one group that fades out at the end
    cw = char_w(L_SIZE)
    lx0 = LX + L_PAD

    def left_y(row):
        return L_FIRST + row * L_PITCH

    # --- the session, and where the cursor is ---
    cursor = []                   # (t, row, col, shown)
    row = 0
    for n, item in enumerate(timed):
        if item[0] == "cmd":
            _, typed, shown, typing = item
            y = left_y(row)
            a.toggle(f"p{n}", shown)
            run.append(f'<g class="p{n}">{text(PROMPT.strip(), lx0, y, L_SIZE, MONO_B, c["ember"])}</g>')
            cursor.append((shown, row, len(PROMPT), 1))
            for i, ch in enumerate(typed):
                t = typing + i * TYPE
                if ch != " ":
                    a.toggle(f"p{n}c{i}", t)
                    run.append(f'<g class="p{n}c{i}">{text(ch, lx0 + (len(PROMPT) + i) * cw, y, L_SIZE, MONO, c["ink"])}</g>')
                cursor.append((t, row, len(PROMPT) + i + 1, 1))
            row += 1
        else:
            _, line, shown = item
            # the cursor leaves the prompt line when the command's output starts
            if cursor and cursor[-1][3]:
                cursor.append((shown, cursor[-1][1], cursor[-1][2], 0))
            g = []
            for runs in wrap(pieces(line)):
                for col, part, colour in runs:
                    if part.strip():
                        g.append(text(part, lx0 + col * cw, left_y(row), L_SIZE, MONO, c[colour]))
                row += 1
            a.toggle(f"o{n}", shown)
            run.append(f'<g class="o{n}">{"".join(g)}</g>')

    # The cursor blinks twice when a prompt waits a while, then stays.
    waits = [item[2] for item in timed if item[0] == "cmd" and (item[3] is None or item[3] - item[2] > 1.5)]
    blinks = list(cursor)
    for start in waits:
        held = [p for p in blinks if p[0] <= start][-1]
        for dt, s in ((0.45, 0), (0.7, 1), (1.15, 0), (1.4, 1)):
            blinks.append((start + dt, held[1], held[2], s))
    blinks.sort()

    def at(col, r):
        return f"translate({lx0 + col * cw:.2f}px,{left_y(r) - L_SIZE * 0.8:.2f}px)"

    frames = []
    still = blinks[0]
    for t, r, col, s in blinks:
        frames.append(f"{pct(t)}{{transform:{at(col, r)};opacity:{s}}}")
        if t <= STILL:
            still = (t, r, col, s)
    a.base.append(f".cur{{transform:{at(still[2], still[1])};opacity:{still[3]}}}")
    first = blinks[0]
    a.css.append(f"@keyframes cur{{{''.join(frames)}100%{{transform:{at(first[2], first[1])};opacity:0}}}}")
    a.rules.append(f".cur{{animation:cur {CYCLE}s step-end infinite}}")
    run.append(f'<rect class="cur" x="0" y="0" width="{cw:.2f}" height="{L_SIZE * 1.05:.2f}" fill="{c["ink"]}" fill-opacity=".7"/>')

    # --- the folder ---
    for r, (depth, layers) in enumerate(folder):
        x, y = RX + R_PAD + depth * R_INDENT, R_FIRST + r * R_PITCH
        for i, (start, s, colour, face) in enumerate(layers):
            name = f"f{r}l{i}"
            changes = [] if start <= 0 else [(start, 1)]
            if i + 1 < len(layers):
                changes.append((layers[i + 1][0], 0))
            a.fade(name, changes, init=int(start <= 0))
            run.append(f'<g class="{name}">{text(s, x, y, R_SIZE, face, c[colour])}</g>')

    # --- the end of the loop: everything goes, then the first prompt starts it again ---
    a.base.append(".run{opacity:1}")
    a.css.append(f"@keyframes run{{0%{{opacity:1}}{pct(OUT_AT)}{{opacity:1;animation-timing-function:{EASE}}}"
                 f"{pct(OUT_AT + 0.5)}{{opacity:0}}100%{{opacity:0}}}}")
    a.rules.append(f".run{{animation:run {CYCLE}s linear infinite}}")

    o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img">']
    o.append(a.style())
    # --- the plate, the terminal and the folder's pane ---
    o.append(f'<rect x="0.5" y="0.5" width="{W - 1}" height="{H - 1}" rx="22" fill="{c["plate"]}" stroke="{c["line"]}"/>')
    o.append(text("pwn-report", LX, 52, 16, MONO_B, c["mute"]))
    o.append(text(WRAPPED + "/", RX, 52, 16, MONO, c["mute"]))
    o.append(f'<rect x="{LX}" y="{TOP}" width="{RX - 20 - LX}" height="{BOTTOM - TOP}" rx="12" fill="{c["glass"]}" stroke="{c["line"]}"/>')
    o.append(f'<rect x="{RX}" y="{TOP}" width="{W - 40 - RX}" height="{BOTTOM - TOP}" rx="12" fill="none" stroke="{c["line"]}"/>')
    o.append(f'<g class="run">{"".join(run)}</g>')

    defs = "".join(f'<path id="{gid}" d="{d}"/>' for gid, d in _glyphs.values() if d)
    o.insert(1, f"<defs>{defs}</defs>")
    o.append("</svg>")
    return "".join(o) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if a panel is not what this script draws")
    args = parser.parse_args(argv)
    timed, folder, end = plan(real_run())
    check_layout(timed, folder, end)
    stale = []
    for theme, path in PANELS.items():
        _glyphs.clear()
        svg = draw(theme, timed, folder).encode("utf-8")
        shown = path.relative_to(ROOT).as_posix()
        if args.check:
            if not path.is_file() or path.read_bytes() != svg:
                stale.append(shown)
            continue
        path.write_bytes(svg)
        print(f"ok    wrote {shown} ({len(svg) // 1024} KB)")
    for shown in stale:
        print(f"fail  {shown} is out of date: run python docs/art/make-panel.py", file=sys.stderr)
    if args.check and not stale:
        print("ok    the panels are what make-panel.py draws")
    return 1 if stale else 0


if __name__ == "__main__":
    raise SystemExit(main())

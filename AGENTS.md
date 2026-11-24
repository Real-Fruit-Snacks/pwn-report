# Agent instructions — pwn-report

Read before touching `src/pwn_report/`, `docs/`, or release panels.

## What this repo is

`pwn-report` builds deterministic, SHA-256-verified, private Markdown/JSON/TOML evidence folders from `pwn-broker` archives (pure Python 3.11+ stdlib, zero network, never reads credential files). Its `docs/` GitHub Pages site is part of the unified four-tab **pwn handbook** (`pwn-broker`, `pwn-shop`, `pwn-playbooks`, `pwn-report`).

## Brand contract (Cyclorama Dawn `v2.1.0`)

Source of truth: `Real-Fruit-Snacks/rfs-brand` (`v2.1.0`).

- **Dark-first (`LX 263` `#050507`)** default; **Light (`LX 512` `#F5F7F9`)** opt-in toggle with radial View Transition and cross-tab `rfs-theme` `localStorage` sync.
- **Palette:** Glacial Steel (`#1F547A` / `#74B8E8` / `#164669`), Maritime Beacon Orange (`#F06E2B` / `#FF9254` / `#AD3D0A`), Signal Mint (`#3DDC97` / `#127247`), Amber (`#FFC247` / `#885800`), Signal Crimson Fault (`#FF5C6C` / `#C92438` / `#B91C2E`).
- **Fonts:** Self-hosted variable WOFF2 only (`Big Shoulders Stencil`, `Albert Sans`, `Azeret Mono`, `OFL.txt`) — zero external CDNs. Note `tests/test_page.py` checks `url(...)` in `docs/styles.css` verbatim, so keep font URLs unquoted (`url(fonts/...)`).
- **Chrome:** Below-header `.rfs-shell` scroll container (`<header class="rfs-shell-header">` + `<div class="rfs-scroll-region">`), wrapped command cards, Cartesian `in oklab` gradients only, zero neon glows, zero capsule pills, zero native `alert()`/`confirm()`/`prompt()`, semantic `[ok]` `popover="manual"` toasts.
- **Shared handbook contract:** The shared base of `docs/styles.css` and `docs/script.js` stays identical across `pwn-broker`, `pwn-shop`, `pwn-playbooks`, and `pwn-report` up to the `this page` comment.

## Required checks before pushing

```sh
python docs/art/make-panel.py
python docs/art/make-panel.py --check
python -m pytest -q -W error
```

- `pwn-report` CLI stdout/stderr format (`ok    report <folder>`, `fail  <reason>`) and exit codes (`0`, `1`, `2`, `130`) are part of the `pwn-broker` contract and must stay plain text.
- `docs/assets/panel-{dark,light}.svg` must match `docs/art/make-panel.py` byte-for-byte.
- Never mention private repositories or unrelated internal tools in any public file.

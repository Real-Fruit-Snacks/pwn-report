# pwn-report guide

## Install

Python 3.11 or later; pwn-report uses only the standard library. Each release publishes three files: the wheel `pwn_report-<version>-py3-none-any.whl`, the sdist `pwn_report-<version>.tar.gz`, and `SHA256SUMS.txt` with the SHA-256 of both. Check the file against `SHA256SUMS.txt` before installing it:

```sh
curl -fsSLO https://github.com/Real-Fruit-Snacks/pwn-report/releases/download/v0.1.0/pwn_report-0.1.0-py3-none-any.whl
curl -fsSLO https://github.com/Real-Fruit-Snacks/pwn-report/releases/download/v0.1.0/SHA256SUMS.txt
sha256sum -c --ignore-missing SHA256SUMS.txt
pipx install ./pwn_report-0.1.0-py3-none-any.whl
```

On Kali, `pipx` comes from `sudo apt install pipx`; Kali's Python refuses a plain `pip install` outside a virtual environment. On Windows or macOS, make a virtual environment and run `python -m pip install pwn_report-0.1.0-py3-none-any.whl` in it. From a checkout, `python -m pip install .`.

`SHA256SUMS.txt` comes from the same release as the wheel, so the check catches a damaged download, not a release replaced by someone else. The release workflow builds both files from a locked set of build tools, records their SHA-256 before anything unpinned runs, and publishes only files with those SHA-256; [docs/tested.md](tested.md) records each release's run.

## The command

```text
pwn-report build <archive> [-o <folder>] [--select <file>]
pwn-report --version
pwn-report --help
```

- `<archive>`: a `<box>.finished.tar.gz` or `<box>.exported.tar.gz` that pwn-broker wrote, from `~/pwn-broker/wrapped/` or wherever it was copied.
- `-o`, `--output`: the report folder to make. Its parent must exist and it must not. Without it, the folder is beside the archive and named after it: `.tar.gz` becomes `.report`, so `2026-11-14_htb_forest.finished.tar.gz` gives `2026-11-14_htb_forest.finished.report/`.
- `--select`: a selection file, below.

What it prints, and the exit status:

| Outcome | Output | Status |
|---|---|---|
| A report was written | `ok    report <folder>` on stdout | 0 |
| Anything went wrong | `fail  <reason>` on stderr, and nothing was written | 1 |
| Ctrl-C | `fail  interrupted; no report was written` on stderr | 130 |
| A mistake on the command line | the usage, on stderr | 2 |

A build always prints exactly one line, and a control or format character from a crafted name is shown as `?`, so the line stays one line. A path that the terminal's encoding cannot show is printed with the character escaped, as `\xe9`, rather than failing after the report was written.

## What a report folder holds

```text
<name>.report/
  report.md       what to read
  report.json     the model: every fact in report.md, with its source path and SHA-256
  report.toml     how it was built
  SHA256SUMS      the SHA-256 of every other file in the folder
  evidence/       the copied files, at their paths inside the box, and notes.md
```

`report.md` has these sections, in this order:

1. **Review status**: a draft, with nothing reviewed or approved, and what the report never reads.
2. **Box summary**: name, platform, OS, difficulty, status, start and finish times, and whether the archive was finished or exported. An OS or difficulty left empty when the box was made reads `Not recorded`.
3. **Targets**: each target's scope, addresses, hostnames and when it was added, by name.
4. **Flags**: each flag's value and when it was recorded.
5. **Timeline**: targets added, flags recorded and files first seen, in the order they happened. The times are the ones pwn-broker recorded, with their own offsets; the order is by the instant, so a box that crosses a change of clock is still in order.
6. **Evidence index**: by target and folder, each file with its ID, the targets it concerns, when it was first seen, its size and SHA-256, and either a link to its copy or why it was not copied.
7. **Not in the index**: the places held back, with how many files each holds, and every other listed file, by path.
8. **Notes**: a link to the box's `notes.md`, copied unchanged.

Every string from the archive is shown as text: Markdown, HTML and template syntax in a file name, a caption or a flag value is escaped, and a control or format character, such as a terminal escape or a right-to-left override, is shown as `?`.

`report.toml` holds `generator`, `generator_version`, `schema_version`, `profile`, `box_id`, `archive_kind`, `source_archive_sha256`, `selection_sha256` when a selection was given, and `status`. `SHA256SUMS` has one `<sha256>  <path>` line for each file in the folder but itself, sorted by path, with a final newline.

### report.json

The model, in schema version 1, with sorted keys, two-space indents and a final newline:

| Key | What it holds |
|---|---|
| `schema_version`, `profile`, `status` | `1`, `"private-technical"`, `"draft"` |
| `box` | `id`, `name`, `platform`, `os`, `difficulty`, `status`, `started`, `finished` if the box has one, and `source` (`box.toml`'s path and SHA-256) |
| `source` | the archive's `kind`, `packed` time and SHA-256, the manifest's SHA-256, and the selection's name and SHA-256 if one was given |
| `targets` | each target from its `target.toml`, sorted by name, with its source |
| `flags` | each flag, sorted by name |
| `timeline` | `target_added`, `flag_recorded` and `file_first_seen` events, each with its source |
| `evidence` | each indexed file: `id`, `path`, `target`, `target_refs`, `first_seen`, `size`, `mtime`, `sha256`, `kind`, `output` (`copied`, `reason`, and `path` when copied), `source`, and `caption` and `alt_text` when a selection gives them |
| `held_back` | each held-back place with its count of listed files |
| `other` | every other listed file, by path |
| `findings` | always empty in schema 1 |
| `notes` | `notes.md`'s source, size and path in the report, when the archive lists it |

An evidence ID is `ev_` and the SHA-256 of the box's ID, the file's path and its SHA-256, so the same file in the same box always has the same ID.

## What goes in

| Where in the box | What happens |
|---|---|
| `scans/`, `screenshots/` and `exploits/`, in a target or at the box's root | indexed and copied |
| `loot/` and `recordings/`, in a target or at the box's root | indexed; copied only when a selection includes the file |
| `targets/<t>/files/`, `upload/` | indexed; copied only when a selection includes the file |
| `creds.toml`, `lists/`, `targets/<t>/creds/`, `tooldata/` | held back: never read or copied, never selectable, shown only as a count of files |
| `box.toml`, `notes.md`, `manifest.toml`, `targets/<t>/target.toml` | read for the report itself; `notes.md` is copied |
| anything else the manifest lists | shown by path under `Not in the index`, never read |

A folder under `targets/` is a target only if it has its `target.toml`; files in one without it are listed under `Not in the index`. So is a file whose name holds a backslash or a control character. Neither stops the report.

`notes.md` and every copied file are copied as they were. pwn-broker's note keys can paste a credential into the note, tool output in `scans/` often shows the passwords it found, a screenshot can show one, and loot a selection copies can hold them, so a report can hold passwords even though it never reads the credential files. It is private, and it says so at the top.

## A selection file

TOML, schema 1, a list of rules, each for one indexed file:

```toml
schema = 1

[[rule]]
path = "targets/dc01/loot/ntds.dit"     # an indexed file's path inside the box
include = true                          # copy it, or with false, don't copy it
caption = "NTDS.dit copied off DC01 with the backup operator's rights"
alt_text = "a hex dump of the file's first page"
target_refs = ["dc01"]                  # more targets this file concerns
```

- `path` is required and must be a file in the evidence index; each path appears once.
- `include` overrides the default for that file, and the report records `selection-include` or `selection-exclude` as the reason.
- `caption` and `alt_text`, if given, must not be empty.
- `target_refs` must name targets the box has.
- A held-back path, a file the archive does not list, and any other key are refused, with nothing written.

The selection file's SHA-256 is recorded in `report.toml` and `report.json`. [selection.example.toml](selection.example.toml) is a complete one.

## How the archive is checked

The archive is untrusted input, read once to build the model and once to copy the evidence, front to back, never unpacked to disk.

- **Members**: regular files and folders only. Links, devices, pipes and sparse files are refused, as is a name that is absolute, starts with a drive letter, or climbs out with `..` by either kind of slash. One box folder holds everything.
- **Limits**, the same as pwn-broker's own: at most 300,000 members, 4,096 bytes for a name and 64 MiB for all names together, a manifest of at most 64 MiB and `box.toml`, `target.toml` and a selection of at most 1 MiB each, and per-member header limits.
- **The manifest**: every file the report uses must be listed with the size and SHA-256 it has; a changed or missing file stops the build. Held-back files are counted from the manifest alone.
- **Writing**: the report is built in a hidden folder beside the output, checked file by file against the model and `SHA256SUMS`, and renamed into place only when everything matches and the archive's SHA-256 is still the one read at the start. On any failure the hidden folder is removed; if it cannot be, the `fail` line names it, since it holds copied evidence.
- **Names the system cannot hold**: on Windows, a name Windows refuses (`CON`, `aux.txt`, a trailing dot or space, `<>:"|?*`), and on Windows and macOS, two names that differ only in case or in Unicode form, stop the build before anything is written, naming the files. Leave one out with a selection rule, or build on Linux.

## The same report every time

The same archive, selection and pwn-report version give a byte-identical folder: everything is sorted explicitly, every line ends in LF, no time is taken from the clock, and nothing random is used. The only times in a report are the ones in the archive.

## When it fails

Every failure is one line naming what is wrong. The common ones:

| The line says | What to do |
|---|---|
| `no archive at <path>` | check the path |
| `output already exists and will not be replaced` | move the old report, or give `-o` |
| `output parent is not an existing directory` | make the folder that `-o` names the parent of |
| `<path> checksum differs from manifest.toml` | the archive was changed after pwn-broker wrote it |
| `selection names <path>, which is held back` | remove that rule |
| `... differ only in case ...` or `Windows refuses the name ...` | leave one file out with a selection rule, or build on Linux |
| `cannot build report model: ...` | the archive is damaged or not one pwn-broker wrote |

# pwn-report

Private, evidence-linked reports from pwn-broker archives

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/panel-dark.svg">
  <img alt="A terminal in ~/pwn-broker/wrapped beside that folder. pwn-report build 2026-11-14_htb_forest.finished.tar.gz writes report.json, report.md and report.toml, then copies of notes.md, two screenshots, an exploit and a scan under evidence/, then SHA256SUMS, into a hidden folder beside the archive named .2026-11-14_htb_forest.finished.report.tmp- and a random end; the folder is renamed to 2026-11-14_htb_forest.finished.report, its files, grey while staged, all turn solid at once, and the command prints ok report 2026-11-14_htb_forest.finished.report. The same command again prints fail output already exists and will not be replaced, and the folder stays as it is. In the report, grep held report.md finds creds.toml, lists/, targets/dc01/creds/ and tooldata/, each held back, and report.md lights up in the folder" src="docs/assets/panel-light.svg" width="100%">
</picture>

<sub>Not a recording, and nothing typed by hand: `docs/art/make-panel.py` builds the full test archive from this repository's suite (box forest, target dc01, finished) in a folder of its own, runs this pwn-report on it there twice, and greps the report; every line and name on the panel comes from that run, and CI fails if the panel no longer matches it. The commands are typed as they would be in `~/pwn-broker/wrapped`. Left out: the random end of the hidden folder's name, and the speed: the build takes milliseconds, and is slowed here so each file can be seen.</sub>

Python 3.11 or later, standard library only, on Linux, Windows or macOS. Each release has a wheel and its SHA-256 in `SHA256SUMS.txt`. On Kali, with `pipx` (`sudo apt install pipx`):

```sh
curl -fsSLO https://github.com/Real-Fruit-Snacks/pwn-report/releases/download/v0.1.0/pwn_report-0.1.0-py3-none-any.whl
curl -fsSLO https://github.com/Real-Fruit-Snacks/pwn-report/releases/download/v0.1.0/SHA256SUMS.txt
sha256sum -c --ignore-missing SHA256SUMS.txt
pipx install ./pwn_report-0.1.0-py3-none-any.whl
```

Elsewhere, install the same wheel into a virtual environment with `python -m pip install pwn_report-0.1.0-py3-none-any.whl`. `pwn-report --version` prints `pwn-report 0.1.0`.

[pwn-broker](https://github.com/Real-Fruit-Snacks/pwn-broker) keeps a box's targets, notes, credentials and files in order, and ends with one archive. pwn-report reads that archive and writes a report folder beside it: the box, its targets and flags, a timeline taken from the archive's own records, and an index of every scan, screenshot, exploit, loot file and recording, each with its SHA-256 and a link to its copy. It never runs anything from the archive, never contacts the network, and never changes the archive. The same archive gives the same report, byte for byte.

I wanted the end of a box to leave something I can read and hand on, not only a tarball. The report is a draft and private: it states facts the archive records and links the files that prove them, and leaves the narrative to me.

## Use

```text
pwn-report build <archive> [-o <folder>] [--select <file>]
```

`<archive>` is a `<box>.finished.tar.gz` or `<box>.exported.tar.gz` that pwn-broker wrote. The report folder is made beside it, named after it, `2026-11-01_htb_forest.finished.report/`, or wherever `-o` says. An existing folder is never replaced, so a report you have edited is safe.

```text
$ pwn-report build ~/pwn-broker/wrapped/2026-11-01_htb_forest.finished.tar.gz
ok    report /home/kali/pwn-broker/wrapped/2026-11-01_htb_forest.finished.report
```

Success is that one line and exit status 0. Anything else is one `fail` line and status 1, with nothing written: the report is built in a hidden folder beside the output and renamed into place only once every file and checksum is right.

## What a report holds

```text
2026-11-01_htb_forest.finished.report/
  report.md       what to read
  report.json     the same facts as data, with every source path and SHA-256
  report.toml     what built it: versions, the archive's SHA-256, the selection's
  SHA256SUMS      the SHA-256 of every file above and below
  evidence/       copies of the scans, screenshots, exploits and notes it links
```

`report.md`, from a box pwn-broker made with one target, two flags, a credential, and a file in each of its folders, cut short:

```text
# forest — private technical report

## Review status

**Draft / unreviewed.** No publication approval, severity rating, or finding validity is implied.

It never reads `creds.toml`, `lists/`, `targets/*/creds/` or `tooldata/`. `notes.md` and every copied file are as they were and can hold passwords; keep this report private.

## Box summary

- Name: forest
- Platform: htb
- OS: windows
- Difficulty: easy
- Status: finished
- Started: 2026-11-01T00:30:00-04:00
- Finished: 2026-11-01T01:10:00-04:00
- Archive kind: finished

## Timeline

- 2026-11-01T00:35:00-04:00 — Target added: dc01
- 2026-11-01T00:40:00-04:00 — Flag recorded: user
- 2026-11-01T00:50:00-04:00 — Flag recorded: root
- 2026-11-01T00:55:00-04:00 — File first seen: targets/dc01/scans/nmap-quick.txt

## Evidence index

### dc01 / loot

#### targets/dc01/loot/ntds.dit

- ID: ev\_66dd0fef166c513eb2d3473c6c7af6e6730a0334ebae1f714bbaf42a271d475c
- Target references: dc01
- First seen: 2026-11-01T00:55:00-04:00
- Size: 12 bytes
- SHA-256: b365e739e50e5fd1b0beb3652b191523734c5b45d159ec9b071475e0492374f5
- File: not copied; loot is indexed only unless a selection includes it

### dc01 / scans

#### targets/dc01/scans/nmap-quick.txt

- ID: ev\_1b43307a4f54f0daa405a7fbdec561a6c393a6adb4036db0b1665f7f148e0513
- Target references: dc01
- First seen: 2026-11-01T00:55:00-04:00
- Size: 49 bytes
- SHA-256: b8fa8a9d6ce6e1dcb58ab96a1cc70091dd2f39d242fa62a79052dd7dbd32882b
- File: [copied](evidence/targets/dc01/scans/nmap-quick.txt)

## Not in the index

Held back, never read or copied:

- creds.toml: held back
- lists/: 10 files, held back
- targets/dc01/creds/: 1 file, held back
- tooldata/: 1 file, held back
```

Left out: the targets, the flags' values and the rest of the timeline and the index. The lines are what the code wrote for an archive that pwn-broker 0.1.11's own code made, with the paths a user called kali would see.

## What it reads, and what it never does

- **Every file the archive lists is accounted for.** Scans, screenshots and exploits are indexed and copied. Loot, recordings and a target's `files/` and `upload/` are indexed and not copied unless a selection file includes them. Anything else is listed by its path under `Not in the index`.
- **Credential files stay out.** It never reads `creds.toml`, `lists/`, `targets/*/creds/` or `tooldata/`. `notes.md` and every copied file are as they were and can hold passwords; keep this report private. Each held-back place is named with its count of files, nothing more, and a selection file that names one is refused.
- **The archive is checked, not trusted.** Every file the report uses has the size and SHA-256 the archive's manifest gives, or the build stops. Links, devices, paths that leave the box and archives past pwn-broker's own limits are refused before anything is read.
- **Nothing runs and nothing leaves the machine.** Archived files are read as bytes. There is no network code at all.

## Choosing what goes in

A selection file adds captions and alt text and decides which indexed files are copied:

```toml
schema = 1

[[rule]]
path = "targets/dc01/loot/ntds.dit"
include = true
caption = "NTDS.dit copied off DC01 with the backup operator's rights"
```

`pwn-report build <archive> --select selection.toml`. The [guide](docs/guide.md#a-selection-file) has every field, and [docs/selection.example.toml](docs/selection.example.toml) is a full one.

## Tested on

- The unit suite on Windows 11 under Python 3.13, with warnings treated as errors, including reports from archives made by pwn-broker 0.1.11's own code: a box with no targets and nothing typed at its os and difficulty, and a full box exported and finished

[docs/tested.md](docs/tested.md) is the full record: counts, versions, dates, what each run checked, and what has not been run.

## Known issues

- A private report by design: there is no public writeup mode, no redaction of notes or scans, and no secret scanning. Read [What it reads](#what-it-reads-and-what-it-never-does) before sharing one.
- No findings, severities or narrative: the report states what the archive records.
- On Windows, a path longer than 260 characters fails with the system's own message.
- Files in the archive that its manifest does not list leave no trace in the report. pwn-broker lists every file except its own bookkeeping, and warns about any whose name is not UTF-8.

The rest of the list is in [docs/tested.md](docs/tested.md#known-limits).

## License

[MIT](LICENSE).
[Guide](docs/guide.md) · [Changelog](CHANGELOG.md) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md)

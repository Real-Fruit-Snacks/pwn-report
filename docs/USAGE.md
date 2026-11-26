# pwn-report Sample Output, Selection, Tested On & Known Issues

Sample report tree and `report.md` excerpt, selection file example, tested platforms, and known issues for `pwn-report`. For full CLI options, manifest verification, and selection schema see [guide.md](guide.md); for the full test matrix see [tested.md](tested.md).

## What a Report Holds

```text
2026-11-01_htb_forest.finished.report/
  report.md       what to read
  report.json     the same facts as data, with every source path and SHA-256
  report.toml     what built it: versions, the archive's SHA-256, the selection's
  SHA256SUMS      the SHA-256 of every file above and below
  evidence/       copies of the scans, screenshots, exploits and notes it links
```

`report.md`, from a box `pwn-broker` made with one target, two flags, a credential, and a file in each of its folders, cut short:

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

## What It Reads, and What It Never Does

- **Every file the archive lists is accounted for.** Scans, screenshots and exploits are indexed and copied. Loot, recordings and a target's `files/` and `upload/` are indexed and not copied unless a selection file includes them. Anything else is listed by its path under `Not in the index`.
- **Credential files stay out.** It never reads `creds.toml`, `lists/`, `targets/*/creds/` or `tooldata/`. `notes.md` and every copied file are as they were and can hold passwords; keep this report private. Each held-back place is named with its count of files, nothing more, and a selection file that names one is refused.
- **The archive is checked, not trusted.** Every file the report uses has the size and SHA-256 the archive's manifest gives, or the build stops. Links, devices, paths that leave the box and archives past pwn-broker's own limits are refused before anything is read.
- **Nothing runs and nothing leaves the machine.** Archived files are read as bytes. There is no network code at all.

## Choosing What Goes In

A selection file adds captions and alt text and decides which indexed files are copied:

```toml
schema = 1

[[rule]]
path = "targets/dc01/loot/ntds.dit"
include = true
caption = "NTDS.dit copied off DC01 with the backup operator's rights"
```

Run `pwn-report build <archive> --select selection.toml`. See [guide.md#a-selection-file](guide.md#a-selection-file) and [selection.example.toml](selection.example.toml).

## Tested On

- Unit suite on Windows 11 (Python 3.13, warnings as errors) and Kali Rolling under WSL 2 (Python 3.14), including reports from real `pwn-broker` archives, README panel tests, and SIGTERM/SIGHUP cleanup.
- CI on every push: Ubuntu (Python 3.11–3.14), Windows Server 2025, macOS 15, `pwn-broker` compatibility job, panel job, and two reproducible builds.
- Published `v0.1.0` wheel installed standalone in Kali against `pwn-broker` boxes.

See [tested.md](tested.md) for the full record.

## Known Issues

- A private report by design: there is no public writeup mode, no redaction of notes or scans, and no secret scanning. Read [What it reads, and what it never does](#what-it-reads-and-what-it-never-does) before sharing one.
- No findings, severities or narrative: the report states what the archive records.
- On Windows, a path longer than 260 characters fails with the system's own message.
- Files in the archive that its manifest does not list leave no trace in the report.

The rest of the list is in [tested.md#known-limits](tested.md#known-limits).

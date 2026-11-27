# Security

## Supported versions

The latest release only. Fixes ship as a new SemVer tag; there are no backports.

## Reporting

Use GitHub's private vulnerability reporting on this repository: [report a vulnerability](https://github.com/Real-Fruit-Snacks/pwn-report/security/advisories/new), or Security → Advisories → Report a vulnerability. Don't open a public issue for anything that could write outside a report folder or put a credential into a report.

Include `pwn-report --version`, your Python version and system, and the command that shows the problem. Never attach a real archive or report: describe the archive's shape, or build a synthetic one, and use placeholder credentials and flags.

This is a one-person project. I read reports within a week. If it's real, the fix and the changelog entry name the problem plainly.

## What counts

- An archive that makes pwn-report write, link or overwrite anything outside the report folder it was asked to make, or replace a folder that already exists.
- Anything from `creds.toml`, `lists/`, `targets/*/creds/` or `tooldata/` that is read, copied, or reaches a report file, including the names of the files inside those folders.
- A failure that leaves a partial report folder in place, or that leaves its hidden staging folder behind without naming it.
- Archived content that is run, imported, evaluated or rendered as anything but text: a template, Markdown, HTML or a terminal escape in a file name, caption or value that takes effect in `report.md`.
- An archive past the documented limits, or one with a link, a device or a path that leaves the box, that is read anyway.
- A network request of any kind.

## What this tool handles

- The archive is untrusted. Every member is checked before anything is read: regular files and folders only, names inside one box folder, and pwn-broker's own limits on counts and sizes. Every file the report uses must match the size and SHA-256 its manifest lists.
- Held-back places are counted from the manifest and never opened.
- The report is built in a hidden folder beside the output and renamed into place only after every file has been checked against the model and `SHA256SUMS`.

## What it does not handle

- The report is private. `notes.md` and every copied file are as they were and can hold passwords: one typed into the note, one a tool printed into a scan, one on a screenshot, or one in loot a selection copied. pwn-report does not redact or scan for secrets, and never claims a report is safe to publish.
- The manifest is not signed. The checks prove an archive is the one its manifest describes, not who made it.
- Release files are checked against `SHA256SUMS.txt` from the same release, which catches a damaged download, not a replaced release.

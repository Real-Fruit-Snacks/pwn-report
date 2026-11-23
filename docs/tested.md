# What has been tested

Everything pwn-report has been run on, with the counts, versions and dates, and everything it has not. The [README](../README.md#tested-on) has the short list.

## Unit tests

- On Windows 11 with Python 3.13, the development machine, on 2026-11-23: 348 passed, 3 skipped, with warnings treated as errors and the pwn-broker compatibility tests included; without a pwn-broker checkout those 9 skip too. The 3 that skip are the README panel's, which need fonttools.
- In Kali Rolling under WSL 2, with Python 3.14.7, as a normal user, on 2026-11-23: 349 passed, 2 skipped, with the pwn-broker compatibility tests against pwn-broker 0.1.11 and the panel's tests. The 2 that skip only mean something on Windows and macOS: a backslash as a path separator, and two names that differ only in case.
- Every test blocks the network: `socket`, `http.client` and `urllib` raise if anything reaches them.
- Only synthetic archives, built in the tests with canary values in every file that must not reach a report: credentials, held-back files, loot, recordings, files the manifest does not list, and extra metadata. Each test that writes a report checks that none of them is in any of its files.

## Archives made by pwn-broker

`tests/broker/make_archives.py` makes archives with pwn-broker's own code, the way its prompt does: `create_box` and `add_target`, the box's note, `flag user`, `flag root` and `cred add` through its command dispatcher, a file in every folder a tool or the user would write to, then `export_box` and `finish_box`. On 2026-11-23, against pwn-broker 0.1.11:

- A box with no targets and nothing typed at its os and difficulty, finished: the report builds, and both read `Not recorded`.
- A full box, exported and then finished, worked across the night the clocks go back, so its times are at -04:00 before 06:00 UTC and at -05:00 after: each report builds twice to identical bytes, its timeline holds both offsets in an order that sorting the text would get wrong, and is in order by instant, every kind of evidence is indexed, the flags and the target are there, and `creds.toml`, `lists/`, `targets/dc01/creds/` and `tooldata/` are held back with no byte of their contents in any file.
- Run against the code as it was before the fixes below, the same tests failed 6 of 9, starting with `box.toml os must be a nonempty string`: the code had only ever been tested on its own fixtures.

## Review

The code was reviewed against its design and pwn-broker's archive code. What it found and what changed, each with a test that failed first:

- An empty `os` or `difficulty`, which pwn-broker writes when nothing is typed, failed the build.
- A target whose addresses were typed twice failed the build; they are now kept as recorded.
- A deflate stream that breaks inside a file's data, and a time with no UTC instant, came out as a Python traceback; both are now one `fail` line, and any unexpected error is too.
- One file with a backslash or a control character in its name failed the whole report with a message naming a manifest row, not the file; such files are now listed under `Not in the index`, and a path that leaves the box fails naming the path. The rule for member names is now the same on every system.
- A folder under `targets/` with no `target.toml` failed the build; its files are now listed under `Not in the index`.
- Names Windows refuses, and names that differ only in case or Unicode form on Windows and macOS, failed late with a message naming neither file; they now stop the build before anything is written, naming the files.
- A staging folder that could not be removed was left in silence; the `fail` line now names it.
- A path the terminal's encoding could not show crashed the `ok` line after the report was written.
- A control or format character in a name, caption or value reached `report.md`; it is shown as `?`.
- An error about a held-back file named the file inside the folder; it names the folder.
- The timeline was ordered by its text, so a box that crossed a change of clock could be out of order; it is ordered by instant.
- Each file was read back from the start of the gzip stream when the archive was not in path order; members are read in archive order.

A second review, of the whole repository before its first release, found and changed:

- CI's pwn-broker job piped the tests through `tee` without `pipefail`, so a failing test could not fail it; every step now runs under bash with `pipefail`.
- The pwn-broker box's times were all at one offset, so the clock-change test against it could not fail; the box now crosses the change.
- The privacy line named notes and scans, but exploits and screenshots are copied too, and a selection can copy loot; it now says every copied file.
- A crafted name in a `fail` line could break it in two or carry a terminal escape; control and format characters in a status line are shown as `?`.

## Building a release

With the locked build tools, two builds of the same commit gave the same sdist and wheel, byte for byte, and `release/check_wheel.py` accepted the wheel. Every workflow parses and passes `actionlint`.

## Known limits

- A private report by design: there is no public writeup mode, no redaction of notes or scans, and no secret scanning.
- No findings, severities or narrative: schema 1's `findings` is always empty.
- On Windows, a path longer than 260 characters fails with the system's own message.
- Files in the archive that its manifest does not list leave no trace in the report.
- There is no limit on the size of a file copied or hashed beyond the free space checked before writing: a box with a capture of many gigabytes in `scans/` takes as long as reading it takes. A selection rule leaves such a file out of the copy, but it is still read once to check its SHA-256.
- An archive is read as long as it takes to decompress, the members its manifest does not list included: a crafted one that decompresses to many gigabytes costs that time. A crafted manifest at its 64 MiB limit can take over a GiB of memory to parse. Both limits are pwn-broker's own.
- On Linux, another process that makes an empty folder at the output path between the last check and the rename would have it replaced, and the staged files are not flushed to disk before the rename.
- A URL in a caption or a file name stays a URL in `report.md`, and some Markdown viewers make it a link.

## Not run yet

- CI on Linux with Python 3.11 to 3.14, and on Windows and macOS: the workflows exist and run on the first push.
- Kali by hand, as a normal user.

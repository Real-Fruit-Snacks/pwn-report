# What has been tested

Everything pwn-report has been run on, with the counts, versions and dates, and everything it has not. [USAGE.md](USAGE.md#tested-on) has the short list.

## Unit tests

- On Windows 11 with Python 3.13, the development machine, on 2026-11-27, at the commit that releases v0.1.1: 554 passed, 20 skipped, with warnings treated as errors and the pwn-broker compatibility tests against pwn-broker 0.1.14; without a pwn-broker checkout those 9 skip too. Of the 20 that skip, 3 are the README panel's, which need fonttools, 11 only mean something on Linux and macOS (signals sent to the build and a folder's mode), and 6 run the workflows' own steps in bash, as GitHub's Linux runners do.
- In Kali Rolling under WSL 2, with Python 3.14.7, as a normal user, on 2026-11-27, at the same commit: 569 passed, 5 skipped, with the pwn-broker compatibility tests against pwn-broker 0.1.14, the panel's tests and the workflows' steps. The 5 that skip only mean something on Windows and macOS: a backslash as a path separator, two names that differ only in case, and three report folder names Windows refuses.
- Every test blocks the network: `socket`, `http.client` and `urllib` raise if anything reaches them.
- Only synthetic archives, built in the tests with canary values in every file that must not reach a report: credentials, held-back files, loot, recordings, files the manifest does not list, and extra metadata. Each test that writes a report checks that none of them is in any of its files.

## Archives made by pwn-broker

`tests/broker/make_archives.py` makes archives with pwn-broker's own code, the way its prompt does: `create_box` and `add_target`, the box's note, `flag user`, `flag root` and `cred add` through its command dispatcher, a file in every folder a tool or the user would write to, then `export_box` and `finish_box`. On 2026-11-23 against pwn-broker 0.1.11, and on 2026-11-27 against pwn-broker 0.1.14, which CI now checks out:

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

A third review, of the release candidate, found and changed:

- SIGTERM, which pwn-broker's timeout sends, and SIGHUP, from a closed terminal or SSH session, ended a build at once and left its staging copy of the evidence behind; they now clean up as Ctrl-C does. A stop during the cleanup, a second one or the first after a failure, cannot cut it short, and stops that land together print one line, not an error from Python as well; a signal the caller ignores, as `nohup` ignores SIGHUP, stays ignored; and the handlers are put back before the line is printed, every one of them even when a stop lands meanwhile.
- A stop that landed just after the report was renamed into place said no report was written; it reports the report. A folder that something else makes at the output meanwhile, a report from another run included, is never taken for this build's report.
- A Ctrl-C whose staging copy could not be removed said no report was written and nothing more; the line now names the copy.
- C1 control characters and line and paragraph separators were not treated as unsafe, so one in a name could split a `fail` line or reach `report.md`; they are shown as `?`, and such a file is listed under `Not in the index`, as a file whose name holds a format character, such as a zero-width joiner, now is too. A DEL character in a value made `report.toml` invalid TOML; it is escaped.
- A manifest that did not list `box.toml` was accepted; it is refused.
- A `~` in a name could strike text through in `report.md`; it is escaped.
- A file and a folder of the same name in the copy failed while writing; they stop the build before anything is written, naming both.
- A report folder name Windows refuses, such as `CON`, was not checked; it is refused by name before anything is made.
- A link or a duplicated entry inside `lists/`, `tooldata/` or a target's `creds/` was named by the file inside it; it is named only up to that place: no part of a name after `lists`, `tooldata`, `creds` or `creds.toml`, in any case, by either slash or glued on with a colon, is printed. So is a manifest row refused for not being a portable path, or for being missing, listed twice or of another size, a drive letter glued to the place's name included.
- With more than one target, building the model decompressed the archive a third time to read each `target.toml`; it reads and parses each in the checksum pass, keeping only its record, so the model is built in two passes, three when large files sort before the manifest, and no target's bytes are kept once it is read. Every address and host name in a target is kept, so a crafted archive of many full targets still took gigabytes; the target files together are now limited to 4 MiB, room for thousands of real ones. Looking up each copied file's SHA-256 walked the whole evidence list, a cost that grew with the square of the number of files; it is one lookup.
- The release workflow published a tag whose changelog heading still said `(unreleased)`, and the wheel check accepted a member named twice; both are refused, the heading matched as text. The wheel check also read the README in the wheel's metadata as if it were headers; it reads the headers alone. The panel's CI job would have passed had its tests skipped, and the panel script put this checkout's `src/` ahead of an installed pwn-report; the job now fails on a skip, and the script uses `src/` only when nothing is installed. The changelog and panel checks are run by the suite, in bash, as the workflow steps they are, and the sdist holds the workflows so that its own suite runs them too.
- A one-byte file was shown as `1 bytes`.

A fourth review, after the first release, found and changed:

- A name that begins like a Markdown block was drawn as one in `report.md`: a file at the box's root named `# Reviewed and approved` was a heading, `- -` a rule, `1. x` a numbered list and one with four leading spaces a code block, a flag with such a name the same, and a `#` at the end of a target's or a file's heading was dropped. What a value starts with is escaped where it could start a block, `#` is escaped everywhere, and a space at either end is written as `&#32;`. The tests read the lines back with markdown-it-py, a CommonMark parser: each such start, and every run of up to three of the characters a block is made of, in each place a line puts a value, and a whole report whose names start blocks beside one whose names do not.
- `report.json` held a C1 control or a format character raw, so printing it sent a name's terminal escape or right-to-left override to the terminal, and `report.toml` did the same with the box's ID. Both write one as a `\u` escape, which loads back as the same character; text in other scripts is written as it was.
- A stop that landed while the archive was read, after another run had put its report at the output, printed `ok` for that report with status 0. The build now says when it has renamed its own report into place, and only then does a stop report a report.
- Checking each file's target references made a set of every target, again for each file, so the check grew with the targets times the files: on Windows 11 with Python 3.13, an archive of 1.2 MB with 8,000 targets and 80,000 files took 13.1 s to check. It is one lookup for each reference, and the same archive takes 2.6 s. The model is still checked twice, as it is built and by what writes it: the second check is the writer's own, of whatever model it is given.
- The guide said only a NUL character in a name stops the build, while a name that leaves the box does too; the guide now says so. The build does as it did.

## CI

On the first push, on 2026-11-23, every job passed:

- The suite on Ubuntu 24.04 with Python 3.11, 3.12, 3.13 and 3.14: 450 passed, 17 skipped on each, with warnings treated as errors. The 17 are the 9 pwn-broker tests and the 3 panel tests, which have jobs of their own, and 5 that only mean something on Windows and macOS.
- The suite on Windows Server 2025 (438 passed, 29 skipped) and macOS 15 (451 passed, 16 skipped).
- The pwn-broker job, against pwn-broker 0.1.11: 9 passed. Since 2026-11-27 the job checks out pwn-broker 0.1.14: `finish` has run pwn-report by itself since 0.1.12, so 0.1.11 was older than any pwn-broker that does. The same 9 pass against 0.1.14 in Kali and on Windows, above.
- The README panel's job: 3 passed, and the panels are what `docs/art/make-panel.py` draws.
- The build job: two builds of the sdist and the wheel with the locked tools gave the same bytes, `release/check_wheel.py` accepted the wheel, and the sdist's own suite gave 450 passed, 17 skipped.
- The links check.

## Building a release

With the locked build tools, two builds of the same commit gave the same sdist and wheel, byte for byte, and `release/check_wheel.py` accepted the wheel. Every workflow parses and passes `actionlint`.

The v0.1.0 release, on 2026-11-23: the release workflow's dry run on `main` and its run for the tag built the same two files, byte for byte, and the run for the tag published them, after its suite against the built wheel gave 450 passed, 17 skipped:

- `pwn_report-0.1.0-py3-none-any.whl`: `fcf3aacda4cd07076042a3b92a7e5d9eefd966b853d74cf451d8482eaf8c446c`
- `pwn_report-0.1.0.tar.gz`: `2b011b88e9e3a80cbaaa40c4332babb8cd0f44466da388b4f4244558cff49fcb`

Downloaded from the release and checked against its `SHA256SUMS.txt`, the wheel was installed on its own in a new venv in Kali, as a user would: `pwn-report --version` printed `pwn-report 0.1.0`, and it built reports from a finished box with no targets and from a full finished box, both made by pwn-broker 0.1.11's own code; each report's `SHA256SUMS` held. On 2026-11-27 the same was done again in Kali Rolling under WSL 2, as a normal user, with boxes made by pwn-broker 0.1.14's own code: the downloaded wheel had the SHA-256 above, and it built reports from the finished box with no targets and from the full box, exported and finished; each report's `SHA256SUMS` held.

## Known limits

- A private report by design: there is no public writeup mode, no redaction of notes or scans, and no secret scanning.
- No findings, severities or narrative: schema 1's `findings` is always empty.
- On Windows, a path longer than 260 characters fails with the system's own message.
- A build ended in a way it cannot answer runs no cleanup, so its hidden `.<name>.tmp-*` folder is left beside the output with the evidence copied so far: SIGKILL on Linux and macOS, which pwn-broker's `finish` sends 5 seconds after its SIGTERM if the build is still running, and Task Manager or `taskkill /f` on Windows. Ctrl-C cleans up, as do SIGTERM and SIGHUP on Linux and macOS. In Kali, a build ended with SIGKILL while it copied six 48 MiB files left its folder, mode 0700, with four of them; ended with SIGTERM at the same point, it left nothing and exited 130.
- Files in the archive that its manifest does not list leave no trace in the report.
- There is no limit on the size of a file copied or hashed beyond the free space checked before writing: a box with a capture of many gigabytes in `scans/` takes as long as reading it takes. A selection rule leaves such a file out of the copy, but it is still read once to check its SHA-256.
- An archive is read as long as it takes to decompress, the members its manifest does not list included: a crafted one that decompresses to many gigabytes costs that time. A crafted manifest at its 64 MiB limit can take over a GiB of memory to parse. Crafted target files at their 4 MiB limit cost far less: in Kali, seven targets of near 1 MiB each of one-character non-Latin addresses, in a 1.4 MB archive, peaked at 136 MiB, and of empty addresses, in an 8 KB archive, at 83 MiB, writing an 18.7 MiB report. A crafted archive that does both costs both. The member and manifest limits are pwn-broker's own; the target files' is pwn-report's.
- On Linux, another process that makes an empty folder at the output path between the last check and the rename would have it replaced, and the staged files are not flushed to disk before the rename.
- A URL in a caption or a file name stays a URL in `report.md`, and some Markdown viewers make it a link.

## Not run yet

- Kali on its own machine or in a virtual machine. The suite's runs in Kali are under WSL 2, and so is the release's wheel as installed and run there by a normal user on 2026-11-27 ([Building a release](#building-a-release)).

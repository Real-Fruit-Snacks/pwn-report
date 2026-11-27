# Changelog

## v0.1.1 (unreleased)

- A name that begins like a Markdown block stays text in `report.md`. A file named `# Reviewed and approved`, `- -`, `1. x` or with four leading spaces, or a flag with such a name, was drawn as a heading, a rule, a list or a code block, and a `#` at the end of a heading was dropped. What a value starts with is now escaped where it could start a block, `#` is escaped everywhere, and a space at either end is written as `&#32;`.
- `report.json` writes a control or format character, or a line or paragraph separator, as a `\u` escape, and `report.toml` does the same for the box's ID. A C1 control or a right-to-left override in a box or file name used to be written raw, so printing the file sent it to the terminal. The escape loads back as the same character, and text in other scripts is still written as it is.
- A build stopped while it read the archive no longer prints `ok` for a report that another run put at the output meanwhile. It prints `fail  interrupted; no report was written` and exits 130, as for any other stop. `build_report` takes a `placed` list and adds the output to it once its own report is in place.
- Checking the model no longer takes time that grows with the number of targets times the number of files: an archive of 1.2 MB with 8,000 targets and 80,000 files took 13 seconds to check, and now takes under 3.
- The guide said only a NUL character in a name stops the build. A name that leaves the box does too, as the same guide says further down, and it now says so in both places.

## v0.1.0

The first release. `pwn-report build <archive>` turns a pwn-broker finished or exported archive into a private report folder beside it: `report.md` with the box, its targets and flags, a timeline from the archive's own records, an evidence index with each file's SHA-256 and a link to its copy, and what is held back or outside the index; `report.json` with the same facts and their sources; `report.toml`; `SHA256SUMS`; and the copied evidence. It never runs archived content, contacts the network or changes the archive, never reads `creds.toml`, `lists/`, `targets/*/creds/` or `tooldata/`, refuses an existing output folder, and gives the same bytes for the same archive. A selection file adds captions and chooses which indexed files are copied. Python 3.11 or later, standard library only.

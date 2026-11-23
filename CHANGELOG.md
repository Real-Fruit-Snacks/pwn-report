# Changelog

## v0.1.0 (unreleased)

The first release. `pwn-report build <archive>` turns a pwn-broker finished or exported archive into a private report folder beside it: `report.md` with the box, its targets and flags, a timeline from the archive's own records, an evidence index with each file's SHA-256 and a link to its copy, and what is held back or outside the index; `report.json` with the same facts and their sources; `report.toml`; `SHA256SUMS`; and the copied evidence. It never runs archived content, contacts the network or changes the archive, never reads `creds.toml`, `lists/`, `targets/*/creds/` or `tooldata/`, refuses an existing output folder, and gives the same bytes for the same archive. A selection file adds captions and chooses which indexed files are copied. Python 3.11 or later, standard library only.

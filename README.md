# pwn-report

Private, evidence-linked reports from pwn-broker archives

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/panel-dark.svg">
  <img alt="A terminal in ~/pwn-broker/wrapped beside that folder. pwn-report build 2026-11-14_htb_forest.finished.tar.gz writes report.json, report.md and report.toml, then copies of notes.md, two screenshots, an exploit and a scan under evidence/, then SHA256SUMS, into a hidden folder beside the archive named .2026-11-14_htb_forest.finished.report.tmp- and a random end; the folder is renamed to 2026-11-14_htb_forest.finished.report, its files, grey while staged, all turn solid at once, and the command prints ok report 2026-11-14_htb_forest.finished.report. The same command again prints fail output already exists and will not be replaced, and the folder stays as it is. In the report, grep held report.md finds creds.toml, lists/, targets/dc01/creds/ and tooldata/, each held back, and report.md lights up in the folder" src="docs/assets/panel-light.svg" width="100%">
</picture>

```sh
curl -fsSLO https://github.com/Real-Fruit-Snacks/pwn-report/releases/download/v0.1.1/pwn_report-0.1.1-py3-none-any.whl
curl -fsSLO https://github.com/Real-Fruit-Snacks/pwn-report/releases/download/v0.1.1/SHA256SUMS.txt
sha256sum -c --ignore-missing SHA256SUMS.txt && pipx install ./pwn_report-0.1.1-py3-none-any.whl
```

- **Usage:** `pwn-report build <archive> [-o <folder>] [--select <file>]` — writes `report.md`, `report.json`, `report.toml`, `SHA256SUMS`, and linked `evidence/` atomically beside the archive without overwriting existing reports.
- **Privacy boundary:** It never reads `creds.toml`, `lists/`, `targets/*/creds/` or `tooldata/`. `notes.md` and every copied file are as they were and can hold passwords; keep this report private.
- **Zero network, deterministic output:** Pure Python 3.11+ standard library; checks every file the report uses against the size and SHA-256 the manifest lists, and produces byte-identical reports for identical archives.
- **Automatic in pwn-broker:** Run `tool install report` in [pwn-broker](https://github.com/Real-Fruit-Snacks/pwn-broker) (via [pwn-shop](https://github.com/Real-Fruit-Snacks/pwn-shop)) so `finish` builds the report automatically beside the archive.

## Documentation

- [Project Page (pwn handbook)](https://real-fruit-snacks.github.io/pwn-report/)
- [Sample Report, Selection Rules & Known Issues](docs/USAGE.md)
- [Full CLI & Selection Guide](docs/guide.md) · [Tested Record & Limits](docs/tested.md)
- [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

## License

[MIT](LICENSE)

# Contributing

Small project, light process.

## Reporting a problem

Use the bug form, with `pwn-report --version`, your Python version and system, the command, and what it printed. Remove real credentials, flags, addresses and file names first, and never attach a real archive or report.

## Setting up and testing

```sh
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q -W error
```

The suite blocks the network in every test and uses only synthetic archives with canary values. Never add real box data to it.

The tests in `tests/test_broker_compat.py` build reports from archives that pwn-broker's own code makes, and skip unless `PWN_REPORT_BROKER_SRC` names a pwn-broker checkout. They run its `tests/broker/make_archives.py` under the Python in `PWN_REPORT_BROKER_PYTHON` (this one by default), which needs pwn-broker's dependencies; CI installs pwn-broker into the same environment:

```sh
git clone https://github.com/Real-Fruit-Snacks/pwn-broker ../pwn-broker
.venv/bin/pip install ../pwn-broker
PWN_REPORT_BROKER_SRC=../pwn-broker .venv/bin/python -m pytest -q tests/test_broker_compat.py
```

## Changing something

1. Branch from `main`.
2. Write the test first. A change to behaviour comes with a test that fails without it.
3. No dependencies: the package uses the standard library only, and stays that way.
4. Add a line to `CHANGELOG.md` under the version being worked on.

Rules that matter to a change:

- The archive is untrusted. Read it as bytes, check before reading, and never extract it to disk or run, import or evaluate anything in it.
- `creds.toml`, `lists/`, `targets/*/creds/` and `tooldata/` are never opened.
- The same inputs give the same bytes: sort explicitly, write LF, take no time from the clock, use nothing random.
- A failure leaves nothing behind and prints one line. Status lines are lowercase and plain, start with `ok` or `fail`, and name the next step when there is one.
- A change to what a report holds changes the model's schema tests, `docs/guide.md` and the README together.

## Commits

One short, plain line in the imperative: `Keep a target's repeated addresses as recorded`. No prefix such as `docs:` or `fix:`, though a few commits in the history carry one, and no trailing full stop. Say more in the PR if it needs it.

## Cutting a release

1. Set `__version__` in `src/pwn_report/__init__.py`; it is the only place the version is written.
2. Change the top heading of `CHANGELOG.md` to the version and drop `(unreleased)`, for example `## v0.1.0`. The notes under it become the release notes.
3. Set the version in the install lines of `README.md`, `docs/guide.md` and `docs/index.html`, and the example in `.github/ISSUE_TEMPLATE/bug.yml`; `git grep -n 'pwn_report-0\.1\.0\|v0\.1\.0\|pwn-report 0\.1\.0'`, with the old version, finds them.
4. Commit, run the `release` workflow by hand on `main` as a dry run, then tag and push: `git tag v0.1.0 && git push origin main v0.1.0`.

The `release` workflow fails if the tag is not `v` and three dot-separated numbers, or not the package version. It builds the sdist and the wheel from `release/build-requirements.lock` with hashes required, records their SHA-256, checks the wheel with `release/check_wheel.py`, runs the suite against the installed wheel, and publishes the wheel, the sdist and `SHA256SUMS.txt` from a second job that runs none of the repository's code and refuses a file whose SHA-256 differs. Started by hand, it is a dry run: every step runs but the one that publishes. Two builds of the same commit give the same bytes, so the dry run's SHA-256 is the release's.

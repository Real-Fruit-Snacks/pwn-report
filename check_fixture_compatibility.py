"""Development-only compatibility check; the pytest suite never imports Broker."""

from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT.parent / "pwn-broker" / "src"))

from fixtures import BOX_ID, LATER, make_archive  # noqa: E402
from pwn_broker.archive import peek_folder, verify  # noqa: E402

CASES = (
    ("H01 minimal", {}),
    ("H02 full", {"full": True}),
    ("H03 finished", {"full": True, "kind": "finished", "finished": LATER}),
    ("H04 exported with finished time", {"kind": "exported", "finished": LATER}),
    ("H04 finished without finished time", {"kind": "finished"}),
)

with tempfile.TemporaryDirectory(prefix="fixture-check-", dir=ROOT) as temporary:
    for index, (label, options) in enumerate(CASES):
        fixture = make_archive(Path(temporary) / f"{index}.tar.gz", **options)
        verify(fixture.path)
        assert peek_folder(fixture.path) == BOX_ID
        assert fixture.archive_sha256 == fixture.model["source"]["archive"]["sha256"]
        print(f"Broker accepted {label} fixture: {len(fixture.records)} listed files")

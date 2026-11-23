"""Sparse and special tar members, represented only as synthetic metadata."""

from __future__ import annotations

import gzip
import io
import tarfile

import pytest

from pwn_report import ReportError, build_model

from fixtures import BOX_ID, add_members, make_archive


def _reject(path, match):
    before = path.read_bytes()
    with pytest.raises(ReportError, match=match):
        build_model(path)
    assert path.read_bytes() == before


def _sparse_header(name: str, real_size: int) -> bytes:
    # An old GNU sparse entry: a header claiming real_size with no stored data.
    info = tarfile.TarInfo(name)
    info.type = tarfile.GNUTYPE_SPARSE
    block = bytearray(info.tobuf(tarfile.GNU_FORMAT))
    block[386:410] = tarfile.itn(0, 12, tarfile.GNU_FORMAT) + tarfile.itn(0, 12, tarfile.GNU_FORMAT)
    block[483:495] = tarfile.itn(real_size, 12, tarfile.GNU_FORMAT)
    block[148:156] = b"        "
    block[148:156] = b"%06o\0 " % tarfile.calc_chksums(bytes(block))[0]
    return bytes(block)


def _sparse_archive(destination, members):
    plain = io.BytesIO()
    with tarfile.open(fileobj=plain, mode="w") as tar:
        add_members(tar, members)
    body = plain.getvalue().rstrip(b"\0")
    body += b"\0" * (-len(body) % 512)
    body += _sparse_header(f"{BOX_ID}/sparse.bin", 64 * 1024**2) + b"\0" * 1024
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
            zipped.write(body)
    return destination


def test_sparse_member_is_rejected_before_its_claimed_data_is_read(tmp_path):
    source = make_archive(tmp_path / "source" / "source.tar.gz")
    original = source.path.read_bytes()
    archive = _sparse_archive(tmp_path / "mutated" / "sparse.tar.gz", source.members)

    with tarfile.open(archive, "r:gz") as tar:
        sparse = tar.getmember(f"{BOX_ID}/sparse.bin")
        assert sparse.issparse() and sparse.size == 64 * 1024**2

    _reject(archive, "sparse")
    assert source.path.read_bytes() == original
    assert not (tmp_path / "sparse.bin").exists()


@pytest.mark.parametrize(
    "member_type",
    [tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE],
    ids=["fifo", "character-device", "block-device"],
)
def test_special_members_are_rejected_without_creating_devices(tmp_path, member_type):
    source = make_archive(tmp_path / "source" / "source.tar.gz")
    original = source.path.read_bytes()
    archive = tmp_path / "mutated" / "special.tar.gz"

    def write(tar):
        add_members(tar, source.members)
        info = tarfile.TarInfo(f"{BOX_ID}/special-member")
        info.type = member_type
        info.mtime = 0
        tar.addfile(info)

    from fixtures import write_raw_archive

    write_raw_archive(archive, write)
    _reject(archive, "is not a regular file or folder")
    assert source.path.read_bytes() == original
    assert not (tmp_path / "special-member").exists()

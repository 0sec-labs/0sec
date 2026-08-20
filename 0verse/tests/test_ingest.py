"""Stage-1 triage runs dependency-free against whatever ELF the CI host has."""

import shutil
from pathlib import Path

import pytest

from zeroverse.ingest import triage


def _an_elf() -> str | None:
    for name in ("ls", "cat", "true"):
        p = shutil.which(name)
        if not p:
            continue
        with Path(p).open("rb") as f:
            if f.read(4) == b"\x7fELF":
                return p
    return None


@pytest.mark.skipif(_an_elf() is None, reason="no ELF binary on host (e.g. macOS)")
def test_triage_system_elf():
    t = triage(_an_elf())
    assert t.fmt == "ELF"
    assert t.bits in (32, 64)
    assert t.arch != "unknown"
    assert set(t.mitigations) == {"nx", "pie", "relro", "canary"}


def test_triage_garbage(tmp_path):
    p = tmp_path / "junk.bin"
    p.write_bytes(b"not a binary at all")
    t = triage(p)
    assert t.fmt == "unknown"

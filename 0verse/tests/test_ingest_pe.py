"""Stage-1 PE triage (#20) — dependency-free on a committed PE32+ x86-64 fixture."""

from __future__ import annotations

from pathlib import Path

from zeroverse.ingest import triage

FIXTURE = Path(__file__).parent / "fixtures" / "pe_overflow_x64.exe"


def test_triage_pe32plus_x86_64() -> None:
    t = triage(FIXTURE)
    assert t.fmt == "PE"
    assert t.arch == "x86-64"
    assert t.bits == 64
    assert t.endian == "little"
    assert t.kind == "EXEC"
    # PE mitigation keys (NX/ASLR/CFG/canary), distinct from the ELF/Mach-O sets.
    assert set(t.mitigations) == {"nx", "aslr", "cfg", "canary"}


def test_pe_dllcharacteristics_parsed() -> None:
    t = triage(FIXTURE)
    # mingw-w64 links with DEP (NX) + ASLR by default.
    assert t.mitigations["nx"] is True
    assert t.mitigations["aslr"] is True


def test_pe_summary_renders() -> None:
    t = triage(FIXTURE)
    s = t.summary()
    assert "PE" in s and "x86-64" in s

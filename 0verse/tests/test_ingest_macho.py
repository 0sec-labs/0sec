"""Stage-1 Mach-O triage (#18) — runs dependency-free on a committed arm64 fixture."""

from __future__ import annotations

from pathlib import Path

from zeroverse.ingest import triage

FIXTURE = Path(__file__).parent / "fixtures" / "iokit_userclient_arm64.macho"


def test_triage_arm64_macho_object() -> None:
    t = triage(FIXTURE)
    assert t.fmt == "Mach-O"
    assert t.arch == "arm64"
    assert t.bits == 64
    assert t.endian == "little"
    assert t.kind == "OBJECT"
    assert set(t.mitigations) == {"nx", "pie", "canary"}


def test_macho_summary_renders() -> None:
    t = triage(FIXTURE)
    s = t.summary()
    assert "Mach-O" in s and "arm64" in s

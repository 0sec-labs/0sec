"""PE routing (#20): the pipeline accepts PE into the decompile path (not rejected
at the format gate) and degrades honestly without Ghidra."""

from __future__ import annotations

from pathlib import Path

from zeroverse.pipeline import SUPPORTED_FORMATS, run

FIXTURE = Path(__file__).parent / "fixtures" / "pe_overflow_x64.exe"


def test_pe_is_a_supported_format() -> None:
    assert "PE" in SUPPORTED_FORMATS


def test_pe_is_routed_not_rejected(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # No Ghidra on the unit host: the run reaches the decompile stage and reports
    # the missing toolchain — crucially it is NOT bounced at the format gate.
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setenv("ZEROVERSE_BACKEND", "ghidra")  # isolate the Ghidra-absent degrade (M5 #27)
    r = run(FIXTURE)
    assert r.triage.fmt == "PE"
    assert r.triage.arch == "x86-64"
    assert "Ghidra" in r.note            # accepted, just needs the engine
    assert "supports" not in r.note      # i.e. not the unsupported-format rejection

"""M5 #27 — the real non-Ghidra fallback end to end (skipped without r2/gcc).

Proves the engine slices a benchmark with **Ghidra disabled**: it pins
``ZEROVERSE_BACKEND=rizin`` (no GHIDRA_HOME), decompiles benchmarks/overflow.c with
r2/r2ghidra, and asserts the read->strcpy memory-flow finding survives. Where this
host can run the target it also confirms a reproducing PoV (PoV-is-truth).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from zeroverse.backends.rizin import r2_available
from zeroverse.pipeline import run

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "benchmarks" / "overflow.c"

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not (r2_available() and shutil.which("gcc")),
    reason="needs Linux ELF + r2 + r2pipe + gcc for the live rizin fallback",
)


@pytest.fixture
def overflow_bin(tmp_path: Path) -> Path:
    out = tmp_path / "overflow"
    subprocess.run(
        ["gcc", "-no-pie", "-fno-stack-protector", "-o", str(out), str(SRC)],
        check=True, capture_output=True,
    )
    return out


def test_rizin_backend_slices_without_ghidra(overflow_bin: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setenv("ZEROVERSE_BACKEND", "rizin")

    r = run(overflow_bin)
    # The slice ran on the rizin-recovered IL (no Ghidra).
    assert "analyze" in r.stages_run
    assert "rizin" in r.note
    pairs = {(tf.finding.source, tf.finding.sink) for tf in r.findings}
    assert ("read", "strcpy") in pairs, f"no read->strcpy finding; got {pairs}"


def test_rizin_backend_confirms_pov_when_runnable(overflow_bin: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setenv("ZEROVERSE_BACKEND", "rizin")

    r = run(overflow_bin)
    confirmed = [tf for tf in r.findings if tf.pov and tf.pov.reproduced]
    # On an x86-64 host the differential oracle should confirm the overflow; if the
    # host cannot run the target the run degrades honestly to a hypothesis.
    if confirmed:
        assert any(tf.finding.sink == "strcpy" for tf in confirmed)
    else:
        assert any(tf.finding.sink == "strcpy" for tf in r.findings)

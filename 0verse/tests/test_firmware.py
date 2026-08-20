"""MIPS/ARM firmware lane (#21): firmware-arch classification, ELF symbol lookup,
the Qiling differential confirm (fake + real backend), and the binwalk unpack."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

import pytest

from zeroverse import firmware
from zeroverse.abi import AAPCS32, AAPCS64, MIPS_O32, MSVC_X64, SYSV_X86_64
from zeroverse.analyze import Finding
from zeroverse.preflight import BudgetTracker, RunBudget

MIPS_FIXTURE = Path(__file__).parent / "fixtures" / "mips_parse_o32.elf"


# --- a fake Qiling backend so the differential logic is unit-tested AFL/UC-free --

class FakeQiling:
    """Deterministic backend: a call 'faults' only when the input passes the magic
    gate AND overruns the buffer (len > threshold) — exactly the gated-overflow
    shape, without Unicorn."""

    def __init__(self, threshold: int = 32, magic: bytes = b"") -> None:
        self.threshold = threshold
        self.magic = magic
        self.calls: list[bytes] = []

    def emulate_call(
        self, binary: object, func_addr: int, input_bytes: bytes, *, abi: object
    ) -> firmware.QilingResult:
        self.calls.append(input_bytes)
        gated = input_bytes.startswith(self.magic) if self.magic else True
        crash = gated and len(input_bytes) > self.threshold
        return firmware.QilingResult(
            crashed=crash,
            reached_end=not crash,
            executed=True,
            exception="UcError: UC_ERR_WRITE_UNMAPPED" if crash else "",
        )


class SlowQiling:
    def emulate_call(
        self,
        binary: object,
        func_addr: int,
        input_bytes: bytes,
        *,
        abi: object,
        timeout: float | None = None,
    ) -> firmware.QilingResult:
        time.sleep(0.2)
        return firmware.QilingResult(crashed=True, reached_end=False, executed=True)


def _finding() -> Finding:
    return Finding(
        source="read", sink="memcpy", function="parse_record",
        source_addr=0, sink_addr=0x100, path_len=0,
    )


def test_is_firmware_arch() -> None:
    assert firmware.is_firmware_arch(MIPS_O32)
    assert firmware.is_firmware_arch(AAPCS64)
    assert not firmware.is_firmware_arch(MSVC_X64)
    assert not firmware.is_firmware_arch(SYSV_X86_64)
    assert not firmware.is_firmware_arch(None)


def test_maybe_qiling_runner_tracks_availability() -> None:
    assert firmware.maybe_qiling_runner(MIPS_O32) is firmware.qiling_available()
    assert firmware.maybe_qiling_runner(MSVC_X64) is False  # never a firmware arch


def test_prefers_qiling_routing(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Force "qiling installed" so routing logic is tested independent of the host.
    monkeypatch.setattr(firmware, "qiling_available", lambda: True)
    # MIPS/ARM prefer the Qiling lane even when a bare static ELF is runnable.
    assert firmware.prefers_qiling(MIPS_O32, runnable=True)
    assert firmware.prefers_qiling(AAPCS32, runnable=True)
    # aarch64 keeps its native/AFL path when runnable, Qiling only as a fallback.
    assert not firmware.prefers_qiling(AAPCS64, runnable=True)
    assert firmware.prefers_qiling(AAPCS64, runnable=False)
    # Non-firmware arches never route through Qiling.
    assert not firmware.prefers_qiling(MSVC_X64, runnable=False)
    assert not firmware.prefers_qiling(None, runnable=False)


def test_qiling_confirm_differential_with_fake_backend() -> None:
    # The confirm path gates on real qiling availability before invoking even a
    # fake backend, so SKIP (not fail) when qiling isn't installed (CI has none).
    pytest.importorskip("qiling")
    be = FakeQiling(threshold=32, magic=b"MIP!")
    pov = firmware.qiling_confirm(
        _finding(), "/no/such/bin", MIPS_O32, 0x100, seeds=[b"MIP!"], backend=be
    )
    assert pov is not None and pov.reproduced
    assert "SIGSEGV" in pov.crash_class
    assert pov.dedup_bucket
    assert "differential" in pov.diff_allocator


def test_qiling_confirm_no_false_positive_on_wrong_gate() -> None:
    # Wrong magic prefix → the gate is never crossed → no fault → no PoV.
    be = FakeQiling(threshold=32, magic=b"MIP!")
    pov = firmware.qiling_confirm(
        _finding(), "/no/such/bin", MIPS_O32, 0x100, seeds=[b"WRONG"], backend=be
    )
    assert pov is None


def test_qiling_confirm_rejects_input_that_always_faults() -> None:
    # A function that faults even on the tiny control input is not a controllable
    # overflow — the differential rejects it (no PoV).
    be = FakeQiling(threshold=0, magic=b"")
    pov = firmware.qiling_confirm(
        _finding(), "/no/such/bin", MIPS_O32, 0x100, seeds=[b""], backend=be
    )
    assert pov is None


def test_qiling_adapter_is_bounded_by_run_deadline(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(firmware, "qiling_available", lambda: True)
    budget = BudgetTracker.start(
        RunBudget(
            attempt_limit=2,
            unknown_sink_oracle_attempts=0,
            deadline_monotonic=time.monotonic() + 0.03,
        )
    )
    started = time.monotonic()

    pov = firmware.qiling_confirm(
        _finding(),
        "/no/such/bin",
        MIPS_O32,
        0x100,
        backend=SlowQiling(),
        budget=budget,
    )

    assert pov is None
    assert time.monotonic() - started >= 0.18


def test_qiling_direct_helper_rejects_disabled_executor(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from zeroverse.sandbox_exec import DisabledExecutor, reset_executor, set_executor

    class TrapQiling:
        def emulate_call(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            raise AssertionError("Qiling ran without local authorization")

    monkeypatch.setattr(firmware, "qiling_available", lambda: True)
    set_executor(DisabledExecutor("disabled for test"))
    try:
        pov = firmware.qiling_confirm(
            _finding(),
            "/no/such/bin",
            MIPS_O32,
            0x100,
            backend=TrapQiling(),
        )
    finally:
        reset_executor()

    assert pov is None


def test_qiling_confirm_degrades_without_ra_reg() -> None:
    # SysV x86-64 has no return-address register to seed → honest None.
    be = FakeQiling(threshold=32)
    pov = firmware.qiling_confirm(
        _finding(), "/no/such/bin", SYSV_X86_64, 0x100, seeds=[b""], backend=be
    )
    assert pov is None


def test_elf_function_addr_on_mips_fixture() -> None:
    addr = firmware.elf_function_addr(MIPS_FIXTURE, "parse_record")
    assert addr is not None and addr > 0
    assert firmware.elf_function_addr(MIPS_FIXTURE, "no_such_symbol") is None


# --- real Qiling engine on the committed MIPS fixture (skipped if not installed) -

@pytest.mark.skipif(not firmware.qiling_available(), reason="qiling not installed")
def test_qiling_real_mips_reachability_and_crash() -> None:
    addr = firmware.elf_function_addr(MIPS_FIXTURE, "parse_record")
    assert addr is not None
    control = firmware.emulate_call(MIPS_FIXTURE, addr, b"MIP!", abi=MIPS_O32)
    trigger = firmware.emulate_call(MIPS_FIXTURE, addr, b"MIP!" + b"A" * 512, abi=MIPS_O32)
    assert control.executed and control.reached_end and not control.crashed
    assert trigger.executed and trigger.crashed

    pov = firmware.qiling_confirm(_finding(), MIPS_FIXTURE, MIPS_O32, addr, seeds=[b"MIP!"])
    assert pov is not None and pov.reproduced
    assert "SIGSEGV" in pov.crash_class


@pytest.mark.skipif(not firmware.binwalk_available(), reason="binwalk not installed")
def test_binwalk_unpack_signature_scan() -> None:
    with tempfile.TemporaryDirectory() as td:
        res = firmware.unpack_firmware(MIPS_FIXTURE, td, extract=False)
    assert res.ok
    # binwalk recognizes the ELF signature in the blob.
    assert any("ELF" in s for s in res.signatures)


def test_unpack_firmware_honest_when_binwalk_missing(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(firmware, "binwalk_available", lambda: False)
    with tempfile.TemporaryDirectory() as td:
        res = firmware.unpack_firmware(MIPS_FIXTURE, td)
    assert not res.ok
    assert "binwalk" in res.note

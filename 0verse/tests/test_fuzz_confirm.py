"""Fuzz crash -> PoV bridge: reuses the M1 differential-allocator oracle (#6)."""

from __future__ import annotations

import pytest

from zeroverse import oracle
from zeroverse.fuzz.confirm import confirm_crash


def _diff(real_heap: bool, stock_crash: bool, guard_crash: bool) -> oracle.DiffAllocVerdict:
    return oracle.DiffAllocVerdict(
        stock=oracle.RunResult(crashed=stock_crash, signal="SIGSEGV" if stock_crash else ""),
        guard=oracle.RunResult(crashed=guard_crash, signal="SIGSEGV" if guard_crash else ""),
        real_heap_bug=real_heap,
        both_crash=stock_crash and guard_crash,
    )


def test_confirm_silent_heap_bug_carries_guard_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # clean under stock, faults under guard -> real silent heap OOB
    monkeypatch.setattr(
        oracle, "differential_allocator",
        lambda *a, **k: _diff(real_heap=True, stock_crash=False, guard_crash=True),
    )
    monkeypatch.setattr(oracle, "run_casr_gdb", lambda *a, **k: None)
    pov = confirm_crash("/tmp/replay", b"REC0\xffAAAA", function="parse_record")
    assert pov is not None
    assert pov.reproduced
    assert pov.env  # guard env embedded so the replay reproduces natively
    assert "clean->crash" in pov.diff_allocator


def test_confirm_threads_planned_native_compiler_to_guard_builds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    differential_calls: list[dict[str, object]] = []
    guard_calls: list[dict[str, object]] = []

    def fake_differential(*args, **kwargs):  # type: ignore[no-untyped-def]
        differential_calls.append(kwargs)
        return _diff(real_heap=True, stock_crash=False, guard_crash=True)

    def fake_guard(*args, **kwargs):  # type: ignore[no-untyped-def]
        guard_calls.append(kwargs)
        return {"LD_PRELOAD": "/planned/guard.so"}

    monkeypatch.setattr(oracle, "differential_allocator", fake_differential)
    monkeypatch.setattr(oracle, "confirm_guard_env", fake_guard)
    monkeypatch.setattr(oracle, "run_casr_gdb", lambda *a, **k: None)

    pov = confirm_crash(
        "/tmp/replay",
        b"boom",
        native_compiler_path="/planned/native-cc",
        compiler_resolved=True,
    )

    assert pov is not None
    assert differential_calls[0]["compiler_path"] == "/planned/native-cc"
    assert guard_calls[0]["compiler_path"] == "/planned/native-cc"
    assert differential_calls[0]["compiler_resolved"] is True
    assert guard_calls[0]["compiler_resolved"] is True


def test_confirm_loud_stack_smash_no_guard_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        oracle,
        "differential_allocator",
        lambda *a, **k: _diff(real_heap=False, stock_crash=True, guard_crash=True),
    )
    monkeypatch.setattr(oracle, "run_casr_gdb", lambda *a, **k: None)
    pov = confirm_crash("/tmp/replay", b"A" * 200)
    assert pov is not None
    assert pov.env == {}  # already faults under stock; no guard env needed


def test_confirm_rejects_unreproducible(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        oracle, "differential_allocator",
        lambda *a, **k: _diff(real_heap=False, stock_crash=False, guard_crash=False),
    )
    assert confirm_crash("/tmp/replay", b"benign") is None

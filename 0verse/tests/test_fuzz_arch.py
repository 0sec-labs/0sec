"""Cross-arch AFL++ QEMU-mode selection (#19) — the trace-resolution + AFL_PATH
plumbing that lets the host fuzz an aarch64 ELF under qemu-user."""

from __future__ import annotations

from pathlib import Path

import pytest

from zeroverse.fuzz import aflpp
from zeroverse.fuzz.aflpp import (
    AflConfig,
    _cpu_target,
    _prepare_cross_afl_path,
    afl_qemu_available,
    afl_qemu_trace_path,
)


def test_cpu_target_maps_canonical_arch() -> None:
    assert _cpu_target("aarch64") == "aarch64"
    assert _cpu_target("arm") == "arm"
    assert _cpu_target("x86-64") == "x86_64"


def test_afl_config_default_arch_is_host() -> None:
    assert AflConfig().qemu_arch == ""


def test_trace_path_env_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = tmp_path / "afl-qemu-trace-aarch64"
    fake.write_text("#!/bin/true\n")
    fake.chmod(0o755)
    monkeypatch.setenv("ZEROVERSE_AFL_QEMU_AARCH64", str(fake))
    assert afl_qemu_trace_path("aarch64") == str(fake)
    assert afl_qemu_available("aarch64") is True


def test_afl_qemu_unavailable_for_missing_arch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ZEROVERSE_AFL_QEMU_SPARC64", raising=False)
    monkeypatch.setattr(aflpp.shutil, "which", lambda _n: None)
    # a made-up cpu with no trace anywhere → not available
    assert afl_qemu_trace_path("sparc64") is None


def test_prepare_cross_afl_path_links_trace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = tmp_path / "afl-qemu-trace-aarch64"
    fake.write_text("#!/bin/true\n")
    fake.chmod(0o755)
    monkeypatch.setenv("ZEROVERSE_AFL_QEMU_AARCH64", str(fake))
    d = _prepare_cross_afl_path("aarch64", tmp_path)
    assert d is not None
    link = Path(d) / "afl-qemu-trace"
    assert link.exists()                       # AFL_PATH dir holds the exact name
    assert link.resolve() == fake.resolve()

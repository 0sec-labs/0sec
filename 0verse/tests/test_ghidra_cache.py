from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

from zeroverse.atomic_store import AtomicObjectStore, canonical_json_bytes, sha256_bytes
from zeroverse.backends import ghidra
from zeroverse.backends.ghidra import GhidraAdapter, ProgramMeta


def _install_fake_pyghidra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        sys.modules,
        "pyghidra",
        types.SimpleNamespace(start=lambda *, install_dir: None),
    )


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"binary")
    home = tmp_path / "ghidra"
    (home / "Ghidra").mkdir(parents=True)
    properties = home / "Ghidra" / "application.properties"
    properties.write_text("application.version=11.2\n")
    return binary, home, properties


def test_ghidra_cache_resumes_only_same_full_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, home, properties = _fixture(tmp_path)
    cache = tmp_path / "cache"
    calls = 0

    def extract(path: str | Path, timeout: int):
        nonlocal calls
        calls += 1
        return [], ProgramMeta(note=f"call={calls};timeout={timeout}")

    _install_fake_pyghidra(monkeypatch)
    monkeypatch.setattr(ghidra, "_extract", extract)

    first = GhidraAdapter.analyze(binary, ghidra_home=str(home), timeout=10, cache_dir=cache)
    resumed = GhidraAdapter.analyze(binary, ghidra_home=str(home), timeout=10, cache_dir=cache)
    assert calls == 1
    assert resumed.meta.note == first.meta.note
    objects = list((cache / "ghidra").glob("[0-9a-f][0-9a-f]/*.json"))
    assert len(objects) == 1
    assert len(objects[0].stem) == 64

    GhidraAdapter.analyze(binary, ghidra_home=str(home), timeout=11, cache_dir=cache)
    properties.write_text("application.version=11.3\n")
    GhidraAdapter.analyze(binary, ghidra_home=str(home), timeout=11, cache_dir=cache)
    monkeypatch.setattr(ghidra, "_GHIDRA_EXPORT_SCHEMA", "zeroverse.ghidra-export/v2")
    GhidraAdapter.analyze(binary, ghidra_home=str(home), timeout=11, cache_dir=cache)
    assert calls == 4


def test_ghidra_corrupt_payload_is_cache_miss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, home, _ = _fixture(tmp_path)
    cache = tmp_path / "cache"
    calls = 0

    def extract(path: str | Path, timeout: int):
        nonlocal calls
        calls += 1
        return [], ProgramMeta(note=f"call={calls}")

    _install_fake_pyghidra(monkeypatch)
    monkeypatch.setattr(ghidra, "_extract", extract)
    GhidraAdapter.analyze(binary, ghidra_home=str(home), timeout=10, cache_dir=cache)
    object_path = next((cache / "ghidra").glob("[0-9a-f][0-9a-f]/*.json"))
    object_path.write_text("{corrupt")

    recovered = GhidraAdapter.analyze(
        binary, ghidra_home=str(home), timeout=10, cache_dir=cache
    )
    assert calls == 2
    assert recovered.meta.note == "call=2"


def test_ghidra_payload_hash_tamper_is_cache_miss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, home, _ = _fixture(tmp_path)
    cache = tmp_path / "cache"
    calls = 0

    def extract(path: str | Path, timeout: int):
        nonlocal calls
        calls += 1
        return [], ProgramMeta(note=f"call={calls}")

    _install_fake_pyghidra(monkeypatch)
    monkeypatch.setattr(ghidra, "_extract", extract)
    GhidraAdapter.analyze(binary, ghidra_home=str(home), timeout=10, cache_dir=cache)
    identity = ghidra._ghidra_cache_identity(binary, str(home), 10)
    key = sha256_bytes(canonical_json_bytes(identity))
    store = AtomicObjectStore(cache, namespace="ghidra")
    value = json.loads(store.object_path(key).read_text())
    value["payload"]["meta"]["note"] = "tampered"
    store.object_path(key).write_text(json.dumps(value))

    recovered = GhidraAdapter.analyze(
        binary, ghidra_home=str(home), timeout=10, cache_dir=cache
    )
    assert calls == 2
    assert recovered.meta.note == "call=2"

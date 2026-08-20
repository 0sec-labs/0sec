from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts/browser/build-contract.py"
REVISION = "0123456789abcdef0123456789abcdef01234567"
LABEL = "//base:base_json_reader_fuzzer"


def load_helper() -> ModuleType:
    spec = importlib.util.spec_from_file_location("browser_build_contract", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fake_run(argv: list[str], *, cwd: Path) -> str:
    del cwd
    if argv[:2] == ["git", "rev-parse"]:
        return f"{REVISION}\n"
    if argv[:2] == ["git", "status"]:
        return ""
    if argv[:2] == ["gn", "refs"]:
        return f"{LABEL}\n"
    if argv[:2] == ["gn", "outputs"]:
        return "base_json_reader_fuzzer\n"
    if argv[:2] == ["clang", "--version"]:
        return "clang version fixture\n"
    raise AssertionError(argv)


def test_catalog_and_receipt_are_canonical_and_exactly_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = load_helper()
    source = tmp_path / "src"
    out = source / "out" / "0verse-asan"
    out.mkdir(parents=True)
    (source / ".git").mkdir()
    (out / "args.gn").write_text("use_libfuzzer = true\nis_asan = true\nsymbol_level = 2\n")
    artifact = out / "base_json_reader_fuzzer"
    artifact.write_bytes(b"fixture libfuzzer")
    artifact.chmod(0o750)
    catalog = out / "catalog.json"
    receipt = out / "receipt.json"
    monkeypatch.setattr(helper, "run", fake_run)

    helper.create_catalog(source, out, catalog)
    helper.create_receipt(source, out, catalog, LABEL, "asan", receipt)

    assert catalog.read_bytes() == helper.canonical_bytes(json.loads(catalog.read_bytes()))
    raw = json.loads(receipt.read_bytes())
    assert receipt.read_bytes() == helper.canonical_bytes(raw)
    assert raw["engine_configuration"] == "use_libfuzzer=true"
    assert "no FuzzTest or LPM claim" in raw["claim"]
    catalog_digest = hashlib.sha256(catalog.read_bytes()).hexdigest()
    receipt_digest = hashlib.sha256(receipt.read_bytes()).hexdigest()
    helper.verify_binding(
        receipt,
        receipt_digest,
        catalog,
        catalog_digest,
        REVISION,
        LABEL,
        artifact,
        hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "asan",
    )

    with pytest.raises(ValueError, match="exact catalog entry"):
        helper.verify_binding(
            receipt,
            receipt_digest,
            catalog,
            catalog_digest,
            REVISION,
            LABEL,
            artifact,
            hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "msan",
        )


def test_catalog_ignores_blank_gn_ref_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = load_helper()
    source = tmp_path / "src"
    out = source / "out" / "0verse-asan"
    out.mkdir(parents=True)
    (source / ".git").mkdir()
    (out / "args.gn").write_text("use_libfuzzer = true\nis_asan = true\nsymbol_level = 2\n")
    artifact = out / "base_json_reader_fuzzer"
    artifact.write_bytes(b"fixture libfuzzer")
    artifact.chmod(0o750)

    def spaced_refs(argv: list[str], *, cwd: Path) -> str:
        if argv[:2] == ["gn", "refs"]:
            return f"\n  {LABEL}  \n\n"
        return fake_run(argv, cwd=cwd)

    monkeypatch.setattr(helper, "run", spaced_refs)
    catalog = out / "catalog.json"
    helper.create_catalog(source, out, catalog)

    assert json.loads(catalog.read_bytes())["targets"] == [
        {
            "artifact_relative_to_out": "base_json_reader_fuzzer",
            "classification": "fuzz-target-candidate",
            "gn_label": LABEL,
        }
    ]


def test_binding_rejects_catalog_entry_or_noncanonical_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = load_helper()
    source = tmp_path / "src"
    out = source / "out" / "0verse-asan"
    out.mkdir(parents=True)
    (source / ".git").mkdir()
    (out / "args.gn").write_text("use_libfuzzer = true\nis_asan = true\nsymbol_level = 2\n")
    artifact = out / "base_json_reader_fuzzer"
    artifact.write_bytes(b"fixture")
    artifact.chmod(0o750)
    catalog = out / "catalog.json"
    receipt = out / "receipt.json"
    monkeypatch.setattr(helper, "run", fake_run)
    helper.create_catalog(source, out, catalog)
    helper.create_receipt(source, out, catalog, LABEL, "asan", receipt)
    raw: dict[str, Any] = json.loads(receipt.read_bytes())
    receipt.write_text(json.dumps(raw, indent=2))

    with pytest.raises(ValueError, match="not canonical"):
        helper.load_canonical(receipt, helper.RECEIPT_SCHEMA)


def test_catalog_rejects_duplicate_artifact_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = load_helper()
    source = tmp_path / "src"
    out = source / "out" / "0verse-asan"
    out.mkdir(parents=True)
    (source / ".git").mkdir()
    (out / "args.gn").write_text("use_libfuzzer = true\n")

    def duplicates(argv: list[str], *, cwd: Path) -> str:
        if argv[:2] == ["gn", "refs"]:
            return "//base:a_fuzzer\n//base:b_fuzzer\n"
        if argv[:2] == ["gn", "outputs"]:
            return "shared_fuzzer\n"
        return fake_run(argv, cwd=cwd)

    monkeypatch.setattr(helper, "run", duplicates)
    with pytest.raises(ValueError, match="duplicate"):
        helper.create_catalog(source, out, out / "catalog.json")


def test_receipt_rejects_contradictory_sanitizer_args(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = load_helper()
    source = tmp_path / "src"
    out = source / "out" / "0verse-asan"
    out.mkdir(parents=True)
    (source / ".git").mkdir()
    args_file = out / "args.gn"
    args_file.write_text("use_libfuzzer = true\nis_asan = true\nis_msan = true\n")
    artifact = out / "base_json_reader_fuzzer"
    artifact.write_bytes(b"fixture")
    artifact.chmod(0o750)
    catalog = out / "catalog.json"
    monkeypatch.setattr(helper, "run", fake_run)
    helper.create_catalog(source, out, catalog)

    with pytest.raises(ValueError, match="contradict"):
        helper.create_receipt(source, out, catalog, LABEL, "asan", out / "receipt.json")



def test_receipt_gn_contract_requires_symbolization_and_msan_runtime() -> None:
    helper = load_helper()

    with pytest.raises(ValueError, match="symbol_level=2"):
        helper.require_integer_gn_arg("symbol_level = 1\n", "symbol_level", 2)
    with pytest.raises(ValueError, match="use_prebuilt_instrumented_libraries=true"):
        helper.require_sanitizer_gn_args("is_msan = true\n", "msan")
    with pytest.raises(ValueError, match="msan_track_origins=2"):
        helper.require_sanitizer_gn_args(
            "is_msan = true\nuse_prebuilt_instrumented_libraries = true\n",
            "msan",
        )

    helper.require_sanitizer_gn_args(
        "is_msan = true\n"
        "use_prebuilt_instrumented_libraries = true\n"
        "msan_track_origins = 2\n",
        "msan",
    )

def test_catalog_uses_one_stable_args_read_for_digest_and_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = load_helper()
    source = tmp_path / "src"
    out = source / "out" / "0verse-asan"
    out.mkdir(parents=True)
    (source / ".git").mkdir()
    args_file = out / "args.gn"
    args_file.write_text("use_libfuzzer = true\nis_asan = true\nsymbol_level = 2\n")
    monkeypatch.setattr(helper, "run", fake_run)
    original = helper.stable_regular_bytes
    reads = 0

    def counted(path: Path, *, limit: int = 64 * 1024 * 1024) -> bytes:
        nonlocal reads
        if path == args_file:
            reads += 1
        return original(path, limit=limit)

    monkeypatch.setattr(helper, "stable_regular_bytes", counted)
    catalog = out / "catalog.json"
    helper.create_catalog(source, out, catalog)
    assert reads == 1
    artifact = out / "base_json_reader_fuzzer"
    artifact.write_bytes(b"fixture")
    artifact.chmod(0o750)
    helper.create_receipt(source, out, catalog, LABEL, "asan", out / "receipt.json")
    assert reads == 2


def test_contract_loader_rejects_symlinks(tmp_path: Path) -> None:
    helper = load_helper()
    target = tmp_path / "catalog.json"
    target.write_bytes(
        helper.canonical_bytes(
            {"schema_version": helper.CATALOG_SCHEMA, "targets": []}
        )
    )
    link = tmp_path / "catalog-link.json"
    link.symlink_to(target)

    with pytest.raises(OSError):
        helper.load_canonical(link, helper.CATALOG_SCHEMA)

from __future__ import annotations

import hashlib
import inspect
import json
import sys
from pathlib import Path

import pytest

import zeroverse.windows_ioctl_ghidra_export as ioctl_export
import zeroverse.windows_variant as windows_variant
from zeroverse.cli import main
from zeroverse.windows_ioctl_ghidra_export import (
    EXPORT_VERSION_V3,
    EXTRACTOR_CONFIG_SHA256,
    EXTRACTOR_PROFILE,
)
from zeroverse.windows_public_pdb import (
    PUBLIC_PDB_PRODUCER,
    PUBLIC_PDB_PROOF_LIMIT,
    PUBLIC_PDB_SCHEMA,
    PublicPdbReceipt,
    public_pdb_url,
)
from zeroverse.windows_variant import (
    ANALYSIS_RECEIPT_VERSION_V3,
    ANALYSIS_RECEIPT_VERSION_V4,
    IOCTL_ANALYSIS_PRODUCER,
    _ioctl_analysis_cache_key,
    _load_artifact,
    _public_ioctl_analysis_cache_key,
    produce_windows_ioctl_analysis_bundle,
    produce_windows_public_ioctl_analysis_bundle,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _setup_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, Path]:
    binary = tmp_path / "source.sys"
    pdb = tmp_path / "source.pdb"
    binary.write_bytes(b"MZ-real-driver")
    pdb.write_bytes(b"PDB-real-symbols")
    ghidra = tmp_path / "ghidra"
    (ghidra / "Ghidra").mkdir(parents=True)
    (ghidra / "Ghidra" / "application.properties").write_text(
        "application.version=11.4.2\n", encoding="utf-8"
    )
    pe_identity = ("00112233445566778899AABBCCDDEEFF", 1, "target.pdb")
    pdb_identity = ("00112233445566778899AABBCCDDEEFF", 1, False)
    monkeypatch.setattr(
        "zeroverse.windows_variant.pe_codeview_identity", lambda _path: pe_identity
    )
    monkeypatch.setattr(
        "zeroverse.windows_variant.pdb_codeview_identity", lambda _path: pdb_identity
    )
    # Export canonicalization is independently covered by the extractor tests;
    # this seam keeps bundle tests focused on provenance and atomic wiring.
    monkeypatch.setattr(
        "zeroverse.windows_ioctl_ghidra_export.canonical_export_bytes",
        lambda raw: (
            json.dumps(raw, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode(),
    )
    monkeypatch.setattr(
        "zeroverse.windows_ioctl_ghidra_export.analyze_windows_ioctl_driver",
        lambda binary_path, pdb_path, *, ghidra_home: _export(binary_path, pdb_path),
    )
    monkeypatch.setattr(
        "zeroverse.windows_ioctl_ghidra_export.analyze_windows_public_ioctl_driver",
        lambda binary_path, pdb_path, public_pdb_bundle, *, ghidra_home: _public_export(
            binary_path, pdb_path
        ),
    )
    return binary, pdb, ghidra


def _export(binary: Path, pdb: Path) -> dict[str, object]:
    return {
        "schema_version": EXPORT_VERSION_V3,
        "producer": "ghidra-high-pcode",
        "extractor_profile": EXTRACTOR_PROFILE,
        "extractor_config_sha256": EXTRACTOR_CONFIG_SHA256,
        "driver_sha256": _sha(binary),
        "pdb_sha256": _sha(pdb),
        "pdb_codeview_identity": "00112233445566778899AABBCCDDEEFF:1:target.pdb",
        "dispatches": [],
    }


def _public_export(binary: Path, pdb: Path) -> dict[str, object]:
    result = _export(binary, pdb)
    result["pdb_codeview_identity"] = "00112233445566778899AABBCCDDEEFF:4:stripped"
    return result


def _public_bundle(
    tmp_path: Path, binary: Path, pdb: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    guid = "00112233445566778899AABBCCDDEEFF"
    monkeypatch.setattr(
        "zeroverse.windows_public_pdb.pe_codeview_identity",
        lambda _path: (guid, 1, "target.pdb"),
    )
    monkeypatch.setattr(
        "zeroverse.windows_public_pdb.pdb_codeview_identity",
        lambda _path: (guid, 4, True),
    )
    monkeypatch.setattr(
        "zeroverse.windows_variant.pdb_codeview_identity",
        lambda _path: (guid, 4, True),
    )
    digest = _sha(pdb)
    bundle = tmp_path / "public-store" / digest
    bundle.mkdir(parents=True)
    artifact = bundle / "artifact"
    artifact.write_bytes(pdb.read_bytes())
    requested_url = public_pdb_url(binary)
    receipt = {
        "schema_version": PUBLIC_PDB_SCHEMA,
        "producer": PUBLIC_PDB_PRODUCER,
        "pe": {
            "sha256": _sha(binary),
            "size_bytes": binary.stat().st_size,
            "codeview": {"guid": guid, "age": 1, "pdb_name": "target.pdb"},
        },
        "pdb": {
            "path": "artifact",
            "sha256": digest,
            "size_bytes": artifact.stat().st_size,
            "identity": {"guid": guid, "age": 4, "stripped": True},
        },
        "source": {
            "requested_url": requested_url,
            "final_url_redacted": requested_url,
            "final_query_sha256": hashlib.sha256(b"").hexdigest(),
            "retrieved_at_utc": "2026-07-17T00:00:00+00:00",
            "http_status": 200,
            "etag": "fixture",
            "last_modified": "",
            "content_type": "application/octet-stream",
            "content_length": str(artifact.stat().st_size),
        },
        "exact_age_match": False,
        "verified_claims": [
            "pe-derived-symbol-key",
            "producer-observed-microsoft-symbol-route",
            "pdb-content-sha256",
            "pdb-guid-match",
            "pdb-stripped",
        ],
        "proof_limit": PUBLIC_PDB_PROOF_LIMIT,
    }
    (bundle / "receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return bundle


def test_public_ioctl_bundle_retains_and_reverifies_complete_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    public_bundle = _public_bundle(tmp_path, binary, pdb, monkeypatch)
    descriptor = produce_windows_public_ioctl_analysis_bundle(
        binary, public_bundle, tmp_path / "bundle", ghidra_home=ghidra
    )

    receipt_path = tmp_path / descriptor["analysis_receipt_path"]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    retained = tmp_path / "bundle" / receipt["public_pdb"]["bundle_path"]
    assert receipt["schema_version"] == ANALYSIS_RECEIPT_VERSION_V4
    assert receipt["public_pdb"]["exact_age_match"] is False
    assert receipt["pdb"]["identity"] == {
        "guid": "00112233445566778899AABBCCDDEEFF",
        "age": 4,
        "stripped": True,
    }
    assert receipt["pdb"]["identity"]["age"] != receipt["public_pdb"]["pe_age"]
    assert {path.name for path in retained.iterdir()} == {"artifact", "receipt.json"}
    assert retained.name == _sha(retained / "artifact")
    artifact = _load_artifact(descriptor, tmp_path, "artifact")
    assert artifact.pdb_identity.endswith(":4:stripped")
    assert artifact.pdb_identity != artifact.pe_codeview_identity
    assert artifact.public_pdb_receipt_sha256 == _sha(retained / "receipt.json")
    assert artifact.public_pdb_requested_url.startswith(
        "https://msdl.microsoft.com/download/symbols/"
    )
    assert artifact.public_pdb_exact_age_match is False


def test_public_ioctl_bundle_loader_rejects_route_receipt_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    public_bundle = _public_bundle(tmp_path, binary, pdb, monkeypatch)
    descriptor = produce_windows_public_ioctl_analysis_bundle(
        binary, public_bundle, tmp_path / "bundle", ghidra_home=ghidra
    )
    receipt = json.loads(
        (tmp_path / descriptor["analysis_receipt_path"]).read_text(encoding="utf-8")
    )
    route = tmp_path / "bundle" / receipt["public_pdb"]["bundle_path"] / "receipt.json"
    route_raw = json.loads(route.read_text(encoding="utf-8"))
    route_raw["exact_age_match"] = True
    route.write_text(json.dumps(route_raw), encoding="utf-8")
    with pytest.raises(ValueError, match="exact_age_match"):
        _load_artifact(descriptor, tmp_path, "artifact")


def test_public_ioctl_bundle_failure_removes_only_owned_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    public_bundle = _public_bundle(tmp_path, binary, pdb, monkeypatch)

    def fail(*args: object, **kwargs: object) -> dict[str, object]:
        raise ValueError("fixture analyzer failure")

    monkeypatch.setattr(
        "zeroverse.windows_ioctl_ghidra_export.analyze_windows_public_ioctl_driver", fail
    )
    with pytest.raises(ValueError, match="fixture analyzer failure"):
        produce_windows_public_ioctl_analysis_bundle(
            binary, public_bundle, tmp_path / "bundle", ghidra_home=ghidra
        )
    assert not (tmp_path / "bundle").exists()
    assert not list(tmp_path.glob(".bundle.tmp-*"))
    assert public_bundle.is_dir()


def test_public_ioctl_bundle_reverifies_route_after_analyzer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    public_bundle = _public_bundle(tmp_path, binary, pdb, monkeypatch)

    def mutate(
        bundled_binary: Path,
        bundled_pdb: Path,
        retained_bundle: Path,
        *,
        ghidra_home: Path,
    ) -> dict[str, object]:
        del ghidra_home
        receipt = retained_bundle / "receipt.json"
        receipt.write_text(receipt.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        return _public_export(bundled_binary, bundled_pdb)

    monkeypatch.setattr(
        "zeroverse.windows_ioctl_ghidra_export.analyze_windows_public_ioctl_driver",
        mutate,
    )
    with pytest.raises(ValueError, match="changed during analysis"):
        produce_windows_public_ioctl_analysis_bundle(
            binary, public_bundle, tmp_path / "bundle", ghidra_home=ghidra
        )


def test_public_cache_key_binds_route_receipt() -> None:
    values = ["1" * 64, "2" * 64, "11.4.2", EXTRACTOR_PROFILE, EXTRACTOR_CONFIG_SHA256]
    first = _public_ioctl_analysis_cache_key(*values, "3" * 64)
    second = _public_ioctl_analysis_cache_key(*values, "4" * 64)
    assert first != second
    assert first != _ioctl_analysis_cache_key(*values)


def test_public_analyzer_derives_age_exception_only_from_verified_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "driver.sys"
    pdb = tmp_path / "artifact"
    route_bundle = tmp_path / "route"
    route_bundle.mkdir()
    binary.write_bytes(b"MZ-driver")
    pdb.write_bytes(b"stripped-pdb")
    ghidra = tmp_path / "ghidra"
    ghidra.mkdir()
    route = PublicPdbReceipt(
        route_bundle,
        pdb,
        _sha(pdb),
        pdb.stat().st_size,
        "1" * 64,
        "https://msdl.microsoft.com/download/symbols/driver.pdb/key/driver.pdb",
        "GUID",
        1,
        "GUID",
        4,
        False,
    )
    monkeypatch.setattr(
        "zeroverse.windows_public_pdb.verify_public_pdb_receipt",
        lambda source, bundle: route,
    )
    observed: dict[str, object] = {}

    def acquire(*args: object, **kwargs: object) -> dict[str, object]:
        observed["args"] = args
        observed["kwargs"] = kwargs
        return {"raw": True}

    monkeypatch.setattr(ioctl_export, "_acquire_normalized_high_pcode_facts", acquire)
    monkeypatch.setattr(
        ioctl_export, "compile_windows_ioctl_high_pcode_facts", lambda raw: raw
    )
    assert ioctl_export.analyze_windows_public_ioctl_driver(
        binary, pdb, route_bundle, ghidra_home=ghidra
    ) == {"raw": True, "pdb_codeview_identity": "GUID:4:stripped"}
    assert observed["kwargs"] == {"public_pdb_bundle": route_bundle}
    parameters = inspect.signature(
        ioctl_export._acquire_normalized_high_pcode_facts
    ).parameters
    assert all("verified_public_identity" not in name for name in parameters)
    assert not hasattr(ioctl_export, "_acquire_normalized_high_pcode_facts_verified")

    other = tmp_path / "other.pdb"
    other.write_bytes(pdb.read_bytes())
    with pytest.raises(ValueError, match="verified route artifact"):
        ioctl_export.analyze_windows_public_ioctl_driver(
            binary, other, route_bundle, ghidra_home=ghidra
        )


def test_every_direct_acquisition_entry_rejects_unverified_stripped_pdb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "driver.sys"
    pdb = tmp_path / "artifact"
    bundle = tmp_path / "route"
    binary.write_bytes(b"MZ-driver")
    pdb.write_bytes(b"stripped-pdb")
    bundle.mkdir()
    ghidra = tmp_path / "ghidra"
    ghidra.mkdir()
    monkeypatch.setitem(sys.modules, "pyghidra", object())
    monkeypatch.setattr(
        "zeroverse.pe_symbols.pe_codeview_identity",
        lambda path: ("GUID", 1, "driver.pdb"),
    )
    monkeypatch.setattr(
        "zeroverse.pe_symbols.pdb_codeview_identity",
        lambda path: ("GUID", 4, True),
    )

    with pytest.raises(ValueError, match=r"exact matching|non-stripped"):
        ioctl_export._acquire_normalized_high_pcode_facts(binary, pdb, ghidra)
    with pytest.raises(ValueError, match=r"exact matching|non-stripped"):
        ioctl_export.analyze_windows_ioctl_driver(binary, pdb, ghidra_home=ghidra)

    def reject(source: Path, route: Path) -> PublicPdbReceipt:
        raise ValueError("route verification failed")

    monkeypatch.setattr(
        "zeroverse.windows_public_pdb.verify_public_pdb_receipt", reject
    )
    with pytest.raises(ValueError, match="route verification failed"):
        ioctl_export._acquire_normalized_high_pcode_facts(
            binary, pdb, ghidra, public_pdb_bundle=bundle
        )
    with pytest.raises(ValueError, match="route verification failed"):
        ioctl_export.analyze_windows_public_ioctl_driver(
            binary, pdb, bundle, ghidra_home=ghidra
        )


def test_ioctl_bundle_v2_round_trips_through_artifact_loader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    descriptor = produce_windows_ioctl_analysis_bundle(
        binary,
        pdb,
        tmp_path / "bundle",
        ghidra_home=ghidra,
    )

    receipt_path = tmp_path / descriptor["analysis_receipt_path"]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert descriptor["binary_path"] == "bundle/source.sys"
    assert receipt["binary_path"] == "source.sys"
    assert (tmp_path / "bundle" / "source.sys").read_bytes() == binary.read_bytes()
    assert not (tmp_path / "bundle" / "target.sys").exists()
    assert receipt["schema_version"] == ANALYSIS_RECEIPT_VERSION_V3
    assert receipt["producer"] == IOCTL_ANALYSIS_PRODUCER
    assert receipt["export_schema_version"] == EXPORT_VERSION_V3
    assert receipt["extractor_profile"] == EXTRACTOR_PROFILE
    assert receipt["extractor_config_sha256"] == EXTRACTOR_CONFIG_SHA256
    assert len(receipt["cache_key"]) == 64

    artifact = _load_artifact(descriptor, tmp_path, "artifact")
    assert artifact.binary_sha256 == descriptor["binary_sha256"]
    assert artifact.export["schema_version"] == EXPORT_VERSION_V3


def test_ioctl_bundle_rejects_non_driver_component_basename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    renamed = binary.with_suffix(".bin")
    binary.rename(renamed)
    with pytest.raises(ValueError, match=r"safe \.sys component basename"):
        produce_windows_ioctl_analysis_bundle(
            renamed, pdb, tmp_path / "bundle", ghidra_home=ghidra
        )


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("export_schema_version", "wrong/v2", "export_schema_version mismatch"),
        ("extractor_profile", "wrong-profile", "extractor_profile mismatch"),
        ("extractor_config_sha256", "0" * 64, "extractor_config_sha256 mismatch"),
        ("tool_version", "11.4.3", "cache key mismatch"),
        ("cache_key", "0" * 64, "cache key mismatch"),
    ],
)
def test_ioctl_bundle_loader_rejects_receipt_v2_contract_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    replacement: str,
    message: str,
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    descriptor = produce_windows_ioctl_analysis_bundle(
        binary,
        pdb,
        tmp_path / "bundle",
        ghidra_home=ghidra,
    )
    receipt_path = tmp_path / descriptor["analysis_receipt_path"]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt[field] = replacement
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    descriptor["analysis_receipt_sha256"] = _sha(receipt_path)

    with pytest.raises(ValueError, match=message):
        _load_artifact(descriptor, tmp_path, "artifact")


@pytest.mark.parametrize("changed_index", range(5))
def test_ioctl_cache_key_binds_every_analysis_input(changed_index: int) -> None:
    values = ["1" * 64, "2" * 64, "11.4.2", EXTRACTOR_PROFILE, EXTRACTOR_CONFIG_SHA256]
    baseline = _ioctl_analysis_cache_key(*values)
    changed = values.copy()
    changed[changed_index] += "-changed"
    assert _ioctl_analysis_cache_key(*changed) != baseline


def test_ioctl_bundle_default_invokes_dedicated_analyzer_with_path_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    observed: dict[str, object] = {}

    def analyze(
        bundled_binary: Path, bundled_pdb: Path, *, ghidra_home: Path
    ) -> dict[str, object]:
        observed["binary"] = bundled_binary
        observed["pdb"] = bundled_pdb
        observed["binary_bytes"] = bundled_binary.read_bytes()
        observed["pdb_bytes"] = bundled_pdb.read_bytes()
        observed["ghidra_home"] = ghidra_home
        return _export(bundled_binary, bundled_pdb)

    monkeypatch.setattr(
        "zeroverse.windows_ioctl_ghidra_export.analyze_windows_ioctl_driver", analyze
    )
    produce_windows_ioctl_analysis_bundle(
        binary, pdb, tmp_path / "bundle", ghidra_home=str(ghidra)
    )

    assert observed["ghidra_home"] == ghidra
    assert observed["binary_bytes"] == binary.read_bytes()
    assert observed["pdb_bytes"] == pdb.read_bytes()


def test_ioctl_analysis_bundle_cli_has_no_analyzer_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    observed: dict[str, object] = {}

    def produce(*args: object, **kwargs: object) -> dict[str, str]:
        observed["args"] = args
        observed["kwargs"] = kwargs
        return {"analysis_receipt_sha256": "a" * 64}

    monkeypatch.setattr(
        "zeroverse.windows_variant.produce_windows_ioctl_analysis_bundle", produce
    )
    rc = main(
        [
            "windows-ioctl-analysis-bundle",
            "driver.sys",
            "driver.pdb",
            "bundle",
            "--ghidra-home",
            str(tmp_path / "ghidra"),
        ]
    )
    assert rc == 0
    assert observed["kwargs"] == {"ghidra_home": str(tmp_path / "ghidra")}
    assert json.loads(capsys.readouterr().out)["analysis_receipt_sha256"] == "a" * 64


def test_public_ioctl_analysis_bundle_cli_uses_route_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    observed: dict[str, object] = {}

    def produce(*args: object, **kwargs: object) -> dict[str, str]:
        observed["args"] = args
        observed["kwargs"] = kwargs
        return {"analysis_receipt_sha256": "b" * 64}

    monkeypatch.setattr(
        "zeroverse.windows_variant.produce_windows_public_ioctl_analysis_bundle", produce
    )
    rc = main(
        [
            "windows-public-ioctl-analysis-bundle",
            "driver.sys",
            "public-store/pdb-sha",
            "bundle",
            "--ghidra-home",
            str(tmp_path / "ghidra"),
        ]
    )
    assert rc == 0
    assert observed["args"] == ("driver.sys", "public-store/pdb-sha", "bundle")
    assert observed["kwargs"] == {"ghidra_home": str(tmp_path / "ghidra")}
    assert json.loads(capsys.readouterr().out)["analysis_receipt_sha256"] == "b" * 64


def test_ioctl_bundle_api_has_no_caller_selected_analyzer() -> None:
    assert "analyzer" not in inspect.signature(produce_windows_ioctl_analysis_bundle).parameters


@pytest.mark.parametrize(("age", "stripped"), [(2, False), (1, True)])
def test_ioctl_bundle_requires_exact_full_pdb(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    age: int,
    stripped: bool,
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "zeroverse.windows_variant.pdb_codeview_identity",
        lambda _path: ("00112233445566778899AABBCCDDEEFF", age, stripped),
    )
    with pytest.raises(ValueError, match=r"non-stripped|GUID and age"):
        produce_windows_ioctl_analysis_bundle(
            binary, pdb, tmp_path / "bundle", ghidra_home=ghidra
        )


def test_ioctl_bundle_rejects_symlink_and_oversized_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    binary_link = tmp_path / "binary-link.sys"
    binary_link.symlink_to(binary)
    with pytest.raises(ValueError, match="non-symlink"):
        produce_windows_ioctl_analysis_bundle(
            binary_link, pdb, tmp_path / "symlink-bundle", ghidra_home=ghidra
        )

    binary.write_bytes(b"")
    binary.touch()
    with binary.open("r+b") as output:
        output.truncate(windows_variant._BINARY_SIZE_CAP + 1)
    with pytest.raises(ValueError, match="size cap"):
        produce_windows_ioctl_analysis_bundle(
            binary, pdb, tmp_path / "oversized-bundle", ghidra_home=ghidra
        )


@pytest.mark.parametrize("replacement", ["regular", "symlink"])
def test_ioctl_bundle_rejects_analyzer_replacement_of_retained_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replacement: str
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    external = tmp_path / "external.sys"

    def analyze(
        retained_binary: Path, retained_pdb: Path, *, ghidra_home: Path
    ) -> dict[str, object]:
        del ghidra_home
        content = retained_binary.read_bytes()
        external.write_bytes(content)
        if replacement == "symlink":
            retained_binary.unlink()
            retained_binary.symlink_to(external)
        else:
            retained_binary.write_bytes(content + b"-mutated")
        return _export(retained_binary, retained_pdb)

    monkeypatch.setattr(
        "zeroverse.windows_ioctl_ghidra_export.analyze_windows_ioctl_driver", analyze
    )
    with pytest.raises(
        (ValueError, OSError), match=r"remain a regular|mutated|not permitted|Permission denied"
    ):
        produce_windows_ioctl_analysis_bundle(
            binary, pdb, tmp_path / "bundle", ghidra_home=ghidra
        )


def test_ioctl_bundle_source_swap_during_snapshot_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    external = tmp_path / "external.pdb"
    external.write_bytes(pdb.read_bytes())
    real_snapshot = windows_variant._snapshot_file_at
    calls = 0

    def swap_after_binary(
        source: Path, directory_fd: int, name: str, label: str, size_cap: int
    ) -> str:
        nonlocal calls
        digest = real_snapshot(source, directory_fd, name, label, size_cap)
        calls += 1
        if calls == 1:
            pdb.unlink()
            pdb.symlink_to(external)
        return digest

    monkeypatch.setattr(windows_variant, "_snapshot_file_at", swap_after_binary)
    with pytest.raises(ValueError, match="non-symlink"):
        produce_windows_ioctl_analysis_bundle(
            binary, pdb, tmp_path / "bundle", ghidra_home=ghidra
        )


def test_ioctl_bundle_analyzes_retained_snapshot_when_original_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    original = binary.read_bytes()

    def analyze(
        retained_binary: Path, retained_pdb: Path, *, ghidra_home: Path
    ) -> dict[str, object]:
        del ghidra_home
        binary.write_bytes(b"MZ-source-changed-after-snapshot")
        return _export(retained_binary, retained_pdb)

    monkeypatch.setattr(
        "zeroverse.windows_ioctl_ghidra_export.analyze_windows_ioctl_driver", analyze
    )
    descriptor = produce_windows_ioctl_analysis_bundle(
        binary, pdb, tmp_path / "bundle", ghidra_home=ghidra
    )
    assert (tmp_path / descriptor["binary_path"]).read_bytes() == original


def test_ioctl_bundle_publication_race_preserves_intruder_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    destination = tmp_path / "bundle"
    observed_inode: list[int] = []

    def analyze(
        retained_binary: Path, retained_pdb: Path, *, ghidra_home: Path
    ) -> dict[str, object]:
        del ghidra_home
        destination.mkdir()
        observed_inode.append(destination.stat().st_ino)
        return _export(retained_binary, retained_pdb)

    monkeypatch.setattr(
        "zeroverse.windows_ioctl_ghidra_export.analyze_windows_ioctl_driver", analyze
    )
    with pytest.raises(FileExistsError):
        produce_windows_ioctl_analysis_bundle(
            binary, pdb, destination, ghidra_home=ghidra
        )
    assert destination.is_dir()
    assert destination.stat().st_ino == observed_inode[0]
    assert list(destination.iterdir()) == []
    assert list(tmp_path.glob(".bundle.tmp-*")) == []


def test_ioctl_bundle_parent_swap_cleanup_stays_anchored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    parent = tmp_path / "output-parent"
    moved_parent = tmp_path / "moved-output-parent"
    parent.mkdir()

    def analyze(
        retained_binary: Path, retained_pdb: Path, *, ghidra_home: Path
    ) -> dict[str, object]:
        del retained_binary, retained_pdb, ghidra_home
        parent.rename(moved_parent)
        parent.mkdir()
        (parent / "intruder-sentinel").write_text("preserve", encoding="utf-8")
        raise RuntimeError("stop after parent swap")

    monkeypatch.setattr(
        "zeroverse.windows_ioctl_ghidra_export.analyze_windows_ioctl_driver", analyze
    )
    with pytest.raises(RuntimeError, match="parent swap"):
        produce_windows_ioctl_analysis_bundle(
            binary, pdb, parent / "bundle", ghidra_home=ghidra
        )

    assert (parent / "intruder-sentinel").read_text(encoding="utf-8") == "preserve"
    assert list(moved_parent.iterdir()) == []
    assert not (parent / "bundle").exists()


def test_ioctl_bundle_rejects_symlinked_output_parent_ancestry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    alias = tmp_path / "parent-alias"
    alias.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="non-symlink"):
        produce_windows_ioctl_analysis_bundle(
            binary, pdb, alias / "bundle", ghidra_home=ghidra
        )
    assert list(real_parent.iterdir()) == []


@pytest.mark.parametrize(
    "artifact_name", ["binary_path", "ghidra_export_path", "analysis_receipt_path"]
)
def test_ioctl_bundle_loader_rejects_descriptor_symlink_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_name: str,
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    descriptor = produce_windows_ioctl_analysis_bundle(
        binary, pdb, tmp_path / "bundle", ghidra_home=ghidra
    )
    path = tmp_path / descriptor[artifact_name]
    external = tmp_path / f"external-{path.name}"
    external.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(external)
    with pytest.raises(ValueError, match="non-symlink"):
        _load_artifact(descriptor, tmp_path, "artifact")


@pytest.mark.parametrize(
    ("artifact_name", "size_cap"),
    [
        ("binary_path", windows_variant._BINARY_SIZE_CAP),
        ("ghidra_export_path", windows_variant._EXPORT_SIZE_CAP),
        ("analysis_receipt_path", windows_variant._RECEIPT_SIZE_CAP),
    ],
)
def test_ioctl_bundle_loader_rejects_oversized_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_name: str,
    size_cap: int,
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    descriptor = produce_windows_ioctl_analysis_bundle(
        binary, pdb, tmp_path / "bundle", ghidra_home=ghidra
    )
    path = tmp_path / descriptor[artifact_name]
    with path.open("r+b") as output:
        output.truncate(size_cap + 1)
    with pytest.raises(ValueError, match="size cap"):
        _load_artifact(descriptor, tmp_path, "artifact")


def test_ioctl_bundle_loader_rejects_symlink_and_oversized_pdb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    descriptor = produce_windows_ioctl_analysis_bundle(
        binary, pdb, tmp_path / "bundle", ghidra_home=ghidra
    )
    retained_pdb = tmp_path / "bundle" / "target.pdb"
    external = tmp_path / "external.pdb"
    external.write_bytes(retained_pdb.read_bytes())
    retained_pdb.unlink()
    retained_pdb.symlink_to(external)
    with pytest.raises(ValueError, match="non-symlink"):
        _load_artifact(descriptor, tmp_path, "artifact")

    retained_pdb.unlink()
    retained_pdb.write_bytes(b"")
    with retained_pdb.open("r+b") as output:
        output.truncate(windows_variant._PDB_SIZE_CAP + 1)
    with pytest.raises(ValueError, match="size cap"):
        _load_artifact(descriptor, tmp_path, "artifact")


def test_ioctl_bundle_loader_validates_private_snapshot_during_late_path_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, pdb, ghidra = _setup_inputs(tmp_path, monkeypatch)
    descriptor = produce_windows_ioctl_analysis_bundle(
        binary, pdb, tmp_path / "bundle", ghidra_home=ghidra
    )
    export_path = tmp_path / descriptor["ghidra_export_path"]

    def pdb_identity(_path: Path) -> tuple[str, int, bool]:
        export_path.write_text('{"swapped":true}', encoding="utf-8")
        return ("00112233445566778899AABBCCDDEEFF", 1, False)

    monkeypatch.setattr("zeroverse.windows_variant.pdb_codeview_identity", pdb_identity)
    artifact = _load_artifact(descriptor, tmp_path, "artifact")
    assert artifact.export["schema_version"] == EXPORT_VERSION_V3
    assert _sha(export_path) != artifact.export_sha256

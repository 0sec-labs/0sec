from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

import zeroverse.windows_ioctl_ghidra_export as ioctl_export
import zeroverse.windows_ioctl_surface_inventory as inventory
from zeroverse.cli import main
from zeroverse.windows_public_pdb import PublicPdbReceipt


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _ref(order: int, opcode: str) -> dict[str, object]:
    return {
        "function_rva": "0x3000",
        "instruction_rva": f"0x{0x3100 + order:x}",
        "pcode_order": order,
        "opcode": opcode,
    }


def _facts() -> dict[str, object]:
    reasons = [
        {
            "stage": "surface-admission",
            "owner_rva": "0x1000",
            "ref": _ref(1, "COPY"),
            "reason_code": "exact-surface-proof-unavailable",
            "detail": "registration alias uniqueness and selector polarity are unproven",
        },
        {
            "stage": "semantic-admission",
            "owner_rva": "0x1000",
            "ref": _ref(2, "RETURN"),
            "reason_code": "semantic-profile-unavailable",
            "detail": "semantic admission is outside v1",
        },
    ]
    return {
        "schema_version": inventory.RAW_VERSION,
        "driver_sha256": "1" * 64,
        "pdb_sha256": "2" * 64,
        "pdb_identity": "GUID:4:stripped",
        "pe_codeview_identity": "GUID:1:afd.pdb",
        "architecture": "x86_64",
        "pointer_size": 8,
        "image_base": "0x140000000",
        "pe_entry_point_rva": "0x1000",
        "tool": {"name": "ghidra", "version": "11.4.2"},
        "outcome": "unsupported",
        "entry": {
            "function_rva": "0x1000",
            "function_name": "ArbitraryEntryName",
            "thunk_chain": [],
            "exact_function_entry": True,
        },
        "registrations": [],
        "device_control": {
            "major_function_index": 14,
            "registration_ref": None,
            "handler_rva": None,
            "handler_name": None,
            "ioctl_root": {
                "source": "unresolved",
                "load_ref": None,
                "pdb_type_path": None,
                "width": None,
                "derivation_refs": [],
            },
            "selectors": [],
            "calls": [],
            "unresolved_edges": reasons,
            "dynamic_dispatch": False,
            "truncated": False,
        },
        "accounting": {
            "functions_total": 300,
            "functions_entry_reachable": 1,
            "functions_decompiled": 300,
            "operations_total": 10000,
            "registrations_observed": 0,
            "selectors_observed": 0,
            "table_entries_observed": 0,
            "limits_hit": [],
        },
        "completeness": {
            "entrypoint_resolved": False,
            "registration_complete": False,
            "ioctl_root_resolved": False,
            "selector_inventory_complete": False,
            "call_edges_complete": False,
            "table_extents_complete": False,
            "semantic_admission_allowed": False,
        },
        "unsupported": reasons,
    }


def test_unsupported_inventory_is_deterministic_neutral_and_zero_surface() -> None:
    first = inventory.compile_windows_ioctl_surface_inventory(_facts())
    reordered = _facts()
    reordered["unsupported"].reverse()
    reordered["device_control"]["unresolved_edges"].reverse()
    second = inventory.compile_windows_ioctl_surface_inventory(reordered)
    assert inventory.canonical_inventory_bytes(first) == inventory.canonical_inventory_bytes(second)
    assert first["outcome"] == "unsupported"
    assert first["registrations"] == []
    assert first["device_control"]["selectors"] == []
    assert first["accounting"]["table_entries_observed"] == 0
    assert not any(first["completeness"].values())
    assert first["candidate_count"] == 0
    assert first["vulnerability_established"] is False
    assert first["reachability_established"] is False


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda raw: raw["registrations"].append({"unique_for_major": True}), "registration"),
        (
            lambda raw: raw["device_control"]["selectors"].append(
                {"exhaustive_for_site": True}
            ),
            "unclaimed",
        ),
        (
            lambda raw: raw["device_control"]["ioctl_root"].update(
                {"source": "claimed", "load_ref": _ref(3, "LOAD")}
            ),
            "IOCTL root",
        ),
        (
            lambda raw: raw["completeness"].update({"selector_inventory_complete": True}),
            "completeness",
        ),
        (lambda raw: raw["unsupported"][0].update({"ref": None}), "must be an object"),
    ],
)
def test_v1_rejects_surface_and_completeness_claims(
    mutate: object, message: str
) -> None:
    facts = _facts()
    mutate(facts)
    with pytest.raises(ValueError, match=message):
        inventory.compile_windows_ioctl_surface_inventory(facts)


@pytest.mark.parametrize(
    "field",
    [
        "entrypoint_resolved",
        "registration_complete",
        "ioctl_root_resolved",
        "selector_inventory_complete",
        "call_edges_complete",
        "table_extents_complete",
        "semantic_admission_allowed",
    ],
)
@pytest.mark.parametrize("falsy_non_boolean", [0, None, "", []])
def test_every_completeness_field_requires_literal_false(
    field: str, falsy_non_boolean: object
) -> None:
    facts = _facts()
    facts["completeness"][field] = falsy_non_boolean
    with pytest.raises(ValueError, match="completeness must remain false"):
        inventory.compile_windows_ioctl_surface_inventory(facts)


def test_inventory_rejects_claim_and_exact_entry_tampering() -> None:
    compiled = inventory.compile_windows_ioctl_surface_inventory(_facts())
    compiled["candidate_count"] = 1
    with pytest.raises(ValueError, match="claim boundary"):
        inventory.canonical_inventory_bytes(compiled)

    wrong_entry = _facts()
    wrong_entry["entry"]["function_rva"] = "0x1001"
    with pytest.raises(ValueError, match="exact non-thunk"):
        inventory.compile_windows_ioctl_surface_inventory(wrong_entry)

    unresolved_without_reason = _facts()
    unresolved_without_reason["entry"] = {
        "function_rva": None,
        "function_name": None,
        "thunk_chain": [],
        "exact_function_entry": False,
    }
    with pytest.raises(ValueError, match="requires one exact"):
        inventory.compile_windows_ioctl_surface_inventory(unresolved_without_reason)

    resolved_with_fallback = _facts()
    fallback = {
        "stage": "entry-resolution",
        "owner_rva": "0x1000",
        "ref": {
            "kind": "pe-header-field",
            "artifact": "driver",
            "field": "AddressOfEntryPoint",
            "rva": "0x1000",
        },
        "reason_code": "exact-pdb-entry-function-unavailable",
        "detail": "missing",
    }
    resolved_with_fallback["unsupported"].append(fallback)
    resolved_with_fallback["device_control"]["unresolved_edges"].append(fallback)
    with pytest.raises(ValueError, match="resolved entry forbids"):
        inventory.compile_windows_ioctl_surface_inventory(resolved_with_fallback)


@pytest.mark.parametrize(("owner", "evidence"), [("0x1001", "0x1000"), ("0x1000", "0x1001")])
def test_unresolved_fallback_reason_must_cross_bind_pe_entry(
    owner: str, evidence: str
) -> None:
    facts = _facts()
    facts["entry"] = {
        "function_rva": None,
        "function_name": None,
        "thunk_chain": [],
        "exact_function_entry": False,
    }
    fallback = {
        "stage": "entry-resolution",
        "owner_rva": owner,
        "ref": {
            "kind": "pe-header-field",
            "artifact": "driver",
            "field": "AddressOfEntryPoint",
            "rva": evidence,
        },
        "reason_code": "exact-pdb-entry-function-unavailable",
        "detail": "missing",
    }
    facts["unsupported"] = [fallback]
    facts["device_control"]["unresolved_edges"] = [fallback]
    with pytest.raises(ValueError, match=r"cross-bound|cross-binding"):
        inventory.compile_windows_ioctl_surface_inventory(facts)


def test_missing_public_pdb_entry_symbol_emits_unresolved_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "afd.sys"
    pdb = tmp_path / "artifact"
    route = tmp_path / "route"
    route.mkdir()
    binary.write_bytes(b"MZ-driver")
    pdb.write_bytes(b"pdb")
    receipt = PublicPdbReceipt(
        route,
        pdb,
        _sha_bytes(b"pdb"),
        3,
        "3" * 64,
        "https://msdl.microsoft.com/download/symbols/afd.pdb/key/afd.pdb",
        "GUID",
        1,
        "GUID",
        4,
        False,
    )
    monkeypatch.setattr(inventory, "verify_public_pdb_receipt", lambda *args: receipt)
    monkeypatch.setattr(inventory, "pdb_functions", lambda *args: {})
    monkeypatch.setattr(inventory, "pe_codeview_identity", lambda path: ("GUID", 1, "afd.pdb"))
    monkeypatch.setattr(inventory, "pdb_codeview_identity", lambda path: ("GUID", 4, True))
    monkeypatch.setattr(inventory, "_pe_entry_rva", lambda path: 0x1000)
    monkeypatch.setattr(ioctl_export, "_pe_machine", lambda path: (0x140000000, "x86_64", 8))
    monkeypatch.setattr(ioctl_export, "_requested_ghidra_version", lambda path: "11.4.2")
    initialized: list[tuple[Path, str]] = []
    monkeypatch.setattr(
        inventory,
        "_initialize_ghidra",
        lambda home, version: initialized.append((home, version)),
    )

    facts = inventory._acquire_surface_facts_ghidra(
        binary,
        pdb,
        ghidra_home=tmp_path / "ghidra",
        public_pdb_bundle=route,
    )
    assert facts["entry"] == {
        "function_rva": None,
        "function_name": None,
        "thunk_chain": [],
        "exact_function_entry": False,
    }
    assert not any(facts["completeness"].values())
    reason = facts["unsupported"][0]
    assert reason["reason_code"] == "exact-pdb-entry-function-unavailable"
    assert reason["ref"] == {
        "kind": "pe-header-field",
        "artifact": "driver",
        "field": "AddressOfEntryPoint",
        "rva": "0x1000",
    }
    compiled = inventory.compile_windows_ioctl_surface_inventory(facts)
    assert compiled["outcome"] == "unsupported"
    assert initialized == [(tmp_path / "ghidra", "11.4.2")]


def test_exact_producer_publishes_atomic_receipt_and_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    binary = tmp_path / "afd.sys"
    pdb = tmp_path / "afd.pdb"
    binary.write_bytes(b"MZ-driver")
    pdb.write_bytes(b"pdb")
    ghidra = tmp_path / "ghidra" / "Ghidra"
    ghidra.mkdir(parents=True)
    (ghidra / "application.properties").write_text("application.version=11.4.2\n", encoding="utf-8")
    monkeypatch.setattr(inventory, "pe_codeview_identity", lambda path: ("GUID", 1, "afd.pdb"))
    monkeypatch.setattr(inventory, "pdb_codeview_identity", lambda path: ("GUID", 1, False))
    monkeypatch.setattr(inventory, "_pe_entry_rva", lambda path: 0x1000)
    monkeypatch.setattr(inventory, "pdb_functions", lambda *args: {0x1000: "DriverEntry"})

    def facts(*args: object, **kwargs: object) -> dict[str, object]:
        value = _facts()
        value["driver_sha256"] = _sha_bytes(b"MZ-driver")
        value["pdb_sha256"] = _sha_bytes(b"pdb")
        value["pdb_identity"] = "GUID:1:full"
        return value

    monkeypatch.setattr(inventory, "_acquire_surface_facts", facts)
    output = tmp_path / "inventory-bundle"
    assert (
        main(
            [
                "windows-ioctl-surface-inventory",
                str(binary),
                str(pdb),
                str(output),
                "--ghidra-home",
                str(ghidra.parent),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["inventory_path"].endswith("inventory.json")
    assert {path.name for path in output.iterdir()} == {
        "afd.sys",
        "target.pdb",
        "inventory.json",
        "receipt.json",
    }
    receipt = json.loads((output / "receipt.json").read_text(encoding="utf-8"))
    assert receipt["schema_version"] == inventory.RECEIPT_VERSION
    assert receipt["execution_authorized"] is False
    expected_cache = hashlib.sha256(
        inventory._CACHE_DOMAIN
        + b"\0".join(
            value.encode()
            for value in (
                receipt["binary_sha256"],
                receipt["pdb"]["sha256"],
                "",
                receipt["inventory_sha256"],
                inventory.EXTRACTOR_CONFIG_SHA256,
                receipt["tool_version"],
                inventory.EXPORT_VERSION,
                inventory.EXTRACTOR_PROFILE,
            )
        )
    ).hexdigest()
    assert receipt["cache_key"] == expected_cache
    verified = inventory.verify_windows_ioctl_surface_inventory_bundle(output)
    assert verified["candidate_count"] == 0
    monkeypatch.setattr(inventory, "pdb_functions", lambda *args: {})
    with pytest.raises(ValueError, match="PDB-entry resolution state mismatch"):
        inventory.verify_windows_ioctl_surface_inventory_bundle(output)
    monkeypatch.setattr(inventory, "pdb_functions", lambda *args: {0x1000: "DriverEntry"})
    assert main(["windows-ioctl-surface-inventory-verify", str(output)]) == 0
    assert json.loads(capsys.readouterr().out)["schema_version"] == inventory.EXPORT_VERSION

    rebound = tmp_path / "rebound-tamper"
    shutil.copytree(output, rebound)
    rebound_inventory = json.loads((rebound / "inventory.json").read_text(encoding="utf-8"))
    rebound_inventory["driver_sha256"] = "f" * 64
    rebound_bytes = inventory.canonical_inventory_bytes(rebound_inventory)
    (rebound / "inventory.json").write_bytes(rebound_bytes)
    rebound_receipt = json.loads((rebound / "receipt.json").read_text(encoding="utf-8"))
    rebound_receipt["inventory_sha256"] = _sha_bytes(rebound_bytes)
    rebound_receipt["cache_key"] = hashlib.sha256(
        inventory._CACHE_DOMAIN
        + b"\0".join(
            value.encode()
            for value in (
                rebound_receipt["binary_sha256"],
                rebound_receipt["pdb"]["sha256"],
                "",
                rebound_receipt["inventory_sha256"],
                inventory.EXTRACTOR_CONFIG_SHA256,
                rebound_receipt["tool_version"],
                inventory.EXPORT_VERSION,
                inventory.EXTRACTOR_PROFILE,
            )
        )
    ).hexdigest()
    (rebound / "receipt.json").write_text(
        json.dumps(rebound_receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="driver_sha256 artifact binding"):
        inventory.verify_windows_ioctl_surface_inventory_bundle(rebound)

    (output / "inventory.json").write_bytes((output / "inventory.json").read_bytes() + b" ")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        inventory.verify_windows_ioctl_surface_inventory_bundle(output)


def test_public_route_mutation_after_analyzer_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "afd.sys"
    route_dir = tmp_path / "route" / _sha_bytes(b"pdb")
    route_dir.mkdir(parents=True)
    binary.write_bytes(b"MZ-driver")
    (route_dir / "artifact").write_bytes(b"pdb")
    (route_dir / "receipt.json").write_text("{}", encoding="utf-8")
    ghidra = tmp_path / "ghidra" / "Ghidra"
    ghidra.mkdir(parents=True)
    (ghidra / "application.properties").write_text("application.version=11.4.2\n", encoding="utf-8")
    base = PublicPdbReceipt(
        route_dir,
        route_dir / "artifact",
        _sha_bytes(b"pdb"),
        3,
        "3" * 64,
        "https://msdl.microsoft.com/download/symbols/afd.pdb/key/afd.pdb",
        "GUID",
        1,
        "GUID",
        4,
        False,
    )
    calls = 0

    def verify(source: Path, bundle: Path) -> PublicPdbReceipt:
        nonlocal calls
        calls += 1
        result = replace(
            base,
            bundle_path=bundle.resolve(),
            artifact_path=(bundle / "artifact").resolve(),
        )
        return replace(result, receipt_sha256="4" * 64) if calls >= 3 else result

    monkeypatch.setattr(inventory, "verify_public_pdb_receipt", verify)
    monkeypatch.setattr(inventory, "_acquire_surface_facts", lambda *a, **k: _facts())
    with pytest.raises(ValueError, match="route changed"):
        inventory.produce_windows_ioctl_surface_inventory(
            binary,
            route_dir / "artifact",
            tmp_path / "out",
            ghidra_home=ghidra.parent,
            public_pdb_bundle=route_dir,
        )
    assert not (tmp_path / "out").exists()


def test_public_positional_pdb_and_reserved_driver_name_fail_before_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "afd.sys"
    binary.write_bytes(b"MZ-driver")
    route = tmp_path / "route"
    route.mkdir()
    artifact = route / "artifact"
    artifact.write_bytes(b"pdb")
    receipt = PublicPdbReceipt(
        route,
        artifact,
        _sha_bytes(b"pdb"),
        3,
        "3" * 64,
        "https://msdl.microsoft.com/download/symbols/afd.pdb/key/afd.pdb",
        "GUID",
        1,
        "GUID",
        4,
        False,
    )
    monkeypatch.setattr(inventory, "verify_public_pdb_receipt", lambda *args: receipt)
    other = tmp_path / "other.pdb"
    other.write_bytes(b"pdb")
    with pytest.raises(ValueError, match="positional PDB"):
        inventory.produce_windows_ioctl_surface_inventory(
            binary,
            other,
            tmp_path / "out",
            ghidra_home=tmp_path,
            public_pdb_bundle=route,
        )
    assert not (tmp_path / "out").exists()

    reserved = tmp_path / "CON.sys"
    reserved.write_bytes(b"MZ-driver")
    with pytest.raises(ValueError, match="non-reserved"):
        inventory.produce_windows_ioctl_surface_inventory(
            reserved,
            other,
            tmp_path / "reserved-out",
            ghidra_home=tmp_path,
        )

from __future__ import annotations

import copy
import hashlib
import importlib.util
import os
import struct
from pathlib import Path
from types import ModuleType

import pytest

import zeroverse.windows_afd_hypotheses as hypotheses


def _selector_test_module() -> ModuleType:
    path = Path(__file__).with_name("test_windows_afd_selector.py")
    spec = importlib.util.spec_from_file_location("_selector_test_support", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _paired_selectors() -> tuple[dict[str, object], dict[str, object]]:
    support = _selector_test_module()
    raw = support.selector.compile_windows_afd_selector(support._facts())
    image_base = int(raw["image_base"], 16)
    targets = [0x2000 + index * 0x10 for index in range(32)] + [0x5000] * 42

    def reshape(value: dict[str, object], delta: int) -> None:
        pointers = [image_base + rva + delta for rva in targets]
        encoded = struct.pack("<74Q", *pointers)
        value["function_table"].update(
            {
                "addressed_bytes": encoded.hex(),
                "addressed_sha256": hashlib.sha256(encoded).hexdigest(),
            }
        )
        for index, row in enumerate(value["rows"]):
            row["target_rva"] = f"0x{targets[index] + delta:x}"
        value["accounting"]["unique_targets"] = 33

    side_a = copy.deepcopy(raw)
    side_b = copy.deepcopy(raw)
    reshape(side_a, 0)
    reshape(side_b, 0x10000)
    side_b["driver_sha256"] = "5" * 64
    side_b["pdb_sha256"] = "6" * 64
    side_b["registration_commitment"]["artifact_sha256"] = "7" * 64
    side_b["registration_commitment"]["receipt_sha256"] = "8" * 64
    return side_a, side_b


def _compile() -> dict[str, object]:
    side_a, side_b = _paired_selectors()
    return hypotheses.compile_windows_afd_hypotheses(
        side_a,
        side_b,
        side_a_receipt_sha256="9" * 64,
        side_b_receipt_sha256="a" * 64,
    )


def test_compiler_emits_33_inert_alias_class_plans() -> None:
    result = _compile()
    assert result["hypothesis_count"] == 33
    assert result["candidate_count"] == 0
    assert result["ranking_performed"] is False
    assert result["execution_authorized"] is False
    assert result["device_ioctl_attempts"] == 0
    assert result["runtime_consumable"] is False
    assert result["model_invocations"] == 0
    assert result["network_performed"] is False
    assert result["handler_identity_established"] is False
    assert result["handler_body_change_established"] is False
    plans = result["hypotheses"]
    assert [plan["enumeration_order"] for plan in plans] == list(range(1, 34))
    assert sum(plan["modal_alias_class"] is True for plan in plans) == 1
    assert plans[32]["row_indices"] == list(range(32, 74))
    assert all(plan["attempts"]["device_ioctl"] == 0 for plan in plans)
    assert all(plan["runtime_consumable"] is False for plan in plans)
    assert not any("score" in plan or "payload" in plan or "command" in plan for plan in plans)


def test_compiler_is_deterministic_and_ids_bind_rvas() -> None:
    first = _compile()
    second = _compile()
    assert hypotheses.canonical_hypotheses_bytes(first) == hypotheses.canonical_hypotheses_bytes(
        second
    )
    forged = copy.deepcopy(first)
    forged["hypotheses"][0]["side_b_target_rva"] = "0x9999"
    with pytest.raises(ValueError, match="identity mismatch"):
        hypotheses.canonical_hypotheses_bytes(forged)


@pytest.mark.parametrize(
    "mutation,match",
    [
        (lambda a, b: b.update({"driver_sha256": a["driver_sha256"]}), "distinct"),
        (
            lambda _a, b: b["key_table"].update({"addressed_bytes": "00" * (74 * 4)}),
            "valid selector",
        ),
        (
            lambda _a, b: b["rows"][0].update({"target_rva": b["rows"][1]["target_rva"]}),
            "valid selector",
        ),
        (
            lambda _a, b: b["partition"].update({"local_branch": "AL!=0"}),
            "valid selector",
        ),
    ],
)
def test_compiler_rejects_pair_and_selector_tamper(mutation: object, match: str) -> None:
    side_a, side_b = _paired_selectors()
    mutation(side_a, side_b)
    with pytest.raises(ValueError, match=match):
        hypotheses.compile_windows_afd_hypotheses(
            side_a,
            side_b,
            side_a_receipt_sha256="9" * 64,
            side_b_receipt_sha256="a" * 64,
        )


def test_claim_plan_order_and_command_fields_fail_closed() -> None:
    raw = _compile()
    raw["candidate_established"] = True
    with pytest.raises(ValueError, match="claim boundary"):
        hypotheses.canonical_hypotheses_bytes(raw)
    raw = _compile()
    raw["hypotheses"][0]["enumeration_order"] = 2
    with pytest.raises(ValueError, match="descriptor"):
        hypotheses.canonical_hypotheses_bytes(raw)
    raw = _compile()
    raw["hypotheses"][0]["command"] = "forbidden"
    with pytest.raises(ValueError, match="unknown or missing"):
        hypotheses.canonical_hypotheses_bytes(raw)


def test_modal_forgery_and_static_limit_mutations_fail_closed() -> None:
    raw = _compile()
    actual = next(index for index, row in enumerate(raw["hypotheses"]) if row["modal_alias_class"])
    raw["hypotheses"][actual]["modal_alias_class"] = False
    raw["hypotheses"][0]["modal_alias_class"] = True
    with pytest.raises(ValueError, match="partition mismatch"):
        hypotheses.canonical_hypotheses_bytes(raw)

    for forged in (False, 0, -1, "300", 300.0, 301):
        raw = _compile()
        raw["hypotheses"][0]["static_limits"]["max_wall_clock_seconds_per_side"] = forged
        with pytest.raises(ValueError, match="descriptor mismatch"):
            hypotheses.canonical_hypotheses_bytes(raw)
    raw = _compile()
    raw["hypotheses"][0]["static_limits"]["max_function_bytes_per_side"] = 65536.0
    with pytest.raises(ValueError, match="descriptor mismatch"):
        hypotheses.canonical_hypotheses_bytes(raw)
    raw = _compile()
    raw["hypotheses"][0]["modal_alias_class"] = 0
    with pytest.raises(ValueError, match="modal flag mismatch"):
        hypotheses.canonical_hypotheses_bytes(raw)


def test_receipt_rejects_topology_and_execution_tamper() -> None:
    receipt = {
        "schema_version": hypotheses.RECEIPT_VERSION,
        "producer": hypotheses.PRODUCER,
        "hypotheses_path": "hypotheses.json",
        "hypotheses_sha256": "1" * 64,
        "side_a_selector_bundle": "side-a-selector",
        "side_a_selector_receipt_sha256": "2" * 64,
        "side_b_selector_bundle": "side-b-selector",
        "side_b_selector_receipt_sha256": "3" * 64,
        "compiler_config_sha256": hypotheses.CONFIG_SHA256,
        "static_only": True,
        "execution_authorized": False,
        "device_ioctl_attempts": 0,
    }
    hypotheses._validate_receipt(receipt)
    receipt["execution_authorized"] = True
    with pytest.raises(ValueError, match="receipt contract"):
        hypotheses._validate_receipt(receipt)


def test_verifier_snapshots_before_replay(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "source"
    source.mkdir()
    original = tmp_path / "original"

    def snapshot(source_fd: int, destination_fd: int) -> None:
        del destination_fd
        source.rename(original)
        source.mkdir()
        assert os.fstat(source_fd).st_ino == original.stat().st_ino

    def verify(retained: Path, home: Path) -> dict[str, object]:
        assert retained != source
        assert home == Path("/ghidra")
        return {"snapshot": True}

    monkeypatch.setattr(hypotheses, "_snapshot_hypotheses_bundle", snapshot)
    monkeypatch.setattr(hypotheses, "_verify_snapshotted_hypotheses_bundle", verify)
    assert hypotheses.verify_windows_afd_hypotheses_bundle(source, ghidra_home="/ghidra") == {
        "snapshot": True
    }


def test_producer_verifies_under_private_root_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    side_a, side_b = _paired_selectors()
    source_a = tmp_path / "source-a"
    source_b = tmp_path / "source-b"
    output_parent = tmp_path / "publish"
    for path in (source_a, source_b, output_parent):
        path.mkdir()
    output = output_parent / "bundle"
    moved_parent = tmp_path / "publish-held"
    swapped = False

    def snapshot_selector(_source_fd: int, destination_fd: int) -> None:
        descriptor = os.open(
            "receipt.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=destination_fd,
        )
        try:
            os.write(descriptor, b"retained-selector-receipt\n")
        finally:
            os.close(descriptor)

    def verify_selector(path: Path, _home: Path) -> dict[str, object]:
        nonlocal swapped
        assert output_parent not in path.parents
        if not swapped:
            output_parent.rename(moved_parent)
            output_parent.mkdir()
            output_parent.rmdir()
            moved_parent.rename(output_parent)
            swapped = True
        return side_a if path.name == "side-a-selector" else side_b

    def verify_bundle(path: Path, _home: Path) -> dict[str, object]:
        assert output_parent not in path.parents
        return {"private_replay": True}

    monkeypatch.setattr(hypotheses, "_snapshot_selector_bundle", snapshot_selector)
    monkeypatch.setattr(hypotheses, "_verify_snapshotted_selector_bundle", verify_selector)
    monkeypatch.setattr(hypotheses, "_verify_snapshotted_hypotheses_bundle", verify_bundle)
    result = hypotheses.produce_windows_afd_hypotheses(
        source_a, source_b, output, ghidra_home="/ghidra"
    )
    assert swapped is True
    assert output.is_dir()
    assert result["hypotheses_path"] == "bundle/hypotheses.json"


def test_private_pair_integration() -> None:
    root = os.environ.get("ZEROVERSE_AFD_SELECTOR_PAIR_ROOT")
    ghidra = os.environ.get("GHIDRA_HOME") or os.environ.get("GHIDRA_INSTALL_DIR")
    if not root or not ghidra:
        pytest.skip("private AFD selector pair unavailable")
    base = Path(root)
    side_a = hypotheses._verify_snapshotted_selector_bundle(
        base / "target-selector-v1-final", Path(ghidra)
    )
    side_b = hypotheses._verify_snapshotted_selector_bundle(
        base / "fixed-selector-v1-final", Path(ghidra)
    )
    result = hypotheses.compile_windows_afd_hypotheses(
        side_a,
        side_b,
        side_a_receipt_sha256=hypotheses._sha_file(
            base / "target-selector-v1-final" / "receipt.json"
        ),
        side_b_receipt_sha256=hypotheses._sha_file(
            base / "fixed-selector-v1-final" / "receipt.json"
        ),
    )
    assert result["comparison"]["addressed_rows"] == 74
    assert result["hypothesis_count"] == 33
    assert result["candidate_count"] == 0
    assert result["device_ioctl_attempts"] == 0

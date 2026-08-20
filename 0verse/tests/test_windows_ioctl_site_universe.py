from __future__ import annotations

import copy
import hashlib
import inspect
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

import zeroverse.windows_ioctl_site_universe as universe_module
from zeroverse.cli import main
from zeroverse.ssh_authorization import sign_ssh_material
from zeroverse.windows_ioctl_ghidra_export import (
    RAW_FACT_VERSION,
    compile_windows_ioctl_high_pcode_facts,
)
from zeroverse.windows_ioctl_real_rank import _rank_dispatches
from zeroverse.windows_ioctl_site_identity import ioctl_site_id, site_universe_sha256
from zeroverse.windows_ioctl_site_universe import (
    PROOF_LIMIT,
    REQUEST_VERSION,
    SIGNATURE_NAMESPACE,
    SIGNER_IDENTITY,
    build_windows_ioctl_site_universe,
    canonical_site_universe_bytes,
    verify_windows_ioctl_site_universe,
)
from zeroverse.windows_variant import Artifact


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def test_site_identity_refactor_preserves_pre_refactor_golden_bytes() -> None:
    """Expected values were frozen from the former rank-module implementation."""
    record: dict[str, object] = {
        "ioctl_code": "0x00222004",
        "registration_rva": "0x1100",
        "handler_name": "DispatchDeviceControl",
        "handler_rva": "0x1200",
        "source": "SystemBuffer",
        "source_inst_id": 1,
        "field_offset": 8,
        "field_width": 4,
        "field_kind": "length",
        "sink_kind": "copy",
        "sink_function": "memcpy",
        "sink_address": "0x1280",
        "sink_inst_id": 2,
    }
    expected_site_id = (
        "93099526bc447b2bba2aaf3c9407d7f9f1e2e37df4156f5e163405b33b6b8e6a"
    )
    assert ioctl_site_id("1" * 64, "2" * 64, record) == expected_site_id
    assert site_universe_sha256([{"site_id": expected_site_id, **record}]) == (
        "a1fed50dc7d6f329cffc82dea140d957026a5eb16e087b5ce2d8aef517c0d18c"
    )


def _authority(root: Path, principal: str = SIGNER_IDENTITY) -> tuple[Path, Path]:
    root.mkdir(parents=True, exist_ok=True)
    key = root / "site-universe.key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
        capture_output=True,
    )
    policy = root / "site-universe.allowed-signers"
    public = key.with_suffix(".key.pub").read_text(encoding="utf-8").strip()
    policy.write_text(f"{principal} {public}\n", encoding="utf-8")
    return key, policy


def _artifact(root: Path) -> Artifact:
    driver_sha = "1" * 64
    pdb_sha = "2" * 64
    identity = "00112233445566778899AABBCCDDEEFF:1:driver.pdb"
    provisional = Artifact(
        binary_path=root / "driver.sys",
        export_path=root / "ghidra-export.json",
        binary_sha256=driver_sha,
        export_sha256="0" * 64,
        pdb_identity=identity,
        pdb_sha256=pdb_sha,
        analysis_receipt_sha256="3" * 64,
        ghidra_version="11.4.2",
        cache_key="4" * 64,
        synthetic_fixture=False,
        export={},
    )
    export = _v2_export(provisional)
    export_bytes = (json.dumps(export, sort_keys=True, separators=(",", ":")) + "\n").encode()
    provisional.export_path.write_bytes(export_bytes)
    return Artifact(
        **{
            **provisional.__dict__,
            "export_sha256": _sha(export_bytes),
            "export": export,
        }
    )


def _v2_export(artifact: Artifact) -> dict[str, Any]:
    def ref(instruction: str, opcode: str) -> dict[str, object]:
        return {
            "function_rva": "0x1200",
            "instruction_rva": instruction,
            "pcode_order": 0,
            "opcode": opcode,
        }

    store = ref("0x1210", "STORE")
    registration_address = ref("0x1208", "PTRADD")
    registration_target = ref("0x120c", "COPY")
    comparison = ref("0x1220", "INT_EQUAL")
    branch = ref("0x1228", "CBRANCH")
    source = ref("0x1240", "LOAD")
    input_length = ref("0x1248", "LOAD")
    guard_comparison = ref("0x1250", "INT_LESS")
    guard_branch = ref("0x1258", "CBRANCH")
    sink = ref("0x1280", "CALL")
    reject_return = ref("0x1290", "RETURN")
    return compile_windows_ioctl_high_pcode_facts(
        {
            "schema_version": RAW_FACT_VERSION,
            "driver_sha256": artifact.binary_sha256,
            "pdb_sha256": artifact.pdb_sha256,
            "pdb_codeview_identity": artifact.pdb_identity,
            "architecture": "x86_64",
            "pointer_size": 8,
            "image_base": "0x140000000",
            "coverage": {
                "framework": "wdm",
                "truncated": False,
                "dynamic_dispatch": False,
                "unresolved_edges": [],
            },
            "dispatches": [
                {
                    "ioctl_code": 0x222004,
                    "device_type": 0x22,
                    "function": 0x801,
                    "method": 0,
                    "access": 0,
                    "handler_name": "DispatchDeviceControl",
                    "handler_rva": "0x1200",
                    "registration_rva": "0x1100",
                    "dispatch_resolved": True,
                    "unresolved_edges": [],
                    "registration_evidence": {
                        "major_function_index": 14,
                        "target_rva": "0x1200",
                        "store_ref": store,
                        "address_dependency_refs": [registration_address],
                        "target_dependency_refs": [registration_target],
                    },
                    "ioctl_match_evidence": {
                        "ioctl_code": 0x222004,
                        "comparison_ref": comparison,
                        "branch_ref": branch,
                        "dominates_handler": True,
                        "match_successor_ref": sink,
                        "reject_return_ref": reject_return,
                        "match_comparison_result": True,
                        "entry_reachable": True,
                        "unique_match_successor": True,
                        "reject_successor_reaches_sink": False,
                    },
                    "ops": [
                        {"ref": registration_address, "input_refs": []},
                        {"ref": registration_target, "input_refs": []},
                        {
                            "ref": store,
                            "input_refs": [registration_address, registration_target],
                        },
                        {"ref": comparison, "input_refs": [source]},
                        {"ref": branch, "input_refs": [comparison]},
                        {"ref": source, "input_refs": []},
                        {"ref": input_length, "input_refs": []},
                        {"ref": guard_comparison, "input_refs": [input_length]},
                        {"ref": guard_branch, "input_refs": [guard_comparison]},
                        {"ref": sink, "input_refs": [source]},
                        {"ref": reject_return, "input_refs": []},
                    ],
                    "fields": [
                        {
                            "offset": 8,
                            "width": 4,
                            "kind": "length",
                            "source": "SystemBuffer",
                            "source_root": "irp.system_buffer",
                            "source_ref": source,
                            "sink_kind": "copy",
                            "sink_function": "memcpy",
                            "sink_address": "0x1280",
                            "sink_ref": sink,
                            "sink_argument_index": 2,
                            "taint_path": [source, sink],
                            "safety_proofs": [
                                {
                                    "proof_kind": "input-field-readable",
                                    "comparison_ref": guard_comparison,
                                    "branch_ref": guard_branch,
                                    "sink_successor_ref": sink,
                                    "reject_return_ref": reject_return,
                                    "sink_comparison_result": False,
                                    "dominates_sink": True,
                                    "entry_reachable": True,
                                    "unique_sink_successor": True,
                                    "reject_successor_reaches_sink": False,
                                    "input_buffer_length_ref": input_length,
                                    "field_end": 12,
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )


def _request(root: Path) -> Path:
    request = root / "site-request.json"
    request.write_text(
        json.dumps(
            {
                "schema_version": REQUEST_VERSION,
                "universe_nonce": "neutral-site-universe-nonce-00000001",
                "declared_frozen_at": datetime.now(UTC).isoformat(),
                "artifact": {
                    "binary_path": "driver.sys",
                    "ghidra_export_path": "ghidra-export.json",
                    "binary_sha256": "1" * 64,
                    "ghidra_export_sha256": "4" * 64,
                    "analysis_receipt_path": "analysis-receipt.json",
                    "analysis_receipt_sha256": "3" * 64,
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return request


def _build(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[dict[str, object], Path, Path, Artifact]:
    artifact = _artifact(root)
    request = _request(root)
    key, policy = _authority(root)
    monkeypatch.setattr(universe_module, "_load_artifact", lambda *_args: artifact)
    manifest = build_windows_ioctl_site_universe(request, allowed_signers=policy)
    return manifest, key, policy, artifact


def _write_signed(path: Path, manifest: dict[str, object], key: Path) -> None:
    path.write_bytes(canonical_site_universe_bytes(manifest))
    Path(f"{path}.sig").write_text(
        sign_ssh_material(
            path.read_bytes(),
            signing_key=key,
            namespace=SIGNATURE_NAMESPACE,
            label="site universe",
        ),
        encoding="utf-8",
    )


def test_builds_complete_rank_neutral_site_universe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, _key, _policy, artifact = _build(tmp_path, monkeypatch)

    sites = cast(list[dict[str, object]], manifest["sites"])
    assert manifest["site_count"] == 1
    assert manifest["site_universe_sha256"] == site_universe_sha256(sites)
    assert manifest["analysis_sha256"] == artifact.export_sha256
    assert manifest["analysis_receipt_sha256"] == artifact.analysis_receipt_sha256
    assert manifest["ranker_invoked"] is False
    assert manifest["labels_loaded"] is False
    assert manifest["ranking_scores_present"] is False
    assert manifest["candidate_classification_present"] is False
    assert manifest["execution_authorized"] is False
    assert manifest["device_ioctl_attempts"] == 0
    assert manifest["proof_limit"] == PROOF_LIMIT
    for site in sites:
        assert not set(site) & {
            "guards",
            "missing_guards",
            "score",
            "candidate_id",
            "label",
        }

    _candidates, ranked_sites = _rank_dispatches(
        cast(list[dict[str, object]], artifact.export["dispatches"]),
        artifact_identity={
            "driver_sha256": artifact.binary_sha256,
            "pdb_sha256": artifact.pdb_sha256,
            "pdb_codeview_identity": artifact.pdb_identity,
            "analysis_sha256": artifact.export_sha256,
            "analysis_receipt_sha256": artifact.analysis_receipt_sha256,
        },
        admission_sha256="5" * 64,
        max_fields=64,
        max_candidates=4096,
    )
    assert sites == ranked_sites


def test_module_has_no_rank_or_label_dependency() -> None:
    source = inspect.getsource(universe_module)
    assert "windows_ioctl_real_rank" not in source
    assert "windows_ioctl_real_eval" not in source
    assert "score_version" not in source
    parameters = inspect.signature(build_windows_ioctl_site_universe).parameters
    assert "labels" not in parameters
    assert "ranker" not in parameters


def test_signed_manifest_verifies_and_recomputes_every_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, key, policy, _artifact_value = _build(tmp_path, monkeypatch)
    path = tmp_path / "site-universe.json"
    _write_signed(path, manifest, key)

    verified = verify_windows_ioctl_site_universe(path, allowed_signers=policy)

    assert verified["signature_verified"] is True
    assert verified["manifest_sha256"] == _sha(path.read_bytes())


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda raw: raw.__setitem__("universe_id", "f" * 64), "universe_id"),
        (
            lambda raw: cast(list[dict[str, object]], raw["sites"])[0].__setitem__(
                "field_width", True
            ),
            "field_width",
        ),
        (
            lambda raw: cast(list[dict[str, object]], raw["sites"])[0].__setitem__(
                "source", "RankOutput"
            ),
            "source",
        ),
        (lambda raw: raw.__setitem__("site_universe_sha256", "e" * 64), "digest"),
    ],
)
def test_verifier_rejects_resigned_semantic_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: Any,
    message: str,
) -> None:
    manifest, key, policy, _artifact_value = _build(tmp_path, monkeypatch)
    mutation(manifest)
    path = tmp_path / "tampered.json"
    path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    Path(f"{path}.sig").write_text(
        sign_ssh_material(
            path.read_bytes(),
            signing_key=key,
            namespace=SIGNATURE_NAMESPACE,
            label="site universe",
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=message):
        verify_windows_ioctl_site_universe(path, allowed_signers=policy)


def test_manifest_schema_rejects_json_type_coercion_and_unbounded_codeview(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, _key, _policy, _artifact_value = _build(tmp_path, monkeypatch)
    mutations: list[tuple[Any, str]] = [
        (lambda raw: raw.__setitem__("site_count", True), "site_count"),
        (lambda raw: raw.__setitem__("request_sha256", int("1" * 64)), "request_sha256"),
        (lambda raw: raw.__setitem__("pdb_sha256", int("2" * 64)), "pdb_sha256"),
        (lambda raw: raw.__setitem__("universe_nonce", int("1" * 32)), "universe_nonce"),
        (
            lambda raw: cast(list[dict[str, object]], raw["sites"])[0].__setitem__(
                "site_id", int("1" * 64)
            ),
            "site_id",
        ),
        (
            lambda raw: raw.__setitem__("pdb_codeview_identity", "x" * 513),
            "pdb_codeview",
        ),
        (
            lambda raw: raw.__setitem__("pdb_codeview_identity", " bad "),
            "pdb_codeview",
        ),
    ]
    for mutation, message in mutations:
        changed = copy.deepcopy(manifest)
        mutation(changed)
        with pytest.raises(ValueError, match=message):
            canonical_site_universe_bytes(changed)


def test_policy_path_substitution_is_rejected_while_same_fd_is_held(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = tmp_path / "allowed-signers"
    replacement = tmp_path / "replacement"
    policy.write_text(
        "windows-ioctl-site-universe@0verse ssh-ed25519 AAAAattacker\n",
        encoding="utf-8",
    )
    replacement.write_text("root-owned-looking replacement\n", encoding="utf-8")
    real_read = universe_module.os.read
    swapped = False

    def swap_path_after_first_read(descriptor: int, count: int) -> bytes:
        nonlocal swapped
        data = real_read(descriptor, count)
        if not swapped:
            swapped = True
            policy.unlink()
            policy.symlink_to(replacement)
        return data

    monkeypatch.setattr(universe_module.os, "read", swap_path_after_first_read)
    with pytest.raises(ValueError, match=r"changed while it was read|path changed"):
        universe_module._read_policy(policy, production=True)


def test_rejects_wrong_role_and_noncanonical_signed_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, key, _policy, _artifact_value = _build(tmp_path, monkeypatch)
    _other_key, wrong_policy = _authority(tmp_path / "wrong", "rank-worker@0verse")
    with pytest.raises(ValueError, match="dedicated signer identity"):
        build_windows_ioctl_site_universe(_request(tmp_path), allowed_signers=wrong_policy)

    path = tmp_path / "pretty.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    Path(f"{path}.sig").write_text(
        sign_ssh_material(
            path.read_bytes(), signing_key=key, namespace=SIGNATURE_NAMESPACE, label="sites"
        ),
        encoding="utf-8",
    )
    _correct_key, correct_policy = _authority(tmp_path / "correct")
    # The encoding check happens before signature validation.
    with pytest.raises(ValueError, match="canonical encoding"):
        verify_windows_ioctl_site_universe(path, allowed_signers=correct_policy)


def test_requires_real_exact_v2_bundle_and_unique_request_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = _artifact(tmp_path)
    _key, policy = _authority(tmp_path)
    request = _request(tmp_path)
    monkeypatch.setattr(
        universe_module,
        "_load_artifact",
        lambda *_args: Artifact(**{**artifact.__dict__, "synthetic_fixture": True}),
    )
    with pytest.raises(ValueError, match="real analysis bundle"):
        build_windows_ioctl_site_universe(request, allowed_signers=policy)

    monkeypatch.setattr(
        universe_module,
        "_load_artifact",
        lambda *_args: Artifact(
            **{
                **artifact.__dict__,
                "binary_sha256": "9" * 64,
            }
        ),
    )
    with pytest.raises(ValueError, match="not bound"):
        build_windows_ioctl_site_universe(request, allowed_signers=policy)

    request.write_text('{"schema_version":"a","schema_version":"b"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        build_windows_ioctl_site_universe(request, allowed_signers=policy)


def test_cli_uses_fixed_policy_and_writes_exclusively(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, _key, policy, _artifact_value = _build(tmp_path, monkeypatch)
    monkeypatch.setattr(universe_module, "DEFAULT_ALLOWED_SIGNERS", policy)
    monkeypatch.setattr(
        universe_module, "build_windows_ioctl_site_universe", lambda _path: manifest
    )
    output = tmp_path / "manifest.json"

    assert main(["windows-ioctl-site-universe", "request.json", "--output", str(output)]) == 0
    assert output.read_bytes() == canonical_site_universe_bytes(manifest)
    assert main(["windows-ioctl-site-universe", "request.json", "--output", str(output)]) == 2
    with pytest.raises(SystemExit):
        main(
            [
                "windows-ioctl-site-universe",
                "request.json",
                "--allowed-signers",
                str(policy),
            ]
        )
    with pytest.raises(SystemExit):
        main(
            [
                "windows-ioctl-site-universe-verify",
                str(output),
                "--allowed-signers",
                str(policy),
            ]
        )

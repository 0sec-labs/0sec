from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest
from authorization_helpers import authorization_key, authorization_policy, sign_document
from test_windows_token_capture import _authority_bundle, _capture_matrix

from zeroverse import windows_token_pack as token_pack_module
from zeroverse.cli import main
from zeroverse.ssh_authorization import sign_ssh_material
from zeroverse.windows_token_capture import ExclusiveFileNonceLedger
from zeroverse.windows_token_evidence import (
    EVIDENCE_SIGNATURE_NAMESPACE,
    aggregate_windows_token_observation,
    derive_windows_token_evidence,
    observe_windows_token_evidence,
)
from zeroverse.windows_token_pack import (
    BUILD_SCHEMA_VERSION,
    ENVELOPE_SCHEMA_VERSION,
    PACK_MANIFEST_MEDIA_TYPE,
    PACK_SCHEMA_VERSION,
    PACK_SIGNATURE_MEDIA_TYPE,
    PACK_SIGNATURE_NAMESPACE,
    POLICY_SCHEMA_VERSION,
    BlobRef,
    BuiltWindowsTokenPack,
    build_windows_token_pack,
    verify_windows_token_pack,
)


def _canonical(raw: dict[str, object]) -> bytes:
    return json.dumps(
        raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _ref(data: bytes, media_type: str) -> dict[str, object]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sizeBytes": len(data),
        "mediaType": media_type,
    }


def _put(blobs: Path, data: bytes) -> dict[str, object]:
    reference = _ref(data, "application/json")
    (blobs / str(reference["sha256"])).write_bytes(data)
    return reference


def _closure(
    tmp_path: Path,
    *,
    target_transition: bool = True,
    authority_kwargs: dict[str, object] | None = None,
    role_policies: dict[str, Path] | None = None,
    role_identities: dict[str, str] | None = None,
    role_signing_keys: dict[str, Path] | None = None,
    pack_policy: Path | None = None,
    pack_signing_key: Path | None = None,
    pack_signer_identity: str = "operator@example.test",
    run_id: str = "windows-token-run-001",
    job_nonce: str = "job_nonce_00000000000000000000001",
    nonce_tag: str = "",
) -> dict[str, Path | dict[str, object]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    authorities = _authority_bundle(tmp_path, **(authority_kwargs or {}))
    captures = _capture_matrix(
        tmp_path,
        authorities,
        target_transition=target_transition,
        capture_policy=(role_policies or {}).get("capture"),
        nonce_tag=nonce_tag,
        capture_signing_key=(role_signing_keys or {}).get("capture"),
    )
    evidence = (
        derive_windows_token_evidence(captures, *authorities)
        if target_transition
        else observe_windows_token_evidence(captures, *authorities).evidence
    )
    receipt = evidence.signed_receipt(
        signed_by=(role_identities or {}).get("aggregateReceipt", "operator@example.test"),
        signing_key=(role_signing_keys or {}).get(
            "aggregateReceipt", authorization_key()
        ),
    )
    receipt_path = tmp_path / "aggregate.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    blobs = tmp_path / "blobs"
    blobs.mkdir()
    artifact_paths = {
        "campaign": tmp_path / "campaign.json",
        "scopeManifest": tmp_path / "scope.json",
        "executionGrant": tmp_path / "grant.json",
        "workerAcceptance": tmp_path / "acceptance.json",
        "aggregateReceipt": receipt_path,
    }
    artifact_refs = {
        name: _put(blobs, path.read_bytes()) for name, path in artifact_paths.items()
    }

    matrix_rows: list[dict[str, object]] = []
    for capture in captures:
        path = tmp_path / f"capture-{capture.case}-{capture.trial}.json"
        matrix_rows.append(
            {
                "case": capture.case,
                "trial": capture.trial,
                "artifact": _put(blobs, path.read_bytes()),
            }
        )

    base_policy = authorization_policy().read_bytes()
    role_names = (
        "scopeAuthorization",
        "executionGrantAuthorization",
        "workerAcceptanceAuthorization",
        "capture",
        "aggregateReceipt",
    )
    policy_refs: dict[str, dict[str, object]] = {}
    policy_digests: dict[str, str] = {}
    for role in role_names:
        source_role = {
            "scopeAuthorization": "scope",
            "executionGrantAuthorization": "grant",
            "workerAcceptanceAuthorization": "acceptance",
            "capture": "capture",
            "aggregateReceipt": "aggregateReceipt",
        }[role]
        policy_bytes = (
            (role_policies or {})[source_role].read_bytes()
            if source_role in (role_policies or {})
            else base_policy + f"# {role}\n".encode()
        )
        reference = _ref(policy_bytes, "text/plain")
        (blobs / str(reference["sha256"])).write_bytes(policy_bytes)
        policy_refs[role] = reference
        policy_digests[role] = str(reference["sha256"])

    resolved_pack_policy = pack_policy or (tmp_path / "pack-allowed-signers")
    if pack_policy is None:
        resolved_pack_policy.write_bytes(base_policy + b"# pack\n")
    pack_policy_digest = hashlib.sha256(resolved_pack_policy.read_bytes()).hexdigest()
    runtime_digest = f"sha256:{'1' * 64}"
    manifest: dict[str, object] = {
        "schemaVersion": PACK_SCHEMA_VERSION,
        "runId": run_id,
        "jobNonce": job_nonce,
        **artifact_refs,
        "matrix": {"trials": 2, "captures": matrix_rows},
        "signerPolicies": policy_refs,
        "zeroverseRuntime": {"kind": "oci-image", "digest": runtime_digest},
        "packSignerIdentity": pack_signer_identity,
    }
    manifest_bytes = _canonical(manifest)
    manifest_ref = _ref(manifest_bytes, PACK_MANIFEST_MEDIA_TYPE)
    (blobs / str(manifest_ref["sha256"])).write_bytes(manifest_bytes)
    signature = sign_ssh_material(
        manifest_bytes,
        signing_key=pack_signing_key or authorization_key(),
        namespace=PACK_SIGNATURE_NAMESPACE,
        label="test Windows token pack",
    ).encode()
    signature_ref = _ref(signature, PACK_SIGNATURE_MEDIA_TYPE)
    (blobs / str(signature_ref["sha256"])).write_bytes(signature)

    envelope: dict[str, object] = {
        "schemaVersion": ENVELOPE_SCHEMA_VERSION,
        "packId": manifest_ref["sha256"],
        "manifest": manifest_ref,
        "signature": signature_ref,
    }
    envelope_path = tmp_path / "envelope.json"
    envelope_path.write_text(json.dumps(envelope), encoding="utf-8")
    expected: dict[str, object] = {
        "runId": manifest["runId"],
        "jobNonce": manifest["jobNonce"],
        "packSignerPolicySha256": pack_policy_digest,
        "campaignSha256": artifact_refs["campaign"]["sha256"],
        "scopeManifestSha256": artifact_refs["scopeManifest"]["sha256"],
        "executionGrantSha256": artifact_refs["executionGrant"]["sha256"],
        "workerAcceptanceSha256": artifact_refs["workerAcceptance"]["sha256"],
    }
    expected_path = tmp_path / "expected.json"
    expected_path.write_text(json.dumps(expected), encoding="utf-8")
    policy: dict[str, object] = {
        "schemaVersion": POLICY_SCHEMA_VERSION,
        "allowedPackSignerIdentities": [pack_signer_identity],
        "allowedPackSignerPolicySha256": [pack_policy_digest],
        "allowedZeroverseOciDigests": [runtime_digest],
        "allowedScopeSignerPolicySha256": [policy_digests["scopeAuthorization"]],
        "allowedExecutionGrantSignerPolicySha256": [
            policy_digests["executionGrantAuthorization"]
        ],
        "allowedWorkerAcceptanceSignerPolicySha256": [
            policy_digests["workerAcceptanceAuthorization"]
        ],
        "allowedCaptureSignerPolicySha256": [policy_digests["capture"]],
        "allowedAggregateReceiptSignerPolicySha256": [
            policy_digests["aggregateReceipt"]
        ],
        "maxBlobSizeBytes": 1024 * 1024,
        "maxBundleSizeBytes": 16 * 1024 * 1024,
    }
    policy_path = tmp_path / "acceptance-policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    return {
        "envelope": envelope_path,
        "blobs": blobs,
        "policy": policy_path,
        "expected": expected_path,
        "pack_policy": resolved_pack_policy,
        "envelope_raw": envelope,
    }


def _production_build(
    tmp_path: Path, *, target_transition: bool, private_parent: bool = True
) -> tuple[BuiltWindowsTokenPack, dict[str, Path]]:
    inputs = tmp_path / "inputs"
    inputs.mkdir(parents=True)
    tmp_path.chmod(0o700 if private_parent else 0o755)
    authorities = _authority_bundle(inputs)
    captures = _capture_matrix(
        inputs,
        authorities,
        target_transition=target_transition,
    )
    observation = aggregate_windows_token_observation(
        captures,
        *authorities,
        ExclusiveFileNonceLedger(inputs / "neutral-ledger"),
    )
    receipt = observation.evidence.signed_receipt(
        signed_by="operator@example.test",
        signing_key=authorization_key(),
    )
    aggregate = inputs / "aggregate.json"
    aggregate.write_text(json.dumps(receipt), encoding="utf-8")

    policy_bytes = authorization_policy().read_bytes()
    policies: dict[str, Path] = {}
    for role in ("scope", "grant", "acceptance", "capture", "aggregate"):
        path = inputs / f"{role}.allowed-signers"
        path.write_bytes(policy_bytes + f"# {role}\n".encode())
        policies[role] = path
    pack_policy = inputs / "pack.allowed-signers"
    pack_policy.write_bytes(policy_bytes + b"# pack\n")
    policies["pack"] = pack_policy

    built = build_windows_token_pack(
        tmp_path / "pack",
        campaign_path=inputs / "campaign.json",
        scope_manifest_path=inputs / "scope.json",
        execution_grant_path=inputs / "grant.json",
        worker_acceptance_path=inputs / "acceptance.json",
        aggregate_receipt_path=aggregate,
        capture_paths=[
            inputs / f"capture-{capture.case}-{capture.trial}.json"
            for capture in reversed(captures)
        ],
        scope_allowed_signers_path=policies["scope"],
        execution_grant_allowed_signers_path=policies["grant"],
        worker_acceptance_allowed_signers_path=policies["acceptance"],
        capture_allowed_signers_path=policies["capture"],
        aggregate_allowed_signers_path=policies["aggregate"],
        run_id="windows-token-run-production-001",
        job_nonce="job_nonce_00000000000000000000001",
        zeroverse_runtime_digest=f"sha256:{'1' * 64}",
        pack_signer_identity="operator@example.test",
        pack_signing_key=authorization_key(),
    )
    expected = {
        **built.context_commitments,
        "packSignerPolicySha256": hashlib.sha256(pack_policy.read_bytes()).hexdigest(),
    }
    expected_path = inputs / "expected.json"
    expected_path.write_text(json.dumps(expected), encoding="utf-8")
    acceptance_policy = {
        "schemaVersion": POLICY_SCHEMA_VERSION,
        "allowedPackSignerIdentities": ["operator@example.test"],
        "allowedPackSignerPolicySha256": [expected["packSignerPolicySha256"]],
        "allowedZeroverseOciDigests": [f"sha256:{'1' * 64}"],
        "allowedScopeSignerPolicySha256": [
            hashlib.sha256(policies["scope"].read_bytes()).hexdigest()
        ],
        "allowedExecutionGrantSignerPolicySha256": [
            hashlib.sha256(policies["grant"].read_bytes()).hexdigest()
        ],
        "allowedWorkerAcceptanceSignerPolicySha256": [
            hashlib.sha256(policies["acceptance"].read_bytes()).hexdigest()
        ],
        "allowedCaptureSignerPolicySha256": [
            hashlib.sha256(policies["capture"].read_bytes()).hexdigest()
        ],
        "allowedAggregateReceiptSignerPolicySha256": [
            hashlib.sha256(policies["aggregate"].read_bytes()).hexdigest()
        ],
        "maxBlobSizeBytes": 1024 * 1024,
        "maxBundleSizeBytes": 16 * 1024 * 1024,
    }
    acceptance_path = inputs / "acceptance-policy.json"
    acceptance_path.write_text(json.dumps(acceptance_policy), encoding="utf-8")
    policies["expected"] = expected_path
    policies["acceptance_policy"] = acceptance_path
    policies["aggregate_receipt"] = aggregate
    return built, policies


def _verify(bundle: dict[str, Path | dict[str, object]]):
    return verify_windows_token_pack(
        bundle["envelope"],
        blob_dir=bundle["blobs"],
        acceptance_policy_path=bundle["policy"],
        expected_context_path=bundle["expected"],
        pack_signer_policy_path=bundle["pack_policy"],
    )


def _rewrite_manifest(
    bundle: dict[str, Path | dict[str, object]],
    mutate: Callable[[dict[str, object], Path], None],
) -> None:
    envelope_path = bundle["envelope"]
    blobs = bundle["blobs"]
    assert isinstance(envelope_path, Path) and isinstance(blobs, Path)
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    manifest_path = blobs / envelope["manifest"]["sha256"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    mutate(manifest, blobs)
    manifest_bytes = _canonical(manifest)
    manifest_ref = _ref(manifest_bytes, PACK_MANIFEST_MEDIA_TYPE)
    (blobs / str(manifest_ref["sha256"])).write_bytes(manifest_bytes)
    signature = sign_ssh_material(
        manifest_bytes,
        signing_key=authorization_key(),
        namespace=PACK_SIGNATURE_NAMESPACE,
        label="rewritten test Windows token pack",
    ).encode()
    signature_ref = _ref(signature, PACK_SIGNATURE_MEDIA_TYPE)
    (blobs / str(signature_ref["sha256"])).write_bytes(signature)
    envelope.update(
        {
            "packId": manifest_ref["sha256"],
            "manifest": manifest_ref,
            "signature": signature_ref,
        }
    )
    envelope_path.write_text(json.dumps(envelope), encoding="utf-8")


def test_full_signed_closure_is_verified_without_acceptance_or_replay(
    tmp_path: Path,
) -> None:
    bundle = _closure(tmp_path)
    verification = _verify(bundle).to_dict()
    assert verification["status"] == "ARTIFACT_CLOSURE_VERIFIED"
    assert verification["target_confirmations"] == 2
    assert verification["clean_controls"] == 2
    assert verification["runtime_provenance"] == "outer-signed-allowlisted-not-attested"
    assert verification["closure_commitment_sha256"] == verification["pack_id"]
    assert verification["schema_version"] == "0verse.windows-token-pack-verification/v3"
    assert verification["witness_user_sid"] == "S-1-5-21-1-2-3-1001"
    assert verification["witness_session_id"] == 1
    assert verification["witness_authentication_id"] == "0000000000001001"
    assert verification["witness_executable_sha256"] == "d" * 64
    assert (
        verification["grant_replay_identity_sha256"]
        == "84a4d242d9db45e95fcf7e88efbe3d1624e375a12a306c7b4105077f476b437f"
    )
    assert verification["ordered_run_replay_identity_sha256"] == [
        "3c83652989282dc2719c6cf6908245a6cf15db3e7e80f1be13594e38ddf3ee89",
        "3d6dc17e57bb163f7754de7e02581d3bcc92f7bbe512017fce54c8c18a407d84",
        "4f607232e091e759c3fa1f931e7671f97e738af0ed4baa4b55b949fe6a281cc9",
        "a17fd455be1e5c993b8f956629bc23873fd352cedfb32df6b52bdc95c42bf043",
    ]
    assert verification["replay_state_consumed"] is False
    assert verification["accepted"] is False
    assert verification["claim_eligible"] is False
    assert not list(tmp_path.rglob("*.used"))


def test_broker_verification_model_fails_before_mislabeling_process_identity(
    tmp_path: Path,
) -> None:
    verification = _verify(_closure(tmp_path))
    broker_model = replace(
        verification,
        ordered_broker_receipt_replay_identity_sha256=("a" * 64,),
        ordered_broker_process_replay_identity_sha256=("b" * 64,),
        ordered_broker_transcript_replay_identity_sha256=("c" * 64,),
        broker_receipt_authority_key_commitment_sha256="d" * 64,
        broker_receipt_signer_identity="broker@example.test",
    )
    with pytest.raises(ValueError, match="acceptance-witness/measured-process"):
        broker_model.to_dict()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ordered_broker_receipt_replay_identity_sha256", ("a" * 64,)),
        ("ordered_broker_process_replay_identity_sha256", ("b" * 64,)),
        ("ordered_broker_transcript_replay_identity_sha256", ("c" * 64,)),
        ("broker_receipt_authority_key_commitment_sha256", "d" * 64),
        ("broker_receipt_signer_identity", "broker@example.test"),
    ],
)
def test_partial_broker_verification_model_is_incoherent(
    tmp_path: Path, field: str, value: object
) -> None:
    verification = _verify(_closure(tmp_path))
    with pytest.raises(ValueError, match="fields are incoherent"):
        replace(verification, **{field: value}).to_dict()


def test_lpac_pack_and_policy_use_strict_additive_schema_versions(tmp_path: Path) -> None:
    bundle = _closure(tmp_path)
    blobs = bundle["blobs"]
    envelope = bundle["envelope_raw"]
    assert isinstance(blobs, Path) and isinstance(envelope, dict)
    manifest_ref = envelope["manifest"]
    assert isinstance(manifest_ref, dict)
    manifest = json.loads((blobs / str(manifest_ref["sha256"])).read_text())

    broker_rows = []
    for index, capture in enumerate(manifest["matrix"]["captures"]):
        data = _canonical({"broker_fixture": index})
        broker_rows.append(
            {
                "case": capture["case"],
                "trial": capture["trial"],
                "artifact": _put(blobs, data),
            }
        )
    broker_policy = b"broker@example.test ssh-ed25519 AAAATEST broker\n"
    broker_policy_ref = _ref(broker_policy, "text/plain")
    (blobs / str(broker_policy_ref["sha256"])).write_bytes(broker_policy)
    manifest["brokerReceipts"] = broker_rows
    manifest["signerPolicies"]["lpacBrokerReceipt"] = broker_policy_ref

    manifest["schemaVersion"] = token_pack_module.LPAC_PACK_SCHEMA_VERSION
    parsed = token_pack_module._parse_manifest(_canonical(manifest))
    assert parsed["schemaVersion"] == "0sec.windows-token-evidence-pack/v2"
    manifest["schemaVersion"] = token_pack_module.PACK_SCHEMA_VERSION
    with pytest.raises(ValueError, match="schema is unsupported"):
        token_pack_module._parse_manifest(_canonical(manifest))

    policy = json.loads(Path(bundle["policy"]).read_text())
    policy["allowedLpacBrokerReceiptSignerPolicySha256"] = [
        str(broker_policy_ref["sha256"])
    ]
    policy["schemaVersion"] = token_pack_module.LPAC_POLICY_SCHEMA_VERSION
    parsed_policy = token_pack_module._parse_policy(policy)
    assert parsed_policy["schemaVersion"] == (
        "0sec.windows-token-evidence-acceptance-policy/v2"
    )
    policy["schemaVersion"] = token_pack_module.POLICY_SCHEMA_VERSION
    with pytest.raises(ValueError, match="schema is unsupported"):
        token_pack_module._parse_policy(policy)


def test_full_signed_closure_preserves_non_admin_session_zero(tmp_path: Path) -> None:
    bundle = _closure(
        tmp_path,
        authority_kwargs={"acceptance_overrides": {"witness_session_id": 0}},
    )
    verification = _verify(bundle).to_dict()
    assert verification["status"] == "ARTIFACT_CLOSURE_VERIFIED"
    assert verification["witness_session_id"] == 0
    assert verification["accepted"] is False
    assert verification["claim_eligible"] is False


def test_envelope_context_blob_and_policy_substitution_fail(tmp_path: Path) -> None:
    bundle = _closure(tmp_path)
    envelope_path = bundle["envelope"]
    assert isinstance(envelope_path, Path)
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    envelope["packId"] = "f" * 64
    envelope["manifest"]["sha256"] = "f" * 64
    envelope_path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises((FileNotFoundError, ValueError)):
        _verify(bundle)

    bundle = _closure(tmp_path / "context")
    expected_path = bundle["expected"]
    assert isinstance(expected_path, Path)
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    expected["runId"] = "different-run"
    expected_path.write_text(json.dumps(expected), encoding="utf-8")
    with pytest.raises(ValueError, match="runId differs"):
        _verify(bundle)

    bundle = _closure(tmp_path / "policy")
    pack_policy = bundle["pack_policy"]
    assert isinstance(pack_policy, Path)
    pack_policy.write_bytes(pack_policy.read_bytes() + b"# substituted\n")
    with pytest.raises(ValueError, match="policy differs"):
        _verify(bundle)

    bundle = _closure(
        tmp_path / "pack-identity",
        pack_signer_identity="different@example.test",
    )
    with pytest.raises(ValueError, match="signature is invalid"):
        _verify(bundle)


def test_stateless_pack_verifier_accepts_neutral_clean_fixed_observation(
    tmp_path: Path,
) -> None:
    verification = _verify(_closure(tmp_path, target_transition=False))
    assert verification.target_confirmations == 0
    assert verification.clean_target_no_transitions == 2
    assert verification.ambiguous_targets == 0
    assert verification.clean_controls == 2
    assert verification.to_dict()["claim_eligible"] is False


@pytest.mark.parametrize(
    ("target_transition", "expected_confirmations"),
    [(True, 2), (False, 0)],
)
def test_production_builder_round_trips_candidate_and_clean_fixed_pack(
    tmp_path: Path,
    target_transition: bool,
    expected_confirmations: int,
) -> None:
    built, paths = _production_build(
        tmp_path,
        target_transition=target_transition,
    )
    verification = verify_windows_token_pack(
        built.envelope_path,
        blob_dir=built.blob_dir,
        acceptance_policy_path=paths["acceptance_policy"],
        expected_context_path=paths["expected"],
        pack_signer_policy_path=paths["pack"],
    )
    assert verification.pack_id == built.pack_id
    assert verification.target_confirmations == expected_confirmations
    assert verification.clean_controls == 2
    assert {path.name for path in built.blob_dir.iterdir()} == {
        ref.sha256 for ref in built.blob_refs
    }
    assert all(
        hashlib.sha256((built.blob_dir / ref.sha256).read_bytes()).hexdigest() == ref.sha256
        for ref in built.blob_refs
    )
    assert hashlib.sha256(built.envelope_path.read_bytes()).hexdigest() == (
        built.envelope_ref.sha256
    )
    refs = json.loads(built.refs_path.read_text(encoding="utf-8"))
    assert refs == built.to_dict()
    assert refs["schema_version"] == BUILD_SCHEMA_VERSION


def test_pack_builder_is_deterministic_and_cli_emits_exact_refs(tmp_path: Path, capsys) -> None:
    first, paths = _production_build(tmp_path / "first", target_transition=True)
    inputs = tmp_path / "first" / "inputs"
    captures = [
        inputs / f"capture-{case}-{trial}.json"
        for trial in (1, 2)
        for case in ("target", "control")
    ]
    argv = [
        "windows-token-pack-build",
        str(tmp_path / "second-pack"),
        "--campaign",
        str(inputs / "campaign.json"),
        "--scope-manifest",
        str(inputs / "scope.json"),
        "--execution-grant",
        str(inputs / "grant.json"),
        "--worker-acceptance",
        str(inputs / "acceptance.json"),
        "--aggregate-receipt",
        str(paths["aggregate_receipt"]),
    ]
    for capture in captures:
        argv.extend(("--capture", str(capture)))
    argv.extend(
        (
            "--scope-allowed-signers",
            str(paths["scope"]),
            "--execution-grant-allowed-signers",
            str(paths["grant"]),
            "--worker-acceptance-allowed-signers",
            str(paths["acceptance"]),
            "--capture-allowed-signers",
            str(paths["capture"]),
            "--aggregate-allowed-signers",
            str(paths["aggregate"]),
            "--run-id",
            "windows-token-run-production-001",
            "--job-nonce",
            "job_nonce_00000000000000000000001",
            "--zeroverse-runtime-digest",
            f"sha256:{'1' * 64}",
            "--pack-signer-identity",
            "operator@example.test",
            "--pack-signing-key",
            str(authorization_key()),
        )
    )
    assert main(argv) == 0
    cli_result = json.loads(capsys.readouterr().out)
    assert cli_result == first.to_dict()
    assert (tmp_path / "second-pack" / "envelope.json").read_bytes() == (
        first.envelope_path.read_bytes()
    )


def test_builder_enforces_unique_bundle_limit_before_pack_signing(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(token_pack_module, "_MAX_BUNDLE_BYTES", 10)
    exact = (
        BlobRef("1" * 64, 7, "application/json"),
        BlobRef("1" * 64, 7, "application/json"),
        BlobRef("2" * 64, 3, "text/plain"),
    )
    token_pack_module._require_build_bundle_size(exact)
    with pytest.raises(ValueError, match="producer bundle limit"):
        token_pack_module._require_build_bundle_size(
            (*exact, BlobRef("3" * 64, 1, "application/json"))
        )

    monkeypatch.setattr(token_pack_module, "_MAX_BUNDLE_BYTES", 1)

    def unexpected_sign(*_args, **_kwargs):
        raise AssertionError("over-limit pack reached signing")

    monkeypatch.setattr(token_pack_module, "sign_ssh_material", unexpected_sign)
    with pytest.raises(ValueError, match="leaves no room"):
        _production_build(tmp_path / "over-limit", target_transition=True)
    assert not (tmp_path / "over-limit" / "pack").exists()


def test_private_dirfd_publication_rejects_races_and_fsyncs_directories(
    tmp_path: Path, monkeypatch
) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    blob_data = b"blob"
    blob_digest = hashlib.sha256(blob_data).hexdigest()
    publish_args = {
        "envelope_bytes": b"{}",
        "blob_bytes": {blob_digest: (blob_data, "application/json")},
        "refs_bytes": b"{}\n",
    }

    directory_fsyncs: list[tuple[int, int]] = []
    real_fsync = os.fsync

    def record_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if stat.S_ISDIR(metadata.st_mode):
            directory_fsyncs.append((metadata.st_dev, metadata.st_ino))
        real_fsync(descriptor)

    monkeypatch.setattr(token_pack_module.os, "fsync", record_fsync)
    destination = private_root / "published"
    token_pack_module._publish_pack_directory(destination, **publish_args)
    assert directory_fsyncs[-3:] == [
        (destination.joinpath("blobs").stat().st_dev, destination.joinpath("blobs").stat().st_ino),
        (destination.stat().st_dev, destination.stat().st_ino),
        (private_root.stat().st_dev, private_root.stat().st_ino),
    ]

    existing = private_root / "existing"
    existing.mkdir()
    (existing / "sentinel").write_text("preserve", encoding="utf-8")
    with pytest.raises(FileExistsError, match="already exists"):
        token_pack_module._publish_pack_directory(existing, **publish_args)
    assert (existing / "sentinel").read_text(encoding="utf-8") == "preserve"

    calls = 0
    original_inode_check = token_pack_module._require_same_directory_inode

    def swapped_parent(parent: Path, expected: os.stat_result) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ValueError("token pack output parent changed during publication")
        original_inode_check(parent, expected)

    monkeypatch.setattr(
        token_pack_module,
        "_require_same_directory_inode",
        swapped_parent,
    )
    swapped_destination = private_root / "swapped"
    with pytest.raises(ValueError, match="parent changed"):
        token_pack_module._publish_pack_directory(swapped_destination, **publish_args)
    assert not swapped_destination.exists()
    assert not any(path.name.startswith(".swapped.") for path in private_root.iterdir())

    public_root = tmp_path / "public"
    public_root.mkdir(mode=0o755)
    public_root.chmod(0o755)
    with pytest.raises(ValueError, match="owner-only"):
        token_pack_module._publish_pack_directory(public_root / "pack", **publish_args)
    assert not (public_root / "pack").exists()

    unsafe_grandparent = tmp_path / "unsafe-grandparent"
    unsafe_grandparent.mkdir(mode=0o777)
    unsafe_grandparent.chmod(0o777)
    nested_private = unsafe_grandparent / "private"
    nested_private.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="non-sticky writable directory"):
        token_pack_module._publish_pack_directory(
            nested_private / "pack",
            **publish_args,
        )
    assert not (nested_private / "pack").exists()

    sticky_grandparent = tmp_path / "sticky-grandparent"
    sticky_grandparent.mkdir(mode=0o700)
    sticky_grandparent.chmod(0o1777)
    sticky_owned_child = sticky_grandparent / "publisher-owned"
    sticky_owned_child.mkdir(mode=0o700)
    token_pack_module._publish_pack_directory(
        sticky_owned_child / "pack",
        **publish_args,
    )
    assert (sticky_owned_child / "pack" / "envelope.json").is_file()


def test_parent_fsync_failure_reports_published_but_unconfirmed(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    parent_identity = (root.stat().st_dev, root.stat().st_ino)
    real_fsync = os.fsync

    def fail_parent_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if stat.S_ISDIR(metadata.st_mode) and (metadata.st_dev, metadata.st_ino) == parent_identity:
            raise OSError("fixture parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(token_pack_module.os, "fsync", fail_parent_fsync)
    destination = root / "published"
    with pytest.raises(RuntimeError, match="published but parent durability is unconfirmed"):
        token_pack_module._publish_pack_directory(
            destination,
            envelope_bytes=b"{}",
            blob_bytes={},
            refs_bytes=b"{}\n",
        )
    assert destination.is_dir()


def test_reordered_matrix_and_resigned_false_aggregate_fail(tmp_path: Path) -> None:
    bundle = _closure(tmp_path / "reorder")

    def reorder(manifest: dict[str, object], _blobs: Path) -> None:
        matrix = manifest["matrix"]
        assert isinstance(matrix, dict)
        captures = matrix["captures"]
        assert isinstance(captures, list)
        captures[0], captures[1] = captures[1], captures[0]

    _rewrite_manifest(bundle, reorder)
    with pytest.raises(ValueError, match="canonical target/control order"):
        _verify(bundle)

    bundle = _closure(tmp_path / "aggregate")

    def forge_aggregate(manifest: dict[str, object], blobs: Path) -> None:
        aggregate_ref = manifest["aggregateReceipt"]
        assert isinstance(aggregate_ref, dict)
        aggregate_path = blobs / str(aggregate_ref["sha256"])
        aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
        aggregate["target_confirmations"] = 1
        forged = json.dumps(
            sign_document(aggregate, EVIDENCE_SIGNATURE_NAMESPACE)
        ).encode()
        reference = _ref(forged, "application/json")
        (blobs / str(reference["sha256"])).write_bytes(forged)
        manifest["aggregateReceipt"] = reference

    _rewrite_manifest(bundle, forge_aggregate)
    with pytest.raises(ValueError, match="target_confirmations differs"):
        _verify(bundle)


def test_cas_blob_tamper_and_symlink_fail(tmp_path: Path) -> None:
    bundle = _closure(tmp_path / "tamper")
    envelope_path = bundle["envelope"]
    blobs = bundle["blobs"]
    assert isinstance(envelope_path, Path) and isinstance(blobs, Path)
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    manifest_path = blobs / envelope["manifest"]["sha256"]
    original = manifest_path.read_bytes()
    manifest_path.write_bytes(original[:-1] + (b"}" if original[-1:] != b"}" else b"]"))
    with pytest.raises(ValueError, match="bytes differ"):
        _verify(bundle)

    bundle = _closure(tmp_path / "symlink")
    envelope_path = bundle["envelope"]
    blobs = bundle["blobs"]
    assert isinstance(envelope_path, Path) and isinstance(blobs, Path)
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    manifest_path = blobs / envelope["manifest"]["sha256"]
    real_path = tmp_path / "outside-manifest"
    real_path.write_bytes(manifest_path.read_bytes())
    manifest_path.unlink()
    manifest_path.symlink_to(real_path)
    with pytest.raises(OSError):
        _verify(bundle)


def test_cli_reports_stateless_safety_gates(tmp_path: Path, capsys) -> None:
    bundle = _closure(tmp_path)
    result = main(
        [
            "windows-token-pack-verify",
            str(bundle["envelope"]),
            "--blob-dir",
            str(bundle["blobs"]),
            "--acceptance-policy",
            str(bundle["policy"]),
            "--expected-context",
            str(bundle["expected"]),
            "--pack-signer-policy",
            str(bundle["pack_policy"]),
        ]
    )
    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["accepted"] is False
    assert payload["claim_eligible"] is False
    assert payload["human_report_gate"] is True

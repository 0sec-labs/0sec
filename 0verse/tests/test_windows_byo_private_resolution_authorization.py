from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from test_windows_ioctl_real_eval import _authority, _closure

from zeroverse.ssh_authority_commitment import ssh_authority_key_commitment
from zeroverse.ssh_authorization import canonical_signed_material, sign_ssh_material
from zeroverse.windows_byo_corpus import BYO_CORPUS_COMMITMENT_SCHEME
from zeroverse.windows_byo_private_construction import CONSTRUCTION_PROFILE
from zeroverse.windows_byo_private_resolution_authorization import (
    AUTHORIZED_OPERATION,
    PRODUCER,
    PROOF_LIMIT,
    PURPOSE,
    SCHEMA_VERSION,
    SIGNATURE_NAMESPACE,
    derive_tuple_replay_identity,
    verify_private_resolution_authorization,
)
from zeroverse.windows_ioctl_real_eval import (
    EVAL_VERSION_V2,
    LABEL_VERSION_V2,
    RANK_RECEIPT_VERSION_V2,
    evaluate_windows_ioctl_real_static,
)
from zeroverse.windows_ioctl_real_rank import BYO_BINDING_FIELDS, RESULT_VERSION_V3


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical(raw: dict[str, Any]) -> bytes:
    return json.dumps(
        raw,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _signed_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    authorization_mutator: Any | None = None,
    evaluation_mutator: Any | None = None,
    resolver_collision: bool = False,
) -> tuple[list[Path], Path, Path, dict[str, Any]]:
    result_path, receipt_path, labels_path, receipt_policy, label_policy = _closure(
        tmp_path, monkeypatch, byo=True
    )
    inventory_path = tmp_path / "byo" / "inventory.json"
    evaluated = evaluate_windows_ioctl_real_static(
        result_path,
        receipt_path,
        labels_path,
        rank_receipt_allowed_signers=receipt_policy,
        label_allowed_signers=label_policy,
    )
    if evaluation_mutator is not None:
        evaluation_mutator(evaluated)
    evaluation_path = tmp_path / "evaluation.json"
    evaluation_path.write_bytes(_canonical(evaluated))

    result = json.loads(result_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    authorizer_key, authorizer_policy, authorizer = _authority(
        tmp_path, "resolution-authorizer", "resolution-authorizer@example.test"
    )
    if resolver_collision:
        resolver_policy = authorizer_policy
        resolver = authorizer
    else:
        _resolver_key, resolver_policy, resolver = _authority(
            tmp_path, "private-resolver", "private-resolver@example.test"
        )
    issued = max(datetime.now(UTC), datetime.fromisoformat(receipt["issued_at"]))
    raw: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "producer": PRODUCER,
        "purpose": PURPOSE,
        "authorized_operation": AUTHORIZED_OPERATION,
        "construction_profile": CONSTRUCTION_PROFILE,
        "commitment_scheme": BYO_CORPUS_COMMITMENT_SCHEME,
        **{name: result[name] for name in BYO_BINDING_FIELDS},
        "campaign_id": result["campaign_id"],
        "campaign_sha256": result["campaign_sha256"],
        "admission_sha256": result["admission_sha256"],
        "analysis_run_id": result["analysis_run_id"],
        "driver_sha256": result["driver_sha256"],
        "pdb_sha256": result["pdb_sha256"],
        "pdb_codeview_identity": result["pdb_codeview_identity"],
        "analysis_sha256": result["analysis_sha256"],
        "analysis_receipt_sha256": result["analysis_receipt_sha256"],
        "rank_contract": RESULT_VERSION_V3,
        "rank_result_sha256": _sha(result_path),
        "rank_receipt_contract": RANK_RECEIPT_VERSION_V2,
        "rank_receipt_sha256": _sha(receipt_path),
        "labels_contract": LABEL_VERSION_V2,
        "labels_sha256": _sha(labels_path),
        "evaluation_contract": EVAL_VERSION_V2,
        "evaluation_sha256": _sha(evaluation_path),
        "evaluation_passed": True,
        "resolver_principal": resolver,
        "resolver_authority_key_commitment": ssh_authority_key_commitment(
            resolver_policy
        ),
        "max_private_bundle_resolutions": 1,
        "single_use": True,
        "human_authorized": True,
        "static_only": True,
        "runtime_consumable": False,
        "execution_authorized": False,
        "network_authorized": False,
        "redistribution_authorized": False,
        "disclosure_authorized": False,
        "weaponization_authorized": False,
        "private_bundle_verified": False,
        "secret_accessed": False,
        "zeroization_verified": False,
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(minutes=10)).isoformat(),
        "request_nonce": "private-resolution-request-nonce-00000001",
        "tuple_replay_identity_sha256": "",
        "proof_limit": PROOF_LIMIT,
        "authorizer_principal": authorizer,
        "authorizer_authority_key_commitment": ssh_authority_key_commitment(
            authorizer_policy
        ),
        "signature_ssh": "",
    }
    raw["tuple_replay_identity_sha256"] = derive_tuple_replay_identity(raw)
    if authorization_mutator is not None:
        authorization_mutator(raw, receipt)
        if raw.get("tuple_replay_identity_sha256") == "recompute":
            raw["tuple_replay_identity_sha256"] = derive_tuple_replay_identity(raw)
    raw["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(raw),
        signing_key=authorizer_key,
        namespace=SIGNATURE_NAMESPACE,
        label="test private resolution authorization",
    )
    authorization_path = tmp_path / "private-resolution-authorization.json"
    authorization_path.write_bytes(_canonical(raw))
    paths = [
        inventory_path,
        result_path,
        receipt_path,
        labels_path,
        evaluation_path,
        authorization_path,
        receipt_policy,
        label_policy,
    ]
    return paths, authorizer_policy, resolver_policy, raw


def _verify(
    paths: list[Path],
    authorizer_policy: Path,
    resolver_policy: Path,
    **kwargs: Any,
) -> Any:
    return verify_private_resolution_authorization(
        *paths[:6],
        rank_receipt_allowed_signers=paths[6],
        label_allowed_signers=paths[7],
        authorization_allowed_signers=authorizer_policy,
        resolver_allowed_signers=resolver_policy,
        **kwargs,
    )


def _reauthorize_evaluation_bytes(
    paths: list[Path], raw: dict[str, Any], authorizer_key: Path
) -> None:
    raw["evaluation_sha256"] = _sha(paths[4])
    raw["tuple_replay_identity_sha256"] = derive_tuple_replay_identity(raw)
    raw["signature_ssh"] = ""
    raw["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(raw),
        signing_key=authorizer_key,
        namespace=SIGNATURE_NAMESPACE,
        label="test reauthorization",
    )
    paths[5].write_bytes(_canonical(raw))


def test_verifies_exact_post_evaluation_authorization_without_private_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, authorizer_policy, resolver_policy, _ = _signed_authorization(
        tmp_path, monkeypatch
    )
    verified = _verify(paths, authorizer_policy, resolver_policy)
    assert len(set(verified.burn_only_replay_identities)) == 2
    assert verified.replay_state_consumed is False
    assert verified.private_bundle_verified is False
    assert verified.secret_accessed is False
    assert verified.zeroization_verified is False
    rendered = repr(verified).lower()
    for forbidden in ("bundle/", ".sys", ".pdb", "vulnerable", "control", "hmac key"):
        assert forbidden not in rendered


def test_fresh_request_nonce_cannot_evade_tuple_once_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first_paths, first_authorizer, first_resolver, raw = _signed_authorization(
        tmp_path / "first", monkeypatch
    )
    first = _verify(first_paths, first_authorizer, first_resolver)

    raw["request_nonce"] = "private-resolution-request-nonce-00000002"
    raw["signature_ssh"] = ""
    raw["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(raw),
        signing_key=tmp_path / "first" / "resolution-authorizer-key",
        namespace=SIGNATURE_NAMESPACE,
        label="test second private resolution authorization",
    )
    second_path = tmp_path / "first" / "private-resolution-authorization-2.json"
    second_path.write_bytes(_canonical(raw))
    second_paths = [*first_paths]
    second_paths[5] = second_path
    second = _verify(second_paths, first_authorizer, first_resolver)
    assert first.tuple_replay_identity_sha256 == second.tuple_replay_identity_sha256
    assert (
        first.authorization_replay_identity_sha256
        != second.authorization_replay_identity_sha256
    )
    with pytest.raises(ValueError, match="already burned"):
        _verify(
            second_paths,
            first_authorizer,
            first_resolver,
            burned_replay_identities=frozenset({first.tuple_replay_identity_sha256}),
        )


def test_rejects_unsigned_evaluation_that_differs_from_recomputation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, authorizer_policy, resolver_policy, _ = _signed_authorization(
        tmp_path,
        monkeypatch,
        evaluation_mutator=lambda value: value.__setitem__("recall_at_cutoff", 0.5),
    )
    with pytest.raises(ValueError, match="canonical deterministic recomputation"):
        _verify(paths, authorizer_policy, resolver_policy)


@pytest.mark.parametrize("alias", ["pretty-json", "false-as-zero"])
def test_evaluation_serialization_or_type_alias_cannot_change_tuple_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, alias: str
) -> None:
    paths, authorizer_policy, resolver_policy, raw = _signed_authorization(
        tmp_path, monkeypatch
    )
    evaluation = json.loads(paths[4].read_text(encoding="utf-8"))
    if alias == "pretty-json":
        paths[4].write_text(
            json.dumps(evaluation, indent=2, sort_keys=False) + "\n", encoding="utf-8"
        )
    else:
        evaluation["runtime_consumable"] = 0
        paths[4].write_bytes(_canonical(evaluation))
    _reauthorize_evaluation_bytes(
        paths, raw, tmp_path / "resolution-authorizer-key"
    )
    with pytest.raises(ValueError, match="canonical deterministic recomputation"):
        _verify(paths, authorizer_policy, resolver_policy)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("byo_item_commitment_sha256", "e" * 64, "artifact binding mismatch"),
        ("rank_result_sha256", "e" * 64, "artifact binding mismatch"),
        ("private_bundle_verified", True, "safety flags"),
        ("proof_limit", "broader claim", "unsupported"),
    ],
)
def test_rejects_signed_binding_or_safety_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
    message: str,
) -> None:
    def mutate(raw: dict[str, Any], _receipt: dict[str, Any]) -> None:
        raw[field] = value
        if field in {
            "byo_item_commitment_sha256",
            "rank_result_sha256",
            "labels_sha256",
            "evaluation_sha256",
        }:
            raw["tuple_replay_identity_sha256"] = "recompute"

    paths, authorizer_policy, resolver_policy, _ = _signed_authorization(
        tmp_path, monkeypatch, authorization_mutator=mutate
    )
    with pytest.raises(ValueError, match=message):
        _verify(paths, authorizer_policy, resolver_policy)


def test_rejects_authorizer_resolver_authority_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, authorizer_policy, resolver_policy, _ = _signed_authorization(
        tmp_path, monkeypatch, resolver_collision=True
    )
    with pytest.raises(ValueError, match="distinct principals and keys"):
        _verify(paths, authorizer_policy, resolver_policy)


@pytest.mark.parametrize("chronology", ["before-receipt", "expired", "overlong"])
def test_rejects_invalid_authorization_chronology(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, chronology: str
) -> None:
    now = datetime.now(UTC)

    def mutate(raw: dict[str, Any], receipt: dict[str, Any]) -> None:
        receipt_issued = datetime.fromisoformat(receipt["issued_at"])
        if chronology == "before-receipt":
            raw["issued_at"] = (receipt_issued - timedelta(seconds=1)).isoformat()
            raw["expires_at"] = (receipt_issued + timedelta(minutes=5)).isoformat()
        elif chronology == "expired":
            raw["issued_at"] = (now - timedelta(minutes=2)).isoformat()
            raw["expires_at"] = (now - timedelta(minutes=1)).isoformat()
        else:
            raw["issued_at"] = now.isoformat()
            raw["expires_at"] = (now + timedelta(minutes=16)).isoformat()

    paths, authorizer_policy, resolver_policy, _ = _signed_authorization(
        tmp_path, monkeypatch, authorization_mutator=mutate
    )
    with pytest.raises(ValueError, match="chronology"):
        _verify(paths, authorizer_policy, resolver_policy, now=now)


def test_rejects_noncanonical_or_extra_authorization_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, authorizer_policy, resolver_policy, raw = _signed_authorization(
        tmp_path, monkeypatch
    )
    paths[5].write_text(json.dumps(raw, indent=2, sort_keys=True), encoding="utf-8")
    with pytest.raises(ValueError, match="canonical JSON"):
        _verify(paths, authorizer_policy, resolver_policy)

    paths, authorizer_policy, resolver_policy, _ = _signed_authorization(
        tmp_path / "extra", monkeypatch,
        authorization_mutator=lambda value, _receipt: value.__setitem__("extra", False),
    )
    with pytest.raises(ValueError, match="fields mismatch"):
        _verify(paths, authorizer_policy, resolver_policy)


def test_rejects_legacy_non_byo_rank_chain_before_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, authorizer_policy, resolver_policy, _ = _signed_authorization(
        tmp_path, monkeypatch
    )
    result = json.loads(paths[1].read_text(encoding="utf-8"))
    result["schema_version"] = "0verse.windows-ioctl-real-static-candidates/v2"
    paths[1].write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
    with pytest.raises(ValueError, match="exact BYO v3/v2 closure"):
        _verify(paths, authorizer_policy, resolver_policy)


def test_signed_authorization_object_is_not_mutated_by_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, authorizer_policy, resolver_policy, raw = _signed_authorization(
        tmp_path, monkeypatch
    )
    before = deepcopy(raw)
    _verify(paths, authorizer_policy, resolver_policy)
    assert raw == before


def test_verifier_ignores_malicious_path_for_every_signature_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, authorizer_policy, resolver_policy, _ = _signed_authorization(
        tmp_path, monkeypatch
    )
    malicious = tmp_path / "malicious-bin"
    malicious.mkdir()
    fake = malicious / "ssh-keygen"
    fake.write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(malicious))
    verified = _verify(paths, authorizer_policy, resolver_policy)
    assert verified.secret_accessed is False

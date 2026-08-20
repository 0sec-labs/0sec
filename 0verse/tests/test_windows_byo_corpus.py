from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from zeroverse import windows_byo_corpus as byo_module
from zeroverse.cli import main
from zeroverse.ssh_authority_commitment import ssh_authority_key_commitment
from zeroverse.ssh_authorization import sign_ssh_material
from zeroverse.windows_byo_corpus import (
    BYO_CORPUS_CLAIMS,
    BYO_CORPUS_COMMITMENT_SCHEME,
    BYO_CORPUS_PROOF_LIMIT,
    BYO_CORPUS_SIGNATURE_NAMESPACE,
    _require_production_policy_permissions,
    _validate_production_policy,
    verify_windows_byo_corpus_manifest,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _authority(root: Path, name: str = "curator") -> tuple[Path, Path]:
    key = root / f"{name}.key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
        capture_output=True,
    )
    policy = root / f"{name}.allowed_signers"
    public = key.with_suffix(".key.pub").read_text(encoding="utf-8").strip()
    policy.write_text(f"corpus-curator@example.test {public}\n", encoding="utf-8")
    return key, policy


def _fixture(root: Path) -> tuple[Path, Path, dict[str, object]]:
    root.mkdir(parents=True, exist_ok=True)
    key, policy = _authority(root)
    items = sorted(
        [
            {
                "item_commitment_sha256": _digest("hmac-item-a"),
                "private_evidence_bundle_commitment_sha256": _digest("hmac-bundle-a"),
            },
            {
                "item_commitment_sha256": _digest("hmac-item-b"),
                "private_evidence_bundle_commitment_sha256": _digest("hmac-bundle-b"),
            },
        ],
        key=lambda value: value["item_commitment_sha256"],
    )
    raw: dict[str, object] = {
        "schema_version": "0verse.windows-byo-corpus-inventory/v1",
        "producer": "zeroverse.windows-byo-corpus-curation/v1",
        "inventory_id": f"inventory-{_digest('inventory')}",
        "inventory_nonce": "inventory-nonce-00000000000000000001",
        "declared_frozen_at": datetime.now(UTC).isoformat(),
        "artifact_policy": {
            "distribution": "commitments-only",
            "retained_bytes": "private-content-addressed-store",
            "permitted_analysis": "offline-static-only-after-separate-admission",
            "execution": "prohibited",
            "network": "prohibited",
        },
        "authority": {
            "manifest_signer_identity": "corpus-curator@example.test",
            "allowed_signers_sha256": hashlib.sha256(policy.read_bytes()).hexdigest(),
            "authority_key_commitment_sha256": ssh_authority_key_commitment(policy),
        },
        "commitment_scheme": BYO_CORPUS_COMMITMENT_SCHEME,
        "blinding_key_commitment_sha256": _digest("private-256-bit-hmac-key"),
        "declared_source_index_commitment_sha256": _digest("private-source-index"),
        "items": items,
        "safety_flags": {
            "metadata_only": True,
            "runtime_consumable": False,
            "automatic_download": False,
            "network_access_performed": False,
            "private_evidence_verified": False,
            "source_provenance_verified": False,
            "blinding_verified": False,
            "freeze_chronology_verified": False,
            "static_evaluation_admitted": False,
            "capability_verified": False,
            "reachability_verified": False,
            "vulnerability_verified": False,
            "impact_verified": False,
            "novelty_verified": False,
            "claim_eligible": False,
            "bounty_eligible": False,
            "execution_authorized": False,
            "redistribution_authorized": False,
            "disclosure_authorized": False,
            "automatic_disclosure": False,
            "weaponization_authorized": False,
            "human_source_review_required": True,
            "human_private_admission_required": True,
            "human_label_unblinding_required": True,
        },
        "verified_claims": BYO_CORPUS_CLAIMS,
        "proof_limit": BYO_CORPUS_PROOF_LIMIT,
    }
    path = root / "inventory.json"
    _write_signed(path, raw, key)
    return path, policy, raw


def _write_signed(path: Path, raw: dict[str, object], key: Path) -> None:
    path.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    Path(f"{path}.sig").write_text(
        sign_ssh_material(
            path.read_bytes(),
            signing_key=key,
            namespace=BYO_CORPUS_SIGNATURE_NAMESPACE,
            label="test BYO corpus inventory",
        ),
        encoding="utf-8",
    )


def _allow_test_policy(monkeypatch: pytest.MonkeyPatch, policy: Path) -> None:
    monkeypatch.setattr("zeroverse.windows_byo_corpus.DEFAULT_ALLOWED_SIGNERS", policy)
    monkeypatch.setattr(
        "zeroverse.windows_byo_corpus._require_production_policy_permissions",
        lambda _path: None,
    )


def test_verifies_signature_only_inventory_and_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path, policy, _ = _fixture(tmp_path)
    _allow_test_policy(monkeypatch, policy)
    verified = verify_windows_byo_corpus_manifest(path)
    output = verified.to_dict()
    assert len(verified.item_commitment_sha256s) == 2
    assert output["signature_verified"] is True
    assert output["blinding_verified"] is False
    assert output["private_evidence_verified"] is False
    assert output["runtime_consumable"] is False
    assert output["proof_limit"] == BYO_CORPUS_PROOF_LIMIT

    assert main(["windows-byo-corpus-verify", str(path)]) == 0
    cli_output = json.loads(capsys.readouterr().out)
    assert cli_output["schema_version"] == "0verse.windows-byo-corpus-inventory/v1"
    assert cli_output["proof_limit"] == BYO_CORPUS_PROOF_LIMIT


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("reverse-items", "canonically sorted"),
        ("reuse-commitment", "globally unique"),
        ("placeholder", "placeholder digest"),
        ("raw-artifact-field", "fields mismatch"),
        ("true-claim", "exhaustive safety gate set"),
        ("wrong-scheme", "commitment scheme mismatch"),
    ],
)
def test_rejects_unblinded_or_ambiguous_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    message: str,
) -> None:
    path, policy, raw = _fixture(tmp_path)
    key = tmp_path / "curator.key"
    items = cast(list[dict[str, Any]], raw["items"])
    if mutation == "reverse-items":
        items.reverse()
    elif mutation == "reuse-commitment":
        items[1]["private_evidence_bundle_commitment_sha256"] = items[0][
            "item_commitment_sha256"
        ]
    elif mutation == "placeholder":
        items[0]["item_commitment_sha256"] = "0" * 64
    elif mutation == "raw-artifact-field":
        items[0]["artifact_sha256"] = _digest("raw-public-artifact")
    elif mutation == "true-claim":
        raw["safety_flags"]["blinding_verified"] = True  # type: ignore[index]
    else:
        raw["commitment_scheme"] = "sha256-unsalted/v1"
    _write_signed(path, raw, key)
    _allow_test_policy(monkeypatch, policy)
    with pytest.raises(ValueError, match=message):
        verify_windows_byo_corpus_manifest(path)


def test_rejects_future_freeze_declaration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, policy, raw = _fixture(tmp_path)
    now = datetime(2026, 7, 15, 12, tzinfo=UTC)
    raw["declared_frozen_at"] = (now + timedelta(minutes=6)).isoformat()
    _write_signed(path, raw, tmp_path / "curator.key")
    _allow_test_policy(monkeypatch, policy)
    with pytest.raises(ValueError, match="too far in the future"):
        verify_windows_byo_corpus_manifest(path, now=now)


def test_rejects_signature_tampering_and_has_no_cli_policy_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, policy, _ = _fixture(tmp_path)
    _allow_test_policy(monkeypatch, policy)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="signature is invalid"):
        verify_windows_byo_corpus_manifest(path)
    with pytest.raises(SystemExit):
        main(["windows-byo-corpus-verify", str(path), str(policy)])


def test_rejects_wrong_signature_namespace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, policy, _ = _fixture(tmp_path)
    Path(f"{path}.sig").write_text(
        sign_ssh_material(
            path.read_bytes(),
            signing_key=tmp_path / "curator.key",
            namespace="wrong-byo-corpus-namespace",
            label="wrong namespace test",
        ),
        encoding="utf-8",
    )
    _allow_test_policy(monkeypatch, policy)
    with pytest.raises(ValueError, match="signature is invalid"):
        verify_windows_byo_corpus_manifest(path)


def test_uses_one_policy_snapshot_for_signature_and_key_commitment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, policy, _ = _fixture(tmp_path)
    _, replacement_policy = _authority(tmp_path, "replacement")
    replacement_bytes = replacement_policy.read_bytes()
    original_commitment = ssh_authority_key_commitment
    _allow_test_policy(monkeypatch, policy)

    def replace_live_policy(snapshot: str | Path) -> str:
        policy.write_bytes(replacement_bytes)
        assert Path(snapshot) != policy
        return original_commitment(snapshot)

    monkeypatch.setattr(byo_module, "ssh_authority_key_commitment", replace_live_policy)
    verified = verify_windows_byo_corpus_manifest(path)
    assert verified.allowed_signers_sha256 != hashlib.sha256(replacement_bytes).hexdigest()


def test_rejects_duplicate_json_keys_and_symlink_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, policy, _ = _fixture(tmp_path)
    _allow_test_policy(monkeypatch, policy)
    duplicate = path.read_text(encoding="utf-8").replace(
        '  "inventory_id":',
        f'  "inventory_id": "inventory-{_digest("duplicate")}",\n  "inventory_id":',
        1,
    )
    path.write_text(duplicate, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        verify_windows_byo_corpus_manifest(path)

    link = tmp_path / "inventory-link.json"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="regular non-symlink file"):
        verify_windows_byo_corpus_manifest(link)


def test_verifier_performs_no_network_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, policy, _ = _fixture(tmp_path)
    _allow_test_policy(monkeypatch, policy)

    def unexpected_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("BYO inventory verification attempted network access")

    monkeypatch.setattr("socket.create_connection", unexpected_network)
    monkeypatch.setattr("urllib.request.urlopen", unexpected_network)
    verify_windows_byo_corpus_manifest(path)


def test_requires_root_owned_nonwritable_production_policy(tmp_path: Path) -> None:
    _, policy = _authority(tmp_path)
    with pytest.raises(ValueError, match="root-owned"):
        _require_production_policy_permissions(policy)


@pytest.mark.parametrize(
    "line",
    [
        "*@example.test ssh-ed25519 AAAA\n",
        "one@example.test,two@example.test ssh-ed25519 AAAA\n",
        "one@example.test ssh-rsa AAAA\n",
        "one@example.test namespaces=bad ssh-ed25519 AAAA\n",
    ],
)
def test_requires_one_literal_ed25519_policy_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, line: str
) -> None:
    policy = tmp_path / "policy"
    policy.write_text(line, encoding="utf-8")
    monkeypatch.setattr(
        "zeroverse.windows_byo_corpus._require_production_policy_permissions",
        lambda _path: None,
    )
    with pytest.raises(ValueError, match=r"literal identity|ssh-ed25519"):
        _validate_production_policy(policy, policy.read_bytes())

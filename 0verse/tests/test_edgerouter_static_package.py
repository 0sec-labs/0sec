from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "benchmarks" / "firmware_candidates" / "ubiquiti_edgerouter_e50"
SCRIPT = PACKAGE / "verify-package.py"
SPEC = importlib.util.spec_from_file_location("edgerouter_static_package", SCRIPT)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def ownership_schema(package: Path = PACKAGE) -> dict[str, object]:
    return cast(
        dict[str, object],
        verifier.validate_published_schemas(package)[
            "ownership-authorization.schema.json"
        ],
    )


def authorized_attestation(now: datetime | None = None) -> dict[str, object]:
    issued = (now or datetime.now(UTC)).replace(microsecond=0)
    return {
        "schema_version": "0verse.firmware-ownership-authorization/v2",
        "attestation_id": "operator-review-1",
        "issued_at_utc": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at_utc": (issued + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "issuer": "0sec-firmware-authority",
        "principal": "0sec-firmware-authority",
        "nonce": "authorization-nonce-0123456789",
        "authorization_basis_reference": "internal/legal-review-reference",
        "product_evidence_reference": "internal/asset-register-reference",
        "product_model": "ER-X",
        "catalog_sha256": hashlib.sha256((PACKAGE / "images.json").read_bytes()).hexdigest(),
        "authorized_image_filenames": [
            "ER-e50.v3.0.0.5842787.tar",
            "ER-e50.v3.0.1.5862409.tar",
        ],
        "authorized_action": "local_image_hashing",
        "owns_or_controls_covered_product": True,
        "firmware_download_terms_accepted": True,
        "static_reverse_engineering_authorized": True,
    }


def signed_authorization(tmp_path: Path, value: dict[str, object]) -> tuple[Path, Path, Path]:
    key = tmp_path / "authority"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    attestation = tmp_path / "authorization.json"
    attestation.write_text(json.dumps(value, sort_keys=True) + "\n")
    subprocess.run(
        [
            "ssh-keygen", "-Y", "sign", "-q", "-f", str(key), "-n",
            verifier.AUTH_NAMESPACE, str(attestation),
        ],
        check=True,
    )
    signature = Path(f"{attestation}.sig")
    public = Path(f"{key}.pub").read_text().strip()
    allowed = tmp_path / "allowed_signers"
    allowed.write_text(
        f"0sec-firmware-authority namespaces=\"{verifier.AUTH_NAMESPACE}\" {public}\n"
    )
    allowed.chmod(0o644)
    return attestation, signature, allowed


def test_static_package_is_truthful_and_not_authorized() -> None:
    images = verifier.validate_package(PACKAGE)
    assert {image["version"] for image in images} == {"3.0.0", "3.0.1"}
    extraction = verifier.load_json(PACKAGE / "extraction-contract.json")
    assert extraction["carved_elf_inventory"] is None
    assert extraction["service_inventory"] is None
    assert extraction["status"] == "NOT_RUN_NOT_AUTHORIZED"


def test_cli_static_validation_does_not_need_firmware() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "STATIC_PACKAGE_OK status=NOT_AUTHORIZED inventory=UNAVAILABLE"
    )


def test_example_attestation_cannot_unlock_hashing() -> None:
    example = verifier.load_json(PACKAGE / "ownership-attestation.example.json")
    assert example["attestation_id"] == "EXAMPLE-NOT-VALID"
    assert example["owns_or_controls_covered_product"] is False


def test_attestation_requires_trusted_signature_freshness_and_exact_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = authorized_attestation()
    auth, signature, allowed = signed_authorization(tmp_path, value)
    monkeypatch.setattr(verifier, "TRUSTED_ALLOWED_SIGNERS", allowed)
    monkeypatch.setattr(
        verifier,
        "TRUSTED_ALLOWED_SIGNERS_SHA256",
        hashlib.sha256(allowed.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(verifier, "TRUSTED_ALLOWED_SIGNERS_UID", allowed.stat().st_uid)
    monkeypatch.setattr(verifier, "TRUSTED_ALLOWED_SIGNERS_GID", allowed.stat().st_gid)
    raw = auth.read_bytes()
    verifier.validate_attestation(
        json.loads(raw), ownership_schema=ownership_schema(), raw_bytes=raw,
        signature_path=signature,
        catalog_bytes=(PACKAGE / "images.json").read_bytes(),
        images=verifier.validate_images(verifier.load_json(PACKAGE / "images.json")),
        required_action="local_image_hashing",
    )
    tampered = json.loads(raw)
    tampered["product_model"] = "ER-10X"
    with pytest.raises(verifier.ContractError, match="hash-pinned schema"):
        verifier.validate_attestation(
            tampered, ownership_schema=ownership_schema(), raw_bytes=raw,
            signature_path=signature,
            catalog_bytes=(PACKAGE / "images.json").read_bytes(),
            images=verifier.validate_images(verifier.load_json(PACKAGE / "images.json")),
            required_action="local_image_hashing",
        )


def test_expired_authorization_is_rejected_before_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = datetime.now(UTC) - timedelta(hours=2)
    value = authorized_attestation(old)
    auth, signature, allowed = signed_authorization(tmp_path, value)
    monkeypatch.setattr(verifier, "TRUSTED_ALLOWED_SIGNERS", allowed)
    monkeypatch.setattr(
        verifier,
        "TRUSTED_ALLOWED_SIGNERS_SHA256",
        hashlib.sha256(allowed.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(verifier, "TRUSTED_ALLOWED_SIGNERS_UID", allowed.stat().st_uid)
    monkeypatch.setattr(verifier, "TRUSTED_ALLOWED_SIGNERS_GID", allowed.stat().st_gid)
    with pytest.raises(verifier.ContractError, match=r"not fresh|expired"):
        verifier.validate_attestation(
            value, ownership_schema=ownership_schema(), raw_bytes=auth.read_bytes(),
            signature_path=signature,
            catalog_bytes=(PACKAGE / "images.json").read_bytes(),
            images=verifier.validate_images(verifier.load_json(PACKAGE / "images.json")),
            required_action="local_image_hashing",
        )


def test_short_nonce_is_rejected_by_hash_pinned_ownership_schema(tmp_path: Path) -> None:
    value = authorized_attestation()
    value["nonce"] = "short"
    raw = (json.dumps(value, sort_keys=True) + "\n").encode()
    with pytest.raises(verifier.ContractError, match="hash-pinned schema"):
        verifier.validate_attestation(
            value,
            ownership_schema=ownership_schema(),
            raw_bytes=raw,
            signature_path=tmp_path / "signature-not-reached",
            catalog_bytes=(PACKAGE / "images.json").read_bytes(),
            images=verifier.validate_images(verifier.load_json(PACKAGE / "images.json")),
            required_action="local_image_hashing",
        )


def test_cached_hash_pinned_schema_survives_on_disk_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    ownership_path = package / "schemas" / "ownership-authorization.schema.json"
    original_stable_bytes = verifier._stable_bytes
    ownership_reads = 0

    def counted_stable_bytes(path: Path, *, limit: int | None = None) -> bytes:
        nonlocal ownership_reads
        if path == ownership_path:
            ownership_reads += 1
        return cast(bytes, original_stable_bytes(path, limit=limit))

    monkeypatch.setattr(verifier, "_stable_bytes", counted_stable_bytes)
    _images, schemas = verifier._validated_package(package)
    assert ownership_reads == 1

    swapped = json.loads(ownership_path.read_text())
    swapped["properties"]["nonce"]["minLength"] = 1
    ownership_path.write_text(json.dumps(swapped, sort_keys=True) + "\n")
    value = authorized_attestation()
    value["nonce"] = "short"
    with pytest.raises(verifier.ContractError, match="hash-pinned schema"):
        verifier.validate_attestation(
            value,
            ownership_schema=schemas["ownership-authorization.schema.json"],
            raw_bytes=(json.dumps(value, sort_keys=True) + "\n").encode(),
            signature_path=tmp_path / "signature-not-reached",
            catalog_bytes=(package / "images.json").read_bytes(),
            images=verifier.validate_images(verifier.load_json(package / "images.json")),
            required_action="local_image_hashing",
        )
    assert ownership_reads == 1


def test_local_hashing_is_stable_and_detects_mismatch(tmp_path: Path) -> None:
    image = tmp_path / "fixture.tar"
    image.write_bytes(b"static-test-fixture")
    md5, sha256, size = verifier.hash_file(image)
    expected_vendor_md5 = hashlib.md5(  # foxguard: ignore[py/no-weak-crypto]
        b"static-test-fixture"
    ).hexdigest()
    assert md5 == expected_vendor_md5
    assert sha256 == hashlib.sha256(b"static-test-fixture").hexdigest()
    assert size == len(b"static-test-fixture")


def test_image_mode_fails_closed_without_attestation(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--image-dir", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "must be supplied together" in result.stderr


def test_catalog_rejects_nonofficial_image_host(tmp_path: Path) -> None:
    catalog = json.loads((PACKAGE / "images.json").read_text())
    catalog["images"][0]["official_image_url"] = "https://mirror.invalid/image.tar"
    with pytest.raises(verifier.ContractError, match="not an official"):
        verifier.validate_images(catalog)


def test_gate_order_is_handler_then_whole_daemon() -> None:
    contract = verifier.load_json(PACKAGE / "execution-gates.json")
    ids = [gate["id"] for gate in contract["gates"]]
    assert ids.index("handler_qiling") < ids.index("whole_daemon_qemu")
    assert all(not gate["allowed_now"] for gate in contract["gates"][1:])


def test_security_bearing_control_and_gate_text_is_exact() -> None:
    model = verifier.load_json(PACKAGE / "target-control-model.json")
    model["controls_required_per_future_target"][0]["requirement"] = "No control required"
    with pytest.raises(verifier.ContractError, match="exact differential controls"):
        verifier.validate_target_controls(model)
    gates = verifier.load_json(PACKAGE / "execution-gates.json")
    gates["gates"][-1]["result"] = "QEMU is authorized now"
    with pytest.raises(verifier.ContractError, match="prerequisites changed"):
        verifier.validate_gates(gates)


def test_exact_official_checksum_response_bytes_are_closed_over() -> None:
    catalog = verifier.validate_images(verifier.load_json(PACKAGE / "images.json"))
    verifier.validate_official_responses(
        verifier.load_json(PACKAGE / "official-response-receipts.json"), catalog, PACKAGE
    )
    receipts = verifier.load_json(PACKAGE / "official-response-receipts.json")
    for receipt in receipts["responses"]:
        body = (PACKAGE / receipt["body_path"]).read_bytes()
        assert hashlib.sha256(body).hexdigest() == receipt["body_sha256"]
        assert len(body) == receipt["body_size"]


def test_all_official_source_bytes_and_strict_schemas_are_closed_over() -> None:
    scope = verifier.load_json(PACKAGE / "scope-snapshot.json")
    images = verifier.validate_images(verifier.load_json(PACKAGE / "images.json"))
    verifier.validate_official_source_responses(
        verifier.load_json(PACKAGE / "official-source-response-receipts.json"),
        scope,
        images,
        PACKAGE,
    )
    verifier.validate_published_schemas(PACKAGE)
    assert len(verifier.SCHEMA_SHA256) == 8


@pytest.mark.parametrize(
    ("document", "field", "value"),
    [
        (
            "official-source-response-receipts.json",
            "command_policy",
            "Firmware fetched and arbitrary writes permitted",
        ),
        (
            "official-response-receipts.json",
            "tool",
            (
                "curl 8.7.1 (x86_64-apple-darwin25.0) libcurl/8.7.1 "
                "(SecureTransport) LibreSSL/3.3.6 attacker-suffix"
            ),
        ),
    ],
)
def test_package_schema_rejects_retrieval_policy_and_tool_mutations(
    tmp_path: Path, document: str, field: str, value: str
) -> None:
    package = tmp_path / "package"
    shutil.copytree(PACKAGE, package)
    path = package / document
    instance = json.loads(path.read_text())
    instance["retrieval"][field] = value
    path.write_text(json.dumps(instance, sort_keys=True) + "\n")
    with pytest.raises(verifier.ContractError, match="strict schema validation failed"):
        verifier.validate_package(package)


def test_cli_cannot_nominate_a_trust_anchor() -> None:
    option_strings = {
        option
        for action in verifier.parser()._actions
        for option in action.option_strings
    }
    assert "--trusted-allowed-signers" not in option_strings
    assert Path("/etc/0verse/firmware-authorization.allowed_signers") == (
        verifier.TRUSTED_ALLOWED_SIGNERS
    )
    assert verifier.TRUSTED_KEY_FINGERPRINT.startswith("SHA256:")

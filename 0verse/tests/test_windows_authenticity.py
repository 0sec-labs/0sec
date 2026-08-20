from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from zeroverse.cli import main
from zeroverse.windows_authenticity import (
    AUTHENTICITY_PROOF_LIMIT,
    verify_windows_authenticity_receipt,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _certificate(subject: str = "CN=Microsoft Windows") -> dict[str, object]:
    return {
        "subject": subject,
        "issuer": "CN=Microsoft Windows Production PCA 2011",
        "serial_number": "1234ABCD",
        "thumbprint_sha1": "A" * 40,
        "cert_sha256": "b" * 64,
        "not_before_utc": "2025-01-01T00:00:00Z",
        "not_after_utc": "2027-01-01T00:00:00Z",
    }


def _receipt(root: Path, **verification_updates: object) -> tuple[Path, Path]:
    artifact = root / "vmswitch.sys"
    artifact.write_bytes(b"MZ-retained-fixture")
    verification: dict[str, object] = {
        "status": "Valid",
        "status_message": "Signature verified.",
        "signature_type": "Catalog",
        "is_os_binary": True,
        "verified_at_utc": "2026-07-13T21:00:00Z",
        "trust_mode": "windows-local-machine",
        "revocation_mode": "get-authenticode-signature-default",
        "network_mode": "network-isolated",
        "signer_certificate": _certificate(),
        "timestamper_certificate": None,
        "verifier": {
            "powershell_version": "5.1.26100.7705",
            "os_build_lab_ex": "26100.1.amd64fre.ge_release.240331-1435",
        },
    }
    verification.update(verification_updates)
    receipt = root / "vmswitch.authenticity.json"
    receipt.write_text(
        json.dumps(
            {
                "schema_version": "0verse.windows-authenticity-observation/v1",
                "producer": "zeroverse.windows-authenticity/powershell-v1",
                "artifact": {
                    "path": artifact.name,
                    "sha256": _sha(artifact),
                    "size_bytes": artifact.stat().st_size,
                },
                "verification": verification,
                "verified_claims": [
                    "producer-observed-windows-valid-signature",
                    "retained-content-sha256",
                ],
                "proof_limit": AUTHENTICITY_PROOF_LIMIT,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return artifact, receipt


def test_verifies_microsoft_signature_observation_and_retained_bytes(tmp_path: Path) -> None:
    artifact, receipt = _receipt(tmp_path)
    result = verify_windows_authenticity_receipt(artifact, receipt)
    assert result.artifact_sha256 == _sha(artifact)
    assert result.artifact_size_bytes == artifact.stat().st_size
    assert result.signature_type == "Catalog"
    assert result.signer_subject == "CN=Microsoft Windows"
    assert result.signer_certificate_sha256 == "b" * 64
    assert result.network_mode == "network-isolated"
    assert result.receipt_sha256 == _sha(receipt)


def test_rejects_artifact_tampering(tmp_path: Path) -> None:
    artifact, receipt = _receipt(tmp_path)
    artifact.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="artifact SHA-256 mismatch"):
        verify_windows_authenticity_receipt(artifact, receipt)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"status": "NotTrusted"}, "status must be Valid"),
        ({"signature_type": "None"}, "signature_type"),
        ({"network_mode": "unknown"}, "network_mode"),
        ({"trust_mode": "current-user"}, "trust_mode"),
        ({"is_os_binary": "true"}, "is_os_binary"),
        ({"signer_certificate": _certificate("CN=Fixture Labs")}, "not Microsoft"),
    ],
)
def test_rejects_unaccepted_signature_observations(
    tmp_path: Path, updates: dict[str, object], message: str
) -> None:
    artifact, receipt = _receipt(tmp_path, **updates)
    with pytest.raises(ValueError, match=message):
        verify_windows_authenticity_receipt(artifact, receipt)


def test_rejects_duplicate_or_unknown_receipt_fields(tmp_path: Path) -> None:
    artifact, receipt = _receipt(tmp_path)
    text = receipt.read_text(encoding="utf-8")
    receipt.write_text(
        text.replace('"producer":', '"producer": "duplicate", "producer":', 1),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate JSON key: producer"):
        verify_windows_authenticity_receipt(artifact, receipt)

    artifact, receipt = _receipt(tmp_path)
    raw = json.loads(receipt.read_text(encoding="utf-8"))
    raw["verification"]["accepted"] = True
    receipt.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown accepted"):
        verify_windows_authenticity_receipt(artifact, receipt)


def test_cli_verifies_authenticity_observation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    artifact, receipt = _receipt(tmp_path)
    assert main(["windows-authenticity-verify", str(artifact), str(receipt)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["artifact_sha256"] == _sha(artifact)
    assert output["signature_type"] == "Catalog"


def test_windows_producer_hashes_retained_artifact_and_records_claim_limit() -> None:
    script = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "windows"
        / "write-artifact-authenticity.ps1"
    ).read_text(encoding="utf-8")
    assert "Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security" in script
    assert "function Get-Sha256" in script
    assert script.count("Get-Sha256 $artifact.FullName") == 3
    assert "Get-AuthenticodeSignature -LiteralPath $artifact.FullName" in script
    status_gate = script.index("if ([string]$signature.Status -ne 'Valid')")
    claim = script.index("producer-observed-windows-valid-signature")
    publication = script.index("Move-Item -LiteralPath $temporary -Destination $OutputPath")
    assert status_gate < claim < publication
    assert AUTHENTICITY_PROOF_LIMIT in script


@pytest.mark.parametrize(
    "relative_script",
    [
        "export-serviced-root-binaries.ps1",
        "export-serviced-driver-set.ps1",
        "export-driverstore-driver-set.ps1",
    ],
)
def test_exporters_hash_retained_destination(relative_script: str) -> None:
    script = (
        Path(__file__).resolve().parents[1] / "scripts" / "windows" / relative_script
    ).read_text(encoding="utf-8")
    assert "Get-FileHash $destination -Algorithm SHA256" in script
    assert "Get-FileHash $file.Source" not in script
    assert "Get-FileHash $driver.FullName" not in script

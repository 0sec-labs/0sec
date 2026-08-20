from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from authorization_helpers import authorization_key, authorization_policy

from zeroverse.cli import main
from zeroverse.windows_trust import (
    TRUST_POLICY_PROOF_LIMIT,
    TRUST_RECEIPT_PROOF_LIMIT,
    WindowsTrustReceipt,
    verify_windows_trust_receipt,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _cert(subject: str, issuer: str, digest: str) -> dict[str, object]:
    return {
        "subject": subject,
        "issuer": issuer,
        "serial_number": "1234ABCD",
        "thumbprint_sha1": "A" * 40,
        "cert_sha256": digest,
        "not_before_utc": "2025-01-01T00:00:00Z",
        "not_after_utc": "2028-01-01T00:00:00Z",
    }


def _ref(path: Path) -> dict[str, object]:
    return {"path": path.name, "sha256": _sha(path), "size_bytes": path.stat().st_size}


def _fixture(
    root: Path, *, mode: str = "embedded"
) -> tuple[Path, Path, Path, Path, Path, Path | None]:
    artifact = root / "vmswitch.sys"
    artifact.write_bytes(b"MZ-retained-system-binary")
    signtool = root / "signtool.exe"
    signtool.write_bytes(b"MZ-pinned-sdk-signtool")
    policy = root / "microsoft-roots.json"
    policy.write_text(
        json.dumps(
            {
                "schema_version": "0verse.windows-trust-root-policy/v1",
                "policy_id": "0sec-windows-roots-2026-07",
                "allowed_root_cert_sha256": ["c" * 64],
                "allowed_signtool_sha256": [_sha(signtool)],
                "proof_limit": TRUST_POLICY_PROOF_LIMIT,
            }
        ),
        encoding="utf-8",
    )
    receipt = root / "vmswitch.trust.json"
    stdout = root / f"{receipt.name}.stdout.bin"
    stderr = root / f"{receipt.name}.stderr.bin"
    stdout.write_bytes(b"SignTool verification output\r\n")
    stderr.write_bytes(b"")
    catalog = None
    catalog_ref = None
    if mode == "catalog":
        catalog = root / "microsoft.cat"
        catalog.write_bytes(b"signed-catalog-fixture")
        catalog_ref = _ref(catalog)
        argv = [
            "verify",
            "/v",
            "/pa",
            "/c",
            rf"C:\retained\{catalog.name}",
            rf"C:\retained\{artifact.name}",
        ]
        signature_type = "Catalog"
    else:
        argv = ["verify", "/v", "/pa", rf"C:\retained\{artifact.name}"]
        signature_type = "Authenticode"
    leaf = _cert("CN=Microsoft Windows", "CN=Microsoft Root", "b" * 64)
    root_cert = _cert("CN=Microsoft Root", "CN=Microsoft Root", "c" * 64)
    claims = [
        "signtool-authenticode-policy-valid",
        "pinned-terminal-root",
        "retained-content-sha256",
    ]
    if mode == "catalog":
        claims.append("explicit-catalog-membership")
    receipt.write_text(
        json.dumps(
            {
                "schema_version": "0verse.windows-signtool-policy-receipt/v1",
                "producer": "zeroverse.windows-signtool-policy/powershell-v1",
                "receipt_signer_identity": _signer_identity(),
                "artifact": _ref(artifact),
                "catalog": catalog_ref,
                "root_policy": {**_ref(policy), "policy_id": "0sec-windows-roots-2026-07"},
                "signtool": {**_ref(signtool), "file_version": "10.0.26100.0"},
                "verification": {
                    "mode": mode,
                    "argv": argv,
                    "exit_code": 0,
                    "stdout": _ref(stdout),
                    "stderr": _ref(stderr),
                    "signature_status": "Valid",
                    "signature_type": signature_type,
                    "signer_certificate": leaf,
                    "certificate_chain": [leaf, root_cert],
                    "terminal_root_cert_sha256": "c" * 64,
                    "chain_build_succeeded": True,
                    "verified_at_utc": "2026-07-14T09:00:00Z",
                    "declared_network_mode": "network-isolated",
                    "os_build_lab_ex": "26100.1.amd64fre.ge_release.240331-1435",
                },
                "verified_claims": claims,
                "proof_limit": TRUST_RECEIPT_PROOF_LIMIT,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    _sign_receipt(receipt)
    return artifact, receipt, policy, signtool, authorization_policy(), catalog


def _verify(
    paths: tuple[Path, Path, Path, Path, Path, Path | None],
) -> WindowsTrustReceipt:
    artifact, receipt, policy, signtool, allowed_signers, catalog = paths
    return verify_windows_trust_receipt(
        artifact,
        receipt,
        policy,
        signtool,
        allowed_signers,
        catalog_path=catalog,
    )


def _signer_identity() -> str:
    return authorization_policy().read_text(encoding="utf-8").split(maxsplit=1)[0]


def _sign_receipt(receipt: Path) -> None:
    Path(f"{receipt}.sig").unlink(missing_ok=True)
    subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-Y",
            "sign",
            "-f",
            str(authorization_key()),
            "-n",
            "0verse-windows-trust-receipt-v1",
            str(receipt),
        ],
        check=True,
        capture_output=True,
    )


def _rewrite_signed(receipt: Path, raw: dict[str, object]) -> None:
    receipt.write_text(json.dumps(raw), encoding="utf-8")
    _sign_receipt(receipt)


@pytest.mark.parametrize("mode", ["embedded", "catalog"])
def test_verifies_pinned_root_and_retained_inputs(tmp_path: Path, mode: str) -> None:
    paths = _fixture(tmp_path, mode=mode)
    result = _verify(paths)
    assert result.mode == mode
    assert result.artifact_sha256 == _sha(paths[0])
    assert result.root_policy_sha256 == _sha(paths[2])
    assert result.signtool_sha256 == _sha(paths[3])
    assert result.receipt_signer_identity == _signer_identity()
    assert result.terminal_root_cert_sha256 == "c" * 64
    assert (result.catalog_path is not None) is (mode == "catalog")


@pytest.mark.parametrize("target_index", [0, 2, 3])
def test_rejects_tampered_retained_inputs(tmp_path: Path, target_index: int) -> None:
    paths = _fixture(tmp_path)
    target = paths[target_index]
    assert target is not None
    target.write_bytes(b"tampered")
    with pytest.raises(ValueError, match=r"SHA-256|Expecting value"):
        _verify(paths)


def test_rejects_tampered_transcript(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    transcript = tmp_path / f"{paths[1].name}.stdout.bin"
    transcript.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="stdout SHA-256 mismatch"):
        _verify(paths)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("exit_code", 2, "exit_code"),
        ("exit_code", False, "exit_code"),
        ("chain_build_succeeded", False, "chain"),
        ("terminal_root_cert_sha256", "d" * 64, "terminal root"),
        ("signature_status", "NotTrusted", "signature_status"),
        ("signature_type", "Catalog", "signature_type"),
    ],
)
def test_rejects_unaccepted_verification(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    paths = _fixture(tmp_path)
    raw = json.loads(paths[1].read_text(encoding="utf-8"))
    raw["verification"][field] = value
    _rewrite_signed(paths[1], raw)
    with pytest.raises(ValueError, match=message):
        _verify(paths)


def test_catalog_requires_explicit_retained_catalog_and_membership_claim(
    tmp_path: Path,
) -> None:
    paths = _fixture(tmp_path, mode="catalog")
    with pytest.raises(ValueError, match="requires the explicit catalog"):
        verify_windows_trust_receipt(
            paths[0], paths[1], paths[2], paths[3], paths[4]
        )
    assert paths[5] is not None
    paths[5].write_bytes(b"tampered")
    with pytest.raises(ValueError, match="catalog SHA-256 mismatch"):
        _verify(paths)


def test_rejects_policy_not_authorizing_terminal_root(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    raw = json.loads(paths[2].read_text(encoding="utf-8"))
    raw["allowed_root_cert_sha256"] = ["d" * 64]
    paths[2].write_text(json.dumps(raw), encoding="utf-8")
    receipt = json.loads(paths[1].read_text(encoding="utf-8"))
    receipt["root_policy"].update(_ref(paths[2]))
    _rewrite_signed(paths[1], receipt)
    with pytest.raises(ValueError, match="not allowed"):
        _verify(paths)


def test_rejects_duplicate_fields_and_unsafe_sidecar_path(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    text = paths[1].read_text(encoding="utf-8")
    paths[1].write_text(
        text.replace('"producer":', '"producer": "duplicate", "producer":', 1),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate JSON key: producer"):
        _verify(paths)

    paths = _fixture(tmp_path)
    raw = json.loads(paths[1].read_text(encoding="utf-8"))
    raw["verification"]["stdout"]["path"] = "../stdout.bin"
    _rewrite_signed(paths[1], raw)
    with pytest.raises(ValueError, match="safe basename"):
        _verify(paths)


def test_rejects_symlinked_retained_input(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    original = paths[0]
    moved = tmp_path / "actual.sys"
    original.rename(moved)
    original.symlink_to(moved)
    with pytest.raises(ValueError, match="non-symlink"):
        _verify(paths)


def test_cli_verifies_catalog_receipt(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    artifact, receipt, policy, signtool, allowed, catalog = _fixture(
        tmp_path, mode="catalog"
    )
    assert catalog is not None
    assert (
        main(
            [
                "windows-trust-verify",
                str(artifact),
                str(receipt),
                str(policy),
                str(signtool),
                str(allowed),
                "--catalog",
                str(catalog),
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["mode"] == "catalog"
    assert output["catalog_sha256"] == _sha(catalog)


def test_rejects_unsigned_or_tampered_receipt(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    Path(f"{paths[1]}.sig").unlink()
    with pytest.raises(ValueError, match="receipt signature"):
        _verify(paths)

    paths = _fixture(tmp_path)
    raw = json.loads(paths[1].read_text(encoding="utf-8"))
    raw["verification"]["exit_code"] = 2
    paths[1].write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="SSH signature is invalid"):
        _verify(paths)


def test_rejects_signtool_not_pinned_by_policy(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    policy = json.loads(paths[2].read_text(encoding="utf-8"))
    policy["allowed_signtool_sha256"] = ["d" * 64]
    paths[2].write_text(json.dumps(policy), encoding="utf-8")
    receipt = json.loads(paths[1].read_text(encoding="utf-8"))
    receipt["root_policy"].update(_ref(paths[2]))
    _rewrite_signed(paths[1], receipt)
    with pytest.raises(ValueError, match="SignTool is not allowed"):
        _verify(paths)

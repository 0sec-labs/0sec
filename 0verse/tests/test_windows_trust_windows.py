from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from zeroverse.windows_trust import verify_windows_trust_receipt

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="requires Windows trust APIs")

POLICY_PROOF_LIMIT = (
    "Out-of-band terminal-root and SignTool allowlists only; policy authenticity and "
    "authorization depend on the operator-supplied retained policy bytes."
)
RECEIPT_PROOF_LIMIT = (
    "Worker-signed producer observation of SignTool policy result, explicit catalog "
    "membership when declared, pinned terminal root, and retained-byte integrity only; "
    "servicing provenance, package or build identity, vulnerability status, bounty "
    "eligibility, and redistribution rights are unproven."
)
SIGNER_IDENTITY = "windows-trust-native-test"


@dataclass(frozen=True)
class SignedFixture:
    artifact: Path
    signtool: Path
    root_sha256: str
    signing_key: Path
    allowed_signers: Path
    ssh_keygen: Path


def _producer() -> Path:
    return (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "windows"
        / "write-signtool-policy-receipt.ps1"
    )


def _find_windows_sdk_tool(name: str) -> Path:
    roots = [
        Path(value)
        for value in (
            os.environ.get("PROGRAMFILES(X86)"),
            os.environ.get("PROGRAMFILES"),
        )
        if value
    ]
    matches: list[tuple[Path, Path]] = []
    for root in roots:
        if not root.is_dir():
            continue
        certification_tool = (
            root / "Windows Kits" / "10" / "App Certification Kit" / name
        )
        if certification_tool.is_file():
            matches.append((certification_tool, root))
        matches.extend(
            (path, root)
            for path in (root / "Windows Kits" / "10" / "bin").glob(
                f"*/x64/{name}"
            )
            if path.is_file()
        )
    if not matches:
        pytest.skip(f"Windows SDK {name} is unavailable")

    def reparse_tag(path: Path) -> int:
        tag = getattr(os.lstat(path), "st_reparse_tag", None)
        if not isinstance(tag, int):
            pytest.fail(f"Windows did not report a reparse tag for {path}")
        return tag

    def unsafe_reparse_ancestor(path: Path, root: Path) -> tuple[Path, int] | None:
        current = path
        while True:
            tag = reparse_tag(current)
            if (current == path and tag != 0) or tag & 0x20000000:
                return current, tag
            if current == root:
                return None
            parent = current.parent
            if parent == current:
                pytest.fail(f"Windows SDK tool escaped Program Files: {path}")
            current = parent

    classified_matches = [
        (path, unsafe_reparse_ancestor(path, root)) for path, root in matches
    ]
    safe_matches = [
        path for path, redirecting_ancestor in classified_matches if redirecting_ancestor is None
    ]
    if not safe_matches:
        tags = [
            f"{path} via {redirecting_ancestor[0]}="
            f"0x{redirecting_ancestor[1]:08x}"
            for path, redirecting_ancestor in classified_matches
            if redirecting_ancestor is not None
        ]
        pytest.fail(
            "Windows SDK has no SignTool with a producer-compatible reparse chain: "
            + ", ".join(tags)
        )
    certification_matches = [
        path for path in safe_matches if "App Certification Kit" in path.parts
    ]
    if certification_matches:
        logical_path = certification_matches[0]
    else:
        logical_path = sorted(
            safe_matches,
            key=lambda path: path.parts[-3],
        )[-1]
    resolved_path = logical_path.resolve(strict=True)
    if not resolved_path.is_file() or resolved_path.name.casefold() != name.casefold():
        pytest.fail(
            "Windows SDK tool junction resolved to an invalid target: "
            f"{logical_path} -> {resolved_path}"
        )
    return resolved_path


def _powershell(script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # foxguard: ignore[py/no-command-injection]
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
            *arguments,
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


@pytest.fixture(scope="module")
def signed_fixture(tmp_path_factory: pytest.TempPathFactory) -> Iterator[SignedFixture]:
    fixture_root = tmp_path_factory.mktemp("windows-trust-signed-fixture")
    signtool = _find_windows_sdk_tool("signtool.exe")
    windows_directory = Path(os.environ["WINDIR"])
    ssh_keygen = windows_directory / "System32" / "OpenSSH" / "ssh-keygen.exe"
    if not ssh_keygen.is_file():
        pytest.skip("protected Windows System32 OpenSSH ssh-keygen.exe is unavailable")
    ssh_keygen = ssh_keygen.resolve()
    signing_key = fixture_root / "receipt-ed25519"
    key_process = subprocess.run(
        [str(ssh_keygen), "-q", "-t", "ed25519", "-N", "", "-f", str(signing_key)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert key_process.returncode == 0, key_process.stdout + key_process.stderr
    public_key = Path(f"{signing_key}.pub").read_text(encoding="utf-8").strip()
    allowed_signers = fixture_root / "allowed_signers"
    allowed_signers.write_text(
        f"{SIGNER_IDENTITY} {public_key}\n",
        encoding="utf-8",
    )
    artifact = fixture_root / "signed-microsoft.exe"
    setup = r"""
$ErrorActionPreference = 'Stop'
$securityModule = Join-Path $PSHOME `
    'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1'
Import-Module $securityModule -ErrorAction Stop
$signTool = $args[0]
$python = $args[1]
$candidates = @(
    $python,
    $signTool,
    (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source,
    (Get-Command git.exe -ErrorAction SilentlyContinue).Source,
    (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'),
    (Join-Path $env:SystemRoot 'System32\notepad.exe'),
    (Join-Path $env:SystemRoot 'System32\cmd.exe')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) }
foreach ($candidate in $candidates) {
    $signature = Get-AuthenticodeSignature -LiteralPath $candidate
    if ([string]$signature.Status -ne 'Valid' -or
        [string]$signature.SignatureType -ne 'Authenticode' -or
        $null -eq $signature.SignerCertificate) {
        continue
    }
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    try {
        $chain.ChainPolicy.RevocationMode = `
            [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        if ($null -ne $chain.ChainPolicy.PSObject.Properties['DisableCertificateDownloads']) {
            $chain.ChainPolicy.DisableCertificateDownloads = $true
        }
        if (-not $chain.Build($signature.SignerCertificate) -or
            $chain.ChainElements.Count -eq 0) {
            continue
        }
        $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $rootSha = ($sha.ComputeHash($root.RawData) |
                ForEach-Object { $_.ToString('x2') }) -join ''
        } finally {
            $sha.Dispose()
        }
    } finally {
        $chain.Dispose()
    }
    [ordered]@{ source_path = $candidate; root_sha256 = $rootSha } |
        ConvertTo-Json -Compress
    exit 0
}
throw 'no embedded-signed Microsoft system binary with a valid chain was found'
"""
    process = _powershell(setup, str(signtool), sys.executable)
    assert process.returncode == 0, process.stdout + process.stderr
    identity = json.loads(process.stdout.strip().splitlines()[-1])
    shutil.copyfile(identity["source_path"], artifact)
    yield SignedFixture(
        artifact,
        signtool,
        identity["root_sha256"],
        signing_key,
        allowed_signers,
        ssh_keygen,
    )


def _write_policy(path: Path, roots: list[str], signtools: list[str]) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "0verse.windows-trust-root-policy/v1",
                "policy_id": "windows-native-producer-test",
                "allowed_root_cert_sha256": roots,
                "allowed_signtool_sha256": signtools,
                "proof_limit": POLICY_PROOF_LIMIT,
            }
        ),
        encoding="utf-8",
    )


def _run_producer(
    artifact: Path,
    receipt: Path,
    policy: Path,
    signtool: Path,
    signing_key: Path,
    ssh_keygen: Path,
    *,
    mode: str = "embedded",
    catalog: Path | None = None,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    powershell = (
        Path(os.environ["WINDIR"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    command = [
        str(powershell),
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(_producer()),
        "-ArtifactPath",
        str(artifact),
        "-OutputPath",
        str(receipt),
        "-RootPolicyPath",
        str(policy),
        "-SignToolPath",
        str(signtool),
        "-ReceiptSigningKeyPath",
        str(signing_key),
        "-ReceiptSignerIdentity",
        SIGNER_IDENTITY,
        "-SshKeygenPath",
        str(ssh_keygen),
        "-Mode",
        mode,
        "-NetworkMode",
        "network-isolated",
    ]
    if catalog is not None:
        command.extend(["-CatalogPath", str(catalog)])
    return subprocess.run(  # foxguard: ignore[py/no-command-injection]
        command,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        cwd=cwd,
        env=env,
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_signtool_producer_accepts_embedded_signature_with_pinned_root(
    tmp_path: Path, signed_fixture: SignedFixture
) -> None:
    artifact = signed_fixture.artifact
    signtool = signed_fixture.signtool
    root_sha256 = signed_fixture.root_sha256
    policy = tmp_path / "root-policy.json"
    receipt = tmp_path / "trust-receipt.json"
    _write_policy(policy, [root_sha256], [_sha256(signtool)])

    process = _run_producer(
        artifact,
        receipt,
        policy,
        signtool,
        signed_fixture.signing_key,
        signed_fixture.ssh_keygen,
    )

    assert process.returncode == 0, process.stdout + process.stderr
    verified = verify_windows_trust_receipt(
        artifact,
        receipt,
        policy,
        signtool,
        signed_fixture.allowed_signers,
    )
    assert verified.artifact_sha256 == _sha256(artifact)
    assert verified.terminal_root_cert_sha256 == root_sha256
    assert verified.mode == "embedded"
    raw = json.loads(receipt.read_bytes())
    assert raw["schema_version"] == "0verse.windows-signtool-policy-receipt/v1"
    assert raw["producer"] == "zeroverse.windows-signtool-policy/powershell-v1"
    assert raw["receipt_signer_identity"] == SIGNER_IDENTITY
    assert Path(f"{receipt}.sig").is_file()
    assert raw["artifact"] == {
        "path": artifact.name,
        "sha256": _sha256(artifact),
        "size_bytes": artifact.stat().st_size,
    }
    assert raw["catalog"] is None
    assert raw["root_policy"]["path"] == policy.name
    assert raw["root_policy"]["sha256"] == _sha256(policy)
    assert raw["root_policy"]["policy_id"] == "windows-native-producer-test"
    assert raw["signtool"]["path"] == signtool.name
    assert raw["signtool"]["sha256"] == _sha256(signtool)
    verification = raw["verification"]
    assert verification["mode"] == "embedded"
    assert verification["argv"][:3] == ["verify", "/v", "/pa"]
    assert Path(verification["argv"][-1]).name == artifact.name
    assert verification["argv"][-1] != str(artifact.resolve())
    assert verification["exit_code"] == 0
    assert verification["signature_status"] == "Valid"
    assert verification["signature_type"] == "Authenticode"
    assert verification["chain_build_succeeded"] is True
    assert verification["declared_network_mode"] == "network-isolated"
    assert verification["terminal_root_cert_sha256"] == root_sha256
    assert verification["certificate_chain"][-1]["cert_sha256"] == root_sha256
    assert verification["signer_certificate"] == verification["certificate_chain"][0]
    assert raw["verified_claims"] == [
        "signtool-authenticode-policy-valid",
        "pinned-terminal-root",
        "retained-content-sha256",
    ]
    assert raw["proof_limit"] == RECEIPT_PROOF_LIMIT
    for stream in ("stdout", "stderr"):
        binding = verification[stream]
        transcript = receipt.parent / binding["path"]
        assert transcript.name == f"{receipt.name}.{stream}.bin"
        assert binding["sha256"] == _sha256(transcript)
        assert binding["size_bytes"] == transcript.stat().st_size
    assert not list(tmp_path.glob(".windows-trust-*"))


def test_signtool_producer_ignores_hostile_cwd_and_path(
    tmp_path: Path, signed_fixture: SignedFixture
) -> None:
    hostile = tmp_path / "hostile"
    hostile.mkdir()
    canary = tmp_path / "hostile-executed"
    (hostile / "ssh-keygen.cmd").write_text(
        f'@echo hostile>"{canary}"\n',
        encoding="utf-8",
    )
    (hostile / "version.dll").write_bytes(b"attacker-controlled DLL canary")
    fake_windows = hostile / "fake-windows"
    fake_open_ssh = fake_windows / "System32" / "OpenSSH"
    fake_open_ssh.mkdir(parents=True)
    (fake_open_ssh / "ssh-keygen.exe").write_bytes(b"attacker-controlled executable")
    policy = tmp_path / "hostile-policy.json"
    receipt = tmp_path / "hostile-receipt.json"
    _write_policy(
        policy,
        [signed_fixture.root_sha256],
        [_sha256(signed_fixture.signtool)],
    )
    environment = os.environ.copy()
    environment["PATH"] = str(hostile)
    environment["WINDIR"] = str(fake_windows)

    process = _run_producer(
        signed_fixture.artifact,
        receipt,
        policy,
        signed_fixture.signtool,
        signed_fixture.signing_key,
        signed_fixture.ssh_keygen,
        cwd=hostile,
        env=environment,
    )

    assert process.returncode == 0, process.stdout + process.stderr
    assert not canary.exists()
    verify_windows_trust_receipt(
        signed_fixture.artifact,
        receipt,
        policy,
        signed_fixture.signtool,
        signed_fixture.allowed_signers,
    )
    assert not list(tmp_path.glob(".windows-trust-*"))


def test_signtool_producer_rejects_sdk_directory_junction(
    tmp_path: Path, signed_fixture: SignedFixture
) -> None:
    sdk_alias = tmp_path / "sdk-alias"
    junction = subprocess.run(
        [
            "cmd.exe",
            "/d",
            "/c",
            "mklink",
            "/j",
            str(sdk_alias),
            str(signed_fixture.signtool.parent),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert junction.returncode == 0, junction.stdout + junction.stderr
    aliased_signtool = sdk_alias / signed_fixture.signtool.name
    policy = tmp_path / "junction-policy.json"
    receipt = tmp_path / "junction-receipt.json"
    _write_policy(
        policy,
        [signed_fixture.root_sha256],
        [_sha256(aliased_signtool)],
    )

    try:
        process = _run_producer(
            signed_fixture.artifact,
            receipt,
            policy,
            aliased_signtool,
            signed_fixture.signing_key,
            signed_fixture.ssh_keygen,
        )
    finally:
        sdk_alias.rmdir()

    assert process.returncode != 0
    assert "Program Files" in process.stderr or "reparse tag" in process.stderr
    assert not receipt.exists()
    assert not Path(f"{receipt}.sig").exists()
    assert not list(tmp_path.glob(".windows-trust-*"))


def test_signtool_producer_rejects_attacker_owned_sdk_copy(
    tmp_path: Path, signed_fixture: SignedFixture
) -> None:
    attacker_sdk = tmp_path / "attacker-sdk"
    attacker_sdk.mkdir()
    copied_signtool = attacker_sdk / "signtool.exe"
    shutil.copyfile(signed_fixture.signtool, copied_signtool)
    version_canary = attacker_sdk / "version.dll"
    version_canary_bytes = b"attacker-controlled version.dll canary"
    version_canary.write_bytes(version_canary_bytes)
    execution_canary = tmp_path / "attacker-sdk-executed"
    policy = tmp_path / "attacker-sdk-policy.json"
    receipt = tmp_path / "attacker-sdk-receipt.json"
    _write_policy(
        policy,
        [signed_fixture.root_sha256],
        [_sha256(copied_signtool)],
    )

    process = _run_producer(
        signed_fixture.artifact,
        receipt,
        policy,
        copied_signtool,
        signed_fixture.signing_key,
        signed_fixture.ssh_keygen,
        cwd=attacker_sdk,
    )

    assert process.returncode != 0
    assert "Program Files" in process.stderr or "SignTool ancestor" in process.stderr
    assert version_canary.read_bytes() == version_canary_bytes
    assert not execution_canary.exists()
    assert not receipt.exists()
    assert not Path(f"{receipt}.stdout.bin").exists()
    assert not Path(f"{receipt}.stderr.bin").exists()
    assert not Path(f"{receipt}.sig").exists()
    assert not list(tmp_path.glob(".windows-trust-*"))


def test_signtool_producer_rejects_unpinned_root_without_outputs(
    tmp_path: Path, signed_fixture: SignedFixture
) -> None:
    artifact = signed_fixture.artifact
    signtool = signed_fixture.signtool
    policy = tmp_path / "wrong-root-policy.json"
    receipt = tmp_path / "rejected.json"
    _write_policy(policy, ["0" * 64], [_sha256(signtool)])

    process = _run_producer(
        artifact,
        receipt,
        policy,
        signtool,
        signed_fixture.signing_key,
        signed_fixture.ssh_keygen,
    )

    assert process.returncode != 0
    assert "terminal root is not allowed" in process.stderr
    assert not receipt.exists()
    assert not Path(f"{receipt}.stdout.bin").exists()
    assert not Path(f"{receipt}.stderr.bin").exists()
    assert not Path(f"{receipt}.sig").exists()


def test_signtool_producer_rejects_unpinned_signtool_without_execution(
    tmp_path: Path, signed_fixture: SignedFixture
) -> None:
    policy = tmp_path / "wrong-tool-policy.json"
    receipt = tmp_path / "wrong-tool.json"
    _write_policy(policy, [signed_fixture.root_sha256], ["0" * 64])

    process = _run_producer(
        signed_fixture.artifact,
        receipt,
        policy,
        signed_fixture.signtool,
        signed_fixture.signing_key,
        signed_fixture.ssh_keygen,
    )

    assert process.returncode != 0
    assert "SignTool is not allowed" in process.stderr
    assert not receipt.exists()
    assert not Path(f"{receipt}.stdout.bin").exists()
    assert not Path(f"{receipt}.stderr.bin").exists()
    assert not Path(f"{receipt}.sig").exists()


def test_signtool_producer_requires_explicit_catalog(
    tmp_path: Path, signed_fixture: SignedFixture
) -> None:
    artifact = signed_fixture.artifact
    signtool = signed_fixture.signtool
    policy = tmp_path / "root-policy.json"
    receipt = tmp_path / "catalog.json"
    _write_policy(policy, [signed_fixture.root_sha256], [_sha256(signtool)])

    process = _run_producer(
        artifact,
        receipt,
        policy,
        signtool,
        signed_fixture.signing_key,
        signed_fixture.ssh_keygen,
        mode="catalog",
    )

    assert process.returncode != 0
    assert "catalog mode requires CatalogPath" in process.stderr
    assert not receipt.exists()


def test_signtool_producer_never_overwrites_existing_receipt(
    tmp_path: Path, signed_fixture: SignedFixture
) -> None:
    artifact = signed_fixture.artifact
    signtool = signed_fixture.signtool
    policy = tmp_path / "root-policy.json"
    receipt = tmp_path / "existing.json"
    _write_policy(policy, [signed_fixture.root_sha256], [_sha256(signtool)])
    receipt.write_bytes(b"operator-owned")

    process = _run_producer(
        artifact,
        receipt,
        policy,
        signtool,
        signed_fixture.signing_key,
        signed_fixture.ssh_keygen,
    )

    assert process.returncode != 0
    assert receipt.read_bytes() == b"operator-owned"
    assert not Path(f"{receipt}.stdout.bin").exists()
    assert not Path(f"{receipt}.stderr.bin").exists()
    assert not Path(f"{receipt}.sig").exists()

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from zeroverse.windows_authenticity import verify_windows_authenticity_receipt

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="requires Windows trust APIs")


def _producer() -> Path:
    return (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "windows"
        / "write-artifact-authenticity.ps1"
    )


def _run_producer(artifact: Path, receipt: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "powershell.exe",
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
            "-NetworkMode",
            "network-enabled",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_windows_producer_accepts_signed_microsoft_system_binary(tmp_path: Path) -> None:
    system_root = Path(os.environ["SYSTEMROOT"])
    source = system_root / "System32" / "kernel32.dll"
    artifact = tmp_path / "kernel32.dll"
    shutil.copyfile(source, artifact)
    receipt = tmp_path / "kernel32.authenticity.json"
    process = _run_producer(artifact, receipt)
    assert process.returncode == 0, process.stdout + process.stderr
    verified = verify_windows_authenticity_receipt(artifact, receipt)
    assert "microsoft" in verified.signer_subject.lower()
    assert verified.signature_type in {"Authenticode", "Catalog"}


def test_windows_producer_rejects_unsigned_file_without_receipt(tmp_path: Path) -> None:
    artifact = tmp_path / "unsigned.exe"
    artifact.write_bytes(b"not a signed portable executable")
    receipt = tmp_path / "unsigned.authenticity.json"
    process = _run_producer(artifact, receipt)
    assert process.returncode != 0
    assert "signature status is" in process.stderr
    assert not receipt.exists()

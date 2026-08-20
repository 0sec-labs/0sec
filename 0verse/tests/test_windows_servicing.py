from __future__ import annotations

import hashlib
import json
import struct
import subprocess
from pathlib import Path
from urllib.request import Request

import pytest
from authorization_helpers import authorization_key, authorization_policy

from zeroverse.cli import main
from zeroverse.windows_pair_plan import (
    PAIR_PLAN_CLAIMS,
    PAIR_PLAN_PROOF_LIMIT,
    verify_windows_pair_plan,
)
from zeroverse.windows_provenance import DownloadReceipt, download_official_artifact
from zeroverse.windows_servicing import (
    SERVICING_RECEIPT_CLAIMS,
    SERVICING_RECEIPT_PROOF_LIMIT,
    WindowsServicingReceipt,
    verify_windows_servicing_receipt,
)


class _Response:
    def __init__(self, body: bytes, url: str) -> None:
        self.body = body
        self.url = url
        self.status = 200
        self.offset = 0
        self.headers = {
            "Content-Length": str(len(body)),
            "Content-Type": "application/octet-stream",
        }

    def geturl(self) -> str:
        return self.url

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self.body) - self.offset
        chunk = self.body[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def _download(root: Path, name: str, body: bytes, kind: str) -> DownloadReceipt:
    url = f"https://download.microsoft.com/{name}"

    def opener(request: Request, *, timeout: float) -> _Response:
        assert request.full_url == url
        assert timeout > 0
        return _Response(body, url)

    return download_official_artifact(url, root, kind=kind, opener=opener)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _pe(marker: bytes) -> bytes:
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x2000, 0x200)
    struct.pack_into("<I", data, optional + 108, 16)
    section = optional + 0xF0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x200 : 0x200 + len(marker)] = marker
    return bytes(data)


def _ref(path: Path, root: Path) -> dict[str, object]:
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": _sha(path),
        "size_bytes": path.stat().st_size,
    }


def _acquisition(
    receipt: DownloadReceipt, root: Path, purpose: str
) -> dict[str, object]:
    return {
        "purpose": purpose,
        "bundle_path": receipt.bundle_path.relative_to(root).as_posix(),
        "artifact_sha256": receipt.artifact_sha256,
        "receipt_sha256": receipt.receipt_sha256,
    }


def _pair_fixture(root: Path) -> tuple[Path, Path, Path]:
    root.mkdir(parents=True, exist_ok=True)
    sources = root / "sources"
    sources.mkdir()
    base = _download(sources, "base.iso", b"base-media", "iso")
    candidate_update = _download(sources, "candidate.msu", b"candidate-update", "msu")
    control_update = _download(sources, "control.msu", b"control-update", "msu")
    candidate_dir = root / "candidate"
    control_dir = root / "control"
    recipe_dir = root / "recipe"
    tools_dir = root / "tools"
    for directory in (candidate_dir, control_dir, recipe_dir, tools_dir):
        directory.mkdir()
    candidate = candidate_dir / "vmswitch.sys"
    control = control_dir / "vmswitch.sys"
    recipe = recipe_dir / "produce-pair.ps1"
    tool = tools_dir / "dism.exe"
    candidate.write_bytes(_pe(b"candidate"))
    control.write_bytes(_pe(b"control"))
    recipe.write_text("# deterministic offline servicing recipe\n", encoding="utf-8")
    tool.write_bytes(b"pinned-dism-tool-fixture")
    plan: dict[str, object] = {
        "schema_version": "0verse.windows-pair-plan/v1",
        "producer": "zeroverse.windows-pair-plan/v1",
        "declared_context": {
            "cve_id": "CVE-2026-12345",
            "component": "vmswitch.sys",
            "architecture": "amd64",
        },
        "candidate": {
            "kb_id": "KB5000001",
            "build_lab_ex": "26100.1000.amd64fre.ge_release.240101-1000",
            "artifact": _ref(candidate, root),
            "acquisition_receipts": [
                _acquisition(base, root, "base-media"),
                _acquisition(candidate_update, root, "servicing-package"),
            ],
        },
        "control": {
            "kb_id": "KB5000002",
            "build_lab_ex": "26100.1100.amd64fre.ge_release.240201-1000",
            "artifact": _ref(control, root),
            "acquisition_receipts": [
                _acquisition(base, root, "base-media"),
                _acquisition(control_update, root, "servicing-package"),
            ],
        },
        "reproduction": {
            "recipe": _ref(recipe, root),
            "tools": [{"name": "dism.exe", **_ref(tool, root)}],
        },
        "verified_claims": PAIR_PLAN_CLAIMS,
        "proof_limit": PAIR_PLAN_PROOF_LIMIT,
    }
    plan_path = root / "pair-plan.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
    return plan_path, candidate, control


def _signer_identity() -> str:
    return authorization_policy().read_text(encoding="utf-8").split(maxsplit=1)[0]


def _sign(receipt: Path) -> None:
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
            "0verse-windows-servicing-receipt-v1",
            str(receipt),
        ],
        check=True,
        capture_output=True,
    )


def _rewrite(receipt: Path, raw: dict[str, object]) -> None:
    receipt.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")
    _sign(receipt)


def _fixture(
    root: Path, *, role: str = "candidate", restart: bool = False
) -> tuple[Path, Path, Path, dict[str, object]]:
    plan_path, candidate, control = _pair_fixture(root)
    plan = verify_windows_pair_plan(plan_path)
    artifact = candidate if role == "candidate" else control
    artifacts = (
        plan.candidate_acquisition_artifact_sha256s
        if role == "candidate"
        else plan.control_acquisition_artifact_sha256s
    )
    receipts = (
        plan.candidate_acquisition_receipt_sha256s
        if role == "candidate"
        else plan.control_acquisition_receipt_sha256s
    )
    build = plan.candidate_build_lab_ex if role == "candidate" else plan.control_build_lab_ex
    receipt = root / f"{role}.servicing.json"
    stdout = root / f"{receipt.name}.stdout.bin"
    stderr = root / f"{receipt.name}.stderr.bin"
    stdout.write_bytes(b"The operation completed successfully.\r\n")
    stderr.write_bytes(b"")
    raw: dict[str, object] = {
        "schema_version": "0verse.windows-servicing-receipt/v1",
        "producer": "zeroverse.windows-servicing-worker/v1",
        "receipt_signer_identity": _signer_identity(),
        "pair_plan": {"sha256": plan.plan_sha256},
        "role": role,
        "inputs": {
            "acquisition_artifact_sha256s": list(artifacts),
            "acquisition_receipt_sha256s": list(receipts),
        },
        "reproduction": {
            "recipe_sha256": plan.recipe_sha256,
            "tools": [
                {"name": name, "sha256": digest} for name, digest in plan.tools
            ],
        },
        "execution": {
            "pre_machine_id": "worker-01",
            "post_machine_id": "worker-01",
            "pre_boot_id": "boot-01",
            "post_boot_id": "boot-02" if restart else "boot-01",
            "started_at_utc": "2026-07-14T09:00:00Z",
            "completed_at_utc": "2026-07-14T09:05:00Z",
            "steps": [
                {
                    "argv": ["dism.exe", "/Image:C:\\mount", "/Add-Package"],
                    "tool_name": "dism.exe",
                    "package_sha256": artifacts[1],
                    "exit_code": 3010 if restart else 0,
                    "restart_required": restart,
                    "stdout": _ref(stdout, root),
                    "stderr": _ref(stderr, root),
                }
            ],
        },
        "observation": {
            "build_lab_ex": build,
            "retained_output": {
                "basename": artifact.name,
                "sha256": _sha(artifact),
                "size_bytes": artifact.stat().st_size,
            },
        },
        "verified_claims": SERVICING_RECEIPT_CLAIMS,
        "proof_limit": SERVICING_RECEIPT_PROOF_LIMIT,
    }
    _rewrite(receipt, raw)
    return plan_path, artifact, receipt, raw


def _verify(paths: tuple[Path, Path, Path, dict[str, object]]) -> WindowsServicingReceipt:
    plan, artifact, receipt, _ = paths
    return verify_windows_servicing_receipt(
        plan, artifact, receipt, authorization_policy()
    )


@pytest.mark.parametrize(("role", "restart"), [("candidate", False), ("control", True)])
def test_verifies_signed_authoritative_rerun_and_cli(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    role: str,
    restart: bool,
) -> None:
    paths = _fixture(tmp_path, role=role, restart=restart)
    verified = _verify(paths)
    assert verified.role == role
    assert verified.reboot_observed is restart
    assert verified.artifact_sha256 == _sha(paths[1])
    assert verified.pair_plan_sha256 == _sha(paths[0])

    assert main(
        [
            "windows-servicing-verify",
            str(paths[0]),
            str(paths[1]),
            str(paths[2]),
            str(authorization_policy()),
        ]
    ) == 0
    assert json.loads(capsys.readouterr().out)["role"] == role


def test_rejects_unsigned_tampered_and_role_swapped_receipts(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    Path(f"{paths[2]}.sig").unlink()
    with pytest.raises(ValueError, match="receipt signature"):
        _verify(paths)

    paths = _fixture(tmp_path / "tamper")
    paths[2].write_bytes(paths[2].read_bytes() + b" ")
    with pytest.raises(ValueError, match="signature is invalid"):
        _verify(paths)

    paths = _fixture(tmp_path / "role")
    paths[3]["role"] = "control"
    _rewrite(paths[2], paths[3])
    with pytest.raises(ValueError, match="ordered acquisition artifacts mismatch"):
        _verify(paths)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("reorder-inputs", "ordered acquisition artifacts mismatch"),
        ("recipe", "recipe SHA-256 mismatch"),
        ("tool", "ordered tools mismatch"),
        ("argv-tool", "tool/argv mismatch"),
        ("package", "execution package order mismatch"),
        ("bool-exit", "exit_code is invalid"),
        ("nonzero-exit", "exit_code is invalid"),
        ("restart-mismatch", "restart/exit mismatch"),
        ("machine-drift", "machine identity changed"),
        ("boot-drift", "reboot boundary mismatch"),
        ("time-reversal", "completion predates start"),
        ("build", "BuildLabEx mismatch"),
        ("output-name", "basename mismatch"),
        ("output-hash", "SHA-256 mismatch"),
        ("forbidden-claim", "unknown vulnerability_status"),
    ],
)
def test_rejects_unbound_or_unsupported_claims(
    tmp_path: Path, mutation: str, message: str
) -> None:
    paths = _fixture(tmp_path)
    raw = paths[3]
    execution = raw["execution"]
    assert isinstance(execution, dict)
    steps = execution["steps"]
    assert isinstance(steps, list)
    step = steps[0]
    assert isinstance(step, dict)
    observation = raw["observation"]
    assert isinstance(observation, dict)
    output = observation["retained_output"]
    assert isinstance(output, dict)
    reproduction = raw["reproduction"]
    assert isinstance(reproduction, dict)
    if mutation == "reorder-inputs":
        inputs = raw["inputs"]
        assert isinstance(inputs, dict)
        artifacts = inputs["acquisition_artifact_sha256s"]
        assert isinstance(artifacts, list)
        artifacts.reverse()
    elif mutation == "recipe":
        reproduction["recipe_sha256"] = "a" * 64
    elif mutation == "tool":
        tools = reproduction["tools"]
        assert isinstance(tools, list) and isinstance(tools[0], dict)
        tools[0]["sha256"] = "a" * 64
    elif mutation == "argv-tool":
        step["argv"] = ["cmd.exe", "/c", "exit 0"]
    elif mutation == "package":
        step["package_sha256"] = "a" * 64
    elif mutation == "bool-exit":
        step["exit_code"] = False
    elif mutation == "nonzero-exit":
        step["exit_code"] = 1
    elif mutation == "restart-mismatch":
        step["restart_required"] = True
    elif mutation == "machine-drift":
        execution["post_machine_id"] = "worker-02"
    elif mutation == "boot-drift":
        execution["post_boot_id"] = "boot-02"
    elif mutation == "time-reversal":
        execution["completed_at_utc"] = "2026-07-14T08:59:59Z"
    elif mutation == "build":
        observation["build_lab_ex"] = "26100.9999.amd64fre.ge_release.240101-1000"
    elif mutation == "output-name":
        output["basename"] = "other.sys"
    elif mutation == "output-hash":
        output["sha256"] = "a" * 64
    else:
        raw["vulnerability_status"] = "vulnerable"
    _rewrite(paths[2], raw)
    with pytest.raises(ValueError, match=message):
        _verify(paths)


def test_rejects_transcript_tampering_unsafe_paths_and_duplicate_json(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    transcript = tmp_path / f"{paths[2].name}.stdout.bin"
    transcript.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="stdout SHA-256 mismatch"):
        _verify(paths)

    paths = _fixture(tmp_path / "path")
    execution = paths[3]["execution"]
    assert isinstance(execution, dict)
    steps = execution["steps"]
    assert isinstance(steps, list) and isinstance(steps[0], dict)
    stdout = steps[0]["stdout"]
    assert isinstance(stdout, dict)
    stdout["path"] = "../outside.bin"
    _rewrite(paths[2], paths[3])
    with pytest.raises(ValueError, match="portable relative path"):
        _verify(paths)

    paths = _fixture(tmp_path / "duplicate")
    text = paths[2].read_text(encoding="utf-8")
    paths[2].write_text(
        text.replace('"producer":', '"producer":"duplicate","producer":', 1),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate JSON key: producer"):
        _verify(paths)

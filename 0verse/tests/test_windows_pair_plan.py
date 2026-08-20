from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from urllib.request import Request

import pytest

from zeroverse.cli import main
from zeroverse.windows_pair_plan import (
    PAIR_PLAN_CLAIMS,
    PAIR_PLAN_PROOF_LIMIT,
    verify_windows_pair_plan,
)
from zeroverse.windows_provenance import DownloadReceipt, download_official_artifact


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


def _pe(machine: int, marker: bytes) -> bytes:
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, machine, 1, 0, 0, 0, 0xF0, 0x2022)
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


def _reference(path: Path, root: Path) -> dict[str, object]:
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


def _fixture(root: Path) -> tuple[Path, dict[str, object]]:
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
    candidate.write_bytes(_pe(0x8664, b"candidate"))
    control.write_bytes(_pe(0x8664, b"control"))
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
            "artifact": _reference(candidate, root),
            "acquisition_receipts": [
                _acquisition(base, root, "base-media"),
                _acquisition(candidate_update, root, "servicing-package"),
            ],
        },
        "control": {
            "kb_id": "KB5000002",
            "build_lab_ex": "26100.1100.amd64fre.ge_release.240201-1000",
            "artifact": _reference(control, root),
            "acquisition_receipts": [
                _acquisition(base, root, "base-media"),
                _acquisition(control_update, root, "servicing-package"),
            ],
        },
        "reproduction": {
            "recipe": _reference(recipe, root),
            "tools": [{"name": "dism.exe", **_reference(tool, root)}],
        },
        "verified_claims": PAIR_PLAN_CLAIMS,
        "proof_limit": PAIR_PLAN_PROOF_LIMIT,
    }
    path = root / "pair-plan.json"
    _write(path, plan)
    return path, plan


def _write(path: Path, plan: dict[str, object]) -> None:
    path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_verifies_exact_pair_inputs_and_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path, _ = _fixture(tmp_path)
    verified = verify_windows_pair_plan(path)
    assert verified.plan_sha256 == _sha(path)
    assert verified.cve_id == "CVE-2026-12345"
    assert verified.component == "vmswitch.sys"
    assert verified.candidate_sha256 != verified.control_sha256
    assert len(verified.acquisition_receipt_sha256s) == 4
    assert verified.candidate_build_lab_ex.startswith("26100.1000.")
    assert verified.control_build_lab_ex.startswith("26100.1100.")
    assert len(verified.candidate_acquisition_artifact_sha256s) == 2
    assert len(verified.control_acquisition_receipt_sha256s) == 2
    assert verified.tools == (("dism.exe", _sha(tmp_path / "tools" / "dism.exe")),)

    assert main(["windows-pair-plan-verify", str(path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["plan_sha256"] == _sha(path)
    assert output["candidate_kb_id"] == "KB5000001"


def test_rejects_referenced_file_and_official_receipt_tampering(tmp_path: Path) -> None:
    path, plan = _fixture(tmp_path)
    candidate_path = tmp_path / str(plan["candidate"]["artifact"]["path"])  # type: ignore[index]
    candidate_path.write_bytes(candidate_path.read_bytes() + b"tampered")
    with pytest.raises(ValueError, match="artifact SHA-256 mismatch"):
        verify_windows_pair_plan(path)

    path, plan = _fixture(tmp_path / "second")
    bundle = tmp_path / "second" / str(
        plan["candidate"]["acquisition_receipts"][0]["bundle_path"]  # type: ignore[index]
    )
    receipt = bundle / "receipt.json"
    raw = json.loads(receipt.read_text(encoding="utf-8"))
    raw["source"]["etag"] = "tampered"
    receipt.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="binding mismatch"):
        verify_windows_pair_plan(path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("kb_id", "kb5000001", "kb_id is invalid"),
        ("build_lab_ex", "", "build_lab_ex is invalid"),
    ],
)
def test_rejects_invalid_declared_side_context(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    path, plan = _fixture(tmp_path)
    plan["candidate"][field] = value  # type: ignore[index]
    _write(path, plan)
    with pytest.raises(ValueError, match=message):
        verify_windows_pair_plan(path)


def test_rejects_unverifiable_labels_and_changed_claims(tmp_path: Path) -> None:
    path, plan = _fixture(tmp_path)
    plan["candidate"]["vulnerability_status"] = "vulnerable"  # type: ignore[index]
    _write(path, plan)
    with pytest.raises(ValueError, match="unknown vulnerability_status"):
        verify_windows_pair_plan(path)

    path, plan = _fixture(tmp_path / "claims")
    plan["verified_claims"] = [*PAIR_PLAN_CLAIMS, "cve-verified"]
    _write(path, plan)
    with pytest.raises(ValueError, match="verified_claims mismatch"):
        verify_windows_pair_plan(path)


def test_rejects_same_pair_identity_and_machine_mismatch(tmp_path: Path) -> None:
    path, plan = _fixture(tmp_path)
    plan["control"]["kb_id"] = plan["candidate"]["kb_id"]  # type: ignore[index]
    _write(path, plan)
    with pytest.raises(ValueError, match="KB IDs must differ"):
        verify_windows_pair_plan(path)

    path, plan = _fixture(tmp_path / "machine")
    plan["declared_context"]["architecture"] = "arm64"  # type: ignore[index]
    plan["candidate"]["build_lab_ex"] = (  # type: ignore[index]
        "26100.1000.arm64fre.ge_release.240101-1000"
    )
    plan["control"]["build_lab_ex"] = (  # type: ignore[index]
        "26100.1100.arm64fre.ge_release.240201-1000"
    )
    _write(path, plan)
    with pytest.raises(ValueError, match="PE machine"):
        verify_windows_pair_plan(path)


def test_rejects_identical_servicing_bytes_behind_distinct_receipts(tmp_path: Path) -> None:
    path, plan = _fixture(tmp_path)
    alternate_store = tmp_path / "alternate-sources"
    alternate_store.mkdir()
    alternate = _download(
        alternate_store,
        "same-candidate-bytes-different-url.msu",
        b"candidate-update",
        "msu",
    )
    plan["control"]["acquisition_receipts"][1] = _acquisition(  # type: ignore[index]
        alternate, tmp_path, "servicing-package"
    )
    _write(path, plan)
    with pytest.raises(ValueError, match="servicing artifacts must differ"):
        verify_windows_pair_plan(path)


def test_rejects_nonstring_hash_and_build_architecture_drift(tmp_path: Path) -> None:
    path, plan = _fixture(tmp_path)
    plan["candidate"]["artifact"]["sha256"] = 123  # type: ignore[index]
    _write(path, plan)
    with pytest.raises(ValueError, match="sha256 must be a string"):
        verify_windows_pair_plan(path)

    path, plan = _fixture(tmp_path / "build-arch")
    plan["candidate"]["build_lab_ex"] = (  # type: ignore[index]
        "26100.1000.arm64fre.ge_release.240101-1000"
    )
    _write(path, plan)
    with pytest.raises(ValueError, match="architecture token mismatch"):
        verify_windows_pair_plan(path)


def test_rejects_marker_only_pe(tmp_path: Path) -> None:
    path, plan = _fixture(tmp_path)
    candidate = tmp_path / "candidate" / "vmswitch.sys"
    marker = bytearray(512)
    marker[:2] = b"MZ"
    struct.pack_into("<I", marker, 0x3C, 0x80)
    marker[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", marker, 0x84, 0x8664)
    candidate.write_bytes(marker)
    plan["candidate"]["artifact"] = _reference(candidate, tmp_path)  # type: ignore[index]
    _write(path, plan)
    with pytest.raises(ValueError, match="header dimensions"):
        verify_windows_pair_plan(path)


def test_rejects_unsafe_paths_symlinks_and_misordered_receipts(tmp_path: Path) -> None:
    path, plan = _fixture(tmp_path)
    plan["candidate"]["artifact"]["path"] = "../outside.sys"  # type: ignore[index]
    _write(path, plan)
    with pytest.raises(ValueError, match="portable relative path"):
        verify_windows_pair_plan(path)

    symlink_root = tmp_path / "symlink"
    path, plan = _fixture(symlink_root)
    candidate = symlink_root / "candidate" / "vmswitch.sys"
    target = symlink_root / "candidate" / "actual.sys"
    candidate.rename(target)
    try:
        candidate.symlink_to(target.name)
    except OSError:
        pytest.skip("symlinks are unavailable")
    with pytest.raises(ValueError, match="symlink"):
        verify_windows_pair_plan(path)

    order_root = tmp_path / "order"
    path, plan = _fixture(order_root)
    plan["control"]["acquisition_receipts"].reverse()  # type: ignore[index,union-attr]
    _write(path, plan)
    with pytest.raises(ValueError, match="order/purpose"):
        verify_windows_pair_plan(path)


def test_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path, _ = _fixture(tmp_path)
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace('"producer":', '"producer": "duplicate", "producer":', 1),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate JSON key: producer"):
        verify_windows_pair_plan(path)

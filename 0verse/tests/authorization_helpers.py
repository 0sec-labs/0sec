from __future__ import annotations

import atexit
import hashlib
import json
import shutil
import subprocess
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from zeroverse.hyperv_prover import (
    GRANT_AUTHORIZATION_NAMESPACE,
    HyperVExecutionGrant,
    load_execution_grant,
)
from zeroverse.ssh_authorization import canonical_signed_material
from zeroverse.windows_scope import (
    AUTHORIZATION_NAMESPACE,
    WindowsScope,
    load_scope,
)

_ROOT = Path(tempfile.mkdtemp(prefix="0verse-authorization-tests-"))
atexit.register(shutil.rmtree, _ROOT, ignore_errors=True)
_KEY = _ROOT / "operator-key"
_POLICY = _ROOT / "allowed-signers"
_IDENTITY = "operator@example.test"


def authorization_policy() -> Path:
    _ensure_key()
    return _POLICY


def authorization_key() -> Path:
    _ensure_key()
    return _KEY


def sign_document(raw: dict[str, object], namespace: str) -> dict[str, object]:
    return _sign(raw, namespace)


def _ensure_key() -> None:
    if _KEY.exists():
        return
    if shutil.which("ssh-keygen") is None:
        pytest.skip("OpenSSH ssh-keygen unavailable for signed contract fixtures")
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(_KEY)],
        check=True,
    )
    public = _KEY.with_suffix(".pub").read_text(encoding="utf-8").strip()
    _POLICY.write_text(f"{_IDENTITY} {public}\n", encoding="utf-8")


def _sign(raw: dict[str, object], namespace: str) -> dict[str, object]:
    _ensure_key()
    signed = json.loads(json.dumps(raw))
    assert isinstance(signed, dict)
    signed["signature_ssh"] = ""
    material = canonical_signed_material(signed)
    material_path = _ROOT / f"material-{uuid.uuid4().hex}.json"
    material_path.write_bytes(material)
    subprocess.run(
        ["ssh-keygen", "-q", "-Y", "sign", "-f", str(_KEY), "-n", namespace, str(material_path)],
        check=True,
    )
    signature_path = Path(f"{material_path}.sig")
    signed["signature_ssh"] = signature_path.read_text(encoding="utf-8")
    material_path.unlink()
    signature_path.unlink()
    return signed


def authorized_scope(raw: dict[str, object]) -> WindowsScope:
    path = _ROOT / f"scope-{uuid.uuid4().hex}.json"
    write_signed_scope(raw, path)
    scope, _ = load_scope(path, allowed_signers=_POLICY, require_authorized=True)
    path.unlink()
    return scope


def write_signed_scope(raw: dict[str, object], path: Path) -> str:
    now = datetime.now(UTC)
    payload: dict[str, Any] = json.loads(json.dumps(raw))
    payload["schema_version"] = "0verse.windows-scope/v2"
    payload.setdefault("latest_build_number", "")
    payload.setdefault("latest_build_source_url", "")
    payload["authorized_by"] = _IDENTITY
    payload["issued_at"] = now.isoformat()
    payload["expires_at"] = (now + timedelta(hours=1)).isoformat()
    payload["nonce"] = "scope-authorization-000000000000000001"
    preflight = payload["preflight"]
    assert isinstance(preflight, dict)
    insider = preflight["insider"]
    assert isinstance(insider, dict)
    insider.setdefault("content_type", "")
    insider.setdefault("channel_family", "")
    signed = _sign(payload, AUTHORIZATION_NAMESPACE)
    path.write_text(json.dumps(signed), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def authorized_grant(raw: dict[str, object]) -> HyperVExecutionGrant:
    path = _ROOT / f"grant-{uuid.uuid4().hex}.json"
    write_signed_grant(raw, path)
    grant, _ = load_execution_grant(path, allowed_signers=_POLICY, require_authorized=True)
    path.unlink()
    return grant


def write_signed_grant(raw: dict[str, object], path: Path) -> str:
    payload: dict[str, object] = json.loads(json.dumps(raw))
    payload["schema_version"] = "0verse.hyperv-execution-grant/v2"
    payload.pop("signature_ssh", None)
    signed = _sign(payload, GRANT_AUTHORIZATION_NAMESPACE)
    path.write_text(json.dumps(signed), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()

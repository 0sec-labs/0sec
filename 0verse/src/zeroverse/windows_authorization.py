"""Operator-only issuance for signed Windows and Hyper-V authorization envelopes."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .hyperv_prover import (
    GRANT_AUTHORIZATION_NAMESPACE,
    SIGNED_GRANT_SCHEMA_VERSION,
    HyperVExecutionGrant,
    load_execution_grant,
)
from .ssh_authorization import (
    canonical_signed_material,
    sign_ssh_material,
    verify_ssh_signature,
)
from .windows_scope import (
    AUTHORIZATION_NAMESPACE,
    DEFAULT_AUTHORIZATION_ALLOWED_SIGNERS,
    SIGNED_SCOPE_SCHEMA_VERSION,
    WindowsScope,
    load_scope,
)

SIGNING_KEY_ENV = "ZEROVERSE_WINDOWS_AUTHORIZATION_SIGNING_KEY"


@dataclass(frozen=True)
class IssuedAuthorization:
    path: Path
    sha256: str
    schema_version: str
    authorized_by: str
    namespace: str

    def to_dict(self) -> dict[str, str]:
        return {
            "path": str(self.path),
            "sha256": self.sha256,
            "schema_version": self.schema_version,
            "authorized_by": self.authorized_by,
            "namespace": self.namespace,
        }


def issue_windows_authorization(
    template_path: str | Path,
    output_path: str | Path,
    *,
    kind: Literal["scope", "grant"],
    signing_key: str | Path | None = None,
    allowed_signers: str | Path | None = None,
) -> IssuedAuthorization:
    """Sign, self-verify, and exclusively publish one v2 authorization envelope."""
    template = Path(template_path)
    output = Path(output_path)
    if template.is_symlink() or not template.is_file():
        raise ValueError("authorization template must be a regular non-symlink file")
    if template.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("authorization template exceeds the 4 MiB limit")
    if output.exists() or output.is_symlink():
        raise ValueError("authorization output must be a new path")
    if output.parent.is_symlink() or not output.parent.is_dir():
        raise ValueError("authorization output parent must be a regular directory")
    raw = json.loads(template.read_bytes(), object_pairs_hook=_unique_object)
    if not isinstance(raw, dict):
        raise ValueError("authorization template must be a JSON object")
    if raw.get("signature_ssh") != "":
        raise ValueError("authorization template signature_ssh must be an empty string")
    if kind == "scope":
        if raw.get("schema_version") != SIGNED_SCOPE_SCHEMA_VERSION:
            raise ValueError("scope authorization template must use Windows scope v2")
        model = WindowsScope.from_mapping(raw)
        namespace = AUTHORIZATION_NAMESPACE
        label = "Windows scope authorization"
    else:
        if raw.get("schema_version") != SIGNED_GRANT_SCHEMA_VERSION:
            raise ValueError("grant authorization template must use Hyper-V grant v2")
        namespace = GRANT_AUTHORIZATION_NAMESPACE
        label = "Hyper-V execution grant authorization"
        model = None
    authorized_by = raw.get("authorized_by")
    if not isinstance(authorized_by, str):
        raise ValueError("authorization template authorized_by must be a string")
    material = canonical_signed_material(raw)
    key_value = signing_key or os.environ.get(SIGNING_KEY_ENV, "")
    if not key_value:
        raise ValueError(f"authorization signing requires {SIGNING_KEY_ENV}")
    signature = sign_ssh_material(
        material,
        signing_key=key_value,
        namespace=namespace,
        label=label,
    )
    raw["signature_ssh"] = signature
    if kind == "grant":
        HyperVExecutionGrant.from_mapping(raw)
    elif model is None:
        raise AssertionError("scope authorization validation was not performed")
    policy = (
        Path(allowed_signers)
        if allowed_signers is not None
        else DEFAULT_AUTHORIZATION_ALLOWED_SIGNERS
    )
    verify_ssh_signature(
        material,
        signature,
        identity=authorized_by,
        namespace=namespace,
        allowed_signers=policy,
        label=label,
        require_trusted_policy=allowed_signers is None,
    )
    payload = (json.dumps(raw, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    with output.open("xb") as destination:
        destination.write(payload)
    try:
        if kind == "scope":
            load_scope(output, allowed_signers=policy, require_authorized=True)
            schema = SIGNED_SCOPE_SCHEMA_VERSION
        else:
            load_execution_grant(output, allowed_signers=policy, require_authorized=True)
            schema = SIGNED_GRANT_SCHEMA_VERSION
    except Exception:
        output.unlink(missing_ok=True)
        raise
    return IssuedAuthorization(
        output.resolve(),
        hashlib.sha256(payload).hexdigest(),
        schema,
        authorized_by,
        namespace,
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

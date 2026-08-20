"""Operator-only issuance for Windows token grant and acceptance envelopes."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .ssh_authority_commitment import ssh_authority_key_commitment
from .ssh_authorization import (
    canonical_signed_material,
    sign_ssh_material,
    verify_ssh_signature,
)
from .windows_scope import DEFAULT_AUTHORIZATION_ALLOWED_SIGNERS, WindowsScope, load_scope
from .windows_token_runner import (
    ACCEPTANCE_SCHEMA_VERSION,
    ACCEPTANCE_SIGNATURE_NAMESPACE,
    DEFAULT_ACCEPTANCE_ALLOWED_SIGNERS,
    DEFAULT_GRANT_ALLOWED_SIGNERS,
    GRANT_SCHEMA_VERSION,
    GRANT_SIGNATURE_NAMESPACE,
    WindowsTokenCampaign,
    WindowsTokenExecutionGrant,
    WindowsTokenWorkerAcceptance,
    load_windows_token_campaign,
    load_windows_token_execution_grant,
    load_windows_token_worker_acceptance,
)

GRANT_SIGNING_KEY_ENV = "ZEROVERSE_WINDOWS_TOKEN_GRANT_SIGNING_KEY"
ACCEPTANCE_SIGNING_KEY_ENV = "ZEROVERSE_WINDOWS_TOKEN_ACCEPTANCE_SIGNING_KEY"
_MAXIMUM_FILE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class IssuedWindowsTokenAuthority:
    path: Path
    sha256: str
    schema_version: str
    identity: str
    namespace: str

    def to_dict(self) -> dict[str, str]:
        return {
            "path": str(self.path),
            "sha256": self.sha256,
            "schema_version": self.schema_version,
            "identity": self.identity,
            "namespace": self.namespace,
        }


def issue_windows_token_execution_grant(
    campaign_path: str | Path,
    scope_path: str | Path,
    template_path: str | Path,
    output_path: str | Path,
    *,
    signing_key: str | Path | None = None,
    scope_allowed_signers: str | Path | None = None,
    grant_allowed_signers: str | Path | None = None,
) -> IssuedWindowsTokenAuthority:
    """Sign and exclusively publish one campaign-bound execution grant."""
    campaign, campaign_sha256 = load_windows_token_campaign(campaign_path)
    scope_policy = (
        Path(scope_allowed_signers)
        if scope_allowed_signers is not None
        else DEFAULT_AUTHORIZATION_ALLOWED_SIGNERS
    )
    grant_policy = (
        Path(grant_allowed_signers)
        if grant_allowed_signers is not None
        else DEFAULT_GRANT_ALLOWED_SIGNERS
    )
    scope, scope_sha256 = load_scope(
        scope_path,
        allowed_signers=scope_policy,
        require_authorized=True,
    )
    raw = _load_unsigned_template(template_path, GRANT_SCHEMA_VERSION, "execution grant")
    unsigned = WindowsTokenExecutionGrant.from_mapping(
        {**raw, "signature_ssh": "unsigned-template"}
    )
    if (
        unsigned.campaign_sha256 != campaign_sha256
        or unsigned.scope_manifest_sha256 != scope_sha256
        or unsigned.campaign_id != campaign.campaign_id
        or unsigned.campaign_id != scope.campaign_id
        or unsigned.worker != campaign.worker
        or unsigned.worker != scope.worker
        or unsigned.target_operation_sha256 != campaign.target_operation_sha256
        or unsigned.control_operation_sha256 != campaign.control_operation_sha256
    ):
        raise ValueError("Windows token execution grant template is not campaign-bound")
    if unsigned.authorized_by == scope.authorized_by:
        raise ValueError("Windows token scope and grant signer identities must differ")
    if ssh_authority_key_commitment(scope_policy) == ssh_authority_key_commitment(grant_policy):
        raise ValueError("Windows token scope and grant SSH authority keys must differ")
    return _sign_publish_verify(
        raw,
        output_path,
        signing_key=signing_key,
        signing_key_env=GRANT_SIGNING_KEY_ENV,
        namespace=GRANT_SIGNATURE_NAMESPACE,
        label="Windows token execution grant",
        identity=unsigned.authorized_by,
        policy=grant_policy,
        require_trusted_policy=grant_allowed_signers is None,
        schema_version=GRANT_SCHEMA_VERSION,
        final_verify=lambda output: _verify_grant(
            output,
            scope_policy,
            grant_policy,
            campaign_path,
            scope_path,
            campaign_sha256,
            scope_sha256,
        ),
    )


def issue_windows_token_worker_acceptance(
    campaign_path: str | Path,
    scope_path: str | Path,
    execution_grant_path: str | Path,
    template_path: str | Path,
    output_path: str | Path,
    *,
    signing_key: str | Path | None = None,
    scope_allowed_signers: str | Path | None = None,
    grant_allowed_signers: str | Path | None = None,
    acceptance_allowed_signers: str | Path | None = None,
) -> IssuedWindowsTokenAuthority:
    """Sign and exclusively publish one independently bound worker acceptance."""
    scope_policy = (
        Path(scope_allowed_signers)
        if scope_allowed_signers is not None
        else DEFAULT_AUTHORIZATION_ALLOWED_SIGNERS
    )
    grant_policy = (
        Path(grant_allowed_signers)
        if grant_allowed_signers is not None
        else DEFAULT_GRANT_ALLOWED_SIGNERS
    )
    acceptance_policy = (
        Path(acceptance_allowed_signers)
        if acceptance_allowed_signers is not None
        else DEFAULT_ACCEPTANCE_ALLOWED_SIGNERS
    )
    campaign, campaign_sha256 = load_windows_token_campaign(campaign_path)
    scope, scope_sha256 = load_scope(
        scope_path,
        allowed_signers=scope_policy,
        require_authorized=True,
    )
    grant, grant_sha256 = load_windows_token_execution_grant(
        execution_grant_path,
        allowed_signers=grant_policy,
        require_authorized=True,
    )
    grant.require_binding(campaign, campaign_sha256, scope, scope_sha256, grant_sha256)
    commitments = {
        ssh_authority_key_commitment(scope_policy),
        ssh_authority_key_commitment(grant_policy),
        ssh_authority_key_commitment(acceptance_policy),
    }
    if len(commitments) != 3:
        raise ValueError(
            "Windows token scope, grant, and acceptance require independent SSH authority keys"
        )
    raw = _load_unsigned_template(
        template_path,
        ACCEPTANCE_SCHEMA_VERSION,
        "worker acceptance",
    )
    unsigned = WindowsTokenWorkerAcceptance.from_mapping(
        {**raw, "signature_ssh": "unsigned-template"}
    )
    if (
        unsigned.campaign_sha256 != campaign_sha256
        or unsigned.scope_manifest_sha256 != scope_sha256
        or unsigned.execution_grant_sha256 != grant_sha256
        or unsigned.execution_grant_nonce != grant.nonce
        or unsigned.campaign_id != campaign.campaign_id
        or unsigned.worker != campaign.worker
        or unsigned.build_lab_ex != scope.preflight_build_lab_ex
        or unsigned.target_operation_sha256 != campaign.target_operation_sha256
        or unsigned.control_operation_sha256 != campaign.control_operation_sha256
    ):
        raise ValueError("Windows token worker acceptance template is not authority-bound")
    role_identities = {
        scope.authorized_by,
        grant.authorized_by,
        unsigned.accepted_by,
        unsigned.capture_signer,
    }
    if len(role_identities) != 4:
        raise ValueError(
            "Windows token scope, grant, acceptance, and capture signer identities must differ"
        )
    return _sign_publish_verify(
        raw,
        output_path,
        signing_key=signing_key,
        signing_key_env=ACCEPTANCE_SIGNING_KEY_ENV,
        namespace=ACCEPTANCE_SIGNATURE_NAMESPACE,
        label="Windows token worker acceptance",
        identity=unsigned.accepted_by,
        policy=acceptance_policy,
        require_trusted_policy=acceptance_allowed_signers is None,
        schema_version=ACCEPTANCE_SCHEMA_VERSION,
        final_verify=lambda output: _verify_acceptance(
            output,
            scope_policy,
            grant_policy,
            acceptance_policy,
            campaign,
            campaign_sha256,
            scope,
            scope_sha256,
            grant,
            grant_sha256,
        ),
    )


def _load_unsigned_template(
    template_path: str | Path,
    schema_version: str,
    label: str,
) -> dict[str, object]:
    template = Path(template_path)
    descriptor = os.open(
        template,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAXIMUM_FILE_BYTES:
            raise ValueError(f"Windows token {label} template must be a bounded regular file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            data = stream.read(_MAXIMUM_FILE_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(data) > _MAXIMUM_FILE_BYTES:
        raise ValueError(f"Windows token {label} template exceeds the 4 MiB limit")
    raw = json.loads(data, object_pairs_hook=_unique_object)
    if not isinstance(raw, dict):
        raise ValueError(f"Windows token {label} template must be a JSON object")
    if raw.get("schema_version") != schema_version:
        raise ValueError(f"Windows token {label} template schema is unsupported")
    if raw.get("signature_ssh") != "":
        raise ValueError(f"Windows token {label} template signature_ssh must be empty")
    return raw


def _sign_publish_verify(
    raw: dict[str, object],
    output_path: str | Path,
    *,
    signing_key: str | Path | None,
    signing_key_env: str,
    namespace: str,
    label: str,
    identity: str,
    policy: Path,
    require_trusted_policy: bool,
    schema_version: str,
    final_verify: Callable[[Path], None],
) -> IssuedWindowsTokenAuthority:
    output = Path(output_path).expanduser().absolute()
    key_value = signing_key or os.environ.get(signing_key_env, "")
    if not key_value:
        raise ValueError(f"{label} signing requires {signing_key_env}")
    material = canonical_signed_material(raw)
    signature = sign_ssh_material(
        material,
        signing_key=key_value,
        namespace=namespace,
        label=label,
    )
    verify_ssh_signature(
        material,
        signature,
        identity=identity,
        namespace=namespace,
        allowed_signers=policy,
        label=label,
        require_trusted_policy=require_trusted_policy,
    )
    signed = {**raw, "signature_ssh": signature}
    payload = (json.dumps(signed, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    _publish_verified_file(output, payload, label=label, final_verify=final_verify)
    return IssuedWindowsTokenAuthority(
        path=output.resolve(),
        sha256=hashlib.sha256(payload).hexdigest(),
        schema_version=schema_version,
        identity=identity,
        namespace=namespace,
    )


def _publish_verified_file(
    output: Path,
    payload: bytes,
    *,
    label: str,
    final_verify: Callable[[Path], None],
) -> None:
    if os.name == "nt" or not all(
        operation in os.supports_dir_fd for operation in (os.open, os.stat, os.unlink)
    ):
        raise ValueError(f"secure {label} publication requires POSIX dirfd support")
    if output.name in {"", ".", ".."} or output.name != Path(output.name).name:
        raise ValueError(f"{label} output name is invalid")
    parent = output.parent
    _require_stable_output_ancestry(parent, label)
    parent_descriptor = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    output_descriptor: int | None = None
    created_identity: tuple[int, int] | None = None
    verified = False
    try:
        parent_metadata = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.geteuid()
            or parent_metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
        ):
            raise ValueError(f"{label} output parent must be publisher-owned and owner-only")
        _require_same_directory_inode(parent, parent_metadata, label)
        try:
            os.stat(output.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError(f"{label} output must be a new path")
        output_descriptor = os.open(
            output.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        created = os.fstat(output_descriptor)
        created_identity = (created.st_dev, created.st_ino)
        with os.fdopen(os.dup(output_descriptor), "wb") as destination:
            destination.write(payload)
            destination.flush()
            os.fsync(destination.fileno())
        _require_same_directory_inode(parent, parent_metadata, label)
        final_verify(output)
        current = os.stat(output.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != created_identity:
            raise ValueError(f"{label} output changed during verification")
        os.fsync(parent_descriptor)
        verified = True
    finally:
        if output_descriptor is not None:
            os.close(output_descriptor)
        if not verified and created_identity is not None:
            with suppress(FileNotFoundError):
                current = os.stat(
                    output.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (current.st_dev, current.st_ino) == created_identity:
                    os.unlink(
                        output.name,
                        dir_fd=parent_descriptor,
                    )  # foxguard: ignore[py/no-path-traversal]
        os.close(parent_descriptor)


def _require_stable_output_ancestry(parent: Path, label: str) -> None:
    if not parent.is_absolute():
        raise ValueError(f"{label} output parent must be absolute")
    publisher_uid = os.geteuid()
    current = Path(parent.anchor)
    try:
        current_metadata = current.lstat()
    except OSError as exc:
        raise ValueError(f"{label} output ancestry is unavailable") from exc
    if not stat.S_ISDIR(current_metadata.st_mode):
        raise ValueError(f"{label} output ancestry must contain only directories")
    for component in parent.parts[1:]:
        child = current / component
        try:
            child_metadata = child.lstat()
        except OSError as exc:
            raise ValueError(f"{label} output ancestry is unavailable") from exc
        if not stat.S_ISDIR(child_metadata.st_mode):
            raise ValueError(f"{label} output ancestry contains a symlink or non-directory")
        if current_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            if not current_metadata.st_mode & stat.S_ISVTX:
                raise ValueError(f"{label} output ancestry contains an unsafe writable directory")
            if child_metadata.st_uid != publisher_uid:
                raise ValueError(f"{label} output sticky ancestry is not publisher-owned")
        current = child
        current_metadata = child_metadata


def _require_same_directory_inode(
    parent: Path,
    expected: os.stat_result,
    label: str,
) -> None:
    try:
        current = parent.lstat()
    except OSError as exc:
        raise ValueError(f"{label} output parent changed during publication") from exc
    if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
        raise ValueError(f"{label} output parent changed during publication")


def _verify_grant(
    output: Path,
    scope_policy: Path,
    grant_policy: Path,
    campaign_path: str | Path,
    scope_path: str | Path,
    campaign_sha256: str,
    scope_sha256: str,
) -> None:
    if ssh_authority_key_commitment(scope_policy) == ssh_authority_key_commitment(
        grant_policy
    ):
        raise ValueError("Windows token issuer authority keys changed during publication")
    campaign, _ = load_windows_token_campaign(campaign_path)
    scope, _ = load_scope(scope_path, allowed_signers=scope_policy, require_authorized=True)
    grant, grant_sha256 = load_windows_token_execution_grant(
        output, allowed_signers=grant_policy, require_authorized=True
    )
    grant.require_binding(campaign, campaign_sha256, scope, scope_sha256, grant_sha256)


def _verify_acceptance(
    output: Path,
    scope_policy: Path,
    grant_policy: Path,
    acceptance_policy: Path,
    campaign: WindowsTokenCampaign,
    campaign_sha256: str,
    scope: WindowsScope,
    scope_sha256: str,
    grant: WindowsTokenExecutionGrant,
    grant_sha256: str,
) -> None:
    acceptance, acceptance_sha256 = load_windows_token_worker_acceptance(
        output, allowed_signers=acceptance_policy, require_authorized=True
    )
    scope.require_signed_authorization()
    grant.require_signed_authorization()
    if (
        len(
            {
                ssh_authority_key_commitment(scope_policy),
                ssh_authority_key_commitment(grant_policy),
                ssh_authority_key_commitment(acceptance_policy),
            }
        )
        != 3
    ):
        raise ValueError("Windows token issuer authority keys changed during publication")
    acceptance.require_binding(
        campaign,
        campaign_sha256,
        scope,
        scope_sha256,
        grant,
        grant_sha256,
        acceptance_sha256,
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

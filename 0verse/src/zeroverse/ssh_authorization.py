"""Reusable OpenSSH signatures for operator authorization artifacts."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path


def canonical_signed_material(
    raw: Mapping[str, object], *, signature_field: str = "signature_ssh"
) -> bytes:
    """Canonicalize every field except the detached signature itself."""
    if signature_field not in raw:
        raise ValueError(f"signed artifact is missing {signature_field}")
    unsigned = {key: value for key, value in raw.items() if key != signature_field}
    return json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def verify_ssh_signature(
    material: bytes,
    signature_ssh: str,
    *,
    identity: str,
    namespace: str,
    allowed_signers: str | Path,
    label: str,
    require_trusted_policy: bool,
    ssh_keygen: str | Path = "ssh-keygen",
    inherit_environment: bool = True,
) -> None:
    """Verify one namespace-separated signature against an allowed-signers policy."""
    if not material or len(material) > 4 * 1024 * 1024:
        raise ValueError(f"{label} signed material is empty or too large")
    for value, field in ((identity, "identity"), (namespace, "namespace")):
        if not value.strip() or any(char in value for char in "\x00\r\n"):
            raise ValueError(f"{label} {field} is empty or unsafe")
    if (
        not isinstance(signature_ssh, str)
        or not signature_ssh.startswith("-----BEGIN SSH SIGNATURE-----\n")
        or not signature_ssh.rstrip().endswith("-----END SSH SIGNATURE-----")
        or len(signature_ssh.encode("utf-8")) > 64 * 1024
        or "\x00" in signature_ssh
    ):
        raise ValueError(f"{label} SSH signature is malformed")
    policy = Path(allowed_signers).expanduser()
    if policy.is_symlink() or not policy.is_file():
        raise ValueError(f"{label} allowed-signers file is missing or unsafe")
    if require_trusted_policy:
        metadata = policy.stat()
        if metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError(
                f"{label} allowed-signers policy must be root-owned and not group/world writable"
            )
    policy = policy.resolve()
    with tempfile.TemporaryDirectory(prefix="0verse-signature-") as temporary:
        signature = Path(temporary) / "signature.ssh"
        signature.write_bytes(signature_ssh.encode("utf-8"))
        try:
            environment = os.environ.copy() if inherit_environment else {
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            }
            result = subprocess.run(  # foxguard: ignore[py/no-command-injection]
                [
                    str(ssh_keygen),
                    "-Y",
                    "verify",
                    "-f",
                    str(policy),
                    "-I",
                    identity,
                    "-n",
                    namespace,
                    "-s",
                    str(signature),
                ],
                input=material,
                capture_output=True,
                timeout=10,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"{label} SSH signature verification failed") from exc
    if result.returncode != 0:
        raise ValueError(f"{label} SSH signature is invalid")


def sign_ssh_material(
    material: bytes,
    *,
    signing_key: str | Path,
    namespace: str,
    label: str,
    ssh_keygen: str | Path = "ssh-keygen",
    inherit_environment: bool = True,
) -> str:
    """Sign canonical material with a restrictive operator-owned private key."""
    key = Path(signing_key).expanduser()
    if key.is_symlink() or not key.is_file():
        raise ValueError(f"{label} signing key is missing or unsafe")
    mode = key.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError(f"{label} signing key permissions are too broad")
    if not material or len(material) > 4 * 1024 * 1024:
        raise ValueError(f"{label} signed material is empty or too large")
    with tempfile.TemporaryDirectory(prefix="0verse-authorization-") as temporary:
        material_path = Path(temporary) / "material.json"
        material_path.write_bytes(material)
        try:
            environment = (
                {**os.environ, "SSH_ASKPASS_REQUIRE": "never"}
                if inherit_environment
                else {
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": "/usr/bin:/bin",
                    "SSH_ASKPASS_REQUIRE": "never",
                }
            )
            result = subprocess.run(  # foxguard: ignore[py/no-command-injection]
                [
                    str(ssh_keygen),
                    "-q",
                    "-Y",
                    "sign",
                    "-f",
                    str(key.resolve()),
                    "-n",
                    namespace,
                    str(material_path),
                ],
                capture_output=True,
                timeout=10,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"{label} signing failed") from exc
        signature_path = Path(f"{material_path}.sig")
        if result.returncode != 0 or not signature_path.is_file():
            raise ValueError(f"{label} signing failed")
        return signature_path.read_text(encoding="utf-8")

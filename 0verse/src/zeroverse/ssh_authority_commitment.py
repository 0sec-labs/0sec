"""Strict public-key commitments for OpenSSH allowed-signers policies."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
from pathlib import Path

_KEY = re.compile(
    r"(?:^|\s)(ssh-(?:ed25519|rsa)|ecdsa-sha2-[^\s]+|sk-[^\s]+)"
    r"\s+([A-Za-z0-9+/]+={0,3})(?:\s|$)"
)


def ssh_authority_key_commitment(path: str | Path) -> str:
    """Commit to the sole unique SSH public key in an allowed-signers policy."""
    source = Path(path)
    descriptor = os.open(
        source,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
            raise ValueError("allowed-signers policy must be a bounded regular file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            data = stream.read(1024 * 1024 + 1)
    finally:
        os.close(descriptor)
    if len(data) > 1024 * 1024:
        raise ValueError("allowed-signers policy exceeds the size limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("allowed-signers policy must be UTF-8") from exc
    keys: set[tuple[str, bytes]] = set()
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _KEY.search(stripped)
        if match is None:
            raise ValueError(f"allowed-signers policy line {number} has no supported SSH key")
        try:
            blob = base64.b64decode(match.group(2), validate=True)
        except ValueError as exc:
            raise ValueError(
                f"allowed-signers policy line {number} has invalid key material"
            ) from exc
        if not blob:
            raise ValueError(f"allowed-signers policy line {number} has an empty key")
        keys.add((match.group(1), blob))
    if len(keys) != 1:
        raise ValueError("allowed-signers policy must contain exactly one unique SSH public key")
    key_type, blob = next(iter(keys))
    return hashlib.sha256(
        b"0verse-ssh-authority-key-v1\0"
        + key_type.encode("ascii")
        + b"\0"
        + blob
    ).hexdigest()

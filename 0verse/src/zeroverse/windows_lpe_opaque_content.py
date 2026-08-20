"""Canonical content references for opaque Windows LPE evidence bodies.

Only files whose existing verification is limited to SHA-256 and size may be
represented here. Structured receipts, signatures, policies, component PEs,
and token-pack blobs remain ordinary verifier-readable files.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

SCHEMA_VERSION = "0verse.windows-lpe-opaque-content/v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PORTABLE_PATH = re.compile(
    r"^(?:[A-Za-z0-9][A-Za-z0-9._-]*/)*[A-Za-z0-9][A-Za-z0-9._-]*$"
)
_MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
_MAX_FILES = 4096
_MAX_SAFE_INTEGER = 2**53 - 1


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _portable_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("opaque content path must be portable and relative")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("opaque content path must be portable and relative")
    if len(value) > 2048 or _PORTABLE_PATH.fullmatch(value) is None:
        raise ValueError("opaque content path contains unsupported characters")
    return value


@dataclass(frozen=True)
class OpaqueContentRef:
    path: str
    sha256: str
    size_bytes: int


class WindowsLpeOpaqueContent:
    def __init__(self, refs: tuple[OpaqueContentRef, ...]) -> None:
        self._refs = {ref.path: ref for ref in refs}
        self._consumed: set[str] = set()

    def require(self, path: str, sha256: str, size_bytes: int) -> None:
        portable = _portable_path(path)
        ref = self._refs.get(portable)
        if ref is None or ref.sha256 != sha256 or ref.size_bytes != size_bytes:
            raise ValueError(f"opaque content reference mismatch: {portable}")
        self._consumed.add(portable)

    def consume(self, path: str) -> OpaqueContentRef:
        portable = _portable_path(path)
        ref = self._refs.get(portable)
        if ref is None:
            raise ValueError(f"opaque content reference is missing: {portable}")
        self._consumed.add(portable)
        return ref

    def require_all_consumed(self) -> None:
        unused = sorted(self._refs.keys() - self._consumed)
        if unused:
            raise ValueError("opaque content manifest contains unused files")


def load_windows_lpe_opaque_content(path: str | Path) -> WindowsLpeOpaqueContent:
    source = Path(path)
    descriptor = os.open(
        source,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_DOCUMENT_BYTES:
            raise ValueError("opaque content manifest must be a bounded regular file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            data = stream.read(_MAX_DOCUMENT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(data) > _MAX_DOCUMENT_BYTES:
        raise ValueError("opaque content manifest exceeds its size limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("opaque content manifest must be UTF-8") from exc
    raw = json.loads(text, object_pairs_hook=_unique_object)
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "files"}:
        raise ValueError("opaque content manifest fields are invalid")
    if raw["schema_version"] != SCHEMA_VERSION:
        raise ValueError("opaque content manifest schema is invalid")
    files = raw["files"]
    if not isinstance(files, list) or not files or len(files) > _MAX_FILES:
        raise ValueError("opaque content manifest files are invalid")
    refs: list[OpaqueContentRef] = []
    previous = ""
    for index, value in enumerate(files):
        if not isinstance(value, dict) or set(value) != {"path", "sha256", "size_bytes"}:
            raise ValueError(f"opaque content files[{index}] fields are invalid")
        portable = _portable_path(value["path"])
        digest = value["sha256"]
        size = value["size_bytes"]
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ValueError(f"opaque content files[{index}] SHA-256 is invalid")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= _MAX_SAFE_INTEGER
        ):
            raise ValueError(f"opaque content files[{index}] size is invalid")
        if portable <= previous:
            raise ValueError("opaque content files must be strictly path-sorted and unique")
        previous = portable
        refs.append(OpaqueContentRef(portable, digest, size))
    canonical = json.dumps(
        raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    if text != canonical:
        raise ValueError("opaque content manifest is not canonical")
    return WindowsLpeOpaqueContent(tuple(refs))

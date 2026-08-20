"""Validated content-addressed objects with serialized atomic writers."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows uses msvcrt below
    fcntl = None  # type: ignore[assignment]

try:
    import msvcrt
except ImportError:  # pragma: no cover - POSIX uses fcntl above
    msvcrt = None  # type: ignore[assignment]

_HEX = frozenset("0123456789abcdef")


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_key(key: str) -> None:
    if len(key) != 64 or any(char not in _HEX for char in key):
        raise ValueError("object key must be a full lowercase SHA-256 digest")


@contextmanager
def key_lock(path: Path) -> Iterator[None]:
    """Acquire an OS-backed per-key lock without process-global mutable state."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        elif msvcrt is not None:  # pragma: no cover - Windows only
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        elif msvcrt is not None:  # pragma: no cover - Windows only
            with contextlib.suppress(OSError):
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Durably replace one file, restoring its old value on a late failure."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    backup = temporary.with_suffix(".previous")
    had_previous = path.is_file()
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if had_previous:
            os.link(path, backup)
        temporary.replace(path)
        try:
            _fsync_directory(path.parent)
        except OSError:
            if had_previous and backup.is_file():
                backup.replace(path)
            else:
                with contextlib.suppress(OSError):
                    path.unlink()
            with contextlib.suppress(OSError):
                _fsync_directory(path.parent)
            raise
    finally:
        for leftover in (temporary, backup):
            with contextlib.suppress(OSError):
                leftover.unlink()


class AtomicObjectStore:
    """Immutable, hash-verified objects with one filesystem lock per key."""

    def __init__(self, root: str | Path, *, namespace: str) -> None:
        self.root = Path(root)
        self.namespace = namespace

    def object_path(self, key: str) -> Path:
        _validate_key(key)
        return self.root / self.namespace / key[:2] / f"{key}.json"

    def lock_path(self, key: str) -> Path:
        _validate_key(key)
        return self.root / self.namespace / "locks" / f"{key}.lock"

    def load(
        self,
        key: str,
        *,
        validator: Callable[[dict[str, Any]], bool] | None = None,
    ) -> dict[str, Any] | None:
        path = self.object_path(key)
        try:
            raw = path.read_bytes()
            value = json.loads(raw)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(value, dict):
            return None
        if validator is not None:
            try:
                if not validator(value):
                    return None
            except (KeyError, TypeError, ValueError, OverflowError):
                return None
        return value

    def store(
        self,
        key: str,
        value: dict[str, Any],
        *,
        validator: Callable[[dict[str, Any]], bool] | None = None,
        abort: Callable[[], bool] | None = None,
    ) -> dict[str, Any] | None:
        encoded = canonical_json_bytes(value)
        with key_lock(self.lock_path(key)):
            if abort is not None and abort():
                return None
            existing = self.load(key, validator=validator)
            if existing is not None:
                return existing
            atomic_write_bytes(self.object_path(key), encoded)
            loaded = self.load(key, validator=validator)
            if loaded is None:
                raise OSError("atomic object failed post-write validation")
            return loaded

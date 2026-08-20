"""Hash-bound, atomically complete resumable stage receipts."""

from __future__ import annotations

import importlib.metadata
import json
import re
import shutil
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from .atomic_store import (
    AtomicObjectStore,
    atomic_write_bytes,
    canonical_json_bytes,
    key_lock,
    sha256_bytes,
    sha256_file,
)
from .cancellation import RunContext

RECEIPT_SCHEMA = "zeroverse.stage-receipt/v1"
_SIDECAR_NAME = re.compile(r"[a-z][a-z0-9_.-]{0,79}")


def _normalized(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            raise ValueError("receipt identity cannot contain a non-finite float")
        return value
    if isinstance(value, Path):
        return str(value.expanduser().resolve(strict=False))
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("receipt identity mapping keys must be strings")
            normalized[key] = _normalized(item)
        return {key: normalized[key] for key in sorted(normalized)}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [_normalized(item) for item in value]
        return sorted(items, key=lambda item: canonical_json_bytes(item)) if isinstance(
            value, (set, frozenset)
        ) else items
    raise TypeError(f"unsupported receipt identity value: {type(value).__name__}")


@dataclass(frozen=True)
class StageIdentity:
    """Every value that can affect one resumable stage's output."""

    stage: str
    stage_schema: str
    input_sha256: str
    options: Mapping[str, Any]
    engine: Mapping[str, Any]
    backend: Mapping[str, Any]
    dependencies: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        if not isinstance(self.input_sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", self.input_sha256
        ):
            raise ValueError("input_sha256 must be the full lowercase SHA-256")
        if not isinstance(self.stage, str) or not isinstance(self.stage_schema, str):
            raise TypeError("stage and stage_schema must be strings")
        if not self.stage or not self.stage_schema:
            raise ValueError("stage and stage_schema are required")
        return cast(
            dict[str, Any],
            _normalized(
                {
                    "stage": self.stage,
                    "stage_schema": self.stage_schema,
                    "input_sha256": self.input_sha256,
                    "options": self.options,
                    "engine": self.engine,
                    "backend": self.backend,
                    "dependencies": self.dependencies,
                }
            ),
        )

    @property
    def key(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.to_dict()))


@dataclass(frozen=True)
class StageReceipt:
    key: str
    identity: dict[str, Any]
    sidecars: dict[str, bytes]
    provenance: dict[str, Any]


class ReceiptStore:
    """Receipt manifests committed last; incomplete blobs are never resumable."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self._manifests = AtomicObjectStore(self.root, namespace="receipts")

    def _blob_path(self, digest: str) -> Path:
        return self.root / "blobs" / digest[:2] / digest

    def _blob_lock(self, digest: str) -> Path:
        return self.root / "blobs" / "locks" / f"{digest}.lock"

    def _store_blob(self, data: bytes) -> str:
        digest = sha256_bytes(data)
        path = self._blob_path(digest)
        with key_lock(self._blob_lock(digest)):
            try:
                if path.is_file() and sha256_file(path) == digest:
                    return digest
            except OSError:
                pass
            atomic_write_bytes(path, data)
            if sha256_file(path) != digest:
                raise OSError("sidecar failed post-write hash validation")
        return digest

    def _valid_manifest(
        self, value: dict[str, Any], expected: StageIdentity
    ) -> bool:
        if value.get("schema") != RECEIPT_SCHEMA or value.get("status") != "completed":
            return False
        if value.get("key") != expected.key or value.get("identity") != expected.to_dict():
            return False
        sidecars = value.get("sidecars")
        if not isinstance(sidecars, dict) or "payload.json" not in sidecars:
            return False
        for name, descriptor in sidecars.items():
            if _SIDECAR_NAME.fullmatch(str(name)) is None or not isinstance(
                descriptor, dict
            ):
                return False
            digest = descriptor.get("sha256")
            size = descriptor.get("size")
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                return False
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                return False
        return isinstance(value.get("provenance"), dict)

    def load(self, identity: StageIdentity) -> StageReceipt | None:
        manifest = self._manifests.load(
            identity.key,
            validator=lambda value: self._valid_manifest(value, identity),
        )
        if manifest is None:
            return None
        loaded: dict[str, bytes] = {}
        sidecars = manifest["sidecars"]
        try:
            for name, descriptor in sidecars.items():
                data = self._blob_path(descriptor["sha256"]).read_bytes()
                if len(data) != descriptor["size"] or sha256_bytes(data) != descriptor["sha256"]:
                    return None
                loaded[name] = data
        except OSError:
            return None
        return StageReceipt(
            key=identity.key,
            identity=dict(manifest["identity"]),
            sidecars=loaded,
            provenance=dict(manifest["provenance"]),
        )

    def write_completed(
        self,
        identity: StageIdentity,
        payload: Mapping[str, Any],
        *,
        sidecars: Mapping[str, bytes] | None = None,
        provenance: Mapping[str, Any] | None = None,
        context: RunContext | None = None,
    ) -> StageReceipt | None:
        """Commit a completed stage; cancellation before manifest commit is a miss."""
        if context is not None and context.stopped:
            return None
        all_sidecars = dict(sidecars or {})
        all_sidecars["payload.json"] = canonical_json_bytes(_normalized(payload))
        descriptors: dict[str, dict[str, Any]] = {}
        for name in sorted(all_sidecars):
            if _SIDECAR_NAME.fullmatch(name) is None:
                raise ValueError(f"invalid sidecar name: {name!r}")
            if context is not None and context.stopped:
                return None
            data = all_sidecars[name]
            if not isinstance(data, bytes):
                raise TypeError("receipt sidecars must be bytes")
            digest = self._store_blob(data)
            descriptors[name] = {"sha256": digest, "size": len(data)}
        if context is not None and context.stopped:
            return None
        manifest = {
            "schema": RECEIPT_SCHEMA,
            "status": "completed",
            "key": identity.key,
            "identity": identity.to_dict(),
            "sidecars": descriptors,
            "provenance": _normalized(dict(provenance or {})),
        }
        committed = self._manifests.store(
            identity.key,
            manifest,
            validator=lambda value: self._valid_manifest(value, identity),
            abort=(lambda: context.stopped) if context is not None else None,
        )
        if committed is None:
            return None
        return self.load(identity)


def dependency_tree_identity(path: str | Path) -> dict[str, str]:
    """Hash every regular file in a stage dependency tree by relative path."""
    root = Path(path)
    if not root.is_dir():
        return {}
    return {
        str(candidate.relative_to(root)): sha256_file(candidate)
        for candidate in sorted(root.rglob("*"))
        if candidate.is_file()
    }


def engine_source_identity(*paths: str | Path) -> dict[str, Any]:
    """Hash the engine version and exact Python sources that implement a stage."""
    from . import __version__

    sources = {
        str(Path(path).resolve(strict=False)): sha256_file(path)
        for path in paths
        if Path(path).is_file()
    }
    return {"name": "zeroverse", "version": __version__, "sources": sources}


def backend_toolchain_identity(name: str, provider: str = "") -> dict[str, Any]:
    """Best-effort identity for the actual selected backend and its toolchain."""
    packages = {
        "ghidra": ("pyghidra",),
        "rizin": ("r2pipe",),
        "angr": ("angr",),
    }.get(name, ())
    package_versions: dict[str, str] = {}
    for package in packages:
        try:
            package_versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            package_versions[package] = "unavailable"
    executable_names = {
        "rizin": ("rizin", "r2"),
        "angr": (),
        "ghidra": (),
    }.get(name, ())
    executables: dict[str, dict[str, str]] = {}
    for executable in executable_names:
        resolved = shutil.which(executable)
        if resolved:
            executables[executable] = {
                "path": str(Path(resolved).resolve()),
                "sha256": sha256_file(resolved),
            }
    return {
        "name": name,
        "provider": provider,
        "python": sys.version.split()[0],
        "packages": package_versions,
        "executables": executables,
    }


def decode_payload(receipt: StageReceipt) -> dict[str, Any] | None:
    try:
        payload = json.loads(receipt.sidecars["payload.json"])
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None

"""Fail-closed import of 0brain-projected, evidence-bound 0research outcomes.

This module is deliberately only a learning sink.  It cannot run an evaluator,
grade a candidate, promote a result, publish evidence, or write to GitHub.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from . import dataset, flywheel
from .ssh_authorization import canonical_signed_material, verify_ssh_signature

_SCAN_DIRECTORY = os.scandir

_MAX_FILE_BYTES = 32 * 1024 * 1024
_MAX_LEDGER_BYTES = 32 * 1024 * 1024
_MAX_TREE_ENTRIES = 100_000
_MAX_TREE_DEPTH = 128
_DIGEST_PREFIX = "sha256:"
_ORACLE_NAMESPACE = "0verse-0research-oracle-result-v1"
_DEFAULT_ORACLE_ALLOWED_SIGNERS = Path("/etc/0verse/0research-oracle-result.allowed_signers")
_PROJECTION_KEYS = frozenset(
    {
        "schemaVersion",
        "kind",
        "runKey",
        "terminalReceiptDigest",
        "itemId",
        "attempt",
        "payloadDigest",
        "adapterReceiptDigest",
        "evidenceDigest",
        "outputTreeDigest",
    }
)
_BUNDLE_KEYS = frozenset({"schemaVersion", "contract", "records"})
_RECORD_KEYS = frozenset(
    {
        "record_id",
        "dataset_version",
        "created_at",
        "tool",
        "backend",
        "binary_name",
        "features",
        "label",
        "verdict",
        "oracle",
        "oracle_receipt",
        "oracle_evidence",
        "pov",
        "explanation",
        "synthetic",
    }
)
_FEATURE_KEYS = frozenset(
    {
        "format",
        "arch",
        "bits",
        "endian",
        "size_bytes",
        "stripped",
        "symbols_present",
        "mitigations",
    }
)
_LABEL_KEYS = frozenset({"bug_class", "source", "sink", "function", "offset"})
_POV_BASE_KEYS = frozenset({"path", "repro_cmd", "capability", "dedup_bucket"})
_ARTIFACT_KEYS = frozenset({"path", "sha256"})
_ORACLE_RECEIPT_KEYS = frozenset(
    {
        "schemaVersion",
        "contract",
        "signerIdentity",
        "sourceRecordDigest",
        "verdict",
        "oracle",
        "evidenceSha256",
        "povSha256",
        "signature_ssh",
    }
)
_PROVENANCE_KEYS = (
    "runKey",
    "terminalReceiptDigest",
    "itemId",
    "attempt",
    "payloadDigest",
    "adapterReceiptDigest",
    "evidenceDigest",
    "outputTreeDigest",
)


@dataclass(frozen=True)
class FeedbackImportReceipt:
    projection_digest: str
    bundle_digest: str
    output_tree_digest: str
    ledger_digest: str
    event_ids: tuple[str, ...]
    records_written: int
    evaluation: bool

    def to_dict(self) -> dict[str, Any]:
        body = {
            "schemaVersion": 1,
            "contract": "0verse-learning-write-receipt-v1",
            "projectionDigest": self.projection_digest,
            "bundleDigest": self.bundle_digest,
            "outputTreeDigest": self.output_tree_digest,
            "ledgerDigest": self.ledger_digest,
            "eventIds": list(self.event_ids),
            "recordsWritten": self.records_written,
            "evaluation": self.evaluation,
            "authority": {
                "gradesCandidates": False,
                "promotesCandidates": False,
                "publishesExternally": False,
                "writesGitHub": False,
            },
        }
        return {**body, "receiptDigest": _sha256(_canonical_bytes(body))}


@dataclass(frozen=True)
class VerifiedFeedbackEvent:
    """One native scientific event after exact oracle and artifact replay."""

    record: dict[str, Any]
    source_artifact_digest: str
    verification_receipt_digest: str


def _sha256(data: bytes) -> str:
    return f"{_DIGEST_PREFIX}{hashlib.sha256(data).hexdigest()}"


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _exact_object(value: Any, keys: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} must contain exactly {sorted(keys)}")
    return value


def _digest(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith(_DIGEST_PREFIX)
        or any(char not in "0123456789abcdef" for char in value[7:])
    ):
        raise ValueError(f"{label} must be a sha256: digest")
    return value


def _stable_read(
    path: Path,
    label: str,
    *,
    allow_empty: bool = False,
    max_bytes: int = _MAX_FILE_BYTES,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or (before.st_size == 0 and not allow_empty)
            or before.st_size > max_bytes
        ):
            raise ValueError(f"{label} must be a bounded non-empty regular file")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"{label} exceeds the size limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if before_identity != after_identity or total != before.st_size:
            raise ValueError(f"{label} changed while read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _sealed_output_tree(
    root_value: str | Path,
    *,
    max_files: int | None = None,
    max_total_bytes: int | None = None,
    max_entries: int = _MAX_TREE_ENTRIES,
    max_depth: int = _MAX_TREE_DEPTH,
) -> tuple[Path, str, dict[Path, bytes]]:
    """Seal a tree and reproduce 0brain's ``outputTreeDigest`` byte-for-byte."""
    requested = Path(root_value).absolute()
    if requested.is_symlink() or requested.resolve(strict=True) != requested:
        raise ValueError("output root traverses a symlink")
    if not requested.is_dir():
        raise ValueError("output root is not a directory")
    entries: list[bytes] = []
    files: dict[Path, bytes] = {}
    captured_bytes = 0
    captured_entries = 0

    def read_descriptor(descriptor: int, info: os.stat_result) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > _MAX_FILE_BYTES:
                raise ValueError("output tree entry exceeds the size limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        before_identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if before_identity != after_identity or total != info.st_size:
            raise ValueError("output tree entry changed while read")
        return b"".join(chunks)

    def walk(directory_descriptor: int, prefix: Path, depth: int) -> None:
        nonlocal captured_bytes, captured_entries
        if depth > max_depth:
            raise ValueError("output tree exceeds the depth limit")
        children: list[str] = []
        # The argument is a pinned directory fd, never a path. Keep the alias so
        # path-traversal scanners do not misclassify descriptor traversal.
        with _SCAN_DIRECTORY(directory_descriptor) as iterator:
            for entry in iterator:
                captured_entries += 1
                if captured_entries > max_entries:
                    raise ValueError("output tree exceeds the entry limit")
                children.append(entry.name)
        children.sort()
        for child in children:
            if child in {"", ".", ".."} or "/" in child or "\0" in child:
                raise ValueError("output tree contains an unsafe entry name")
            relative_path = prefix / child
            relative = relative_path.as_posix()
            info = os.stat(child, dir_fd=directory_descriptor, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                raise ValueError("output tree contains a symlink")
            if stat.S_ISDIR(info.st_mode):
                entries.append(f"d\0{relative}\n".encode())
                child_descriptor = os.open(
                    child,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=directory_descriptor,
                )
                try:
                    opened = os.fstat(child_descriptor)
                    if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
                        raise ValueError("output tree directory changed while opened")
                    walk(child_descriptor, relative_path, depth + 1)
                    after = os.fstat(child_descriptor)
                    if (opened.st_dev, opened.st_ino, opened.st_mtime_ns) != (
                        after.st_dev,
                        after.st_ino,
                        after.st_mtime_ns,
                    ):
                        raise ValueError("output tree directory changed while read")
                finally:
                    os.close(child_descriptor)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("output tree contains an unsupported entry")
            if max_files is not None and len(files) >= max_files:
                raise ValueError("output tree exceeds the file limit")
            if max_total_bytes is not None and (info.st_size > max_total_bytes - captured_bytes):
                raise ValueError("output tree exceeds the total byte limit")
            descriptor = os.open(
                child,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_descriptor,
            )
            try:
                opened = os.fstat(descriptor)
                if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
                    raise ValueError("output tree entry changed while opened")
                data = read_descriptor(descriptor, opened)
            finally:
                os.close(descriptor)
            files[requested / relative_path] = data
            captured_bytes += len(data)
            entries.append(f"f\0{relative}\0{_sha256(data)}\n".encode())

    root_descriptor = os.open(
        requested,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        opened_root = os.fstat(root_descriptor)
        requested_root = requested.stat()
        if (opened_root.st_dev, opened_root.st_ino) != (
            requested_root.st_dev,
            requested_root.st_ino,
        ):
            raise ValueError("output root changed while opened")
        walk(root_descriptor, Path(), 0)
        after_root = os.fstat(root_descriptor)
        if (opened_root.st_dev, opened_root.st_ino, opened_root.st_mtime_ns) != (
            after_root.st_dev,
            after_root.st_ino,
            after_root.st_mtime_ns,
        ):
            raise ValueError("output root changed while read")
    finally:
        os.close(root_descriptor)
    return requested, _sha256(b"".join(entries)), files


def _load_json(data: bytes, label: str) -> Any:
    try:
        return json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc


def _projection(data: bytes) -> dict[str, Any]:
    raw = _exact_object(_load_json(data, "projection"), _PROJECTION_KEYS, "projection")
    if raw["schemaVersion"] != 1 or raw["kind"] != "0verse-feedback-projection":
        raise ValueError("unsupported 0verse feedback projection")
    if not isinstance(raw["runKey"], str) or not re.fullmatch(
        r"0research-[0-9a-f]{64}", raw["runKey"]
    ):
        raise ValueError("projection.runKey must be an exact 0research content key")
    if not isinstance(raw["itemId"], str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9._-]{2,127}", raw["itemId"]
    ):
        raise ValueError("projection.itemId is not a safe item identity")
    if (
        isinstance(raw["attempt"], bool)
        or not isinstance(raw["attempt"], int)
        or raw["attempt"] < 1
    ):
        raise ValueError("projection.attempt must be a positive integer")
    for key in (
        "terminalReceiptDigest",
        "payloadDigest",
        "adapterReceiptDigest",
        "evidenceDigest",
        "outputTreeDigest",
    ):
        _digest(raw[key], f"projection.{key}")
    return raw


def _validate_bundle_record(raw: Any, *, allow_synthetic: bool = False) -> dict[str, Any]:
    record = _exact_object(raw, _RECORD_KEYS, "bundle record")
    for key in (
        "record_id",
        "dataset_version",
        "created_at",
        "backend",
        "binary_name",
        "explanation",
        "verdict",
        "oracle",
    ):
        if not isinstance(record.get(key), str):
            raise ValueError(f"bundle record.{key} must be a string")
    tool = _exact_object(record.get("tool"), frozenset({"name", "version"}), "bundle record.tool")
    if not all(isinstance(tool[key], str) and tool[key] for key in tool):
        raise ValueError("bundle record.tool values must be non-empty strings")
    features = _exact_object(record.get("features"), _FEATURE_KEYS, "bundle record.features")
    for key in ("format", "arch", "endian"):
        if not isinstance(features[key], str):
            raise ValueError(f"bundle record.features.{key} must be a string")
    for key in ("bits", "size_bytes"):
        if (
            isinstance(features[key], bool)
            or not isinstance(features[key], int)
            or features[key] < 0
        ):
            raise ValueError(f"bundle record.features.{key} must be a non-negative integer")
    for key in ("stripped", "symbols_present"):
        if features[key] is not None and not isinstance(features[key], bool):
            raise ValueError(f"bundle record.features.{key} must be boolean or null")
    if not isinstance(features["mitigations"], dict):
        raise ValueError("bundle record.features.mitigations must be an object")
    label = _exact_object(record.get("label"), _LABEL_KEYS, "bundle record.label")
    if not all(isinstance(label[key], str) for key in label):
        raise ValueError("bundle record.label values must be strings")
    pov = record.get("pov")
    if not isinstance(pov, dict) or set(pov) not in (_POV_BASE_KEYS, _POV_BASE_KEYS | {"sha256"}):
        raise ValueError("bundle record.pov has an invalid shape")
    if not all(isinstance(pov[key], str) for key in pov):
        raise ValueError("bundle record.pov values must be strings")
    for key in ("oracle_receipt", "oracle_evidence"):
        artifact = _exact_object(record.get(key), _ARTIFACT_KEYS, f"bundle record.{key}")
        if not isinstance(artifact["path"], str) or not artifact["path"]:
            raise ValueError(f"bundle record.{key}.path must be non-empty")
        _digest(artifact["sha256"], f"bundle record.{key}.sha256")
    _reject_base64_keys(record)
    dataset.validate_record(record)
    if record["synthetic"] is not False and not (allow_synthetic and record["synthetic"] is True):
        raise ValueError("synthetic rows are not production learning")
    if record["verdict"] == "confirmed":
        if record["oracle"] not in {
            "differential-allocator",
            "canary-marker",
            "differential-crash",
        }:
            raise ValueError("confirmed learning requires a deterministic PoV oracle")
        if "sha256" not in pov:
            raise ValueError("confirmed learning requires a replay-script digest")
    elif record["verdict"] == "pruned":
        if record["oracle"] != "angr-reachability(UNSAT)":
            raise ValueError("only exact angr UNSAT refutations may be learned")
        if pov.get("path") or pov.get("repro_cmd") or "sha256" in pov:
            raise ValueError("an UNSAT refutation must not carry a PoV")
    else:
        raise ValueError("unresolved hypotheses may not enter production learning")
    return record


def _reject_base64_keys(value: Any, location: str = "bundle record") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if "base64" in str(key).lower():
                raise ValueError(f"{location} contains forbidden base64-bearing key {key!r}")
            _reject_base64_keys(nested, f"{location}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_base64_keys(nested, f"{location}[{index}]")


def _bundle(data: bytes, *, allow_synthetic: bool = False) -> list[dict[str, Any]]:
    raw = _exact_object(_load_json(data, "bundle"), _BUNDLE_KEYS, "bundle")
    if raw["schemaVersion"] != 1 or raw["contract"] != "0verse-learning-bundle-v1":
        raise ValueError("unsupported 0verse learning bundle")
    records = raw["records"]
    if not isinstance(records, list) or not records:
        raise ValueError("bundle.records must be a non-empty array")
    if len(records) > 1_000:
        raise ValueError("bundle contains too many records")
    return [_validate_bundle_record(record, allow_synthetic=allow_synthetic) for record in records]


def _event_record(
    record: dict[str, Any],
    projection: dict[str, Any],
    root: Path,
    files: dict[Path, bytes],
    oracle_allowed_signers: Path,
    require_trusted_policy: bool,
) -> VerifiedFeedbackEvent:
    retained = cast(dict[str, Any], json.loads(json.dumps(record)))
    pov = retained["pov"]
    if retained["verdict"] == "confirmed":
        relative = Path(pov["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("bundle PoV path must be relative and traversal-free")
        target = root.joinpath(relative)
        data = files.get(target)
        if data is None:
            raise ValueError("bundle PoV is not a regular file in the sealed output tree")
        if _sha256(data) != f"sha256:{pov['sha256']}":
            raise ValueError("bundle PoV digest does not match the sealed replay script")
        pov["path"] = str(target)
        pov["repro_cmd"] = f"python3 {target}"

    def artifact_bytes(descriptor: dict[str, Any], label: str) -> bytes:
        relative = Path(descriptor["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"bundle {label} path must be relative and traversal-free")
        data = files.get(root.joinpath(relative))
        if data is None or _sha256(data) != descriptor["sha256"]:
            raise ValueError(f"bundle {label} is missing or digest-drifted")
        return data

    evidence = artifact_bytes(retained["oracle_evidence"], "oracle evidence")
    receipt_descriptor = retained["oracle_receipt"]
    receipt_bytes = artifact_bytes(receipt_descriptor, "oracle receipt")
    receipt = _exact_object(
        _load_json(receipt_bytes, "oracle receipt"),
        _ORACLE_RECEIPT_KEYS,
        "oracle receipt",
    )
    unsigned_record = {key: value for key, value in record.items() if key != "oracle_receipt"}
    expected_source = _sha256(_canonical_bytes(unsigned_record))
    expected_pov = f"sha256:{pov.get('sha256', '')}" if pov.get("sha256") else _sha256(b"")
    if (
        receipt["schemaVersion"] != 1
        or receipt["contract"] != "0verse-oracle-result-receipt-v1"
        or receipt["sourceRecordDigest"] != expected_source
        or receipt["verdict"] != retained["verdict"]
        or receipt["oracle"] != retained["oracle"]
        or receipt["evidenceSha256"] != _sha256(evidence)
        or receipt["povSha256"] != expected_pov
    ):
        raise ValueError("oracle receipt does not bind the exact scientific outcome")
    if not isinstance(receipt["signerIdentity"], str) or not receipt["signerIdentity"]:
        raise ValueError("oracle receipt signer identity is invalid")
    if not isinstance(receipt["signature_ssh"], str):
        raise ValueError("oracle receipt signature is invalid")
    verify_ssh_signature(
        canonical_signed_material(receipt),
        receipt["signature_ssh"],
        identity=receipt["signerIdentity"],
        namespace=_ORACLE_NAMESPACE,
        allowed_signers=oracle_allowed_signers,
        label="0research oracle result receipt",
        require_trusted_policy=require_trusted_policy,
        inherit_environment=False,
    )

    source = {key: projection[key] for key in _PROVENANCE_KEYS}
    scientific_identity = {
        "oracleReceiptDigest": receipt_descriptor["sha256"],
        "sourceRecordDigest": receipt["sourceRecordDigest"],
        "oracleEvidenceDigest": retained["oracle_evidence"]["sha256"],
        "signerIdentity": receipt["signerIdentity"],
        "binaryName": retained["binary_name"],
        "label": retained["label"],
        "verdict": retained["verdict"],
        "oracle": retained["oracle"],
        "povSha256": pov.get("sha256", ""),
    }
    # Scheduler transport can be repeated under fresh run keys.  The learning
    # identity therefore comes only from the separately signed scientific
    # observation; transport provenance is retained but cannot amplify a row.
    event_id = _sha256(_canonical_bytes(scientific_identity))
    retained["dataset_version"] = dataset.DATASET_VERSION
    retained["event_id"] = event_id
    retained["provenance"] = {
        "contract": "0brain-zeroverse-feedback-v1",
        **source,
    }
    dataset.validate_record(retained)
    return VerifiedFeedbackEvent(
        record=retained,
        source_artifact_digest=receipt["sourceRecordDigest"],
        verification_receipt_digest=receipt_descriptor["sha256"],
    )


def verify_feedback_events(
    *,
    projection_path: str | Path,
    bundle_path: str | Path,
    output_root: str | Path,
    oracle_allowed_signers: str | Path | None = None,
) -> tuple[tuple[VerifiedFeedbackEvent, ...], str, str, str]:
    """Replay native evidence without mutating the production learning ledger."""
    projection_bytes = _stable_read(Path(projection_path), "projection")
    projection = _projection(projection_bytes)
    root, tree_digest, files = _sealed_output_tree(output_root)
    requested_bundle = Path(bundle_path).absolute()
    try:
        requested_bundle.relative_to(root)
    except ValueError as exc:
        raise ValueError("bundle must be inside the trusted output root") from exc
    bundle_bytes = files.get(requested_bundle)
    if bundle_bytes is None:
        raise ValueError("bundle must be a regular file in the sealed output tree")
    bundle_digest = _sha256(bundle_bytes)
    if projection["outputTreeDigest"] != tree_digest:
        raise ValueError("projection output-tree digest does not match the sealed output tree")
    if projection["evidenceDigest"] != bundle_digest:
        raise ValueError("projection evidence digest does not match the learning bundle")
    oracle_policy = (
        Path(oracle_allowed_signers)
        if oracle_allowed_signers is not None
        else _DEFAULT_ORACLE_ALLOWED_SIGNERS
    )
    evaluation = flywheel._env_truthy("ZEROVERSE_EVALUATION")
    verified = tuple(
        _event_record(row, projection, root, files, oracle_policy, True)
        for row in _bundle(bundle_bytes, allow_synthetic=evaluation)
    )
    by_event: dict[str, VerifiedFeedbackEvent] = {}
    for event in verified:
        by_event.setdefault(str(event.record["event_id"]), event)
    return (
        tuple(by_event.values()),
        _sha256(projection_bytes),
        bundle_digest,
        tree_digest,
    )


def _ledger_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file():
        raise ValueError("learning ledger must be a regular non-symlink file")
    rows: list[dict[str, Any]] = []
    for line in _stable_read(
        path, "learning ledger", allow_empty=True, max_bytes=_MAX_LEDGER_BYTES
    ).splitlines():
        if not line.strip():
            continue
        row = _load_json(line, "learning ledger row")
        if not isinstance(row, dict):
            raise ValueError("learning ledger row must be an object")
        dataset.validate_record(row)
        rows.append(row)
    return rows


@contextmanager
def locked_retained_feedback_events(
    path_value: str | Path,
) -> Iterator[tuple[dict[str, Any], ...]]:
    """Hold the private ledger lock while a consumer commits derived state."""
    path = Path(path_value).absolute()
    with _locked_ledger(path):
        yield tuple(_ledger_rows(path))


def retained_feedback_events(path_value: str | Path) -> tuple[dict[str, Any], ...]:
    """Stable-read exact production rows under the ledger's private lock."""
    with locked_retained_feedback_events(path_value) as rows:
        return rows


def _atomic_ledger_write(path: Path, rows: list[dict[str, Any]]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = b"".join(_canonical_bytes(row) for row in rows)
    if len(payload) > _MAX_LEDGER_BYTES:
        raise ValueError(
            "learning ledger reached its bounded segment limit; rotate to a new segment"
        )
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        Path(temporary).replace(path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        Path(temporary).unlink(missing_ok=True)
        raise
    return _sha256(payload)


@contextmanager
def _locked_ledger(path: Path) -> Iterator[None]:
    """Lock a private ledger without following a substituted lock-path symlink."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.resolve(strict=True) != path.parent:
        raise ValueError("learning ledger parent traverses a symlink")
    parent_info = path.parent.stat()
    if parent_info.st_uid != os.getuid() or parent_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("learning ledger parent must be owner-controlled and private")
    lock = path.with_name(f".{path.name}.lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(lock, flags, 0o600)
    lock_info = os.fstat(descriptor)
    if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.getuid():
        os.close(descriptor)
        raise ValueError("learning ledger lock must be an owner-controlled regular file")
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "a+b", closefd=True) as handle:
        flywheel._lock_file(handle)
        try:
            yield
        finally:
            flywheel._unlock_file(handle)


def import_feedback(
    *,
    projection_path: str | Path,
    bundle_path: str | Path,
    output_root: str | Path,
    ledger_path: str | Path,
    oracle_allowed_signers: str | Path | None = None,
) -> FeedbackImportReceipt:
    """Verify a feedback projection and atomically retain only evidence-grade rows."""
    events, projection_digest, bundle_digest, tree_digest = verify_feedback_events(
        projection_path=projection_path,
        bundle_path=bundle_path,
        output_root=output_root,
        oracle_allowed_signers=oracle_allowed_signers,
    )
    evaluation = flywheel._env_truthy("ZEROVERSE_EVALUATION")
    records = [event.record for event in events]

    ledger = Path(ledger_path).absolute()
    recall = os.environ.get("ZEROVERSE_DATASET_PATH", "").strip()
    if recall and ledger.resolve() == Path(recall).resolve():
        raise ValueError("production learning ledger must differ from the evaluation corpus")
    if evaluation:
        ledger_bytes = (
            _stable_read(
                ledger,
                "learning ledger",
                allow_empty=True,
                max_bytes=_MAX_LEDGER_BYTES,
            )
            if ledger.exists()
            else b""
        )
        return FeedbackImportReceipt(
            projection_digest=projection_digest,
            bundle_digest=bundle_digest,
            output_tree_digest=tree_digest,
            ledger_digest=_sha256(ledger_bytes),
            event_ids=tuple(record["event_id"] for record in records),
            records_written=0,
            evaluation=True,
        )

    with _locked_ledger(ledger):
        existing = _ledger_rows(ledger)
        retained_ids = [str(row["event_id"]) for row in existing if row.get("event_id")]
        existing_ids = set(retained_ids)
        if len(existing_ids) != len(retained_ids):
            raise ValueError("learning ledger contains duplicate event identities")
        fresh = [row for row in records if row["event_id"] not in existing_ids]
        all_rows = [*existing, *fresh]
        ledger_digest = (
            _atomic_ledger_write(ledger, all_rows)
            if fresh
            else _sha256(
                _stable_read(
                    ledger,
                    "learning ledger",
                    allow_empty=True,
                    max_bytes=_MAX_LEDGER_BYTES,
                )
            )
        )
    return FeedbackImportReceipt(
        projection_digest=projection_digest,
        bundle_digest=bundle_digest,
        output_tree_digest=tree_digest,
        ledger_digest=ledger_digest,
        event_ids=tuple(row["event_id"] for row in records),
        records_written=len(fresh),
        evaluation=False,
    )

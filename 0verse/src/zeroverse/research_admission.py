"""Per-event 0research admissions from natively verified 0verse outcomes."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any

from . import flywheel, research_feedback
from .ssh_authorization import canonical_signed_material, verify_ssh_signature

_LIST_DIRECTORY = os.listdir
_UNLINK = os.unlink

_ADMISSION_NAMESPACE = "0research-evidence-admission-v1:zeroverse_scientific_event"
_PACKAGE_NAMESPACE = "0verse-research-admission-bundle-v2"
_SNAPSHOT_NAMESPACE = "0verse-0research-target-snapshot-v1"
_SHA = re.compile(r"sha256:[0-9a-f]{64}")
_GIT_OID = re.compile(r"[0-9a-f]{40}")
_PRINCIPAL = re.compile(r"[A-Za-z0-9@._-]{3,128}")
_KEY_PATTERN = re.compile(r"^(?:sk-)?ssh-(?:ed25519|rsa)|^ecdsa-sha2-")
_SNAPSHOT_ARTIFACTS = frozenset({"sourceTree", "package", "lockfile", "toolchain", "runtimeConfig"})
_MAX_PROVENANCE_FILES = 2_000
_MAX_PROVENANCE_BYTES = 384 * 1024 * 1024
_MAX_PROVENANCE_ENTRIES = 4_000
_MAX_PROVENANCE_DEPTH = 64
_AUTHORITY = {
    "privateProposalRetentionAllowed": True,
    "executionAllowed": False,
    "providerAccessAllowed": False,
    "spendAllowed": False,
    "learningPromotionAllowed": False,
    "trainingAllowed": False,
    "modelWriteAllowed": False,
    "githubWriteAllowed": False,
    "autoMergeAllowed": False,
    "deploymentAllowed": False,
    "externalPublicationAllowed": False,
}

ResearchAdmissionSigner = Callable[[bytes, str, str], str]
BoundaryCheck = Callable[[str], None]


@dataclass(frozen=True)
class VerifiedFeedbackAdmissionBundle:
    """Authenticated manifest and captured bytes; consumers never reopen paths."""

    manifest: dict[str, Any]
    _artifacts: MappingProxyType[str, bytes]

    def read_bytes(self, relative_path: str | Path) -> bytes:
        relative = Path(relative_path)
        _safe_parts(relative, "verified admission artifact")
        try:
            return self._artifacts[relative.as_posix()]
        except KeyError as exc:
            raise ValueError("verified admission artifact is absent") from exc


def _production_ledger() -> Path:
    configured = os.environ.get("ZEROVERSE_LEARNING_PATH", "")
    if not configured:
        raise ValueError("ZEROVERSE_LEARNING_PATH must name the production ledger")
    path = Path(configured)
    if (
        not path.is_absolute()
        or path != path.absolute()
        or path.is_symlink()
        or path.resolve(strict=True) != path
    ):
        raise ValueError("ZEROVERSE_LEARNING_PATH must be an absolute canonical path")
    return path


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _sealed_provenance_tree(
    root: str | Path,
    *,
    max_files: int | None = None,
    max_total_bytes: int | None = None,
) -> tuple[Path, str, dict[Path, bytes]]:
    return research_feedback._sealed_output_tree(
        root,
        max_files=max_files,
        max_total_bytes=max_total_bytes,
        max_entries=_MAX_PROVENANCE_ENTRIES,
        max_depth=_MAX_PROVENANCE_DEPTH,
    )


def _domain(name: str, value: Any) -> str:
    return _sha256(name.encode() + b"\0" + _canonical(value) + b"\n")


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase sha256 digest")
    return value


def _read(path: Path, label: str, maximum: int = 32 * 1024 * 1024) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 1 or before.st_size > maximum:
            raise ValueError(f"{label} must be a bounded regular file")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, min(1024 * 1024, maximum + 1)):
            chunks.append(chunk)
            if sum(map(len, chunks)) > maximum:
                raise ValueError(f"{label} exceeds its size limit")
        after = os.fstat(descriptor)

        def identity(info: os.stat_result) -> tuple[int, int, int, int]:
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)

        data = b"".join(chunks)
        if identity(before) != identity(after) or len(data) != before.st_size:
            raise ValueError(f"{label} changed while read")
        return data
    finally:
        os.close(descriptor)


def _canonical_observed_at(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("scientific event created_at must be non-empty text")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("scientific event created_at must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("scientific event created_at must include a timezone")
    utc = parsed.astimezone(UTC)
    milliseconds = utc.microsecond // 1_000
    return (
        utc.replace(microsecond=milliseconds * 1_000)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _policy_keys(path_value: str | Path, label: str) -> set[tuple[str, str]]:
    path = Path(path_value).absolute()
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise ValueError(f"{label} signer policy is missing or unsafe")
    keys: set[tuple[str, str]] = set()
    for raw in _read(path, f"{label} signer policy", 1024 * 1024).decode().splitlines():
        tokens = raw.strip().split()
        if not tokens or tokens[0].startswith("#"):
            continue
        for index, token in enumerate(tokens[:-1]):
            if _KEY_PATTERN.match(token):
                keys.add((token, tokens[index + 1]))
                break
    if not keys:
        raise ValueError(f"{label} signer policy contains no SSH public keys")
    return keys


def _validate_policy_separation(policies: dict[str, str | Path]) -> None:
    resolved = {
        role: Path(value).absolute().resolve(strict=True) for role, value in policies.items()
    }
    if len(set(resolved.values())) != len(resolved):
        raise ValueError("0verse source signer policies must be pairwise distinct")
    owners: dict[tuple[str, str], str] = {}
    for role, policy in resolved.items():
        for key in _policy_keys(policy, role):
            if key in owners:
                raise ValueError(f"0verse source signer keys overlap: {owners[key]} and {role}")
            owners[key] = role


def _require_plain_ed25519_policy(path_value: str | Path) -> None:
    path = Path(path_value).absolute()
    keys: set[str] = set()
    for raw in _read(path, "evidence signer policy", 1024 * 1024).decode().splitlines():
        tokens = raw.strip().split()
        if not tokens or tokens[0].startswith("#"):
            continue
        try:
            key_index = tokens.index("ssh-ed25519")
        except ValueError as exc:
            raise ValueError(
                "0verse evidence policy must contain only plain ssh-ed25519 signer lines"
            ) from exc
        if (
            len(tokens) < 3
            or key_index < 1
            or key_index + 1 >= len(tokens)
            or re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", tokens[key_index + 1]) is None
        ):
            raise ValueError("0verse evidence policy has an unsupported signer line")
        keys.add(tokens[key_index + 1])
    if not keys:
        raise ValueError("0verse evidence policy contains no signers")


def _read_artifact_under(root: Path, relative: Path, label: str) -> bytes:
    """Read an artifact through pinned directories without following symlinks."""
    parts = relative.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"{label} path is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    directory = os.open(root, flags | getattr(os, "O_DIRECTORY", 0))
    try:
        for part in parts[:-1]:
            child = os.open(part, flags | getattr(os, "O_DIRECTORY", 0), dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(parts[-1], flags, dir_fd=directory)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size < 1:
                raise ValueError(f"{label} must be a non-empty regular file")
            chunks: list[bytes] = []
            total = 0
            while chunk := os.read(descriptor, 1024 * 1024):
                total += len(chunk)
                if total > 32 * 1024 * 1024:
                    raise ValueError(f"{label} exceeds its size limit")
                chunks.append(chunk)
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ) or total != before.st_size:
                raise ValueError(f"{label} changed while read")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ValueError(f"{label} is missing or unsafe") from exc
    finally:
        os.close(directory)


def _target_snapshot(
    snapshot_path_value: str | Path,
    expected_event_ids: tuple[str, ...],
    allowed_signers: str | Path,
) -> str:
    snapshot_path = Path(snapshot_path_value).absolute()
    if snapshot_path.is_symlink() or snapshot_path.resolve(strict=True) != snapshot_path:
        raise ValueError("0verse target snapshot path is unsafe")
    try:
        raw = json.loads(_read(snapshot_path, "0verse target snapshot"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("0verse target snapshot is not UTF-8 JSON") from exc
    keys = {
        "schemaVersion",
        "contract",
        "repository",
        "commitSha",
        "gitTreeOid",
        "artifacts",
        "eventIds",
        "principal",
        "signature_ssh",
    }
    if not isinstance(raw, dict) or set(raw) != keys:
        raise ValueError("0verse target snapshot has unsupported or missing fields")
    if (
        raw["schemaVersion"] != 1
        or raw["contract"] != "0verse-target-snapshot-v1"
        or raw["repository"] != "0sec-labs/0verse"
    ):
        raise ValueError("0verse target snapshot identity is invalid")
    if (
        not isinstance(raw["commitSha"], str)
        or _GIT_OID.fullmatch(raw["commitSha"]) is None
        or not isinstance(raw["gitTreeOid"], str)
        or _GIT_OID.fullmatch(raw["gitTreeOid"]) is None
    ):
        raise ValueError("0verse target snapshot Git identity is invalid")
    if raw["eventIds"] != sorted(expected_event_ids) or len(set(raw["eventIds"])) != len(
        expected_event_ids
    ):
        raise ValueError("0verse target snapshot does not bind the exact scientific events")
    artifacts = raw["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != _SNAPSHOT_ARTIFACTS:
        raise ValueError("0verse target snapshot artifact set is invalid")
    artifact_digests: dict[str, str] = {}
    root = snapshot_path.parent.resolve(strict=True)
    for name in sorted(_SNAPSHOT_ARTIFACTS):
        descriptor = artifacts[name]
        if (
            not isinstance(descriptor, dict)
            or set(descriptor) != {"path", "sha256"}
            or not isinstance(descriptor["path"], str)
        ):
            raise ValueError(f"0verse target snapshot {name} descriptor is invalid")
        relative = Path(descriptor["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"0verse target snapshot {name} path is unsafe")
        expected = _digest(descriptor["sha256"], f"0verse target snapshot {name}")
        artifact_bytes = _read_artifact_under(root, relative, f"0verse target snapshot {name}")
        if _sha256(artifact_bytes) != expected:
            raise ValueError(f"0verse target snapshot {name} bytes drift")
        artifact_digests[name] = expected
    principal = raw["principal"]
    if not isinstance(principal, str) or _PRINCIPAL.fullmatch(principal) is None:
        raise ValueError("0verse target snapshot principal is unsafe")
    verify_ssh_signature(
        canonical_signed_material(raw),
        raw["signature_ssh"],
        identity=principal,
        namespace=_SNAPSHOT_NAMESPACE,
        allowed_signers=allowed_signers,
        label="0verse target snapshot",
        require_trusted_policy=True,
        inherit_environment=False,
    )
    return _domain(
        "0research-zeroverse-target-snapshot-v1",
        {
            "repository": raw["repository"],
            "commitSha": raw["commitSha"],
            "gitTreeOid": raw["gitTreeOid"],
            "artifactDigests": artifact_digests,
        },
    )


def _indexed_retained_events(
    records: tuple[dict[str, Any], ...],
) -> dict[str, dict[str, Any]]:
    retained: dict[str, dict[str, Any]] = {}
    for record in records:
        event_id = record.get("event_id")
        if isinstance(event_id, str):
            if event_id in retained:
                raise ValueError("production ledger contains duplicate event identities")
            retained[event_id] = record
    return retained


def _without_transport(record: dict[str, Any]) -> dict[str, Any]:
    normalized = {key: nested for key, nested in record.items() if key != "provenance"}
    pov = normalized.get("pov")
    if isinstance(pov, dict):
        normalized["pov"] = {
            key: nested for key, nested in pov.items() if key not in {"path", "repro_cmd"}
        }
    return normalized


def _write_bytes_exclusive_at(directory: int, name: str, payload: bytes) -> None:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=directory,
    )
    try:
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_exclusive_at(directory: int, name: str, value: Any) -> None:
    _write_bytes_exclusive_at(
        directory,
        name,
        json.dumps(value, sort_keys=True, indent=2).encode() + b"\n",
    )


def _safe_parts(relative: Path, label: str) -> tuple[str, ...]:
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} or "/" in part or "\0" in part for part in relative.parts)
    ):
        raise ValueError(f"{label} path is unsafe")
    return relative.parts


def _write_bytes_under(root: int, relative: Path, payload: bytes, label: str) -> None:
    parts = _safe_parts(relative, label)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    directory = os.dup(root)
    try:
        for part in parts[:-1]:
            with suppress(FileExistsError):
                os.mkdir(part, 0o700, dir_fd=directory)
            child = os.open(part, flags, dir_fd=directory)
            opened = os.fstat(child)
            if not stat.S_ISDIR(opened.st_mode):
                os.close(child)
                raise ValueError(f"{label} directory is unsafe")
            os.close(directory)
            directory = child
        _write_bytes_exclusive_at(directory, parts[-1], payload)
        os.fsync(directory)
    finally:
        os.close(directory)


def _target_snapshot_sources(snapshot_path_value: str | Path) -> tuple[bytes, dict[Path, bytes]]:
    snapshot_path = Path(snapshot_path_value).absolute()
    snapshot_bytes = _read(snapshot_path, "0verse target snapshot")
    try:
        raw = json.loads(snapshot_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("0verse target snapshot is not UTF-8 JSON") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("artifacts"), dict):
        raise ValueError("0verse target snapshot artifacts are invalid")
    artifacts = raw["artifacts"]
    if set(artifacts) != _SNAPSHOT_ARTIFACTS:
        raise ValueError("0verse target snapshot artifact set is invalid")
    retained: dict[Path, bytes] = {Path("snapshot.json"): snapshot_bytes}
    root = snapshot_path.parent.resolve(strict=True)
    for name in sorted(_SNAPSHOT_ARTIFACTS):
        descriptor = artifacts[name]
        if (
            not isinstance(descriptor, dict)
            or set(descriptor) != {"path", "sha256"}
            or not isinstance(descriptor["path"], str)
        ):
            raise ValueError(f"0verse target snapshot {name} descriptor is invalid")
        relative = Path(descriptor["path"])
        _safe_parts(relative, f"0verse target snapshot {name}")
        if relative in retained:
            raise ValueError("0verse target snapshot source paths collide")
        retained[relative] = _read_artifact_under(root, relative, f"0verse target snapshot {name}")
    return snapshot_bytes, retained


def _temporary_directory_at(parent: int, prefix: str) -> str:
    for _ in range(128):
        name = f".{prefix}.tmp-{secrets.token_hex(12)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
            return name
        except FileExistsError:
            continue
    raise FileExistsError("could not reserve a unique admission staging directory")


def _exchange_directories(parent: int, left: str, right: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    left_bytes = os.fsencode(left)
    right_bytes = os.fsencode(right)
    if sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        renameatx_np = libc.renameatx_np
        renameatx_np.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameatx_np.restype = ctypes.c_int
        result = renameatx_np(parent, left_bytes, parent, right_bytes, 0x00000002)
    elif hasattr(libc, "renameat2"):
        renameat2 = libc.renameat2
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(parent, left_bytes, parent, right_bytes, 2)
    else:
        raise ValueError("atomic directory exchange is unsupported")
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), right)


def _identity(info: os.stat_result) -> tuple[int, int]:
    return (info.st_dev, info.st_ino)


def _named_identity(parent: int, name: str) -> tuple[int, int]:
    return _identity(os.stat(name, dir_fd=parent, follow_symlinks=False))


def _remove_tree_at(parent: int, name: str, expected: tuple[int, int]) -> bool:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    directory = os.open(name, flags, dir_fd=parent)
    try:
        if _identity(os.fstat(directory)) != expected:
            return False
        entries = _LIST_DIRECTORY(directory)
        for entry in entries:
            if entry in {"", ".", ".."} or "/" in entry or "\0" in entry:
                raise ValueError("admission staging directory contains an unsafe entry name")
            info = os.stat(entry, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                _remove_tree_at(directory, entry, _identity(info))
            else:
                _UNLINK(entry, dir_fd=directory)
    finally:
        os.close(directory)
    if _named_identity(parent, name) != expected:
        return False
    os.rmdir(name, dir_fd=parent)
    return True


def _signed_admissions(
    events: tuple[research_feedback.VerifiedFeedbackEvent, ...],
    target_snapshot_digest: str,
    evidence_principal: str,
    evidence_allowed_signers: str | Path,
    signer: ResearchAdmissionSigner,
    check_boundary: BoundaryCheck,
) -> list[tuple[str, str, dict[str, Any], dict[str, Any]]]:
    admissions: list[tuple[str, str, dict[str, Any], dict[str, Any]]] = []
    for event in events:
        record = event.record
        if record.get("synthetic") is not False:
            raise ValueError("synthetic events cannot produce research admissions")
        verdict = record.get("verdict")
        outcome = (
            "confirmed" if verdict == "confirmed" else "refuted" if verdict == "pruned" else None
        )
        if outcome is None:
            raise ValueError("unresolved events cannot produce research admissions")
        event_id = str(record["event_id"])
        observed_at = _canonical_observed_at(record.get("created_at"))
        pov_digest = (
            f"sha256:{record['pov']['sha256']}" if record["pov"].get("sha256") else _sha256(b"")
        )
        receipt_body = {
            "schemaVersion": 1,
            "contract": "0verse-scientific-event-verification-v2",
            "eventId": event_id,
            "sourceRecordDigest": event.source_artifact_digest,
            "oracleReceiptDigest": event.verification_receipt_digest,
            "oracleEvidenceDigest": record["oracle_evidence"]["sha256"],
            "povSha256": pov_digest,
            "oracle": record["oracle"],
            "verdict": verdict,
            "outcome": outcome,
            "targetSnapshotDigest": target_snapshot_digest,
            "observedAt": observed_at,
            "retainedInProductionLedger": True,
            "authority": dict(_AUTHORITY),
        }
        verification_digest = _sha256(_canonical(receipt_body) + b"\n")
        body = {
            "schemaVersion": 1,
            "contract": "0research-evidence-admission-v1",
            "kind": "zeroverse_scientific_event",
            "project": "0verse",
            "outcome": outcome,
            "sourceArtifactDigest": event_id,
            "verificationReceiptDigest": verification_digest,
            "targetSnapshotDigest": target_snapshot_digest,
            "observedAt": observed_at,
            "principal": evidence_principal,
            "synthetic": False,
            "authority": dict(_AUTHORITY),
        }
        material = _canonical(body)
        check_boundary("before evidence signing")
        signature = signer(material, evidence_principal, _ADMISSION_NAMESPACE)
        check_boundary("during evidence signing")
        verify_ssh_signature(
            material,
            signature,
            identity=evidence_principal,
            namespace=_ADMISSION_NAMESPACE,
            allowed_signers=evidence_allowed_signers,
            label="0verse scientific evidence admission",
            require_trusted_policy=True,
            inherit_environment=False,
        )
        check_boundary("during evidence verification")
        admission = {**body, "signatureSsh": signature}
        admission_digest = _sha256(material + b"\n")
        admissions.append((admission_digest, event_id, receipt_body, admission))
    admissions.sort(key=lambda item: item[0])
    return admissions


def issue_feedback_admissions(
    *,
    projection_path: str | Path,
    bundle_path: str | Path,
    output_root: str | Path,
    target_snapshot_path: str | Path,
    admission_output: str | Path,
    oracle_allowed_signers: str | Path,
    target_snapshot_allowed_signers: str | Path,
    evidence_allowed_signers: str | Path,
    evidence_principal: str,
    signer: ResearchAdmissionSigner,
) -> tuple[dict[str, Any], ...]:
    """Reverify, sign, and atomically retain one admission per ledger event."""
    if flywheel._env_truthy("ZEROVERSE_EVALUATION"):
        raise ValueError("evaluation mode cannot produce research admissions")
    if _PRINCIPAL.fullmatch(evidence_principal) is None:
        raise ValueError("0verse evidence principal is unsafe")
    source_policies = {
        "oracle": oracle_allowed_signers,
        "target-snapshot": target_snapshot_allowed_signers,
        "evidence": evidence_allowed_signers,
    }
    _validate_policy_separation(source_policies)
    _require_plain_ed25519_policy(evidence_allowed_signers)
    ledger_path = _production_ledger()
    output = Path(admission_output).absolute()
    parent = output.parent
    output_name = output.name
    if output_name in {"", ".", ".."} or Path(output_name).name != output_name:
        raise ValueError("0verse admission output name is unsafe")
    if (
        output.exists()
        or parent.is_symlink()
        or not parent.is_dir()
        or parent.resolve(strict=True) != parent
    ):
        raise ValueError("0verse admission output or parent is unsafe")
    parent_info = parent.stat()
    if parent_info.st_uid != os.getuid() or parent_info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("0verse admission parent must be owner-only")
    parent_descriptor = os.open(
        parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    pinned_parent = os.fstat(parent_descriptor)
    if (pinned_parent.st_dev, pinned_parent.st_ino) != (
        parent_info.st_dev,
        parent_info.st_ino,
    ):
        os.close(parent_descriptor)
        raise ValueError("0verse admission parent changed while opened")
    temporary_name: str | None = None
    stage_descriptor: int | None = None
    reservation_descriptor: int | None = None
    reservation_identity: tuple[int, int] | None = None
    temporary_identity: tuple[int, int] | None = None
    published = False
    admissions: list[tuple[str, str, dict[str, Any], dict[str, Any]]] = []
    try:
        os.mkdir(output_name, 0o700, dir_fd=parent_descriptor)
        reservation_descriptor = os.open(
            output_name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
        reservation_identity = _identity(os.fstat(reservation_descriptor))
        temporary_name = _temporary_directory_at(parent_descriptor, output_name)
        staging_name = temporary_name
        stage_descriptor = os.open(
            staging_name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
        temporary_identity = _identity(os.fstat(stage_descriptor))

        def check_reservation(label: str) -> None:
            if (
                _named_identity(parent_descriptor, output_name) != reservation_identity
                or _named_identity(parent_descriptor, staging_name) != temporary_identity
            ):
                raise ValueError(f"0verse admission reservation changed {label}")

        projection_bytes = _read(Path(projection_path).absolute(), "0verse feedback projection")
        _, target_sources = _target_snapshot_sources(target_snapshot_path)
        policy_bytes = {
            role: _read(Path(value).absolute(), f"{role} signer policy", 1024 * 1024)
            for role, value in source_policies.items()
        }
        fixed_source_payloads = [projection_bytes, *target_sources.values(), *policy_bytes.values()]
        fixed_source_bytes = sum(map(len, fixed_source_payloads))
        if (
            len(fixed_source_payloads) >= _MAX_PROVENANCE_FILES
            or fixed_source_bytes >= _MAX_PROVENANCE_BYTES
        ):
            raise ValueError("0verse retained provenance exceeds its file or byte limit")
        captured_root, captured_output_tree_digest, captured_files = _sealed_provenance_tree(
            output_root,
            max_files=_MAX_PROVENANCE_FILES - len(fixed_source_payloads),
            max_total_bytes=_MAX_PROVENANCE_BYTES - fixed_source_bytes,
        )
        requested_bundle = Path(bundle_path).absolute()
        try:
            bundle_relative = requested_bundle.relative_to(captured_root)
        except ValueError as exc:
            raise ValueError("bundle must be inside the trusted output root") from exc
        if requested_bundle not in captured_files:
            raise ValueError("bundle must be retained in the sealed output tree")
        retained_payloads = [*fixed_source_payloads, *captured_files.values()]
        _write_bytes_under(
            stage_descriptor,
            Path("payload/source/projection.json"),
            projection_bytes,
            "retained projection",
        )
        for source_file, payload in sorted(
            captured_files.items(), key=lambda item: item[0].as_posix()
        ):
            relative = source_file.relative_to(captured_root)
            _write_bytes_under(
                stage_descriptor,
                Path("payload/source/output") / relative,
                payload,
                "retained output",
            )
        for relative, payload in sorted(
            target_sources.items(), key=lambda item: item[0].as_posix()
        ):
            _write_bytes_under(
                stage_descriptor,
                Path("payload/source/target") / relative,
                payload,
                "retained target snapshot",
            )
        for role, payload in sorted(policy_bytes.items()):
            _write_bytes_under(
                stage_descriptor,
                Path("payload/source/policies") / f"{role}.allowed_signers",
                payload,
                "retained signer policy",
            )

        stage_path = parent / staging_name
        payload_path = stage_path / "payload"
        source_path = payload_path / "source"
        retained_projection = source_path / "projection.json"
        retained_output = source_path / "output"
        retained_bundle = retained_output / bundle_relative
        retained_target = source_path / "target" / "snapshot.json"
        retained_policies: dict[str, str | Path] = {
            role: source_path / "policies" / f"{role}.allowed_signers" for role in source_policies
        }
        _validate_policy_separation(retained_policies)
        preledger_source_tree_digest = _sealed_provenance_tree(source_path)[1]

        def check_preledger_boundary(label: str) -> None:
            check_reservation(label)
            if _sealed_provenance_tree(source_path)[1] != preledger_source_tree_digest:
                raise ValueError(f"0verse retained source tree changed {label}")

        check_preledger_boundary("before native verification")
        events, projection_digest, bundle_digest, output_tree_digest = (
            research_feedback.verify_feedback_events(
                projection_path=retained_projection,
                bundle_path=retained_bundle,
                output_root=retained_output,
                oracle_allowed_signers=retained_policies["oracle"],
            )
        )
        check_preledger_boundary("during native verification")
        if output_tree_digest != captured_output_tree_digest:
            raise ValueError("retained 0verse output tree changed while copied")
        event_ids = tuple(sorted(str(event.record["event_id"]) for event in events))
        package_file_count = len(retained_payloads) + 2 + (2 * len(events)) + 1
        if package_file_count > _MAX_PROVENANCE_FILES:
            raise ValueError("0verse retained provenance exceeds its package file limit")
        check_preledger_boundary("before target snapshot verification")
        target_snapshot_digest = _target_snapshot(
            retained_target, event_ids, retained_policies["target-snapshot"]
        )
        check_preledger_boundary("during target snapshot verification")

        with research_feedback.locked_retained_feedback_events(ledger_path) as locked_rows:
            retained_before_commit = _indexed_retained_events(locked_rows)
            ledger_snapshot_bytes = _read(
                ledger_path, "locked production learning ledger", 32 * 1024 * 1024
            )
            raw_rows: list[dict[str, Any]] = []
            raw_membership: dict[str, tuple[int, bytes]] = {}
            for ordinal, line in enumerate(ledger_snapshot_bytes.splitlines(keepends=True)):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValueError("locked production ledger is not valid NDJSON") from exc
                if not isinstance(row, dict) or not isinstance(row.get("event_id"), str):
                    raise ValueError("locked production ledger row identity is invalid")
                event_id = str(row["event_id"])
                if event_id in raw_membership:
                    raise ValueError("locked production ledger contains duplicate event identities")
                raw_rows.append(row)
                raw_membership[event_id] = (ordinal, line)
            if tuple(_canonical(item) for item in raw_rows) != tuple(
                _canonical(item) for item in locked_rows
            ):
                raise ValueError("locked production ledger bytes drift from parsed rows")
            selected_rows: list[dict[str, Any]] = []
            membership: list[dict[str, Any]] = []
            for event in events:
                event_id = str(event.record["event_id"])
                stored = retained_before_commit.get(event_id)
                if stored is None or _canonical(_without_transport(stored)) != _canonical(
                    _without_transport(event.record)
                ):
                    raise ValueError("production ledger changed before admission retention")
                selected_rows.append(stored)
                ordinal, raw_line = raw_membership[event_id]
                membership.append(
                    {
                        "eventId": event_id,
                        "lineOrdinal": ordinal,
                        "rawLineDigest": _sha256(raw_line),
                    }
                )
            selected_rows.sort(key=lambda item: str(item["event_id"]))
            membership.sort(key=lambda item: str(item["eventId"]))
            ledger_membership_bytes = (
                json.dumps(membership, sort_keys=True, indent=2).encode() + b"\n"
            )
            if (
                sum(map(len, retained_payloads))
                + len(ledger_snapshot_bytes)
                + len(ledger_membership_bytes)
                > _MAX_PROVENANCE_BYTES
            ):
                raise ValueError("0verse retained provenance exceeds its total byte limit")
            _write_bytes_under(
                stage_descriptor,
                Path("payload/source/production-ledger.ndjson"),
                ledger_snapshot_bytes,
                "retained production ledger",
            )
            _write_bytes_under(
                stage_descriptor,
                Path("payload/source/ledger-membership.json"),
                ledger_membership_bytes,
                "retained ledger membership",
            )
            source_tree_digest = _sealed_provenance_tree(source_path)[1]

            def check_authority_boundary(label: str) -> None:
                check_reservation(label)
                if _sealed_provenance_tree(source_path)[1] != source_tree_digest:
                    raise ValueError(f"0verse retained source tree changed {label}")

            admissions = _signed_admissions(
                events,
                target_snapshot_digest,
                evidence_principal,
                retained_policies["evidence"],
                signer,
                check_authority_boundary,
            )
            refs: list[dict[str, str]] = []
            rendered_admissions: list[tuple[str, bytes, str, bytes]] = []
            for admission_digest, event_id, receipt, admission in admissions:
                stem = admission_digest[7:]
                receipt_path = f"payload/{stem}.verification.json"
                admission_path = f"payload/{stem}.admission.json"
                receipt_bytes = json.dumps(receipt, sort_keys=True, indent=2).encode() + b"\n"
                admission_bytes = json.dumps(admission, sort_keys=True, indent=2).encode() + b"\n"
                rendered_admissions.append(
                    (receipt_path, receipt_bytes, admission_path, admission_bytes)
                )
                refs.append(
                    {
                        "admissionDigest": admission_digest,
                        "admissionSignedArtifactDigest": _sha256(admission_bytes),
                        "eventId": event_id,
                        "verificationReceiptDigest": str(admission["verificationReceiptDigest"]),
                        "verificationSignedArtifactDigest": _sha256(receipt_bytes),
                        "admissionPath": admission_path,
                        "verificationPath": receipt_path,
                    }
                )
            generated_payload_bytes = sum(
                len(receipt_bytes) + len(admission_bytes)
                for _, receipt_bytes, _, admission_bytes in rendered_admissions
            )
            if (
                sum(map(len, retained_payloads))
                + len(ledger_snapshot_bytes)
                + len(ledger_membership_bytes)
                + generated_payload_bytes
                > _MAX_PROVENANCE_BYTES
            ):
                raise ValueError("0verse retained provenance exceeds its package byte limit")
            for receipt_path, receipt_bytes, admission_path, admission_bytes in rendered_admissions:
                _write_bytes_under(
                    stage_descriptor,
                    Path(receipt_path),
                    receipt_bytes,
                    "retained 0verse verification receipt",
                )
                _write_bytes_under(
                    stage_descriptor,
                    Path(admission_path),
                    admission_bytes,
                    "retained signed 0verse admission",
                )
            check_authority_boundary("before retained replay")
            replayed, replayed_projection, replayed_bundle, replayed_tree = (
                research_feedback.verify_feedback_events(
                    projection_path=retained_projection,
                    bundle_path=retained_bundle,
                    output_root=retained_output,
                    oracle_allowed_signers=retained_policies["oracle"],
                )
            )
            check_authority_boundary("during retained replay")
            replayed_target = _target_snapshot(
                retained_target, event_ids, retained_policies["target-snapshot"]
            )
            check_authority_boundary("during retained target replay")
            if (
                tuple(_canonical(item.record) for item in replayed)
                != tuple(_canonical(item.record) for item in events)
                or (replayed_projection, replayed_bundle, replayed_tree)
                != (projection_digest, bundle_digest, output_tree_digest)
                or replayed_target != target_snapshot_digest
                or _read(source_path / "production-ledger.ndjson", "retained production ledger")
                != ledger_snapshot_bytes
                or _read(source_path / "ledger-membership.json", "retained ledger membership")
                != ledger_membership_bytes
            ):
                raise ValueError("retained 0verse provenance does not replay exactly")
            if (
                _read(ledger_path, "production ledger after signing", 32 * 1024 * 1024)
                != ledger_snapshot_bytes
            ):
                raise ValueError("production ledger changed during admission signing")
            for ref in refs:
                if (
                    _sha256(
                        _read(stage_path / ref["admissionPath"], "retained signed 0verse admission")
                    )
                    != ref["admissionSignedArtifactDigest"]
                    or _sha256(
                        _read(
                            stage_path / ref["verificationPath"],
                            "retained 0verse verification receipt",
                        )
                    )
                    != ref["verificationSignedArtifactDigest"]
                ):
                    raise ValueError("retained 0verse admission artifacts changed before commit")
            payload_tree_digest = _sealed_provenance_tree(payload_path)[1]
            manifest_body = {
                "schemaVersion": 2,
                "contract": "0verse-research-admission-bundle-v2",
                "principal": evidence_principal,
                "projectionDigest": projection_digest,
                "learningBundleDigest": bundle_digest,
                "outputTreeDigest": output_tree_digest,
                "targetSnapshotDigest": target_snapshot_digest,
                "sourceTreeDigest": source_tree_digest,
                "payloadTreeDigest": payload_tree_digest,
                "ledgerSnapshotDigest": _sha256(ledger_snapshot_bytes),
                "ledgerMembershipDigest": _sha256(ledger_membership_bytes),
                "policyDigests": {
                    role: _sha256(payload) for role, payload in sorted(policy_bytes.items())
                },
                "sourcePaths": {
                    "projection": "payload/source/projection.json",
                    "output": "payload/source/output",
                    "bundle": (Path("payload/source/output") / bundle_relative).as_posix(),
                    "targetSnapshot": "payload/source/target/snapshot.json",
                    "productionLedger": "payload/source/production-ledger.ndjson",
                    "ledgerMembership": "payload/source/ledger-membership.json",
                    "policies": {
                        role: f"payload/source/policies/{role}.allowed_signers"
                        for role in sorted(source_policies)
                    },
                },
                "admissions": refs,
                "authority": dict(_AUTHORITY),
            }
            manifest_material = _canonical(manifest_body)
            check_authority_boundary("before package-root signing")
            manifest_signature = signer(manifest_material, evidence_principal, _PACKAGE_NAMESPACE)
            check_authority_boundary("during package-root signing")
            verify_ssh_signature(
                manifest_material,
                manifest_signature,
                identity=evidence_principal,
                namespace=_PACKAGE_NAMESPACE,
                allowed_signers=retained_policies["evidence"],
                label="0verse research admission package root",
                require_trusted_policy=True,
                inherit_environment=False,
            )
            check_authority_boundary("during package-root verification")
            manifest = {**manifest_body, "signatureSsh": manifest_signature}
            manifest_bytes = _canonical(manifest) + b"\n"
            if (
                sum(map(len, retained_payloads))
                + len(ledger_snapshot_bytes)
                + len(ledger_membership_bytes)
                + generated_payload_bytes
                + len(manifest_bytes)
                > _MAX_PROVENANCE_BYTES
            ):
                raise ValueError("0verse retained provenance exceeds its package byte limit")
            _write_bytes_exclusive_at(stage_descriptor, "manifest.json", manifest_bytes)
            os.fsync(stage_descriptor)
            check_authority_boundary("before commit")
            if (
                _sealed_provenance_tree(payload_path)[1] != payload_tree_digest
                or _read(stage_path / "manifest.json", "retained admission manifest")
                != manifest_bytes
            ):
                raise ValueError("0verse admission payload or manifest changed before commit")
            _exchange_directories(parent_descriptor, temporary_name, output_name)
            if (
                _named_identity(parent_descriptor, output_name) != temporary_identity
                or _named_identity(parent_descriptor, temporary_name) != reservation_identity
            ):
                with suppress(OSError):
                    _exchange_directories(parent_descriptor, temporary_name, output_name)
                raise ValueError("0verse admission exchange identity mismatch")
            published = True
            temporary_identity = reservation_identity
            os.fsync(parent_descriptor)
            if not _remove_tree_at(parent_descriptor, temporary_name, temporary_identity):
                raise ValueError("0verse admission reservation changed during cleanup")
            temporary_name = None
            os.fsync(parent_descriptor)
    except BaseException:
        if temporary_name is not None and temporary_identity is not None:
            with suppress(OSError):
                _remove_tree_at(parent_descriptor, temporary_name, temporary_identity)
        if reservation_identity is not None and not published:
            with suppress(OSError):
                _remove_tree_at(parent_descriptor, output_name, reservation_identity)
        raise
    finally:
        if stage_descriptor is not None:
            os.close(stage_descriptor)
        if reservation_descriptor is not None:
            os.close(reservation_descriptor)
        os.close(parent_descriptor)
    verify_feedback_admission_bundle(output, evidence_allowed_signers=evidence_allowed_signers)
    return tuple(item[3] for item in admissions)


def verify_feedback_admission_bundle(
    bundle_path: str | Path,
    *,
    evidence_allowed_signers: str | Path,
) -> VerifiedFeedbackAdmissionBundle:
    """Authenticate a retained package root and its complete bounded payload."""
    root = Path(bundle_path).absolute()
    if root.is_symlink() or root.resolve(strict=True) != root or not root.is_dir():
        raise ValueError("0verse admission bundle path is unsafe")
    if sorted(path.name for path in root.iterdir()) != ["manifest.json", "payload"]:
        raise ValueError("0verse admission bundle has unexpected top-level entries")
    manifest_bytes = _read(root / "manifest.json", "0verse admission manifest")
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("0verse admission manifest is not UTF-8 JSON") from exc
    if not isinstance(manifest, dict) or set(manifest) != {
        "schemaVersion",
        "contract",
        "principal",
        "projectionDigest",
        "learningBundleDigest",
        "outputTreeDigest",
        "targetSnapshotDigest",
        "sourceTreeDigest",
        "payloadTreeDigest",
        "ledgerSnapshotDigest",
        "ledgerMembershipDigest",
        "policyDigests",
        "sourcePaths",
        "admissions",
        "authority",
        "signatureSsh",
    }:
        raise ValueError("0verse admission manifest fields are invalid")
    if (
        manifest.get("schemaVersion") != 2
        or manifest.get("contract") != "0verse-research-admission-bundle-v2"
        or manifest.get("authority") != _AUTHORITY
        or not isinstance(manifest.get("principal"), str)
        or _PRINCIPAL.fullmatch(str(manifest["principal"])) is None
        or not isinstance(manifest.get("signatureSsh"), str)
    ):
        raise ValueError("0verse admission manifest contract is invalid")
    if manifest_bytes != _canonical(manifest) + b"\n":
        raise ValueError("0verse admission manifest encoding is not canonical")
    body = {key: value for key, value in manifest.items() if key != "signatureSsh"}
    verify_ssh_signature(
        _canonical(body),
        str(manifest["signatureSsh"]),
        identity=str(manifest["principal"]),
        namespace=_PACKAGE_NAMESPACE,
        allowed_signers=evidence_allowed_signers,
        label="0verse research admission package root",
        require_trusted_policy=True,
        inherit_environment=False,
    )
    payload = root / "payload"
    _, payload_digest, payload_files = _sealed_provenance_tree(
        payload,
        max_files=_MAX_PROVENANCE_FILES - 1,
        max_total_bytes=_MAX_PROVENANCE_BYTES - len(manifest_bytes),
    )
    if len(payload_files) + 1 > _MAX_PROVENANCE_FILES:
        raise ValueError("0verse admission bundle exceeds its package file limit")
    if payload_digest != manifest.get("payloadTreeDigest"):
        raise ValueError("0verse admission bundle payload root is invalid")
    source_paths = manifest.get("sourcePaths")
    policy_digests = manifest.get("policyDigests")
    if not isinstance(source_paths, dict) or not isinstance(policy_digests, dict):
        raise ValueError("0verse admission manifest source policy fields are invalid")
    policies = source_paths.get("policies")
    if not isinstance(policies, dict) or policies.get("evidence") != (
        "payload/source/policies/evidence.allowed_signers"
    ):
        raise ValueError("0verse admission evidence policy path is invalid")
    retained_policy = payload_files.get(
        payload / "source" / "policies" / "evidence.allowed_signers"
    )
    trusted_policy = _read(
        Path(evidence_allowed_signers).absolute(), "trusted evidence signer policy", 1024 * 1024
    )
    if (
        retained_policy is None
        or retained_policy != trusted_policy
        or policy_digests.get("evidence") != _sha256(retained_policy)
    ):
        raise ValueError("0verse admission retained evidence policy is not trusted")
    captured = {
        "manifest.json": manifest_bytes,
        **{path.relative_to(root).as_posix(): payload for path, payload in payload_files.items()},
    }
    return VerifiedFeedbackAdmissionBundle(
        manifest=manifest,
        _artifacts=MappingProxyType(captured),
    )

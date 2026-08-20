"""Exclusively publish one signed, immutable Windows IOCTL rank-result pair."""

from __future__ import annotations

import base64
import ctypes
import errno
import hashlib
import json
import os
import re
import resource
import secrets
import select
import signal
import stat
import sys
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import pe_symbols as pe_symbols_module
from . import ssh_authority_commitment as authority_commitment_module
from . import ssh_authorization as authorization_module
from . import windows_byo_corpus as byo_module
from . import windows_ioctl_boundary as boundary_module
from . import windows_ioctl_rank as rank_helpers_module
from . import windows_ioctl_real_eval as rank_eval_module
from . import windows_ioctl_real_rank as real_rank_module
from . import windows_variant as variant_module
from .ssh_authorization import canonical_signed_material, sign_ssh_material
from .windows_ioctl_rank import _read_bounded, _relative_file
from .windows_ioctl_real_eval import (
    DEFAULT_ALLOWED_SIGNERS as LABEL_ALLOWED_SIGNERS,
)
from .windows_ioctl_real_eval import (
    DEFAULT_RANK_RECEIPT_ALLOWED_SIGNERS,
    RANK_RECEIPT_NAMESPACE,
    RANK_RECEIPT_NAMESPACE_V2,
    RANK_RECEIPT_PROOF_LIMIT,
    RANK_RECEIPT_PROOF_LIMIT_V2,
    RANK_RECEIPT_VERSION,
    RANK_RECEIPT_VERSION_V2,
    _validate_rank_receipt,
    _validate_rank_result,
)
from .windows_ioctl_real_rank import (
    BYO_BINDING_FIELDS,
    RESULT_VERSION_V2,
    RESULT_VERSION_V3,
    _timestamp,
    rank_windows_ioctl_real_static,
)

PUBLISHER_CONFIG = Path("/etc/0verse/windows-ioctl-rank-result-publisher.json")
PUBLISHER_SIGNING_KEY = Path("/etc/0verse/windows-ioctl-rank-result.key")
PUBLISHER_SSH_KEYGEN = Path("/usr/bin/ssh-keygen")
PUBLISHER_ALLOWED_SIGNERS = DEFAULT_RANK_RECEIPT_ALLOWED_SIGNERS
PUBLISHER_LABEL_ALLOWED_SIGNERS = LABEL_ALLOWED_SIGNERS
PUBLISHER_SPOOL_ROOT = Path("/var/lib/0verse/windows-ioctl-rank-results")
PUBLISHER_REPLAY_DIRECTORY = ".replays"
PUBLISHER_PRINCIPAL = "windows-ioctl-rank-result@0verse"
PUBLISHER_CONFIG_VERSION = "0verse.windows-ioctl-rank-result-publisher-config/v1"
PUBLISHER_SERVICE_UID = 0
PUBLISHER_RANK_TIMEOUT_SECONDS = 600.0

RESULT_NAME = "result.json"
RECEIPT_NAME = "receipt.json"
_BUNDLE_NAME = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?")
_TOKEN = re.compile(r"[A-Za-z0-9_.:@/-]{1,128}")
_MAX_RESULT = 16 * 1024 * 1024
_MAX_RECEIPT = 1024 * 1024
_MAX_CONFIG = 64 * 1024
_RENAME_NOREPLACE = 1
_RENAME_EXCL = 0x00000004


def publish_windows_ioctl_rank_result(
    campaign_path: str | Path,
    bundle_name: str,
) -> dict[str, object]:
    """Run the static ranker once and atomically publish its exact signed bytes."""
    if _BUNDLE_NAME.fullmatch(bundle_name) is None:
        raise ValueError("rank-result bundle name is unsafe")
    _require_service_custody()
    config_bytes = _read_custodied_file(PUBLISHER_CONFIG, _MAX_CONFIG, "publisher config")
    config = _load_config(config_bytes)
    _check_custodied_file(PUBLISHER_SIGNING_KEY, 64 * 1024, "publisher signing key", private=True)
    ssh_keygen_sha256 = _custodied_file_sha256(
        PUBLISHER_SSH_KEYGEN, 16 * 1024 * 1024, "fixed ssh-keygen"
    )
    receipt_policy_bytes = _read_custodied_file(
        PUBLISHER_ALLOWED_SIGNERS, 1024 * 1024, "publisher allowed-signers policy"
    )
    label_policy_bytes = _read_custodied_file(
        PUBLISHER_LABEL_ALLOWED_SIGNERS, 1024 * 1024, "label allowed-signers policy"
    )
    receipt_principal, receipt_key_commitment = _policy_identity_and_commitment(
        receipt_policy_bytes, "publisher allowed-signers policy"
    )
    label_principal, label_key_commitment = _policy_identity_and_commitment(
        label_policy_bytes, "label allowed-signers policy"
    )
    if receipt_key_commitment == label_key_commitment or label_principal == PUBLISHER_PRINCIPAL:
        raise ValueError("rank-result publisher and label authority keys must differ")
    if receipt_principal != PUBLISHER_PRINCIPAL:
        raise ValueError("publisher policy does not contain the fixed principal")
    executable_sha256 = _ranker_executable_sha256()

    spool_fd = _open_custodied_directory(PUBLISHER_SPOOL_ROOT, "publisher spool root")
    replay_fd = -1
    staging_fd = -1
    staging_name = f".stage-{secrets.token_hex(16)}"
    renamed = False
    try:
        replay_fd = _open_directory_at(spool_fd, PUBLISHER_REPLAY_DIRECTORY, "replay directory")
        _require_absent_at(spool_fd, bundle_name)

        started_at = datetime.now(UTC)
        result = _rank_unprivileged(
            campaign_path,
            rank_uid=int(config["rank_worker_uid"]),
            rank_gid=int(config["rank_worker_gid"]),
        )
        completed_at = datetime.now(UTC)
        _validate_rank_result(result)
        if result["schema_version"] not in {RESULT_VERSION_V2, RESULT_VERSION_V3}:
            raise ValueError("publisher accepts only blinded v2/v3 rank results")
        if (
            result["admission_principal"] == PUBLISHER_PRINCIPAL
            or result["admission_authority_key_commitment"] == receipt_key_commitment
        ):
            raise ValueError("rank-result publisher and admission authorities must differ")
        if result["schema_version"] == RESULT_VERSION_V3 and (
            result["byo_curator_principal"] == PUBLISHER_PRINCIPAL
            or result["byo_curator_authority_key_commitment"] == receipt_key_commitment
        ):
            raise ValueError("rank-result publisher and BYO curator authorities must differ")

        replay_name = _replay_name(result)
        _reserve_replay(replay_fd, replay_name, bundle_name)
        os.fsync(replay_fd)
        os.fsync(spool_fd)
        admission_expires = _verified_admission_expiry(Path(campaign_path), result)
        if completed_at > admission_expires:
            raise ValueError("rank run completed after the signed admission expired")
        if _read_custodied_file(PUBLISHER_CONFIG, _MAX_CONFIG, "publisher config") != config_bytes:
            raise ValueError("publisher configuration changed during rank execution")
        if _ranker_executable_sha256() != executable_sha256:
            raise ValueError("ranker executable manifest changed during rank execution")
        signing_key_sha256 = _custodied_file_sha256(
            PUBLISHER_SIGNING_KEY, 64 * 1024, "publisher signing key", private=True
        )
        _require_authority_material_unchanged(
            receipt_policy_bytes,
            label_policy_bytes,
            signing_key_sha256,
            ssh_keygen_sha256,
        )

        os.mkdir(staging_name, mode=0o700, dir_fd=spool_fd)
        staging_fd = _open_directory_at(spool_fd, staging_name, "publisher staging directory")
        result_bytes = _canonical_json_bytes(result)
        _write_new_file(staging_fd, RESULT_NAME, result_bytes, _MAX_RESULT)
        retained_result_bytes = _read_file_at(staging_fd, RESULT_NAME, _MAX_RESULT)
        if retained_result_bytes != result_bytes:
            raise ValueError("published rank-result bytes changed before receipt signing")
        retained_result = _load_object(retained_result_bytes, "retained rank result")
        if retained_result != result:
            raise ValueError("retained rank result differs from the ranker output")
        _validate_rank_result(retained_result)

        issued_at = datetime.now(UTC)
        receipt = _build_receipt(
            retained_result,
            retained_result_bytes,
            config=config,
            config_sha256=hashlib.sha256(config_bytes).hexdigest(),
            executable_sha256=executable_sha256,
            started_at=started_at,
            completed_at=completed_at,
            issued_at=issued_at,
        )
        receipt["signature_ssh"] = sign_ssh_material(
            canonical_signed_material(receipt),
            signing_key=PUBLISHER_SIGNING_KEY,
            namespace=(
                RANK_RECEIPT_NAMESPACE_V2
                if result["schema_version"] == RESULT_VERSION_V3
                else RANK_RECEIPT_NAMESPACE
            ),
            label="Windows IOCTL rank-result receipt",
            ssh_keygen=PUBLISHER_SSH_KEYGEN,
            inherit_environment=False,
        )
        _require_authority_material_unchanged(
            receipt_policy_bytes,
            label_policy_bytes,
            signing_key_sha256,
            ssh_keygen_sha256,
        )
        receipt_bytes = _canonical_json_bytes(receipt)
        _write_new_file(staging_fd, RECEIPT_NAME, receipt_bytes, _MAX_RECEIPT)
        retained_receipt_bytes = _read_file_at(staging_fd, RECEIPT_NAME, _MAX_RECEIPT)
        if retained_receipt_bytes != receipt_bytes:
            raise ValueError("published rank-result receipt changed before publication")
        retained_receipt = _load_object(retained_receipt_bytes, "retained rank-result receipt")
        verified_principal, verified_commitment = _validate_rank_receipt(
            retained_receipt,
            result=retained_result,
            rank_bytes=retained_result_bytes,
            policy=PUBLISHER_ALLOWED_SIGNERS,
            require_trusted_policy=True,
            now=datetime.now(UTC),
            verification_ssh_keygen=PUBLISHER_SSH_KEYGEN,
            verification_inherit_environment=False,
        )
        _require_authority_material_unchanged(
            receipt_policy_bytes,
            label_policy_bytes,
            signing_key_sha256,
            ssh_keygen_sha256,
        )
        if (
            verified_principal != receipt_principal
            or verified_commitment != receipt_key_commitment
            or verified_principal == result["admission_principal"]
            or verified_commitment == result["admission_authority_key_commitment"]
            or verified_principal == label_principal
            or verified_commitment == label_key_commitment
            or (
                result["schema_version"] == RESULT_VERSION_V3
                and (
                    verified_principal == result["byo_curator_principal"]
                    or verified_commitment
                    == result["byo_curator_authority_key_commitment"]
                )
            )
        ):
            raise ValueError("final rank-result receipt authority separation failed")
        if sorted(os.listdir(staging_fd)) != [  # noqa: PTH208  # foxguard: ignore[py/no-path-traversal]
            RECEIPT_NAME,
            RESULT_NAME,
        ]:
            raise ValueError("publisher staging directory contains unexpected entries")
        os.fsync(staging_fd)
        os.close(staging_fd)
        staging_fd = -1
        _require_path_matches_directory(PUBLISHER_SPOOL_ROOT, spool_fd)
        _rename_exclusive(spool_fd, staging_name, bundle_name)
        renamed = True
        os.fsync(spool_fd)
        _require_path_matches_directory(PUBLISHER_SPOOL_ROOT, spool_fd)
        return {
            "bundle_name": bundle_name,
            "bundle_path": str(PUBLISHER_SPOOL_ROOT / bundle_name),
            "result_path": str(PUBLISHER_SPOOL_ROOT / bundle_name / RESULT_NAME),
            "receipt_path": str(PUBLISHER_SPOOL_ROOT / bundle_name / RECEIPT_NAME),
            "rank_result_sha256": hashlib.sha256(retained_result_bytes).hexdigest(),
            "rank_receipt_sha256": hashlib.sha256(retained_receipt_bytes).hexdigest(),
            "admission_sha256": result["admission_sha256"],
            "analysis_run_id": result["analysis_run_id"],
            "private_bundle_verified": (
                result["private_bundle_verified"]
                if result["schema_version"] == RESULT_VERSION_V3
                else False
            ),
            "execution_authorized": False,
            "redistribution": False,
        }
    finally:
        if staging_fd >= 0:
            os.close(staging_fd)
        if not renamed:
            _remove_staging(spool_fd, staging_name)
        if replay_fd >= 0:
            os.close(replay_fd)
        os.close(spool_fd)


def _build_receipt(
    result: dict[str, Any],
    result_bytes: bytes,
    *,
    config: dict[str, str | int],
    config_sha256: str,
    executable_sha256: str,
    started_at: datetime,
    completed_at: datetime,
    issued_at: datetime,
) -> dict[str, object]:
    version = result["schema_version"]
    content_ids = [row["candidate_content_id"] for row in result["candidates"]]
    ordered_digest = hashlib.sha256(
        b"0verse-windows-ioctl-ordered-candidate-content-ids-v1\0"
        + json.dumps(content_ids, separators=(",", ":")).encode()
    ).hexdigest()
    receipt: dict[str, object] = {
        "schema_version": (
            RANK_RECEIPT_VERSION_V2 if version == RESULT_VERSION_V3 else RANK_RECEIPT_VERSION
        ),
        "producer": "zeroverse.windows-ioctl-real-rank-worker/v1",
        "purpose": "static-rank-result-observation-only",
        "rank_contract": version,
        "result_schema_version": version,
        "rank_result_sha256": hashlib.sha256(result_bytes).hexdigest(),
        "rank_result_size_bytes": len(result_bytes),
        "campaign_id": result["campaign_id"],
        "campaign_sha256": result["campaign_sha256"],
        "admission_sha256": result["admission_sha256"],
        "label_manifest_commitment_sha256": result["label_manifest_commitment_sha256"],
        "driver_sha256": result["driver_sha256"],
        "pdb_sha256": result["pdb_sha256"],
        "pdb_codeview_identity": result["pdb_codeview_identity"],
        "analysis_sha256": result["analysis_sha256"],
        "analysis_receipt_sha256": result["analysis_receipt_sha256"],
        "score_version": result["score_version"],
        "candidate_count": result["candidate_count"],
        "ordered_candidate_content_ids_sha256": ordered_digest,
        "site_count": result["site_count"],
        "site_universe_sha256": result["site_universe_sha256"],
        "analysis_run_id": result["analysis_run_id"],
        "static_only": True,
        "runtime_consumable": False,
        "execution_authorized": False,
        "device_ioctl_attempts": 0,
        "ranker_executable_sha256": executable_sha256,
        "ranker_configuration_sha256": config_sha256,
        "worker_machine_id": str(config["worker_machine_id"]),
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "issued_at": issued_at.isoformat(),
        "run_nonce": secrets.token_urlsafe(32),
        "proof_limit": (
            RANK_RECEIPT_PROOF_LIMIT_V2
            if version == RESULT_VERSION_V3
            else RANK_RECEIPT_PROOF_LIMIT
        ),
        "receipt_signer_identity": PUBLISHER_PRINCIPAL,
        "signature_ssh": "",
    }
    if version == RESULT_VERSION_V3:
        receipt.update(
            {
                **{name: result[name] for name in BYO_BINDING_FIELDS},
                "admission_expires_at": result["admission_expires_at"],
                "private_bundle_verified": False,
            }
        )
    return receipt


def _load_config(data: bytes) -> dict[str, str | int]:
    try:
        raw = json.loads(data, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("publisher config is not valid UTF-8 JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError("publisher config must be a JSON object")
    if set(raw) != {
        "schema_version",
        "worker_machine_id",
        "rank_worker_uid",
        "rank_worker_gid",
    }:
        raise ValueError("publisher config fields mismatch")
    if raw["schema_version"] != PUBLISHER_CONFIG_VERSION:
        raise ValueError("publisher config schema mismatch")
    worker = str(raw["worker_machine_id"])
    if _TOKEN.fullmatch(worker) is None:
        raise ValueError("publisher worker_machine_id is invalid")
    identity: dict[str, int] = {}
    for field in ("rank_worker_uid", "rank_worker_gid"):
        value = raw[field]
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 < value < 2**31
            or value == 65534
        ):
            raise ValueError(f"publisher {field} must name a dedicated non-nobody identity")
        identity[field] = value
    return {"worker_machine_id": worker, **identity}


def _canonical_json_bytes(raw: dict[str, Any]) -> bytes:
    return (
        json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _load_object(data: bytes, label: str) -> dict[str, Any]:
    try:
        raw = json.loads(data, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be a JSON object")
    return raw


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _replay_name(result: dict[str, Any]) -> str:
    admission = str(result["admission_sha256"])
    run = str(result["analysis_run_id"])
    if re.fullmatch(r"[0-9a-f]{64}", admission) is None or re.fullmatch(
        r"[0-9a-f]{64}", run
    ) is None:
        raise ValueError("rank result replay identity is invalid")
    return f"{admission}-{run}.reserved"


def _reserve_replay(directory_fd: int, name: str, bundle_name: str) -> None:
    data = (bundle_name + "\n").encode("ascii")
    _write_new_file(directory_fd, name, data, 256)


def _rank_unprivileged(
    campaign_path: str | Path, *, rank_uid: int, rank_gid: int
) -> dict[str, Any]:
    """Run all attacker-influenced artifact parsing after dropping root authority."""
    if not hasattr(os, "fork"):
        raise OSError(errno.ENOTSUP, "unprivileged rank child requires fork")
    stable_campaign_path = Path(campaign_path).absolute()
    read_fd, write_fd = os.pipe()
    process = os.fork()
    if process == 0:
        try:
            os.close(read_fd)
            write_fd = _isolate_child_descriptors(write_fd)
            os.umask(0o077)
            os.setsid()
            _apply_rank_child_limits(include_process_limit=rank_uid != os.geteuid())
            _set_no_new_privileges()
            if os.geteuid() == 0:
                os.setgroups([])
                os.setgid(rank_gid)
                os.setuid(rank_uid)
            if os.geteuid() != rank_uid or os.getegid() != rank_gid:
                raise PermissionError("rank child did not enter the fixed unprivileged identity")
            os.chdir("/")
            os.environ.clear()
            os.environ.update({"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"})
            result = rank_windows_ioctl_real_static(stable_campaign_path)
            payload = _canonical_json_bytes({"ok": True, "result": result})
            if len(payload) > _MAX_RESULT:
                raise ValueError("unprivileged rank child result exceeds its size limit")
            _write_all(write_fd, payload)
            os.close(write_fd)
            os._exit(0)
        except BaseException as exc:  # child must return a bounded fail-closed envelope
            try:
                payload = _canonical_json_bytes(
                    {
                        "error": f"{type(exc).__name__}: {exc}"[:512],
                        "ok": False,
                    }
                )
                _write_all(write_fd, payload)
                os.close(write_fd)
            finally:
                os._exit(1)
    os.close(write_fd)
    deadline = time.monotonic() + PUBLISHER_RANK_TIMEOUT_SECONDS
    try:
        payload = _read_all(read_fd, _MAX_RESULT, deadline)
        os.close(read_fd)
        read_fd = -1
        status = _wait_child_until(process, deadline)
    except BaseException:
        with suppress(ProcessLookupError):
            os.kill(process, signal.SIGKILL)
        os.waitpid(process, 0)
        raise
    finally:
        if read_fd >= 0:
            os.close(read_fd)
    envelope = _load_object(payload, "unprivileged rank child response")
    if os.waitstatus_to_exitcode(status) != 0 or envelope.get("ok") is not True:
        raise ValueError(str(envelope.get("error", "unprivileged rank child failed")))
    if set(envelope) != {"ok", "result"} or not isinstance(envelope["result"], dict):
        raise ValueError("unprivileged rank child response fields mismatch")
    return envelope["result"]


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write from unprivileged rank child")
        view = view[written:]


def _read_all(descriptor: int, max_bytes: int, deadline: float) -> bytes:
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining:
        wait = deadline - time.monotonic()
        if wait <= 0:
            raise TimeoutError("unprivileged rank child exceeded its wall-clock limit")
        readable, _, _ = select.select([descriptor], [], [], wait)
        if not readable:
            raise TimeoutError("unprivileged rank child exceeded its wall-clock limit")
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > max_bytes:
        raise ValueError("unprivileged rank child response is oversized")
    return data


def _wait_child_until(process: int, deadline: float) -> int:
    while True:
        observed, status = os.waitpid(process, os.WNOHANG)
        if observed == process:
            return status
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("unprivileged rank child exceeded its wall-clock limit")
        time.sleep(min(0.01, remaining))


def _isolate_child_descriptors(write_fd: int) -> int:
    pipe_fd = 3
    if write_fd != pipe_fd:
        os.dup2(write_fd, pipe_fd)
        os.close(write_fd)
    null_fd = os.open("/dev/null", os.O_RDWR)
    try:
        for descriptor in (0, 1, 2):
            os.dup2(null_fd, descriptor)
    finally:
        if null_fd > pipe_fd:
            os.close(null_fd)
    maximum = int(os.sysconf("SC_OPEN_MAX"))
    os.closerange(pipe_fd + 1, maximum)
    return pipe_fd


def _apply_rank_child_limits(*, include_process_limit: bool) -> None:
    limits = {
        resource.RLIMIT_CORE: 0,
        resource.RLIMIT_CPU: 300,
        resource.RLIMIT_FSIZE: 32 * 1024 * 1024,
        resource.RLIMIT_NOFILE: 64,
    }
    if sys.platform != "darwin":
        limits[resource.RLIMIT_AS] = 4 * 1024 * 1024 * 1024
    if include_process_limit and hasattr(resource, "RLIMIT_NPROC"):
        limits[resource.RLIMIT_NPROC] = 32
    for kind, requested in limits.items():
        soft, hard = resource.getrlimit(kind)
        bounded = requested if hard == resource.RLIM_INFINITY else min(requested, hard)
        bounded = bounded if soft == resource.RLIM_INFINITY else min(bounded, soft)
        try:
            resource.setrlimit(kind, (bounded, hard))
            resource.setrlimit(kind, (bounded, bounded))
        except (OSError, ValueError) as exc:
            raise ValueError(f"failed to apply rank child rlimit {kind}") from exc


def _set_no_new_privileges() -> None:
    if not sys.platform.startswith("linux"):
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if not hasattr(libc, "prctl") or libc.prctl(38, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno() or errno.EPERM
        raise OSError(error, "failed to set no_new_privs in rank child")


def _ranker_executable_sha256() -> str:
    root = Path(__file__).resolve().parents[2]
    paths = {
        "windows_ioctl_rank_publisher.py": Path(__file__),
        "windows_ioctl_real_rank.py": Path(real_rank_module.__file__ or ""),
        "windows_ioctl_real_eval.py": Path(rank_eval_module.__file__ or ""),
        "windows_ioctl_rank.py": Path(rank_helpers_module.__file__ or ""),
        "windows_ioctl_boundary.py": Path(boundary_module.__file__ or ""),
        "windows_byo_corpus.py": Path(byo_module.__file__ or ""),
        "windows_variant.py": Path(variant_module.__file__ or ""),
        "pe_symbols.py": Path(pe_symbols_module.__file__ or ""),
        "ssh_authorization.py": Path(authorization_module.__file__ or ""),
        "ssh_authority_commitment.py": Path(authority_commitment_module.__file__ or ""),
        "python-executable": Path(sys.executable).resolve(),
        "ssh-keygen": PUBLISHER_SSH_KEYGEN,
        "uv.lock": root / "uv.lock",
    }
    manifest = {
        name: hashlib.sha256(
            _read_custodied_file(path, 128 * 1024 * 1024, f"ranker manifest {name}")
        ).hexdigest()
        for name, path in paths.items()
    }
    return hashlib.sha256(
        b"0verse-windows-ioctl-ranker-executable-manifest-v1\0"
        + json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _verified_admission_expiry(campaign_path: Path, result: dict[str, Any]) -> datetime:
    campaign_bytes = _read_bounded(campaign_path, 1024 * 1024, "publisher campaign")
    if hashlib.sha256(campaign_bytes).hexdigest() != result["campaign_sha256"]:
        raise ValueError("publisher campaign changed after ranking")
    campaign = _load_object(campaign_bytes, "publisher campaign")
    admission_path = _relative_file(
        campaign_path.parent, campaign.get("admission_path"), "admission_path"
    )
    admission_bytes = _read_bounded(admission_path, 1024 * 1024, "publisher admission")
    if hashlib.sha256(admission_bytes).hexdigest() != result["admission_sha256"]:
        raise ValueError("publisher admission changed after ranking")
    admission = _load_object(admission_bytes, "publisher admission")
    expires_raw = admission.get("expires_at")
    expires = _timestamp(expires_raw, "publisher admission expires_at")
    if result["schema_version"] == RESULT_VERSION_V3 and str(expires_raw) != result[
        "admission_expires_at"
    ]:
        raise ValueError("rank result admission expiry binding mismatch")
    return expires


def _require_service_custody() -> None:
    if os.geteuid() != PUBLISHER_SERVICE_UID:
        raise PermissionError("rank-result publication requires the fixed service UID")
    for path in {
        PUBLISHER_CONFIG,
        PUBLISHER_SIGNING_KEY,
        PUBLISHER_SSH_KEYGEN,
        PUBLISHER_ALLOWED_SIGNERS,
        PUBLISHER_LABEL_ALLOWED_SIGNERS,
        PUBLISHER_SPOOL_ROOT,
    }:
        _require_root_owned_ancestry(path)


def _custodied_file_sha256(
    path: Path, max_bytes: int, label: str, *, private: bool = False
) -> str:
    material = bytearray(_read_custodied_file(path, max_bytes, label, private=private))
    try:
        return hashlib.sha256(material).hexdigest()
    finally:
        material[:] = b"\0" * len(material)


def _require_authority_material_unchanged(
    receipt_policy_bytes: bytes,
    label_policy_bytes: bytes,
    signing_key_sha256: str,
    ssh_keygen_sha256: str,
) -> None:
    if _read_custodied_file(
        PUBLISHER_ALLOWED_SIGNERS, 1024 * 1024, "publisher allowed-signers policy"
    ) != receipt_policy_bytes:
        raise ValueError("publisher allowed-signers policy changed during publication")
    if _read_custodied_file(
        PUBLISHER_LABEL_ALLOWED_SIGNERS, 1024 * 1024, "label allowed-signers policy"
    ) != label_policy_bytes:
        raise ValueError("label allowed-signers policy changed during publication")
    if (
        _custodied_file_sha256(
            PUBLISHER_SIGNING_KEY, 64 * 1024, "publisher signing key", private=True
        )
        != signing_key_sha256
    ):
        raise ValueError("publisher signing key changed during publication")
    if (
        _custodied_file_sha256(
            PUBLISHER_SSH_KEYGEN, 16 * 1024 * 1024, "fixed ssh-keygen"
        )
        != ssh_keygen_sha256
    ):
        raise ValueError("fixed ssh-keygen changed during publication")


def _require_root_owned_ancestry(path: Path) -> None:
    current = path.absolute()
    if not current.is_absolute():
        raise ValueError("publisher custody path must be absolute")
    for parent in [current, *current.parents]:
        if not parent.exists():
            continue
        metadata = parent.lstat()
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != PUBLISHER_SERVICE_UID:
            raise PermissionError(f"publisher custody path is not service-owned: {parent}")
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PermissionError(f"publisher custody path is group/world writable: {parent}")


def _read_custodied_file(
    path: Path, max_bytes: int, label: str, *, private: bool = False
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        forbidden = stat.S_IRWXG | stat.S_IRWXO if private else stat.S_IWGRP | stat.S_IWOTH
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != PUBLISHER_SERVICE_UID
            or metadata.st_nlink != 1
            or metadata.st_mode & forbidden
            or not 0 < metadata.st_size <= max_bytes
        ):
            raise PermissionError(f"{label} custody is unsafe")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != metadata.st_size or len(data) > max_bytes:
            raise ValueError(f"{label} changed during bounded read")
        return data
    finally:
        os.close(descriptor)


def _check_custodied_file(
    path: Path, max_bytes: int, label: str, *, private: bool = False
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        forbidden = stat.S_IRWXG | stat.S_IRWXO if private else stat.S_IWGRP | stat.S_IWOTH
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != PUBLISHER_SERVICE_UID
            or metadata.st_nlink != 1
            or metadata.st_mode & forbidden
            or not 0 < metadata.st_size <= max_bytes
        ):
            raise PermissionError(f"{label} custody is unsafe")
    finally:
        os.close(descriptor)


def _open_custodied_directory(path: Path, label: str) -> int:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != PUBLISHER_SERVICE_UID
        or metadata.st_nlink < 2
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        os.close(descriptor)
        raise PermissionError(f"{label} custody is unsafe")
    return descriptor


def _open_directory_at(parent_fd: int, name: str, label: str) -> int:
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent_fd,
    )
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != PUBLISHER_SERVICE_UID
        or metadata.st_nlink < 2
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        os.close(descriptor)
        raise PermissionError(f"{label} custody is unsafe")
    return descriptor


def _require_absent_at(parent_fd: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise FileExistsError(f"rank-result bundle already exists: {name}")


def _write_new_file(directory_fd: int, name: str, data: bytes, max_bytes: int) -> None:
    if not data or len(data) > max_bytes:
        raise ValueError(f"{name} is empty or exceeds its size limit")
    descriptor = os.open(
        name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=directory_fd,
    )
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while publishing rank-result bundle")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_file_at(directory_fd: int, name: str, max_bytes: int) -> bytes:
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        dir_fd=directory_fd,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != PUBLISHER_SERVICE_UID
            or metadata.st_nlink != 1
            or metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
            or not 0 < metadata.st_size <= max_bytes
        ):
            raise PermissionError(f"published {name} custody is unsafe")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != metadata.st_size or len(data) > max_bytes:
            raise ValueError(f"published {name} changed during read")
        return data
    finally:
        os.close(descriptor)


def _policy_identity_and_commitment(data: bytes, label: str) -> tuple[str, str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} must be UTF-8") from exc
    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if (
        len(lines) != 1
        or len(lines[0].split()) not in {3, 4}
        or lines[0].split()[1] != "ssh-ed25519"
    ):
        raise ValueError(f"{label} must contain exactly one signer")
    parts = lines[0].split()
    try:
        key = base64.b64decode(parts[2], validate=True)
    except ValueError as exc:
        raise ValueError(f"{label} contains a malformed authority key") from exc
    if not key:
        raise ValueError(f"{label} contains an empty authority key")
    commitment = hashlib.sha256(
        b"0verse-ssh-authority-key-v1\0ssh-ed25519\0" + key
    ).hexdigest()
    return parts[0], commitment


def _require_path_matches_directory(path: Path, descriptor: int) -> None:
    observed = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        expected_metadata = os.fstat(descriptor)
        observed_metadata = os.fstat(observed)
        if (expected_metadata.st_dev, expected_metadata.st_ino) != (
            observed_metadata.st_dev,
            observed_metadata.st_ino,
        ):
            raise PermissionError("publisher spool path changed during publication")
    finally:
        os.close(observed)


def _rename_exclusive(root_fd: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        result = libc.renameat2(
            root_fd,
            source.encode(),
            root_fd,
            destination.encode(),
            _RENAME_NOREPLACE,
        )
    elif sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        result = libc.renameatx_np(
            root_fd,
            source.encode(),
            root_fd,
            destination.encode(),
            _RENAME_EXCL,
        )
    else:
        raise OSError(errno.ENOTSUP, "exclusive atomic directory rename is unavailable")
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)


def _remove_staging(root_fd: int, name: str) -> None:
    try:
        descriptor = _open_directory_at(root_fd, name, "publisher staging cleanup")
    except FileNotFoundError:
        return
    try:
        for entry in os.listdir(  # noqa: PTH208  # foxguard: ignore[py/no-path-traversal]
            descriptor
        ):
            os.unlink(  # foxguard: ignore[py/no-path-traversal]
                entry, dir_fd=descriptor
            )
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=root_fd)

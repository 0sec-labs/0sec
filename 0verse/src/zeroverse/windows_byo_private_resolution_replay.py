"""Durably consume private-resolution replay state before any secret access."""

from __future__ import annotations

import os
import re
import stat
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .windows_byo_private_resolution_authorization import (
    VerifiedPrivateResolutionAuthorization,
    verify_private_resolution_authorization,
)

DEFAULT_REPLAY_ROOT = Path(
    "/private/var/lib/0verse/windows-byo-private-resolution-replay"
    if sys.platform == "darwin"
    else "/var/lib/0verse/windows-byo-private-resolution-replay"
)
REPLAY_ROOT = DEFAULT_REPLAY_ROOT
TUPLE_DIRECTORY = "tuples"
AUTHORIZATION_DIRECTORY = "authorizations"
REPLAY_SERVICE_UID = 0
REPLAY_SERVICE_GID = 0
MARKER_SUFFIX = ".used"

_SHA256 = re.compile(r"[0-9a-f]{64}")
_GENERIC_DENIAL = "private resolution unavailable"


class PrivateResolutionDenied(RuntimeError):
    """Generic fail-closed service-boundary denial without membership detail."""


@dataclass(frozen=True)
class ConsumedPrivateResolutionReplayState:
    """Non-secret proof that both replay identities reached durable markers."""

    authorization_sha256: str
    replay_state_consumed: bool = True
    dual_replay_reservation_durable: bool = True
    resolver_started: bool = False
    private_bundle_verified: bool = False
    secret_accessed: bool = False
    zeroization_verified: bool = False
    execution_authorized: bool = False
    network_authorized: bool = False
    redistribution_authorized: bool = False
    disclosure_authorized: bool = False
    automatic_disclosure: bool = False
    weaponization_authorized: bool = False


def verify_and_consume_private_resolution_authorization(
    inventory_path: str | Path,
    rank_output_path: str | Path,
    rank_receipt_path: str | Path,
    labels_path: str | Path,
    evaluation_path: str | Path,
    authorization_path: str | Path,
) -> ConsumedPrivateResolutionReplayState:
    """Verify the fixed permit and durably burn its tuple then permit identities.

    Production has no caller-controlled policy, helper, UID, root, or marker-name
    parameter.  Tests replace module constants, following the publisher pattern.
    """
    descriptors: list[int] = []
    denied = False
    try:
        _require_secure_platform()
        _require_service_custody()
        root_fd = _open_custodied_directory(REPLAY_ROOT, "replay root")
        descriptors.append(root_fd)
        tuple_fd = _open_directory_at(root_fd, TUPLE_DIRECTORY, "tuple replay directory")
        descriptors.append(tuple_fd)
        authorization_fd = _open_directory_at(
            root_fd, AUTHORIZATION_DIRECTORY, "authorization replay directory"
        )
        descriptors.append(authorization_fd)

        verified = verify_private_resolution_authorization(
            inventory_path,
            rank_output_path,
            rank_receipt_path,
            labels_path,
            evaluation_path,
            authorization_path,
        )
        _validate_verified_boundary(verified)
        _require_fixed_directory_inodes(root_fd, tuple_fd, authorization_fd)

        tuple_identity, authorization_identity = verified.burn_only_replay_identities
        _create_empty_marker(
            tuple_fd,
            _marker_name(tuple_identity),
            "tuple replay marker",
        )
        os.fsync(tuple_fd)

        _create_empty_marker(
            authorization_fd,
            _marker_name(authorization_identity),
            "authorization replay marker",
        )
        os.fsync(authorization_fd)
        os.fsync(root_fd)
        _require_fixed_directory_inodes(root_fd, tuple_fd, authorization_fd)

        return ConsumedPrivateResolutionReplayState(
            authorization_sha256=verified.authorization_sha256
        )
    except BaseException:
        denied = True
    finally:
        for descriptor in reversed(descriptors):
            with suppress(OSError):
                os.close(descriptor)
    if denied:
        raise PrivateResolutionDenied(_GENERIC_DENIAL)
    raise AssertionError("private resolution consumption ended without a result")


def _validate_verified_boundary(verified: VerifiedPrivateResolutionAuthorization) -> None:
    identities = verified.burn_only_replay_identities
    if (
        len(identities) != 2
        or len(set(identities)) != 2
        or any(_SHA256.fullmatch(value) is None for value in identities)
        or verified.replay_state_consumed is not False
        or verified.private_bundle_verified is not False
        or verified.secret_accessed is not False
        or verified.zeroization_verified is not False
        or _SHA256.fullmatch(verified.authorization_sha256) is None
    ):
        raise ValueError("verified private resolution boundary is invalid")


def _require_secure_platform() -> None:
    if (
        os.name != "posix"
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_CLOEXEC")
        or os.open not in os.supports_dir_fd
    ):
        raise OSError("secure replay dirfd operations are unavailable")


def _require_service_custody() -> None:
    if os.geteuid() != REPLAY_SERVICE_UID or os.getegid() != REPLAY_SERVICE_GID:
        raise PermissionError("fixed replay service identity is required")
    root = REPLAY_ROOT.absolute()
    if not root.is_absolute():
        raise ValueError("fixed replay root must be absolute")
    allowed_owners = {0, REPLAY_SERVICE_UID}
    for component in [root, *root.parents]:
        metadata = component.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid not in allowed_owners
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise PermissionError("fixed replay ancestry custody is unsafe")


def _directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _open_custodied_directory(path: Path, label: str) -> int:
    descriptor = os.open(path, _directory_flags())
    try:
        _validate_directory_descriptor(descriptor, label)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_directory_at(parent_fd: int, name: str, label: str) -> int:
    if name not in {TUPLE_DIRECTORY, AUTHORIZATION_DIRECTORY}:
        raise ValueError("fixed replay directory name is invalid")
    descriptor = os.open(name, _directory_flags(), dir_fd=parent_fd)
    try:
        _validate_directory_descriptor(descriptor, label)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validate_directory_descriptor(descriptor: int, label: str) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != REPLAY_SERVICE_UID
        or metadata.st_gid != REPLAY_SERVICE_GID
        or metadata.st_nlink < 2
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise PermissionError(f"{label} custody is unsafe")


def _marker_name(identity: str) -> str:
    if _SHA256.fullmatch(identity) is None:
        raise ValueError("replay identity is invalid")
    return f"{identity}{MARKER_SUFFIX}"


def _create_empty_marker(directory_fd: int, name: str, label: str) -> None:
    if re.fullmatch(r"[0-9a-f]{64}\.used", name) is None:
        raise ValueError("replay marker name is invalid")
    descriptor = os.open(
        name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | os.O_CLOEXEC,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != REPLAY_SERVICE_UID
            or metadata.st_gid != REPLAY_SERVICE_GID
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != 0
        ):
            raise PermissionError(f"{label} custody is unsafe")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_fixed_directory_inodes(
    root_fd: int, tuple_fd: int, authorization_fd: int
) -> None:
    _validate_directory_descriptor(root_fd, "held replay root")
    _validate_directory_descriptor(tuple_fd, "held tuple replay directory")
    _validate_directory_descriptor(
        authorization_fd, "held authorization replay directory"
    )
    reopened: list[int] = []
    try:
        reopened_root = _open_custodied_directory(REPLAY_ROOT, "reopened replay root")
        reopened.append(reopened_root)
        reopened_tuple = _open_directory_at(
            reopened_root, TUPLE_DIRECTORY, "reopened tuple replay directory"
        )
        reopened.append(reopened_tuple)
        reopened_authorization = _open_directory_at(
            reopened_root,
            AUTHORIZATION_DIRECTORY,
            "reopened authorization replay directory",
        )
        reopened.append(reopened_authorization)
        for held, current in (
            (root_fd, reopened_root),
            (tuple_fd, reopened_tuple),
            (authorization_fd, reopened_authorization),
        ):
            held_meta = os.fstat(held)
            current_meta = os.fstat(current)
            if (held_meta.st_dev, held_meta.st_ino) != (
                current_meta.st_dev,
                current_meta.st_ino,
            ):
                raise ValueError("fixed replay directory changed during consumption")
    finally:
        for descriptor in reversed(reopened):
            os.close(descriptor)

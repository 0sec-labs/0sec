from __future__ import annotations

import inspect
import json
import os
import stat
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from test_windows_byo_private_resolution_authorization import _signed_authorization

import zeroverse.windows_byo_private_resolution_authorization as authorization_module
import zeroverse.windows_byo_private_resolution_replay as replay_module
import zeroverse.windows_ioctl_real_eval as evaluation_module
from zeroverse.windows_byo_private_resolution_authorization import (
    verify_private_resolution_authorization,
)
from zeroverse.windows_byo_private_resolution_replay import (
    PrivateResolutionDenied,
    verify_and_consume_private_resolution_authorization,
)


def _provision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authorizer_policy: Path,
    resolver_policy: Path,
    receipt_policy: Path,
    label_policy: Path,
) -> Path:
    root = tmp_path / "replay-root"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    for name in (replay_module.TUPLE_DIRECTORY, replay_module.AUTHORIZATION_DIRECTORY):
        child = root / name
        child.mkdir(mode=0o700)
        child.chmod(0o700)
    monkeypatch.setattr(replay_module, "REPLAY_ROOT", root)
    monkeypatch.setattr(replay_module, "REPLAY_SERVICE_UID", os.geteuid())
    monkeypatch.setattr(replay_module, "REPLAY_SERVICE_GID", os.getegid())
    monkeypatch.setattr(authorization_module, "DEFAULT_ALLOWED_SIGNERS", authorizer_policy)
    monkeypatch.setattr(
        authorization_module, "DEFAULT_RESOLVER_ALLOWED_SIGNERS", resolver_policy
    )
    monkeypatch.setattr(
        evaluation_module, "DEFAULT_RANK_RECEIPT_ALLOWED_SIGNERS", receipt_policy
    )
    monkeypatch.setattr(evaluation_module, "DEFAULT_ALLOWED_SIGNERS", label_policy)

    def verify_with_fixture_policies(*paths: str | Path) -> Any:
        return verify_private_resolution_authorization(
            *paths,
            rank_receipt_allowed_signers=receipt_policy,
            label_allowed_signers=label_policy,
            authorization_allowed_signers=authorizer_policy,
            resolver_allowed_signers=resolver_policy,
        )

    monkeypatch.setattr(
        replay_module,
        "verify_private_resolution_authorization",
        verify_with_fixture_policies,
    )
    return root


def _fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[list[Path], Path, Path, Path]:
    paths, authorizer_policy, resolver_policy, _raw = _signed_authorization(
        tmp_path, monkeypatch
    )
    root = _provision(
        tmp_path,
        monkeypatch,
        authorizer_policy,
        resolver_policy,
        paths[6],
        paths[7],
    )
    return paths, root, authorizer_policy, resolver_policy


def _consume(paths: list[Path]) -> Any:
    return verify_and_consume_private_resolution_authorization(*paths[:6])


def _verified(
    paths: list[Path], authorizer_policy: Path, resolver_policy: Path
) -> Any:
    return verify_private_resolution_authorization(
        *paths[:6],
        rank_receipt_allowed_signers=paths[6],
        label_allowed_signers=paths[7],
        authorization_allowed_signers=authorizer_policy,
        resolver_allowed_signers=resolver_policy,
    )


def _assert_generic_denial(denied: PrivateResolutionDenied) -> None:
    assert type(denied) is PrivateResolutionDenied
    assert denied.args == ("private resolution unavailable",)
    assert denied.__cause__ is None
    assert denied.__context__ is None


def test_verifies_then_durably_consumes_two_empty_private_markers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, root, _authorizer_policy, _resolver_policy = _fixture(tmp_path, monkeypatch)
    fsync_kinds: list[str] = []
    real_fsync = os.fsync

    def record_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        fsync_kinds.append("directory" if stat.S_ISDIR(metadata.st_mode) else "file")
        real_fsync(descriptor)

    monkeypatch.setattr(replay_module.os, "fsync", record_fsync)
    consumed = _consume(paths)
    assert fsync_kinds == ["file", "directory", "file", "directory", "directory"]
    assert consumed.replay_state_consumed is True
    assert consumed.dual_replay_reservation_durable is True
    assert consumed.resolver_started is False
    assert consumed.private_bundle_verified is False
    assert consumed.secret_accessed is False
    assert consumed.zeroization_verified is False

    markers = sorted(root.glob("*/*.used"))
    assert len(markers) == 2
    for marker in markers:
        metadata = marker.stat()
        assert marker.read_bytes() == b""
        assert stat.S_ISREG(metadata.st_mode)
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert metadata.st_nlink == 1
    rendered = repr(consumed).lower()
    for forbidden in (str(root).lower(), ".sys", ".pdb", "vulnerable", "bundle/"):
        assert forbidden not in rendered


def test_replay_denial_is_generic_and_preserves_both_markers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, root, _authorizer_policy, _resolver_policy = _fixture(tmp_path, monkeypatch)
    _consume(paths)
    before = {path: path.stat().st_ino for path in root.glob("*/*.used")}
    with pytest.raises(PrivateResolutionDenied) as denied:
        _consume(paths)
    _assert_generic_denial(denied.value)
    assert {path: path.stat().st_ino for path in root.glob("*/*.used")} == before
    assert str(root) not in str(denied.value)


def test_preexisting_authorization_marker_still_permanently_burns_tuple_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, root, authorizer_policy, resolver_policy = _fixture(tmp_path, monkeypatch)
    verified = _verified(paths, authorizer_policy, resolver_policy)
    tuple_id, authorization_id = verified.burn_only_replay_identities
    authorization_marker = (
        root / replay_module.AUTHORIZATION_DIRECTORY / f"{authorization_id}.used"
    )
    authorization_marker.write_bytes(b"")
    authorization_marker.chmod(0o600)

    with pytest.raises(PrivateResolutionDenied) as denied:
        _consume(paths)
    _assert_generic_denial(denied.value)
    tuple_marker = root / replay_module.TUPLE_DIRECTORY / f"{tuple_id}.used"
    assert tuple_marker.is_file()
    assert authorization_marker.is_file()


def test_second_marker_failure_never_rolls_back_first_burn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, root, authorizer_policy, resolver_policy = _fixture(tmp_path, monkeypatch)
    verified = _verified(paths, authorizer_policy, resolver_policy)
    tuple_id, _authorization_id = verified.burn_only_replay_identities
    real_create = replay_module._create_empty_marker

    def fail_authorization(directory_fd: int, name: str, label: str) -> None:
        if label == "authorization replay marker":
            raise OSError("injected second-marker failure")
        real_create(directory_fd, name, label)

    monkeypatch.setattr(replay_module, "_create_empty_marker", fail_authorization)
    with pytest.raises(PrivateResolutionDenied) as denied:
        _consume(paths)
    _assert_generic_denial(denied.value)
    tuple_marker = root / replay_module.TUPLE_DIRECTORY / f"{tuple_id}.used"
    assert tuple_marker.is_file()
    assert list((root / replay_module.AUTHORIZATION_DIRECTORY).iterdir()) == []

    monkeypatch.setattr(replay_module, "_create_empty_marker", real_create)
    with pytest.raises(PrivateResolutionDenied) as denied:
        _consume(paths)
    _assert_generic_denial(denied.value)
    assert tuple_marker.is_file()


def test_first_marker_fsync_failure_is_fail_closed_and_leaves_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, root, authorizer_policy, resolver_policy = _fixture(tmp_path, monkeypatch)
    verified = _verified(paths, authorizer_policy, resolver_policy)
    tuple_id, _authorization_id = verified.burn_only_replay_identities
    real_fsync = os.fsync
    failed = False

    def fail_first_file(descriptor: int) -> None:
        nonlocal failed
        if not failed and stat.S_ISREG(os.fstat(descriptor).st_mode):
            failed = True
            raise OSError("injected marker fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(replay_module.os, "fsync", fail_first_file)
    with pytest.raises(PrivateResolutionDenied) as denied:
        _consume(paths)
    _assert_generic_denial(denied.value)
    assert (root / replay_module.TUPLE_DIRECTORY / f"{tuple_id}.used").is_file()
    assert list((root / replay_module.AUTHORIZATION_DIRECTORY).iterdir()) == []


def test_two_concurrent_consumers_yield_exactly_one_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, root, _authorizer_policy, _resolver_policy = _fixture(tmp_path, monkeypatch)

    def attempt() -> bool:
        try:
            _consume(paths)
            return True
        except PrivateResolutionDenied:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _index: attempt(), range(2)))
    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 1
    assert len(list(root.glob("*/*.used"))) == 2


@pytest.mark.parametrize("unsafe", ["broad-root", "symlink-subdir"])
def test_rejects_unsafe_fixed_replay_custody_without_markers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe: str,
) -> None:
    paths, root, _authorizer_policy, _resolver_policy = _fixture(tmp_path, monkeypatch)
    if unsafe == "broad-root":
        root.chmod(0o755)
    else:
        tuples = root / replay_module.TUPLE_DIRECTORY
        tuples.rmdir()
        tuples.symlink_to(root / replay_module.AUTHORIZATION_DIRECTORY, target_is_directory=True)
    with pytest.raises(PrivateResolutionDenied) as denied:
        _consume(paths)
    _assert_generic_denial(denied.value)
    assert list((root / replay_module.AUTHORIZATION_DIRECTORY).iterdir()) == []


def test_verifier_failure_creates_no_replay_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, root, _authorizer_policy, _resolver_policy = _fixture(tmp_path, monkeypatch)
    paths[5].write_bytes(b"{}")
    with pytest.raises(PrivateResolutionDenied) as denied:
        _consume(paths)
    _assert_generic_denial(denied.value)
    assert list(root.glob("*/*.used")) == []


def test_public_boundary_has_no_policy_root_uid_helper_or_identity_override() -> None:
    parameters = inspect.signature(
        verify_and_consume_private_resolution_authorization
    ).parameters
    assert tuple(parameters) == (
        "inventory_path",
        "rank_output_path",
        "rank_receipt_path",
        "labels_path",
        "evaluation_path",
        "authorization_path",
    )


def test_fixed_root_uses_physical_darwin_path_and_linux_var_path() -> None:
    expected = (
        Path("/private/var/lib/0verse/windows-byo-private-resolution-replay")
        if sys.platform == "darwin"
        else Path("/var/lib/0verse/windows-byo-private-resolution-replay")
    )
    assert expected == replay_module.DEFAULT_REPLAY_ROOT


def test_result_json_shape_contains_only_non_resolution_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _root, _authorizer_policy, _resolver_policy = _fixture(tmp_path, monkeypatch)
    consumed = _consume(paths)
    raw = json.loads(json.dumps(consumed.__dict__))
    assert set(raw) == {
        "authorization_sha256",
        "replay_state_consumed",
        "dual_replay_reservation_durable",
        "resolver_started",
        "private_bundle_verified",
        "secret_accessed",
        "zeroization_verified",
        "execution_authorized",
        "network_authorized",
        "redistribution_authorized",
        "disclosure_authorized",
        "automatic_disclosure",
        "weaponization_authorized",
    }

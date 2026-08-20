from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from test_windows_ioctl_real_eval import _authority, _closure

import zeroverse.windows_ioctl_rank_publisher as publisher
from zeroverse.cli import main
from zeroverse.ssh_authorization import (
    canonical_signed_material,
    sign_ssh_material,
    verify_ssh_signature,
)
from zeroverse.windows_ioctl_rank_publisher import (
    PUBLISHER_CONFIG_VERSION,
    PUBLISHER_PRINCIPAL,
    publish_windows_ioctl_rank_result,
)
from zeroverse.windows_ioctl_real_eval import (
    RANK_RECEIPT_VERSION,
    RANK_RECEIPT_VERSION_V2,
    evaluate_windows_ioctl_real_static,
)


def _publisher_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    byo: bool = False,
) -> tuple[Path, Path, Path, Path, Path, dict[str, Any], list[int]]:
    rank_root = tmp_path / "rank"
    rank_root.mkdir()
    closure = _closure(rank_root, monkeypatch, byo=byo)
    campaign = next(rank_root.glob("campaign-*.json"))
    result = json.loads(closure[0].read_text(encoding="utf-8"))
    key, policy, _ = _authority(tmp_path, "publisher", PUBLISHER_PRINCIPAL)
    spool = tmp_path / "spool"
    replay = spool / ".replays"
    replay.mkdir(parents=True, mode=0o700)
    config = tmp_path / "publisher.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": PUBLISHER_CONFIG_VERSION,
                "worker_machine_id": "fixed-rank-worker-01",
                "rank_worker_uid": 65532 if os.geteuid() == 0 else os.geteuid(),
                "rank_worker_gid": 65532 if os.geteuid() == 0 else os.getegid(),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    calls: list[int] = []

    def rank_once(_campaign: str | Path, **_kwargs: object) -> dict[str, Any]:
        calls.append(1)
        return json.loads(json.dumps(result))

    module = "zeroverse.windows_ioctl_rank_publisher"
    fixed_ssh_keygen = tmp_path / "fixed-ssh-keygen"
    fixed_ssh_keygen.write_text(
        '#!/bin/sh\nexec /usr/bin/ssh-keygen "$@"\n', encoding="utf-8"
    )
    fixed_ssh_keygen.chmod(0o755)
    monkeypatch.setattr(f"{module}.PUBLISHER_CONFIG", config)
    monkeypatch.setattr(f"{module}.PUBLISHER_SIGNING_KEY", key)
    monkeypatch.setattr(f"{module}.PUBLISHER_SSH_KEYGEN", fixed_ssh_keygen)
    monkeypatch.setattr(f"{module}.PUBLISHER_ALLOWED_SIGNERS", policy)
    monkeypatch.setattr(f"{module}.PUBLISHER_LABEL_ALLOWED_SIGNERS", closure[4])
    monkeypatch.setattr(f"{module}.PUBLISHER_SPOOL_ROOT", spool)
    monkeypatch.setattr(f"{module}.PUBLISHER_SERVICE_UID", os.geteuid())
    monkeypatch.setattr(f"{module}._require_service_custody", lambda: None)
    monkeypatch.setattr(f"{module}._rank_unprivileged", rank_once)
    monkeypatch.setattr(f"{module}._check_custodied_file", lambda *_args, **_kwargs: None)
    validate_receipt = publisher._validate_rank_receipt

    def validate_with_test_policy(*args: Any, **kwargs: Any) -> tuple[str, str]:
        kwargs["require_trusted_policy"] = False
        return validate_receipt(*args, **kwargs)

    monkeypatch.setattr(f"{module}._validate_rank_receipt", validate_with_test_policy)
    return spool, campaign, closure[2], closure[4], policy, result, calls


@pytest.mark.parametrize(
    ("byo", "receipt_version"),
    [(False, RANK_RECEIPT_VERSION), (True, RANK_RECEIPT_VERSION_V2)],
)
def test_publishes_exact_result_and_matching_receipt_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    byo: bool,
    receipt_version: str,
) -> None:
    spool, campaign, labels, label_policy, receipt_policy, expected, calls = _publisher_fixture(
        tmp_path, monkeypatch, byo=byo
    )
    published = publish_windows_ioctl_rank_result(campaign, "run-0001")
    bundle = spool / "run-0001"
    assert calls == [1]
    assert sorted(path.name for path in bundle.iterdir()) == ["receipt.json", "result.json"]
    assert json.loads((bundle / "result.json").read_text(encoding="utf-8")) == expected
    receipt = json.loads((bundle / "receipt.json").read_text(encoding="utf-8"))
    assert receipt["schema_version"] == receipt_version
    assert receipt["rank_result_sha256"] == hashlib.sha256(
        (bundle / "result.json").read_bytes()
    ).hexdigest()
    assert receipt["receipt_signer_identity"] == PUBLISHER_PRINCIPAL
    assert receipt["runtime_consumable"] is False
    assert receipt["execution_authorized"] is False
    assert published["redistribution"] is False
    verify_ssh_signature(
        canonical_signed_material(receipt),
        receipt["signature_ssh"],
        identity=PUBLISHER_PRINCIPAL,
        namespace=(
            publisher.RANK_RECEIPT_NAMESPACE_V2
            if byo
            else publisher.RANK_RECEIPT_NAMESPACE
        ),
        allowed_signers=receipt_policy,
        label="publisher real-signature compatibility",
        require_trusted_policy=False,
    )
    assert not any(path.name.startswith(".stage-") for path in spool.iterdir())
    evaluated = evaluate_windows_ioctl_real_static(
        bundle / "result.json",
        bundle / "receipt.json",
        labels,
        rank_receipt_allowed_signers=receipt_policy,
        label_allowed_signers=label_policy,
    )
    assert evaluated["passed"] is True


def test_existing_bundle_is_rejected_before_rank(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spool, campaign, _labels, _label_policy, _receipt_policy, _result, calls = _publisher_fixture(
        tmp_path, monkeypatch
    )
    (spool / "run-0001").mkdir()
    with pytest.raises(FileExistsError, match="already exists"):
        publish_windows_ioctl_rank_result(campaign, "run-0001")
    assert calls == []


def test_signing_failure_leaves_no_half_pair_and_keeps_replay_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spool, campaign, _labels, _label_policy, _receipt_policy, _result, calls = _publisher_fixture(
        tmp_path, monkeypatch
    )
    monkeypatch.setattr(
        "zeroverse.windows_ioctl_rank_publisher.sign_ssh_material",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("signing failed")),
    )
    with pytest.raises(ValueError, match="signing failed"):
        publish_windows_ioctl_rank_result(campaign, "run-0001")
    assert calls == [1]
    assert not (spool / "run-0001").exists()
    assert not any(path.name.startswith(".stage-") for path in spool.iterdir())
    assert len(list((spool / ".replays").iterdir())) == 1
    with pytest.raises(FileExistsError):
        publish_windows_ioctl_rank_result(campaign, "run-0002")
    assert calls == [1, 1]


def test_unsafe_bundle_name_and_replay_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _spool, campaign, _labels, _label_policy, _receipt_policy, _result, calls = _publisher_fixture(
        tmp_path, monkeypatch
    )
    with pytest.raises(ValueError, match="unsafe"):
        publish_windows_ioctl_rank_result(campaign, "../escape")
    assert calls == []


def test_cli_has_no_key_policy_identity_or_output_root_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    spool, campaign, _labels, _label_policy, _receipt_policy, _result, calls = _publisher_fixture(
        tmp_path, monkeypatch
    )
    assert main(
        ["windows-ioctl-real-rank-publish", str(campaign), "run-cli"]
    ) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["bundle_path"] == str(spool / "run-cli")
    assert calls == [1]


def test_configuration_drift_burns_replay_without_publishing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spool, campaign, _labels, _label_policy, _receipt_policy, result, calls = _publisher_fixture(
        tmp_path, monkeypatch
    )

    def rank_and_mutate(_campaign: str | Path, **_kwargs: object) -> dict[str, Any]:
        calls.append(1)
        publisher.PUBLISHER_CONFIG.write_text(
            json.dumps(
                {
                    "schema_version": PUBLISHER_CONFIG_VERSION,
                    "worker_machine_id": "changed-rank-worker-02",
                    "rank_worker_uid": 65532 if os.geteuid() == 0 else os.geteuid(),
                    "rank_worker_gid": 65532 if os.geteuid() == 0 else os.getegid(),
                }
            ),
            encoding="utf-8",
        )
        return json.loads(json.dumps(result))

    monkeypatch.setattr(publisher, "_rank_unprivileged", rank_and_mutate)
    with pytest.raises(ValueError, match="configuration changed"):
        publish_windows_ioctl_rank_result(campaign, "run-drift")
    assert not (spool / "run-drift").exists()
    assert len(list((spool / ".replays").iterdir())) == 1


def test_executable_manifest_drift_burns_replay_without_publishing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spool, campaign, _labels, _label_policy, _receipt_policy, _result, _calls = (
        _publisher_fixture(tmp_path, monkeypatch)
    )
    hashes = iter(["a" * 64, "b" * 64])
    monkeypatch.setattr(publisher, "_ranker_executable_sha256", lambda: next(hashes))
    with pytest.raises(ValueError, match="manifest changed"):
        publish_windows_ioctl_rank_result(campaign, "run-drift")
    assert not (spool / "run-drift").exists()
    assert len(list((spool / ".replays").iterdir())) == 1


def test_v2_rank_must_complete_inside_reopened_admission_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spool, campaign, _labels, _label_policy, _receipt_policy, _result, _calls = (
        _publisher_fixture(tmp_path, monkeypatch)
    )
    real_now = datetime.now(UTC)

    class FutureCompletion(datetime):
        calls = 0

        @classmethod
        def now(cls, tz: object | None = None) -> datetime:
            cls.calls += 1
            value = real_now if cls.calls == 1 else real_now + timedelta(hours=2)
            return value if tz is not None else value.replace(tzinfo=None)

    monkeypatch.setattr(publisher, "datetime", FutureCompletion)
    with pytest.raises(ValueError, match="admission expired"):
        publish_windows_ioctl_rank_result(campaign, "run-expired")
    assert not (spool / "run-expired").exists()
    assert len(list((spool / ".replays").iterdir())) == 1


def test_duplicate_config_key_and_label_principal_reuse_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _spool, campaign, _labels, label_policy, _receipt_policy, _result, calls = (
        _publisher_fixture(tmp_path, monkeypatch)
    )
    publisher.PUBLISHER_CONFIG.write_text(
        '{"schema_version":"'
        + PUBLISHER_CONFIG_VERSION
        + '","worker_machine_id":"one","worker_machine_id":"two"}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate JSON key"):
        publish_windows_ioctl_rank_result(campaign, "run-config")
    assert calls == []

    publisher.PUBLISHER_CONFIG.write_text(
        json.dumps(
            {
                "schema_version": PUBLISHER_CONFIG_VERSION,
                "worker_machine_id": "fixed-rank-worker-01",
                "rank_worker_uid": 65532 if os.geteuid() == 0 else os.geteuid(),
                "rank_worker_gid": 65532 if os.geteuid() == 0 else os.getegid(),
            }
        ),
        encoding="utf-8",
    )
    fields = label_policy.read_text(encoding="utf-8").split()
    fields[0] = PUBLISHER_PRINCIPAL
    label_policy.write_text(" ".join(fields) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="label authority"):
        publish_windows_ioctl_rank_result(campaign, "run-principal")
    assert calls == []

    receipt_fields = publisher.PUBLISHER_ALLOWED_SIGNERS.read_text(encoding="utf-8").split()
    receipt_fields[0] = "still-a-distinct-labeler@example.test"
    label_policy.write_text(" ".join(receipt_fields) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="label authority"):
        publish_windows_ioctl_rank_result(campaign, "run-key-reuse")
    assert calls == []


@pytest.mark.parametrize(
    "artifact", ["receipt-policy", "label-policy", "signing-key", "ssh-keygen"]
)
def test_authority_material_drift_burns_replay_without_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, artifact: str
) -> None:
    spool, campaign, _labels, label_policy, receipt_policy, _result, _calls = (
        _publisher_fixture(tmp_path, monkeypatch)
    )
    original_sign = publisher.sign_ssh_material

    def sign_then_mutate(*args: Any, **kwargs: Any) -> str:
        signature = original_sign(*args, **kwargs)
        target = {
            "receipt-policy": receipt_policy,
            "label-policy": label_policy,
            "signing-key": publisher.PUBLISHER_SIGNING_KEY,
            "ssh-keygen": publisher.PUBLISHER_SSH_KEYGEN,
        }[artifact]
        target.write_bytes(target.read_bytes() + b"\n")
        return signature

    monkeypatch.setattr(publisher, "sign_ssh_material", sign_then_mutate)
    with pytest.raises(ValueError, match="changed during publication"):
        publish_windows_ioctl_rank_result(campaign, f"run-drift-{artifact}")
    assert not (spool / f"run-drift-{artifact}").exists()
    assert len(list((spool / ".replays").iterdir())) == 1


def test_unprivileged_rank_child_returns_bounded_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rank_uid = 65534 if os.geteuid() == 0 else os.geteuid()
    rank_gid = 65534 if os.geteuid() == 0 else os.getegid()
    monkeypatch.setattr(
        publisher,
        "rank_windows_ioctl_real_static",
        lambda _campaign: {"child": "unprivileged"},
    )
    assert publisher._rank_unprivileged(
        "unused", rank_uid=rank_uid, rank_gid=rank_gid
    ) == {"child": "unprivileged"}


def test_publisher_ignores_caller_path_for_private_key_signing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spool, campaign, _labels, _label_policy, _receipt_policy, _result, _calls = (
        _publisher_fixture(tmp_path, monkeypatch)
    )
    marker = tmp_path / "path-helper-ran"
    helper = tmp_path / "ssh-keygen"
    helper.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n", encoding="utf-8")
    helper.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    publish_windows_ioctl_rank_result(campaign, "run-fixed-helper")
    assert (spool / "run-fixed-helper" / "receipt.json").is_file()
    assert not marker.exists()


def test_darwin_exclusive_commit_remains_dirfd_relative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []

    class Libc:
        def renameatx_np(self, *args: object) -> int:
            calls.append(args)
            return 0

    monkeypatch.setattr(publisher.sys, "platform", "darwin")
    monkeypatch.setattr(publisher.ctypes, "CDLL", lambda *_args, **_kwargs: Libc())
    publisher._rename_exclusive(41, ".stage-a", "run-a")
    assert calls == [(41, b".stage-a", 41, b"run-a", publisher._RENAME_EXCL)]


def test_rank_child_closes_inherited_descriptors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inherited = os.open(tmp_path / "parent-private", os.O_WRONLY | os.O_CREAT, 0o600)
    rank_uid = 65534 if os.geteuid() == 0 else os.geteuid()
    rank_gid = 65534 if os.geteuid() == 0 else os.getegid()

    def inspect_descriptor(_campaign: str | Path) -> dict[str, object]:
        try:
            os.fstat(inherited)
        except OSError:
            return {"inherited_descriptor_open": False}
        return {"inherited_descriptor_open": True}

    monkeypatch.setattr(publisher, "rank_windows_ioctl_real_static", inspect_descriptor)
    try:
        assert publisher._rank_unprivileged(
            "unused", rank_uid=rank_uid, rank_gid=rank_gid
        ) == {
            "inherited_descriptor_open": False
        }
    finally:
        os.close(inherited)


def test_rank_child_timeout_kills_and_reaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rank_uid = 65534 if os.geteuid() == 0 else os.geteuid()
    rank_gid = 65534 if os.geteuid() == 0 else os.getegid()
    monkeypatch.setattr(publisher, "PUBLISHER_RANK_TIMEOUT_SECONDS", 0.05)

    def hang(_campaign: str | Path) -> dict[str, object]:
        time.sleep(5)
        return {"late": True}

    monkeypatch.setattr(publisher, "rank_windows_ioctl_real_static", hang)
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="wall-clock limit"):
        publisher._rank_unprivileged("unused", rank_uid=rank_uid, rank_gid=rank_gid)
    assert time.monotonic() - started < 2


def test_rank_child_timeout_also_covers_exit_after_pipe_eof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rank_uid = 65534 if os.geteuid() == 0 else os.geteuid()
    rank_gid = 65534 if os.geteuid() == 0 else os.getegid()
    monkeypatch.setattr(publisher, "PUBLISHER_RANK_TIMEOUT_SECONDS", 0.05)

    def close_pipe_then_hang(_campaign: str | Path) -> dict[str, object]:
        os.close(3)
        time.sleep(5)
        return {"late": True}

    monkeypatch.setattr(publisher, "rank_windows_ioctl_real_static", close_pipe_then_hang)
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="wall-clock limit"):
        publisher._rank_unprivileged("unused", rank_uid=rank_uid, rank_gid=rank_gid)
    assert time.monotonic() - started < 2


def test_rank_child_normalizes_relative_campaign_before_chdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rank_uid = 65534 if os.geteuid() == 0 else os.geteuid()
    rank_gid = 65534 if os.geteuid() == 0 else os.getegid()
    campaign = tmp_path / "relative-campaign.json"
    campaign.write_text("{}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        publisher,
        "rank_windows_ioctl_real_static",
        lambda value: {"absolute": Path(value).is_absolute(), "name": Path(value).name},
    )
    assert publisher._rank_unprivileged(
        campaign.name, rank_uid=rank_uid, rank_gid=rank_gid
    ) == {"absolute": True, "name": campaign.name}


def test_rank_child_can_run_real_cryptographic_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rank_uid = 65534 if os.geteuid() == 0 else os.geteuid()
    rank_gid = 65534 if os.geteuid() == 0 else os.getegid()
    key, policy, identity = _authority(tmp_path, "child-crypto", "child@example.test")
    material = b'{"child":"cryptographic-verification"}'
    namespace = "0verse-rank-child-crypto-test-v1"
    signature = sign_ssh_material(
        material,
        signing_key=key,
        namespace=namespace,
        label="rank child crypto test",
    )
    descriptor, public_policy_name = tempfile.mkstemp(prefix="0verse-child-policy-", dir="/tmp")
    public_policy = Path(public_policy_name)
    try:
        os.write(descriptor, policy.read_bytes())
        os.close(descriptor)
        public_policy.chmod(0o644)

        def verify_in_child(_campaign: str | Path) -> dict[str, object]:
            verify_ssh_signature(
                material,
                signature,
                identity=identity,
                namespace=namespace,
                allowed_signers=public_policy,
                label="rank child crypto test",
                require_trusted_policy=False,
                ssh_keygen="/usr/bin/ssh-keygen",
                inherit_environment=False,
            )
            return {"verified": True}

        monkeypatch.setattr(publisher, "rank_windows_ioctl_real_static", verify_in_child)
        assert publisher._rank_unprivileged(
            "unused", rank_uid=rank_uid, rank_gid=rank_gid
        ) == {"verified": True}
    finally:
        with suppress(OSError):
            os.close(descriptor)
        public_policy.unlink(missing_ok=True)

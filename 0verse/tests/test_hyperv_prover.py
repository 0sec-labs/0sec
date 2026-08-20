from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from authorization_helpers import authorized_grant, authorized_scope

from zeroverse.hyperv_prover import (
    HyperVExecutionGrant,
    HyperVObservation,
    HyperVProverEvidence,
    HyperVProverManifest,
    load_manifest,
    prove_hyperv,
    write_evidence_bundle,
)
from zeroverse.hyperv_transport import crash_signature
from zeroverse.windows_scope import WindowsScope


def manifest(**updates: object) -> dict[str, object]:
    raw: dict[str, object] = {
        "schema_version": "0verse.hyperv-prover/v1",
        "campaign_id": "vmswitch-oid-001",
        "worker": "worker-01.example.test",
        "guest_worker": "attacker-insider",
        "vm_name": "attacker",
        "checkpoint_name": "clean",
        "trigger_argv": ["/root/harness/send-oid", "--case", "candidate"],
        "control_argv": ["/root/harness/send-oid", "--case", "control"],
        "trials": 3,
        "minimum_confirmations": 3,
    }
    raw.update(updates)
    return raw


def bound_campaign(**updates: object) -> HyperVProverManifest:
    raw = manifest(**updates)
    source = json.dumps(raw, sort_keys=True).encode()
    return replace(
        HyperVProverManifest.from_mapping(raw),
        _source_material=source,
        _source_sha256=hashlib.sha256(source).hexdigest(),
    )


def scope(**updates: object) -> WindowsScope:
    now = datetime.now(UTC).isoformat()
    raw: dict[str, object] = {
        "schema_version": "0verse.windows-scope/v1",
        "campaign_id": "vmswitch-oid-001",
        "program": "hyperv-insider",
        "scope_url": "https://example.test/msrc-hyperv-scope",
        "target_feature": "Hyper-V vmswitch",
        "reachability": "stock child partition RNDIS message",
        "authorization": "published bounty scope; owned host and guest",
        "worker": "worker-01.example.test",
        "latest_build_verified_at": now,
        "preflight": {
            "ok": True,
            "program": "hyperv-insider",
            "checked_at": now,
            "build_lab_ex": "28020.1.amd64fre.rs_prerelease",
            "product_name": "Windows 11 Pro",
            "hyperv_available": True,
            "insider": {"ring": "External", "branch_name": "rs_prerelease"},
        },
    }
    raw.update(updates)
    return authorized_scope(raw)


def grant(
    campaign: HyperVProverManifest,
    **updates: object,
) -> HyperVExecutionGrant:
    now = datetime.now(UTC)
    raw: dict[str, object] = {
        "schema_version": "0verse.hyperv-execution-grant/v1",
        "campaign_sha256": campaign._source_sha256,
        "scope_manifest_sha256": "b" * 64,
        "campaign_id": campaign.campaign_id,
        "worker": campaign.worker,
        "guest_worker": campaign.guest_worker,
        "vm_name": campaign.vm_name,
        "checkpoint_name": campaign.checkpoint_name,
        "dump_path": campaign.dump_path,
        "trigger_executable_sha256": "c" * 64,
        "control_executable_sha256": "c" * 64,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "nonce": "grant-nonce-000000000000000000001",
        "authorized_by": "operator@example.test",
    }
    raw.update(updates)
    return authorized_grant(raw)


class Worker:
    def __init__(self, target_statuses: Sequence[str], *, control_status: str = "CLEAN") -> None:
        self.target_statuses = target_statuses
        self.control_status = control_status
        self.calls: list[tuple[str, int]] = []

    def run_case(
        self,
        campaign: HyperVProverManifest,
        *,
        case: str,
        trial: int,
        argv: Sequence[str],
    ) -> HyperVObservation:
        self.calls.append((case, trial))
        status = self.control_status if case == "control" else self.target_statuses[trial - 1]
        transcript = hashlib.sha256(f"{case}:{trial}:{argv!r}".encode()).hexdigest()
        return HyperVObservation(
            case=case,
            trial=trial,
            build_lab_ex="28020.1.amd64fre.rs_prerelease",
            status=status,
            crash_signature="0x1337:vmswitch!ParseOid" if status == "CRASH" else "",
            dump_sha256=hashlib.sha256(f"dump:{trial}".encode()).hexdigest()
            if status == "CRASH"
            else "",
            dump_identity=f"identity:{trial}" if status == "CRASH" else "",
            dump_artifact_path=f"C:\\dumps\\trial-{trial}.dmp"
            if status == "CRASH"
            else "",
            guest_transcript_sha256=transcript,
            run_nonce=f"{case}-{trial}".ljust(32, "x"),
            argv_sha256=hashlib.sha256(repr(tuple(argv)).encode()).hexdigest(),
            error="transport failed" if status == "ERROR" else "",
        )


class Acceptance:
    def __init__(self) -> None:
        self.validations = 0

    def validate_binding(self, *args: object, **kwargs: object) -> None:
        self.validations += 1


def test_load_manifest_and_hash(tmp_path: Path) -> None:
    path = tmp_path / "campaign.json"
    path.write_text(json.dumps(manifest()), encoding="utf-8")
    loaded, digest = load_manifest(path)
    assert loaded.trials == 3
    assert len(digest) == 64


@pytest.mark.parametrize(
    "updates",
    [
        {"trials": 1},
        {"minimum_confirmations": 4},
        {"trigger_argv": ["/tmp/trigger"]},
        {"trigger_argv": ["/root/harness/../evil"]},
        {"trigger_argv": ["/root/harness/send-oid", "bad\narg"]},
        {"control_argv": ["/root/harness/send-oid", "--case", "candidate"]},
        {"worker": "bad worker"},
        {"worker": "0.0.0.0"},
        {"worker": "worker-01.example.test", "guest_worker": "worker-01.example.test"},
        {"dump_path": "/tmp/MEMORY.DMP"},
        {"dump_path": "C:\\dumps\\..\\MEMORY.DMP"},
        {"dump_path": "C:\\dumps\\MEMORY.DMP:stream"},
        {"connect_timeout_seconds": 0},
        {"recovery_timeout_seconds": 10},
    ],
)
def test_manifest_fails_closed(updates: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        HyperVProverManifest.from_mapping(manifest(**updates))


def test_reproduced_requires_paired_repeatable_target_only_crashes() -> None:
    campaign = bound_campaign()
    scope_manifest = scope()
    worker = Worker(["CRASH", "CRASH", "CRASH"])
    acceptance = Acceptance()
    evidence = prove_hyperv(
        campaign,
        campaign._source_sha256,
        scope_manifest,
        scope_manifest._source_sha256,
        worker=worker,
        execution_grant=grant(
            campaign, scope_manifest_sha256=scope_manifest._source_sha256
        ),
        worker_acceptance=acceptance,  # type: ignore[arg-type]
        execution_grant_sha256="e" * 64,
    )
    assert evidence.status == "REPRODUCED"
    assert evidence.to_dict()["schema_version"] == "0verse.hyperv-evidence/v1"
    assert evidence.confirmations == 3
    assert acceptance.validations == 8  # start + 6 cases + promotion
    assert worker.calls == [
        ("control", 1),
        ("target", 1),
        ("control", 2),
        ("target", 2),
        ("control", 3),
        ("target", 3),
    ]


def test_worker_acceptance_is_rechecked_before_target() -> None:
    campaign = bound_campaign()
    scope_manifest = scope()

    class ExpiringAcceptance(Acceptance):
        def validate_binding(self, *args: object, **kwargs: object) -> None:
            super().validate_binding(*args, **kwargs)
            if self.validations == 3:
                raise ValueError("worker acceptance has expired")

    worker = Worker(["CRASH"] * 3)
    evidence = prove_hyperv(
        campaign,
        campaign._source_sha256,
        scope_manifest,
        scope_manifest._source_sha256,
        worker=worker,
        execution_grant=grant(
            campaign, scope_manifest_sha256=scope_manifest._source_sha256
        ),
        worker_acceptance=ExpiringAcceptance(),  # type: ignore[arg-type]
        execution_grant_sha256="e" * 64,
    )
    assert evidence.status == "INCONCLUSIVE"
    assert "expired" in evidence.error
    assert worker.calls == [("control", 1)]


def test_dirty_control_is_inconclusive() -> None:
    campaign = bound_campaign()
    scope_manifest = scope()
    worker = Worker(["CRASH"] * 3, control_status="CRASH")
    evidence = prove_hyperv(
        campaign,
        campaign._source_sha256,
        scope_manifest,
        scope_manifest._source_sha256,
        worker=worker,
        execution_grant=grant(
            campaign, scope_manifest_sha256=scope_manifest._source_sha256
        ),
        worker_acceptance=Acceptance(),  # type: ignore[arg-type]
        execution_grant_sha256="e" * 64,
    )
    assert evidence.status == "INCONCLUSIVE"
    assert "control" in evidence.error
    assert worker.calls == [("control", 1)]


def test_threshold_miss_is_not_reproduced() -> None:
    campaign = bound_campaign()
    scope_manifest = scope()
    evidence = prove_hyperv(
        campaign,
        campaign._source_sha256,
        scope_manifest,
        scope_manifest._source_sha256,
        worker=Worker(["CRASH", "CLEAN", "CLEAN"]),
        execution_grant=grant(
            campaign, scope_manifest_sha256=scope_manifest._source_sha256
        ),
        worker_acceptance=Acceptance(),  # type: ignore[arg-type]
        execution_grant_sha256="e" * 64,
    )
    assert evidence.status == "NOT_REPRODUCED"
    assert evidence.confirmations == 1


def test_target_transport_error_is_inconclusive_even_if_threshold_is_met() -> None:
    campaign = bound_campaign(minimum_confirmations=2)
    scope_manifest = scope()
    worker = Worker(["ERROR", "CRASH", "CRASH"])
    evidence = prove_hyperv(
        campaign,
        campaign._source_sha256,
        scope_manifest,
        scope_manifest._source_sha256,
        worker=worker,
        execution_grant=grant(
            campaign, scope_manifest_sha256=scope_manifest._source_sha256
        ),
        worker_acceptance=Acceptance(),  # type: ignore[arg-type]
        execution_grant_sha256="e" * 64,
    )
    assert evidence.status == "INCONCLUSIVE"
    assert "failed" in evidence.error
    assert worker.calls == [("control", 1), ("target", 1)]


def test_scope_worker_and_build_are_bound() -> None:
    campaign = bound_campaign()
    wrong_worker_scope = scope(worker="other-worker")
    with pytest.raises(ValueError, match="worker"):
        prove_hyperv(
            campaign,
            campaign._source_sha256,
            wrong_worker_scope,
            wrong_worker_scope._source_sha256,
            worker=Worker(["CRASH"] * 3),
            execution_grant=grant(
                campaign, scope_manifest_sha256=wrong_worker_scope._source_sha256
            ),
            worker_acceptance=Acceptance(),  # type: ignore[arg-type]
            execution_grant_sha256="e" * 64,
        )

    wrong_campaign_scope = scope(campaign_id="other-campaign")
    with pytest.raises(ValueError, match="campaign_id"):
        prove_hyperv(
            campaign,
            campaign._source_sha256,
            wrong_campaign_scope,
            wrong_campaign_scope._source_sha256,
            worker=Worker(["CRASH"] * 3),
            execution_grant=grant(
                campaign, scope_manifest_sha256=wrong_campaign_scope._source_sha256
            ),
            worker_acceptance=Acceptance(),  # type: ignore[arg-type]
            execution_grant_sha256="e" * 64,
        )

    class WrongBuild(Worker):
        def run_case(self, *args: object, **kwargs: object) -> HyperVObservation:
            row = super().run_case(*args, **kwargs)  # type: ignore[arg-type]
            return HyperVObservation(**{**row.to_dict(), "build_lab_ex": "wrong-build"})

    scope_manifest = scope()
    evidence = prove_hyperv(
        campaign,
        campaign._source_sha256,
        scope_manifest,
        scope_manifest._source_sha256,
        worker=(wrong_worker := WrongBuild(["CRASH"] * 3)),
        execution_grant=grant(
            campaign, scope_manifest_sha256=scope_manifest._source_sha256
        ),
        worker_acceptance=Acceptance(),  # type: ignore[arg-type]
        execution_grant_sha256="e" * 64,
    )
    assert evidence.status == "INCONCLUSIVE"
    assert "build changed" in evidence.error
    assert wrong_worker.calls == [("control", 1)]


def test_execution_grant_is_expiring_and_digest_bound() -> None:
    campaign = bound_campaign()
    with pytest.raises(ValueError, match="expired"):
        grant(
            campaign,
            issued_at=(datetime.now(UTC) - timedelta(hours=2)).isoformat(),
            expires_at=(datetime.now(UTC) - timedelta(hours=1)).isoformat(),
        )


def test_execution_grant_rejects_live_campaign_divergence() -> None:
    campaign = bound_campaign()
    mutated = replace(
        campaign,
        trigger_argv=("/root/harness/send-oid", "unsigned-argument"),
    )
    with pytest.raises(ValueError, match="differ from source material"):
        grant(campaign).validate_binding(mutated, campaign._source_sha256, "b" * 64)
    scope_manifest = scope()
    with pytest.raises(ValueError, match="binding mismatch"):
        prove_hyperv(
            campaign,
            campaign._source_sha256,
            scope_manifest,
            scope_manifest._source_sha256,
            worker=Worker(["CRASH"] * 3),
            execution_grant=grant(
                campaign,
                scope_manifest_sha256=scope_manifest._source_sha256,
                vm_name="wrong-vm",
            ),
            worker_acceptance=Acceptance(),  # type: ignore[arg-type]
            execution_grant_sha256="e" * 64,
        )


def test_reused_dump_cannot_count_as_multiple_confirmations() -> None:
    campaign = bound_campaign()
    scope_manifest = scope()

    class ReusedDump(Worker):
        def run_case(self, *args: object, **kwargs: object) -> HyperVObservation:
            row = super().run_case(*args, **kwargs)  # type: ignore[arg-type]
            if row.status == "CRASH":
                return HyperVObservation(**{**row.to_dict(), "dump_sha256": "e" * 64})
            return row

    worker = ReusedDump(["CRASH"] * 3)
    evidence = prove_hyperv(
        campaign,
        campaign._source_sha256,
        scope_manifest,
        scope_manifest._source_sha256,
        worker=worker,
        execution_grant=grant(
            campaign, scope_manifest_sha256=scope_manifest._source_sha256
        ),
        worker_acceptance=Acceptance(),  # type: ignore[arg-type]
        execution_grant_sha256="e" * 64,
    )
    assert evidence.status == "INCONCLUSIVE"
    assert "reused" in evidence.error
    assert worker.calls == [
        ("control", 1),
        ("target", 1),
        ("control", 2),
        ("target", 2),
    ]


def bundle_evidence(transcript: Path, analysis: Path) -> HyperVProverEvidence:
    dump = analysis.parent / "retained.dmp"
    dump.write_bytes(b"sanitized test dump\n")
    observation = HyperVObservation(
        case="target",
        trial=1,
        build_lab_ex="28020.1.amd64fre.rs_prerelease",
        status="CRASH",
        crash_signature="bugcheck-133:bucket",
        dump_sha256=hashlib.sha256(dump.read_bytes()).hexdigest(),
        dump_identity="test-dump|nonce|target|1|retained",
        dump_artifact_path=str(dump.resolve()),
        guest_transcript_sha256=hashlib.sha256(transcript.read_bytes()).hexdigest(),
        guest_transcript_path=str(transcript.resolve()),
        dump_analysis_path=str(analysis.resolve()),
    )
    return HyperVProverEvidence(
        manifest_sha256="a" * 64,
        scope_manifest_sha256="b" * 64,
        campaign_id="portable-bundle",
        scope_program="hyperv-insider",
        worker="worker-01.example.test",
        status="REPRODUCED",
        crash_signature=observation.crash_signature,
        confirmations=1,
        required_confirmations=1,
        observations=(observation,),
    )


def test_write_evidence_bundle_uses_receipt_relative_sidecars(tmp_path: Path) -> None:
    transcript = tmp_path / "trial-01-target-guest.json"
    analysis = tmp_path / "trial-01-target-cdb.txt"
    transcript.write_text("{}", encoding="utf-8")
    analysis.write_text("BugCheck 133\n", encoding="utf-8")

    payload, receipt = write_evidence_bundle(bundle_evidence(transcript, analysis), tmp_path)

    assert receipt == tmp_path / "evidence.json"
    stored = json.loads(receipt.read_text(encoding="utf-8"))
    assert stored == payload
    row = stored["observations"][0]
    assert row["guest_transcript_path"] == transcript.name
    assert row["dump_analysis_path"] == analysis.name
    assert row["dump_artifact_path"] == "retained.dmp"


def test_write_evidence_bundle_rejects_unretained_or_detached_paths(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    transcript = tmp_path / "outside.json"
    analysis = bundle / "analysis.txt"
    transcript.write_text("{}", encoding="utf-8")
    analysis.write_text("analysis", encoding="utf-8")
    evidence = bundle_evidence(transcript, analysis)

    with pytest.raises(ValueError, match="outside"):
        write_evidence_bundle(evidence, bundle)
    with pytest.raises(ValueError, match="directly inside"):
        write_evidence_bundle(evidence, tmp_path, tmp_path / "nested" / "evidence.json")
    (tmp_path / "evidence.json").write_text("do not overwrite", encoding="utf-8")
    with pytest.raises(FileExistsError):
        write_evidence_bundle(evidence, tmp_path)


def test_golden_hyperv_receipt_is_portable_and_non_claim_eligible() -> None:
    root = Path(__file__).parent / "fixtures" / "hyperv-evidence-v1" / "reproduced"
    receipt = json.loads((root / "receipt.json").read_text(encoding="utf-8"))
    assert receipt["manifest_sha256"] == hashlib.sha256(
        (root / "campaign.json").read_bytes()
    ).hexdigest()
    assert receipt["scope_manifest_sha256"] == hashlib.sha256(
        (root / "scope.json").read_bytes()
    ).hexdigest()
    assert receipt["fixture_kind"] == "sanitized-contract"
    assert receipt["claim_eligible"] is False
    assert receipt["weaponization"] is False
    assert receipt["auto_disclosure"] is False

    dump_hashes: set[str] = set()
    for raw in receipt["observations"]:
        observation = HyperVObservation(**raw)
        observation.validate(raw["case"], raw["trial"])
        transcript = root / observation.guest_transcript_path
        assert transcript.is_file()
        assert hashlib.sha256(transcript.read_bytes()).hexdigest() == (
            observation.guest_transcript_sha256
        )
        if observation.status == "CRASH":
            dump = root / observation.dump_artifact_path
            assert dump.is_file()
            assert hashlib.sha256(dump.read_bytes()).hexdigest() == observation.dump_sha256
            dump_hashes.add(observation.dump_sha256)
            analysis = root / observation.dump_analysis_path
            assert hashlib.sha256(analysis.read_bytes()).hexdigest() == (
                observation.dump_analysis_sha256
            )
            assert crash_signature(analysis.read_text(encoding="utf-8")) == (
                observation.crash_signature
            )
    assert len(dump_hashes) == receipt["confirmations"]

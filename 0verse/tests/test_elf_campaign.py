from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from zeroverse.elf_campaign import (
    ACCEPTANCE_SCHEMA_VERSION,
    CAMPAIGN_SCHEMA_VERSION,
    RECEIPT_SCHEMA_VERSION,
    ElfCampaign,
    ElfCampaignReceipt,
    load_campaign,
    load_receipt,
)

NOW = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)
TARGET_SHA = hashlib.sha256(b"target").hexdigest()
CONTROL_SHA = hashlib.sha256(b"control").hexdigest()
INPUT_SHA = hashlib.sha256(b"input").hexdigest()
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _trusted_test_signatures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("zeroverse.elf_campaign.verify_ssh_signature", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "zeroverse.elf_campaign.ssh_authority_key_commitment",
        lambda path: hashlib.sha256(str(path).encode()).hexdigest(),
    )


def _iso(delta: timedelta) -> str:
    return (NOW + delta).isoformat()


def acceptance(**updates: object) -> dict[str, object]:
    raw: dict[str, object] = {
        "schema_version": ACCEPTANCE_SCHEMA_VERSION,
        "acceptance_id": "elf-worker-acceptance-001",
        "campaign_id": "elf-contract-test-001",
        "worker": "elf-worker",
        "target_sha256": TARGET_SHA,
        "control_sha256": CONTROL_SHA,
        "execution_mode": "native",
        "oracles": ["asan", "casr"],
        "accepted_at": _iso(timedelta(hours=-1)),
        "expires_at": _iso(timedelta(days=1)),
        "statement": "owned isolated worker accepted for this exact contract",
        "accepted_by": "elf-worker-authority",
        "signature_ssh": "test-signature",
    }
    raw.update(updates)
    return raw


def manifest(acceptance_sha256: str, **updates: object) -> dict[str, object]:
    raw: dict[str, object] = {
        "schema_version": CAMPAIGN_SCHEMA_VERSION,
        "campaign_id": "elf-contract-test-001",
        "target": {"path": "/srv/elf/target", "sha256": TARGET_SHA},
        "control": {"path": "/srv/elf/control", "sha256": CONTROL_SHA},
        "worker": "elf-worker",
        "worker_acceptance_path": "worker-acceptance.json",
        "worker_acceptance_sha256": acceptance_sha256,
        "execution_mode": "native",
        "oracles": ["asan", "casr"],
        "authorization": {
            "campaign_id": "elf-contract-test-001",
            "target_sha256": TARGET_SHA,
            "control_sha256": CONTROL_SHA,
            "worker": "elf-worker",
            "execution_mode": "native",
            "oracles": ["asan", "casr"],
            "kind": "owned-lab",
            "reference": "urn:0verse:test-owned-lab",
            "statement": "test-owned artifacts and worker",
            "checked_at": _iso(timedelta(days=-1)),
            "expires_at": _iso(timedelta(days=2)),
            "authorized_by": "elf-scope-authority",
            "signature_ssh": "test-signature",
        },
    }
    raw.update(updates)
    return raw


def write_bundle(tmp_path: Path, **manifest_updates: object) -> Path:
    acceptance_path = tmp_path / "worker-acceptance.json"
    acceptance_path.write_text(json.dumps(acceptance(), sort_keys=True), encoding="utf-8")
    acceptance_sha = hashlib.sha256(acceptance_path.read_bytes()).hexdigest()
    manifest_path = tmp_path / "campaign.json"
    manifest_path.write_text(
        json.dumps(manifest(acceptance_sha, **manifest_updates), sort_keys=True),
        encoding="utf-8",
    )
    return manifest_path


def receipt(
    campaign_sha256: str,
    acceptance_sha256: str,
    artifact_sha256: str,
    artifact_size: int,
    input_size: int = 5,
    **updates: object,
) -> dict[str, object]:
    artifact = {"path": "target.stderr", "sha256": artifact_sha256, "size": artifact_size}
    raw: dict[str, object] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "campaign_id": "elf-contract-test-001",
        "campaign_sha256": campaign_sha256,
        "worker_acceptance_sha256": acceptance_sha256,
        "worker": "elf-worker",
        "target_sha256": TARGET_SHA,
        "control_sha256": CONTROL_SHA,
        "input": {"path": "input.bin", "sha256": INPUT_SHA, "size": input_size},
        "execution_mode": "native",
        "oracles": ["asan", "casr"],
        "started_at": _iso(timedelta(minutes=-30)),
        "finished_at": _iso(timedelta(minutes=-29)),
        "classification": "TARGET_ONLY_CRASH",
        "target_observation": observation(
            "target", campaign_sha256, acceptance_sha256, TARGET_SHA, "CRASH", [artifact]
        ),
        "control_observation": observation(
            "control", campaign_sha256, acceptance_sha256, CONTROL_SHA, "CLEAN"
        ),
        "artifacts": [artifact],
        "claim_eligible": False,
        "auto_disclosure": False,
    }
    raw.update(updates)
    return raw


def observation(
    role: str,
    campaign_sha256: str,
    acceptance_sha256: str,
    binary_sha256: str,
    outcome: str,
    evidence: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "role": role,
        "campaign_sha256": campaign_sha256,
        "worker_acceptance_sha256": acceptance_sha256,
        "binary_sha256": binary_sha256,
        "input_sha256": INPUT_SHA,
        "outcome": outcome,
        "exit_code": 0 if outcome == "CLEAN" else None,
        "signal": 11 if outcome == "CRASH" else None,
        "started_at": _iso(timedelta(minutes=-30)),
        "finished_at": _iso(timedelta(minutes=-29)),
        "evidence": evidence or [],
        "observed_by": f"{role}-observation-authority",
        "signature_ssh": "test-signature",
    }


def test_load_campaign_binds_fresh_authorization_and_worker_acceptance(
    tmp_path: Path,
) -> None:
    path = write_bundle(tmp_path)
    campaign, campaign_sha, accepted, acceptance_sha = load_campaign(path, now=NOW)
    assert campaign.schema_version == CAMPAIGN_SCHEMA_VERSION
    assert campaign.target.sha256 == TARGET_SHA
    assert campaign.control.sha256 == CONTROL_SHA
    assert campaign.target.sha256 != campaign.control.sha256
    assert accepted.worker == campaign.worker
    assert accepted.oracles == campaign.oracles == ("asan", "casr")
    assert campaign_sha == hashlib.sha256(path.read_bytes()).hexdigest()
    assert acceptance_sha == campaign.worker_acceptance_sha256


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"schema_version": "0verse.elf-campaign/v0"}, "unsupported"),
        ({"execution_mode": "wine"}, "execution mode"),
        ({"oracles": ["imaginary-oracle"]}, "unsupported ELF oracle"),
        (
            {"control": {"path": "/srv/elf/control", "sha256": TARGET_SHA}},
            "digests must differ",
        ),
        (
            {"control": {"path": "/srv/elf/target", "sha256": CONTROL_SHA}},
            "paths must differ",
        ),
    ],
)
def test_manifest_rejects_unsupported_or_unpaired_identity(
    updates: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        ElfCampaign.from_mapping(manifest("a" * 64, **updates), now=NOW)


def test_authorization_must_be_current_and_published_scope_uses_https() -> None:
    stale = manifest("a" * 64)
    assert isinstance(stale["authorization"], dict)
    stale["authorization"]["checked_at"] = _iso(timedelta(days=-31))
    with pytest.raises(ValueError, match="30 days"):
        ElfCampaign.from_mapping(stale, now=NOW)

    published = manifest("a" * 64)
    assert isinstance(published["authorization"], dict)
    published["authorization"].update(
        {"kind": "published-bounty", "reference": "http://scope.invalid"}
    )
    with pytest.raises(ValueError, match="https"):
        ElfCampaign.from_mapping(published, now=NOW)


def test_worker_acceptance_hash_and_binding_are_fail_closed(tmp_path: Path) -> None:
    path = write_bundle(tmp_path)
    acceptance_path = tmp_path / "worker-acceptance.json"
    raw = json.loads(acceptance_path.read_text(encoding="utf-8"))
    raw["worker"] = "different-worker"
    acceptance_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256 differs"):
        load_campaign(path, now=NOW)

    digest = hashlib.sha256(acceptance_path.read_bytes()).hexdigest()
    campaign_raw = json.loads(path.read_text(encoding="utf-8"))
    campaign_raw["worker_acceptance_sha256"] = digest
    path.write_text(json.dumps(campaign_raw), encoding="utf-8")
    with pytest.raises(ValueError, match="not bound"):
        load_campaign(path, now=NOW)


def test_authorization_acceptance_roles_and_namespaces_are_separate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: list[tuple[str, str]] = []

    def verify(*_args: object, **kwargs: object) -> None:
        observed.append((str(kwargs["identity"]), str(kwargs["namespace"])))

    monkeypatch.setattr("zeroverse.elf_campaign.verify_ssh_signature", verify)
    path = write_bundle(tmp_path)
    load_campaign(path, now=NOW)
    assert observed == [
        ("elf-scope-authority", "0verse-elf-authorization-v1"),
        ("elf-worker-authority", "0verse-elf-worker-acceptance-v1"),
    ]

    acceptance_path = tmp_path / "worker-acceptance.json"
    raw = acceptance(accepted_by="elf-scope-authority")
    acceptance_path.write_text(json.dumps(raw), encoding="utf-8")
    digest = hashlib.sha256(acceptance_path.read_bytes()).hexdigest()
    path.write_text(json.dumps(manifest(digest)), encoding="utf-8")
    with pytest.raises(ValueError, match="signer roles must differ"):
        load_campaign(path, now=NOW)


def test_worker_acceptance_expiry_is_checked(tmp_path: Path) -> None:
    acceptance_path = tmp_path / "worker-acceptance.json"
    acceptance_path.write_text(
        json.dumps(
            acceptance(
                accepted_at=_iso(timedelta(days=-8)),
                expires_at=_iso(timedelta(days=1)),
            )
        ),
        encoding="utf-8",
    )
    digest = hashlib.sha256(acceptance_path.read_bytes()).hexdigest()
    path = tmp_path / "campaign.json"
    path.write_text(json.dumps(manifest(digest)), encoding="utf-8")
    with pytest.raises(ValueError, match="7 days"):
        load_campaign(path, now=NOW)


def test_duplicate_json_keys_and_symlinked_acceptance_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "campaign.json"
    path.write_text('{"schema_version":"a","schema_version":"b"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_campaign(path, now=NOW)

    real = tmp_path / "real-acceptance.json"
    real.write_text(json.dumps(acceptance()), encoding="utf-8")
    link = tmp_path / "worker-acceptance.json"
    link.symlink_to(real)
    digest = hashlib.sha256(real.read_bytes()).hexdigest()
    path.write_text(json.dumps(manifest(digest)), encoding="utf-8")
    with pytest.raises(ValueError, match="symlink"):
        load_campaign(path, now=NOW)

    real_dir = tmp_path / "real-dir"
    real_dir.mkdir()
    (real_dir / "acceptance.json").write_text(json.dumps(acceptance()), encoding="utf-8")
    linked_dir = tmp_path / "linked-dir"
    linked_dir.symlink_to(real_dir, target_is_directory=True)
    digest = hashlib.sha256((real_dir / "acceptance.json").read_bytes()).hexdigest()
    raw = manifest(digest)
    raw["worker_acceptance_path"] = "linked-dir/acceptance.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="non-symlink"):
        load_campaign(path, now=NOW)


def test_receipt_binds_campaign_acceptance_window_and_immutable_artifacts(
    tmp_path: Path,
) -> None:
    path = write_bundle(tmp_path)
    campaign, campaign_sha, accepted, acceptance_sha = load_campaign(path, now=NOW)
    artifact = tmp_path / "target.stderr"
    artifact.write_bytes(b"ERROR: AddressSanitizer: heap-buffer-overflow\n")
    (tmp_path / "input.bin").write_bytes(b"input")
    artifact_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(
        json.dumps(receipt(campaign_sha, acceptance_sha, artifact_sha, artifact.stat().st_size)),
        encoding="utf-8",
    )

    loaded, receipt_sha = load_receipt(
        receipt_path, campaign, campaign_sha, accepted, acceptance_sha
    )
    assert loaded.classification == "TARGET_ONLY_CRASH"
    assert not loaded.claim_eligible and not loaded.auto_disclosure
    assert receipt_sha == hashlib.sha256(receipt_path.read_bytes()).hexdigest()

    artifact.write_bytes(b"tampered")
    with pytest.raises(ValueError, match=r"size differs|SHA-256 differs"):
        load_receipt(receipt_path, campaign, campaign_sha, accepted, acceptance_sha)

    artifact.write_bytes(b"ERROR: AddressSanitizer: heap-buffer-overflow\n")
    (tmp_path / "input.bin").write_bytes(b"tampered-input")
    with pytest.raises(ValueError, match=r"size differs|SHA-256 differs"):
        load_receipt(receipt_path, campaign, campaign_sha, accepted, acceptance_sha)


def test_receipt_observation_signatures_are_role_separated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_bundle(tmp_path)
    campaign, campaign_sha, accepted, acceptance_sha = load_campaign(path, now=NOW)
    (tmp_path / "input.bin").write_bytes(b"input")
    artifact = tmp_path / "target.stderr"
    artifact.write_bytes(b"evidence")
    raw = receipt(campaign_sha, acceptance_sha, hashlib.sha256(b"evidence").hexdigest(), 8)
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(raw), encoding="utf-8")
    observed: list[tuple[str, str]] = []

    def verify(*_args: object, **kwargs: object) -> None:
        observed.append((str(kwargs["identity"]), str(kwargs["namespace"])))

    monkeypatch.setattr("zeroverse.elf_campaign.verify_ssh_signature", verify)
    load_receipt(receipt_path, campaign, campaign_sha, accepted, acceptance_sha)
    assert observed == [
        ("target-observation-authority", "0verse-elf-target-observation-v1"),
        ("control-observation-authority", "0verse-elf-control-observation-v1"),
    ]


def test_receipt_derives_classification_and_binds_exact_input() -> None:
    raw = receipt("a" * 64, "b" * 64, "c" * 64, 1)
    raw["classification"] = "CLEAN"
    with pytest.raises(ValueError, match="not derived"):
        ElfCampaignReceipt.from_mapping(raw)

    raw = receipt("a" * 64, "b" * 64, "c" * 64, 1)
    assert isinstance(raw["target_observation"], dict)
    raw["target_observation"]["input_sha256"] = "d" * 64
    parsed = ElfCampaignReceipt.from_mapping(raw)
    campaign = ElfCampaign.from_mapping(manifest("b" * 64), now=NOW)
    from zeroverse.elf_campaign import ElfWorkerAcceptance

    accepted = ElfWorkerAcceptance.from_mapping(acceptance(), now=NOW)
    with pytest.raises(ValueError, match="input/campaign bound"):
        parsed.require_binding(campaign, "a" * 64, accepted, "b" * 64)


def test_receipt_rejects_unbound_or_overclaiming_evidence() -> None:
    raw = receipt("a" * 64, "b" * 64, "c" * 64, 1, claim_eligible=True)
    with pytest.raises(ValueError, match="cannot claim eligibility"):
        ElfCampaignReceipt.from_mapping(raw)

    raw = receipt("a" * 64, "b" * 64, "c" * 64, 1, campaign_id="other-campaign")
    parsed = ElfCampaignReceipt.from_mapping(raw)
    campaign = ElfCampaign.from_mapping(manifest("b" * 64), now=NOW)
    accepted_raw = acceptance()
    from zeroverse.elf_campaign import ElfWorkerAcceptance

    accepted = ElfWorkerAcceptance.from_mapping(accepted_raw, now=NOW)
    with pytest.raises(ValueError, match="not bound"):
        parsed.require_binding(campaign, "a" * 64, accepted, "b" * 64)


def test_receipt_execution_must_stay_inside_authority_windows() -> None:
    raw = receipt(
        "a" * 64,
        "b" * 64,
        "c" * 64,
        1,
        started_at=_iso(timedelta(hours=-2)),
        finished_at=_iso(timedelta(hours=-1, minutes=-30)),
    )
    for key in ("target_observation", "control_observation"):
        assert isinstance(raw[key], dict)
        raw[key]["started_at"] = _iso(timedelta(hours=-2))
        raw[key]["finished_at"] = _iso(timedelta(hours=-1, minutes=-30))
    parsed = ElfCampaignReceipt.from_mapping(raw)
    campaign = ElfCampaign.from_mapping(manifest("b" * 64), now=NOW)
    from zeroverse.elf_campaign import ElfWorkerAcceptance

    accepted = ElfWorkerAcceptance.from_mapping(acceptance(), now=NOW)
    with pytest.raises(ValueError, match="predates worker acceptance"):
        parsed.require_binding(campaign, "a" * 64, accepted, "b" * 64)


def test_published_schemas_are_versioned_and_fail_closed() -> None:
    expected = {
        "elf-campaign-v1.schema.json": CAMPAIGN_SCHEMA_VERSION,
        "elf-worker-acceptance-v1.schema.json": ACCEPTANCE_SCHEMA_VERSION,
        "elf-campaign-receipt-v1.schema.json": RECEIPT_SCHEMA_VERSION,
    }
    for name, version in expected.items():
        raw = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(raw)
        assert raw["additionalProperties"] is False
        assert raw["properties"]["schema_version"]["const"] == version

    instances = {
        "elf-campaign-v1.schema.json": manifest("b" * 64),
        "elf-worker-acceptance-v1.schema.json": acceptance(),
        "elf-campaign-receipt-v1.schema.json": receipt("a" * 64, "b" * 64, "c" * 64, 1),
    }
    for name, instance in instances.items():
        schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(instance)


def test_schema_and_runtime_both_reject_bad_datetime_and_identifier() -> None:
    raw = manifest("a" * 64)
    assert isinstance(raw["authorization"], dict)
    raw["authorization"]["checked_at"] = "not-a-date"
    schema = json.loads((ROOT / "schemas" / "elf-campaign-v1.schema.json").read_text())
    with pytest.raises(ValidationError):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(raw)
    with pytest.raises(ValueError, match="RFC3339"):
        ElfCampaign.from_mapping(raw, now=NOW)

    raw = acceptance(acceptance_id="bad id")
    schema = json.loads((ROOT / "schemas" / "elf-worker-acceptance-v1.schema.json").read_text())
    with pytest.raises(ValidationError):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(raw)
    from zeroverse.elf_campaign import ElfWorkerAcceptance

    with pytest.raises(ValueError, match="identifier"):
        ElfWorkerAcceptance.from_mapping(raw, now=NOW)


def test_schema_and_runtime_reject_uppercase_hashes() -> None:
    raw = manifest("A" * 64)
    schema = json.loads((ROOT / "schemas" / "elf-campaign-v1.schema.json").read_text())
    with pytest.raises(ValidationError):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(raw)
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        ElfCampaign.from_mapping(raw, now=NOW)


@pytest.mark.parametrize(
    "invalid",
    [
        "2026-07-15 12:00:00+00:00",
        "2026-07-15T12:00:00+0000",
        "2026-07-15T12:00Z",
    ],
)
def test_schema_and_runtime_reject_non_rfc3339_timestamp_lexemes(invalid: str) -> None:
    raw = manifest("a" * 64)
    assert isinstance(raw["authorization"], dict)
    raw["authorization"]["checked_at"] = invalid
    schema = json.loads((ROOT / "schemas" / "elf-campaign-v1.schema.json").read_text())
    with pytest.raises(ValidationError):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(raw)
    with pytest.raises(ValueError, match="RFC3339"):
        ElfCampaign.from_mapping(raw, now=NOW)


@pytest.mark.parametrize("path", [".", "..", "./acceptance.json", "dir//acceptance.json"])
def test_schema_and_runtime_reject_noncanonical_relative_paths(path: str) -> None:
    raw = manifest("a" * 64, worker_acceptance_path=path)
    schema = json.loads((ROOT / "schemas" / "elf-campaign-v1.schema.json").read_text())
    with pytest.raises(ValidationError):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(raw)
    with pytest.raises(ValueError, match="canonical bundle-relative"):
        ElfCampaign.from_mapping(raw, now=NOW)

    receipt_raw = receipt("a" * 64, "b" * 64, "c" * 64, 1)
    assert isinstance(receipt_raw["input"], dict)
    receipt_raw["input"]["path"] = path
    receipt_schema = json.loads(
        (ROOT / "schemas" / "elf-campaign-receipt-v1.schema.json").read_text()
    )
    with pytest.raises(ValidationError):
        Draft202012Validator(receipt_schema, format_checker=FormatChecker()).validate(receipt_raw)
    with pytest.raises(ValueError, match="canonical bundle-relative"):
        ElfCampaignReceipt.from_mapping(receipt_raw)


def test_lowercase_rfc3339_t_and_z_match_schema_and_runtime() -> None:
    raw = manifest("a" * 64)
    assert isinstance(raw["authorization"], dict)
    raw["authorization"]["checked_at"] = "2026-07-14t12:00:00z"
    raw["authorization"]["expires_at"] = "2026-07-17t12:00:00z"
    schema = json.loads((ROOT / "schemas" / "elf-campaign-v1.schema.json").read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(raw)
    ElfCampaign.from_mapping(raw, now=NOW)


def test_documentation_template_is_intentionally_not_a_live_campaign() -> None:
    raw = json.loads((ROOT / "examples" / "elf_campaign.template.json").read_text(encoding="utf-8"))
    with pytest.raises(ValueError, match="SHA-256"):
        ElfCampaign.from_mapping(raw, now=NOW)

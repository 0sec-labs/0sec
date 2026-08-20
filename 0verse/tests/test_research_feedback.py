from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from zeroverse import dataset, research_admission, research_feedback
from zeroverse.cli import main
from zeroverse.ssh_authorization import (
    canonical_signed_material,
    sign_ssh_material,
)
from zeroverse.ssh_authorization import (
    verify_ssh_signature as real_verify_ssh_signature,
)


@pytest.fixture(autouse=True)
def _verify_test_policy_without_root_ownership(monkeypatch) -> None:
    """Keep cryptographic verification real while allowing tmp-path test policies."""

    def verify(*args, **kwargs) -> None:
        kwargs["require_trusted_policy"] = False
        real_verify_ssh_signature(*args, **kwargs)

    monkeypatch.setattr(research_feedback, "verify_ssh_signature", verify)
    monkeypatch.setattr(research_admission, "verify_ssh_signature", verify)


def _evidence_signer(tmp_path: Path):
    key = tmp_path / "evidence-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    principal = "0research-zeroverse-evidence@test"
    public = key.with_suffix(".pub").read_text(encoding="utf-8").split()
    policy = tmp_path / "evidence.allowed_signers"
    policy.write_text(f"{principal} {public[0]} {public[1]}\n", encoding="utf-8")

    def signer(material: bytes, identity: str, namespace: str) -> str:
        assert identity == principal
        return sign_ssh_material(
            material,
            signing_key=key,
            namespace=namespace,
            label="test 0verse evidence admission",
            inherit_environment=False,
        )

    return principal, policy, signer


def _target_snapshot(tmp_path: Path, event_ids: tuple[str, ...]):
    root = tmp_path / "target-snapshot"
    root.mkdir()
    key = tmp_path / "target-snapshot-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    principal = "0research-zeroverse-target@test"
    public = key.with_suffix(".pub").read_text(encoding="utf-8").split()
    policy = tmp_path / "target-snapshot.allowed_signers"
    policy.write_text(f"{principal} {public[0]} {public[1]}\n", encoding="utf-8")
    artifacts = {}
    for name in ("sourceTree", "package", "lockfile", "toolchain", "runtimeConfig"):
        artifact = root / f"{name}.bin"
        artifact.write_bytes(f"exact-{name}\n".encode())
        artifacts[name] = {"path": artifact.name, "sha256": _digest(artifact.read_bytes())}
    body = {
        "schemaVersion": 1,
        "contract": "0verse-target-snapshot-v1",
        "repository": "0sec-labs/0verse",
        "commitSha": "a" * 40,
        "gitTreeOid": "b" * 40,
        "artifacts": artifacts,
        "eventIds": sorted(event_ids),
        "principal": principal,
    }
    signed = {**body, "signature_ssh": ""}
    signed["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(signed),
        signing_key=key,
        namespace="0verse-0research-target-snapshot-v1",
        label="test 0verse target snapshot",
        inherit_environment=False,
    )
    snapshot = root / "snapshot.json"
    snapshot.write_text(json.dumps(signed, sort_keys=True) + "\n", encoding="utf-8")
    return snapshot, policy


def _digest(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _record(*, verdict: str = "confirmed", oracle: str = "differential-crash") -> dict:
    confirmed = verdict == "confirmed"
    return {
        "record_id": "feedback-record",
        "dataset_version": dataset.DATASET_VERSION,
        "created_at": "2026-07-18T00:00:00+00:00",
        "tool": {"name": "0verse", "version": "0.0.1"},
        "backend": "ghidra",
        "binary_name": "target",
        "features": {
            "format": "ELF",
            "arch": "x86-64",
            "bits": 64,
            "endian": "little",
            "size_bytes": 42,
            "stripped": True,
            "symbols_present": False,
            "mitigations": {},
        },
        "label": {
            "bug_class": "CWE-787",
            "source": "stdin",
            "sink": "memcpy",
            "function": "parse",
            "offset": "0x10",
        },
        "verdict": verdict,
        "oracle": oracle,
        "oracle_receipt": {},
        "oracle_evidence": {},
        "pov": {
            "path": "povs/replay.py" if confirmed else "",
            "repro_cmd": "python3 povs/replay.py" if confirmed else "",
            "capability": "oob-write" if confirmed else "",
            "dedup_bucket": "bucket" if confirmed else "",
            **({"sha256": ""} if confirmed else {}),
        },
        "explanation": "deterministic evidence",
        "synthetic": False,
    }


def _fixture(tmp_path: Path, records: list[dict] | None = None) -> tuple[Path, Path, Path, Path]:
    root = tmp_path / "output"
    pov = root / "povs" / "replay.py"
    pov.parent.mkdir(parents=True)
    pov.write_bytes(b"print('replay')\n")
    selected = records or [_record()]
    key = tmp_path / "oracle-key"
    key.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    identity = "0research-oracle@test"
    public = key.with_suffix(".pub").read_text(encoding="utf-8").split()
    policy = tmp_path / "oracle.allowed_signers"
    policy.write_text(f"{identity} {public[0]} {public[1]}\n", encoding="utf-8")
    for record in selected:
        if record["verdict"] == "confirmed":
            record["pov"]["sha256"] = hashlib.sha256(pov.read_bytes()).hexdigest()
        evidence_path = Path("oracle") / f"{record['record_id']}.json"
        evidence = (
            json.dumps(
                {
                    "oracle": record["oracle"],
                    "recordId": record["record_id"],
                    "result": record["verdict"],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        target = root / evidence_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(evidence)
        record["oracle_evidence"] = {
            "path": evidence_path.as_posix(),
            "sha256": _digest(evidence),
        }
        unsigned_record = {key: value for key, value in record.items() if key != "oracle_receipt"}
        source_digest = _digest(
            (json.dumps(unsigned_record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        receipt_body = {
            "schemaVersion": 1,
            "contract": "0verse-oracle-result-receipt-v1",
            "signerIdentity": identity,
            "sourceRecordDigest": source_digest,
            "verdict": record["verdict"],
            "oracle": record["oracle"],
            "evidenceSha256": _digest(evidence),
            "povSha256": (
                f"sha256:{record['pov']['sha256']}" if record["pov"].get("sha256") else _digest(b"")
            ),
        }
        signed = {**receipt_body, "signature_ssh": ""}
        signed["signature_ssh"] = sign_ssh_material(
            canonical_signed_material(signed),
            signing_key=key,
            namespace="0verse-0research-oracle-result-v1",
            label="test oracle result",
            inherit_environment=False,
        )
        receipt_path = Path("oracle") / f"{record['record_id']}.receipt.json"
        receipt_bytes = (json.dumps(signed, sort_keys=True, separators=(",", ":")) + "\n").encode()
        (root / receipt_path).write_bytes(receipt_bytes)
        record["oracle_receipt"] = {
            "path": receipt_path.as_posix(),
            "sha256": _digest(receipt_bytes),
        }
    bundle = root / "learning-bundle.json"
    bundle.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "contract": "0verse-learning-bundle-v1",
                "records": selected,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _, tree_digest, _ = research_feedback._sealed_output_tree(root)
    projection = tmp_path / "projection.json"
    projection.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "kind": "0verse-feedback-projection",
                "runKey": f"0research-{'a' * 64}",
                "terminalReceiptDigest": _digest(b"terminal"),
                "itemId": "zeroverse-1",
                "attempt": 1,
                "payloadDigest": _digest(b"payload"),
                "adapterReceiptDigest": _digest(b"adapter"),
                "evidenceDigest": _digest(bundle.read_bytes()),
                "outputTreeDigest": tree_digest,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return projection, bundle, root, policy


def test_import_retains_bound_outcomes_atomically_and_idempotently(tmp_path: Path) -> None:
    rows = [
        _record(),
        _record(verdict="pruned", oracle="angr-reachability(UNSAT)"),
    ]
    rows[1]["record_id"] = "unsat-record"
    projection, bundle, root, policy = _fixture(tmp_path, rows)
    ledger = tmp_path / "private" / "learning.ndjson"

    first = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=policy,
    )
    assert first.records_written == 2
    assert first.evaluation is False
    learned = list(dataset.iter_records(ledger))
    assert len(learned) == 2
    assert all(row["event_id"].startswith("sha256:") for row in learned)
    assert all(row["provenance"]["runKey"] == f"0research-{'a' * 64}" for row in learned)
    confirmed = next(row for row in learned if row["verdict"] == "confirmed")
    assert Path(confirmed["pov"]["path"]).is_absolute()
    assert (
        confirmed["pov"]["sha256"]
        == hashlib.sha256((root / "povs" / "replay.py").read_bytes()).hexdigest()
    )
    mode = ledger.stat().st_mode & 0o777
    assert mode == 0o600

    second = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=policy,
    )
    assert second.records_written == 0
    assert second.ledger_digest == first.ledger_digest
    assert list(dataset.iter_records(ledger)) == learned


def test_generic_or_unverified_outcomes_cannot_create_learning(tmp_path: Path) -> None:
    for row in (
        _record(verdict="hypothesis", oracle="llm-triage"),
        _record(verdict="pruned", oracle="scheduler-reject"),
        _record(verdict="confirmed", oracle="scheduler-pass"),
    ):
        projection, bundle, root, policy = _fixture(tmp_path / row["oracle"], [row])
        with pytest.raises(ValueError):
            research_feedback.import_feedback(
                projection_path=projection,
                bundle_path=bundle,
                output_root=root,
                ledger_path=tmp_path / "ledger.ndjson",
                oracle_allowed_signers=policy,
            )
    assert not (tmp_path / "ledger.ndjson").exists()


def test_projection_identity_and_nested_base64_are_rejected(tmp_path: Path) -> None:
    row = _record()
    row["features"]["mitigations"] = {"terminalReceiptBase64": "hidden"}
    projection, bundle, root, policy = _fixture(tmp_path / "base64", [row])
    with pytest.raises(ValueError, match="base64-bearing"):
        research_feedback.import_feedback(
            projection_path=projection,
            bundle_path=bundle,
            output_root=root,
            ledger_path=tmp_path / "ledger.ndjson",
            oracle_allowed_signers=policy,
        )

    projection, bundle, root, policy = _fixture(tmp_path / "identity")
    raw = json.loads(projection.read_text(encoding="utf-8"))
    raw["runKey"] = "run-1"
    projection.write_text(json.dumps(raw) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="content key"):
        research_feedback.import_feedback(
            projection_path=projection,
            bundle_path=bundle,
            output_root=root,
            ledger_path=tmp_path / "ledger.ndjson",
            oracle_allowed_signers=policy,
        )


def test_projection_and_tree_bindings_fail_closed(tmp_path: Path) -> None:
    projection, bundle, root, policy = _fixture(tmp_path)
    ledger = tmp_path / "ledger.ndjson"
    bundle.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="output-tree digest"):
        research_feedback.import_feedback(
            projection_path=projection,
            bundle_path=bundle,
            output_root=root,
            ledger_path=ledger,
            oracle_allowed_signers=policy,
        )
    assert not ledger.exists()


def test_pov_must_be_relative_digest_bound_and_not_a_symlink(tmp_path: Path) -> None:
    row = _record()
    row["pov"]["path"] = "../escape.py"
    projection, bundle, root, policy = _fixture(tmp_path / "traversal", [row])
    with pytest.raises(ValueError, match="traversal-free"):
        research_feedback.import_feedback(
            projection_path=projection,
            bundle_path=bundle,
            output_root=root,
            ledger_path=tmp_path / "ledger.ndjson",
            oracle_allowed_signers=policy,
        )

    projection, bundle, root, policy = _fixture(tmp_path / "symlink")
    replay = root / "povs" / "replay.py"
    replay.unlink()
    replay.symlink_to(tmp_path / "outside.py")
    with pytest.raises(ValueError, match="symlink"):
        research_feedback.import_feedback(
            projection_path=projection,
            bundle_path=bundle,
            output_root=root,
            ledger_path=tmp_path / "ledger.ndjson",
            oracle_allowed_signers=policy,
        )


def test_evaluation_mode_verifies_but_never_writes(tmp_path: Path, monkeypatch) -> None:
    row = _record()
    row["synthetic"] = True
    projection, bundle, root, policy = _fixture(tmp_path, [row])
    ledger = tmp_path / "ledger.ndjson"
    existing = (json.dumps(_record(), separators=(", ", ": ")) + "\n").encode()
    ledger.write_bytes(existing)
    monkeypatch.setenv("ZEROVERSE_EVALUATION", "1")
    receipt = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=policy,
    )
    assert receipt.evaluation is True
    assert receipt.records_written == 0
    assert receipt.ledger_digest == _digest(existing)
    assert ledger.read_bytes() == existing


def test_synthetic_feedback_is_rejected_outside_evaluation(tmp_path: Path) -> None:
    row = _record()
    row["synthetic"] = True
    projection, bundle, root, policy = _fixture(tmp_path, [row])
    ledger = tmp_path / "ledger.ndjson"
    with pytest.raises(ValueError, match="not production learning"):
        research_feedback.import_feedback(
            projection_path=projection,
            bundle_path=bundle,
            output_root=root,
            ledger_path=ledger,
            oracle_allowed_signers=policy,
        )
    assert not ledger.exists()


def test_untrusted_oracle_signer_cannot_create_learning(tmp_path: Path) -> None:
    projection, bundle, root, _ = _fixture(tmp_path / "signed")
    _, _, _, wrong_policy = _fixture(tmp_path / "wrong")
    ledger = tmp_path / "ledger.ndjson"
    with pytest.raises(ValueError, match="signature is invalid"):
        research_feedback.import_feedback(
            projection_path=projection,
            bundle_path=bundle,
            output_root=root,
            ledger_path=ledger,
            oracle_allowed_signers=wrong_policy,
        )
    assert not ledger.exists()


def test_ledger_digest_is_exact_and_growth_cannot_write_an_unreadable_segment(
    tmp_path: Path, monkeypatch
) -> None:
    projection, bundle, root, policy = _fixture(tmp_path)
    ledger = tmp_path / "ledger.ndjson"
    first = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=policy,
    )
    row = json.loads(ledger.read_text(encoding="utf-8"))
    noncanonical = (json.dumps(row, sort_keys=False, separators=(", ", ": ")) + "\n").encode()
    ledger.write_bytes(noncanonical)
    second = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=policy,
    )
    assert second.records_written == 0
    assert second.ledger_digest == _digest(noncanonical)
    assert first.ledger_digest != second.ledger_digest

    before = ledger.read_bytes()
    other = _record()
    other["binary_name"] = "second-target"
    other["record_id"] = "second-record"
    projection2, bundle2, root2, policy2 = _fixture(tmp_path / "other", [other])
    monkeypatch.setattr(research_feedback, "_MAX_LEDGER_BYTES", len(before) + 1)
    with pytest.raises(ValueError, match="rotate to a new segment"):
        research_feedback.import_feedback(
            projection_path=projection2,
            bundle_path=bundle2,
            output_root=root2,
            ledger_path=ledger,
            oracle_allowed_signers=policy2,
        )
    assert ledger.read_bytes() == before


def test_legacy_ledger_rows_are_preserved_and_semantic_duplicates_collapse(
    tmp_path: Path,
) -> None:
    first = _record()
    duplicate = json.loads(json.dumps(first))
    projection, bundle, root, policy = _fixture(tmp_path, [first, duplicate])
    ledger = tmp_path / "learning.ndjson"
    legacy = _record(verdict="pruned", oracle="angr-reachability(UNSAT)")
    legacy["record_id"] = "legacy-v1.1"
    legacy["dataset_version"] = "1.1"
    ledger.write_text(json.dumps(legacy, sort_keys=True) + "\n", encoding="utf-8")

    receipt = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=policy,
    )
    assert receipt.records_written == 1
    learned = list(dataset.iter_records(ledger))
    assert len(learned) == 2
    assert learned[0]["record_id"] == "legacy-v1.1"
    assert learned[1]["record_id"] == "feedback-record"


def test_fresh_scheduler_projection_cannot_replay_amplify_signed_learning(
    tmp_path: Path,
) -> None:
    projection, bundle, root, policy = _fixture(tmp_path)
    ledger = tmp_path / "ledger.ndjson"
    first = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=policy,
    )
    projected = json.loads(projection.read_text(encoding="utf-8"))
    projected["runKey"] = f"0research-{'b' * 64}"
    projected["terminalReceiptDigest"] = _digest(b"different-terminal")
    projection.write_text(json.dumps(projected, sort_keys=True) + "\n", encoding="utf-8")
    second = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=policy,
    )
    assert first.records_written == 1
    assert second.records_written == 0
    assert second.event_ids == first.event_ids
    assert len(list(dataset.iter_records(ledger))) == 1


def test_cli_emits_content_addressed_write_receipt(tmp_path: Path, capsys, monkeypatch) -> None:
    projection, bundle, root, policy = _fixture(tmp_path)
    monkeypatch.setattr(research_feedback, "_DEFAULT_ORACLE_ALLOWED_SIGNERS", policy)
    ledger = tmp_path / "ledger.ndjson"
    assert (
        main(
            [
                "research-feedback-import",
                "--projection",
                str(projection),
                "--bundle",
                str(bundle),
                "--output-root",
                str(root),
                "--ledger",
                str(ledger),
            ]
        )
        == 0
    )
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["contract"] == "0verse-learning-write-receipt-v1"
    assert receipt["recordsWritten"] == 1
    digest = receipt.pop("receiptDigest")
    canonical = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    assert digest == _digest(canonical)
    assert receipt["authority"] == {
        "gradesCandidates": False,
        "promotesCandidates": False,
        "publishesExternally": False,
        "writesGitHub": False,
    }


def test_issues_one_signed_admission_per_verified_scientific_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = [
        _record(),
        _record(verdict="pruned", oracle="angr-reachability(UNSAT)"),
    ]
    rows[1]["record_id"] = "unsat-record"
    projection, bundle, root, oracle_policy = _fixture(tmp_path, rows)
    principal, evidence_policy, signer = _evidence_signer(tmp_path)
    ledger = tmp_path / "learning.ndjson"
    imported = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=oracle_policy,
    )
    snapshot, snapshot_policy = _target_snapshot(tmp_path, imported.event_ids)
    admission_parent = tmp_path / "private-admissions"
    admission_parent.mkdir(mode=0o700)
    output = admission_parent / "batch"
    monkeypatch.setenv("ZEROVERSE_LEARNING_PATH", str(ledger))

    admissions = research_admission.issue_feedback_admissions(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        target_snapshot_path=snapshot,
        admission_output=output,
        oracle_allowed_signers=oracle_policy,
        target_snapshot_allowed_signers=snapshot_policy,
        evidence_allowed_signers=evidence_policy,
        evidence_principal=principal,
        signer=signer,
    )

    assert sorted(item["outcome"] for item in admissions) == ["confirmed", "refuted"]
    assert all(item["kind"] == "zeroverse_scientific_event" for item in admissions)
    assert {item["sourceArtifactDigest"] for item in admissions} == set(imported.event_ids)
    assert all(item["observedAt"] == "2026-07-18T00:00:00.000Z" for item in admissions)
    assert all(item["synthetic"] is False for item in admissions)
    assert all(item["authority"]["learningPromotionAllowed"] is False for item in admissions)
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    verified = research_admission.verify_feedback_admission_bundle(
        output, evidence_allowed_signers=evidence_policy
    )
    assert verified.manifest == manifest
    first_admission_path = manifest["admissions"][0]["admissionPath"]
    captured_admission = verified.read_bytes(first_admission_path)
    (output / first_admission_path).write_bytes(b"mutated after verified capture\n")
    assert verified.read_bytes(first_admission_path) == captured_admission
    (output / first_admission_path).write_bytes(captured_admission)
    assert manifest["contract"] == "0verse-research-admission-bundle-v2"
    assert manifest["schemaVersion"] == 2
    assert len(manifest["admissions"]) == 2
    assert sorted(path.name for path in output.iterdir()) == ["manifest.json", "payload"]
    assert (
        research_feedback._sealed_output_tree(output / "payload" / "source")[1]
        == manifest["sourceTreeDigest"]
    )
    assert (
        research_feedback._sealed_output_tree(output / "payload")[1]
        == manifest["payloadTreeDigest"]
    )
    ledger_bytes = (output / manifest["sourcePaths"]["productionLedger"]).read_bytes()
    membership_bytes = (output / manifest["sourcePaths"]["ledgerMembership"]).read_bytes()
    assert ledger_bytes == ledger.read_bytes()
    assert manifest["ledgerSnapshotDigest"] == _digest(ledger_bytes)
    assert manifest["ledgerMembershipDigest"] == _digest(membership_bytes)
    memberships = json.loads(membership_bytes)
    assert len(memberships) == 2
    ledger_lines = ledger_bytes.splitlines(keepends=True)
    for membership in memberships:
        assert membership["rawLineDigest"] == _digest(ledger_lines[membership["lineOrdinal"]])
    assert manifest["authority"] == admissions[0]["authority"]
    assert all(
        json.loads((output / item["verificationPath"]).read_text())["authority"]
        == admissions[0]["authority"]
        for item in manifest["admissions"]
    )
    assert set(manifest["policyDigests"]) == {"evidence", "oracle", "target-snapshot"}
    for role, relative in manifest["sourcePaths"]["policies"].items():
        assert manifest["policyDigests"][role] == _digest((output / relative).read_bytes())
    assert all(
        (output / item["admissionPath"]).stat().st_mode & 0o777 == 0o600
        for item in manifest["admissions"]
    )
    for item in manifest["admissions"]:
        receipt = json.loads((output / item["verificationPath"]).read_text(encoding="utf-8"))
        assert item["verificationReceiptDigest"] == _digest(
            (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        assert item["admissionSignedArtifactDigest"] == _digest(
            (output / item["admissionPath"]).read_bytes()
        )
        assert item["verificationSignedArtifactDigest"] == _digest(
            (output / item["verificationPath"]).read_bytes()
        )


def test_native_admission_matches_0brain_cross_language_golden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_path = (
        Path(__file__).parent
        / "fixtures"
        / "0research"
        / "zeroverse-scientific-event-admission-v1.json"
    )
    golden = json.loads(fixture_path.read_text(encoding="utf-8"))
    expected = golden["admission"]
    event = research_feedback.VerifiedFeedbackEvent(
        record={
            "event_id": "sha256:" + "1" * 64,
            "created_at": "2026-07-18T00:00:00+00:00",
            "verdict": "confirmed",
            "oracle": "differential-crash",
            "oracle_evidence": {"sha256": "sha256:" + "4" * 64},
            "pov": {"sha256": "5" * 64},
            "synthetic": False,
        },
        source_artifact_digest="sha256:" + "2" * 64,
        verification_receipt_digest="sha256:" + "3" * 64,
    )

    expected_body = {key: value for key, value in expected.items() if key != "signatureSsh"}
    expected_material = research_admission._canonical(expected_body)
    expected_namespace = golden["signatureNamespace"]
    expected_principal = expected["principal"]
    expected_policy = "/fixture/evidence.allowed_signers"
    verifier_calls = 0

    def verify(material: bytes, signature: str, **kwargs) -> None:
        nonlocal verifier_calls
        verifier_calls += 1
        assert material == expected_material
        assert signature == expected["signatureSsh"]
        assert kwargs["identity"] == expected_principal
        assert kwargs["namespace"] == expected_namespace
        assert kwargs["allowed_signers"] == expected_policy

    monkeypatch.setattr(research_admission, "verify_ssh_signature", verify)

    def signer(material: bytes, identity: str, namespace: str) -> str:
        assert material == expected_material
        assert identity == expected_principal
        assert namespace == expected_namespace
        return expected["signatureSsh"]

    admissions = research_admission._signed_admissions(
        (event,),
        "sha256:" + "6" * 64,
        expected_principal,
        expected_policy,
        signer,
        lambda _label: None,
    )

    assert golden["schemaVersion"] == 1
    assert golden["contract"] == "0verse-0brain-admission-golden-v1"
    assert _digest(expected_material) == golden["signedMaterialDigest"]
    assert admissions[0][0] == golden["admissionDigest"]
    assert admissions[0][3] == expected
    assert verifier_calls == 1


@pytest.mark.parametrize(
    "algorithm",
    ["ssh-rsa", "ecdsa-sha2-nistp256", "sk-ssh-ed25519@openssh.com"],
)
def test_admission_evidence_policy_matches_0brain_plain_ed25519_contract(
    tmp_path: Path, algorithm: str
) -> None:
    policy = tmp_path / "evidence.allowed_signers"
    policy.write_text(
        f"0research-zeroverse-evidence@test {algorithm} fixture-key\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="only plain ssh-ed25519"):
        research_admission._require_plain_ed25519_policy(policy)


def test_admission_evidence_policy_rejects_mixed_unsupported_lines(tmp_path: Path) -> None:
    policy = tmp_path / "evidence.allowed_signers"
    policy.write_text(
        "reviewer ssh-ed25519 AAAA\nlegacy ssh-dss AAAABOGUS\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="only plain ssh-ed25519"):
        research_admission._require_plain_ed25519_policy(policy)


def test_admission_identity_ignores_scheduler_transport_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projection, bundle, root, oracle_policy = _fixture(tmp_path)
    principal, evidence_policy, signer = _evidence_signer(tmp_path)
    ledger = tmp_path / "learning.ndjson"
    imported = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=oracle_policy,
    )
    snapshot, snapshot_policy = _target_snapshot(tmp_path, imported.event_ids)
    parent = tmp_path / "admissions"
    parent.mkdir(mode=0o700)
    monkeypatch.setenv("ZEROVERSE_LEARNING_PATH", str(ledger))
    first = research_admission.issue_feedback_admissions(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        target_snapshot_path=snapshot,
        admission_output=parent / "first",
        oracle_allowed_signers=oracle_policy,
        target_snapshot_allowed_signers=snapshot_policy,
        evidence_allowed_signers=evidence_policy,
        evidence_principal=principal,
        signer=signer,
    )
    projected = json.loads(projection.read_text(encoding="utf-8"))
    projected["runKey"] = f"0research-{'b' * 64}"
    projected["terminalReceiptDigest"] = _digest(b"different-terminal")
    projection.write_text(json.dumps(projected, sort_keys=True) + "\n", encoding="utf-8")
    second = research_admission.issue_feedback_admissions(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        target_snapshot_path=snapshot,
        admission_output=parent / "second",
        oracle_allowed_signers=oracle_policy,
        target_snapshot_allowed_signers=snapshot_policy,
        evidence_allowed_signers=evidence_policy,
        evidence_principal=principal,
        signer=signer,
    )
    assert first == second


def test_admission_signing_failure_leaves_no_committed_partial_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projection, bundle, root, oracle_policy = _fixture(tmp_path)
    principal, evidence_policy, _ = _evidence_signer(tmp_path)
    ledger = tmp_path / "learning.ndjson"
    imported = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=oracle_policy,
    )
    snapshot, snapshot_policy = _target_snapshot(tmp_path, imported.event_ids)
    parent = tmp_path / "admissions"
    parent.mkdir(mode=0o700)
    output = parent / "failed"
    monkeypatch.setenv("ZEROVERSE_LEARNING_PATH", str(ledger))

    def fail(_material: bytes, _principal: str, _namespace: str) -> str:
        raise ValueError("signer unavailable")

    with pytest.raises(ValueError, match="signer unavailable"):
        research_admission.issue_feedback_admissions(
            projection_path=projection,
            bundle_path=bundle,
            output_root=root,
            target_snapshot_path=snapshot,
            admission_output=output,
            oracle_allowed_signers=oracle_policy,
            target_snapshot_allowed_signers=snapshot_policy,
            evidence_allowed_signers=evidence_policy,
            evidence_principal=principal,
            signer=fail,
        )
    assert not output.exists()
    assert not any(parent.iterdir())


def test_admission_reserves_destination_before_signing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projection, bundle, root, oracle_policy = _fixture(tmp_path)
    principal, evidence_policy, real_signer = _evidence_signer(tmp_path)
    ledger = tmp_path / "learning.ndjson"
    imported = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=oracle_policy,
    )
    snapshot, snapshot_policy = _target_snapshot(tmp_path, imported.event_ids)
    parent = tmp_path / "admissions"
    parent.mkdir(mode=0o700)
    output = parent / "concurrent"
    monkeypatch.setenv("ZEROVERSE_LEARNING_PATH", str(ledger))
    real_signatures = 0

    def racing_signer(material: bytes, identity: str, namespace: str) -> str:
        nonlocal real_signatures
        output.mkdir()
        real_signatures += 1
        return real_signer(material, identity, namespace)

    with pytest.raises(FileExistsError):
        research_admission.issue_feedback_admissions(
            projection_path=projection,
            bundle_path=bundle,
            output_root=root,
            target_snapshot_path=snapshot,
            admission_output=output,
            oracle_allowed_signers=oracle_policy,
            target_snapshot_allowed_signers=snapshot_policy,
            evidence_allowed_signers=evidence_policy,
            evidence_principal=principal,
            signer=racing_signer,
        )
    assert real_signatures == 0
    assert not output.exists()
    assert not any(parent.iterdir())


@pytest.mark.parametrize("sign_after_replacement", [False, True])
def test_admission_preserves_replacement_of_pinned_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sign_after_replacement: bool,
) -> None:
    projection, bundle, root, oracle_policy = _fixture(tmp_path)
    principal, evidence_policy, real_signer = _evidence_signer(tmp_path)
    ledger = tmp_path / "learning.ndjson"
    imported = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=oracle_policy,
    )
    snapshot, snapshot_policy = _target_snapshot(tmp_path, imported.event_ids)
    parent = tmp_path / "admissions"
    parent.mkdir(mode=0o700)
    output = parent / "replaced"
    monkeypatch.setenv("ZEROVERSE_LEARNING_PATH", str(ledger))

    def replacing_signer(material: bytes, identity: str, namespace: str) -> str:
        output.rmdir()
        output.mkdir()
        (output / "sentinel").write_text("foreign writer\n", encoding="utf-8")
        if sign_after_replacement:
            return real_signer(material, identity, namespace)
        raise ValueError("signer stopped after replacement")

    expected = (
        "reservation changed during evidence signing"
        if sign_after_replacement
        else "signer stopped after replacement"
    )
    with pytest.raises(ValueError, match=expected):
        research_admission.issue_feedback_admissions(
            projection_path=projection,
            bundle_path=bundle,
            output_root=root,
            target_snapshot_path=snapshot,
            admission_output=output,
            oracle_allowed_signers=oracle_policy,
            target_snapshot_allowed_signers=snapshot_policy,
            evidence_allowed_signers=evidence_policy,
            evidence_principal=principal,
            signer=replacing_signer,
        )
    assert (output / "sentinel").read_text(encoding="utf-8") == "foreign writer\n"
    assert sorted(path.name for path in parent.iterdir()) == ["replaced"]


def test_admission_signer_cannot_mutate_retained_native_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projection, bundle, root, oracle_policy = _fixture(tmp_path)
    principal, evidence_policy, real_signer = _evidence_signer(tmp_path)
    ledger = tmp_path / "learning.ndjson"
    imported = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=oracle_policy,
    )
    snapshot, snapshot_policy = _target_snapshot(tmp_path, imported.event_ids)
    parent = tmp_path / "admissions"
    parent.mkdir(mode=0o700)
    output = parent / "mutated"
    monkeypatch.setenv("ZEROVERSE_LEARNING_PATH", str(ledger))

    def mutating_signer(material: bytes, identity: str, namespace: str) -> str:
        stage = next(path for path in parent.iterdir() if path.name.startswith(".mutated.tmp-"))
        retained_bundle = stage / "payload" / "source" / "output" / bundle.relative_to(root)
        retained_bundle.write_bytes(retained_bundle.read_bytes() + b"mutation\n")
        return real_signer(material, identity, namespace)

    with pytest.raises(ValueError, match="retained source tree changed during evidence signing"):
        research_admission.issue_feedback_admissions(
            projection_path=projection,
            bundle_path=bundle,
            output_root=root,
            target_snapshot_path=snapshot,
            admission_output=output,
            oracle_allowed_signers=oracle_policy,
            target_snapshot_allowed_signers=snapshot_policy,
            evidence_allowed_signers=evidence_policy,
            evidence_principal=principal,
            signer=mutating_signer,
        )
    assert not output.exists()
    assert not any(parent.iterdir())


def test_native_verifier_mutation_blocks_the_evidence_signer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projection, bundle, root, oracle_policy = _fixture(tmp_path)
    principal, evidence_policy, real_signer = _evidence_signer(tmp_path)
    ledger = tmp_path / "learning.ndjson"
    imported = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=oracle_policy,
    )
    snapshot, snapshot_policy = _target_snapshot(tmp_path, imported.event_ids)
    parent = tmp_path / "admissions"
    parent.mkdir(mode=0o700)
    output = parent / "verifier-mutation"
    monkeypatch.setenv("ZEROVERSE_LEARNING_PATH", str(ledger))
    real_verifier = research_feedback.verify_ssh_signature
    signer_calls = 0
    mutated = False

    def mutating_verifier(*args, **kwargs) -> None:
        nonlocal mutated
        real_verifier(*args, **kwargs)
        if not mutated and kwargs.get("namespace") == "0verse-0research-oracle-result-v1":
            stage = next(
                path for path in parent.iterdir() if path.name.startswith(".verifier-mutation.tmp-")
            )
            retained = stage / "payload" / "source" / "projection.json"
            retained.write_bytes(retained.read_bytes() + b"mutation\n")
            mutated = True

    def counting_signer(material: bytes, identity: str, namespace: str) -> str:
        nonlocal signer_calls
        signer_calls += 1
        return real_signer(material, identity, namespace)

    monkeypatch.setattr(research_feedback, "verify_ssh_signature", mutating_verifier)
    with pytest.raises(ValueError, match="retained source tree changed during native verification"):
        research_admission.issue_feedback_admissions(
            projection_path=projection,
            bundle_path=bundle,
            output_root=root,
            target_snapshot_path=snapshot,
            admission_output=output,
            oracle_allowed_signers=oracle_policy,
            target_snapshot_allowed_signers=snapshot_policy,
            evidence_allowed_signers=evidence_policy,
            evidence_principal=principal,
            signer=counting_signer,
        )
    assert signer_calls == 0
    assert not output.exists()


def test_admission_signer_cannot_drift_the_locked_production_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projection, bundle, root, oracle_policy = _fixture(tmp_path)
    principal, evidence_policy, real_signer = _evidence_signer(tmp_path)
    ledger = tmp_path / "learning.ndjson"
    imported = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=oracle_policy,
    )
    snapshot, snapshot_policy = _target_snapshot(tmp_path, imported.event_ids)
    parent = tmp_path / "admissions"
    parent.mkdir(mode=0o700)
    output = parent / "ledger-mutation"
    monkeypatch.setenv("ZEROVERSE_LEARNING_PATH", str(ledger))

    def mutating_signer(material: bytes, identity: str, namespace: str) -> str:
        row = json.loads(ledger.read_text(encoding="utf-8"))
        row["explanation"] = "mutated while the admission signer ran"
        ledger.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
        return real_signer(material, identity, namespace)

    with pytest.raises(ValueError, match="production ledger changed during admission signing"):
        research_admission.issue_feedback_admissions(
            projection_path=projection,
            bundle_path=bundle,
            output_root=root,
            target_snapshot_path=snapshot,
            admission_output=output,
            oracle_allowed_signers=oracle_policy,
            target_snapshot_allowed_signers=snapshot_policy,
            evidence_allowed_signers=evidence_policy,
            evidence_principal=principal,
            signer=mutating_signer,
        )
    assert not output.exists()


@pytest.mark.parametrize("mutated_part", ["payload", "manifest"])
def test_final_package_recheck_blocks_delayed_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutated_part: str
) -> None:
    projection, bundle, root, oracle_policy = _fixture(tmp_path)
    principal, evidence_policy, signer = _evidence_signer(tmp_path)
    ledger = tmp_path / "learning.ndjson"
    imported = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=oracle_policy,
    )
    snapshot, snapshot_policy = _target_snapshot(tmp_path, imported.event_ids)
    parent = tmp_path / "admissions"
    parent.mkdir(mode=0o700)
    output = parent / f"delayed-{mutated_part}"
    monkeypatch.setenv("ZEROVERSE_LEARNING_PATH", str(ledger))
    real_write = research_admission._write_bytes_exclusive_at

    def mutating_write(directory: int, name: str, payload: bytes) -> None:
        real_write(directory, name, payload)
        if name != "manifest.json":
            return
        stage = next(
            path
            for path in parent.iterdir()
            if path.name.startswith(f".delayed-{mutated_part}.tmp-")
        )
        if mutated_part == "manifest":
            (stage / "manifest.json").write_bytes((stage / "manifest.json").read_bytes() + b"x")
        else:
            admission = next((stage / "payload").glob("*.admission.json"))
            admission.write_bytes(admission.read_bytes() + b"x")

    monkeypatch.setattr(research_admission, "_write_bytes_exclusive_at", mutating_write)
    with pytest.raises(ValueError, match="payload or manifest changed before commit"):
        research_admission.issue_feedback_admissions(
            projection_path=projection,
            bundle_path=bundle,
            output_root=root,
            target_snapshot_path=snapshot,
            admission_output=output,
            oracle_allowed_signers=oracle_policy,
            target_snapshot_allowed_signers=snapshot_policy,
            evidence_allowed_signers=evidence_policy,
            evidence_principal=principal,
            signer=signer,
        )
    assert not output.exists()


@pytest.mark.parametrize("mutated_part", ["payload", "manifest"])
def test_package_root_rejects_postpublication_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutated_part: str
) -> None:
    projection, bundle, root, oracle_policy = _fixture(tmp_path)
    principal, evidence_policy, signer = _evidence_signer(tmp_path)
    ledger = tmp_path / "learning.ndjson"
    imported = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=oracle_policy,
    )
    snapshot, snapshot_policy = _target_snapshot(tmp_path, imported.event_ids)
    parent = tmp_path / "admissions"
    parent.mkdir(mode=0o700)
    output = parent / f"published-{mutated_part}"
    monkeypatch.setenv("ZEROVERSE_LEARNING_PATH", str(ledger))
    research_admission.issue_feedback_admissions(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        target_snapshot_path=snapshot,
        admission_output=output,
        oracle_allowed_signers=oracle_policy,
        target_snapshot_allowed_signers=snapshot_policy,
        evidence_allowed_signers=evidence_policy,
        evidence_principal=principal,
        signer=signer,
    )
    if mutated_part == "manifest":
        manifest = json.loads((output / "manifest.json").read_bytes())
        manifest["sourceTreeDigest"] = _digest(b"forged source")
        (output / "manifest.json").write_bytes(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
        message = "package root SSH signature is invalid"
    else:
        admission = next((output / "payload").glob("*.admission.json"))
        admission.write_bytes(admission.read_bytes() + b"x")
        message = "payload root is invalid"
    with pytest.raises(ValueError, match=message):
        research_admission.verify_feedback_admission_bundle(
            output, evidence_allowed_signers=evidence_policy
        )


def test_package_file_limit_reserves_generated_artifacts_before_signing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projection, bundle, root, oracle_policy = _fixture(tmp_path)
    principal, evidence_policy, real_signer = _evidence_signer(tmp_path)
    ledger = tmp_path / "learning.ndjson"
    imported = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=oracle_policy,
    )
    snapshot, snapshot_policy = _target_snapshot(tmp_path, imported.event_ids)
    _, _, output_files = research_feedback._sealed_output_tree(root)
    _, target_files = research_admission._target_snapshot_sources(snapshot)
    source_files = 1 + len(output_files) + len(target_files) + 3
    required_files = source_files + 2 + (2 * len(imported.event_ids)) + 1
    monkeypatch.setattr(research_admission, "_MAX_PROVENANCE_FILES", required_files - 1)
    monkeypatch.setenv("ZEROVERSE_LEARNING_PATH", str(ledger))
    signer_calls = 0

    def counting_signer(material: bytes, identity: str, namespace: str) -> str:
        nonlocal signer_calls
        signer_calls += 1
        return real_signer(material, identity, namespace)

    parent = tmp_path / "admissions"
    parent.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="package file limit"):
        research_admission.issue_feedback_admissions(
            projection_path=projection,
            bundle_path=bundle,
            output_root=root,
            target_snapshot_path=snapshot,
            admission_output=parent / "blocked",
            oracle_allowed_signers=oracle_policy,
            target_snapshot_allowed_signers=snapshot_policy,
            evidence_allowed_signers=evidence_policy,
            evidence_principal=principal,
            signer=counting_signer,
        )
    assert signer_calls == 0


def test_sealed_output_tree_enforces_aggregate_caps_while_capturing(tmp_path: Path) -> None:
    root = tmp_path / "bounded"
    root.mkdir()
    (root / "a").write_bytes(b"1234")
    (root / "b").write_bytes(b"5")
    with pytest.raises(ValueError, match="total byte limit"):
        research_feedback._sealed_output_tree(root, max_total_bytes=3)
    with pytest.raises(ValueError, match="file limit"):
        research_feedback._sealed_output_tree(root, max_files=1)
    with pytest.raises(ValueError, match="entry limit"):
        research_feedback._sealed_output_tree(root, max_entries=1)
    nested = root / "nested"
    nested.mkdir()
    (nested / "leaf").write_bytes(b"leaf")
    with pytest.raises(ValueError, match="depth limit"):
        research_feedback._sealed_output_tree(root, max_depth=0)


def test_oracle_and_admission_authorities_must_be_key_disjoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projection, bundle, root, oracle_policy = _fixture(tmp_path)
    principal, _, signer = _evidence_signer(tmp_path)
    ledger = tmp_path / "learning.ndjson"
    imported = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=oracle_policy,
    )
    snapshot, snapshot_policy = _target_snapshot(tmp_path, imported.event_ids)
    overlapping_policy = tmp_path / "overlapping-evidence.allowed_signers"
    overlapping_policy.write_bytes(oracle_policy.read_bytes())
    parent = tmp_path / "admissions"
    parent.mkdir(mode=0o700)
    monkeypatch.setenv("ZEROVERSE_LEARNING_PATH", str(ledger))
    with pytest.raises(ValueError, match="signer keys overlap"):
        research_admission.issue_feedback_admissions(
            projection_path=projection,
            bundle_path=bundle,
            output_root=root,
            target_snapshot_path=snapshot,
            admission_output=parent / "blocked",
            oracle_allowed_signers=oracle_policy,
            target_snapshot_allowed_signers=snapshot_policy,
            evidence_allowed_signers=overlapping_policy,
            evidence_principal=principal,
            signer=signer,
        )


def test_target_snapshot_tampering_and_noncanonical_event_time_reject_before_signing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projection, bundle, root, oracle_policy = _fixture(tmp_path / "tamper")
    principal, evidence_policy, real_signer = _evidence_signer(tmp_path / "tamper")
    ledger = tmp_path / "tamper" / "learning.ndjson"
    imported = research_feedback.import_feedback(
        projection_path=projection,
        bundle_path=bundle,
        output_root=root,
        ledger_path=ledger,
        oracle_allowed_signers=oracle_policy,
    )
    snapshot, snapshot_policy = _target_snapshot(tmp_path / "tamper", imported.event_ids)
    (snapshot.parent / "package.bin").write_bytes(b"substituted\n")
    calls = 0

    def counting_signer(material: bytes, identity: str, namespace: str) -> str:
        nonlocal calls
        calls += 1
        return real_signer(material, identity, namespace)

    parent = tmp_path / "tamper" / "admissions"
    parent.mkdir(mode=0o700)
    monkeypatch.setenv("ZEROVERSE_LEARNING_PATH", str(ledger))
    with pytest.raises(ValueError, match="package bytes drift"):
        research_admission.issue_feedback_admissions(
            projection_path=projection,
            bundle_path=bundle,
            output_root=root,
            target_snapshot_path=snapshot,
            admission_output=parent / "blocked",
            oracle_allowed_signers=oracle_policy,
            target_snapshot_allowed_signers=snapshot_policy,
            evidence_allowed_signers=evidence_policy,
            evidence_principal=principal,
            signer=counting_signer,
        )
    assert calls == 0

    row = _record()
    row["created_at"] = "2026-07-18T00:00:00"
    projection2, bundle2, root2, oracle2 = _fixture(tmp_path / "time", [row])
    principal2, evidence2, signer2 = _evidence_signer(tmp_path / "time")
    ledger2 = tmp_path / "time" / "learning.ndjson"
    imported2 = research_feedback.import_feedback(
        projection_path=projection2,
        bundle_path=bundle2,
        output_root=root2,
        ledger_path=ledger2,
        oracle_allowed_signers=oracle2,
    )
    snapshot2, snapshot_policy2 = _target_snapshot(tmp_path / "time", imported2.event_ids)
    parent2 = tmp_path / "time" / "admissions"
    parent2.mkdir(mode=0o700)
    monkeypatch.setenv("ZEROVERSE_LEARNING_PATH", str(ledger2))
    with pytest.raises(ValueError, match="include a timezone"):
        research_admission.issue_feedback_admissions(
            projection_path=projection2,
            bundle_path=bundle2,
            output_root=root2,
            target_snapshot_path=snapshot2,
            admission_output=parent2 / "blocked",
            oracle_allowed_signers=oracle2,
            target_snapshot_allowed_signers=snapshot_policy2,
            evidence_allowed_signers=evidence2,
            evidence_principal=principal2,
            signer=signer2,
        )
    assert not (parent2 / "blocked").exists()

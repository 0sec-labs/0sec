from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest

from zeroverse.elf_campaign import ElfArtifactIdentity, ElfCampaign, load_campaign

ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN = ROOT / "campaigns" / "elf" / "openthread-radio-regression-20260715"
HANDOFF = CAMPAIGN / "sustained-authorization"
PREFLIGHT = HANDOFF / "preflight.py"
NOW = datetime(2026, 7, 15, 20, 0, tzinfo=UTC)


def _run(*arguments: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(PREFLIGHT), *(str(item) for item in arguments)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def _run_fixture(*arguments: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(PREFLIGHT), *(str(item) for item in arguments)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "ZEROVERSE_OPENTHREAD_PREFLIGHT_FIXTURE_ONLY": "1"},
    )


def _preflight_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("openthread_preflight_test", PREFLIGHT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _key_and_policy(tmp_path: Path, stem: str, identity: str) -> tuple[Path, Path]:
    key = tmp_path / stem
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    public = key.with_suffix(".pub").read_text().strip().split()
    policy = tmp_path / f"{stem}.allowed_signers"
    policy.write_text(f"{identity} {public[0]} {public[1]}\n")
    return key, policy


def _sign(material: Path, key: Path, namespace: str) -> Path:
    subprocess.run(
        ["ssh-keygen", "-q", "-Y", "sign", "-f", str(key), "-n", namespace, str(material)],
        check=True,
    )
    return Path(f"{material}.sig")


def test_unsigned_templates_are_exactly_pinned_and_fail_closed(tmp_path: Path) -> None:
    authorization = json.loads((HANDOFF / "authorization.unsigned.json").read_text())
    acceptance_path = HANDOFF / "worker-acceptance.unsigned.json"
    acceptance = json.loads(acceptance_path.read_text())
    manifest = json.loads((HANDOFF / "campaign.unsigned.json").read_text())
    assert manifest["authorization"] == authorization
    assert manifest["worker_acceptance_sha256"] == hashlib.sha256(
        acceptance_path.read_bytes()
    ).hexdigest()
    assert authorization["signature_ssh"] == acceptance["signature_ssh"] == "UNSIGNED"
    assert manifest["target"]["sha256"] == (
        "e828fdbefeb110f744ed5e107e661e1adc9406ce43bd1dc13914f64cb8897891"
    )
    assert manifest["control"]["sha256"] == (
        "30c98932be4435d516c07353d6ffb8379324723845220320752e240067f61f1f"
    )
    with pytest.raises(ValueError, match="RFC3339"):
        ElfCampaign.from_mapping(manifest, now=NOW)

    rendered = tmp_path / "rendered"
    result = _run(
        "render",
        "--output",
        rendered,
        "--checked-at",
        "2026-07-15T17:31:16Z",
        "--authorization-expires-at",
        "2026-07-16T17:30:00Z",
        "--accepted-at",
        "2026-07-15T19:05:00Z",
        "--acceptance-expires-at",
        "2026-07-16T17:30:00Z",
        "--now",
        "2026-07-15T20:00:00Z",
    )
    assert result.returncode == 0, result.stderr
    fake_signature = tmp_path / "fake.sig"
    fake_signature.write_text("UNSIGNED\n")
    result = _run(
        "attach",
        "--input",
        rendered / "authorization.unsigned.json",
        "--signature",
        fake_signature,
        "--output",
        tmp_path / "authorization.json",
    )
    assert result.returncode != 0
    assert "real armored SSH signature" in result.stderr


def test_real_role_separated_signatures_and_policies_complete_preflight(tmp_path: Path) -> None:
    rendered = tmp_path / "rendered"
    result = _run(
        "render",
        "--output",
        rendered,
        "--checked-at",
        "2026-07-15T17:31:16Z",
        "--authorization-expires-at",
        "2026-07-16T17:30:00Z",
        "--accepted-at",
        "2026-07-15T19:05:00Z",
        "--acceptance-expires-at",
        "2026-07-16T17:30:00Z",
        "--now",
        "2026-07-15T20:00:00Z",
    )
    assert result.returncode == 0, result.stderr

    auth_key, auth_policy = _key_and_policy(
        tmp_path, "authorization-key", "openthread-scope-authority"
    )
    accept_key, accept_policy = _key_and_policy(
        tmp_path, "acceptance-key", "openthread-worker-authority"
    )
    signed_paths: dict[str, Path] = {}
    for role, namespace, key in (
        ("authorization", "0verse-elf-authorization-v1", auth_key),
        ("worker-acceptance", "0verse-elf-worker-acceptance-v1", accept_key),
    ):
        unsigned = rendered / f"{role}.unsigned.json"
        material = tmp_path / f"{role}.material.json"
        result = _run("material", "--input", unsigned, "--output", material)
        assert result.returncode == 0, result.stderr
        signature = _sign(material, key, namespace)
        signed = tmp_path / f"{role}.json"
        result = _run(
            "attach", "--input", unsigned, "--signature", signature, "--output", signed
        )
        assert result.returncode == 0, result.stderr
        signed_paths[role] = signed

    assembled = tmp_path / "assembled"
    result = _run(
        "assemble",
        "--authorization",
        signed_paths["authorization"],
        "--acceptance",
        signed_paths["worker-acceptance"],
        "--output",
        assembled,
        "--now",
        "2026-07-15T20:00:00Z",
    )
    assert result.returncode == 0, result.stderr

    campaign, _, acceptance, _ = load_campaign(
        assembled / "campaign.json",
        now=NOW,
        authorization_allowed_signers=auth_policy,
        acceptance_allowed_signers=accept_policy,
    )
    assert campaign.worker == "bench-dedicated-elf-worker"
    assert acceptance.accepted_by == "openthread-worker-authority"
    result = _run_fixture(
        "_fixture-verify",
        "--fixture-root",
        tmp_path,
        "--campaign",
        assembled / "campaign.json",
        "--authorization-policy",
        auth_policy,
        "--acceptance-policy",
        accept_policy,
        "--now",
        "2026-07-15T20:00:00Z",
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["status"] == "FIXTURE_ONLY_NOT_PRODUCTION_VALIDATION"

    result = _run_fixture(
        "_fixture-verify",
        "--fixture-root",
        tmp_path,
        "--campaign",
        assembled / "campaign.json",
        "--authorization-policy",
        accept_policy,
        "--acceptance-policy",
        auth_policy,
        "--now",
        "2026-07-15T20:00:00Z",
    )
    assert result.returncode != 0

    result = _run(
        "_fixture-verify",
        "--fixture-root",
        tmp_path,
        "--campaign",
        assembled / "campaign.json",
        "--authorization-policy",
        auth_policy,
        "--acceptance-policy",
        accept_policy,
        "--now",
        "2026-07-15T20:00:00Z",
    )
    assert result.returncode != 0
    assert "disabled outside the test harness" in result.stderr


def test_production_verify_has_no_policy_time_or_closure_bypass(tmp_path: Path) -> None:
    for option in (
        "--authorization-policy",
        "--acceptance-policy",
        "--evidence-root",
        "--check-binaries",
        "--now",
    ):
        result = _run(
            "verify",
            "--campaign",
            tmp_path / "campaign.json",
            option,
            tmp_path / "bypass",
        )
        assert result.returncode != 0
        assert "unrecognized arguments" in result.stderr


def test_v10_closure_requires_every_evidence_file_and_both_exact_binaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _preflight_module()
    manifest = json.loads((HANDOFF / "campaign.unsigned.json").read_text())
    manifest["authorization"]["checked_at"] = "2026-07-15T17:31:16Z"
    manifest["authorization"]["expires_at"] = "2026-07-16T17:30:00Z"
    campaign = ElfCampaign.from_mapping(manifest, now=NOW)
    target = tmp_path / "target"
    control = tmp_path / "control"
    target.write_bytes(b"target fixture")
    control.write_bytes(b"control fixture")
    campaign = replace(
        campaign,
        target=ElfArtifactIdentity(str(target), hashlib.sha256(target.read_bytes()).hexdigest()),
        control=ElfArtifactIdentity(
            str(control), hashlib.sha256(control.read_bytes()).hexdigest()
        ),
    )
    evidence = {
        "scope-receipt.json": b"scope",
        "build-evidence/target-build-receipt.json": b"target build",
        "build-evidence/control-build-receipt.json": b"control build",
    }
    monkeypatch.setattr(
        module,
        "PINNED_EVIDENCE",
        {name: hashlib.sha256(data).hexdigest() for name, data in evidence.items()},
    )
    with pytest.raises(ValueError, match="regular non-symlink"):
        module._verify_v10_closure(campaign, tmp_path)

    for name, data in evidence.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    module._verify_v10_closure(campaign, tmp_path)

    control.unlink()
    with pytest.raises(ValueError, match="regular non-symlink"):
        module._verify_v10_closure(campaign, tmp_path)
    control.write_bytes(b"control fixture")
    (tmp_path / "scope-receipt.json").write_bytes(b"mutated")
    with pytest.raises(ValueError, match="retained evidence differs"):
        module._verify_v10_closure(campaign, tmp_path)
    (tmp_path / "scope-receipt.json").write_bytes(evidence["scope-receipt.json"])
    target.write_bytes(b"mutated target")
    with pytest.raises(ValueError, match="target binary differs"):
        module._verify_v10_closure(campaign, tmp_path)


def test_preflight_pins_merged_v10_evidence_and_has_no_execution_surface() -> None:
    expected = {
        "scope-receipt.json": "a879150b677596ac44ec72706cadeedaa1d3b9d8d7876d4332aef7d1b9de8029",
        "target-build-receipt.json": (
            "c40f10f68a5b1ae114a289e635683f1fcc5c151705d2f19cb90d8976afa41d84"
        ),
        "control-build-receipt.json": (
            "9c9cb7e9e11a8e28f8d027b182fe8c287e03e76e0c55f0e6cc6fc845a9e6f032"
        ),
    }
    for name, digest in expected.items():
        assert hashlib.sha256((CAMPAIGN / name).read_bytes()).hexdigest() == digest
    source = PREFLIGHT.read_text()
    assert "load_campaign(" in source
    assert "subprocess" not in source
    assert "sign_ssh_material" not in source
    assert "Popen" not in source
    assert 'SSH_KEYGEN = Path("/usr/bin/ssh-keygen")' in source
    assert 'AUTHORIZATION_POLICY = Path("/etc/0verse/elf-authorization.allowed_signers")' in source
    assert 'ACCEPTANCE_POLICY = Path("/etc/0verse/elf-worker-acceptance.allowed_signers")' in source
    assert "os.environ.clear()" in source
    calls = {
        node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and isinstance(node.func, (ast.Attribute, ast.Name))
    }
    assert not {"execv", "execve", "system", "Popen", "run"} & calls

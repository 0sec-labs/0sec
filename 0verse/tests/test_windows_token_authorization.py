from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from authorization_helpers import authorization_key, authorization_policy, sign_document

from zeroverse.cli import main
from zeroverse.windows_scope import AUTHORIZATION_NAMESPACE
from zeroverse.windows_token_authorization import (
    ACCEPTANCE_SIGNING_KEY_ENV,
    GRANT_SIGNING_KEY_ENV,
    issue_windows_token_execution_grant,
    issue_windows_token_worker_acceptance,
)
from zeroverse.windows_token_runner import (
    load_windows_token_execution_grant,
    load_windows_token_worker_acceptance,
)


def _write(path: Path, value: dict[str, object]) -> str:
    path.write_text(json.dumps(value), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _independent_authority(tmp_path: Path, stem: str, identity: str) -> tuple[Path, Path]:
    key = tmp_path / f"{stem}-key"
    policy = tmp_path / f"{stem}-allowed-signers"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    public = key.with_suffix(".pub").read_text(encoding="utf-8").strip()
    policy.write_text(f"{identity} {public}\n", encoding="utf-8")
    return key, policy


def _campaign() -> dict[str, object]:
    return {
        "schema_version": "0verse.windows-token-campaign/v1",
        "campaign_id": "issuer-lpe-001",
        "worker": "canary-worker-issuer",
        "starting_context": "standard-user",
        "finishing_principal": "local-system",
        "target_operation_sha256": "a" * 64,
        "control_operation_sha256": "b" * 64,
        "trials": 2,
        "minimum_confirmations": 2,
    }


def _scope(now: datetime) -> dict[str, object]:
    return {
        "schema_version": "0verse.windows-scope/v2",
        "campaign_id": "issuer-lpe-001",
        "program": "windows-canary",
        "scope_url": "https://www.microsoft.com/en-us/msrc/bounty-windows-insider-preview",
        "target_feature": "Windows local privilege boundary",
        "reachability": "owned Canary VM",
        "authorization": "published scope; owned worker",
        "worker": "canary-worker-issuer",
        "latest_build_verified_at": now.isoformat(),
        "latest_build_number": "29000.1",
        "latest_build_source_url": "https://learn.microsoft.com/en-us/windows-insider/flight-hub/",
        "preflight": {
            "ok": True,
            "program": "windows-canary",
            "checked_at": now.isoformat(),
            "build_lab_ex": "29000.1.amd64fre.rs_prerelease",
            "product_name": "Windows 11 Pro",
            "hyperv_available": False,
            "insider": {
                "ring": "Experimental Future Platforms",
                "content_type": "Mainline",
                "branch_name": "rs_prerelease",
                "channel_family": "experimental-future-platforms",
            },
        },
        "authorized_by": "operator@example.test",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "nonce": "scope_authorization_nonce_issuer_000001",
        "signature_ssh": "",
    }


def _grant(campaign_sha: str, scope_sha: str, now: datetime) -> dict[str, object]:
    return {
        "schema_version": "0verse.windows-token-execution-grant/v1",
        "campaign_sha256": campaign_sha,
        "scope_manifest_sha256": scope_sha,
        "campaign_id": "issuer-lpe-001",
        "worker": "canary-worker-issuer",
        "target_operation_sha256": "a" * 64,
        "control_operation_sha256": "b" * 64,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "nonce": "execution_grant_nonce_issuer_000001",
        "authorized_by": "grant@example.test",
        "signature_ssh": "",
    }


def _acceptance(
    campaign_sha: str,
    scope_sha: str,
    grant_sha: str,
    now: datetime,
) -> dict[str, object]:
    return {
        "schema_version": "0verse.windows-token-worker-acceptance/v2",
        "campaign_sha256": campaign_sha,
        "scope_manifest_sha256": scope_sha,
        "execution_grant_sha256": grant_sha,
        "execution_grant_nonce": "execution_grant_nonce_issuer_000001",
        "campaign_id": "issuer-lpe-001",
        "worker": "canary-worker-issuer",
        "build_lab_ex": "29000.1.amd64fre.rs_prerelease",
        "worker_machine_id": "owned-canary-machine-issuer",
        "runner_executable_sha256": "c" * 64,
        "witness_user_sid": "S-1-5-21-1-2-3-1001",
        "witness_session_id": 0,
        "witness_authentication_id": "0000000000001001",
        "witness_executable_sha256": "d" * 64,
        "target_operation_sha256": "a" * 64,
        "control_operation_sha256": "b" * 64,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "nonce": "worker_acceptance_nonce_issuer_0001",
        "accepted_by": "acceptance@example.test",
        "capture_signer": "capture@example.test",
        "signature_ssh": "",
    }


def _inputs(tmp_path: Path) -> tuple[Path, str, Path, str, datetime]:
    now = datetime.now(UTC)
    campaign_path = tmp_path / "campaign.json"
    campaign_sha = _write(campaign_path, _campaign())
    scope_path = tmp_path / "scope.json"
    scope_sha = _write(scope_path, sign_document(_scope(now), AUTHORIZATION_NAMESPACE))
    return campaign_path, campaign_sha, scope_path, scope_sha, now


def test_issuers_sign_verify_bind_and_never_overwrite(tmp_path: Path) -> None:
    campaign_path, campaign_sha, scope_path, scope_sha, now = _inputs(tmp_path)
    grant_template = tmp_path / "grant-template.json"
    grant_output = tmp_path / "grant.json"
    grant_key, grant_policy = _independent_authority(tmp_path, "grant", "grant@example.test")
    _write(grant_template, _grant(campaign_sha, scope_sha, now))
    issued_grant = issue_windows_token_execution_grant(
        campaign_path,
        scope_path,
        grant_template,
        grant_output,
        signing_key=grant_key,
        scope_allowed_signers=authorization_policy(),
        grant_allowed_signers=grant_policy,
    )
    _, grant_sha = load_windows_token_execution_grant(
        grant_output,
        allowed_signers=grant_policy,
        require_authorized=True,
    )
    assert issued_grant.sha256 == grant_sha
    with pytest.raises(ValueError, match="new path"):
        issue_windows_token_execution_grant(
            campaign_path,
            scope_path,
            grant_template,
            grant_output,
            signing_key=grant_key,
            scope_allowed_signers=authorization_policy(),
            grant_allowed_signers=grant_policy,
        )

    acceptance_template = tmp_path / "acceptance-template.json"
    acceptance_output = tmp_path / "acceptance.json"
    acceptance_key, acceptance_policy = _independent_authority(
        tmp_path, "acceptance", "acceptance@example.test"
    )
    _write(acceptance_template, _acceptance(campaign_sha, scope_sha, grant_sha, now))
    issued_acceptance = issue_windows_token_worker_acceptance(
        campaign_path,
        scope_path,
        grant_output,
        acceptance_template,
        acceptance_output,
        signing_key=acceptance_key,
        scope_allowed_signers=authorization_policy(),
        grant_allowed_signers=grant_policy,
        acceptance_allowed_signers=acceptance_policy,
    )
    _, acceptance_sha = load_windows_token_worker_acceptance(
        acceptance_output,
        allowed_signers=acceptance_policy,
        require_authorized=True,
    )
    assert issued_acceptance.sha256 == acceptance_sha


def test_issuers_reject_unbound_expired_signed_or_symlink_templates(tmp_path: Path) -> None:
    campaign_path, campaign_sha, scope_path, scope_sha, now = _inputs(tmp_path)
    grant_key, grant_policy = _independent_authority(tmp_path, "grant", "grant@example.test")
    template = tmp_path / "grant-template.json"
    raw = _grant(campaign_sha, "f" * 64, now)
    _write(template, raw)
    with pytest.raises(ValueError, match="not campaign-bound"):
        issue_windows_token_execution_grant(
            campaign_path,
            scope_path,
            template,
            tmp_path / "grant.json",
            signing_key=grant_key,
            scope_allowed_signers=authorization_policy(),
            grant_allowed_signers=grant_policy,
        )

    raw = _grant(campaign_sha, scope_sha, now)
    raw["expires_at"] = (now + timedelta(hours=25)).isoformat()
    _write(template, raw)
    with pytest.raises(ValueError, match="lifetime exceeds"):
        issue_windows_token_execution_grant(
            campaign_path,
            scope_path,
            template,
            tmp_path / "grant.json",
            signing_key=grant_key,
            scope_allowed_signers=authorization_policy(),
            grant_allowed_signers=grant_policy,
        )

    raw = _grant(campaign_sha, scope_sha, now)
    raw["signature_ssh"] = "pre-signed"
    _write(template, raw)
    with pytest.raises(ValueError, match="must be empty"):
        issue_windows_token_execution_grant(
            campaign_path,
            scope_path,
            template,
            tmp_path / "grant.json",
            signing_key=grant_key,
            scope_allowed_signers=authorization_policy(),
            grant_allowed_signers=grant_policy,
        )

    raw["signature_ssh"] = ""
    _write(template, raw)
    link = tmp_path / "grant-link.json"
    link.symlink_to(template)
    with pytest.raises(OSError):
        issue_windows_token_execution_grant(
            campaign_path,
            scope_path,
            link,
            tmp_path / "grant.json",
            signing_key=grant_key,
            scope_allowed_signers=authorization_policy(),
            grant_allowed_signers=grant_policy,
        )


def test_cli_uses_env_only_keys_and_explicit_authority_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    campaign_path, campaign_sha, scope_path, scope_sha, now = _inputs(tmp_path)
    template = tmp_path / "grant-template.json"
    output = tmp_path / "grant.json"
    _write(template, _grant(campaign_sha, scope_sha, now))
    import zeroverse.windows_token_authorization as issuer

    original_grant_issuer = issuer.issue_windows_token_execution_grant
    original_acceptance_issuer = issuer.issue_windows_token_worker_acceptance
    grant_key, grant_policy = _independent_authority(tmp_path, "grant", "grant@example.test")
    _, acceptance_policy = _independent_authority(tmp_path, "acceptance", "acceptance@example.test")

    def cli_grant_issuer(*args: object, **kwargs: object):
        return original_grant_issuer(
            *args,
            **kwargs,
            scope_allowed_signers=authorization_policy(),
            grant_allowed_signers=grant_policy,
        )

    def cli_acceptance_issuer(*args: object, **kwargs: object):
        return original_acceptance_issuer(
            *args,
            **kwargs,
            scope_allowed_signers=authorization_policy(),
            grant_allowed_signers=grant_policy,
            acceptance_allowed_signers=acceptance_policy,
        )

    monkeypatch.setattr(issuer, "issue_windows_token_execution_grant", cli_grant_issuer)
    monkeypatch.setattr(issuer, "issue_windows_token_worker_acceptance", cli_acceptance_issuer)
    monkeypatch.setenv(GRANT_SIGNING_KEY_ENV, str(grant_key))
    assert (
        main(
            [
                "windows-token-authorize-execution",
                str(campaign_path),
                str(template),
                str(output),
                "--scope-manifest",
                str(scope_path),
            ]
        )
        == 0
    )
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    assert str(grant_key) not in json.dumps(rendered)

    monkeypatch.delenv(ACCEPTANCE_SIGNING_KEY_ENV, raising=False)
    acceptance_template = tmp_path / "acceptance-template.json"
    grant_sha = hashlib.sha256(output.read_bytes()).hexdigest()
    _write(acceptance_template, _acceptance(campaign_sha, scope_sha, grant_sha, now))
    assert (
        main(
            [
                "windows-token-accept-worker",
                str(campaign_path),
                str(acceptance_template),
                str(tmp_path / "acceptance.json"),
                "--scope-manifest",
                str(scope_path),
                "--execution-grant",
                str(output),
            ]
        )
        == 2
    )
    assert ACCEPTANCE_SIGNING_KEY_ENV in capsys.readouterr().err


def test_issuers_require_distinct_role_identities_and_authority_keys(
    tmp_path: Path,
) -> None:
    campaign_path, campaign_sha, scope_path, scope_sha, now = _inputs(tmp_path)
    grant_key, grant_policy = _independent_authority(tmp_path, "grant", "grant@example.test")
    template = tmp_path / "grant-template.json"
    same_identity = _grant(campaign_sha, scope_sha, now)
    same_identity["authorized_by"] = "operator@example.test"
    _write(template, same_identity)
    with pytest.raises(ValueError, match="signer identities must differ"):
        issue_windows_token_execution_grant(
            campaign_path,
            scope_path,
            template,
            tmp_path / "same-identity-grant.json",
            signing_key=grant_key,
            scope_allowed_signers=authorization_policy(),
            grant_allowed_signers=grant_policy,
        )

    _write(template, _grant(campaign_sha, scope_sha, now))
    with pytest.raises(ValueError, match="authority keys must differ"):
        issue_windows_token_execution_grant(
            campaign_path,
            scope_path,
            template,
            tmp_path / "same-key-grant.json",
            signing_key=authorization_key(),
            scope_allowed_signers=authorization_policy(),
            grant_allowed_signers=authorization_policy(),
        )

    grant_output = tmp_path / "grant.json"
    issue_windows_token_execution_grant(
        campaign_path,
        scope_path,
        template,
        grant_output,
        signing_key=grant_key,
        scope_allowed_signers=authorization_policy(),
        grant_allowed_signers=grant_policy,
    )
    grant_sha = hashlib.sha256(grant_output.read_bytes()).hexdigest()
    acceptance_key, acceptance_policy = _independent_authority(
        tmp_path, "acceptance", "acceptance@example.test"
    )
    acceptance_template = tmp_path / "acceptance-template.json"
    duplicate_capture = _acceptance(campaign_sha, scope_sha, grant_sha, now)
    duplicate_capture["capture_signer"] = "grant@example.test"
    _write(acceptance_template, duplicate_capture)
    with pytest.raises(ValueError, match="signer identities must differ"):
        issue_windows_token_worker_acceptance(
            campaign_path,
            scope_path,
            grant_output,
            acceptance_template,
            tmp_path / "acceptance.json",
            signing_key=acceptance_key,
            scope_allowed_signers=authorization_policy(),
            grant_allowed_signers=grant_policy,
            acceptance_allowed_signers=acceptance_policy,
        )

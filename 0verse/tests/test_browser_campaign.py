from __future__ import annotations

import base64
import hashlib
import json
import os
import shlex
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from zeroverse.browser_campaign import (
    BrowserCampaign,
    _run_remote,
    crash_signature,
    execute_campaign,
    load_manifest,
)
from zeroverse.cli import main


def manifest(**updates: object) -> dict[str, object]:
    raw: dict[str, object] = {
        "schema_version": "0verse.browser-campaign/v3",
        "campaign_id": "v8-json-001",
        "component": "v8",
        "revision": "0123456789abcdef0123456789abcdef01234567",
        "build_flags": ["is_asan=true", "dcheck_always_on=true"],
        "corpus": "/srv/corpus/json",
        "harness": "json_parser_fuzzer",
        "harness_sha256": "a" * 64,
        "oracle": "asan",
        "process": "js-engine",
        "target_os": "linux",
        "bounty_program": "Chrome Vulnerability Reward Program",
        "bounty_scope_url": "https://example.test/scope",
        "scope_checked_at": datetime.now(UTC).isoformat(),
        "authorization": "published bounty scope; owned worker",
        "worker": "browser-worker",
        "source_root": "/srv/chromium/src",
        "build_receipt": "/srv/chromium/src/out/asan/build.json",
        "build_receipt_sha256": "b" * 64,
        "target_catalog": "/srv/chromium/src/out/asan/catalog.json",
        "target_catalog_sha256": "c" * 64,
        "gn_label": "//v8:json_parser_fuzzer",
        "command": [
            "/srv/chromium/src/out/asan/json_parser_fuzzer",
            "-artifact_prefix=/srv/0verse/artifacts/v8-json/",
            "-runs=1000",
            "/srv/corpus/json",
        ],
        "timeout_seconds": 60,
    }
    raw.update(updates)
    return raw


def replay_manifest(**updates: object) -> dict[str, object]:
    raw = manifest(
        revision="0123456789abcdef0123456789abcdef01234567",
        source_root="/srv/chromium/src",
        replay_command=[
            "/srv/chromium/src/out/asan/json_parser_fuzzer",
            "-runs=1",
            "{input}",
        ],
    )
    raw.update(updates)
    return raw


def ready(
    campaign: BrowserCampaign,
    argv: list[str] | tuple[str, ...],
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        argv,
        0,
        (
            f"CAMPAIGN revision={campaign.revision} "
            f"harness_sha256={campaign.harness_sha256} "
            f"catalog_sha256={campaign.target_catalog_sha256} "
            f"gn_label={campaign.gn_label} sanitizer={campaign.oracle}\n"
            "SUMMARY mode=campaign failures=0 warnings=0\n"
        ),
        "",
    )


def supervised(
    argv: list[str] | tuple[str, ...],
    *,
    returncode: int,
    stdout: bytes = b"",
    stderr: bytes = b"",
    timed_out: bool = False,
    artifacts: list[dict[str, object]] | None = None,
) -> subprocess.CompletedProcess[str]:
    token = argv[-1].split()[-1]
    header = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
    marker = header["marker"]
    record = {
        "protocol": "0verse.browser-campaign-supervisor/v1",
        "marker": marker,
        "target_returncode": returncode,
        "timed_out": timed_out,
        "stdout": {
            "tail_base64": base64.b64encode(stdout).decode(),
            "sha256": hashlib.sha256(stdout).hexdigest(),
            "bytes": len(stdout),
            "truncated": False,
        },
        "stderr": {
            "tail_base64": base64.b64encode(stderr).decode(),
            "sha256": hashlib.sha256(stderr).hexdigest(),
            "bytes": len(stderr),
            "truncated": False,
        },
        "artifacts": artifacts or [],
        "identity": {
            "hostname": "browser",
            "user": "browser",
            "group": "browser",
            "bootstrap_marker_sha256": "d" * 64,
        },
    }
    encoded = base64.b64encode(json.dumps(record, separators=(",", ":")).encode()).decode()
    return subprocess.CompletedProcess(
        argv, 0, f"0VERSE-BROWSER-CAMPAIGN:{marker}:{encoded}\n", ""
    )


def test_load_manifest_and_hash(tmp_path: Path) -> None:
    path = tmp_path / "campaign.json"
    path.write_text(json.dumps(manifest()), encoding="utf-8")
    campaign, digest = load_manifest(path)
    assert campaign.component == "v8"
    assert len(digest) == 64


def test_v2_requires_build_identity_fields() -> None:
    with pytest.raises(ValueError, match="unsupported browser campaign schema"):
        BrowserCampaign.from_mapping(manifest(schema_version="0verse.browser-campaign/v1"))
    with pytest.raises(ValueError, match="harness_sha256"):
        BrowserCampaign.from_mapping(manifest(harness_sha256="not-a-digest"))
    with pytest.raises(ValueError, match="source_root/out"):
        BrowserCampaign.from_mapping(
            manifest(command=["/usr/bin/json_parser_fuzzer", "/srv/corpus/json"])
        )


def test_v3_requires_exact_build_contract_binding() -> None:
    with pytest.raises(ValueError, match="build_receipt_sha256"):
        BrowserCampaign.from_mapping(manifest(build_receipt_sha256=""))
    with pytest.raises(ValueError, match="target_catalog_sha256"):
        BrowserCampaign.from_mapping(manifest(target_catalog_sha256=""))
    with pytest.raises(ValueError, match="canonical GN"):
        BrowserCampaign.from_mapping(manifest(gn_label="json_parser_fuzzer"))


@pytest.mark.parametrize(
    "worker",
    [
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
    ],
)
def test_rejects_local_or_inappropriate_worker(worker: str) -> None:
    with pytest.raises(ValueError, match="dedicated remote worker"):
        BrowserCampaign.from_mapping(manifest(worker=worker))


def test_requires_fresh_https_scope() -> None:
    with pytest.raises(ValueError, match="https"):
        BrowserCampaign.from_mapping(manifest(bounty_scope_url="http://example.test"))
    with pytest.raises(ValueError, match="30 days"):
        BrowserCampaign.from_mapping(manifest(scope_checked_at="2020-01-01T00:00:00Z"))


def test_rejects_placeholder_revision() -> None:
    with pytest.raises(ValueError, match="commit id"):
        BrowserCampaign.from_mapping(manifest(revision="REPLACE_WITH_REVISION"))
    with pytest.raises(ValueError, match="commit id"):
        BrowserCampaign.from_mapping(manifest(revision="0000000"))


def test_rejects_component_process_oracle_mismatch() -> None:
    with pytest.raises(ValueError, match="not valid for process"):
        BrowserCampaign.from_mapping(manifest(component="v8", process="gpu"))
    with pytest.raises(ValueError, match="Windows"):
        BrowserCampaign.from_mapping(manifest(oracle="pageheap-cdb", target_os="linux"))


def test_sanitizer_oracle_requires_matching_build_flag() -> None:
    with pytest.raises(ValueError, match="is_asan=true"):
        BrowserCampaign.from_mapping(manifest(build_flags=["is_debug=false"]))


@pytest.mark.parametrize(
    "flags",
    [
        ["is_asan=true", "is_msan=true"],
        ["is_asan=true", "is_asan=false"],
        ["is_asan=true", "is_asan=true"],
    ],
)
def test_manifest_rejects_contradictory_or_duplicate_sanitizer_flags(
    flags: list[str],
) -> None:
    with pytest.raises(ValueError, match=r"contradictory|more than once"):
        BrowserCampaign.from_mapping(manifest(build_flags=flags))


@pytest.mark.parametrize(
    "updates",
    [
        {"harness": "other_fuzzer"},
        {"command": ["json_parser_fuzzer", "/srv/corpus/json"]},
        {"corpus": "/srv/corpus/other"},
        {
            "corpus": "relative-corpus",
            "command": [
                "/srv/chromium/out/asan/json_parser_fuzzer",
                "relative-corpus",
            ],
        },
    ],
)
def test_linux_command_is_bound_to_declared_harness_and_corpus(updates: dict[str, object]) -> None:
    with pytest.raises(ValueError, match=r"harness|corpus"):
        BrowserCampaign.from_mapping(manifest(**updates))


@pytest.mark.parametrize(
    "prefix",
    [
        "/tmp/artifacts/",
        "/srv/0verse/artifacts/",
        "/srv/0verse/artifacts/../escaped/",
        "/srv/0verse/artifacts/campaign",
    ],
)
def test_linux_campaign_requires_a_dedicated_safe_artifact_prefix(prefix: str) -> None:
    command = list(manifest()["command"])
    command[1] = f"-artifact_prefix={prefix}"
    campaign = BrowserCampaign.from_mapping(manifest(command=command))
    calls = 0

    def unexpected_runner(
        argv: list[str] | tuple[str, ...], timeout: int
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(argv, 0, "", "")

    evidence = execute_campaign(campaign, "1" * 64, runner=unexpected_runner)
    assert evidence.status == "ERROR"
    assert "artifact prefix" in evidence.error
    assert calls == 0


def test_replay_compatible_manifest_without_artifact_prefix_fails_only_at_dispatch() -> None:
    command = [
        "/srv/chromium/src/out/asan/json_parser_fuzzer",
        "-runs=1000",
        "/srv/corpus/json",
    ]
    campaign = BrowserCampaign.from_mapping(manifest(command=command))
    calls = 0

    def unexpected_runner(
        argv: list[str] | tuple[str, ...], timeout: int
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(argv, 0, "", "")

    evidence = execute_campaign(campaign, "1" * 64, runner=unexpected_runner)
    assert evidence.status == "ERROR"
    assert "exactly one -artifact_prefix" in evidence.error
    assert calls == 0


def test_v2_replay_contract_cannot_dispatch_a_sustained_campaign() -> None:
    campaign = BrowserCampaign.from_mapping(
        manifest(schema_version="0verse.browser-campaign/v2")
    )
    calls = 0

    def unexpected_runner(
        argv: list[str] | tuple[str, ...], timeout: int
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(argv, 0, "", "")

    evidence = execute_campaign(campaign, "1" * 64, runner=unexpected_runner)
    assert evidence.status == "ERROR"
    assert "v3 build contract" in evidence.error
    assert calls == 0


def test_remote_transport_caps_output_while_streaming(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    ssh = fake_bin / "ssh"
    ssh.write_text(
        "#!/usr/bin/env python3\nimport sys\nsys.stdout.write('x' * 4096)\n",
        encoding="utf-8",
    )
    ssh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}:{os.environ['PATH']}")
    monkeypatch.setattr("zeroverse.browser_campaign.MAX_REMOTE_STDOUT_BYTES", 1024)

    with pytest.raises(RuntimeError, match="exceeded"):
        _run_remote(["ssh", "fixture"], 5)


def test_single_input_replay_profile_is_explicit_and_bound() -> None:
    campaign = BrowserCampaign.from_mapping(replay_manifest())
    assert campaign.source_root == "/srv/chromium/src"
    assert campaign.replay_command[-1] == "{input}"


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"source_root": ""}, "source_root"),
        ({"revision": "0123456"}, "full source revision"),
        ({"replay_command": []}, ""),
        (
            {
                    "replay_command": [
                        "/srv/chromium/src/out/asan/json_parser_fuzzer",
                    "prefix={input}",
                ]
            },
            "complete argument",
        ),
        (
            {
                    "replay_command": [
                        "/srv/chromium/src/out/asan/json_parser_fuzzer",
                    "{input}",
                    "{input}",
                ]
            },
            "exactly one",
        ),
    ],
)
def test_replay_profile_rejects_ambiguous_identity(
    updates: dict[str, object], message: str
) -> None:
    if "replay_command" in updates and not updates["replay_command"]:
        # replay_command is optional for the sustained-fuzz-only v2 profile.
        assert BrowserCampaign.from_mapping(replay_manifest(**updates)).replay_command == ()
        return
    with pytest.raises(ValueError, match=message):
        BrowserCampaign.from_mapping(replay_manifest(**updates))


def test_execute_records_remote_argv_and_evidence() -> None:
    campaign = BrowserCampaign.from_mapping(manifest())
    seen: list[str] = []

    def fake(argv: list[str] | tuple[str, ...], timeout: int) -> subprocess.CompletedProcess[str]:
        if "worker-preflight.sh campaign" in argv[-1]:
            assert timeout == 60
            return ready(campaign, argv)
        seen.extend(argv)
        assert timeout == 90
        return supervised(argv, returncode=1, stderr=b"==ERROR: AddressSanitizer")

    evidence = execute_campaign(campaign, "a" * 64, runner=fake)
    assert seen[:9] == [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ServerAliveInterval=30",
        "-o",
        "ServerAliveCountMax=3",
        "--",
        "browser-worker",
    ]
    assert evidence.status == "CRASH"
    assert evidence.returncode == 1
    assert evidence.crash_signature == "ERROR: AddressSanitizer"
    assert "AddressSanitizer" in evidence.stderr
    assert evidence.stderr_sha256 == hashlib.sha256(
        b"==ERROR: AddressSanitizer"
    ).hexdigest()
    assert evidence.stderr_bytes == len(b"==ERROR: AddressSanitizer")


def test_nonzero_without_oracle_signature_is_error() -> None:
    campaign = BrowserCampaign.from_mapping(manifest())

    def fake(argv: list[str] | tuple[str, ...], timeout: int) -> subprocess.CompletedProcess[str]:
        if "worker-preflight.sh campaign" in argv[-1]:
            return ready(campaign, argv)
        return supervised(argv, returncode=2, stderr=b"unknown command-line flag")

    evidence = execute_campaign(campaign, "b" * 64, runner=fake)
    assert evidence.status == "ERROR"
    assert evidence.crash_signature == ""


@pytest.mark.parametrize("returncode", [0, 255])
def test_asan_marker_without_valid_failing_target_exit_is_error(returncode: int) -> None:
    campaign = BrowserCampaign.from_mapping(manifest())

    def fake(argv: list[str] | tuple[str, ...], timeout: int) -> subprocess.CompletedProcess[str]:
        if "worker-preflight.sh campaign" in argv[-1]:
            return ready(campaign, argv)
        return supervised(argv, returncode=returncode, stderr=b"ERROR: AddressSanitizer")

    evidence = execute_campaign(campaign, "c" * 64, runner=fake)
    assert evidence.status == "ERROR"
    assert evidence.crash_signature == "ERROR: AddressSanitizer"
    assert "not accompanied" in evidence.error


def test_supervisor_artifact_inventory_is_verified_and_retained() -> None:
    campaign = BrowserCampaign.from_mapping(manifest())
    content = b"reproducer bytes"
    artifact = {
        "name": "crash-deadbeef",
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "retrieved": True,
        "content_base64": base64.b64encode(content).decode(),
    }

    def fake(argv: list[str] | tuple[str, ...], timeout: int) -> subprocess.CompletedProcess[str]:
        if "worker-preflight.sh campaign" in argv[-1]:
            return ready(campaign, argv)
        return supervised(argv, returncode=0, artifacts=[artifact])

    evidence = execute_campaign(campaign, "f" * 64, runner=fake)
    assert evidence.status == "CLEAN"
    assert evidence.artifacts == (artifact,)


def test_tampered_supervisor_artifact_fails_closed() -> None:
    campaign = BrowserCampaign.from_mapping(manifest())
    artifact = {
        "name": "crash-deadbeef",
        "size": 4,
        "sha256": hashlib.sha256(b"safe").hexdigest(),
        "retrieved": True,
        "content_base64": base64.b64encode(b"evil").decode(),
    }

    def fake(argv: list[str] | tuple[str, ...], timeout: int) -> subprocess.CompletedProcess[str]:
        if "worker-preflight.sh campaign" in argv[-1]:
            return ready(campaign, argv)
        return supervised(argv, returncode=0, artifacts=[artifact])

    evidence = execute_campaign(campaign, "f" * 64, runner=fake)
    assert evidence.status == "ERROR"
    assert "does not match" in evidence.error


def test_duplicate_supervisor_artifact_names_fail_closed() -> None:
    campaign = BrowserCampaign.from_mapping(manifest())
    artifact = {
        "name": "crash-duplicate",
        "size": 0,
        "sha256": hashlib.sha256(b"").hexdigest(),
        "retrieved": True,
        "content_base64": "",
    }

    def fake(argv: list[str] | tuple[str, ...], timeout: int) -> subprocess.CompletedProcess[str]:
        if "worker-preflight.sh campaign" in argv[-1]:
            return ready(campaign, argv)
        return supervised(argv, returncode=0, artifacts=[artifact, artifact])

    evidence = execute_campaign(campaign, "f" * 64, runner=fake)
    assert evidence.status == "ERROR"
    assert "duplicate campaign artifact name" in evidence.error


def test_supervisor_timeout_is_evidence_not_transport_timeout() -> None:
    campaign = BrowserCampaign.from_mapping(manifest())

    def fake(argv: list[str] | tuple[str, ...], timeout: int) -> subprocess.CompletedProcess[str]:
        if "worker-preflight.sh campaign" in argv[-1]:
            return ready(campaign, argv)
        return supervised(argv, returncode=-15, timed_out=True)

    evidence = execute_campaign(campaign, "f" * 64, runner=fake)
    assert evidence.status == "TIMEOUT"
    assert evidence.returncode == -15


def test_pageheap_marker_can_confirm_when_cdb_exits_zero() -> None:
    campaign = BrowserCampaign.from_mapping(
        manifest(oracle="pageheap-cdb", target_os="windows")
    )

    def fake(argv: list[str] | tuple[str, ...], timeout: int) -> subprocess.CompletedProcess[str]:
        if "worker-preflight.sh campaign" in argv[-1]:
            return ready(campaign, argv)
        return subprocess.CompletedProcess(argv, 0, "APPLICATION_VERIFIER", "")

    assert execute_campaign(campaign, "d" * 64, runner=fake).status == "CRASH"


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [
        (1, "SUMMARY mode=campaign failures=1 warnings=0\n"),
        (0, "unattested output\n"),
    ],
)
def test_readiness_failure_never_launches_campaign(returncode: int, stdout: str) -> None:
    campaign = BrowserCampaign.from_mapping(manifest())
    calls: list[tuple[str, ...]] = []

    def fake(argv: list[str] | tuple[str, ...], timeout: int) -> subprocess.CompletedProcess[str]:
        calls.append(tuple(argv))
        return subprocess.CompletedProcess(argv, returncode, stdout, "preflight detail")

    evidence = execute_campaign(campaign, "e" * 64, runner=fake)

    assert len(calls) == 1
    assert calls[0][-1].startswith("/srv/0verse/bin/worker-preflight.sh campaign ")
    preflight = shlex.split(calls[0][-1])
    assert preflight[-6:] == [
        campaign.build_receipt,
        campaign.build_receipt_sha256,
        campaign.target_catalog,
        campaign.target_catalog_sha256,
        campaign.gn_label,
        campaign.oracle,
    ]
    assert evidence.status == "ERROR"
    assert "campaign was not launched" in evidence.error


def test_signature_is_oracle_specific() -> None:
    assert crash_signature("asan", "", "ERROR: AddressSanitizer: heap-use-after-free")
    assert crash_signature("msan", "", "ERROR: AddressSanitizer") == ""


def test_cli_dry_run_never_invokes_ssh(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "campaign.json"
    path.write_text(json.dumps(manifest()), encoding="utf-8")
    assert main(["browser-campaign", str(path), "--dry-run"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "VALIDATED"
    assert output["campaign"]["worker"] == "browser-worker"

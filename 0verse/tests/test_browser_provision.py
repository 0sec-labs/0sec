from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts/browser/provision-worker.sh"
WORKER_PREFLIGHT = SCRIPT.parent / "worker-preflight.sh"


def run(
    *args: str,
    allow: bool = False,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    if allow:
        environment["ZEROVERSE_ALLOW_BROWSER_PROVISION"] = "YES"
    else:
        environment.pop("ZEROVERSE_ALLOW_BROWSER_PROVISION", None)
    environment.update(extra_env or {})
    return subprocess.run(
        [str(SCRIPT), *args],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def test_requires_explicit_mutation_gate() -> None:
    result = run("new-browser", "--apply")
    assert result.returncode == 2
    assert "ZEROVERSE_ALLOW_BROWSER_PROVISION=YES" in result.stderr


def test_rejects_protected_alias_before_ssh() -> None:
    result = run("bench", "--apply", allow=True)
    assert result.returncode == 1
    assert "not an approved new dedicated browser worker" in result.stderr


def test_rejects_every_known_server_ip_before_ssh() -> None:
    for address in (
        "127.0.0.1",
    ):
        result = run(address, "--apply", allow=True)
        assert result.returncode == 1
        assert "not an approved new dedicated browser worker" in result.stderr


def test_rejects_unsafe_host_syntax_before_ssh() -> None:
    result = run("-oProxyCommand=bad", "--apply", allow=True)
    assert result.returncode == 2
    assert "unsafe SSH host syntax" in result.stderr


def test_provision_installs_hash_bound_campaign_helpers(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    call_log = tmp_path / "calls.log"
    bootstrap = SCRIPT.parent / "bootstrap-worker.sh"
    expected_hash = hashlib.sha256(bootstrap.read_bytes()).hexdigest()
    replay_helper = SCRIPT.parent / "replay-candidate.py"
    expected_helper_hash = hashlib.sha256(replay_helper.read_bytes()).hexdigest()
    campaign_supervisor = SCRIPT.parent / "run-campaign.py"
    expected_supervisor_hash = hashlib.sha256(campaign_supervisor.read_bytes()).hexdigest()
    build_contract = SCRIPT.parent / "build-contract.py"
    expected_contract_hash = hashlib.sha256(build_contract.read_bytes()).hexdigest()
    fake_ssh = fake_bin / "ssh"
    fake_ssh.write_text(
        "#!/bin/sh\n"
        'printf \'ssh %s\\n\' "$*" >> "$CALL_LOG"\n'
        'case "$*" in\n'
        '  *"bootstrap_sha256=//p"*) printf \'%s\\n\' "$EXPECTED_HASH";;\n'
        '  *"sha256sum /srv/0verse/0verse/scripts/browser/replay-candidate.py"*) '
        'printf \'%s\\n\' "$EXPECTED_HELPER_HASH";;\n'
        '  *"sha256sum /srv/0verse/0verse/scripts/browser/run-campaign.py"*) '
        'printf \'%s\\n\' "$EXPECTED_SUPERVISOR_HASH";;\n'
        '  *"sha256sum /srv/0verse/bin/build-contract.py"*) '
        'printf \'%s\\n\' "$EXPECTED_CONTRACT_HASH";;\n'
        "esac\n"
    )
    fake_scp = fake_bin / "scp"
    fake_scp.write_text(
        "#!/bin/sh\n"
        'printf \'scp %s\\n\' "$*" >> "$CALL_LOG"\n'
    )
    fake_ssh.chmod(0o755)
    fake_scp.chmod(0o755)

    result = run(
        "new-browser",
        "--apply",
        allow=True,
        extra_env={
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "CALL_LOG": str(call_log),
            "EXPECTED_HASH": expected_hash,
            "EXPECTED_HELPER_HASH": expected_helper_hash,
            "EXPECTED_SUPERVISOR_HASH": expected_supervisor_hash,
            "EXPECTED_CONTRACT_HASH": expected_contract_hash,
        },
    )

    assert result.returncode == 0, result.stderr
    calls = call_log.read_text()
    assert str(replay_helper) in calls
    assert str(campaign_supervisor) in calls
    assert str(build_contract) in calls
    assert "root@new-browser:/tmp/0verse-browser-provision." in calls
    assert "/srv/0verse/0verse/scripts/browser/replay-candidate.py" in calls
    assert "/srv/0verse/0verse/scripts/browser/run-campaign.py" in calls
    assert "install -d -o root -g browser -m 0750 /srv/0verse/bin" in calls
    assert "install -o root -g browser -m 0550" in calls
    assert "PROVISIONED host=new-browser user=browser" in result.stdout


def test_campaign_preflight_attests_exact_checkout_and_harness(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    root = tmp_path / "root"
    source_root = root / "chromium" / "src"
    harness = source_root / "out" / "asan" / "json_parser_fuzzer"
    corpus = root / "corpus"
    helper = root / "0verse" / "scripts" / "browser" / "replay-candidate.py"
    supervisor = root / "0verse" / "scripts" / "browser" / "run-campaign.py"
    contract = root / "bin" / "build-contract.py"
    preflight = root / "bin" / "worker-preflight.sh"
    harness.parent.mkdir(parents=True)
    corpus.mkdir(parents=True)
    helper.parent.mkdir(parents=True)
    contract.parent.mkdir(parents=True)
    (source_root / ".git").mkdir()
    harness.write_bytes(b"fixture harness")
    harness.chmod(0o750)
    helper.write_text("fixture helper")
    supervisor.write_text("fixture supervisor")
    contract.write_text("fixture contract")
    contract.chmod(0o750)
    preflight.write_text("fixture preflight")
    preflight.chmod(0o750)
    marker = root / ".browser-worker"
    marker.write_text(
        "schema=1\n"
        "hostname=browser\n"
        "bootstrapped_at_utc=2026-07-13T00:00:00Z\n"
        f"bootstrap_sha256={'b' * 64}\n"
    )
    revision = "1" * 40
    harness_hash = hashlib.sha256(harness.read_bytes()).hexdigest()

    commands = {
        "uname": 'case "$1" in -s) echo Linux;; -m) echo x86_64;; esac',
        "getconf": "echo 16",
        "awk": (
            'case "$*" in *MemTotal*) echo 67108864; exit 0;; '
            '*NR*) cat >/dev/null; echo 1048576000; exit 0;; *) /usr/bin/awk "$@";; esac'
        ),
        "df": "printf 'fs blocks used available capacity mount\\nfs 1 1 1048576000 1%% /\\n'",
        "hostname": "echo browser",
        "id": 'case "$1" in -un|-gn) echo browser;; esac',
        "stat": (
            'case "$2" in %a) case "$3" in *.browser-worker) echo 640;; '
            '*.py|*.sh) echo 550;; *) echo 750;; esac;; '
            '%U:%G) if [ "${UNSAFE_CUSTODY:-}" = 1 ] && '
            'case "$3" in */build-contract.py) true;; *) false;; esac; '
            'then echo browser:browser; else echo root:browser; fi;; esac'
        ),
        "git": 'echo "$EXPECTED_REVISION"',
        "sha256sum": 'printf \'%s  %s\\n\' "$EXPECTED_HARNESS_HASH" "$1"',
        "readlink": 'printf \'%s\\n\' "$2"',
        "python3": ":",
        "clang": ":",
        "llvm-symbolizer": ":",
        "rsync": ":",
        "timeout": ":",
        "autoninja": ":",
    }
    for name, body in commands.items():
        executable = fake_bin / name
        executable.write_text(f"#!/bin/sh\n{body}\n")
        executable.chmod(0o755)

    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{fake_bin}:{environment['PATH']}",
            "BROWSER_ROOT": str(root),
            "EXPECTED_REVISION": revision,
            "EXPECTED_HARNESS_HASH": harness_hash,
        }
    )
    result = subprocess.run(
        [
            str(WORKER_PREFLIGHT),
            "campaign",
            revision,
            harness_hash,
            str(source_root),
            str(harness),
            str(corpus),
            str(source_root / "out" / "asan" / "build.json"),
            "b" * 64,
            str(source_root / "out" / "asan" / "catalog.json"),
            "c" * 64,
            "//v8:json_parser_fuzzer",
            "asan",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert (
        f"CAMPAIGN revision={revision} harness_sha256={harness_hash} "
        f"catalog_sha256={'c' * 64} gn_label=//v8:json_parser_fuzzer sanitizer=asan"
    ) in result.stdout
    assert "SUMMARY mode=campaign failures=0 warnings=0" in result.stdout

    unsafe_environment = {**environment, "UNSAFE_CUSTODY": "1"}
    unsafe = subprocess.run(
        result.args,
        check=False,
        capture_output=True,
        text=True,
        env=unsafe_environment,
    )
    assert unsafe.returncode != 0
    assert "unsafe custody: browser:browser 550" in unsafe.stdout

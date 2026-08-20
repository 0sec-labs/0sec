from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN = ROOT / "campaigns" / "elf" / "openthread-radio-regression-20260715"


def _json(name: str) -> dict[str, object]:
    raw = json.loads((CAMPAIGN / name).read_bytes())
    assert isinstance(raw, dict)
    return raw


def test_scope_receipt_is_official_current_and_does_not_overauthorize() -> None:
    receipt = _json("scope-receipt.json")
    assert receipt["program"] == "Google Open Source Software Vulnerability Reward Program"
    assert receipt["tier"] == "OT0"
    assert receipt["repository"] == "https://github.com/openthread/openthread"
    assert "bughunters.google.com/about/rules/" in receipt["program_rules"]["url"]
    assert receipt["tier_source"]["url"].startswith("https://github.com/google/bughunters/")
    assert (
        "/0aa6107a30e47b6fdd8da03ad5a66adbccf510ba/" in receipt["tier_source"]["immutable_raw_url"]
    )
    assert receipt["program_rules"]["snapshot_size"] == 124027
    assert re.fullmatch(r"[0-9a-f]{64}", receipt["program_rules"]["snapshot_sha256"])
    assert "does not authorize disclosure" in receipt["authorization_limit"]


def test_plan_pins_exact_pair_harness_and_oss_fuzz_boundary() -> None:
    plan = _json("campaign-plan.json")
    assert plan["status"] == "PREPARED_NOT_AUTHORIZED"
    assert plan["target"]["revision"] == "9eb7f98008a50f16d083d87f71e969bbedb91cba"
    assert plan["control"]["revision"] == "593fc53fcfa006d853eddea9cc310f9857ef1510"
    assert plan["target"]["revision"] != plan["control"]["revision"]
    assert plan["build"]["oss_fuzz_revision"] == "80c56dfe1e1746a3b569839d7742e0377ee00c9b"
    assert plan["harness"]["target_sha256"] == plan["harness"]["control_sha256"]
    assert plan["worker"]["mac_allowed"] is False
    assert plan["sustained_fuzzing_started"] is False
    assert plan["automatic_disclosure"] is False
    assert "REPLACE_" not in json.dumps(plan)
    digest = re.compile(r"^[0-9a-f]{64}$")
    assert digest.fullmatch(plan["target"]["binary_sha256"])
    assert digest.fullmatch(plan["control"]["binary_sha256"])
    assert plan["build"]["builder_image_id"].startswith("sha256:")
    assert plan["build"]["base_builder_image_id"].startswith("sha256:")
    assert plan["build"]["dockerfile_sha256"] == (
        "300dafb951c90862acf419924ab2e38857e30073cdaca08ee9de52487b14998c"
    )
    assert "vulnerable/fixed pair" in plan["oracle"]["differential"]


def test_scope_receipt_hash_and_canary_are_fail_closed() -> None:
    plan = _json("campaign-plan.json")
    receipt_digest = hashlib.sha256((CAMPAIGN / "scope-receipt.json").read_bytes()).hexdigest()
    assert plan["scope_receipt_sha256"] == receipt_digest
    canary = (CAMPAIGN / "canary.sh").read_text(encoding="utf-8")
    assert canary.startswith("#!/usr/bin/bash\n")
    assert "readonly PATH=/usr/sbin:/usr/bin:/sbin:/bin" in canary
    assert "systemd-run" in canary
    assert "ExitType=cgroup" in canary
    assert "KillMode=control-group" in canary
    assert "cgroup.procs" in canary
    assert "ZEROVERSE_PACKAGE_MANIFEST_SHA256" in canary
    assert "preflight" in canary
    assert "freeze-sign" in canary
    assert "evidence path must not already exist" in canary
    assert "ZEROVERSE_WORKER_ROLE" in canary
    assert "root:600" in canary
    assert "sustained_fuzzing_started=false" in canary
    runner = (CAMPAIGN / "canary_runner.py").read_text(encoding="utf-8")
    assert "start_new_session=True" in runner
    assert "os.killpg" in runner
    assert "DEADLINE_SECONDS = 15" in runner
    assert '"-runs=1"' in runner
    assert '"-runs=0"' not in runner
    assert "shell=False" in runner
    assert runner.count("foxguard: ignore[py/no-command-injection]") == 1
    verifier = (CAMPAIGN / "canary_package.py").read_text(encoding="utf-8")
    assert 'GIT = "/usr/bin/git"' in verifier
    assert 'DOCKER = "/usr/bin/docker"' in verifier
    assert 'SSH_KEYGEN = "/usr/bin/ssh-keygen"' in verifier
    assert '"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"' in verifier
    assert '"--untracked-files=all"' in verifier
    assert '"--untracked-files=no"' not in verifier
    assert "os.O_NOFOLLOW" in verifier
    assert "/proc/self/mountinfo" in verifier
    assert "os.fchown(child, 0, 0)" in verifier
    assert "os.fchmod(child, 0o500)" in verifier
    assert "pass_fds=(evidence_fd,)" in verifier
    assert '[DOCKER, "image", "inspect"' in verifier
    assert '"submodule", "status", "--recursive"' in verifier
    assert "_validate_frozen_attestation" in verifier
    assert "frozen evidence path set differs from the attestation" in verifier
    assert "frozen evidence identity mismatch" in verifier
    assert verifier.count("foxguard: ignore[py/no-path-traversal]") == 3


def test_canary_attestation_is_bounded_signed_and_matches_plan() -> None:
    plan = _json("campaign-plan.json")
    receipt = _json("canary-attestation.json")
    assert receipt["sustained_fuzzing_started"] is False
    assert receipt["execution_authorized"] is False
    assert "not an ElfCampaignReceipt" in receipt["attestation_limit"]
    assert receipt["worker"]["unprivileged"] is True
    assert receipt["worker"]["uid"] != 0
    assert receipt["containment"]["exit_type"] == "cgroup"
    assert receipt["containment"]["kill_mode"] == "control-group"
    assert receipt["launch_package_manifest_sha256"] == hashlib.sha256(
        (CAMPAIGN / "launch-manifest.json").read_bytes()
    ).hexdigest()
    assert receipt["scripts"]["runner_sha256"] == hashlib.sha256(
        (CAMPAIGN / "canary_runner.py").read_bytes()
    ).hexdigest()
    assert receipt["scripts"]["wrapper_sha256"] == hashlib.sha256(
        (CAMPAIGN / "canary.sh").read_bytes()
    ).hexdigest()
    assert (
        receipt["campaign_plan_sha256"]
        == hashlib.sha256((CAMPAIGN / "campaign-plan.json").read_bytes()).hexdigest()
    )
    assert len(receipt["replays"]) == 2
    by_role = {item["role"]: item for item in receipt["replays"]}
    for role in ("target", "control"):
        assert "-runs=1" in by_role[role]["argv"]
        assert by_role[role]["outcome"] == "CLEAN"
        assert by_role[role]["revision"] == plan[role]["revision"]
        assert by_role[role]["binary_sha256"] == plan[role]["binary_sha256"]
        assert by_role[role]["hard_deadline_seconds"] == 15
        assert by_role[role]["stdout"]["sha256"]
        assert by_role[role]["stderr"]["sha256"]

    subprocess.run(
        [
            "ssh-keygen",
            "-Y",
            "verify",
            "-q",
            "-f",
            str(CAMPAIGN / "canary-attestation.allowed_signers"),
            "-I",
            "bench-canary@0verse",
            "-n",
            "zeroverse-elf-canary-attestation-v1",
            "-s",
            str(CAMPAIGN / "canary-attestation.json.sig"),
        ],
        input=(CAMPAIGN / "canary-attestation.json").read_bytes(),
        check=True,
    )


def test_bounded_build_helper_and_side_receipts_close_derivation() -> None:
    helper = (CAMPAIGN / "build-bounded.sh").read_text(encoding="utf-8")
    assert helper.startswith("#!/usr/bin/bash\n")
    assert "readonly PATH=/usr/sbin:/usr/bin:/sbin:/bin" in helper
    assert "--untracked-files=all" in helper
    assert "--untracked-files=no" not in helper
    assert helper.count("foxguard: ignore[bash/taint-path-traversal]") == 2
    assert "build_fuzzers" in helper
    assert "submodule status --recursive" in helper
    assert "taskset -c 0-7" in helper
    assert "-runs=" not in helper
    for role in ("target", "control"):
        receipt_path = CAMPAIGN / f"{role}-build-receipt.json"
        receipt_bytes = receipt_path.read_bytes()
        receipt = _json(f"{role}-build-receipt.json")
        pinned = _json("campaign-plan.json")["build"]["side_receipts"][role]
        assert hashlib.sha256(receipt_bytes).hexdigest() == pinned["sha256"]
        assert receipt_bytes == (
            json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        ).encode()
        assert receipt["role"] == role
        assert receipt["output"]["sha256"] == _json("campaign-plan.json")[role]["binary_sha256"]
        assert receipt["build_log"]["size"] > 100_000
        assert receipt["submodule_closure"]["sha256"] == (
            "f6cb8bfa026c074fcec1bfc6fa677cdd7440c9d116c0afbe5a66c443f2cf614a"
        )


def test_package_manifest_pins_exact_raw_bytes() -> None:
    manifest = _json("evidence-manifest.json")
    for name, expected in manifest["files"].items():
        assert hashlib.sha256((CAMPAIGN / name).read_bytes()).hexdigest() == expected


def test_launch_manifest_is_externally_pinned_and_closes_all_references() -> None:
    raw = (CAMPAIGN / "launch-manifest.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == (
        "e852057acae417663e632701e2b3bf430140b8062366f1e8fb90495b788e5b0a"
    )
    manifest = json.loads(raw)
    assert manifest["schema_version"] == "0verse.elf-canary-launch-package/v1"
    files = manifest["files"]
    local_mapping = {
        "campaign-plan.json": "campaign-plan.json",
        "scope-receipt.json": "scope-receipt.json",
        "build-bounded.sh": "build-bounded.sh",
        "canary.sh": "canary.sh",
        "canary_runner.py": "canary_runner.py",
        "canary_package.py": "canary_package.py",
        "canary-attestation.allowed_signers": "canary-attestation.allowed_signers",
        "canary-attestation-key.json": "canary-attestation-key.json",
        "build-evidence/target-build-receipt.json": "target-build-receipt.json",
        "build-evidence/control-build-receipt.json": "control-build-receipt.json",
    }
    for remote, local in local_mapping.items():
        data = (CAMPAIGN / local).read_bytes()
        assert files[remote]["sha256"] == hashlib.sha256(data).hexdigest()
        assert files[remote]["size"] == len(data)
        assert files[remote]["uid"] == files[remote]["gid"] == 0

    closure = set(manifest["referenced_closure"])
    assert {
        "scope-evidence/google-oss-vrp-rules.dom.html",
        "scope-evidence/tier.md",
        "build-evidence/build-image.log",
        "build-evidence/target-build.log",
        "build-evidence/control-build.log",
        "build-evidence/target-command.txt",
        "build-evidence/control-command.txt",
        "build-evidence/target-submodules.txt",
        "build-evidence/control-submodules.txt",
        "oss-fuzz/projects/openthread/Dockerfile",
        "oss-fuzz/projects/openthread/build.sh",
        "oss-fuzz/projects/openthread/project.yaml",
        "oss-fuzz/projects/openthread/run_tests.sh",
        "out-target/radio-one-node-fuzzer",
        "out-control/radio-one-node-fuzzer",
        "target/tests/fuzz/CMakeLists.txt",
        "control/tests/fuzz/CMakeLists.txt",
        "target/tests/fuzz/fuzz_radio-one-node.cpp",
        "control/tests/fuzz/fuzz_radio-one-node.cpp",
        "build-bounded.sh",
    } == closure

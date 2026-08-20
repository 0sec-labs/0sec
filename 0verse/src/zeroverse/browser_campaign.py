"""Manifest-driven orchestration for authorized remote browser fuzzing."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import shlex
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Protocol

SCHEMA_VERSION = "0verse.browser-campaign/v3"
LEGACY_SCHEMA_VERSION = "0verse.browser-campaign/v2"
COMPONENTS = frozenset({"v8", "blink", "mojo", "skia", "media", "gpu", "spidermonkey", "ipdl"})
ORACLES = frozenset({"asan", "msan", "ubsan", "browser-crash", "pageheap-cdb"})
PROCESSES = frozenset({"js-engine", "renderer", "browser", "gpu", "utility", "media"})
TARGET_OSES = frozenset({"linux", "windows"})
COMPONENT_PROCESSES: dict[str, frozenset[str]] = {
    "v8": frozenset({"js-engine"}),
    "spidermonkey": frozenset({"js-engine"}),
    "blink": frozenset({"renderer"}),
    "mojo": frozenset({"renderer", "browser", "utility"}),
    "ipdl": frozenset({"renderer", "browser"}),
    "skia": frozenset({"renderer", "gpu"}),
    "gpu": frozenset({"gpu"}),
    "media": frozenset({"media", "renderer", "utility"}),
}
LOCAL_HOSTS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "mac",
        "mac-mini",
        "peakbook",
        "peakbuntu",
        "fabian-mac",
        "feza-macbook-air",
        "vega",
        "fuzzer",
        "bench",
        "sandbox",
    }
)
WORKER_PREFLIGHT = "/srv/0verse/bin/worker-preflight.sh"
CAMPAIGN_SUPERVISOR = "/srv/0verse/0verse/scripts/browser/run-campaign.py"
CAMPAIGN_SUPERVISOR_PROTOCOL = "0verse.browser-campaign-supervisor/v1"
CAMPAIGN_ARTIFACT_ROOT = PurePosixPath("/srv/0verse/artifacts")
MAX_RETAINED_STREAM_BYTES = 1024 * 1024
MAX_CAMPAIGN_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_RETRIEVED_ARTIFACT_BYTES = 64 * 1024 * 1024
# The supervisor record base64-wraps JSON that itself contains base64 artifacts
# and stream tails. 128 MiB admits the bounded 64 MiB retrieval contract while
# preventing an untrusted SSH peer from driving unbounded coordinator memory.
MAX_REMOTE_STDOUT_BYTES = 128 * 1024 * 1024
MAX_REMOTE_STDERR_BYTES = 1024 * 1024
_CAMPAIGN_SUMMARY = re.compile(
    r"^SUMMARY mode=campaign failures=0 warnings=\d+$", re.MULTILINE
)


@dataclass(frozen=True)
class BrowserCampaign:
    campaign_id: str
    component: str
    revision: str
    build_flags: tuple[str, ...]
    corpus: str
    harness: str
    harness_sha256: str
    oracle: str
    process: str
    target_os: str
    bounty_program: str
    bounty_scope_url: str
    scope_checked_at: str
    authorization: str
    worker: str
    command: tuple[str, ...]
    replay_command: tuple[str, ...] = ()
    source_root: str = ""
    build_receipt: str = ""
    build_receipt_sha256: str = ""
    target_catalog: str = ""
    target_catalog_sha256: str = ""
    gn_label: str = ""
    timeout_seconds: int = 3600
    schema_version: str = SCHEMA_VERSION
    env: tuple[tuple[str, str], ...] = ()

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> BrowserCampaign:
        required = {
            "campaign_id",
            "component",
            "revision",
            "build_flags",
            "corpus",
            "harness",
            "harness_sha256",
            "oracle",
            "process",
            "target_os",
            "bounty_program",
            "bounty_scope_url",
            "scope_checked_at",
            "authorization",
            "worker",
            "command",
        }
        missing = sorted(required - raw.keys())
        if missing:
            raise ValueError(f"missing browser campaign fields: {', '.join(missing)}")
        schema = str(raw.get("schema_version", SCHEMA_VERSION))
        if schema not in {SCHEMA_VERSION, LEGACY_SCHEMA_VERSION}:
            raise ValueError(f"unsupported browser campaign schema: {schema}")
        build_flags = _string_sequence(raw["build_flags"], "build_flags")
        command = _string_sequence(raw["command"], "command")
        replay_command = _string_sequence(raw.get("replay_command", []), "replay_command")
        campaign = cls(
            campaign_id=str(raw["campaign_id"]),
            component=str(raw["component"]).lower(),
            revision=str(raw["revision"]),
            build_flags=build_flags,
            corpus=str(raw["corpus"]),
            harness=str(raw["harness"]),
            harness_sha256=str(raw["harness_sha256"]).lower(),
            oracle=str(raw["oracle"]).lower(),
            process=str(raw["process"]).lower(),
            target_os=str(raw["target_os"]).lower(),
            bounty_program=str(raw["bounty_program"]),
            bounty_scope_url=str(raw["bounty_scope_url"]),
            scope_checked_at=str(raw["scope_checked_at"]),
            authorization=str(raw["authorization"]),
            worker=str(raw["worker"]),
            command=command,
            replay_command=replay_command,
            source_root=str(raw.get("source_root", "")),
            build_receipt=str(raw.get("build_receipt", "")),
            build_receipt_sha256=str(raw.get("build_receipt_sha256", "")).lower(),
            target_catalog=str(raw.get("target_catalog", "")),
            target_catalog_sha256=str(raw.get("target_catalog_sha256", "")).lower(),
            gn_label=str(raw.get("gn_label", "")),
            timeout_seconds=_integer(raw.get("timeout_seconds", 3600), "timeout_seconds"),
            schema_version=schema,
            env=_env_pairs(raw.get("env", {}), "env"),
        )
        campaign.validate()
        return campaign

    def validate(self) -> None:
        for name in (
            "campaign_id",
            "revision",
            "corpus",
            "harness",
            "harness_sha256",
            "bounty_program",
            "authorization",
            "worker",
        ):
            if not getattr(self, name).strip():
                raise ValueError(f"browser campaign field is empty: {name}")
        if self.component not in COMPONENTS:
            raise ValueError(f"unsupported browser component: {self.component}")
        if self.oracle not in ORACLES:
            raise ValueError(f"unsupported browser oracle: {self.oracle}")
        if self.process not in PROCESSES:
            raise ValueError(f"unsupported browser process: {self.process}")
        if self.target_os not in TARGET_OSES:
            raise ValueError(f"unsupported browser target OS: {self.target_os}")
        if self.process not in COMPONENT_PROCESSES[self.component]:
            raise ValueError(f"{self.component} is not valid for process {self.process}")
        if self.oracle == "pageheap-cdb" and self.target_os != "windows":
            raise ValueError("pageheap-cdb requires a Windows target")
        if self.oracle == "msan" and self.target_os != "linux":
            raise ValueError("msan browser campaigns require a Linux target")
        if not re.fullmatch(r"[0-9a-fA-F]{7,64}", self.revision) or not any(
            char != "0" for char in self.revision
        ):
            raise ValueError("revision must be a nonzero 7-64 character hexadecimal commit id")
        if not re.fullmatch(r"[0-9a-f]{64}", self.harness_sha256):
            raise ValueError("harness_sha256 must be a lowercase SHA-256 digest")
        if self.worker.lower() in LOCAL_HOSTS:
            raise ValueError(f"browser campaign requires a dedicated remote worker: {self.worker}")
        if not self.bounty_scope_url.startswith("https://"):
            raise ValueError("bounty_scope_url must be an https URL")
        try:
            checked = datetime.fromisoformat(self.scope_checked_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("scope_checked_at must be ISO-8601") from exc
        if checked.tzinfo is None:
            raise ValueError("scope_checked_at must include a timezone")
        age = datetime.now(UTC) - checked.astimezone(UTC)
        if age.days < 0 or age.days > 30:
            raise ValueError("bounty scope check must be no more than 30 days old")
        if not self.build_flags:
            raise ValueError("build_flags must record the sanitizer/instrumentation build")
        if not self.command or not self.command[0].strip():
            raise ValueError("command must contain a remote executable argv")
        if any("\x00" in argument for argument in (*self.command, *self.replay_command)):
            raise ValueError("browser commands must not contain NUL bytes")
        assignments: dict[str, bool] = {}
        for flag in self.build_flags:
            match = re.fullmatch(r"\s*([a-zA-Z0-9_]+)\s*=\s*(true|false)\s*", flag)
            if match is None:
                raise ValueError("build_flags must contain exact boolean GN assignments")
            name, raw_value = match.groups()
            name = name.lower()
            if name in assignments:
                raise ValueError(f"build_flags assigns {name} more than once")
            assignments[name] = raw_value == "true"
        required_build_flag = {
            "asan": "is_asan",
            "msan": "is_msan",
            "ubsan": "is_ubsan",
        }.get(self.oracle)
        if required_build_flag and assignments.get(required_build_flag) is not True:
            raise ValueError(f"{self.oracle} oracle requires build flag {required_build_flag}=true")
        enabled_sanitizers = {
            name.removeprefix("is_")
            for name in ("is_asan", "is_msan", "is_ubsan")
            if assignments.get(name) is True
        }
        if len(enabled_sanitizers) > 1 or (
            self.oracle in {"asan", "msan", "ubsan"}
            and enabled_sanitizers != {self.oracle}
        ):
            raise ValueError("build_flags contain contradictory sanitizer assignments")
        if self.target_os == "linux":
            executable = PurePosixPath(self.command[0])
            if not executable.is_absolute() or executable.name != self.harness:
                raise ValueError("Linux command must execute the declared absolute harness path")
            if not PurePosixPath(self.corpus).is_absolute() or self.corpus not in self.command[1:]:
                raise ValueError("Linux command must include the declared absolute corpus path")
            if not PurePosixPath(self.source_root).is_absolute():
                raise ValueError("Linux campaign requires an absolute source_root")
            if len(self.revision) not in {40, 64}:
                raise ValueError("Linux campaign requires a full source revision")
            try:
                executable.relative_to(PurePosixPath(self.source_root) / "out")
            except ValueError as exc:
                raise ValueError("Linux harness must be inside source_root/out") from exc
            if self.schema_version == SCHEMA_VERSION:
                if self.oracle not in {"asan", "msan"}:
                    raise ValueError(
                        "Linux v3 build receipts require an asan or msan oracle"
                    )
                contract_paths = (
                    PurePosixPath(self.build_receipt),
                    PurePosixPath(self.target_catalog),
                )
                if any(not path.is_absolute() or ".." in path.parts for path in contract_paths):
                    raise ValueError(
                        "Linux campaign build receipt and target catalog must be absolute"
                    )
                for path in contract_paths:
                    try:
                        path.relative_to(PurePosixPath(self.source_root) / "out")
                    except ValueError as exc:
                        raise ValueError(
                            "Linux campaign build contracts must be inside source_root/out"
                        ) from exc
                if not re.fullmatch(r"[0-9a-f]{64}", self.build_receipt_sha256):
                    raise ValueError("build_receipt_sha256 must be a lowercase SHA-256 digest")
                if not re.fullmatch(r"[0-9a-f]{64}", self.target_catalog_sha256):
                    raise ValueError("target_catalog_sha256 must be a lowercase SHA-256 digest")
                if not re.fullmatch(r"//[A-Za-z0-9_./+-]+:[A-Za-z0-9_.+-]+", self.gn_label):
                    raise ValueError("gn_label must be a canonical GN target label")
        if self.replay_command:
            if self.target_os != "linux":
                raise ValueError("single-input browser replay currently requires Linux")
            if self.replay_command[0] != self.command[0]:
                raise ValueError("replay command must execute the declared campaign harness")
            if any(
                "{input}" in argument and argument != "{input}"
                for argument in self.replay_command
            ):
                raise ValueError("replay {input} placeholder must be a complete argument")
            if self.replay_command.count("{input}") != 1:
                raise ValueError("replay command requires exactly one {input} argument")
            if not PurePosixPath(self.source_root).is_absolute():
                raise ValueError("single-input replay requires an absolute source_root")
            if len(self.revision) not in {40, 64}:
                raise ValueError("single-input replay requires a full source revision")
        if self.timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class BrowserRunEvidence:
    manifest_sha256: str
    campaign_id: str
    component: str
    revision: str
    harness_sha256: str
    worker: str
    oracle: str
    process: str
    target_os: str
    started_at: str
    finished_at: str
    status: str
    returncode: int | None
    crash_signature: str = ""
    stdout: str = ""
    stderr: str = ""
    stdout_sha256: str = ""
    stderr_sha256: str = ""
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    artifacts: tuple[dict[str, object], ...] = ()
    error: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class RemoteRunner(Protocol):
    def __call__(self, argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]: ...


def load_manifest(path: str | Path) -> tuple[BrowserCampaign, str]:
    manifest_path = Path(path)
    data = manifest_path.read_bytes()
    raw = json.loads(data)
    if not isinstance(raw, dict):
        raise ValueError("browser campaign manifest must be a JSON object")
    campaign = BrowserCampaign.from_mapping(raw)
    return campaign, hashlib.sha256(data).hexdigest()


def execute_campaign(
    campaign: BrowserCampaign,
    manifest_sha256: str,
    *,
    runner: RemoteRunner | None = None,
) -> BrowserRunEvidence:
    campaign.validate()
    started = datetime.now(UTC)
    invoke = runner or _run_remote
    stage = "worker campaign preflight"
    stdout_sha256 = stderr_sha256 = ""
    stdout_bytes = stderr_bytes = 0
    stdout_truncated = stderr_truncated = False
    artifacts: tuple[dict[str, object], ...] = ()
    try:
        # The v2 manifest is also the replay-adapter contract, whose sustained
        # command historically had no artifact prefix. Require it only here.
        if campaign.target_os == "linux":
            _campaign_artifact_dir(campaign.command)
            if campaign.schema_version != SCHEMA_VERSION:
                raise ValueError("sustained Linux campaigns require the v3 build contract")
        preflight_command = shlex.join(
            (
                WORKER_PREFLIGHT,
                "campaign",
                campaign.revision.lower(),
                campaign.harness_sha256,
                campaign.source_root,
                campaign.command[0],
                campaign.corpus,
                campaign.build_receipt,
                campaign.build_receipt_sha256,
                campaign.target_catalog,
                campaign.target_catalog_sha256,
                campaign.gn_label,
                campaign.oracle,
            )
        )
        ready = invoke(
            ["ssh", "-o", "BatchMode=yes", "--", campaign.worker, preflight_command],
            min(campaign.timeout_seconds, 60),
        )
        expected_attestation = (
            f"CAMPAIGN revision={campaign.revision.lower()} "
            f"harness_sha256={campaign.harness_sha256} "
            f"catalog_sha256={campaign.target_catalog_sha256} "
            f"gn_label={campaign.gn_label} sanitizer={campaign.oracle}"
        )
        attestation_count = sum(
            line == expected_attestation for line in ready.stdout.splitlines()
        )
        if (
            ready.returncode != 0
            or not _CAMPAIGN_SUMMARY.search(ready.stdout)
            or attestation_count != 1
        ):
            finished = datetime.now(UTC)
            return BrowserRunEvidence(
                manifest_sha256=manifest_sha256,
                campaign_id=campaign.campaign_id,
                component=campaign.component,
                revision=campaign.revision,
                harness_sha256=campaign.harness_sha256,
                worker=campaign.worker,
                oracle=campaign.oracle,
                process=campaign.process,
                target_os=campaign.target_os,
                started_at=started.isoformat(),
                finished_at=finished.isoformat(),
                status="ERROR",
                returncode=ready.returncode,
                stdout=ready.stdout,
                stderr=ready.stderr,
                error=(
                    "dedicated browser worker failed the mandatory build attestation; "
                    "campaign was not launched"
                ),
            )
        stage = "remote campaign"
        if campaign.target_os == "linux":
            supervised = _run_supervised_campaign(campaign, invoke)
            target_returncode = _record_integer(
                supervised["returncode"], "supervised.returncode"
            )
            timed_out = _record_boolean(supervised["timed_out"], "supervised.timed_out")
            stdout = _record_string(supervised["stdout"], "supervised.stdout")
            stderr = _record_string(supervised["stderr"], "supervised.stderr")
            stdout_sha256 = _record_string(
                supervised["stdout_sha256"], "supervised.stdout_sha256"
            )
            stderr_sha256 = _record_string(
                supervised["stderr_sha256"], "supervised.stderr_sha256"
            )
            stdout_bytes = _record_integer(
                supervised["stdout_bytes"], "supervised.stdout_bytes"
            )
            stderr_bytes = _record_integer(
                supervised["stderr_bytes"], "supervised.stderr_bytes"
            )
            stdout_truncated = _record_boolean(
                supervised["stdout_truncated"], "supervised.stdout_truncated"
            )
            stderr_truncated = _record_boolean(
                supervised["stderr_truncated"], "supervised.stderr_truncated"
            )
            supervised_artifacts = supervised["artifacts"]
            if not isinstance(supervised_artifacts, tuple):
                raise RuntimeError("invalid campaign supervisor artifact result")
            artifacts = supervised_artifacts
        else:
            result = invoke(
                [
                    "ssh",
                    "-o",
                    "BatchMode=yes",
                    "--",
                    campaign.worker,
                    shlex.join(campaign.command),
                ],
                campaign.timeout_seconds,
            )
            target_returncode = result.returncode
            timed_out = False
            stdout, stderr = result.stdout, result.stderr
            stdout_bytes, stderr_bytes = len(stdout.encode()), len(stderr.encode())
            stdout_sha256 = hashlib.sha256(stdout.encode()).hexdigest()
            stderr_sha256 = hashlib.sha256(stderr.encode()).hexdigest()
        signature = crash_signature(campaign.oracle, stdout, stderr)
        confirmed = bool(signature) and target_returncode != 255 and (
            campaign.oracle == "pageheap-cdb" or target_returncode != 0
        )
        if confirmed:
            status, error = "CRASH", ""
        elif signature:
            status = "ERROR"
            error = (
                "oracle marker was not accompanied by a failing target exit "
                "or arrived with SSH transport failure"
            )
        else:
            status = "TIMEOUT" if timed_out else ("CLEAN" if target_returncode == 0 else "ERROR")
            error = ""
        returncode: int | None = target_returncode
    except subprocess.TimeoutExpired as exc:
        status, returncode, signature = "TIMEOUT", None, ""
        stdout = _text(exc.stdout)
        stderr = _text(exc.stderr)
        error = f"{stage} exceeded its timeout"
    except (OSError, RuntimeError, ValueError) as exc:
        status, returncode, signature, stdout, stderr, error = (
            "ERROR",
            None,
            "",
            "",
            "",
            str(exc),
        )
    finished = datetime.now(UTC)
    return BrowserRunEvidence(
        manifest_sha256=manifest_sha256,
        campaign_id=campaign.campaign_id,
        component=campaign.component,
        revision=campaign.revision,
        harness_sha256=campaign.harness_sha256,
        worker=campaign.worker,
        oracle=campaign.oracle,
        process=campaign.process,
        target_os=campaign.target_os,
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        status=status,
        returncode=returncode,
        crash_signature=signature,
        stdout=stdout,
        stderr=stderr,
        stdout_sha256=stdout_sha256,
        stderr_sha256=stderr_sha256,
        stdout_bytes=stdout_bytes,
        stderr_bytes=stderr_bytes,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
        artifacts=artifacts,
        error=error,
    )


def _campaign_artifact_dir(command: Sequence[str]) -> PurePosixPath:
    prefixes = [
        argument.removeprefix("-artifact_prefix=")
        for argument in command
        if argument.startswith("-artifact_prefix=")
    ]
    if len(prefixes) != 1:
        raise ValueError("Linux campaign requires exactly one -artifact_prefix argument")
    raw = prefixes[0]
    path = PurePosixPath(raw)
    if not raw.endswith("/") or not path.is_absolute() or ".." in path.parts:
        raise ValueError("campaign artifact prefix must be an absolute directory ending in '/'")
    try:
        path.relative_to(CAMPAIGN_ARTIFACT_ROOT)
    except ValueError as exc:
        raise ValueError("campaign artifact prefix must be inside /srv/0verse/artifacts") from exc
    if path == CAMPAIGN_ARTIFACT_ROOT:
        raise ValueError("campaign artifact prefix must use a dedicated subdirectory")
    return path


def _run_supervised_campaign(
    campaign: BrowserCampaign, invoke: RemoteRunner
) -> dict[str, object]:
    marker = secrets.token_hex(16)
    helper_path = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "browser"
        / "run-campaign.py"
    )
    if not helper_path.is_file():
        raise ValueError(f"browser campaign supervisor is missing: {helper_path}")
    header = {
        "protocol": CAMPAIGN_SUPERVISOR_PROTOCOL,
        "marker": marker,
        "helper_sha256": hashlib.sha256(helper_path.read_bytes()).hexdigest(),
        "worker_hostname": "browser",
        "worker_user": "browser",
        "worker_group": "browser",
        "bootstrap_marker": "/srv/0verse/.browser-worker",
        "bootstrap_marker_owner": "root",
        "bootstrap_marker_group": "browser",
        "revision": campaign.revision.lower(),
        "harness": campaign.command[0],
        "harness_sha256": campaign.harness_sha256,
        "source_root": campaign.source_root,
        "corpus": campaign.corpus,
        "artifact_root": str(CAMPAIGN_ARTIFACT_ROOT),
        "artifact_dir": str(_campaign_artifact_dir(campaign.command)),
        "argv": list(campaign.command),
        "timeout_seconds": campaign.timeout_seconds,
        "env": dict(campaign.env),
    }
    token = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
    ).decode().rstrip("=")
    remote_command = shlex.join(("python3", CAMPAIGN_SUPERVISOR, token))
    transport = invoke(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ServerAliveInterval=30",
            "-o",
            "ServerAliveCountMax=3",
            "--",
            campaign.worker,
            remote_command,
        ],
        campaign.timeout_seconds + 30,
    )
    if transport.returncode != 0:
        raise RuntimeError(
            "dedicated browser campaign supervisor failed: "
            + (transport.stderr.strip() or f"SSH exit {transport.returncode}")
        )
    prefix = f"0VERSE-BROWSER-CAMPAIGN:{marker}:"
    lines = transport.stdout.splitlines()
    records = [line.removeprefix(prefix) for line in lines if line.startswith(prefix)]
    if len(records) != 1 or len(lines) != 1:
        raise RuntimeError("missing, duplicate, or contaminated campaign supervisor record")
    try:
        raw = json.loads(base64.b64decode(records[0], validate=True))
    except (ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("invalid campaign supervisor record") from exc
    if (
        not isinstance(raw, dict)
        or raw.get("protocol") != CAMPAIGN_SUPERVISOR_PROTOCOL
        or raw.get("marker") != marker
    ):
        raise RuntimeError("campaign supervisor record identity mismatch")
    identity = raw.get("identity")
    if (
        not isinstance(identity, dict)
        or identity.get("hostname") != "browser"
        or identity.get("user") != "browser"
        or identity.get("group") != "browser"
        or not isinstance(identity.get("bootstrap_marker_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", identity["bootstrap_marker_sha256"])
    ):
        raise RuntimeError("campaign supervisor worker identity mismatch")
    stdout = _decode_stream_record(raw.get("stdout"), "stdout")
    stderr = _decode_stream_record(raw.get("stderr"), "stderr")
    artifacts = _decode_artifacts(raw.get("artifacts"))
    return {
        "returncode": _record_integer(raw.get("target_returncode"), "target_returncode"),
        "timed_out": _record_boolean(raw.get("timed_out"), "timed_out"),
        "stdout": stdout[0],
        "stdout_sha256": stdout[1],
        "stdout_bytes": stdout[2],
        "stdout_truncated": stdout[3],
        "stderr": stderr[0],
        "stderr_sha256": stderr[1],
        "stderr_bytes": stderr[2],
        "stderr_truncated": stderr[3],
        "artifacts": artifacts,
    }


def _decode_stream_record(value: object, name: str) -> tuple[str, str, int, bool]:
    if not isinstance(value, dict):
        raise RuntimeError(f"invalid campaign {name} record")
    encoded, digest = value.get("tail_base64"), value.get("sha256")
    size, truncated = value.get("bytes"), value.get("truncated")
    if (
        not isinstance(encoded, str)
        or not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
    ):
        raise RuntimeError(f"invalid campaign {name} digest")
    size = _record_integer(size, f"{name}.bytes")
    truncated = _record_boolean(truncated, f"{name}.truncated")
    try:
        tail = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise RuntimeError(f"invalid campaign {name} tail") from exc
    if size < 0 or len(tail) > MAX_RETAINED_STREAM_BYTES or len(tail) > size:
        raise RuntimeError(f"inconsistent campaign {name} size")
    if truncated:
        if size <= MAX_RETAINED_STREAM_BYTES or len(tail) != MAX_RETAINED_STREAM_BYTES:
            raise RuntimeError(f"inconsistent campaign {name} truncation")
    elif len(tail) != size or hashlib.sha256(tail).hexdigest() != digest:
        raise RuntimeError(f"inconsistent campaign {name} digest")
    return tail.decode("utf-8", "replace"), digest, size, truncated


def _decode_artifacts(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list) or len(value) > 64:
        raise RuntimeError("invalid campaign artifact inventory")
    result: list[dict[str, object]] = []
    retrieved_bytes = 0
    names: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            raise RuntimeError("invalid campaign artifact record")
        name, digest = item.get("name"), item.get("sha256")
        size, retrieved = item.get("size"), item.get("retrieved")
        if (
            not isinstance(name, str)
            or not name
            or "/" in name
            or name in {".", ".."}
            or any(ord(character) < 32 for character in name)
        ):
            raise RuntimeError("invalid campaign artifact name")
        if name in names:
            raise RuntimeError("duplicate campaign artifact name")
        names.add(name)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuntimeError("invalid campaign artifact digest")
        size = _record_integer(size, "artifact.size")
        retrieved = _record_boolean(retrieved, "artifact.retrieved")
        if size < 0:
            raise RuntimeError("invalid campaign artifact size")
        record: dict[str, object] = {
            "name": name,
            "size": size,
            "sha256": digest,
            "retrieved": retrieved,
        }
        if retrieved:
            if size > MAX_CAMPAIGN_ARTIFACT_BYTES:
                raise RuntimeError("retrieved campaign artifact exceeds the size limit")
            encoded = item.get("content_base64")
            if not isinstance(encoded, str):
                raise RuntimeError("retrieved campaign artifact is missing content")
            try:
                content = base64.b64decode(encoded, validate=True)
            except ValueError as exc:
                raise RuntimeError("invalid campaign artifact content") from exc
            if len(content) != size or hashlib.sha256(content).hexdigest() != digest:
                raise RuntimeError("campaign artifact content does not match its inventory")
            retrieved_bytes += size
            if retrieved_bytes > MAX_RETRIEVED_ARTIFACT_BYTES:
                raise RuntimeError("retrieved campaign artifacts exceed the total size limit")
            record["content_base64"] = encoded
        result.append(record)
    return tuple(result)


def _record_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeError(f"invalid campaign record integer: {name}")
    return value


def _record_boolean(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise RuntimeError(f"invalid campaign record boolean: {name}")
    return value


def _record_string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise RuntimeError(f"invalid campaign record string: {name}")
    return value


def crash_signature(oracle: str, stdout: str, stderr: str) -> str:
    """Return the first oracle-specific crash marker; never infer from rc alone."""
    text = f"{stdout}\n{stderr}".lower()
    markers: dict[str, tuple[str, ...]] = {
        "asan": (
            "ERROR: AddressSanitizer",
            "SUMMARY: AddressSanitizer",
            "AddressSanitizer:DEADLYSIGNAL",
            "ERROR: libFuzzer: deadly signal",
        ),
        "msan": ("WARNING: MemorySanitizer", "SUMMARY: MemorySanitizer"),
        "ubsan": ("runtime error:", "SUMMARY: UndefinedBehaviorSanitizer"),
        "browser-crash": ("Received signal ", "FATAL:", "CHECK failed:"),
        "pageheap-cdb": ("Access violation", "APPLICATION_VERIFIER", "Page heap:"),
    }
    for marker in markers[oracle]:
        if marker.lower() in text:
            return marker
    return ""


class _CappedRemoteCapture:
    def __init__(self, maximum: int, exceeded: threading.Event) -> None:
        self.maximum = maximum
        self.exceeded = exceeded
        self.data = bytearray()
        self.error: OSError | None = None

    def consume(self, source: object) -> None:
        try:
            while chunk := source.read(64 * 1024):  # type: ignore[attr-defined]
                remaining = self.maximum - len(self.data)
                if len(chunk) > remaining:
                    self.data.extend(chunk[: max(remaining, 0)])
                    self.exceeded.set()
                    return
                self.data.extend(chunk)
        except OSError as exc:
            self.error = exc


def _stop_remote_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _run_remote(argv: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
    if not argv or argv[0] != "ssh" or any("\x00" in argument for argument in argv):
        raise ValueError("remote command must be a NUL-free ssh argument vector")
    process = subprocess.Popen(  # foxguard: ignore[py/no-command-injection]
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None and process.stderr is not None
    exceeded = threading.Event()
    stdout = _CappedRemoteCapture(MAX_REMOTE_STDOUT_BYTES, exceeded)
    stderr = _CappedRemoteCapture(MAX_REMOTE_STDERR_BYTES, exceeded)
    threads = [
        threading.Thread(target=stdout.consume, args=(process.stdout,), daemon=True),
        threading.Thread(target=stderr.consume, args=(process.stderr,), daemon=True),
    ]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + timeout
    try:
        while process.poll() is None:
            if exceeded.is_set():
                raise RuntimeError("remote SSH output exceeded its retained byte limit")
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(argv, timeout)
            time.sleep(0.01)
    except BaseException:
        _stop_remote_process(process)
        raise
    finally:
        for thread in threads:
            thread.join(timeout=5)
    if any(thread.is_alive() for thread in threads):
        _stop_remote_process(process)
        raise RuntimeError("remote SSH output capture did not terminate")
    if stdout.error is not None or stderr.error is not None:
        raise OSError("remote SSH output capture failed") from (stdout.error or stderr.error)
    if exceeded.is_set():
        raise RuntimeError("remote SSH output exceeded its retained byte limit")
    return subprocess.CompletedProcess(
        argv,
        process.returncode,
        bytes(stdout.data).decode("utf-8", "replace"),
        bytes(stderr.data).decode("utf-8", "replace"),
    )


def _env_pairs(value: object, name: str) -> tuple[tuple[str, str], ...]:
    """Bounded optional extra environment for the fuzzer process (e.g. DISPLAY).

    Keys must be valid shell identifiers; values are plain bounded strings. The
    supervisor merges these BEFORE its sanitizer options so oracle control stays
    with the runner."""
    if not isinstance(value, Mapping) or len(value) > 16:
        raise ValueError(f"{name} must be a mapping of at most 16 entries")
    result: list[tuple[str, str]] = []
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not isinstance(item, str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
            or len(item) > 4096
            or "\x00" in item
        ):
            raise ValueError(f"{name} has an invalid entry")
        result.append((key, item))
    return tuple(result)


def _string_sequence(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be an array of strings")
    return tuple(value)


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def _integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    return value

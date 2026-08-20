"""Hash-bound single-input execution on a dedicated browser component worker."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol, cast

from ..browser_campaign import BrowserCampaign, crash_signature, load_manifest
from .contract import (
    ExecutionCapabilities,
    ExecutionEvidence,
    ExecutionRequest,
    ExecutionStatus,
    sha256_bytes,
    sha256_file,
)

REPLAY_PROTOCOL_VERSION = "0verse.browser-replay/v1"
DEFAULT_REMOTE_HELPER = PurePosixPath(
    "/srv/0verse/0verse/scripts/browser/replay-candidate.py"
)
DEFAULT_BOOTSTRAP_MARKER = PurePosixPath("/srv/0verse/.browser-worker")
EXPECTED_WORKER_HOSTNAME = "browser"
EXPECTED_WORKER_USER = "browser"
EXPECTED_WORKER_GROUP = "browser"
EXPECTED_BOOTSTRAP_MARKER_OWNER = "root"
EXPECTED_BOOTSTRAP_MARKER_GROUP = "browser"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_MARKER = re.compile(r"[0-9a-f]{32}")
MAX_BROWSER_INPUT_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class BrowserTransportResult:
    marker: str
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""

    def __post_init__(self) -> None:
        if not _MARKER.fullmatch(self.marker):
            raise ValueError("invalid browser transport marker")


class BrowserCandidateTransport(Protocol):
    @property
    def helper_sha256(self) -> str: ...

    def run(
        self, campaign: BrowserCampaign, request: ExecutionRequest
    ) -> BrowserTransportResult: ...


class SshBrowserCandidateTransport:
    """Send a framed candidate over SSH stdin to the fixed remote helper."""

    def __init__(
        self,
        *,
        local_helper: str | Path | None = None,
        remote_helper: str | PurePosixPath = DEFAULT_REMOTE_HELPER,
    ) -> None:
        packaged_helper = Path(__file__).resolve().parent / "replay-candidate.py"
        repository_helper = (
            Path(__file__).resolve().parents[3]
            / "scripts"
            / "browser"
            / "replay-candidate.py"
        )
        default_local = packaged_helper if packaged_helper.is_file() else repository_helper
        self.local_helper = Path(local_helper) if local_helper is not None else default_local
        self.remote_helper = PurePosixPath(remote_helper)
        if not self.local_helper.is_file():
            raise ValueError(f"browser replay helper is missing: {self.local_helper}")
        if not self.remote_helper.is_absolute():
            raise ValueError("remote browser replay helper path must be absolute")
        self._helper_sha256 = sha256_file(self.local_helper)

    @property
    def helper_sha256(self) -> str:
        return self._helper_sha256

    def run(
        self, campaign: BrowserCampaign, request: ExecutionRequest
    ) -> BrowserTransportResult:
        marker = secrets.token_hex(16)
        header = {
            "protocol": REPLAY_PROTOCOL_VERSION,
            "marker": marker,
            "target_sha256": request.target_sha256,
            "input_sha256": request.input_sha256,
            "helper_sha256": self.helper_sha256,
            "worker_hostname": EXPECTED_WORKER_HOSTNAME,
            "worker_user": EXPECTED_WORKER_USER,
            "worker_group": EXPECTED_WORKER_GROUP,
            "bootstrap_marker": str(DEFAULT_BOOTSTRAP_MARKER),
            "bootstrap_marker_owner": EXPECTED_BOOTSTRAP_MARKER_OWNER,
            "bootstrap_marker_group": EXPECTED_BOOTSTRAP_MARKER_GROUP,
            "oracle": campaign.oracle,
            "revision": campaign.revision.lower(),
            "timeout_seconds": request.timeout,
            "source_root": campaign.source_root,
            "harness": campaign.replay_command[0],
            "argv": list(campaign.replay_command),
        }
        framed = json.dumps(header, separators=(",", ":")).encode() + b"\n" + request.payload
        remote_command = f"python3 {shlex.quote(str(self.remote_helper))}"
        result = subprocess.run(  # foxguard: ignore[py/taint-command-injection]
            # The only remote argv is a fixed, operator-reviewed helper path.
            # Manifest strings and candidate bytes travel over SSH stdin.
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "--",
                campaign.worker,
                remote_command,
            ],
            input=framed,
            capture_output=True,
            timeout=request.timeout + 20,
            check=False,
        )
        return BrowserTransportResult(
            marker=marker,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )


class BrowserExecutionBackend:
    """Execution-contract adapter for one Linux browser component harness."""

    name = "browser-component-worker"

    def __init__(
        self,
        manifest_path: str | Path,
        *,
        transport: BrowserCandidateTransport | None = None,
        replay_timeout: float = 30.0,
    ) -> None:
        self.manifest_path = Path(manifest_path).resolve()
        campaign, digest = load_manifest(self.manifest_path)
        self._validate_profile(campaign)
        if replay_timeout <= 0 or replay_timeout > campaign.timeout_seconds:
            raise ValueError("browser replay timeout must fit within campaign timeout")
        self._campaign = campaign
        self._manifest_sha256 = digest
        self.transport = transport or SshBrowserCandidateTransport()
        if not _HEX64.fullmatch(self.transport.helper_sha256):
            raise ValueError("browser transport has invalid helper SHA-256")
        self.capabilities = ExecutionCapabilities(
            formats=frozenset({"ELF"}),
            vectors=frozenset({"file"}),
            oracles=frozenset({campaign.oracle}),
            default_timeout=replay_timeout,
        )

    @staticmethod
    def _validate_profile(campaign: BrowserCampaign) -> None:
        campaign.validate()
        if campaign.target_os != "linux":
            raise ValueError("browser execution adapter currently supports Linux only")
        if campaign.oracle not in {"asan", "msan", "ubsan", "browser-crash"}:
            raise ValueError("browser execution adapter requires a Linux crash oracle")
        if not campaign.replay_command:
            raise ValueError("browser execution adapter requires replay_command")

    def _reload(self) -> BrowserCampaign:
        campaign, digest = load_manifest(self.manifest_path)
        self._validate_profile(campaign)
        if digest != self._manifest_sha256:
            raise ValueError("browser campaign manifest changed after adapter creation")
        return campaign

    def run(self, request: ExecutionRequest) -> ExecutionEvidence:
        environment = self._environment(self._campaign)
        if not self.capabilities.supports(
            request.target_format, request.vector, request.oracle
        ):
            return self._evidence(
                request,
                environment,
                status="UNSUPPORTED",
                error=(
                    f"{self.name} does not support {request.target_format}/"
                    f"{request.vector}/{request.oracle}"
                ),
            )
        if request.argv or request.env:
            return self._evidence(
                request,
                environment,
                status="UNSUPPORTED",
                error="browser replay accepts only the manifest-bound file vector",
            )
        if request.timeout > self._campaign.timeout_seconds:
            return self._evidence(
                request,
                environment,
                status="ERROR",
                error="browser replay timeout exceeds the manifest limit",
            )
        if len(request.payload) > MAX_BROWSER_INPUT_BYTES:
            return self._evidence(
                request,
                environment,
                status="ERROR",
                error="browser replay input exceeds 64 MiB",
            )
        if Path(request.target).name != self._campaign.harness:
            return self._evidence(
                request,
                environment,
                status="ERROR",
                error="local target basename does not match the declared browser harness",
            )
        try:
            campaign = self._reload()
            environment = self._environment(campaign)
            transport = self.transport.run(campaign, request)
            return self._normalize(request, campaign, environment, transport)
        except subprocess.TimeoutExpired as exc:
            return self._evidence(
                request,
                environment,
                status="TIMEOUT",
                stdout=_text(exc.stdout),
                stderr=_text(exc.stderr),
                error="browser SSH/helper transport timed out",
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return self._evidence(
                request,
                environment,
                status="ERROR",
                error=str(exc),
            )

    def _normalize(
        self,
        request: ExecutionRequest,
        campaign: BrowserCampaign,
        environment: dict[str, str],
        transport: BrowserTransportResult,
    ) -> ExecutionEvidence:
        helper_stdout = transport.stdout.decode("utf-8", "replace")
        helper_stderr = transport.stderr.decode("utf-8", "replace")
        if transport.returncode != 0:
            detail = (
                "SSH transport failed"
                if transport.returncode == 255
                else "replay helper failed"
            )
            return self._evidence(
                request,
                environment,
                status="ERROR",
                stderr=helper_stderr[-400:],
                error=f"{detail} with exit {transport.returncode}",
            )
        try:
            def record(name: str) -> str:
                return _record(helper_stdout, transport.marker, name)

            worker_hostname = record("WORKER-HOSTNAME")
            worker_user = record("WORKER-USER")
            worker_group = record("WORKER-GROUP")
            marker_owner = record("BOOTSTRAP-MARKER-OWNER")
            marker_group = record("BOOTSTRAP-MARKER-GROUP")
            marker_hash = record("BOOTSTRAP-MARKER-SHA256")
            bootstrap_hash = record("BOOTSTRAP-SHA256")
            oracle = record("ORACLE")
            helper_hash = record("HELPER-SHA256")
            target_before = record("TARGET-SHA256-BEFORE")
            target_after = record("TARGET-SHA256-AFTER")
            input_hash = record("INPUT-SHA256")
            revision_before = record("REVISION-BEFORE")
            revision_after = record("REVISION-AFTER")
            target_exit = int(record("TARGET-EXIT"))
            timed_out = record("TIMED-OUT")
            stdout = _b64(record("STDOUT-B64"), "stdout")
            stderr = _b64(record("STDERR-B64"), "stderr")
            stdout_hash = record("STDOUT-SHA256")
            stderr_hash = record("STDERR-SHA256")
            stdout_tail_hash = record("STDOUT-TAIL-SHA256")
            stderr_tail_hash = record("STDERR-TAIL-SHA256")
            stdout_truncated = record("STDOUT-TRUNCATED")
            stderr_truncated = record("STDERR-TRUNCATED")
        except (TypeError, ValueError) as exc:
            return self._evidence(
                request,
                environment,
                status="ERROR",
                stderr=helper_stderr[-400:],
                error=f"invalid browser helper evidence: {exc}",
            )

        identities = {
            "worker-hostname": (worker_hostname, EXPECTED_WORKER_HOSTNAME),
            "worker-user": (worker_user, EXPECTED_WORKER_USER),
            "worker-group": (worker_group, EXPECTED_WORKER_GROUP),
            "bootstrap-marker-owner": (
                marker_owner,
                EXPECTED_BOOTSTRAP_MARKER_OWNER,
            ),
            "bootstrap-marker-group": (
                marker_group,
                EXPECTED_BOOTSTRAP_MARKER_GROUP,
            ),
            "oracle": (oracle, campaign.oracle),
            "helper": (helper_hash, self.transport.helper_sha256),
            "target-before": (target_before, request.target_sha256),
            "target-after": (target_after, request.target_sha256),
            "input": (input_hash, request.input_sha256),
            "revision-before": (revision_before, campaign.revision.lower()),
            "revision-after": (revision_after, campaign.revision.lower()),
        }
        mismatch = next(
            (name for name, (observed, expected) in identities.items() if observed != expected),
            "",
        )
        if mismatch:
            return self._evidence(
                request,
                environment,
                status="ERROR",
                error=f"browser replay {mismatch} identity mismatch",
            )
        hashes = (
            marker_hash,
            bootstrap_hash,
            stdout_hash,
            stderr_hash,
            stdout_tail_hash,
            stderr_tail_hash,
        )
        if any(not _HEX64.fullmatch(value) for value in hashes):
            return self._evidence(
                request,
                environment,
                status="ERROR",
                error="browser replay returned an invalid output SHA-256",
            )
        booleans = (timed_out, stdout_truncated, stderr_truncated)
        if any(value not in {"0", "1"} for value in booleans):
            return self._evidence(
                request,
                environment,
                status="ERROR",
                error="browser replay returned invalid boolean evidence",
            )
        if sha256_bytes(stdout) != stdout_tail_hash:
            return self._evidence(
                request,
                environment,
                status="ERROR",
                error="browser stdout tail SHA-256 mismatch",
            )
        if sha256_bytes(stderr) != stderr_tail_hash:
            return self._evidence(
                request,
                environment,
                status="ERROR",
                error="browser stderr tail SHA-256 mismatch",
            )
        if stdout_truncated == "0" and stdout_tail_hash != stdout_hash:
            return self._evidence(
                request, environment, status="ERROR", error="browser stdout SHA-256 mismatch"
            )
        if stderr_truncated == "0" and stderr_tail_hash != stderr_hash:
            return self._evidence(
                request, environment, status="ERROR", error="browser stderr SHA-256 mismatch"
            )
        environment.update(
            {
                "replay_protocol": REPLAY_PROTOCOL_VERSION,
                "worker_hostname": worker_hostname,
                "worker_user": worker_user,
                "worker_group": worker_group,
                "bootstrap_marker_owner": marker_owner,
                "bootstrap_marker_group": marker_group,
                "bootstrap_marker_sha256": marker_hash,
                "bootstrap_sha256": bootstrap_hash,
                "attested_oracle": oracle,
                "helper_sha256": helper_hash,
                "target_sha256_before": target_before,
                "target_sha256_after": target_after,
                "revision_before": revision_before,
                "revision_after": revision_after,
                "stdout_sha256": stdout_hash,
                "stderr_sha256": stderr_hash,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
            }
        )
        if timed_out == "1":
            return self._evidence(
                request,
                environment,
                status="TIMEOUT",
                returncode=target_exit,
                stdout=stdout.decode("utf-8", "replace"),
                stderr=stderr.decode("utf-8", "replace"),
                error="browser component replay exceeded its target timeout",
            )

        decoded_stdout = stdout.decode("utf-8", "replace")
        decoded_stderr = stderr.decode("utf-8", "replace")
        signature = _corroborated_crash_signature(
            campaign.oracle, decoded_stdout, decoded_stderr
        )
        if signature and target_exit != 0:
            status, error = "CRASH", ""
        elif signature:
            status, error = "ERROR", "oracle marker was not accompanied by a failing target exit"
        elif target_exit == 0:
            status, error = "CLEAN", ""
        else:
            status, error = "ERROR", "failing browser target exit lacks an oracle marker"
        return self._evidence(
            request,
            environment,
            status=cast(ExecutionStatus, status),
            returncode=target_exit,
            crash_signature=signature if status == "CRASH" else "",
            stdout=decoded_stdout,
            stderr=decoded_stderr,
            error=error,
        )

    def _environment(self, campaign: BrowserCampaign) -> dict[str, str]:
        return {
            "worker": campaign.worker,
            "component": campaign.component,
            "process": campaign.process,
            "target_os": campaign.target_os,
            "revision": campaign.revision.lower(),
            "manifest_sha256": self._manifest_sha256,
            "bounty_program": campaign.bounty_program,
            "scope_url": campaign.bounty_scope_url,
            "scope_checked_at": campaign.scope_checked_at,
            "authorization_sha256": hashlib.sha256(
                campaign.authorization.encode()
            ).hexdigest(),
        }

    def _evidence(
        self,
        request: ExecutionRequest,
        environment: dict[str, str],
        *,
        status: ExecutionStatus,
        returncode: int | None = None,
        crash_signature: str = "",
        stdout: str = "",
        stderr: str = "",
        error: str = "",
    ) -> ExecutionEvidence:
        return ExecutionEvidence(
            backend=self.name,
            status=status,
            oracle=self._campaign.oracle,
            target_sha256=request.target_sha256,
            input_sha256=request.input_sha256,
            environment=environment,
            returncode=returncode,
            crash_signature=crash_signature,
            stdout=stdout,
            stderr=stderr,
            error=error,
        )


def _record(output: str, marker: str, name: str) -> str:
    prefix = f"0VERSE-BROWSER-{marker}-{name}:"
    values: list[str] = re.findall(
        rf"^{re.escape(prefix)}(.*)$", output, re.MULTILINE
    )
    if len(values) != 1:
        raise ValueError(f"expected exactly one {name} record")
    return values[0].strip()


def _b64(value: str, name: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError(f"invalid {name} base64") from exc


def _corroborated_crash_signature(oracle: str, stdout: str, stderr: str) -> str:
    """Require structured runtime evidence, not one candidate-reflectable phrase."""
    output = f"{stdout}\n{stderr}"
    signature = crash_signature(oracle, stdout, stderr)
    if not signature:
        return ""
    if oracle == "asan":
        error = re.search(r"^==[0-9]+==ERROR: AddressSanitizer:", output, re.MULTILINE)
        summary = re.search(r"^SUMMARY: AddressSanitizer:", output, re.MULTILINE)
        deadly = "AddressSanitizer:DEADLYSIGNAL" in output and re.search(
            r"^\s*#[0-9]+\s+0x[0-9a-f]+", output, re.MULTILINE | re.IGNORECASE
        )
        return signature if (error and summary) or deadly else ""
    if oracle == "msan":
        warning = re.search(r"^==[0-9]+==WARNING: MemorySanitizer:", output, re.MULTILINE)
        summary = re.search(r"^SUMMARY: MemorySanitizer:", output, re.MULTILINE)
        return signature if warning and summary else ""
    if oracle == "ubsan":
        runtime_error = re.search(r"^.+:[0-9]+:[0-9]+: runtime error:", output, re.MULTILINE)
        stack = re.search(r"^\s*#[0-9]+\s+0x[0-9a-f]+", output, re.MULTILINE | re.IGNORECASE)
        return signature if runtime_error and stack else ""
    if oracle == "browser-crash":
        stack = re.search(r"^\s*#[0-9]+\s+0x[0-9a-f]+", output, re.MULTILINE | re.IGNORECASE)
        return signature if stack else ""
    return ""


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value

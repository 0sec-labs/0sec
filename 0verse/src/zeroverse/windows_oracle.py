"""Windows PE crash-oracle transport.

The analysis process stays on Linux/macOS and dispatches a PE plus PoV to an
authorized Windows host over SSH.  The remote side runs Dr. Memory and returns
only its text report; deterministic parsing/adjudication remains local.
"""

from __future__ import annotations

import base64
import contextlib
import os
import re
import secrets
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .oracle import RunResult

if TYPE_CHECKING:
    from .windows_scope import WindowsScope

WINDOWS_HOST_ENV = "ZEROVERSE_WINDOWS_HOST"
_BUILDLAB_RE = re.compile(r"^0VERSE-BUILDLABEX:(?P<build>\S.+)$", re.MULTILINE)
_BINARY_SHA_RE = re.compile(
    r"^0VERSE-BINARY-SHA256:(?P<digest>[0-9a-fA-F]{64})\r?$", re.MULTILINE
)
_INPUT_SHA_RE = re.compile(
    r"^0VERSE-INPUT-SHA256:(?P<digest>[0-9a-fA-F]{64})\r?$", re.MULTILINE
)
_SSH_HOST_RE = re.compile(r"^[A-Za-z0-9_.:@-]+$")


def _invalid_run(detail: str, *, timed_out: bool = False) -> RunResult:
    """Return a fail-closed result for transport/setup failures, never a clean verdict."""
    return RunResult(
        False,
        stderr=detail,
        valid=False,
        timed_out=timed_out,
        infrastructure_error="" if timed_out else detail,
    )


def extract_buildlabex(report: str) -> str:
    """Return one unambiguous Windows build revision captured beside a report."""
    builds = {match.group("build").strip() for match in _BUILDLAB_RE.finditer(report)}
    return builds.pop() if len(builds) == 1 else ""


def extract_binary_sha256(report: str) -> str:
    """Return one unambiguous remote hash for the uploaded PE."""
    digests = {match.group("digest").lower() for match in _BINARY_SHA_RE.finditer(report)}
    return digests.pop() if len(digests) == 1 else ""


def extract_input_sha256(report: str) -> str:
    """Return one unambiguous remote hash for the uploaded PoV input."""
    digests = {match.group("digest").lower() for match in _INPUT_SHA_RE.finditer(report)}
    return digests.pop() if len(digests) == 1 else ""


def _encoded_powershell(script: str) -> str:
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {encoded}"


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


@dataclass(frozen=True)
class WindowsWorker:
    """SSH-backed, fail-closed Windows execution worker."""

    host: str
    connect_timeout: float = 8.0
    authorization: WindowsScope | None = None
    lab_only: bool = False
    _cleanup_capabilities: dict[str, tuple[str, str, float]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if not self.host or self.host.startswith("-") or not _SSH_HOST_RE.fullmatch(self.host):
            raise ValueError("Windows worker must be a plain SSH host or user@host token")
        if self.authorization is not None and self.lab_only:
            raise ValueError("Windows worker cannot combine signed scope and lab-only mode")
        if self.authorization is None and not self.lab_only:
            raise ValueError("Windows worker requires signed scope authorization or lab_only=True")
        if self.authorization is not None:
            self.authorization.require_signed_authorization()
            if self.authorization.worker != self.host:
                raise ValueError("Windows worker host does not match signed scope")

    @classmethod
    def from_env(cls) -> WindowsWorker | None:
        host = os.environ.get(WINDOWS_HOST_ENV, "").strip()
        return cls(host, lab_only=True) if host else None

    def _require_authorized(self) -> None:
        if self.authorization is not None:
            self.authorization.require_signed_authorization()
        elif not self.lab_only:
            raise ValueError("Windows worker authorization is unavailable")

    def _ssh(self, script: str, *, timeout: float) -> subprocess.CompletedProcess[bytes]:
        self._require_authorized()
        return subprocess.run(
            [
                "ssh", "-o", "BatchMode=yes", "-o",
                f"ConnectTimeout={max(1, int(self.connect_timeout))}",
                "--", self.host, _encoded_powershell(script),
            ],
            capture_output=True,
            timeout=timeout,
            check=False,
        )

    def _ssh_cleanup(
        self, *, timeout: float, capability: str
    ) -> subprocess.CompletedProcess[bytes]:
        """Use the already-authorized run's narrow cleanup path after expiry."""
        authorized = self._cleanup_capabilities.pop(capability, None)
        if authorized is None:
            raise ValueError("Windows cleanup capability is missing or already consumed")
        script, host, expires_at = authorized
        if (
            host != self.host
            or time.monotonic() > expires_at
        ):
            raise ValueError("Windows cleanup capability is expired or command-bound elsewhere")
        if self.lab_only:
            return self._ssh(script, timeout=timeout)
        return subprocess.run(
            [
                "ssh", "-o", "BatchMode=yes", "-o",
                f"ConnectTimeout={max(1, int(self.connect_timeout))}",
                "--", self.host, _encoded_powershell(script),
            ],
            capture_output=True,
            timeout=timeout,
            check=False,
        )

    def _issue_cleanup_capability(
        self,
        run_id: str,
        *,
        pageheap_binary: str = "",
        ttl_seconds: float,
    ) -> str:
        self._require_authorized()
        if not re.fullmatch(r"0verse-[0-9a-f]{32}", run_id):
            raise ValueError("Windows cleanup run identifier is invalid")
        if pageheap_binary and (
            Path(pageheap_binary).name != pageheap_binary
            or not re.fullmatch(r"[A-Za-z0-9_. -]{1,128}\.exe", pageheap_binary, re.IGNORECASE)
        ):
            raise ValueError("Windows PageHeap cleanup binary name is invalid")
        if not 1 <= ttl_seconds <= 3600:
            raise ValueError("Windows cleanup capability lifetime is invalid")
        remote_dir = f"C:\\Windows\\Temp\\{run_id}"
        script = (
            f"Remove-Item -LiteralPath {_ps_quote(remote_dir)} -Recurse -Force "
            "-ErrorAction SilentlyContinue"
        )
        if pageheap_binary:
            gflags = (
                "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\gflags.exe"
            )
            lock_dir = "C:\\Windows\\Temp\\0verse-pageheap.lock"
            script = (
                "$ErrorActionPreference='Stop';"
                f"& {_ps_quote(gflags)} /p /disable {_ps_quote(pageheap_binary)};"
                "if($LASTEXITCODE -ne 0){throw 'gflags PageHeap disable failed'};"
                f"Remove-Item -LiteralPath {_ps_quote(lock_dir)} -Recurse -Force "
                "-ErrorAction SilentlyContinue;"
                f"{script}"
            )
        capability = secrets.token_urlsafe(32)
        self._cleanup_capabilities[capability] = (
            script,
            self.host,
            time.monotonic() + ttl_seconds,
        )
        return capability

    def _scp(self, uploads: list[str], run_id: str) -> subprocess.CompletedProcess[bytes]:
        self._require_authorized()
        if not re.fullmatch(r"0verse-[0-9a-f]{32}", run_id):
            raise ValueError("Windows upload run identifier is invalid")
        destination = f"{self.host}:C:/Windows/Temp/{run_id}/"
        return subprocess.run(
            ["scp", "-q", "--", *uploads, destination],
            capture_output=True,
            timeout=self.connect_timeout + 30,
            check=False,
        )

    def available(self) -> tuple[bool, str]:
        try:
            result = self._ssh(
                "$d=(Get-Command drmemory.exe -ErrorAction SilentlyContinue);"
                "if($null -eq $d){Write-Error 'drmemory.exe not found';exit 2};"
                "Write-Output $d.Source",
                timeout=self.connect_timeout + 5,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, str(exc)
        detail = (result.stdout + result.stderr).decode("utf-8", "replace").strip()
        return result.returncode == 0, detail

    def run_drmemory(
        self,
        binary: str | Path,
        poc: bytes,
        *,
        vector: str = "file",
        timeout: float = 30.0,
    ) -> RunResult:
        if vector != "file":
            return _invalid_run(f"unsupported Windows vector: {vector}")
        binary_path = Path(binary)
        if not binary_path.is_file():
            return _invalid_run(f"PE does not exist: {binary_path}")

        run_id = f"0verse-{uuid.uuid4().hex}"
        remote_dir = f"C:\\Windows\\Temp\\{run_id}"
        remote_binary = f"{remote_dir}\\{binary_path.name}"
        remote_poc = f"{remote_dir}\\poc.bin"
        remote_log = f"{remote_dir}\\logs"
        mkdir = f"New-Item -ItemType Directory -Force -Path {_ps_quote(remote_dir)} | Out-Null"
        cleanup_capability = self._issue_cleanup_capability(
            run_id, ttl_seconds=min(3600, timeout + self.connect_timeout + 60)
        )

        try:
            made = self._ssh(mkdir, timeout=self.connect_timeout + 5)
            if made.returncode != 0:
                detail = (made.stdout + made.stderr).decode("utf-8", "replace")
                return _invalid_run(f"Windows worker mkdir failed: {detail}")
            with tempfile.NamedTemporaryFile(prefix="0verse-poc-", delete=False) as handle:
                handle.write(poc)
                local_poc = Path(handle.name)
            remote_uploaded_poc = f"{remote_dir}\\{local_poc.name}"
            pdb_path = binary_path.with_suffix(".pdb")
            uploads = [str(binary_path.resolve()), str(local_poc)]
            if pdb_path.is_file():
                uploads.append(str(pdb_path.resolve()))
            try:
                copied = self._scp(uploads, run_id)
            finally:
                local_poc.unlink(missing_ok=True)
            if copied.returncode != 0:
                detail = (copied.stdout + copied.stderr).decode("utf-8", "replace")
                return _invalid_run(f"Windows worker upload failed: {detail}")

            # Normalize only the randomized local PoV name. Preserve the PE/PDB
            # basename pair so cdb can resolve private symbols.
            normalize = (
                "$cv=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion';"
                "Write-Output \"0VERSE-BUILDLABEX:$($cv.BuildLabEx)\";"
                f"$binaryHash=(Get-FileHash -Algorithm SHA256 -LiteralPath "
                f"{_ps_quote(remote_binary)}).Hash.ToLowerInvariant();"
                "Write-Output \"0VERSE-BINARY-SHA256:$binaryHash\";"
                f"Move-Item -LiteralPath {_ps_quote(remote_uploaded_poc)} "
                f"-Destination {_ps_quote(remote_poc)} -Force;"
                f"$inputHash=(Get-FileHash -Algorithm SHA256 -LiteralPath "
                f"{_ps_quote(remote_poc)}).Hash.ToLowerInvariant();"
                "Write-Output \"0VERSE-INPUT-SHA256:$inputHash\";"
                f"New-Item -ItemType Directory -Force -Path {_ps_quote(remote_log)} | Out-Null;"
                f"& drmemory.exe -batch -quiet -logdir {_ps_quote(remote_log)} -- "
                f"{_ps_quote(remote_binary)} {_ps_quote(remote_poc)};"
                "$exit=$LASTEXITCODE;"
                f"Get-ChildItem -LiteralPath {_ps_quote(remote_log)} "
                "-Filter 'results.txt' -Recurse | "
                "ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw };"
                "Write-Output \"0VERSE-EXIT:$exit\""
            )
            result = self._ssh(normalize, timeout=timeout + self.connect_timeout + 10)
            report = (result.stdout + result.stderr).decode("utf-8", "replace")
            if result.returncode != 0:
                detail = (
                        f"Windows worker error: SSH/PowerShell exited "
                        f"{result.returncode}: {report}"
                )
                return _invalid_run(detail)
            markers = ("UNADDRESSABLE ACCESS", "USE AFTER FREE", "INVALID HEAP ARGUMENT")
            crashed = any(marker in report.upper() for marker in markers)
            return RunResult(crashed, sanitizer="drmemory" if crashed else "", stderr=report)
        except subprocess.TimeoutExpired:
            return _invalid_run("Windows worker timeout", timed_out=True)
        except OSError as exc:
            return _invalid_run(f"Windows worker error: {exc}")
        finally:
            with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                self._ssh_cleanup(
                    timeout=self.connect_timeout + 5,
                    capability=cleanup_capability,
                )

    def run_pageheap(
        self,
        binary: str | Path,
        poc: bytes,
        *,
        vector: str = "file",
        timeout: float = 30.0,
    ) -> RunResult:
        """Run a PE under full PageHeap and cdb, always disabling PageHeap after."""
        if vector != "file":
            return _invalid_run(f"unsupported Windows vector: {vector}")
        binary_path = Path(binary)
        if not binary_path.is_file():
            return _invalid_run(f"PE does not exist: {binary_path}")

        run_id = f"0verse-{uuid.uuid4().hex}"
        remote_dir = f"C:\\Windows\\Temp\\{run_id}"
        remote_binary = f"{remote_dir}\\{binary_path.name}"
        remote_poc = f"{remote_dir}\\poc.bin"
        lock_dir = "C:\\Windows\\Temp\\0verse-pageheap.lock"
        lock_owner = f"{lock_dir}\\owner"
        debugger_root = "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64"
        gflags = f"{debugger_root}\\gflags.exe"
        cdb = f"{debugger_root}\\cdb.exe"
        mkdir = f"New-Item -ItemType Directory -Force -Path {_ps_quote(remote_dir)} | Out-Null"
        acquire = (
            "$ErrorActionPreference='Stop';"
            f"New-Item -ItemType Directory -Path {_ps_quote(lock_dir)} | Out-Null;"
            f"Set-Content -LiteralPath {_ps_quote(lock_owner)} "
            f"-Value @({_ps_quote(run_id)}, {_ps_quote(binary_path.name)})"
        )
        pageheap_acquired = False
        outcome: RunResult | None = None
        cleanup_capability = self._issue_cleanup_capability(
            run_id,
            ttl_seconds=min(3600, timeout + self.connect_timeout + 120),
        )
        locked_cleanup_capability = self._issue_cleanup_capability(
            run_id,
            pageheap_binary=binary_path.name,
            ttl_seconds=min(3600, timeout + self.connect_timeout + 120),
        )

        try:
            made = self._ssh(mkdir, timeout=self.connect_timeout + 5)
            if made.returncode != 0:
                detail = (made.stdout + made.stderr).decode("utf-8", "replace")
                return _invalid_run(f"Windows worker mkdir failed: {detail}")
            locked = self._ssh(acquire, timeout=self.connect_timeout + 5)
            if locked.returncode != 0:
                detail = (locked.stdout + locked.stderr).decode("utf-8", "replace")
                return _invalid_run(
                    f"Windows PageHeap worker error: another replay owns the lock: {detail}"
                )
            pageheap_acquired = True
            self._cleanup_capabilities.pop(cleanup_capability, None)
            cleanup_capability = locked_cleanup_capability
            with tempfile.NamedTemporaryFile(prefix="0verse-poc-", delete=False) as handle:
                handle.write(poc)
                local_poc = Path(handle.name)
            uploaded_poc = f"{remote_dir}\\{local_poc.name}"
            pdb_path = binary_path.with_suffix(".pdb")
            uploads = [str(binary_path.resolve()), str(local_poc)]
            if pdb_path.is_file():
                uploads.append(str(pdb_path.resolve()))
            try:
                copied = self._scp(uploads, run_id)
            finally:
                local_poc.unlink(missing_ok=True)
            if copied.returncode != 0:
                detail = (copied.stdout + copied.stderr).decode("utf-8", "replace")
                outcome = _invalid_run(f"Windows worker upload failed: {detail}")
                return outcome  # noqa: RET504 - finally may invalidate this mutable result

            script = (
                "$cv=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion';"
                "Write-Output \"0VERSE-BUILDLABEX:$($cv.BuildLabEx)\";"
                f"$binaryHash=(Get-FileHash -Algorithm SHA256 -LiteralPath "
                f"{_ps_quote(remote_binary)}).Hash.ToLowerInvariant();"
                "Write-Output \"0VERSE-BINARY-SHA256:$binaryHash\";"
                f"Move-Item -LiteralPath {_ps_quote(uploaded_poc)} "
                f"-Destination {_ps_quote(remote_poc)} -Force;"
                f"$inputHash=(Get-FileHash -Algorithm SHA256 -LiteralPath "
                f"{_ps_quote(remote_poc)}).Hash.ToLowerInvariant();"
                "Write-Output \"0VERSE-INPUT-SHA256:$inputHash\";"
                f"& {_ps_quote(gflags)} /p /enable {_ps_quote(binary_path.name)} /full;"
                "try {"
                f"& {_ps_quote(cdb)} -g -G -c '!analyze -v;q' "
                f"{_ps_quote(remote_binary)} {_ps_quote(remote_poc)}"
                f"}} finally {{ & {_ps_quote(gflags)} /p /disable "
                f"{_ps_quote(binary_path.name)} }}"
            )
            result = self._ssh(script, timeout=timeout + self.connect_timeout + 30)
            report = (result.stdout + result.stderr).decode("utf-8", "replace")
            if result.returncode != 0:
                detail = (
                        f"Windows worker error: SSH/PowerShell exited "
                        f"{result.returncode}: {report}"
                )
                outcome = _invalid_run(detail)
                return outcome  # noqa: RET504 - finally may invalidate this mutable result
            markers = ("VERIFIER STOP", "APPLICATION_VERIFIER_", "EXCEPTION_CODE:")
            crashed = any(marker in report.upper() for marker in markers)
            outcome = RunResult(
                crashed,
                sanitizer="pageheap-cdb" if crashed else "",
                stderr=report,
            )
            return outcome  # noqa: RET504 - finally may invalidate this mutable result
        except subprocess.TimeoutExpired:
            outcome = _invalid_run("Windows PageHeap worker timeout", timed_out=True)
            return outcome  # noqa: RET504 - finally may invalidate this mutable result
        except OSError as exc:
            outcome = _invalid_run(f"Windows PageHeap worker error: {exc}")
            return outcome  # noqa: RET504 - finally may invalidate this mutable result
        finally:
            if not pageheap_acquired:
                self._cleanup_capabilities.pop(locked_cleanup_capability, None)
            cleanup_error = ""
            try:
                cleaned = self._ssh_cleanup(
                    timeout=self.connect_timeout + 5,
                    capability=cleanup_capability,
                )
                if cleaned.returncode != 0:
                    detail = (cleaned.stdout + cleaned.stderr).decode("utf-8", "replace").strip()
                    cleanup_error = f"cleanup returned {cleaned.returncode}: {detail}"
            except (OSError, subprocess.TimeoutExpired) as exc:
                cleanup_error = str(exc)
            if pageheap_acquired and cleanup_error and outcome is not None:
                outcome.crashed = False
                outcome.sanitizer = ""
                outcome.valid = False
                outcome.infrastructure_error = f"PageHeap cleanup failed: {cleanup_error}"
                outcome.stderr = (
                    f"{outcome.stderr.rstrip()}\nWindows PageHeap worker error: "
                    f"cleanup failed; lock retained: {cleanup_error}"
                )

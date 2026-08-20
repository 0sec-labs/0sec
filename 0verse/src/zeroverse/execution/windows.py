"""Adapter from the authorized Windows worker to normalized execution evidence."""

from __future__ import annotations

import re
from typing import cast

from zeroverse.windows_oracle import (
    WindowsWorker,
    extract_binary_sha256,
    extract_buildlabex,
    extract_input_sha256,
)

from .contract import (
    ExecutionCapabilities,
    ExecutionEvidence,
    ExecutionRequest,
    ExecutionStatus,
)

_EXIT_RE = re.compile(r"^0VERSE-EXIT:(-?\d+)$", re.MULTILINE)


class WindowsExecutionBackend:
    """File-input PE confirmation on an explicitly supplied Windows worker."""

    name = "windows-worker"
    capabilities = ExecutionCapabilities(
        formats=frozenset({"PE"}),
        vectors=frozenset({"file"}),
        oracles=frozenset({"auto", "drmemory", "pageheap-cdb"}),
        default_timeout=30.0,
    )

    def __init__(
        self,
        worker: WindowsWorker,
        *,
        scope_mode: str,
        authorization: str,
        oracle: str = "auto",
    ) -> None:
        if oracle not in self.capabilities.oracles:
            raise ValueError(f"unsupported Windows execution oracle: {oracle}")
        if scope_mode not in {"LAB_ONLY", "BOUNTY_SCOPE"}:
            raise ValueError("Windows execution scope must be LAB_ONLY or BOUNTY_SCOPE")
        if not authorization.strip():
            raise ValueError("Windows execution requires an authorization statement")
        self.worker = worker
        self.oracle = oracle
        self.scope_mode = scope_mode
        self.authorization = authorization

    def run(self, request: ExecutionRequest) -> ExecutionEvidence:
        target_hash = request.target_sha256
        input_hash = request.input_sha256
        environment = {
            "host": self.worker.host,
            "mode": "windows-worker",
            "scope_mode": self.scope_mode,
            "authorization": self.authorization,
        }
        requested_oracle = self.oracle if request.oracle == "auto" else request.oracle
        if not self.capabilities.supports(
            request.target_format, request.vector, requested_oracle
        ):
            return ExecutionEvidence(
                backend=self.name,
                status="UNSUPPORTED",
                oracle=requested_oracle,
                target_sha256=target_hash,
                input_sha256=input_hash,
                environment=environment,
                error=(
                    f"{self.name} does not support {request.target_format}/"
                    f"{request.vector}/{requested_oracle}"
                ),
            )

        run = (
            self.worker.run_pageheap(request.target, request.payload, timeout=request.timeout)
            if requested_oracle == "pageheap-cdb"
            else self.worker.run_drmemory(request.target, request.payload, timeout=request.timeout)
        )
        if (
            requested_oracle == "auto"
            and not run.crashed
            and "0VERSE-EXIT:-1" in run.stderr
            and "Windows worker error:" not in run.stderr
            and bool(extract_buildlabex(run.stderr))
        ):
            run = self.worker.run_pageheap(
                request.target, request.payload, timeout=request.timeout
            )

        build = extract_buildlabex(run.stderr)
        remote_target = extract_binary_sha256(run.stderr)
        remote_input = extract_input_sha256(run.stderr)
        if build:
            environment["build_lab_ex"] = build
        error = ""
        status = "CRASH" if run.crashed else "CLEAN"
        if "worker timeout" in run.stderr.lower():
            status, error = "TIMEOUT", "Windows worker timeout"
        elif "worker error" in run.stderr.lower():
            status, error = "ERROR", run.stderr.strip()[-500:]
        elif not build:
            status, error = "ERROR", "Windows worker returned no unambiguous BuildLabEx"
        elif remote_target != target_hash:
            status, error = "ERROR", "Windows worker target SHA-256 is missing or mismatched"
        elif remote_input != input_hash:
            status, error = "ERROR", "Windows worker input SHA-256 is missing or mismatched"
        elif status == "CRASH" and not run.sanitizer:
            status, error = "ERROR", "Windows worker crash lacks an oracle signature"

        exit_matches = {int(value) for value in _EXIT_RE.findall(run.stderr)}
        returncode = exit_matches.pop() if len(exit_matches) == 1 else None
        oracle = run.sanitizer or requested_oracle
        signature = run.sanitizer if status == "CRASH" else ""
        normalized_status = cast(ExecutionStatus, status)
        return ExecutionEvidence(
            backend=self.name,
            status=normalized_status,
            oracle=oracle,
            target_sha256=target_hash,
            input_sha256=input_hash,
            environment=environment,
            returncode=returncode,
            crash_signature=signature,
            stderr=run.stderr,
            error=error,
        )

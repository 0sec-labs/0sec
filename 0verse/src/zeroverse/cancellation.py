"""Run-local cancellation and deadline-aware subprocess execution."""

from __future__ import annotations

import math
import os
import signal
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field


class CancelledError(RuntimeError):
    """Raised when a run-local cancellation request interrupts an operation."""


class CancellationToken:
    """Thread-safe, run-local cooperative cancellation token."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._reason = ""

    def cancel(self, reason: str = "caller requested cancellation") -> None:
        with self._lock:
            if not self._event.is_set():
                self._reason = reason
                self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str:
        with self._lock:
            return self._reason or "caller requested cancellation"

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)


@dataclass(frozen=True)
class RunContext:
    """Cancellation and absolute deadline state belonging to exactly one run."""

    deadline_monotonic: float
    cancellation: CancellationToken = field(default_factory=CancellationToken)

    def remaining_seconds(self) -> float:
        return max(0.0, self.deadline_monotonic - time.monotonic())

    @property
    def deadline_expired(self) -> bool:
        return self.remaining_seconds() <= 0.0

    @property
    def cancelled(self) -> bool:
        return self.cancellation.cancelled

    @property
    def stopped(self) -> bool:
        return self.cancelled or self.deadline_expired

    @property
    def reason(self) -> str:
        if self.cancelled:
            return self.cancellation.reason
        if self.deadline_expired:
            return "wall-clock budget exhausted"
        return ""

    def checkpoint(self) -> None:
        if self.stopped:
            raise CancelledError(self.reason)


@dataclass(frozen=True)
class ProcessResult:
    args: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    cancelled: bool = False
    error: str = ""


def _terminate_process_group(process: subprocess.Popen[bytes], grace: float = 0.25) -> None:
    """Terminate a subprocess and all its descendants without installing global handlers.

    On POSIX, sends SIGTERM then SIGKILL to the process group even when the group
    leader has already exited — orphaned descendants may still be alive and remain
    in the original process group until all members exit."""
    pgid = process.pid
    if os.name != "posix":  # pragma: no cover - exercised on Windows CI only
        if process.poll() is None:
            process.terminate()
            with contextlib_suppress_timeout():
                process.wait(timeout=grace)
            if process.poll() is None:
                process.kill()
                with contextlib_suppress_timeout():
                    process.wait(timeout=1.0)
        return
    for signum in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, signum)
        except ProcessLookupError:
            break
        try:
            process.wait(timeout=grace if signum == signal.SIGTERM else 1.0)
            return
        except subprocess.TimeoutExpired:
            pass
    with contextlib_suppress_timeout():
        process.wait(timeout=1.0)


class contextlib_suppress_timeout:
    """Tiny local suppressor that keeps the subprocess helper dependency-free."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        return exc_type is subprocess.TimeoutExpired


def run_process(
    argv: Sequence[str],
    *,
    input: bytes = b"",
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
    context: RunContext | None = None,
    poll_interval: float = 0.05,
) -> ProcessResult:
    """Run a process group and reap it on timeout or run-local cancellation."""
    args = tuple(str(item) for item in argv)
    if not args:
        return ProcessResult(args, -1, b"", b"", error="empty argv")
    if context is not None and context.stopped:
        return ProcessResult(
            args,
            -1,
            b"",
            context.reason.encode(),
            timed_out=context.deadline_expired and not context.cancelled,
            cancelled=context.cancelled,
            error=context.reason,
        )
    if timeout is not None and not math.isfinite(timeout):
        return ProcessResult(args, -1, b"", str(timeout).encode(), error=str(timeout))
    effective_timeout = timeout
    if context is not None:
        remaining = context.remaining_seconds()
        effective_timeout = remaining if effective_timeout is None else min(
            effective_timeout, remaining
        )
    if effective_timeout is not None and (
        not math.isfinite(effective_timeout) or effective_timeout <= 0
    ):
        return ProcessResult(
            args, -1, b"", b"timeout", timed_out=True, error="timeout"
        )
    process: subprocess.Popen[bytes]
    popen_kwargs: dict[str, object] = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "env": dict(env) if env is not None else None,
    }
    if os.name == "posix":
        popen_kwargs["process_group"] = 0
    try:
        process = subprocess.Popen(list(args), **popen_kwargs)  # type: ignore[call-overload]  # foxguard: ignore[py/no-command-injection]
    except (OSError, ValueError, OverflowError) as exc:
        return ProcessResult(args, -1, b"", str(exc).encode(), error=str(exc))

    started = time.monotonic()

    first_communicate = True
    while True:
        if context is not None and context.cancelled:
            _terminate_process_group(process)
            stdout, stderr = process.communicate()
            reason = context.reason
            return ProcessResult(
                args,
                process.returncode,
                stdout,
                stderr,
                cancelled=True,
                error=reason,
            )
        elapsed = time.monotonic() - started
        deadline_timeout = (
            context.deadline_expired if context is not None else False
        )
        local_timeout = effective_timeout is not None and elapsed >= effective_timeout
        if deadline_timeout or local_timeout:
            _terminate_process_group(process)
            stdout, stderr = process.communicate()
            return ProcessResult(
                args,
                process.returncode,
                stdout,
                stderr,
                timed_out=True,
                error="timeout",
            )
        wait = poll_interval
        if effective_timeout is not None:
            wait = min(wait, max(0.001, effective_timeout - elapsed))
        if context is not None:
            wait = min(wait, max(0.001, context.remaining_seconds()))
        try:
            stdout, stderr = process.communicate(
                input=input if first_communicate else None,
                timeout=wait,
            )
            return ProcessResult(args, process.returncode, stdout, stderr)
        except subprocess.TimeoutExpired:
            first_communicate = False

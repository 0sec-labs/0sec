"""Local-process implementation of the execution contract."""

from __future__ import annotations

import os
import platform
import subprocess
import tempfile
from pathlib import Path

from .contract import (
    ExecutionCapabilities,
    ExecutionEvidence,
    ExecutionRequest,
    ExecutionStatus,
    sha256_file,
)

_SIGNALS = {-11: "SIGSEGV", -6: "SIGABRT", -4: "SIGILL", -8: "SIGFPE"}
_HOST_FORMAT = {"linux": "ELF", "darwin": "Mach-O", "windows": "PE"}.get(
    platform.system().lower(), "unknown"
)


class LocalProcessBackend:
    """Run ordinary executable targets on the current host.

    This adapter is opt-in at the public contract seam.  The legacy local ELF
    path remains the pipeline default for backward compatibility.
    """

    name = "local-process"
    capabilities = ExecutionCapabilities(
        formats=frozenset({_HOST_FORMAT}),
        vectors=frozenset({"stdin", "argv", "file", "env"}),
        oracles=frozenset({"native-crash", "marker"}),
    )

    def run(self, request: ExecutionRequest) -> ExecutionEvidence:
        target_hash = request.target_sha256
        input_hash = request.input_sha256
        if not self.capabilities.supports(
            request.target_format, request.vector, request.oracle
        ):
            return ExecutionEvidence(
                backend=self.name,
                status="UNSUPPORTED",
                oracle=request.oracle,
                target_sha256=target_hash,
                input_sha256=input_hash,
                environment=self._environment(),
                error=(
                    f"{self.name} does not support {request.target_format}/"
                    f"{request.vector}/{request.oracle}"
                ),
            )
        if sha256_file(request.target) != target_hash:
            return ExecutionEvidence(
                backend=self.name,
                status="ERROR",
                oracle=request.oracle,
                target_sha256=target_hash,
                input_sha256=input_hash,
                environment=self._environment(),
                error="local target changed after the execution request was created",
            )

        temp_path: Path | None = None
        argv = list(request.argv)
        stdin = b""
        env = {**os.environ, **request.env}
        if request.vector == "stdin":
            stdin = request.payload
        elif request.vector == "argv":
            argv.append(request.payload.decode("latin-1"))
        elif request.vector == "env":
            pass  # the candidate is represented by the explicitly supplied env
        elif request.vector == "file":
            fd, name = tempfile.mkstemp(prefix="0verse-input-")
            temp_path = Path(name)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(request.payload)
                argv.append(str(temp_path))
            except Exception:
                temp_path.unlink(missing_ok=True)
                raise

        try:
            result = subprocess.run(  # foxguard: ignore[py/taint-command-injection]
                # The adapter intentionally executes an operator-selected target.
                # shell=False (the default) and a structured argv keep payload
                # bytes out of shell parsing.
                [request.target, *argv],
                input=stdin,
                env=env,
                capture_output=True,
                timeout=request.timeout,
                check=False,
            )
            signal = _SIGNALS.get(result.returncode, "")
            status: ExecutionStatus = "CRASH" if signal else "CLEAN"
            return ExecutionEvidence(
                backend=self.name,
                status=status,
                oracle=request.oracle,
                target_sha256=target_hash,
                input_sha256=input_hash,
                environment=self._environment(),
                returncode=result.returncode,
                signal=signal,
                crash_signature=signal,
                stdout=result.stdout.decode("utf-8", "replace"),
                stderr=result.stderr.decode("utf-8", "replace"),
            )
        except subprocess.TimeoutExpired as exc:
            return ExecutionEvidence(
                backend=self.name,
                status="TIMEOUT",
                oracle=request.oracle,
                target_sha256=target_hash,
                input_sha256=input_hash,
                environment=self._environment(),
                stdout=_text(exc.stdout),
                stderr=_text(exc.stderr),
                error=f"local target exceeded {request.timeout}s",
            )
        except OSError as exc:
            return ExecutionEvidence(
                backend=self.name,
                status="ERROR",
                oracle=request.oracle,
                target_sha256=target_hash,
                input_sha256=input_hash,
                environment=self._environment(),
                error=str(exc),
            )
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    @staticmethod
    def _environment() -> dict[str, str]:
        return {
            "host": platform.node(),
            "platform": platform.system().lower(),
            "machine": platform.machine(),
            "mode": "local-process",
        }


def _text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value

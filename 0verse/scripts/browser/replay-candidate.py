#!/usr/bin/env python3
"""Remote single-input browser-harness replay helper.

Protocol: one bounded JSON header line followed by raw candidate bytes on stdin.
Complete runs emit nonce-bound, machine-readable records and exit zero regardless
of the target's exit status. Helper/setup failures exit 125 without complete
records, so SSH transport state and target state cannot be confused.
"""

from __future__ import annotations

import base64
import contextlib
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "0verse.browser-replay/v1"
MAX_HEADER_BYTES = 64 * 1024
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_TIMEOUT_SECONDS = 3600.0
_HEX64 = re.compile(r"[0-9a-f]{64}")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_MARKER = re.compile(r"[0-9a-f]{32}")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fail(message: str) -> int:
    print(f"0VERSE-BROWSER-HELPER-ERROR:{message}", file=sys.stderr)
    return 125


def _header() -> dict[str, Any]:
    line = sys.stdin.buffer.readline(MAX_HEADER_BYTES + 1)
    if len(line) > MAX_HEADER_BYTES or not line.endswith(b"\n"):
        raise ValueError("invalid or oversized replay header")
    raw = json.loads(line)
    if not isinstance(raw, dict):
        raise ValueError("replay header must be an object")
    return raw


def _text(raw: dict[str, Any], name: str) -> str:
    value = raw.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"invalid replay header field: {name}")
    return value


def _validate(raw: dict[str, Any]) -> tuple[str, str, str, str, float, Path, Path, list[str]]:
    if _text(raw, "protocol") != PROTOCOL_VERSION:
        raise ValueError("unsupported browser replay protocol")
    marker = _text(raw, "marker")
    target_hash = _text(raw, "target_sha256")
    input_hash = _text(raw, "input_sha256")
    helper_hash = _text(raw, "helper_sha256")
    revision = _text(raw, "revision").lower()
    if not _MARKER.fullmatch(marker):
        raise ValueError("invalid replay marker")
    if any(not _HEX64.fullmatch(value) for value in (target_hash, input_hash, helper_hash)):
        raise ValueError("invalid replay SHA-256")
    if not _REVISION.fullmatch(revision):
        raise ValueError("browser replay requires a full source revision")
    timeout = raw.get("timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("invalid replay timeout")
    timeout = float(timeout)
    if timeout <= 0 or timeout > MAX_TIMEOUT_SECONDS:
        raise ValueError("replay timeout is outside the allowed range")
    source_root = Path(_text(raw, "source_root"))
    harness = Path(_text(raw, "harness"))
    if not source_root.is_absolute() or not harness.is_absolute():
        raise ValueError("browser replay paths must be absolute")
    argv = raw.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(value, str) for value in argv)
        or len(argv) > 128
        or any(len(value) > 4096 or "\x00" in value for value in argv)
    ):
        raise ValueError("invalid browser replay argv")
    if argv[0] != str(harness) or argv.count("{input}") != 1:
        raise ValueError("browser replay argv is not bound to one harness input")
    if any("{input}" in value and value != "{input}" for value in argv):
        raise ValueError("browser replay placeholder must be a complete argument")
    return marker, target_hash, input_hash, helper_hash, timeout, source_root, harness, argv


def _write_input(path: Path, expected_hash: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(fd, "wb") as output:
            while True:
                chunk = sys.stdin.buffer.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_INPUT_BYTES:
                    raise ValueError("browser replay input exceeds 64 MiB")
                digest.update(chunk)
                output.write(chunk)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    if digest.hexdigest() != expected_hash:
        raise ValueError("browser replay input SHA-256 mismatch")


def _git_revision(source_root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError("cannot attest browser source revision")
    return result.stdout.strip().lower()


def _worker_identity(raw: dict[str, Any]) -> tuple[str, str, str, str, str, str, str]:
    expected_hostname = _text(raw, "worker_hostname").lower()
    expected_user = _text(raw, "worker_user")
    expected_group = _text(raw, "worker_group")
    expected_marker_owner = _text(raw, "bootstrap_marker_owner")
    expected_marker_group = _text(raw, "bootstrap_marker_group")
    marker = Path(_text(raw, "bootstrap_marker"))
    if not marker.is_absolute():
        raise ValueError("browser bootstrap marker path must be absolute")

    hostname = socket.gethostname().split(".", 1)[0].lower()
    user = pwd.getpwuid(os.geteuid()).pw_name
    group = grp.getgrgid(os.getegid()).gr_name
    if hostname != expected_hostname:
        raise ValueError("browser worker hostname mismatch")
    if user != expected_user:
        raise ValueError("browser worker user mismatch")
    if group != expected_group:
        raise ValueError("browser worker group mismatch")
    if not marker.is_file() or marker.is_symlink():
        raise ValueError("browser bootstrap marker is missing or unsafe")
    marker_stat = marker.stat()
    marker_owner = pwd.getpwuid(marker_stat.st_uid).pw_name
    marker_group = grp.getgrgid(marker_stat.st_gid).gr_name
    if marker_owner != expected_marker_owner or marker_group != expected_marker_group:
        raise ValueError("browser bootstrap marker has unsafe ownership")
    if stat.S_IMODE(marker_stat.st_mode) != 0o640:
        raise ValueError("browser bootstrap marker has unsafe mode")
    marker_bytes = marker.read_bytes()
    if len(marker_bytes) > 4096:
        raise ValueError("browser bootstrap marker is oversized")
    try:
        lines = marker_bytes.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("browser bootstrap marker is not UTF-8") from exc
    fields: dict[str, str] = {}
    for line in lines:
        name, separator, value = line.partition("=")
        if not separator or name in fields:
            raise ValueError("browser bootstrap marker is malformed")
        fields[name] = value
    bootstrap_hash = fields.get("bootstrap_sha256", "")
    if (
        set(fields) != {"schema", "hostname", "bootstrapped_at_utc", "bootstrap_sha256"}
        or fields["schema"] != "1"
        or fields["hostname"].lower() != expected_hostname
        or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[^\s]+Z", fields["bootstrapped_at_utc"])
        or not _HEX64.fullmatch(bootstrap_hash)
    ):
        raise ValueError("browser bootstrap marker is malformed")
    return (
        hostname,
        user,
        group,
        marker_owner,
        marker_group,
        hashlib.sha256(marker_bytes).hexdigest(),
        bootstrap_hash,
    )


class _BoundedCapture:
    """Hash a stream while retaining only its bounded tail in memory."""

    def __init__(self) -> None:
        self.digest = hashlib.sha256()
        self.tail = bytearray()
        self.size = 0
        self.error: OSError | None = None

    def consume(self, source: Any) -> None:
        try:
            while True:
                chunk = source.read(64 * 1024)
                if not chunk:
                    break
                self.digest.update(chunk)
                self.size += len(chunk)
                self.tail.extend(chunk)
                if len(self.tail) > MAX_OUTPUT_BYTES:
                    del self.tail[: len(self.tail) - MAX_OUTPUT_BYTES]
        except OSError as exc:
            self.error = exc

    def result(self) -> tuple[bytes, str, bool]:
        if self.error is not None:
            raise self.error
        return bytes(self.tail), self.digest.hexdigest(), self.size > MAX_OUTPUT_BYTES


def _emit(marker: str, values: dict[str, str]) -> None:
    for name, value in values.items():
        print(f"0VERSE-BROWSER-{marker}-{name}:{value}")


def main() -> int:
    run_dir: Path | None = None
    try:
        raw = _header()
        marker, target_hash, input_hash, helper_hash, timeout, source_root, harness, argv = (
            _validate(raw)
        )
        oracle = _text(raw, "oracle")
        if oracle not in {"asan", "msan", "ubsan", "browser-crash"}:
            raise ValueError("unsupported browser replay oracle")
        if _sha256_file(Path(__file__).resolve()) != helper_hash:
            raise ValueError("remote replay helper SHA-256 mismatch")
        (
            worker_hostname,
            worker_user,
            worker_group,
            marker_owner,
            marker_group,
            marker_hash,
            bootstrap_hash,
        ) = _worker_identity(raw)
        if not harness.is_file() or harness.is_symlink() or not os.access(harness, os.X_OK):
            raise ValueError("browser harness is not a regular executable")
        revision_before = _git_revision(source_root)
        if revision_before != _text(raw, "revision").lower():
            raise ValueError("remote browser source revision mismatch")
        before_hash = _sha256_file(harness)
        if before_hash != target_hash:
            raise ValueError("remote browser harness SHA-256 mismatch")

        run_dir = Path(tempfile.mkdtemp(prefix="0verse-browser-replay-", dir="/tmp"))
        run_dir.chmod(0o700)
        input_path = run_dir / "input"
        _write_input(input_path, input_hash)
        command = [str(input_path) if value == "{input}" else value for value in argv]
        target_env = os.environ.copy()
        sanitizer_options = {
            "asan": ("ASAN_OPTIONS", "abort_on_error=1:halt_on_error=1:detect_leaks=0:symbolize=1"),
            "msan": ("MSAN_OPTIONS", "halt_on_error=1:symbolize=1"),
            "ubsan": ("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1:symbolize=1"),
        }
        if oracle in sanitizer_options:
            variable, value = sanitizer_options[oracle]
            target_env[variable] = value

        timed_out = False
        process = subprocess.Popen(  # foxguard: ignore[py/taint-command-injection]
            # The helper intentionally executes the manifest-bound harness via a
            # structured argv; no shell parses the candidate or command fields.
            command,
            cwd=source_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=target_env,
            start_new_session=True,
        )
        assert process.stdout is not None and process.stderr is not None
        stdout_capture = _BoundedCapture()
        stderr_capture = _BoundedCapture()
        stdout_thread = threading.Thread(
            target=stdout_capture.consume, args=(process.stdout,), daemon=True
        )
        stderr_thread = threading.Thread(
            target=stderr_capture.consume, args=(process.stderr,), daemon=True
        )
        stdout_thread.start()
        stderr_thread.start()
        try:
            target_exit = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            target_exit = 124
            process.wait()
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        if stdout_thread.is_alive() or stderr_thread.is_alive():
            raise ValueError("browser harness output pipes did not close")

        after_hash = _sha256_file(harness)
        revision_after = _git_revision(source_root)
        stdout, stdout_hash, stdout_truncated = stdout_capture.result()
        stderr, stderr_hash, stderr_truncated = stderr_capture.result()
        _emit(
            marker,
            {
                "WORKER-HOSTNAME": worker_hostname,
                "WORKER-USER": worker_user,
                "WORKER-GROUP": worker_group,
                "BOOTSTRAP-MARKER-OWNER": marker_owner,
                "BOOTSTRAP-MARKER-GROUP": marker_group,
                "BOOTSTRAP-MARKER-SHA256": marker_hash,
                "BOOTSTRAP-SHA256": bootstrap_hash,
                "ORACLE": oracle,
                "HELPER-SHA256": helper_hash,
                "TARGET-SHA256-BEFORE": before_hash,
                "TARGET-SHA256-AFTER": after_hash,
                "INPUT-SHA256": input_hash,
                "REVISION-BEFORE": revision_before,
                "REVISION-AFTER": revision_after,
                "TARGET-EXIT": str(target_exit),
                "TIMED-OUT": "1" if timed_out else "0",
                "STDOUT-SHA256": stdout_hash,
                "STDERR-SHA256": stderr_hash,
                "STDOUT-TAIL-SHA256": hashlib.sha256(stdout).hexdigest(),
                "STDERR-TAIL-SHA256": hashlib.sha256(stderr).hexdigest(),
                "STDOUT-TRUNCATED": "1" if stdout_truncated else "0",
                "STDERR-TRUNCATED": "1" if stderr_truncated else "0",
                "STDOUT-B64": base64.b64encode(stdout).decode("ascii"),
                "STDERR-B64": base64.b64encode(stderr).decode("ascii"),
            },
        )
        return 0
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        return _fail(str(exc))
    finally:
        if run_dir is not None:
            shutil.rmtree(run_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())

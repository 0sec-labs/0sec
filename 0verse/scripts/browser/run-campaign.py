#!/usr/bin/env python3
"""Fail-closed supervisor for one sustained browser component campaign."""

from __future__ import annotations

import base64
import ctypes
import grp
import hashlib
import json
import os
import pwd
import re
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "0verse.browser-campaign-supervisor/v1"
RECORD_PREFIX = "0VERSE-BROWSER-CAMPAIGN:"
MAX_HEADER_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_TIMEOUT_SECONDS = 7 * 24 * 3600.0
MAX_ARTIFACTS = 64
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_RETRIEVED_BYTES = 64 * 1024 * 1024
_HEX64 = re.compile(r"[0-9a-f]{64}")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_MARKER = re.compile(r"[0-9a-f]{32}")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _text(raw: dict[str, Any], name: str) -> str:
    value = raw.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"invalid campaign header field: {name}")
    return value


def _decode_header(argument: str) -> dict[str, Any]:
    if len(argument) > MAX_HEADER_BYTES * 2:
        raise ValueError("oversized campaign header")
    try:
        encoded = argument.encode("ascii")
        data = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
        raw = json.loads(data)
    except (UnicodeEncodeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("invalid campaign header") from exc
    if len(data) > MAX_HEADER_BYTES or not isinstance(raw, dict):
        raise ValueError("invalid or oversized campaign header")
    return raw


def _safe_file(path: Path, *, executable: bool = False) -> None:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"missing or unsafe file: {path}")
    mode = path.stat().st_mode
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(f"group/other-writable file: {path}")
    if executable and not os.access(path, os.X_OK):
        raise ValueError(f"file is not executable: {path}")


def _fd_path(descriptor: int) -> str:
    for root in ("/proc/self/fd", "/dev/fd"):
        if Path(root).is_dir():
            return f"{root}/{descriptor}"
    raise RuntimeError("the worker has no descriptor execution filesystem")


def _tool_directory_path(descriptor: int, fallback: Path) -> str:
    # Linux workers expose stable directory descriptors through procfs. macOS
    # has /dev/fd for exact file execution but Git/cwd do not accept directory
    # descriptors there, so hermetic local tests use the already no-follow-opened path.
    if Path("/proc/self/fd").is_dir():
        return f"/proc/self/fd/{descriptor}"
    return str(fallback)


def _open_directory_nofollow(path: Path, label: str) -> int:
    """Open an absolute directory without following any path component."""
    if not path.is_absolute() or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError(f"{label} requires absolute no-follow path support")
    parts = path.parts
    descriptor = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in parts[1:]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_relative_nofollow(
    root_descriptor: int, relative: Path, label: str, *, directory: bool
) -> int:
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError(f"unsafe relative {label} path")
    descriptor = os.dup(root_descriptor)
    try:
        for component in relative.parts[:-1]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        if directory:
            flags |= os.O_DIRECTORY
        result = os.open(relative.parts[-1], flags, dir_fd=descriptor)
        metadata = os.fstat(result)
        expected = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
        if not expected:
            os.close(result)
            raise ValueError(f"{label} has an unsafe file type")
        return result
    except OSError as exc:
        raise ValueError(f"missing or symlinked {label}") from exc
    finally:
        os.close(descriptor)


def _sha256_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _directory_is_readable_writable(descriptor: int) -> bool:
    metadata = os.fstat(descriptor)
    if os.geteuid() == 0:
        return True
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid == os.geteuid():
        permissions = (mode >> 6) & 0o7
    elif metadata.st_gid == os.getegid() or metadata.st_gid in os.getgroups():
        permissions = (mode >> 3) & 0o7
    else:
        permissions = mode & 0o7
    return permissions == 0o7


def _git_revision(source_descriptor: int, source_fallback: Path) -> str:
    source = _tool_directory_path(source_descriptor, source_fallback)
    result = subprocess.run(
        ["git", "-C", source, "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        pass_fds=(source_descriptor,),
    )
    if result.returncode != 0:
        raise ValueError("cannot attest browser source revision")
    return result.stdout.strip().lower()


def _validate_identity(raw: dict[str, Any]) -> dict[str, str]:
    expected_hostname = _text(raw, "worker_hostname").lower()
    expected_user = _text(raw, "worker_user")
    expected_group = _text(raw, "worker_group")
    expected_marker_owner = _text(raw, "bootstrap_marker_owner")
    expected_marker_group = _text(raw, "bootstrap_marker_group")
    marker = Path(_text(raw, "bootstrap_marker"))
    if not marker.is_absolute():
        raise ValueError("bootstrap marker must be absolute")
    hostname = socket.gethostname().split(".", 1)[0].lower()
    user = pwd.getpwuid(os.geteuid()).pw_name
    group = grp.getgrgid(os.getegid()).gr_name
    if (hostname, user, group) != (expected_hostname, expected_user, expected_group):
        raise ValueError("browser worker identity mismatch")
    _safe_file(marker)
    marker_stat = marker.stat()
    owner = pwd.getpwuid(marker_stat.st_uid).pw_name
    marker_group = grp.getgrgid(marker_stat.st_gid).gr_name
    if (owner, marker_group) != (expected_marker_owner, expected_marker_group):
        raise ValueError("bootstrap marker ownership mismatch")
    if stat.S_IMODE(marker_stat.st_mode) != 0o640:
        raise ValueError("bootstrap marker mode mismatch")
    marker_bytes = marker.read_bytes()
    if len(marker_bytes) > 4096:
        raise ValueError("bootstrap marker is oversized")
    return {
        "hostname": hostname,
        "user": user,
        "group": group,
        "bootstrap_marker_sha256": hashlib.sha256(marker_bytes).hexdigest(),
    }


def _validate(
    raw: dict[str, Any], helper_path: Path
) -> tuple[str, float, Path, int, int, int, int, list[str], str, str, dict[str, str]]:
    if _text(raw, "protocol") != PROTOCOL_VERSION:
        raise ValueError("unsupported campaign supervisor protocol")
    marker = _text(raw, "marker")
    revision = _text(raw, "revision").lower()
    harness_sha256 = _text(raw, "harness_sha256")
    helper_sha256 = _text(raw, "helper_sha256")
    if not _MARKER.fullmatch(marker):
        raise ValueError("invalid campaign marker")
    if not _REVISION.fullmatch(revision):
        raise ValueError("campaign requires a full source revision")
    if not _HEX64.fullmatch(harness_sha256) or not _HEX64.fullmatch(helper_sha256):
        raise ValueError("invalid campaign SHA-256")
    if _sha256_file(helper_path) != helper_sha256:
        raise ValueError("campaign supervisor SHA-256 mismatch")
    timeout = raw.get("timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("invalid campaign timeout")
    timeout = float(timeout)
    if timeout <= 0 or timeout > MAX_TIMEOUT_SECONDS:
        raise ValueError("campaign timeout is outside the allowed range")
    source_root = Path(_text(raw, "source_root"))
    harness = Path(_text(raw, "harness"))
    corpus = Path(_text(raw, "corpus"))
    artifact_root = Path(_text(raw, "artifact_root"))
    artifact_dir = Path(_text(raw, "artifact_dir"))
    paths = (source_root, harness, corpus, artifact_root, artifact_dir)
    if any(not path.is_absolute() or ".." in path.parts for path in paths):
        raise ValueError("campaign paths must be canonical absolute paths")
    try:
        harness_relative = harness.relative_to(source_root / "out")
        artifact_relative = artifact_dir.relative_to(artifact_root)
    except ValueError as exc:
        raise ValueError("campaign harness or artifact directory is outside its root") from exc
    if not harness_relative.parts or not artifact_relative.parts:
        raise ValueError("campaign requires dedicated harness and artifact paths")
    argv = raw.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(value, str) for value in argv)
        or len(argv) > 128
        or any(len(value) > 4096 or "\x00" in value for value in argv)
    ):
        raise ValueError("invalid campaign argv")
    if argv[0] != str(harness) or argv.count(str(corpus)) != 1:
        raise ValueError("campaign argv is not bound to harness and corpus")
    expected_prefix = f"-artifact_prefix={artifact_dir}/"
    if argv.count(expected_prefix) != 1:
        raise ValueError("campaign argv is not bound to its artifact directory")
    extra_env = raw.get("env", {})
    if (
        not isinstance(extra_env, dict)
        or len(extra_env) > 16
        or not all(
            isinstance(key, str)
            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
            and isinstance(value, str)
            and len(value) <= 4096
            and "\x00" not in value
            for key, value in extra_env.items()
        )
    ):
        raise ValueError("invalid campaign env")
    descriptors: list[int] = []
    try:
        source_descriptor = _open_directory_nofollow(source_root, "Chromium source root")
        descriptors.append(source_descriptor)
        git_descriptor = _open_relative_nofollow(
            source_descriptor, Path(".git"), "Chromium Git directory", directory=True
        )
        os.close(git_descriptor)
        harness_descriptor = _open_relative_nofollow(
            source_descriptor,
            Path("out") / harness_relative,
            "campaign harness",
            directory=False,
        )
        descriptors.append(harness_descriptor)
        harness_mode = os.fstat(harness_descriptor).st_mode
        if harness_mode & (stat.S_IWGRP | stat.S_IWOTH) or (harness_mode & 0o111) == 0:
            raise ValueError("campaign harness is writable or not executable")
        corpus_descriptor = _open_directory_nofollow(corpus, "campaign corpus")
        descriptors.append(corpus_descriptor)
        artifact_root_descriptor = _open_directory_nofollow(artifact_root, "campaign artifact root")
        try:
            artifact_descriptor = _open_relative_nofollow(
                artifact_root_descriptor,
                artifact_relative,
                "campaign artifact directory",
                directory=True,
            )
        finally:
            os.close(artifact_root_descriptor)
        descriptors.append(artifact_descriptor)
        if not _directory_is_readable_writable(
            corpus_descriptor
        ) or not _directory_is_readable_writable(artifact_descriptor):
            raise ValueError("campaign corpus and artifact directory must be readable/writable")
        identity = _validate_identity(raw)
        command = list(argv)
        # FuzzTest-generated wrapper binaries spawn the real fuzzer as a grandchild;
        # inherited /proc/self/fd/N paths do not survive that spawn. Keep real paths
        # for corpus/artifact directories in FuzzTest mode (custody checks above still
        # hold the descriptors, and the artifact inventory below reads by descriptor).
        fuzztest_mode = any(
            argument.startswith("--corpus_database=") for argument in command
        )
        if not fuzztest_mode:
            command[command.index(str(corpus))] = _tool_directory_path(
                corpus_descriptor, corpus
            )
            command[command.index(expected_prefix)] = (
                f"-artifact_prefix={_tool_directory_path(artifact_descriptor, artifact_dir)}/"
            )
        return (
            marker,
            timeout,
            source_root,
            source_descriptor,
            harness_descriptor,
            corpus_descriptor,
            artifact_descriptor,
            command,
            revision,
            harness_sha256,
            identity,
            dict(extra_env),
        )
    except Exception:
        for descriptor in descriptors:
            os.close(descriptor)
        raise


class _BoundedCapture:
    def __init__(self) -> None:
        self.digest = hashlib.sha256()
        self.tail = bytearray()
        self.size = 0
        self.error: OSError | None = None

    def consume(self, source: Any) -> None:
        try:
            while chunk := source.read(64 * 1024):
                self.digest.update(chunk)
                self.size += len(chunk)
                self.tail.extend(chunk)
                if len(self.tail) > MAX_OUTPUT_BYTES:
                    del self.tail[: len(self.tail) - MAX_OUTPUT_BYTES]
        except OSError as exc:
            self.error = exc

    def result(self) -> dict[str, Any]:
        if self.error is not None:
            raise self.error
        return {
            "tail_base64": base64.b64encode(bytes(self.tail)).decode("ascii"),
            "sha256": self.digest.hexdigest(),
            "bytes": self.size,
            "truncated": self.size > MAX_OUTPUT_BYTES,
        }


def _require_empty_artifact_directory(descriptor: int) -> None:
    # descriptor was opened component-wise with O_NOFOLLOW and is never
    # resolved again by pathname.
    if os.listdir(descriptor):  # foxguard: ignore[py/no-path-traversal]
        raise ValueError("campaign artifact directory must be empty and unique to this run")


def _read_artifact(
    directory_descriptor: int, name: str, retrieval_budget: int
) -> tuple[int, str, bytes | None]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("crash artifact is not a regular file")
        retrieve = before.st_size <= min(MAX_ARTIFACT_BYTES, retrieval_budget)
        content = bytearray() if retrieve else None
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
                if content is not None:
                    content.extend(chunk)
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if before_identity != after_identity or size != after.st_size:
            raise ValueError("crash artifact changed during inventory")
        return size, digest.hexdigest(), bytes(content) if content is not None else None
    finally:
        os.close(descriptor)


def _artifacts(directory_descriptor: int) -> list[dict[str, Any]]:
    # Directory enumeration is fd-relative after no-follow admission.
    names = sorted(
        os.listdir(directory_descriptor)  # foxguard: ignore[py/no-path-traversal]
    )
    if len(names) > MAX_ARTIFACTS:
        raise ValueError("campaign produced too many crash artifacts")
    retrieved = 0
    records: list[dict[str, Any]] = []
    for name in names:
        if not name or "/" in name or any(ord(character) < 32 for character in name):
            raise ValueError("campaign produced an unsafe crash artifact name")
        size, digest, data = _read_artifact(
            directory_descriptor, name, MAX_RETRIEVED_BYTES - retrieved
        )
        record: dict[str, Any] = {"name": name, "size": size, "sha256": digest}
        if data is not None:
            record["content_base64"] = base64.b64encode(data).decode("ascii")
            record["retrieved"] = True
            retrieved += size
        else:
            record["retrieved"] = False
        records.append(record)
    return records


def _group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # EPERM proves that the group still exists; treating it as gone would
        # turn an unverifiable cleanup into a successful one.
        return True
    return True


def _enable_child_subreaper() -> None:
    if not sys.platform.startswith("linux"):
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))



def _terminate_if_parent_dies() -> None:
    if not sys.platform.startswith("linux"):
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))

def _reap_group_children(pgid: int) -> None:
    while True:
        try:
            child, _ = os.waitpid(-pgid, os.WNOHANG)
        except ChildProcessError:
            return
        if child == 0:
            return


def _wait_for_group_exit(process: subprocess.Popen[bytes], seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        process.poll()
        _reap_group_children(process.pid)
        if not _group_exists(process.pid):
            return True
        time.sleep(0.05)
    process.poll()
    _reap_group_children(process.pid)
    return not _group_exists(process.pid)


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except PermissionError as exc:
        raise RuntimeError("campaign process group could not receive SIGTERM") from exc
    if _wait_for_group_exit(process, 2):
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except PermissionError as exc:
        raise RuntimeError("campaign process group could not receive SIGKILL") from exc
    if not _wait_for_group_exit(process, 5):
        raise RuntimeError("campaign process group survived SIGKILL")


def _run(
    argv: list[str],
    executable: str,
    source_root: Path,
    source_descriptor: int,
    inherited_descriptors: tuple[int, ...],
    timeout: float,
    extra_env: dict[str, str] | None = None,
) -> tuple[int, bool, dict[str, Any], dict[str, Any]]:
    _enable_child_subreaper()
    execution_path = executable if Path("/proc/self/fd").is_dir() else argv[0]
    process = subprocess.Popen(  # foxguard: ignore[py/no-command-injection]
        argv,
        executable=execution_path,
        cwd=_tool_directory_path(source_descriptor, source_root),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        pass_fds=inherited_descriptors,
        # Manifest env is merged before the sanitizer options so oracle
        # control (halt/abort) always wins over operator-supplied variables.
        env={
            **os.environ,
            **(extra_env or {}),
            "ASAN_OPTIONS": "halt_on_error=1:abort_on_error=1:symbolize=1",
            "MSAN_OPTIONS": "halt_on_error=1:abort_on_error=1:symbolize=1",
            "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1:print_stacktrace=1",
        },
    )
    assert process.stdout is not None and process.stderr is not None
    stdout = _BoundedCapture()
    stderr = _BoundedCapture()
    threads = [
        threading.Thread(target=stdout.consume, args=(process.stdout,), daemon=True),
        threading.Thread(target=stderr.consume, args=(process.stderr,), daemon=True),
    ]
    started_threads: list[threading.Thread] = []
    timed_out = False
    returncode: int | None = None
    def terminate(_signal: int, _frame: Any) -> None:
        raise RuntimeError("campaign supervisor received a termination signal")

    previous_handlers = {
        value: signal.signal(value, terminate) for value in (signal.SIGTERM, signal.SIGHUP)
    }
    try:
        for thread in threads:
            thread.start()
            started_threads.append(thread)
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
    finally:
        # A harness can exit while descendants continue with redirected streams.
        # Always clear the private session, not just the leader, before returning.
        cleanup_error: RuntimeError | None = None
        try:
            _terminate_group(process)
        except RuntimeError as exc:
            cleanup_error = exc
        for thread in started_threads:
            thread.join(timeout=5)
        if any(thread.is_alive() for thread in started_threads):
            raise RuntimeError("campaign output capture did not terminate")
        if cleanup_error is not None:
            raise cleanup_error
        for value, previous in previous_handlers.items():
            signal.signal(value, previous)
    if returncode is None:
        returncode = process.returncode if process.returncode is not None else -signal.SIGKILL
    return returncode, timed_out, stdout.result(), stderr.result()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("0VERSE-BROWSER-CAMPAIGN-ERROR:expected one encoded header", file=sys.stderr)
        return 125
    helper_path = Path(__file__).resolve()
    descriptors: tuple[int, ...] = ()
    _terminate_if_parent_dies()
    try:
        raw = _decode_header(args[0])
        (
            marker,
            timeout,
            source_root,
            source_descriptor,
            harness_descriptor,
            corpus_descriptor,
            artifact_descriptor,
            command,
            revision,
            harness_hash,
            identity,
            extra_env,
        ) = _validate(raw, helper_path)
        descriptors = (
            source_descriptor,
            harness_descriptor,
            corpus_descriptor,
            artifact_descriptor,
        )
        if (
            _git_revision(source_descriptor, source_root) != revision
            or _sha256_fd(harness_descriptor) != harness_hash
        ):
            raise ValueError("campaign build attestation failed before execution")
        _require_empty_artifact_directory(artifact_descriptor)
        returncode, timed_out, stdout, stderr = _run(
            command,
            _fd_path(harness_descriptor),
            source_root,
            source_descriptor,
            descriptors,
            timeout,
            extra_env,
        )
        if (
            _git_revision(source_descriptor, source_root) != revision
            or _sha256_fd(harness_descriptor) != harness_hash
        ):
            raise ValueError("campaign build attestation changed during execution")
        record = {
            "protocol": PROTOCOL_VERSION,
            "marker": marker,
            "target_returncode": returncode,
            "timed_out": timed_out,
            "stdout": stdout,
            "stderr": stderr,
            "artifacts": _artifacts(artifact_descriptor),
            "identity": identity,
        }
        encoded = base64.b64encode(
            json.dumps(record, separators=(",", ":"), sort_keys=True).encode()
        ).decode("ascii")
        # marker is a validated nonce and encoded is canonical base64 JSON.
        print(  # foxguard: ignore[py/taint-log-injection]
            f"{RECORD_PREFIX}{marker}:{encoded}"
        )
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
        print(f"0VERSE-BROWSER-CAMPAIGN-ERROR:{exc}", file=sys.stderr)
        return 125
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


if __name__ == "__main__":
    raise SystemExit(main())

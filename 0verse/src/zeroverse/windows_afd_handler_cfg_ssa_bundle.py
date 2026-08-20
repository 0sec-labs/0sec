"""Custody-bound production and replay of paired AFD CFG/SSA evidence."""

from __future__ import annotations

import hashlib
import json
import os
import selectors
import signal
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast

from . import windows_afd_handler_cfg_ssa as core
from . import windows_afd_handler_cfg_ssa_ghidra as ghidra_extractor
from . import windows_afd_handler_semantics as native_semantics
from .windows_afd_handler_cfg_ssa import (
    canonical_handler_cfg_ssa_bytes,
    compile_windows_afd_handler_cfg_ssa,
)
from .windows_afd_handler_semantics import (
    _snapshot_semantics_bundle,
    _verify_snapshotted_semantics_bundle,
)
from .windows_afd_selector import _remove_tree_at
from .windows_driver_entry_bridge import _toolchain_fingerprint
from .windows_driver_registration import (
    _exact,
    _obj,
    _read_regular_file_at,
    _relative_file,
    _sha,
    _snapshot_file_from_dirfd,
    _unique,
)
from .windows_variant import (
    _create_staging_directory,
    _open_directory_ancestry,
    _publish_directory_no_replace,
    _require_directory_path_identity,
    _write_new_file_at,
)

RECEIPT_VERSION = "0verse.windows-afd-handler-cfg-ssa-receipt/v1"
PRODUCER = "zeroverse.windows-afd-handler-cfg-ssa-bundle/v1"
ISOLATED_REPLAY_TIMEOUT_SECONDS = 1800
ISOLATED_REPLAY_OUTPUT_LIMIT = 64 * 1024
ISOLATED_REPLAY_KILL_WAIT_SECONDS = 10
SIDE_HARD_TIMEOUT_SECONDS = ghidra_extractor.SIDE_WALL_CLOCK_SECONDS
SIDE_OUTPUT_LIMIT = 512 * 1024 * 1024
_CONFIG = {
    "native_schema": native_semantics.EXPORT_VERSION,
    "cfg_ssa_schema": core.EXPORT_VERSION,
    "side_schema": core.ACQUISITION_VERSION,
    "functions_per_side": core.EXPECTED_FUNCTIONS_PER_SIDE,
    "max_blocks_per_side": core.MAX_TOTAL_BLOCKS_PER_SIDE,
    "max_ops_per_side": core.MAX_TOTAL_OPS_PER_SIDE,
    "max_edges_per_side": core.MAX_TOTAL_EDGES_PER_SIDE,
    "side_wall_clock_seconds": ghidra_extractor.SIDE_WALL_CLOCK_SECONDS,
    "side_hard_process_timeout_seconds": SIDE_HARD_TIMEOUT_SECONDS,
    "isolated_replay_timeout_seconds": ISOLATED_REPLAY_TIMEOUT_SECONDS,
    "isolated_replay_kill_wait_seconds": ISOLATED_REPLAY_KILL_WAIT_SECONDS,
    "static_only": True,
}
CONFIG_SHA256 = hashlib.sha256(
    json.dumps(_CONFIG, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()


def produce_windows_afd_handler_cfg_ssa(
    native_bundle: str | Path,
    output_dir: str | Path,
    *,
    ghidra_home: str | Path,
) -> dict[str, str]:
    """Build, fully replay, and atomically publish one paired CFG/SSA bundle."""
    source = Path(os.path.abspath(native_bundle))  # noqa: PTH100 - lexical custody
    output = Path(os.path.abspath(output_dir))  # noqa: PTH100 - lexical publication
    home = Path(os.path.abspath(ghidra_home))  # noqa: PTH100 - tool custody
    if output.exists() or output.is_symlink():
        raise FileExistsError("AFD CFG/SSA output already exists")
    parent_fd = _open_directory_ancestry(output.parent, "AFD CFG/SSA output parent")
    source_fd = _open_directory_ancestry(source, "AFD native semantics source")
    temporary_name, temporary_fd, published = "", -1, False
    try:
        with TemporaryDirectory(prefix="zeroverse-afd-cfg-ssa-build-") as root:
            private = Path(root).resolve(strict=True) / "bundle"
            private.mkdir(mode=0o700)
            private_fd = os.open(private, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.mkdir("native", 0o700, dir_fd=private_fd)
                native_fd = os.open(
                    "native", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=private_fd
                )
                try:
                    _snapshot_semantics_bundle(source_fd, native_fd)
                finally:
                    os.close(native_fd)
                retained_native = private / "native"
                native = _verify_snapshotted_semantics_bundle(retained_native, home)
                script_sha = _extractor_script_sha256()
                toolchain = _toolchain_fingerprint(home)
                _require_pins(home, script_sha, toolchain)
                facts: dict[str, object] = {}
                for side, directory in (
                    ("side_a", "side-a-selector"),
                    ("side_b", "side-b-selector"),
                ):
                    binary, pdb = _retained_side_inputs(retained_native, directory, side)
                    facts[side] = _acquire_side_isolated(
                        binary,
                        pdb,
                        home,
                        retained_native / "semantics.json",
                        side=side,
                    )
                    _require_pins(home, script_sha, toolchain)
                artifact = compile_windows_afd_handler_cfg_ssa(
                    native, facts["side_a"], facts["side_b"]
                )
                artifact_bytes = canonical_handler_cfg_ssa_bytes(artifact)
                artifact_sha = _write_new_file_at(private_fd, "cfg-ssa.json", artifact_bytes)
                native_artifact_sha = _sha_file(retained_native / "semantics.json")
                native_receipt_sha = _sha_file(retained_native / "receipt.json")
                receipt = _receipt(
                    artifact_sha,
                    native_artifact_sha,
                    native_receipt_sha,
                    script_sha,
                    toolchain,
                )
                receipt_bytes = json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n"
                _write_new_file_at(private_fd, "receipt.json", receipt_bytes)
                os.fsync(private_fd)
                _require_replay_sha(artifact_sha, _verify_bundle_isolated(private, home))
                _require_pins(home, script_sha, toolchain)
                _require_directory_path_identity(
                    output.parent, parent_fd, "AFD CFG/SSA output parent"
                )
                temporary_name, temporary_fd = _create_staging_directory(
                    parent_fd, f".{output.name}.tmp-"
                )
                _snapshot_cfg_ssa_bundle(private_fd, temporary_fd)
                os.fsync(temporary_fd)
                _require_directory_path_identity(
                    output.parent / temporary_name,
                    temporary_fd,
                    "AFD CFG/SSA publication staging",
                )
                _publish_directory_no_replace(parent_fd, temporary_name, output.name)
                os.fsync(parent_fd)
                published = True
                return {
                    "cfg_ssa_path": f"{output.name}/cfg-ssa.json",
                    "cfg_ssa_sha256": artifact_sha,
                    "receipt_path": f"{output.name}/receipt.json",
                    "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
                }
            finally:
                os.close(private_fd)
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_name and not published:
            _remove_tree_at(parent_fd, temporary_name)
        os.close(source_fd)
        os.close(parent_fd)


def verify_windows_afd_handler_cfg_ssa_bundle(
    bundle_path: str | Path, *, ghidra_home: str | Path
) -> dict[str, object]:
    """Snapshot and fully replay one published CFG/SSA bundle."""
    source_fd = _open_directory_ancestry(Path(bundle_path), "AFD CFG/SSA bundle")
    home = Path(os.path.abspath(ghidra_home))  # noqa: PTH100 - tool custody
    try:
        with TemporaryDirectory(prefix="zeroverse-afd-cfg-ssa-verify-") as root:
            retained = Path(root).resolve(strict=True) / "bundle"
            retained.mkdir(mode=0o700)
            retained_fd = os.open(retained, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                _snapshot_cfg_ssa_bundle(source_fd, retained_fd)
                os.fsync(retained_fd)
            finally:
                os.close(retained_fd)
            artifact, receipt, _native = _read_retained_bundle(retained, home)
            expected_sha = hashlib.sha256(canonical_handler_cfg_ssa_bytes(artifact)).hexdigest()
            _require_replay_sha(expected_sha, _verify_bundle_isolated(retained, home))
            _require_pins(home, receipt["extractor_script_sha256"], receipt["toolchain"])
            return artifact
    finally:
        os.close(source_fd)


def _verify_snapshotted_cfg_ssa_bundle(bundle: Path, home: Path) -> dict[str, object]:
    artifact, receipt, native = _read_retained_bundle(bundle, home)
    facts: dict[str, object] = {}
    for side, directory in (("side_a", "side-a-selector"), ("side_b", "side-b-selector")):
        binary, pdb = _retained_side_inputs(bundle / "native", directory, side)
        facts[side] = _acquire_side_isolated(
            binary,
            pdb,
            home,
            bundle / "native" / "semantics.json",
            side=side,
        )
        _require_pins(home, receipt["extractor_script_sha256"], receipt["toolchain"])
    replay = compile_windows_afd_handler_cfg_ssa(native, facts["side_a"], facts["side_b"])
    if canonical_handler_cfg_ssa_bytes(replay) != canonical_handler_cfg_ssa_bytes(artifact):
        raise ValueError("AFD CFG/SSA full replay mismatch")
    return artifact


def _read_retained_bundle(
    bundle: Path, home: Path
) -> tuple[dict[str, object], dict[str, Any], dict[str, object]]:
    bundle_fd = _open_directory_ancestry(bundle, "retained AFD CFG/SSA bundle")
    try:
        receipt = _obj(
            json.loads(
                _read_regular_file_at(
                    bundle_fd, "receipt.json", "AFD CFG/SSA receipt", 1024 * 1024
                ),
                object_pairs_hook=_unique,
            ),
            "AFD CFG/SSA receipt",
        )
        _validate_receipt(receipt, home)
        raw = _read_regular_file_at(
            bundle_fd, "cfg-ssa.json", "AFD CFG/SSA artifact", 512 * 1024 * 1024
        )
        if hashlib.sha256(raw).hexdigest() != receipt["cfg_ssa_sha256"]:
            raise ValueError("AFD CFG/SSA artifact SHA-256 mismatch")
        artifact = core._validate(json.loads(raw, object_pairs_hook=_unique))
        if canonical_handler_cfg_ssa_bytes(artifact) != raw:
            raise ValueError("AFD CFG/SSA artifact is not canonical")
        native_path = bundle / "native"
        native = _verify_snapshotted_semantics_bundle(native_path, home)
        if (
            _sha_file(native_path / "semantics.json") != receipt["native_semantics_sha256"]
            or _sha_file(native_path / "receipt.json") != receipt["native_receipt_sha256"]
            or cast(dict[str, Any], artifact["native_semantics_commitment"])["artifact_sha256"]
            != hashlib.sha256(
                json.dumps(native, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        ):
            raise ValueError("AFD CFG/SSA retained native commitment mismatch")
        return artifact, receipt, native
    finally:
        os.close(bundle_fd)


def _receipt(
    artifact_sha: str,
    native_artifact_sha: str,
    native_receipt_sha: str,
    script_sha: str,
    toolchain: dict[str, object],
) -> dict[str, object]:
    return {
        "schema_version": RECEIPT_VERSION,
        "producer": PRODUCER,
        "cfg_ssa_path": "cfg-ssa.json",
        "cfg_ssa_sha256": artifact_sha,
        "native_bundle": "native",
        "native_semantics_sha256": native_artifact_sha,
        "native_receipt_sha256": native_receipt_sha,
        "extractor_config_sha256": CONFIG_SHA256,
        "extractor_script_sha256": script_sha,
        "toolchain": toolchain,
        "isolated_replay_timeout_seconds": ISOLATED_REPLAY_TIMEOUT_SECONDS,
        "isolated_replay_kill_wait_seconds": ISOLATED_REPLAY_KILL_WAIT_SECONDS,
        "side_hard_process_timeout_seconds": SIDE_HARD_TIMEOUT_SECONDS,
        "static_only": True,
        "execution_authorized": False,
        "driver_load_attempts": 0,
        "device_open_attempts": 0,
        "device_ioctl_attempts": 0,
        "runtime_attempts": 0,
    }


def _validate_receipt(receipt: dict[str, Any], home: Path) -> None:
    fields = set(_receipt("0" * 64, "0" * 64, "0" * 64, "0" * 64, {}))
    _exact(receipt, fields, "AFD CFG/SSA receipt")
    for name in (
        "cfg_ssa_sha256",
        "native_semantics_sha256",
        "native_receipt_sha256",
        "extractor_config_sha256",
        "extractor_script_sha256",
    ):
        _sha(receipt[name], name)
    if (
        receipt["schema_version"] != RECEIPT_VERSION
        or receipt["producer"] != PRODUCER
        or receipt["cfg_ssa_path"] != "cfg-ssa.json"
        or receipt["native_bundle"] != "native"
        or receipt["extractor_config_sha256"] != CONFIG_SHA256
        or receipt["toolchain"] != _toolchain_fingerprint(home)
        or type(receipt["isolated_replay_timeout_seconds"]) is not int
        or receipt["isolated_replay_timeout_seconds"] != ISOLATED_REPLAY_TIMEOUT_SECONDS
        or type(receipt["isolated_replay_kill_wait_seconds"]) is not int
        or receipt["isolated_replay_kill_wait_seconds"] != ISOLATED_REPLAY_KILL_WAIT_SECONDS
        or type(receipt["side_hard_process_timeout_seconds"]) is not int
        or receipt["side_hard_process_timeout_seconds"] != SIDE_HARD_TIMEOUT_SECONDS
        or receipt["static_only"] is not True
        or receipt["execution_authorized"] is not False
        or any(
            type(receipt[name]) is not int or receipt[name] != 0
            for name in (
                "driver_load_attempts",
                "device_open_attempts",
                "device_ioctl_attempts",
                "runtime_attempts",
            )
        )
    ):
        raise ValueError("AFD CFG/SSA receipt contract mismatch")
    _require_pins(home, receipt["extractor_script_sha256"], receipt["toolchain"])


def _retained_side_inputs(native: Path, directory: str, side: str) -> tuple[Path, Path]:
    bridge = native / "hypotheses" / directory / "registration" / "entry-bridge"
    receipt_fd = _open_directory_ancestry(bridge, f"{side} retained entry bridge")
    try:
        receipt = _obj(
            json.loads(
                _read_regular_file_at(
                    receipt_fd, "receipt.json", f"{side} bridge receipt", 1024 * 1024
                ),
                object_pairs_hook=_unique,
            ),
            f"{side} bridge receipt",
        )
    finally:
        os.close(receipt_fd)
    return (
        _relative_file(bridge, receipt["binary_path"], f"{side} binary"),
        _relative_file(bridge, receipt["pdb_path"], f"{side} PDB"),
    )


def _snapshot_cfg_ssa_bundle(source_fd: int, destination_fd: int) -> None:
    for name, limit in (("receipt.json", 1024 * 1024), ("cfg-ssa.json", 512 * 1024 * 1024)):
        _snapshot_file_from_dirfd(
            source_fd, name, destination_fd, name, "AFD CFG/SSA retained file", limit
        )
    source_native_fd = os.open(
        "native", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source_fd
    )
    os.mkdir("native", 0o700, dir_fd=destination_fd)
    destination_native_fd = os.open(
        "native", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=destination_fd
    )
    try:
        _snapshot_semantics_bundle(source_native_fd, destination_native_fd)
    finally:
        os.close(destination_native_fd)
        os.close(source_native_fd)


def _extractor_script_sha256() -> str:
    digest = hashlib.sha256(b"0verse-afd-handler-cfg-ssa-scripts-v1\0")
    paths = (
        Path(__file__),
        Path(core.__file__ or ""),
        Path(ghidra_extractor.__file__ or ""),
        Path(__file__).with_name("windows_afd_handler_cfg_ssa_replay.py"),
        Path(__file__).with_name("windows_afd_handler_cfg_ssa_side_replay.py"),
    )
    for path in sorted(paths, key=lambda item: item.name):
        raw = path.read_bytes()
        digest.update(path.name.encode())
        digest.update(len(raw).to_bytes(8, "little"))
        digest.update(raw)
    return digest.hexdigest()


def _require_pins(home: Path, script_sha: object, toolchain: object) -> None:
    if _extractor_script_sha256() != script_sha or _toolchain_fingerprint(home) != toolchain:
        raise ValueError("AFD CFG/SSA extractor script or toolchain changed during analysis")


def _sha_file(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 64 * 1024):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _verify_bundle_isolated(bundle: Path, home: Path) -> str:
    marker = "0VERSE_AFD_CFG_SSA_ISOLATED_RESULT="
    phase = "0VERSE_AFD_CFG_SSA_ISOLATED_PHASE=full-replay-start"
    package_root = Path(__file__).resolve(strict=True).parent.parent
    bootstrap = (
        "import sys;sys.path.insert(0,sys.argv[1]);"
        "from zeroverse.windows_afd_handler_cfg_ssa_replay import main;"
        "raise SystemExit(main(sys.argv[2:]))"
    )
    process = subprocess.Popen(  # foxguard: ignore[py/no-command-injection]
        [sys.executable, "-I", "-c", bootstrap, str(package_root), str(bundle), str(home)],
        cwd="/",
        env={
            name: os.environ[name]
            for name in ("PATH", "JAVA_HOME", "HOME", "TMPDIR")
            if name in os.environ
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    stdout, stderr = _capture_process(
        process,
        timeout_seconds=ISOLATED_REPLAY_TIMEOUT_SECONDS,
        label="AFD CFG/SSA isolated replay",
    )
    lines = stdout.decode("utf-8", "replace").splitlines()
    markers = [line.removeprefix(marker) for line in lines if line.startswith(marker)]
    if process.returncode != 0 or lines.count(phase) != 1 or len(markers) != 1:
        raise ValueError(
            "AFD CFG/SSA isolated replay failed closed: "
            + stderr.decode("utf-8", "replace")[-4096:]
        )
    result = _obj(json.loads(markers[0], object_pairs_hook=_unique), "isolated replay result")
    _exact(result, {"schema_version", "phase", "artifact_sha256"}, "isolated replay result")
    if (
        result["schema_version"] != "0verse.windows-afd-cfg-ssa-isolated-replay-result/v1"
        or result["phase"] != "full-replay-complete"
    ):
        raise ValueError("AFD CFG/SSA isolated replay result marker mismatch")
    return _sha(result["artifact_sha256"], "isolated replay artifact")


def _acquire_side_isolated(
    binary: Path,
    pdb: Path,
    home: Path,
    native_artifact: Path,
    *,
    side: str,
) -> dict[str, object]:
    marker = "0VERSE_AFD_CFG_SSA_SIDE_RESULT="
    package_root = Path(__file__).resolve(strict=True).parent.parent
    bootstrap = (
        "import sys;sys.path.insert(0,sys.argv[1]);"
        "from zeroverse.windows_afd_handler_cfg_ssa_side_replay import main;"
        "raise SystemExit(main(sys.argv[2:]))"
    )
    with TemporaryDirectory(prefix=f"zeroverse-afd-cfg-ssa-{side}-isolated-") as root:
        private = Path(root).resolve(strict=True)
        output = private / "side.json"
        process = subprocess.Popen(  # foxguard: ignore[py/no-command-injection]
            [
                sys.executable,
                "-I",
                "-c",
                bootstrap,
                str(package_root),
                str(binary),
                str(pdb),
                str(home),
                str(native_artifact),
                side,
                str(output),
            ],
            cwd="/",
            env={
                name: os.environ[name]
                for name in ("PATH", "JAVA_HOME", "HOME", "TMPDIR")
                if name in os.environ
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout, stderr = _capture_process(
            process,
            timeout_seconds=SIDE_HARD_TIMEOUT_SECONDS,
            label=f"AFD CFG/SSA {side} acquisition",
        )
        lines = stdout.decode("utf-8", "replace").splitlines()
        markers = [line.removeprefix(marker) for line in lines if line.startswith(marker)]
        if process.returncode != 0 or len(markers) != 1:
            raise ValueError(
                f"AFD CFG/SSA {side} isolated acquisition failed closed: "
                + stderr.decode("utf-8", "replace")[-4096:]
            )
        result = _obj(json.loads(markers[0], object_pairs_hook=_unique), "side replay result")
        _exact(
            result,
            {"schema_version", "side", "artifact_sha256"},
            "side replay result",
        )
        if (
            result["schema_version"] != "0verse.windows-afd-cfg-ssa-side-isolated-result/v1"
            or result["side"] != side
        ):
            raise ValueError("AFD CFG/SSA side isolated result marker mismatch")
        expected_sha = _sha(result["artifact_sha256"], "side isolated artifact")
        directory_fd = _open_directory_ancestry(private, f"AFD CFG/SSA {side} output parent")
        try:
            raw = _read_regular_file_at(
                directory_fd,
                output.name,
                f"AFD CFG/SSA {side} output",
                SIDE_OUTPUT_LIMIT,
            )
        finally:
            os.close(directory_fd)
        if hashlib.sha256(raw).hexdigest() != expected_sha:
            raise ValueError("AFD CFG/SSA side isolated artifact SHA-256 mismatch")
        facts = _obj(json.loads(raw, object_pairs_hook=_unique), f"AFD CFG/SSA {side} output")
        canonical = json.dumps(facts, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        if canonical != raw:
            raise ValueError("AFD CFG/SSA side isolated artifact is not canonical")
        return cast(dict[str, object], facts)


def _capture_process(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: int = ISOLATED_REPLAY_TIMEOUT_SECONDS,
    label: str = "AFD CFG/SSA isolated replay",
) -> tuple[bytes, bytes]:
    if process.stdout is None or process.stderr is None:
        _kill_process_group(process)
        raise ValueError("AFD CFG/SSA isolated replay pipes are unavailable")
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    selector: selectors.BaseSelector | None = None
    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        _kill_process_group(process)
        raise ValueError("AFD CFG/SSA process timeout is invalid")
    deadline = time.monotonic() + timeout_seconds
    try:
        selector = selectors.DefaultSelector()
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError(f"{label} exceeded its timeout")
            for key, _events in selector.select(min(remaining, 0.25)):
                stream = cast(Any, key.fileobj)
                chunk = os.read(stream.fileno(), 8192)
                if not chunk:
                    selector.unregister(stream)
                    continue
                target = streams[stream]
                target.extend(chunk)
                if len(target) > ISOLATED_REPLAY_OUTPUT_LIMIT:
                    raise ValueError(f"{label} output exceeded its bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError(f"{label} exceeded its timeout")
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise ValueError(f"{label} exceeded its timeout") from exc
        # The leader may exit after spawning a process that inherited this dedicated
        # group. Sweep the group before returning even on an otherwise normal exit;
        # callers can then validate status/markers without leaking descendants.
        _kill_process_group(process)
        return bytes(streams[process.stdout]), bytes(streams[process.stderr])
    except BaseException:
        _kill_process_group(process)
        raise
    finally:
        if selector is not None:
            selector.close()
        for stream in streams:
            stream.close()


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=ISOLATED_REPLAY_KILL_WAIT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise ValueError("AFD CFG/SSA isolated replay process group did not terminate") from exc


def _require_replay_sha(expected: object, observed: object) -> None:
    if _sha(expected, "expected replay artifact") != _sha(observed, "observed replay artifact"):
        raise ValueError("AFD CFG/SSA isolated replay artifact SHA-256 mismatch")

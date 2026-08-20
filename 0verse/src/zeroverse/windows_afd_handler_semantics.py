"""Custody-bound side-local evidence for AFD hypothesis-selected functions."""

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
from itertools import pairwise
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast

from . import windows_afd_handler_semantics_ghidra as ghidra_extractor
from .windows_afd_handler_semantics_ghidra import acquire_afd_handler_semantic_facts
from .windows_afd_hypotheses import (
    EXPORT_VERSION as HYPOTHESES_VERSION,
)
from .windows_afd_hypotheses import (
    _snapshot_hypotheses_bundle,
    _verify_snapshotted_hypotheses_bundle,
)
from .windows_afd_hypotheses import (
    _validate as _validate_hypotheses,
)
from .windows_afd_selector import _remove_tree_at
from .windows_driver_entry_bridge import _toolchain_fingerprint
from .windows_driver_registration import (
    _exact,
    _hex,
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

RAW_VERSION = "0verse.windows-afd-handler-semantics-facts/v1"
EXPORT_VERSION = "0verse.windows-afd-handler-semantics/v1"
RECEIPT_VERSION = "0verse.windows-afd-handler-semantics-receipt/v1"
PRODUCER = "zeroverse.windows-afd-handler-semantics/v1"
_EXPECTED_FUNCTIONS = 33
ISOLATED_REPLAY_TIMEOUT_SECONDS = 900
ISOLATED_REPLAY_OUTPUT_LIMIT = 64 * 1024
ISOLATED_REPLAY_KILL_WAIT_SECONDS = 10
_CONFIG = {
    "hypotheses_schema": HYPOTHESES_VERSION,
    "functions_per_side": _EXPECTED_FUNCTIONS,
    "max_total_body_bytes": ghidra_extractor.MAX_TOTAL_BODY_BYTES,
    "max_total_instructions": ghidra_extractor.MAX_TOTAL_INSTRUCTIONS,
    "inherited_per_plan_limits": {
        "max_function_bytes_per_side": 65536,
        "max_instructions_per_side": 20000,
        "max_wall_clock_seconds_per_side": 300,
    },
    "scope": "function-local-side-evidence-only",
    "isolated_replay_timeout_seconds": ISOLATED_REPLAY_TIMEOUT_SECONDS,
    "isolated_replay_kill_wait_seconds": ISOLATED_REPLAY_KILL_WAIT_SECONDS,
}
CONFIG_SHA256 = hashlib.sha256(
    json.dumps(_CONFIG, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
_PROOF_LIMIT = (
    "Exact side-local Ghidra plan-entry observation, complete captured address-set, "
    "disjoint body-range bytes, canonical native instructions, and exact uncovered-byte "
    "intervals for the 33 row-set-correlated entries per side. Address and byte hashes "
    "are factual observations only. "
    "No cross-build handler identity, semantic equivalence or difference, source/sink flow, "
    "guard delta, call-graph completeness, servicing lineage, patch causality, runtime or "
    "unprivileged reachability, execution, candidate, vulnerability, LPE, exploitability, "
    "novelty, bounty eligibility, or weaponization is established."
)


def compile_windows_afd_handler_semantics(
    hypotheses_raw: object,
    side_a_facts_raw: object,
    side_b_facts_raw: object,
    *,
    hypotheses_receipt_sha256: str,
    extractor_script_sha256: str,
) -> dict[str, object]:
    hypotheses = _validate_hypotheses(hypotheses_raw)
    receipt_sha = _sha(hypotheses_receipt_sha256, "hypotheses receipt")
    script_sha = _sha(extractor_script_sha256, "extractor script manifest")
    side_a = _side(side_a_facts_raw, hypotheses, "side_a")
    side_b = _side(side_b_facts_raw, hypotheses, "side_b")
    functions_a = cast(list[dict[str, Any]], side_a["functions"])
    functions_b = cast(list[dict[str, Any]], side_b["functions"])
    pairs: list[dict[str, object]] = []
    for order, (left, right) in enumerate(zip(functions_a, functions_b, strict=True), 1):
        if (
            left["hypothesis_id"] != right["hypothesis_id"]
            or left["row_indices"] != right["row_indices"]
            or left["ioctl_keys"] != right["ioctl_keys"]
        ):
            raise ValueError("AFD handler semantic pair correlation mismatch")
        pair = {
                "enumeration_order": order,
                "hypothesis_id": left["hypothesis_id"],
                "row_indices": left["row_indices"],
                "ioctl_keys": left["ioctl_keys"],
                "side_a_entry_rva": left["entry_rva"],
                "side_b_entry_rva": right["entry_rva"],
                "native_body_hashes_equal": (
                    left["body"]["addressed_sha256"] == right["body"]["addressed_sha256"]
                ),
                "native_instruction_hashes_equal": (
                    _canonical_hash(left["instructions"]) == _canonical_hash(right["instructions"])
                ),
                "factual_hash_comparison_only": True,
            }
        pair["pair_id"] = _domain_hash(
            "0verse-afd-native-pair-v1",
            {
                "side_a_evidence_id": side_a["evidence_id"],
                "side_b_evidence_id": side_b["evidence_id"],
                "hypotheses_artifact_sha256": _canonical_hash(hypotheses),
                "hypotheses_receipt_sha256": receipt_sha,
                "pair": pair,
            },
        )
        pairs.append(pair)
    result = {
        "schema_version": EXPORT_VERSION,
        "producer": PRODUCER,
        "extractor_config_sha256": CONFIG_SHA256,
        "extractor_script_sha256": script_sha,
        "hypotheses_commitment": {
            "path": "hypotheses",
            "schema_version": HYPOTHESES_VERSION,
            "artifact_sha256": _canonical_hash(hypotheses),
            "receipt_sha256": receipt_sha,
        },
        "sides": {"side_a": side_a, "side_b": side_b},
        "pair_count": len(pairs),
        "pairs": pairs,
        "exact_plan_entry_observed": True,
        "complete_ghidra_address_set_captured": True,
        "side_local_exact_function_identity_established": False,
        "ghidra_function_body_extent_complete": False,
        "function_local_cfg_complete": False,
        "function_local_high_pcode_complete": False,
        "cross_build_handler_identity_established": False,
        "handler_body_change_established": False,
        "semantic_difference_established": False,
        "source_sink_semantics_established": False,
        "guard_delta_established": False,
        "call_graph_complete": False,
        "ranking_performed": False,
        "candidate_count": 0,
        "candidate_established": False,
        "labels_consumed": False,
        "ground_truth_consumed": False,
        "model_invocations": 0,
        "network_performed": False,
        "driver_load_attempts": 0,
        "device_open_attempts": 0,
        "device_ioctl_attempts": 0,
        "runtime_attempts": 0,
        "runtime_consumable": False,
        "execution_authorized": False,
        "runtime_reachability_established": False,
        "unprivileged_reachability_established": False,
        "vulnerability_established": False,
        "lpe_established": False,
        "exploitability_established": False,
        "novelty_established": False,
        "claim_eligible": False,
        "bounty_eligible": False,
        "weaponization": False,
        "automatic_disclosure": False,
        "human_promotion_gate": True,
        "proof_limit": _PROOF_LIMIT,
    }
    return _validate(result)


def canonical_handler_semantics_bytes(raw: object) -> bytes:
    return _canonical(_validate(raw)) + b"\n"


def produce_windows_afd_handler_semantics(
    hypotheses_bundle: str | Path,
    output_dir: str | Path,
    *,
    ghidra_home: str | Path,
) -> dict[str, str]:
    source = Path(os.path.abspath(hypotheses_bundle))  # noqa: PTH100 - lexical custody
    output = Path(os.path.abspath(output_dir))  # noqa: PTH100 - lexical publication
    home = Path(os.path.abspath(ghidra_home))  # noqa: PTH100 - tool custody
    if output.exists() or output.is_symlink():
        raise FileExistsError("AFD handler semantics output already exists")
    parent_fd = _open_directory_ancestry(output.parent, "AFD semantics output parent")
    source_fd = _open_directory_ancestry(source, "AFD hypotheses source")
    temporary_name, temporary_fd, published = "", -1, False
    try:
        with TemporaryDirectory(prefix="zeroverse-afd-semantics-build-") as private_root:
            private = Path(private_root).resolve(strict=True) / "bundle"
            private.mkdir(mode=0o700)
            private_fd = os.open(private, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.mkdir("hypotheses", 0o700, dir_fd=private_fd)
                retained_fd = os.open(
                    "hypotheses", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=private_fd,
                )
                try:
                    _snapshot_hypotheses_bundle(source_fd, retained_fd)
                finally:
                    os.close(retained_fd)
                retained = private / "hypotheses"
                script_sha = _extractor_script_sha256()
                toolchain = _toolchain_fingerprint(home)
                hypotheses = _verify_snapshotted_hypotheses_bundle(retained, home)
                _require_extractor_pins(home, script_sha, toolchain)
                plans = cast(list[dict[str, object]], hypotheses["hypotheses"])
                side_facts = {}
                for side, directory in (
                    ("side_a", "side-a-selector"), ("side_b", "side-b-selector")
                ):
                    bridge = retained / directory / "registration" / "entry-bridge"
                    bridge_receipt = _json_file(
                        bridge / "receipt.json", f"{side} bridge receipt"
                    )
                    binary = _relative_file(
                        bridge, bridge_receipt["binary_path"], f"{side} binary"
                    )
                    pdb = _relative_file(bridge, bridge_receipt["pdb_path"], f"{side} PDB")
                    side_facts[side] = acquire_afd_handler_semantic_facts(
                        binary, pdb, home, plans, side=side
                    )
                    _require_extractor_pins(home, script_sha, toolchain)
                hypothesis_receipt_sha = _sha_file(retained / "receipt.json")
                export = compile_windows_afd_handler_semantics(
                    hypotheses, side_facts["side_a"], side_facts["side_b"],
                    hypotheses_receipt_sha256=hypothesis_receipt_sha,
                    extractor_script_sha256=script_sha,
                )
                artifact_bytes = canonical_handler_semantics_bytes(export)
                artifact_sha = _write_new_file_at(private_fd, "semantics.json", artifact_bytes)
                receipt = {
                    "schema_version": RECEIPT_VERSION, "producer": PRODUCER,
                    "semantics_path": "semantics.json", "semantics_sha256": artifact_sha,
                    "hypotheses_bundle": "hypotheses",
                    "hypotheses_receipt_sha256": hypothesis_receipt_sha,
                    "extractor_config_sha256": CONFIG_SHA256,
                    "extractor_script_sha256": script_sha, "toolchain": toolchain,
                    "isolated_replay_timeout_seconds": ISOLATED_REPLAY_TIMEOUT_SECONDS,
                    "isolated_replay_kill_wait_seconds": ISOLATED_REPLAY_KILL_WAIT_SECONDS,
                    "static_only": True, "execution_authorized": False,
                    "device_ioctl_attempts": 0,
                }
                receipt_bytes = json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n"
                _write_new_file_at(private_fd, "receipt.json", receipt_bytes)
                os.fsync(private_fd)
                replay_sha = _verify_semantics_bundle_isolated(private, home)
                _require_replay_sha(artifact_sha, replay_sha)
                _require_extractor_pins(home, script_sha, toolchain)
                _require_directory_path_identity(
                    output.parent, parent_fd, "AFD semantics output parent"
                )
                temporary_name, temporary_fd = _create_staging_directory(
                    parent_fd, f".{output.name}.tmp-"
                )
                _snapshot_semantics_bundle(private_fd, temporary_fd)
                os.fsync(temporary_fd)
                _require_directory_path_identity(
                    output.parent / temporary_name,
                    temporary_fd,
                    "AFD semantics publication staging",
                )
                _publish_directory_no_replace(parent_fd, temporary_name, output.name)
                os.fsync(parent_fd)
                published = True
                return {
                    "semantics_path": f"{output.name}/semantics.json",
                    "semantics_sha256": artifact_sha,
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


def verify_windows_afd_handler_semantics_bundle(
    bundle_path: str | Path, *, ghidra_home: str | Path
) -> dict[str, object]:
    source_fd = _open_directory_ancestry(Path(bundle_path), "AFD semantics bundle")
    home = Path(os.path.abspath(ghidra_home))  # noqa: PTH100 - tool custody
    try:
        with TemporaryDirectory(prefix="zeroverse-afd-semantics-verify-") as temporary:
            retained = Path(temporary).resolve(strict=True) / "bundle"
            retained.mkdir(mode=0o700)
            retained_fd = os.open(retained, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                _snapshot_semantics_bundle(source_fd, retained_fd)
                os.fsync(retained_fd)
            finally:
                os.close(retained_fd)
            artifact, receipt = _read_retained_semantics_artifact(retained, home)
            pinned_script = receipt["extractor_script_sha256"]
            pinned_toolchain = receipt["toolchain"]
            replay_sha = _verify_semantics_bundle_isolated(retained, home)
            expected_sha = hashlib.sha256(canonical_handler_semantics_bytes(artifact)).hexdigest()
            _require_replay_sha(expected_sha, replay_sha)
            _require_extractor_pins(home, pinned_script, pinned_toolchain)
            return artifact
    finally:
        os.close(source_fd)


def _verify_snapshotted_semantics_bundle(bundle: Path, home: Path) -> dict[str, object]:
    bundle_fd = _open_directory_ancestry(bundle, "retained AFD semantics bundle")
    try:
        receipt_bytes = _read_regular_file_at(
            bundle_fd, "receipt.json", "AFD semantics receipt", 1024 * 1024
        )
        receipt = _obj(json.loads(receipt_bytes, object_pairs_hook=_unique), "semantics receipt")
        _validate_receipt(receipt, _toolchain_fingerprint(home), _extractor_script_sha256())
        pinned_script = receipt["extractor_script_sha256"]
        pinned_toolchain = receipt["toolchain"]
        artifact_bytes = _read_regular_file_at(
            bundle_fd, "semantics.json", "AFD semantics artifact", 128 * 1024 * 1024
        )
        if hashlib.sha256(artifact_bytes).hexdigest() != receipt["semantics_sha256"]:
            raise ValueError("AFD semantics artifact SHA-256 mismatch")
        artifact = _validate(json.loads(artifact_bytes, object_pairs_hook=_unique))
        if canonical_handler_semantics_bytes(artifact) != artifact_bytes:
            raise ValueError("AFD semantics artifact is not canonical")
        hypotheses_path = bundle / "hypotheses"
        hypotheses = _verify_snapshotted_hypotheses_bundle(hypotheses_path, home)
        hypothesis_receipt_sha = _sha_file(hypotheses_path / "receipt.json")
        if hypothesis_receipt_sha != receipt["hypotheses_receipt_sha256"]:
            raise ValueError("AFD semantics retained hypotheses receipt mismatch")
        plans = cast(list[dict[str, object]], hypotheses["hypotheses"])
        facts = {}
        for side, directory in (("side_a", "side-a-selector"), ("side_b", "side-b-selector")):
            bridge = hypotheses_path / directory / "registration" / "entry-bridge"
            bridge_receipt = _json_file(bridge / "receipt.json", f"{side} bridge receipt")
            binary = _relative_file(bridge, bridge_receipt["binary_path"], f"{side} binary")
            pdb = _relative_file(bridge, bridge_receipt["pdb_path"], f"{side} PDB")
            facts[side] = acquire_afd_handler_semantic_facts(binary, pdb, home, plans, side=side)
            _require_extractor_pins(home, pinned_script, pinned_toolchain)
        replay = compile_windows_afd_handler_semantics(
            hypotheses,
            facts["side_a"],
            facts["side_b"],
            hypotheses_receipt_sha256=hypothesis_receipt_sha,
            extractor_script_sha256=receipt["extractor_script_sha256"],
        )
        if canonical_handler_semantics_bytes(replay) != artifact_bytes:
            raise ValueError("AFD handler semantics replay mismatch")
        _require_extractor_pins(home, pinned_script, pinned_toolchain)
        return artifact
    finally:
        os.close(bundle_fd)


def _read_retained_semantics_artifact(
    bundle: Path, home: Path
) -> tuple[dict[str, object], dict[str, Any]]:
    bundle_fd = _open_directory_ancestry(bundle, "retained AFD semantics bundle")
    try:
        receipt = _obj(
            json.loads(
                _read_regular_file_at(
                    bundle_fd, "receipt.json", "AFD semantics receipt", 1024 * 1024
                ),
                object_pairs_hook=_unique,
            ),
            "semantics receipt",
        )
        _validate_receipt(receipt, _toolchain_fingerprint(home), _extractor_script_sha256())
        raw = _read_regular_file_at(
            bundle_fd, "semantics.json", "AFD semantics artifact", 128 * 1024 * 1024
        )
        if hashlib.sha256(raw).hexdigest() != receipt["semantics_sha256"]:
            raise ValueError("AFD semantics artifact SHA-256 mismatch")
        artifact = _validate(json.loads(raw, object_pairs_hook=_unique))
        if canonical_handler_semantics_bytes(artifact) != raw:
            raise ValueError("AFD semantics artifact is not canonical")
        return artifact, receipt
    finally:
        os.close(bundle_fd)


def _verify_semantics_bundle_isolated(bundle: Path, home: Path) -> str:
    marker = "0VERSE_AFD_ISOLATED_RESULT="
    phase_marker = "0VERSE_AFD_ISOLATED_PHASE=full-replay-start"
    package_root = Path(__file__).resolve(strict=True).parent.parent
    bootstrap = (
        "import sys;"
        "sys.path.insert(0,sys.argv[1]);"
        "from zeroverse.windows_afd_handler_semantics_replay import main;"
        "raise SystemExit(main(sys.argv[2:]))"
    )
    command = [sys.executable, "-I", "-c", bootstrap, str(package_root), str(bundle), str(home)]
    process = subprocess.Popen(  # foxguard: ignore[py/no-command-injection]
        command,
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
    captured_stdout, captured_stderr = _capture_isolated_process(process)
    return_code = process.returncode
    lines = captured_stdout.decode("utf-8", "replace").splitlines()
    if lines.count(phase_marker) != 1:
        raise ValueError("AFD isolated replay phase marker mismatch")
    markers = [line.removeprefix(marker) for line in lines if line.startswith(marker)]
    if return_code != 0 or len(markers) != 1:
        detail = captured_stderr.decode("utf-8", "replace")[-4096:]
        raise ValueError(f"AFD isolated replay failed closed: {detail}")
    result = _obj(json.loads(markers[0], object_pairs_hook=_unique), "isolated replay result")
    _exact(result, {"schema_version", "phase", "artifact_sha256"}, "isolated result")
    if (
        result["schema_version"] != "0verse.windows-afd-isolated-replay-result/v1"
        or result["phase"] != "full-replay-complete"
    ):
        raise ValueError("AFD isolated replay result marker mismatch")
    return _sha(result["artifact_sha256"], "isolated artifact")


def _capture_isolated_process(process: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
    if process.stdout is None or process.stderr is None:
        raise ValueError("AFD isolated replay pipes are unavailable")
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    selector = selectors.DefaultSelector()
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + ISOLATED_REPLAY_TIMEOUT_SECONDS
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_isolated_process_group(process)
                raise ValueError("AFD isolated full replay exceeded its exact total timeout")
            for key, _events in selector.select(min(remaining, 0.25)):
                stream = cast(Any, key.fileobj)
                chunk = os.read(stream.fileno(), 8192)
                if not chunk:
                    selector.unregister(stream)
                    continue
                streams[stream].extend(chunk)
                if len(streams[stream]) > ISOLATED_REPLAY_OUTPUT_LIMIT:
                    _kill_isolated_process_group(process)
                    raise ValueError("AFD isolated replay output exceeded its bound")
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            _kill_isolated_process_group(process)
            raise ValueError("AFD isolated full replay exceeded its exact total timeout") from exc
        return bytes(streams[process.stdout]), bytes(streams[process.stderr])
    finally:
        selector.close()


def _kill_isolated_process_group(process: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=ISOLATED_REPLAY_KILL_WAIT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise ValueError("AFD isolated replay process group did not terminate") from exc


def _require_replay_sha(expected: object, observed: object) -> None:
    if _sha(expected, "expected replay artifact") != _sha(
        observed, "observed replay artifact"
    ):
        raise ValueError("AFD isolated replay artifact SHA-256 mismatch")


def _snapshot_semantics_bundle(source_fd: int, destination_fd: int) -> None:
    for name, limit in (("receipt.json", 1024 * 1024), ("semantics.json", 128 * 1024 * 1024)):
        _snapshot_file_from_dirfd(
            source_fd, name, destination_fd, name, "AFD semantics retained file", limit
        )
    source_hypotheses_fd = os.open(
        "hypotheses", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source_fd
    )
    os.mkdir("hypotheses", 0o700, dir_fd=destination_fd)
    destination_hypotheses_fd = os.open(
        "hypotheses", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=destination_fd
    )
    try:
        _snapshot_hypotheses_bundle(source_hypotheses_fd, destination_hypotheses_fd)
    finally:
        os.close(destination_hypotheses_fd)
        os.close(source_hypotheses_fd)


def _side(raw: object, hypotheses: dict[str, object], side: str) -> dict[str, object]:
    value = _obj(json.loads(json.dumps(raw)), side)
    _exact(
        value,
        {
            "side",
            "driver_sha256",
            "pdb_sha256",
            "image_base",
            "architecture",
            "tool",
            "functions",
            "accounting",
        },
        side,
    )
    if value["side"] != side or value["architecture"] != "x86_64":
        raise ValueError("AFD semantic side identity mismatch")
    expected_side = _obj(_obj(hypotheses["sides"], "hypotheses sides")[side], side)
    if (
        value["driver_sha256"] != expected_side["driver_sha256"]
        or value["pdb_sha256"] != expected_side["pdb_sha256"]
    ):
        raise ValueError("AFD semantic side artifact commitment mismatch")
    _hex(value["image_base"], f"{side} image base")
    functions = value["functions"]
    plans = hypotheses["hypotheses"]
    if not isinstance(functions, list) or len(functions) != 33 or not isinstance(plans, list):
        raise ValueError("AFD semantic side function extent mismatch")
    for index, (function, plan) in enumerate(zip(functions, plans, strict=True), 1):
        _function(_obj(function, f"{side} function {index}"), _obj(plan, "hypothesis plan"), side)
    accounting = _obj(value["accounting"], f"{side} accounting")
    _exact(
        accounting,
        {
            "functions_requested",
            "functions_observed",
            "body_bytes_total",
            "instructions_total",
            "limits_hit",
        },
        f"{side} accounting",
    )
    if (
        accounting.get("functions_requested") != 33
        or accounting.get("functions_observed") != 33
        or accounting.get("limits_hit") != []
        or type(accounting.get("body_bytes_total")) is not int
        or type(accounting.get("instructions_total")) is not int
        or not 0 < accounting["body_bytes_total"] <= ghidra_extractor.MAX_TOTAL_BODY_BYTES
        or not 0 < accounting["instructions_total"] <= ghidra_extractor.MAX_TOTAL_INSTRUCTIONS
    ):
        raise ValueError("AFD semantic side accounting mismatch")
    value["evidence_id"] = _domain_hash(
        "0verse-afd-native-side-v1", value
    )
    return cast(dict[str, object], value)


def _function(value: dict[str, Any], plan: dict[str, Any], side: str) -> None:
    _exact(
        value,
        {
            "hypothesis_id",
            "row_indices",
            "ioctl_keys",
            "entry_rva",
            "exact_plan_entry_observed",
            "executable",
            "non_thunk",
            "body",
            "instructions",
            "instruction_count",
            "inherited_limits",
        },
        "AFD semantic function",
    )
    if (
        value["hypothesis_id"] != plan["hypothesis_id"]
        or value["row_indices"] != plan["row_indices"]
        or value["ioctl_keys"] != plan["ioctl_keys"]
        or value["entry_rva"] != plan[f"{side}_target_rva"]
        or value["exact_plan_entry_observed"] is not True
        or value["executable"] is not True
        or value["non_thunk"] is not True
    ):
        raise ValueError("AFD semantic function/plan binding mismatch")
    body = _obj(value["body"], "AFD function body")
    _exact(
        body,
        {
            "ranges", "gaps", "range_count", "addressed_size", "addressed_sha256",
            "disjoint_ranges_preserved", "complete_ghidra_address_set_captured",
        },
        "AFD function body",
    )
    ranges = body.get("ranges")
    if (
        not isinstance(ranges, list)
        or not ranges
        or type(body.get("range_count")) is not int
        or body.get("range_count") != len(ranges)
        or type(body.get("addressed_size")) is not int
        or body.get("disjoint_ranges_preserved") is not True
        or body.get("complete_ghidra_address_set_captured") is not True
    ):
        raise ValueError("AFD function body extent mismatch")
    digest = hashlib.sha256(b"0verse-afd-function-body-ranges-v1\0")
    total = 0
    previous_end = -1
    for raw_range in ranges:
        row = _obj(raw_range, "AFD function body range")
        _exact(
            row,
            {
                "start_rva", "size", "bytes", "sha256", "executable",
                "uncovered_byte_intervals",
            },
            "body range",
        )
        start = _hex(row["start_rva"], "body range start")
        size = row["size"]
        if type(size) is not int or not 1 <= size <= 65536:
            raise ValueError("AFD body range size mismatch")
        encoded = bytes.fromhex(row["bytes"])
        if (
            start <= previous_end
            or len(encoded) != size
            or hashlib.sha256(encoded).hexdigest() != row["sha256"]
            or row["executable"] is not True
        ):
            raise ValueError("AFD body range bytes/order mismatch")
        digest.update(start.to_bytes(8, "little"))
        digest.update(size.to_bytes(8, "little"))
        digest.update(encoded)
        total += size
        previous_end = start + size - 1
    if body.get("addressed_size") != total or body.get("addressed_sha256") != digest.hexdigest():
        raise ValueError("AFD body aggregate commitment mismatch")
    expected_gaps = []
    for left, right in pairwise(ranges):
        left_end = _hex(left["start_rva"], "body range start") + left["size"]
        right_start = _hex(right["start_rva"], "body range start")
        expected_gaps.append({"start_rva": f"0x{left_end:x}", "size": right_start - left_end})
    if body["gaps"] != expected_gaps:
        raise ValueError("AFD body gap accounting mismatch")
    for gap in body["gaps"]:
        gap_row = _obj(gap, "AFD body gap")
        _exact(gap_row, {"start_rva", "size"}, "AFD body gap")
        _hex(gap_row["start_rva"], "body gap start")
        if type(gap_row["size"]) is not int or gap_row["size"] <= 0:
            raise ValueError("AFD body gap size mismatch")
    plan_limits = _obj(plan["static_limits"], "hypothesis static limits")
    if total > plan_limits["max_function_bytes_per_side"]:
        raise ValueError("AFD body exceeds inherited limit")
    instructions = value["instructions"]
    if (
        not isinstance(instructions, list)
        or type(value["instruction_count"]) is not int
        or value["instruction_count"] != len(instructions)
        or not instructions
    ):
        raise ValueError("AFD native instruction extent mismatch")
    previous_instruction = -1
    coverage: dict[int, list[tuple[int, int]]] = {index: [] for index in range(len(ranges))}
    for raw_instruction in instructions:
        instruction = _obj(raw_instruction, "native instruction")
        _exact(
            instruction,
            {"rva", "bytes", "sha256", "mnemonic", "operands"},
            "native instruction",
        )
        encoded = bytes.fromhex(instruction["bytes"])
        instruction_rva = _hex(instruction["rva"], "native instruction RVA")
        if (
            not encoded
            or hashlib.sha256(encoded).hexdigest() != instruction["sha256"]
            or not isinstance(instruction["mnemonic"], str)
            or not instruction["mnemonic"]
            or not isinstance(instruction["operands"], str)
            or not instruction["operands"]
        ):
            raise ValueError("AFD native instruction commitment mismatch")
        matching_ranges = [
            row
            for row in ranges
            if _hex(row["start_rva"], "body range start") <= instruction_rva
            and instruction_rva + len(encoded)
            <= _hex(row["start_rva"], "body range start") + row["size"]
        ]
        if instruction_rva <= previous_instruction or len(matching_ranges) != 1:
            raise ValueError("AFD native instruction order/extent mismatch")
        body_range = matching_ranges[0]
        body_range_index = ranges.index(body_range)
        coverage[body_range_index].append((instruction_rva, instruction_rva + len(encoded)))
        offset = instruction_rva - _hex(body_range["start_rva"], "body range start")
        if bytes.fromhex(body_range["bytes"])[offset : offset + len(encoded)] != encoded:
            expected = bytes.fromhex(body_range["bytes"])[offset : offset + len(encoded)]
            raise ValueError(
                "AFD native instruction/body byte mismatch: "
                f"side={side} hypothesis={value['hypothesis_id']} "
                f"entry={value['entry_rva']} instruction={instruction['rva']} "
                f"expected={expected.hex()} observed={encoded.hex()}"
            )
        previous_instruction = instruction_rva + len(encoded) - 1
    if _hex(instructions[0]["rva"], "first instruction RVA") != _hex(
        value["entry_rva"], "plan entry RVA"
    ):
        raise ValueError("AFD first native instruction does not match the exact plan entry")
    for index, body_range in enumerate(ranges):
        start = _hex(body_range["start_rva"], "body range start")
        end = start + body_range["size"]
        cursor = start
        expected_uncovered = []
        for instruction_start, instruction_end in coverage[index]:
            if instruction_start > cursor:
                expected_uncovered.append(
                    {"start_rva": f"0x{cursor:x}", "size": instruction_start - cursor}
                )
            cursor = instruction_end
        if cursor < end:
            expected_uncovered.append({"start_rva": f"0x{cursor:x}", "size": end - cursor})
        if body_range["uncovered_byte_intervals"] != expected_uncovered:
            raise ValueError("AFD uncovered byte interval recomputation mismatch")
        for interval in body_range["uncovered_byte_intervals"]:
            interval_row = _obj(interval, "uncovered byte interval")
            if (
                set(interval_row) != {"start_rva", "size"}
                or type(interval_row["size"]) is not int
                or interval_row["size"] <= 0
            ):
                raise ValueError("AFD uncovered byte interval mismatch")
    if len(instructions) > plan_limits["max_instructions_per_side"]:
        raise ValueError("AFD instructions exceed inherited limit")
    limits = _obj(value["inherited_limits"], "AFD inherited limits")
    if limits != {
        "max_function_bytes_per_side": plan_limits["max_function_bytes_per_side"],
        "max_instructions_per_side": plan_limits["max_instructions_per_side"],
        "max_wall_clock_seconds_per_side": plan_limits["max_wall_clock_seconds_per_side"],
    }:
        raise ValueError("AFD inherited limits mismatch")


def _validate(raw: object) -> dict[str, object]:
    value = _obj(json.loads(json.dumps(raw)), "AFD handler semantics")
    fields = {
        "schema_version",
        "producer",
        "extractor_config_sha256",
        "extractor_script_sha256",
        "hypotheses_commitment",
        "sides",
        "pair_count",
        "pairs",
        "side_local_exact_function_identity_established",
        "ghidra_function_body_extent_complete",
        "exact_plan_entry_observed",
        "complete_ghidra_address_set_captured",
        "function_local_cfg_complete",
        "function_local_high_pcode_complete",
        "cross_build_handler_identity_established",
        "handler_body_change_established",
        "semantic_difference_established",
        "source_sink_semantics_established",
        "guard_delta_established",
        "call_graph_complete",
        "ranking_performed",
        "candidate_count",
        "candidate_established",
        "labels_consumed",
        "ground_truth_consumed",
        "model_invocations",
        "network_performed",
        "driver_load_attempts",
        "device_open_attempts",
        "device_ioctl_attempts",
        "runtime_attempts",
        "runtime_consumable",
        "execution_authorized",
        "runtime_reachability_established",
        "unprivileged_reachability_established",
        "vulnerability_established",
        "lpe_established",
        "exploitability_established",
        "novelty_established",
        "claim_eligible",
        "bounty_eligible",
        "weaponization",
        "automatic_disclosure",
        "human_promotion_gate",
        "proof_limit",
    }
    _exact(value, fields, "AFD handler semantics")
    if (
        value["schema_version"] != EXPORT_VERSION
        or value["producer"] != PRODUCER
        or value["extractor_config_sha256"] != CONFIG_SHA256
        or value["proof_limit"] != _PROOF_LIMIT
        or type(value["pair_count"]) is not int
        or value["pair_count"] != 33
        or any(
            type(value[name]) is not int or value[name] != 0
            for name in (
                "candidate_count", "model_invocations", "driver_load_attempts",
                "device_open_attempts", "device_ioctl_attempts", "runtime_attempts",
            )
        )
        or value["human_promotion_gate"] is not True
    ):
        raise ValueError("AFD handler semantics contract mismatch")
    true_fields = {
        "exact_plan_entry_observed",
        "complete_ghidra_address_set_captured",
        "human_promotion_gate",
    }
    false_fields = (
        fields
        - true_fields
        - {
            "schema_version",
            "producer",
            "extractor_config_sha256",
            "extractor_script_sha256",
            "hypotheses_commitment",
            "sides",
            "pair_count",
            "pairs",
            "candidate_count",
            "model_invocations",
            "driver_load_attempts",
            "device_open_attempts",
            "device_ioctl_attempts",
            "runtime_attempts",
            "proof_limit",
        }
    )
    if any(value[name] is not True for name in true_fields) or any(
        value[name] is not False for name in false_fields
    ):
        raise ValueError("AFD handler semantics claim boundary mismatch")
    _sha(value["extractor_script_sha256"], "extractor script")
    commitment = _obj(value["hypotheses_commitment"], "hypotheses commitment")
    if (
        set(commitment) != {"path", "schema_version", "artifact_sha256", "receipt_sha256"}
        or commitment["path"] != "hypotheses"
        or commitment["schema_version"] != HYPOTHESES_VERSION
    ):
        raise ValueError("AFD hypotheses commitment mismatch")
    _sha(commitment["artifact_sha256"], "hypotheses artifact")
    _sha(commitment["receipt_sha256"], "hypotheses receipt")
    sides = _obj(value["sides"], "AFD native evidence sides")
    _exact(sides, {"side_a", "side_b"}, "AFD native evidence sides")
    side_values: dict[str, dict[str, Any]] = {}
    for side_name in ("side_a", "side_b"):
        side_value = _obj(sides[side_name], f"{side_name} native evidence")
        material = dict(side_value)
        evidence_id = _sha(material.pop("evidence_id", None), f"{side_name} evidence ID")
        if evidence_id != _domain_hash("0verse-afd-native-side-v1", material):
            raise ValueError("AFD native side evidence identity mismatch")
        _exact(
            material,
            {
                "side", "driver_sha256", "pdb_sha256", "image_base", "architecture",
                "tool", "functions", "accounting",
            },
            f"{side_name} native evidence",
        )
        if material["side"] != side_name or material["architecture"] != "x86_64":
            raise ValueError("AFD native side identity mismatch")
        _sha(material["driver_sha256"], "driver")
        _sha(material["pdb_sha256"], "PDB")
        _hex(material["image_base"], "image base")
        functions = material["functions"]
        if not isinstance(functions, list) or len(functions) != 33:
            raise ValueError("AFD native side function extent mismatch")
        accounting = _obj(material["accounting"], "native accounting")
        expected_bytes = sum(
            _obj(_obj(item, "function")["body"], "body")["addressed_size"]
            for item in functions
        )
        expected_instructions = sum(
            _obj(item, "function")["instruction_count"] for item in functions
        )
        if (
            type(accounting.get("functions_requested")) is not int
            or accounting.get("functions_requested") != 33
            or type(accounting.get("functions_observed")) is not int
            or accounting.get("functions_observed") != 33
            or type(accounting.get("body_bytes_total")) is not int
            or accounting.get("body_bytes_total") != expected_bytes
            or type(accounting.get("instructions_total")) is not int
            or accounting.get("instructions_total") != expected_instructions
            or accounting.get("limits_hit") != []
        ):
            raise ValueError("AFD native accounting recomputation mismatch")
        side_values[side_name] = side_value
    pairs = value["pairs"]
    if not isinstance(pairs, list) or len(pairs) != 33:
        raise ValueError("AFD semantic pair extent mismatch")
    for order, raw_pair in enumerate(pairs, 1):
        pair = _obj(raw_pair, "AFD semantic pair")
        _exact(
            pair,
            {
                "enumeration_order",
                "pair_id",
                "hypothesis_id",
                "row_indices",
                "ioctl_keys",
                "side_a_entry_rva",
                "side_b_entry_rva",
                "native_body_hashes_equal",
                "native_instruction_hashes_equal",
                "factual_hash_comparison_only",
            },
            "semantic pair",
        )
        if (
            pair["enumeration_order"] != order
            or type(pair["enumeration_order"]) is not int
            or pair["factual_hash_comparison_only"] is not True
            or any(
                type(pair[name]) is not bool
                for name in (
                    "native_body_hashes_equal",
                    "native_instruction_hashes_equal",
                )
            )
        ):
            raise ValueError("AFD semantic pair comparison mismatch")
        left = _obj(side_values["side_a"]["functions"][order - 1], "side A function")
        right = _obj(side_values["side_b"]["functions"][order - 1], "side B function")
        plan = {
            "hypothesis_id": pair["hypothesis_id"],
            "row_indices": pair["row_indices"],
            "ioctl_keys": pair["ioctl_keys"],
            "side_a_target_rva": pair["side_a_entry_rva"],
            "side_b_target_rva": pair["side_b_entry_rva"],
            "static_limits": {
                "max_function_bytes_per_side": 65536,
            "max_instructions_per_side": 20000,
                "max_wall_clock_seconds_per_side": 300,
            },
        }
        _function(left, plan, "side_a")
        _function(right, plan, "side_b")
        expected_pair = {
            "enumeration_order": order,
            "hypothesis_id": left["hypothesis_id"],
            "row_indices": left["row_indices"],
            "ioctl_keys": left["ioctl_keys"],
            "side_a_entry_rva": left["entry_rva"],
            "side_b_entry_rva": right["entry_rva"],
            "native_body_hashes_equal": (
                left["body"]["addressed_sha256"] == right["body"]["addressed_sha256"]
            ),
            "native_instruction_hashes_equal": (
                _canonical_hash(left["instructions"])
                == _canonical_hash(right["instructions"])
            ),
            "factual_hash_comparison_only": True,
        }
        expected_pair["pair_id"] = _domain_hash(
            "0verse-afd-native-pair-v1",
            {
                "side_a_evidence_id": side_values["side_a"]["evidence_id"],
                "side_b_evidence_id": side_values["side_b"]["evidence_id"],
                "hypotheses_artifact_sha256": commitment["artifact_sha256"],
                "hypotheses_receipt_sha256": commitment["receipt_sha256"],
                "pair": expected_pair,
            },
        )
        if pair != expected_pair:
            raise ValueError("AFD native pair comparison recomputation mismatch")
    return cast(dict[str, object], json.loads(json.dumps(value, sort_keys=True)))


def _validate_receipt(
    receipt: dict[str, Any], toolchain: dict[str, object], script_sha: str
) -> None:
    _exact(
        receipt,
        {
            "schema_version",
            "producer",
            "semantics_path",
            "semantics_sha256",
            "hypotheses_bundle",
            "hypotheses_receipt_sha256",
            "extractor_config_sha256",
            "extractor_script_sha256",
            "toolchain",
            "isolated_replay_timeout_seconds",
            "isolated_replay_kill_wait_seconds",
            "static_only",
            "execution_authorized",
            "device_ioctl_attempts",
        },
        "AFD semantics receipt",
    )
    if (
        receipt["schema_version"] != RECEIPT_VERSION
        or receipt["producer"] != PRODUCER
        or receipt["semantics_path"] != "semantics.json"
        or receipt["hypotheses_bundle"] != "hypotheses"
        or receipt["extractor_config_sha256"] != CONFIG_SHA256
        or receipt["extractor_script_sha256"] != script_sha
        or receipt["toolchain"] != toolchain
        or type(receipt["isolated_replay_timeout_seconds"]) is not int
        or receipt["isolated_replay_timeout_seconds"] != ISOLATED_REPLAY_TIMEOUT_SECONDS
        or type(receipt["isolated_replay_kill_wait_seconds"]) is not int
        or receipt["isolated_replay_kill_wait_seconds"] != ISOLATED_REPLAY_KILL_WAIT_SECONDS
        or receipt["static_only"] is not True
        or receipt["execution_authorized"] is not False
        or type(receipt["device_ioctl_attempts"]) is not int
        or receipt["device_ioctl_attempts"] != 0
    ):
        raise ValueError("AFD semantics receipt contract mismatch")


def _extractor_script_sha256() -> str:
    digest = hashlib.sha256(b"0verse-afd-handler-semantics-scripts-v1\0")
    for path in sorted(
        (
            Path(__file__),
            Path(ghidra_extractor.__file__ or ""),
            Path(__file__).with_name("windows_afd_handler_semantics_replay.py"),
        ),
        key=lambda item: item.name,
    ):
        raw = path.read_bytes()
        digest.update(path.name.encode())
        digest.update(len(raw).to_bytes(8, "little"))
        digest.update(raw)
    return digest.hexdigest()


def _require_extractor_pins(
    home: Path, script_sha256: object, toolchain: object
) -> None:
    if (
        _extractor_script_sha256() != script_sha256
        or _toolchain_fingerprint(home) != toolchain
    ):
        raise ValueError("AFD extractor script or toolchain changed during analysis")


def _json_file(path: Path, label: str) -> dict[str, Any]:
    parent_fd = _open_directory_ancestry(path.parent, f"{label} parent")
    try:
        return _obj(
            json.loads(
                _read_regular_file_at(parent_fd, path.name, label, 1024 * 1024),
                object_pairs_hook=_unique,
            ),
            label,
        )
    finally:
        os.close(parent_fd)


def _sha_file(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 64 * 1024):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _canonical(raw: object) -> bytes:
    return json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()


def _canonical_hash(raw: object) -> str:
    return hashlib.sha256(_canonical(raw)).hexdigest()


def _domain_hash(domain: str, raw: object) -> str:
    digest = hashlib.sha256(domain.encode() + b"\0")
    encoded = _canonical(raw)
    digest.update(len(encoded).to_bytes(8, "little"))
    digest.update(encoded)
    return digest.hexdigest()

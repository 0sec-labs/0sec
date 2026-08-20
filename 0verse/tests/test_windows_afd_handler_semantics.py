from __future__ import annotations

import hashlib
import importlib.util
import os
import socket
from pathlib import Path
from types import ModuleType

import pytest

import zeroverse.windows_afd_handler_semantics as semantics
import zeroverse.windows_afd_handler_semantics_ghidra as ghidra


def _hypotheses_support() -> ModuleType:
    path = Path(__file__).with_name("test_windows_afd_hypotheses.py")
    spec = importlib.util.spec_from_file_location("_hypotheses_support", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _inputs() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    hypotheses = _hypotheses_support()._compile()

    def side_facts(side: str) -> dict[str, object]:
        side_commitment = hypotheses["sides"][side]
        functions = []
        total_bytes = 0
        for plan in hypotheses["hypotheses"]:
            entry = plan[f"{side}_target_rva"]
            body = bytes.fromhex("90c3")
            functions.append(
                {
                    "hypothesis_id": plan["hypothesis_id"],
                    "row_indices": plan["row_indices"],
                    "ioctl_keys": plan["ioctl_keys"],
                    "entry_rva": entry,
                    "exact_plan_entry_observed": True,
                    "executable": True,
                    "non_thunk": True,
                    "body": {
                        "ranges": [{
                            "start_rva": entry,
                            "size": len(body),
                            "bytes": body.hex(),
                            "sha256": hashlib.sha256(body).hexdigest(),
                            "executable": True,
                            "uncovered_byte_intervals": [],
                        }],
                        "gaps": [],
                        "range_count": 1,
                        "addressed_size": len(body),
                        "addressed_sha256": _body_hash(int(entry, 16), body),
                        "disjoint_ranges_preserved": True,
                        "complete_ghidra_address_set_captured": True,
                    },
                    "instructions": [{
                        "rva": entry,
                        "bytes": body.hex(),
                        "sha256": hashlib.sha256(body).hexdigest(),
                        "mnemonic": "NOP_RET",
                        "operands": "NOP_RET",
                    }],
                    "instruction_count": 1,
                    "inherited_limits": {
                        "max_function_bytes_per_side": 65536,
                        "max_instructions_per_side": 20000,
                        "max_wall_clock_seconds_per_side": 300,
                    },
                }
            )
            total_bytes += len(body)
        return {
            "side": side,
            "driver_sha256": side_commitment["driver_sha256"],
            "pdb_sha256": side_commitment["pdb_sha256"],
            "image_base": "0x140000000",
            "architecture": "x86_64",
            "tool": {"name": "ghidra", "version": "test"},
            "functions": functions,
            "accounting": {
                "functions_requested": 33,
                "functions_observed": 33,
                "body_bytes_total": total_bytes,
                "instructions_total": 33,
                "limits_hit": [],
            },
        }

    return hypotheses, side_facts("side_a"), side_facts("side_b")


def _body_hash(rva: int, body: bytes) -> str:
    digest = hashlib.sha256(b"0verse-afd-function-body-ranges-v1\0")
    digest.update(rva.to_bytes(8, "little"))
    digest.update(len(body).to_bytes(8, "little"))
    digest.update(body)
    return digest.hexdigest()


def _compile() -> dict[str, object]:
    hypotheses, side_a, side_b = _inputs()
    return semantics.compile_windows_afd_handler_semantics(
        hypotheses,
        side_a,
        side_b,
        hypotheses_receipt_sha256="a" * 64,
        extractor_script_sha256="b" * 64,
    )


def _refresh_ids(raw: dict[str, object]) -> None:
    sides = raw["sides"]
    for side in ("side_a", "side_b"):
        material = dict(sides[side])
        material.pop("evidence_id")
        sides[side]["evidence_id"] = semantics._domain_hash(
            "0verse-afd-native-side-v1", material
        )
    commitment = raw["hypotheses_commitment"]
    for pair in raw["pairs"]:
        material = dict(pair)
        material.pop("pair_id")
        pair["pair_id"] = semantics._domain_hash(
            "0verse-afd-native-pair-v1",
            {
                "side_a_evidence_id": sides["side_a"]["evidence_id"],
                "side_b_evidence_id": sides["side_b"]["evidence_id"],
                "hypotheses_artifact_sha256": commitment["artifact_sha256"],
                "hypotheses_receipt_sha256": commitment["receipt_sha256"],
                "pair": material,
            },
        )


def test_compiler_emits_exact_native_only_zero_candidate_evidence() -> None:
    result = _compile()
    assert result["pair_count"] == 33
    assert result["candidate_count"] == 0
    assert result["function_local_cfg_complete"] is False
    assert result["function_local_high_pcode_complete"] is False
    assert result["exact_plan_entry_observed"] is True
    assert result["complete_ghidra_address_set_captured"] is True
    assert result["side_local_exact_function_identity_established"] is False
    assert result["device_ioctl_attempts"] == 0
    assert result["runtime_consumable"] is False
    assert all("cfg" not in row for row in result["sides"]["side_a"]["functions"])


@pytest.mark.parametrize("forged", [False, 33.0, -1, 34])
def test_pair_count_rejects_non_exact_integer(forged: object) -> None:
    raw = _compile()
    raw["pair_count"] = forged
    with pytest.raises(ValueError, match="contract"):
        semantics.canonical_handler_semantics_bytes(raw)


def test_validator_recomputes_body_instruction_and_pair_commitments() -> None:
    raw = _compile()
    raw["sides"]["side_a"]["functions"][0]["instructions"][0]["bytes"] = "cc"
    with pytest.raises(ValueError):
        semantics.canonical_handler_semantics_bytes(raw)

    raw = _compile()
    raw["pairs"][0]["native_body_hashes_equal"] = True
    with pytest.raises(ValueError, match="recomputation"):
        semantics.canonical_handler_semantics_bytes(raw)


def test_validator_rejects_bool_as_int_accounting() -> None:
    raw = _compile()
    raw["sides"]["side_a"]["accounting"]["instructions_total"] = True
    with pytest.raises(ValueError, match=r"identity|accounting"):
        semantics.canonical_handler_semantics_bytes(raw)


def test_receipt_rejects_bool_as_zero() -> None:
    receipt = {
        "schema_version": semantics.RECEIPT_VERSION,
        "producer": semantics.PRODUCER,
        "semantics_path": "semantics.json",
        "semantics_sha256": "1" * 64,
        "hypotheses_bundle": "hypotheses",
        "hypotheses_receipt_sha256": "2" * 64,
        "extractor_config_sha256": semantics.CONFIG_SHA256,
        "extractor_script_sha256": "3" * 64,
        "toolchain": {"x": "y"},
        "isolated_replay_timeout_seconds": semantics.ISOLATED_REPLAY_TIMEOUT_SECONDS,
        "isolated_replay_kill_wait_seconds": semantics.ISOLATED_REPLAY_KILL_WAIT_SECONDS,
        "static_only": True,
        "execution_authorized": False,
        "device_ioctl_attempts": False,
    }
    with pytest.raises(ValueError, match="receipt contract"):
        semantics._validate_receipt(receipt, {"x": "y"}, "3" * 64)


def test_side_evidence_id_rejects_tamper() -> None:
    raw = _compile()
    raw["sides"]["side_a"]["image_base"] = "0x150000000"
    with pytest.raises(ValueError, match="identity"):
        semantics.canonical_handler_semantics_bytes(raw)


@pytest.mark.parametrize(
    "field",
    ["range_count", "addressed_size"],
)
def test_nested_body_counts_reject_bool_as_int(field: str) -> None:
    raw = _compile()
    raw["sides"]["side_a"]["functions"][0]["body"][field] = True
    _refresh_ids(raw)
    with pytest.raises(ValueError, match=r"extent|accounting"):
        semantics.canonical_handler_semantics_bytes(raw)


def test_nested_instruction_count_rejects_bool_as_int() -> None:
    raw = _compile()
    raw["sides"]["side_a"]["functions"][0]["instruction_count"] = True
    _refresh_ids(raw)
    with pytest.raises(ValueError, match="instruction extent"):
        semantics.canonical_handler_semantics_bytes(raw)


def test_uncovered_intervals_and_enumeration_fail_closed() -> None:
    raw = _compile()
    raw["sides"]["side_a"]["functions"][0]["body"]["ranges"][0][
        "uncovered_byte_intervals"
    ] = [{"start_rva": raw["pairs"][0]["side_a_entry_rva"], "size": True}]
    _refresh_ids(raw)
    with pytest.raises(ValueError, match="uncovered"):
        semantics.canonical_handler_semantics_bytes(raw)

    raw = _compile()
    raw["pairs"][0]["enumeration_order"] = True
    with pytest.raises(ValueError, match="comparison"):
        semantics.canonical_handler_semantics_bytes(raw)


def test_pair_id_binds_both_hypotheses_commitments() -> None:
    for field in ("artifact_sha256", "receipt_sha256"):
        raw = _compile()
        raw["hypotheses_commitment"][field] = "f" * 64
        with pytest.raises(ValueError, match="recomputation"):
            semantics.canonical_handler_semantics_bytes(raw)


def test_monotonic_wall_cap_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ghidra.time, "monotonic", lambda: 301.0)
    with pytest.raises(ValueError, match="wall-clock cap"):
        ghidra._require_elapsed_within(0.0, 300)


def test_extractor_pin_change_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(semantics, "_extractor_script_sha256", lambda: "a" * 64)
    monkeypatch.setattr(semantics, "_toolchain_fingerprint", lambda _home: {"v": "1"})
    semantics._require_extractor_pins(Path("/ghidra"), "a" * 64, {"v": "1"})
    with pytest.raises(ValueError, match="changed during analysis"):
        semantics._require_extractor_pins(Path("/ghidra"), "b" * 64, {"v": "1"})


def test_isolated_replay_timeout_kills_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Process:
        returncode = None

    process = Process()
    monkeypatch.setattr(semantics.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(
        semantics,
        "_capture_isolated_process",
        lambda _process: (_ for _ in ()).throw(ValueError("exact total timeout")),
    )
    with pytest.raises(ValueError, match="exact total timeout"):
        semantics._verify_semantics_bundle_isolated(Path("/bundle"), Path("/ghidra"))


def test_isolated_replay_failure_is_bounded_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Process:
        returncode = 7

        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

    monkeypatch.setattr(semantics.subprocess, "Popen", Process)
    monkeypatch.setattr(
        semantics,
        "_capture_isolated_process",
        lambda _process: (b"0VERSE_AFD_ISOLATED_PHASE=full-replay-start\n", b"child failed"),
    )
    with pytest.raises(ValueError, match="child failed"):
        semantics._verify_semantics_bundle_isolated(Path("/bundle"), Path("/ghidra"))


def test_isolated_replay_hash_mismatch_fails_closed() -> None:
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        semantics._require_replay_sha("a" * 64, "b" * 64)


def test_process_group_kill_wait_failure_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Process:
        pid = 123

        def wait(self, timeout: int | None = None) -> int:
            raise semantics.subprocess.TimeoutExpired("replay", timeout)

    monkeypatch.setattr(semantics.os, "killpg", lambda pid, sig: None)
    with pytest.raises(ValueError, match="did not terminate"):
        semantics._kill_isolated_process_group(Process())


def test_output_overflow_kills_process_group(monkeypatch: pytest.MonkeyPatch) -> None:
    stdout_read, stdout_write = socket.socketpair()
    stderr_read, stderr_write = socket.socketpair()
    monkeypatch.setattr(semantics, "ISOLATED_REPLAY_OUTPUT_LIMIT", 1024)
    stdout_write.sendall(b"x" * 1025)
    stdout_write.shutdown(socket.SHUT_WR)
    stderr_write.shutdown(socket.SHUT_WR)

    class Process:
        stdout = stdout_read
        stderr = stderr_read

    killed = []
    monkeypatch.setattr(
        semantics, "_kill_isolated_process_group", lambda process: killed.append(process)
    )
    try:
        with pytest.raises(ValueError, match="output exceeded"):
            semantics._capture_isolated_process(Process())
        assert killed
    finally:
        for stream in (stdout_read, stdout_write, stderr_read, stderr_write):
            stream.close()


def test_isolated_bootstrap_ignores_shadow_modules(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    class Process:
        returncode = 0

        def __init__(self, command: list[str], **kwargs: object) -> None:
            captured.update({"command": command, **kwargs})

    marker = {
        "schema_version": "0verse.windows-afd-isolated-replay-result/v1",
        "phase": "full-replay-complete",
        "artifact_sha256": "a" * 64,
    }
    monkeypatch.setattr(semantics.subprocess, "Popen", Process)
    monkeypatch.setattr(
        semantics,
        "_capture_isolated_process",
        lambda _process: (
            b"0VERSE_AFD_ISOLATED_PHASE=full-replay-start\n"
            + b"0VERSE_AFD_ISOLATED_RESULT="
            + semantics.json.dumps(marker).encode()
            + b"\n",
            b"",
        ),
    )
    assert semantics._verify_semantics_bundle_isolated(Path("/bundle"), Path("/ghidra")) == "a" * 64
    assert captured["command"][1:3] == ["-I", "-c"]
    assert captured["cwd"] == "/"
    assert "PYTHONPATH" not in captured["env"]
    assert captured["start_new_session"] is True


def test_replay_module_mutation_changes_script_manifest(monkeypatch: pytest.MonkeyPatch) -> None:
    original = semantics._extractor_script_sha256()
    replay = Path(semantics.__file__).with_name("windows_afd_handler_semantics_replay.py")
    read_bytes = Path.read_bytes

    def mutated(path: Path) -> bytes:
        raw = read_bytes(path)
        return raw + b"mutation" if path == replay else raw

    monkeypatch.setattr(Path, "read_bytes", mutated)
    assert semantics._extractor_script_sha256() != original


def test_public_verifier_checks_parent_pins_after_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    artifact = _compile()
    expected = hashlib.sha256(semantics.canonical_handler_semantics_bytes(artifact)).hexdigest()
    receipt = {"extractor_script_sha256": "a" * 64, "toolchain": {"v": "1"}}
    phases = []
    monkeypatch.setattr(semantics, "_snapshot_semantics_bundle", lambda source_fd, dest_fd: None)
    monkeypatch.setattr(
        semantics,
        "_read_retained_semantics_artifact",
        lambda retained, home: (phases.append("parent-pre") or artifact, receipt),
    )

    def isolated(retained: Path, home: Path) -> str:
        assert phases == ["parent-pre"]
        phases.append("child")
        return expected

    monkeypatch.setattr(semantics, "_verify_semantics_bundle_isolated", isolated)
    monkeypatch.setattr(
        semantics,
        "_require_extractor_pins",
        lambda home, script, toolchain: phases.append("parent-post"),
    )
    semantics.verify_windows_afd_handler_semantics_bundle(source, ghidra_home="/ghidra")
    assert phases == ["parent-pre", "child", "parent-post"]


def test_publication_staging_substitution_fails_closed(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    staging_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        staging.rename(tmp_path / "held-staging")
        staging.mkdir()
        with pytest.raises(ValueError, match="changed"):
            semantics._require_directory_path_identity(
                staging, staging_fd, "AFD semantics publication staging"
            )
    finally:
        os.close(staging_fd)

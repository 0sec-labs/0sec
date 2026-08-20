"""Hermetic tests for the windows kernel oracle gate (no VM, fixtures only)."""

from __future__ import annotations

import hashlib as _hashlib
import json
from pathlib import Path

from zeroverse.adjudicate import CONFIRMED, DIVERGENT, NO_CRASH, UNRUNNABLE
from zeroverse.windows_kernel_oracle import (
    adjudicate_evidence_dir,
    adjudicate_kernel_crash,
    adjudicate_kernel_witness,
    adjudicate_trigger_witness,
    dump_identity_is_new,
    parse_cdb_kernel_analysis,
    parse_kd_witness_log,
    parse_trigger_jsonl,
    parse_trigger_witness_fields,
)

GOOD_SHA = "ab" * 32

# The canonical 0x38-byte NalMmapAddressEx input struct (cmd=57, phys=0x1000,
# len=0x1000, out-slot/flag zero) and its sha256 — the oracle's expected binding.

CANON_STRUCT_HEX = (
    "3900000000000000" + "00" * 16 + "00" * 8
    + "0010000000000000" + "00100000" + "00000000" + "00" * 8
)
CANON_SHA = _hashlib.sha256(bytes.fromhex(CANON_STRUCT_HEX)).hexdigest()

ANALYZE_50_MYFAULT = """\
Microsoft (R) Windows Debugger Version 10.0.26100.1 AMD64

BugCheck 50, {ffff878a01234000, 1, fffff8012ab01234, 2}

*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

PAGE_FAULT_IN_NONPAGED_AREA (50)
Invalid system memory was referenced.  This cannot be protected by try-except.
Arguments:
Arg1: ffff878a01234000, memory referenced.
Arg2: 0000000000000001, value 0 = read operation, 1 = write operation.
Arg3: fffff8012ab01234, If non-zero, the instruction address which referenced the bad memory
	address.

Debugging Details:
------------------

Attempt to write to address ffff878a01234000

MODULE_NAME: myfault64

FAULTING_MODULE: fffff80100000000 nt

IMAGE_NAME:  myfault64.sys

FAILURE_BUCKET_ID:  0x50_VRF_myfault64!unknown_function

STACK_TEXT:
ffffc30a`8b7e9000 fffff801`2ab01234 : 00000000`00000000 00000000`00000000 : myfault64+0x1234
ffffc30a`8b7e9040 fffff801`00001234 : 00000000`00000000 00000000`00000000 : nt!IofCallDriver+0x55
"""

ANALYZE_50_NT = ANALYZE_50_MYFAULT.replace(
    "MODULE_NAME: myfault64", "MODULE_NAME: nt"
).replace("IMAGE_NAME:  myfault64.sys", "IMAGE_NAME:  ntkrnlmp.exe")

ANALYZE_F4 = ANALYZE_50_MYFAULT.replace("BugCheck 50,", "BugCheck F4,")

KD_WITNESS_LOG = """\
Microsoft (R) Windows Debugger Version 10.0.26100.1 AMD64
Connected to Windows 10 26100 x64 target
0VERSE-KD-ARMED
0VERSE-WITNESS-BPS-BOUND
0 kD> g
0VERSE-WITNESS-OPERANDS
rcx=0000000000001000 rdx=0000000000001000
0VERSE-WITNESS-READBACK
00000000`00001000  00460056`4d454d52 00000000`00000000
00000000`00001010  00000000`01010600 00000000`00000000
00000000`00001020  00000000`00000000 00000000`00000000
00000000`00001030  00000000`00000000 00000000`00000000
fffff801`2ab09000  00460056`4d454d52 00000000`00000000
fffff801`2ab09010  00000000`01010600 00000000`00000000
fffff801`2ab09020  00000000`00000000 00000000`00000000
fffff801`2ab09030  00000000`00000000 00000000`00000000
0 kD> gc
"""

TRIGGER_WITNESS = (
    '0VERSE-TRIGGER-JSON:{"device":"\\\\\\\\.\\\\Nal","ioctl":"0x80862007",'
    f'"in_sha256":"{CANON_SHA}","in_len":56,"call_ok":true,"win32_error":0,'
    '"bytes_returned":0,"in_post_hex":"39000000000000000000000000000000'
    '00000000000000000080a663848affff001000000000000000100000000000000000000000000000",'
    '"out_sha256":"","out_post_hex":""}'
)

TRIGGER_CONTROL = TRIGGER_WITNESS.replace(GOOD_SHA, "cd" * 32)


def test_parse_cdb_analysis_fields() -> None:
    crash = parse_cdb_kernel_analysis(ANALYZE_50_MYFAULT)
    assert crash.bugcheck == "50"
    assert crash.deterministic
    assert crash.module_name == "myfault64"
    assert crash.image_name == "myfault64.sys"
    assert crash.access == "WRITE"
    assert crash.signature == "bugcheck-50:0x50_vrf_myfault64!unknown_function"
    assert "myfault64" in crash.frames
    assert all("nt!" not in f for f in crash.frames)


def test_crash_gate_confirmed() -> None:
    trigger = parse_trigger_jsonl(TRIGGER_WITNESS)
    verdict = adjudicate_kernel_crash(
        ANALYZE_50_MYFAULT,
        expected_driver="myfault64.sys",
        trigger=trigger,
        expected_in_sha256=CANON_SHA,
        dump_ticks=200,
        invoke_ticks=100,
        control_clean=True,
    )
    assert verdict.status == CONFIRMED
    assert "myfault64" in verdict.reason


def test_crash_gate_divergent_wrong_module() -> None:
    trigger = parse_trigger_jsonl(TRIGGER_WITNESS)
    verdict = adjudicate_kernel_crash(
        ANALYZE_50_NT,
        expected_driver="myfault64.sys",
        trigger=trigger,
        expected_in_sha256=CANON_SHA,
        dump_ticks=200,
        invoke_ticks=100,
        control_clean=True,
    )
    assert verdict.status == DIVERGENT
    assert "not 'myfault64.sys'" in verdict.reason


def test_crash_gate_divergent_bugcheck_outside_set() -> None:
    trigger = parse_trigger_jsonl(TRIGGER_WITNESS)
    verdict = adjudicate_kernel_crash(
        ANALYZE_F4,
        expected_driver="myfault64.sys",
        trigger=trigger,
        expected_in_sha256=CANON_SHA,
        dump_ticks=200,
        invoke_ticks=100,
        control_clean=True,
    )
    assert verdict.status == DIVERGENT
    assert "outside the deterministic set" in verdict.reason


def test_crash_gate_unrunnable_stale_dump() -> None:
    trigger = parse_trigger_jsonl(TRIGGER_WITNESS)
    verdict = adjudicate_kernel_crash(
        ANALYZE_50_MYFAULT,
        expected_driver="myfault64.sys",
        trigger=trigger,
        expected_in_sha256=CANON_SHA,
        dump_ticks=50,
        invoke_ticks=100,
        control_clean=True,
    )
    assert verdict.status == UNRUNNABLE
    assert "postdate" in verdict.reason


def test_crash_gate_accepts_new_identity_despite_checkpoint_clock_skew() -> None:
    trigger = parse_trigger_jsonl(TRIGGER_WITNESS)
    verdict = adjudicate_kernel_crash(
        ANALYZE_50_MYFAULT,
        expected_driver="myfault64.sys",
        trigger=trigger,
        expected_in_sha256=CANON_SHA,
        control_clean=True,
        dump_ticks=50,
        invoke_ticks=100,
        dump_identity_new=True,
    )
    assert verdict.status == CONFIRMED


def test_dump_identity_requires_one_new_hash_bound_to_copied_dump() -> None:
    old = {"name": "old.dmp", "length": 10, "sha256": "11" * 32}
    new = {"name": "new.dmp", "length": 20, "sha256": "22" * 32}
    pre = {"dumps_before": [old]}
    post = {"dumps_after": [old, new], "new_dumps": [new]}
    assert dump_identity_is_new(pre, post, {"dump_sha256": "22" * 32})
    assert not dump_identity_is_new(pre, post, {"dump_sha256": "33" * 32})
    assert not dump_identity_is_new(
        pre,
        {"dumps_after": [old, new], "new_dumps": []},
        {"dump_sha256": "22" * 32},
    )
    assert not dump_identity_is_new(
        {"dumps_before": None},
        post,
        {"dump_sha256": "22" * 32},
    )


def test_crash_gate_unrunnable_hash_mismatch() -> None:
    trigger = parse_trigger_jsonl(TRIGGER_WITNESS)
    verdict = adjudicate_kernel_crash(
        ANALYZE_50_MYFAULT,
        expected_driver="myfault64.sys",
        trigger=trigger,
        expected_in_sha256="ff" * 32,
        dump_ticks=200,
        invoke_ticks=100,
        control_clean=True,
    )
    assert verdict.status == UNRUNNABLE
    assert "differs" in verdict.reason


def test_witness_gate_confirmed() -> None:
    witness = parse_kd_witness_log(KD_WITNESS_LOG)
    assert witness.armed
    assert witness.operands_hits == 1
    assert witness.readback_hits == 1
    assert witness.operand_rcx == "0000000000001000"
    assert witness.operand_rdx == "0000000000001000"
    assert witness.readback_matches
    trigger = parse_trigger_jsonl(TRIGGER_WITNESS)
    verdict = adjudicate_kernel_witness(
        KD_WITNESS_LOG,
        expected_driver="iqvw64e.sys",
        expected_phys=0x1000,
        expected_len=0x1000,
        trigger=trigger,
        expected_in_sha256=CANON_SHA,
        control_no_signal=True,
    )
    assert verdict.status == CONFIRMED
    assert "MmMapIoSpace" in verdict.reason


def test_witness_gate_divergent_wrong_operands() -> None:
    trigger = parse_trigger_jsonl(TRIGGER_WITNESS)
    verdict = adjudicate_kernel_witness(
        KD_WITNESS_LOG,
        expected_driver="iqvw64e.sys",
        expected_phys=0x2000,
        expected_len=0x1000,
        trigger=trigger,
        expected_in_sha256=CANON_SHA,
        control_no_signal=True,
    )
    assert verdict.status == DIVERGENT
    assert "operands" in verdict.reason


def test_witness_gate_no_crash_when_silent() -> None:
    trigger = parse_trigger_jsonl(TRIGGER_WITNESS)
    verdict = adjudicate_kernel_witness(
        "0VERSE-KD-ARMED\n0VERSE-WITNESS-BPS-BOUND\n0 kD> g\n",
        expected_driver="iqvw64e.sys",
        expected_phys=0x1000,
        expected_len=0x1000,
        trigger=trigger,
        expected_in_sha256=CANON_SHA,
        control_no_signal=True,
    )
    assert verdict.status == NO_CRASH


def test_witness_gate_unrunnable_when_breakpoints_never_bound() -> None:
    trigger = parse_trigger_jsonl(TRIGGER_WITNESS)
    verdict = adjudicate_kernel_witness(
        KD_WITNESS_LOG.replace("0VERSE-WITNESS-BPS-BOUND\n", ""),
        expected_driver="iqvw64e.sys",
        expected_phys=0x1000,
        expected_len=0x1000,
        trigger=trigger,
        expected_in_sha256=CANON_SHA,
        control_no_signal=True,
    )
    assert verdict.status == UNRUNNABLE
    assert "bound" in verdict.reason


def test_witness_parser_ignores_marker_text_in_kd_command_echoes() -> None:
    command_echo = (
        'kd> bp iqvw64e+0x2a14 ".echo 0VERSE-WITNESS-OPERANDS; gc"\n'
        'kd> .echo 0VERSE-WITNESS-BPS-BOUND\n'
    )
    witness = parse_kd_witness_log(command_echo + KD_WITNESS_LOG)
    assert witness.breakpoints_bound
    assert witness.operands_hits == 1
    assert witness.readback_hits == 1


def test_witness_gate_divergent_control_hit() -> None:
    trigger = parse_trigger_jsonl(TRIGGER_WITNESS)
    verdict = adjudicate_kernel_witness(
        KD_WITNESS_LOG,
        expected_driver="iqvw64e.sys",
        expected_phys=0x1000,
        expected_len=0x1000,
        trigger=trigger,
        expected_in_sha256=CANON_SHA,
        control_no_signal=False,
    )
    assert verdict.status == DIVERGENT
    assert "control" in verdict.reason


# --- trigger-level witness gate (live-evidence-shaped fixtures from the M0 run) ---

# Live shapes: witness in_post_hex = cmd57 struct with [0x10]=0 status and
# [0x18]=0xffff8a8463a68000 (kernel VA); len0 control [0x10]=0xc86a8004; cmd99
# call_ok=false.
LIVE_WITNESS_POST = (
    "3900000000000000" + "00" * 8 + "00000000" + "00000000"
    + "0080a663848affff" + "0010000000000000" + "00100000" + "00000000" + "00" * 8
)
LIVE_LEN0_POST = (
    "3900000000000000" + "00" * 8 + "04806ac8" + "00000000"
    + "0000000000000000" + "0010000000000000" + "00100000" + "00000000" + "00" * 8
)


def _trigger_record(sha: str, call_ok: bool, post_hex: str):
    from zeroverse.windows_kernel_oracle import TriggerRecord

    return TriggerRecord(
        device="\\\\.\\Nal",
        ioctl="0x80862007",
        in_sha256=sha,
        in_len=56,
        call_ok=call_ok,
        win32_error=0 if call_ok else 317,
        in_post_hex=post_hex,
    )


def test_parse_trigger_witness_fields_live_shape() -> None:
    t = _trigger_record(CANON_SHA, True, LIVE_WITNESS_POST)
    fields = parse_trigger_witness_fields(t)
    assert fields.status == 0
    assert fields.mapped_va == 0xFFFF8A8463A68000
    len0 = parse_trigger_witness_fields(_trigger_record(CANON_SHA, True, LIVE_LEN0_POST))
    assert len0.status == 0xC86A8004
    assert len0.mapped_va == 0


def test_trigger_witness_gate_confirmed() -> None:
    verdict = adjudicate_trigger_witness(
        _trigger_record(CANON_SHA, True, LIVE_WITNESS_POST),
        expected_in_sha256=CANON_SHA,
        control_cmd99=_trigger_record(CANON_SHA, False, "6300000000000000" + "00" * 48),
        control_len0=_trigger_record(CANON_SHA, True, LIVE_LEN0_POST),
    )
    assert verdict.status == CONFIRMED
    assert "0xffff8a8463a68000" in verdict.reason


def test_trigger_witness_gate_no_crash_when_rejected() -> None:
    verdict = adjudicate_trigger_witness(
        _trigger_record(CANON_SHA, True, LIVE_LEN0_POST),
        expected_in_sha256=CANON_SHA,
        control_cmd99=_trigger_record(CANON_SHA, False, "6300000000000000" + "00" * 48),
        control_len0=_trigger_record(CANON_SHA, True, LIVE_LEN0_POST),
    )
    assert verdict.status == NO_CRASH


def test_trigger_witness_gate_divergent_control_leak() -> None:
    verdict = adjudicate_trigger_witness(
        _trigger_record(CANON_SHA, True, LIVE_WITNESS_POST),
        expected_in_sha256=CANON_SHA,
        control_cmd99=_trigger_record(CANON_SHA, True, "6300000000000000" + "00" * 48),
        control_len0=_trigger_record(CANON_SHA, True, LIVE_LEN0_POST),
    )
    assert verdict.status == DIVERGENT
    assert "bogus-cmd" in verdict.reason


def test_evidence_dir_requires_bound_kd_and_new_dump_identity(tmp_path) -> None:
    witness = _trigger_record(CANON_SHA, True, LIVE_WITNESS_POST)
    c99 = _trigger_record(CANON_SHA, False, "6300000000000000" + "00" * 48)
    len0 = _trigger_record(CANON_SHA, True, LIVE_LEN0_POST)

    def write_trigger(name, record) -> None:
        (tmp_path / name).write_text(
            "0VERSE-TRIGGER-JSON:" + json.dumps(record.__dict__) + "\n"
        )

    write_trigger("trigger-witness.jsonl", witness)
    write_trigger("trigger-control-cmd99.jsonl", c99)
    write_trigger("trigger-control-len0.jsonl", len0)
    (tmp_path / "kd-witness.log").write_text(KD_WITNESS_LOG)
    (tmp_path / "arm-witness-result.json").write_text(json.dumps({
        "breakpoints_bound": True,
        "controls_clean": True,
        "driver_sha256": "4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b",
        "operands_hits": 1,
        "readback_hits": 1,
        "control_cmd99_hits": {"operands": 0, "readback": 0},
        "control_len0_hits": {"operands": 0, "readback": 0},
    }))

    old = {"name": "old.dmp", "length": 10, "sha256": "11" * 32}
    new = {"name": "new.dmp", "length": 20, "sha256": "22" * 32}
    (tmp_path / "crash-pre.json").write_text(json.dumps({"dumps_before": [old]}))
    (tmp_path / "crash-post.json").write_text(json.dumps({
        "dumps_after": [old, new],
        "new_dumps": [new],
    }))
    (tmp_path / "arm-crash-result.json").write_text(json.dumps({"dump_sha256": "22" * 32}))
    (tmp_path / "crash-cdb-analysis.txt").write_text(
        ANALYZE_50_MYFAULT
        .replace("myfault64.sys", "myfault.sys")
        .replace("myfault64", "myfault")
    )

    result = adjudicate_evidence_dir(tmp_path)
    assert result["witness"]["status"] == CONFIRMED
    assert result["crash"]["status"] == CONFIRMED

    (tmp_path / "arm-witness-result.json").write_text(json.dumps({
        "breakpoints_bound": False,
        "controls_clean": True,
        "driver_sha256": "4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b",
        "operands_hits": 1,
        "readback_hits": 1,
        "control_cmd99_hits": {"operands": 0, "readback": 0},
        "control_len0_hits": {"operands": 0, "readback": 0},
    }))
    (tmp_path / "crash-post.json").write_text(json.dumps({
        "dumps_after": [old, new],
        "new_dumps": [],
    }))
    failed = adjudicate_evidence_dir(tmp_path)
    assert failed["witness"]["status"] == UNRUNNABLE
    assert failed["crash"]["status"] == UNRUNNABLE


def test_m0_wrapper_propagates_runner_failure_to_process_exit() -> None:
    wrapper = (
        Path(__file__).parents[1]
        / "scripts"
        / "windows"
        / "oracle"
        / "run-m0-controls-wrapper.ps1"
    ).read_text()
    assert "$exitCode = 1" in wrapper
    assert "$exitCode = 0" in wrapper
    assert "Write-Error -ErrorRecord $_ -ErrorAction Continue" in wrapper
    assert "exit $exitCode" in wrapper


def test_ioctl_trigger_accepts_only_inline_payloads() -> None:
    source = (
        Path(__file__).parents[1]
        / "scripts"
        / "windows"
        / "oracle"
        / "IoctlTrigger.cs"
    ).read_text()
    assert "File.ReadAllBytes" not in source
    assert "input must be '-' or an inline hex: payload" in source


def test_m0_runtime_bytes_are_sampled_after_driver_dispatch() -> None:
    source = (
        Path(__file__).parents[1]
        / "scripts"
        / "windows"
        / "oracle"
        / "run-m0-controls.ps1"
    ).read_text()
    probe = 'bp /1 iqvw64e+0x29c0 ".echo 0VERSE-SINK-BYTES; db iqvw64e+0x2a14 L6; gc"'
    assert probe in source
    assert "db iqvw64e+0x2a14 L6\nbu iqvw64e+0x2a14" not in source
    assert source.index("control A2 (cmd=57 len=0)") < source.index(
        "iqvw64e dispatch did not reach the runtime byte-binding probe"
    )
    assert source.index("loaded iqvw64e sink bytes do not match") < source.index(
        "# Witness: cmd=57"
    )


def test_iqvw_witness_points_are_module_relative_rvas() -> None:
    root = Path(__file__).parents[1]
    ioctl_map = json.loads(
        (root / "benchmarks/windows_driver_corpus/iqvw64e-ioctl-map.json").read_text()
    )
    assert ioctl_map["witness_points"]["operands_bp"]["rva"] == "0x2a14"
    assert ioctl_map["witness_points"]["readback_bp"]["rva"] == "0x2a1a"
    assert "image base 0x10000" in ioctl_map["source"]

    script = (root / "scripts/windows/oracle/run-m0-controls.ps1").read_text()
    for preferred_va in ("+0x129c0", "+0x12a14", "+0x12a1a"):
        assert preferred_va not in script

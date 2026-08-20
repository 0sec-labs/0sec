"""Hermetic tests for the M1 drive-plan builder (no VM)."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from zeroverse.windows_kernel_oracle import adjudicate_drive_plan, load_drive_plan

_BUILDER_PATH = (
    Path(__file__).resolve().parent.parent / "scripts" / "windows" / "oracle" / "build-m1-plans.py"
)
_spec = importlib.util.spec_from_file_location("build_m1_plans", _BUILDER_PATH)
builder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(builder)


_VALID_VIRAGT_KD = """\
0VERSE-KD-ARMED
0VERSE-WITNESS-OPERANDS-READ_KSD_VERSION
rcx=fffff780`0000026c rdx=00000000`00000008
0VERSE-WITNESS-READBACK-READ_KSD_VERSION
fffff780`0000026c 00000000`0000000a
"""


def _write_trigger(path: Path, record: dict[str, object]) -> None:
    path.write_text(f"0VERSE-TRIGGER-JSON:{json.dumps(record, sort_keys=True)}\n")


def _write_viragt_evidence(tmp_path: Path, kd_text: str | None) -> None:
    source = builder.build_plans(tmp_path)["viragt64"]
    plan_path = tmp_path / "drive-plan.json"
    plan_path.write_text(source.read_text())
    plan = load_drive_plan(plan_path)
    (arm,) = plan.arms
    _write_trigger(
        tmp_path / f"trigger-{arm.name}.jsonl",
        {
            "device": plan.device,
            "ioctl": arm.ioctl,
            "in_sha256": arm.expected_in_sha256,
            "call_ok": True,
            "win32_error": 0,
            "bytes_returned": 8,
            "out_post_hex": "0a000000" + "00" * 28,
        },
    )
    _write_trigger(
        tmp_path / "trigger-control-bogus-ioctl.jsonl",
        {
            "device": plan.device,
            "ioctl": "0x22220000",
            "call_ok": True,
            "win32_error": 0,
            "bytes_returned": 0,
        },
    )
    if kd_text is not None:
        (tmp_path / f"kd-{arm.name}.log").write_text(kd_text)


def test_build_plans_round_trip(tmp_path: Path) -> None:
    written = builder.build_plans(tmp_path)
    assert set(written) == {"dbutil", "viragt64", "fxdrv64", "segwindrvx64", "iscflashx64", "rwdrv"}
    for path in written.values():
        plan = load_drive_plan(path)  # gate loader must accept every plan
        assert plan.arms, path
        assert plan.controls, path
        for arm in plan.arms:
            raw = json.loads(path.read_text())
            match = next(a for a in raw["arms"] if a["name"] == arm.name)
            expected = hashlib.sha256(bytes.fromhex(arm.in_hex)).hexdigest()
            assert match["expected_in_sha256"] == expected


@pytest.mark.parametrize(
    "kd_text",
    [
        None,
        _VALID_VIRAGT_KD.replace("0VERSE-KD-ARMED\n", "", 1),
        _VALID_VIRAGT_KD.replace(
            "0VERSE-KD-ARMED", "kd> .echo 0VERSE-KD-ARMED", 1
        ),
        "0VERSE-KD-ARMED\n",
        _VALID_VIRAGT_KD
        + "0VERSE-WITNESS-OPERANDS-READ_KSD_VERSION\n"
        + "rcx=fffff780`0000026c rdx=00000000`00000008\n",
        _VALID_VIRAGT_KD.replace(
            "fffff780`0000026c 00000000`0000000a\n", "", 1
        ),
        _VALID_VIRAGT_KD.replace(
            "0VERSE-KD-ARMED\n", "0VERSE-KD-ARMED\n0VERSE-KD-ARMED\n", 1
        ),
    ],
    ids=[
        "missing",
        "unarmed",
        "malformed-armed-marker",
        "zero-hit",
        "duplicate-hit",
        "incomplete-readback",
        "duplicate-armed-marker",
    ],
)
def test_drive_plan_requires_valid_kd_evidence(
    tmp_path: Path, kd_text: str | None
) -> None:
    _write_viragt_evidence(tmp_path, kd_text)
    assert adjudicate_drive_plan(tmp_path)["status"] != "CONFIRMED"


def test_drive_plan_confirms_valid_trigger_and_kd(tmp_path: Path) -> None:
    _write_viragt_evidence(tmp_path, _VALID_VIRAGT_KD)
    result = adjudicate_drive_plan(tmp_path)
    assert result["status"] == "CONFIRMED"
    assert result["arms"]["read-ksd-version"]["status"] == "CONFIRMED"


def test_dbutil_plan_shape(tmp_path: Path) -> None:
    plan = load_drive_plan(builder.build_plans(tmp_path)["dbutil"])
    read, write = plan.arms
    assert read.ioctl == "0x9b0c1f40"
    assert read.kd.operands_regs == (("rcx", 0x1000), ("rdx", 0x1000))
    assert read.kd.readback_mode == "phys_dq_match_out_qword"
    assert read.kd.readback_out_offset == 0x10
    assert write.ioctl == "0x9b0c1f44"
    assert write.kd.operands_regs == (("rcx", 0x1000), ("rdx", 0x10))
    # struct: cookie(8) + phys(8) + data
    assert bytes.fromhex(read.in_hex)[8:16] == (0x1000).to_bytes(8, "little")
    assert len(bytes.fromhex(read.in_hex)) == 0x1010
    bogus, short = plan.controls
    assert bogus.expect_win32_error == 87
    assert short.expect_win32_error == 87


def test_viragt64_plan_shape(tmp_path: Path) -> None:
    plan = load_drive_plan(builder.build_plans(tmp_path)["viragt64"])
    (read,) = plan.arms
    assert read.ioctl == "0x82730028"
    assert read.kd.operands_regs == (("rcx", 0xFFFFF7800000026C), ("rdx", 8))
    assert read.kd.readback_mode == "dq_va_expect"
    assert read.kd.readback_expect_qword == 0xA
    assert read.expect_out_hex_at == ((0, "0a000000"),)
    (bogus,) = plan.controls
    # below the dispatch ladder; in-range odd codes fall through benignly
    assert bogus.ioctl == "0x22220000"
    # measured end-to-end: out-of-set codes return success with zero information
    assert bogus.expect_call_ok is True
    assert bogus.expect_win32_error == 0
    assert bogus.expect_bytes_returned == 0


def test_fxdrv64_plan_shape(tmp_path: Path) -> None:
    plan = load_drive_plan(builder.build_plans(tmp_path)["fxdrv64"])
    (read,) = plan.arms
    assert read.ioctl == "0x221c00"
    assert read.kd.operands_regs == (("rax", 0x80000000),)
    assert read.kd.readback_mode == "reg_dword_match_trigger_out"
    assert read.kd.readback_reg == "eax"
    struct_bytes = bytes.fromhex(read.in_hex)
    assert len(struct_bytes) == 0x14
    assert struct_bytes[8:10] == (4).to_bytes(2, "little")  # size-class dword read
    bogus, short = plan.controls
    assert bogus.expect_win32_error == 87
    assert short.expect_win32_error == 122  # STATUS_BUFFER_TOO_SMALL


def test_segwindrvx64_plan_shape(tmp_path: Path) -> None:
    raw = json.loads(builder.build_plans(tmp_path)["segwindrvx64"].read_text())
    plan = load_drive_plan(builder.build_plans(tmp_path)["segwindrvx64"])
    read, write = plan.arms
    assert read.ioctl == "0x22229a"
    # struct: dword phys + dword pad + dword len (0x0c bytes)
    struct_bytes = bytes.fromhex(read.in_hex)
    assert len(struct_bytes) == 0x0C
    assert struct_bytes[0:4] == (0x1000).to_bytes(4, "little")
    assert struct_bytes[8:12] == (0x1000).to_bytes(4, "little")
    assert read.out_len == 0x1000
    assert read.expect_bytes_returned == 4        # Information hardcoded 4 by the case
    assert read.kd.operands_regs == (("rcx", 0x1000), ("rdx", 0x1000))
    assert read.kd.readback_mode == "phys_dq_match_out_qword"
    assert read.kd.readback_out_offset == 0       # out[0:8] IS the physical qword
    assert write.ioctl == "0x2222aa"
    assert write.out_len == 0x10                  # the OUT buffer is the write source
    assert write.expect_bytes_returned == 4
    assert write.kd.operands_regs == (("rcx", 0x1000), ("rdx", 0x10))
    assert write.kd.readback_mode == "none"
    # the identity write prefills the OUT buffer (METHOD_OUT_DIRECT source), not in_hex
    write_raw = next(a for a in raw["arms"] if a["name"] == "write-phys-0x1000")
    assert write_raw["identity"] == {
        "read_arm": "read-phys-0x1000", "read_out_offset": 0,
        "length": 0x10, "apply": "out_prefill",
    }
    bogus, empty = plan.controls
    assert bogus.ioctl == "0x222001"
    assert bogus.expect_call_ok is False
    # STATUS_INVALID_DEVICE_REQUEST -> ERROR_INVALID_FUNCTION (measured)
    assert bogus.expect_win32_error == 1
    assert empty.ioctl == "0x22229a"
    assert empty.in_hex == ""
    assert empty.expect_call_ok is False
    assert empty.expect_win32_error == 31         # STATUS_UNSUCCESSFUL


def test_iscflashx64_plan_shape(tmp_path: Path) -> None:
    raw = json.loads(builder.build_plans(tmp_path)["iscflashx64"].read_text())
    plan = load_drive_plan(builder.build_plans(tmp_path)["iscflashx64"])
    read, write = plan.arms
    assert read.ioctl == "0x22229a"
    # older Insyde generation: dword phys + dword len (0x08 bytes, no pad dword)
    struct_bytes = bytes.fromhex(read.in_hex)
    assert len(struct_bytes) == 0x08
    assert struct_bytes[0:4] == (0x1000).to_bytes(4, "little")
    assert struct_bytes[4:8] == (0x1000).to_bytes(4, "little")
    assert read.out_len == 0x1000
    assert read.expect_bytes_returned == 4        # Information hardcoded 4 by the case
    assert read.kd.operands_regs == (("rcx", 0x1000), ("rdx", 0x1000))
    assert read.kd.readback_mode == "phys_dq_match_out_qword"
    assert read.kd.readback_out_offset == 0       # out[0:8] IS the physical qword
    assert write.ioctl == "0x2222aa"
    assert write.out_len == 0x10                  # the OUT buffer is the write source
    assert write.expect_bytes_returned == 4
    assert write.kd.operands_regs == (("rcx", 0x1000), ("rdx", 0x10))
    assert write.kd.readback_mode == "none"
    # same METHOD_OUT_DIRECT out_prefill identity write as segwindrvx64
    write_raw = next(a for a in raw["arms"] if a["name"] == "write-phys-0x1000")
    assert write_raw["identity"] == {
        "read_arm": "read-phys-0x1000", "read_out_offset": 0,
        "length": 0x10, "apply": "out_prefill",
    }
    # only the bogus-ioctl control (no empty-input: the case has no in_len check,
    # so in_len=0 is a crash-lane null-deref surface, not a clean rejection)
    (bogus,) = plan.controls
    assert bogus.ioctl == "0x222001"
    assert bogus.expect_call_ok is False
    # STATUS_INVALID_DEVICE_REQUEST -> ERROR_INVALID_FUNCTION
    assert bogus.expect_win32_error == 1


def test_rwdrv_plan_shape_and_inptr(tmp_path: Path) -> None:
    from zeroverse.windows_kernel_oracle import (
        ArmKdObservation,
        TriggerRecord,
        adjudicate_drive_arm,
    )

    plan = load_drive_plan(builder.build_plans(tmp_path)["rwdrv"])
    read, write = plan.arms
    # METHOD_NEITHER embedded-pointer struct: [phys:q@0][len:d@8][class:d@0xc][ptr:q@0x10]
    assert read.ioctl == "0x222808"        # RWEverything read-physical-memory
    assert write.ioctl == "0x22280c"       # write-physical-memory
    sb = bytes.fromhex(read.in_hex)
    assert len(sb) == 0x18
    assert sb[0:8] == (0x1000).to_bytes(8, "little")   # phys qword
    assert sb[8:12] == (8).to_bytes(4, "little")       # len
    assert sb[12:16] == (2).to_bytes(4, "little")      # dword sizeclass
    assert sb[16:24] == b"\x00" * 8                    # userptr zero in the template
    assert read.inptr == (0x10, 8)
    assert write.inptr == (0x10, 8)   # write len == read len so the identity write has enough bytes
    assert read.kd.operands_regs == (("rcx", 0x1000), ("rdx", 8))
    assert read.kd.readback_mode == "phys_dq_match_out_qword"
    assert write.kd.operands_regs == (("rcx", 0x1000), ("rdx", 8))
    (bogus,) = plan.controls
    assert bogus.ioctl == "0x222800"
    assert bogus.expect_win32_error == 87  # STATUS_INVALID_PARAMETER default

    # inptr binding: the gate binds via in_template_sha256 (pointer masked), not
    # in_sha256 (which carries the runtime VA and can't be pre-committed).
    kd = ArmKdObservation(
        operands_hits=1, regs=(("rcx", 0x1000), ("rdx", 8)),
        readback_hits=1, dq_blocks=[[0], [0]],
    )
    good = TriggerRecord(
        call_ok=True, win32_error=0, in_sha256="ab" * 32,
        in_template_sha256=read.expected_in_sha256, userptr="0x1f2a0000",
        out_post_hex="00" * 8,
    )
    assert adjudicate_drive_arm(plan, read, good, kd, kd_required=False).status == "CONFIRMED"
    # missing template hash on an inptr arm is a binding failure, never CONFIRMED
    no_tmpl = TriggerRecord(call_ok=True, win32_error=0, in_sha256="ab" * 32, out_post_hex="00" * 8)
    assert adjudicate_drive_arm(plan, read, no_tmpl, kd, kd_required=False).status != "CONFIRMED"


def test_marker_suffix_matches_gate() -> None:
    # the gate namespaces kd markers as ARM.upper().replace('-', '_'); the
    # plan's kd_bps cmds must use the identical suffix per arm
    for name in ("dbutil", "viragt64", "fxdrv64", "segwindrvx64", "iscflashx64", "rwdrv"):
        plan = builder.BUILDERS[name]()
        suffixes = {bp["cmds"].split("0VERSE-WITNESS-OPERANDS-")[1].split(";")[0]
                    for bp in plan["kd_bps"] if "OPERANDS" in bp["cmds"]}
        for arm in plan["arms"]:
            expected = arm["name"].upper().replace("-", "_")
            if any(bp["arm"] == arm["name"] and "OPERANDS" in bp["cmds"] for bp in plan["kd_bps"]):
                assert expected in suffixes, (name, arm["name"], suffixes)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))

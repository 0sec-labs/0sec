#!/usr/bin/env python3
"""Native Linux proof for generated shared-library harness fuzzing.

This owns both sides of the regression: a gate-reachable stack-overflow DSO and
an ABI-identical fixed DSO. It exercises the production selector, generated
``dlopen`` harness, AFL crash persistence, plain replay, and oracle gate.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

os.environ["ZEROVERSE_EXECUTOR"] = "local"
os.environ["ZEROVERSE_FUZZ_SHARED_LIB"] = "1"

from zeroverse.fuzz.aflpp import AflConfig
from zeroverse.fuzz.orchestrator import FuzzFinding, run_fuzz_stage

FIXTURES = Path("/opt/0verse-fixtures")
DECOMPILED = {
    "parse_shared": """
        int parse_shared(byte *data, int len) {
            char record[8];
            if (memcmp(data, \"ZVSL!\", 5) == 0) {
                memcpy(record, data + 5, len - 5);
            }
            return 0;
        }
    """,
}
CONTROL = b"A"
NEAR_TRIGGER = b"ZVSL!" + b"A" * 8
TRIGGER = b"ZVSL!" + b"A" * 9


def _compile_shared(source: Path, output: Path) -> None:
    subprocess.run(
        [
            "cc", "-shared", "-fPIC", "-O0", "-fno-omit-frame-pointer",
            "-fstack-protector-all", str(source), "-o", str(output),
        ],
        check=True,
        capture_output=True,
    )


def _run(binary: Path, workdir: Path) -> tuple[list[FuzzFinding], str]:
    config = AflConfig(
        duration_s=8,
        qemu_mode=False,
        cmplog=False,
        rand_seed=0,
        seeds=[NEAR_TRIGGER],
        dict_tokens=["ZVSL!"],
    )
    return run_fuzz_stage(binary, DECOMPILED, out_dir=workdir, config=config)


def _replay(binary: Path, testcase: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([str(binary)], input=testcase, capture_output=True, check=False)


def _assert_clean(binary: Path, testcase: bytes, label: str) -> None:
    result = _replay(binary, testcase)
    if result.returncode != 0:
        detail = result.stderr[-300:]
        raise RuntimeError(
            f"{label} replay failed: exit {result.returncode}: {detail!r}"
        )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="zv_shared_harness_e2e_") as directory:
        root = Path(directory)
        vulnerable = root / "vulnerable.so"
        fixed = root / "fixed.so"
        _compile_shared(FIXTURES / "shared_library_harness_vuln.c", vulnerable)
        _compile_shared(FIXTURES / "shared_library_harness_fixed.c", fixed)

        findings, note = _run(vulnerable, root / "vulnerable")
        replay = root / "vulnerable" / "shared_harness_parse_shared" / "build" / "harness_replay"
        _assert_clean(replay, CONTROL, "vulnerable control")
        vulnerable_crash_dir = (
            root / "vulnerable" / "shared_harness_parse_shared" / "out" / "default" / "crashes"
        )
        crash_files = sorted(vulnerable_crash_dir.glob("id:*"))
        if not crash_files:
            raise RuntimeError(f"AFL saved no shared-library crash: {note}")
        saved_crash = crash_files[0].read_bytes()
        if _replay(replay, saved_crash).returncode == 0:
            raise RuntimeError("AFL shared-library crash did not fail plain replay")
        if len(findings) != 1 or not findings[0].pov.reproduced:
            raise RuntimeError(f"shared-library crash was not oracle-confirmed: {note}")
        if findings[0].pov.input_bytes != saved_crash:
            raise RuntimeError("confirmed PoV bytes differ from AFL-saved crash")

        fixed_findings, fixed_note = _run(fixed, root / "fixed")
        fixed_replay = root / "fixed" / "shared_harness_parse_shared" / "build" / "harness_replay"
        _assert_clean(fixed_replay, CONTROL, "fixed control")
        _assert_clean(fixed_replay, TRIGGER, "fixed trigger")
        fixed_crash_dir = (
            root / "fixed" / "shared_harness_parse_shared" / "out" / "default" / "crashes"
        )
        fixed_crashes = list(fixed_crash_dir.glob("id:*"))
        if fixed_findings or fixed_crashes:
            raise RuntimeError(f"fixed shared library produced a crash: {fixed_note}")

    print("shared-library harness E2E: vulnerable confirmed; fixed clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

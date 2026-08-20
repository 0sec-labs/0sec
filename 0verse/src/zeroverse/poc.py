"""Stage 7 — PoV emitter.

Turns a confirmed :class:`~zeroverse.report.PoV` into a **standalone, runnable
pwntools script** that replays the crashing input deterministically against the
real binary and exits non-zero unless the expected crash reproduces. This is the
artifact a human (or CI, or a disclosure) re-runs to see the bug for themselves —
the unit of truth, made portable.

The generated script depends only on ``pwntools``; it embeds the exact delivery
vector (stdin bytes / argv / env), so it is self-contained. ``zeroverse`` itself
is not imported by the emitted script.
"""

from __future__ import annotations

from pathlib import Path

from .report import PoV

_TEMPLATE = '''#!/usr/bin/env python3
# 0verse proof-of-vulnerability — AUTO-GENERATED, deterministic replay.
# Re-run:  python3 {script_name}
# Exits 0 iff the binary crashes as expected ({crash_class}).
import os
import signal
import sys
import tempfile

from pwn import context, process  # pip install pwntools

context.log_level = "error"

BINARY = {binary!r}
CRASH_INPUT = bytes.fromhex({input_hex!r})  # stdin bytes, or FILE contents when FILE_INPUT
ARGV = {argv!r}
ENV = {env!r}
EXPECT = {crash_class!r}
FILE_INPUT = {file_input!r}  # deliver CRASH_INPUT as a file whose path is argv[1]


def main() -> int:
    if not os.path.exists(BINARY):
        print(f"[0verse] missing binary: {{BINARY}}", file=sys.stderr)
        return 2
    argv = list(ARGV)
    tmp = None
    if FILE_INPUT:
        fd, tmp = tempfile.mkstemp(prefix="0verse-poc-")
        with os.fdopen(fd, "wb") as fh:
            fh.write(CRASH_INPUT)
        argv = [*argv, tmp]
    io = process([BINARY, *argv], env={{**os.environ, **ENV}})
    out = b""
    try:
        if CRASH_INPUT and not FILE_INPUT:
            io.send(CRASH_INPUT)
        try:
            out = io.recvall(timeout=15)
        except Exception:
            out = b""
        io.wait(timeout=15)
    finally:
        rc = io.poll(block=True)
    if tmp:
        os.unlink(tmp)
    sig = -rc if rc is not None and rc < 0 else 0
    name = signal.Signals(sig).name if sig else "no-signal"
    # A sanitizer (ASan/UBSan) target crashes via a non-zero *exit* + a report on
    # stderr, not a native signal — accept either as a reproduced crash.
    sanitizer = (b"Sanitizer" in out or b"runtime error:" in out) and rc not in (0, None)
    crashed = sig != 0 or sanitizer
    reason = name if sig else ("sanitizer-report" if sanitizer else "no-signal")
    print(f"[0verse] replay of {{BINARY}} -> {{reason}} (expected crash class: {{EXPECT}})")
    if crashed:
        print("[0verse] PoV REPRODUCED ✅")
        return 0
    print("[0verse] PoV did NOT reproduce ❌", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
'''


def emit_pov_script(binary: str | Path, pov: PoV, *, script_name: str = "pov.py") -> str:
    """Render a standalone pwntools replay script for `pov` as a string."""
    return _TEMPLATE.format(
        script_name=script_name,
        binary=str(binary),
        input_hex=(pov.input_bytes or b"").hex(),
        argv=list(pov.argv),
        env=dict(pov.env),
        crash_class=pov.crash_class,
        file_input=bool(pov.file_input),
    )


def write_pov_script(path: str | Path, binary: str | Path, pov: PoV) -> Path:
    """Write the replay script to `path` (chmod +x) and return it."""
    p = Path(path)
    p.write_text(emit_pov_script(binary, pov, script_name=p.name))
    p.chmod(0o755)
    return p

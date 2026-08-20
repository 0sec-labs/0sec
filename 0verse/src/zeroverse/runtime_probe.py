"""Runtime-introspection probe — the feedback that turns "entered the function" into
"reached the vulnerable line" and "tripped the fault".

WHY THIS EXISTS. :mod:`zeroverse.trace_synth` (envelope recovery) + :mod:`zeroverse.
dynamic_trace` (libFuzzer ``-print_coverage`` reachability) get a candidate to ENTER the
vulnerable parser, but coverage is function-granular: it cannot tell us that a candidate
*entered* ``parseAdobeRAFMakernote`` yet *bailed at an inner check* three lines short of
the sink, nor WHY. And when a candidate finally reaches the sink read, coverage cannot
report the LIVE fault state — the offset value, the buffer bounds, which input byte
controls the offset. That missing signal is why byte-placement stalled: the loop was
flying blind at exactly the last inch.

This module opens the box. It drives the ``vuln`` binary under ``gdb`` batch mode using
the binary's OWN embedded DWARF line table + struct/register state (fair game — it is in
the binary; no upstream source, no Ghidra) and reports:

  * REACHABILITY — of the sink function's source lines, which ones executed and the
    MAX line reached (= where the candidate diverged / returned early). Uses temporary
    breakpoints (``tbreak``) so loops don't explode: each line is recorded once.
  * READ-SITE STATE — at each reader-helper call inside the sink (``sget4``/``get4``/…),
    the offset argument, the return value, the buffer base + size, and whether the
    offset is out of ``[0, size)`` (the fault condition, one- or two-sided).
  * PROVENANCE — the concrete input bytes that control the offset, located by searching
    the input for the little/big-endian encodings of the captured field value. This is
    the byte the refinement must flip.

Every ``gdb`` invocation is capped by a wall-clock timeout and the process group is
killed on expiry, so a runaway inferior cannot wedge a co-tenanted box.

PoV-IS-TRUTH. This module OBSERVES; it never confirms. A crash it sees under gdb is a
hypothesis until the deterministic differential oracle (:mod:`zeroverse.oracle`)
reproduces it (vuln crashes at the sink AND fixed runs the same input clean). The probe's
job is only to make the refinement loop sighted.

TARGET-AGNOSTIC. The probe takes a sink function name + the two binaries + a candidate.
Sink source-line range and the reader-helper call sites are discovered from the binary
(objdump DWARF + disassembly); the checked-buffer accessor offsets are auto-derived from
the accessor's own disassembly, or supplied explicitly for precision. Nothing here is
libraw-specific.
"""

from __future__ import annotations

import contextlib
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .sandbox_exec import LocalExecutor, current_executor

# Reader-helper name hint: a call to one of these inside the sink is where an
# attacker-controlled scalar is read — the fault site for OOB-read bugs.
_READER_HINT = re.compile(r"sget|get2|get4|getint|getbits|read", re.I)

_GDB = os.environ.get("ZEROVERSE_GDB", "/usr/bin/gdb")
_OBJDUMP = os.environ.get("ZEROVERSE_OBJDUMP", "objdump")


# --------------------------------------------------------------------------- #
# data model
# --------------------------------------------------------------------------- #
@dataclass
class ReadObs:
    """One observed reader-helper call inside the sink function."""

    site: str = ""  # symbol / address label of the call site
    line: int = 0  # source line of the call (DWARF)
    offset: int | None = None  # the offset argument (signed)
    ret: int | None = None  # the value the reader returned (the scalar read)
    buf_base: int | None = None
    buf_size: int | None = None
    oob: bool = False  # offset outside [0, size)
    oob_reason: str = ""


@dataclass
class Provenance:
    """A captured runtime value located back to concrete input bytes."""

    value: int = 0
    input_offset: int = -1
    width: int = 0
    endian: str = ""  # "little" | "big"
    via: str = ""  # which observation this came from


@dataclass
class ProbeResult:
    """What the runtime probe saw. ``reached_func``/``reached_lines`` are the reachability
    signal; ``reads`` the live fault state; ``provenance`` the byte to flip. ``crashed``
    is a HYPOTHESIS — only the oracle confirms."""

    reached_func: bool = False
    reached_lines: list[int] = field(default_factory=list)
    max_line: int = 0
    bail_line: int = 0  # last line reached before divergence (== max_line)
    crashed: bool = False
    crash_line: int = 0
    crash_at_sink: bool = False
    reads: list[ReadObs] = field(default_factory=list)
    provenance: list[Provenance] = field(default_factory=list)
    exit_code: int | None = None
    timed_out: bool = False
    error: str = ""
    raw_tail: str = ""

    @property
    def oob_read(self) -> ReadObs | None:
        """The reader observation whose offset is out of bounds, if any."""
        for r in self.reads:
            if r.oob:
                return r
        return None

    @property
    def last_read(self) -> ReadObs | None:
        return self.reads[-1] if self.reads else None


# --------------------------------------------------------------------------- #
# binary introspection (objdump / DWARF) — all fair: from the binary itself
# --------------------------------------------------------------------------- #
_DEMANGLE_TAIL = re.compile(r"(?:.*::)?([A-Za-z_][\w]*)")


def _run(cmd: list[str], timeout: float = 60.0) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except Exception:
        return ""
    return (p.stdout + p.stderr).decode("utf-8", "replace")


def func_address_range(binary: str, sink_func: str) -> tuple[int, int] | None:
    """(start, end) virtual addresses of ``sink_func`` from the symbol table. Matches on
    the *bare* identifier so a demangled/mangled/namespaced name all resolve."""
    bare = _DEMANGLE_TAIL.match(sink_func.split("(")[0].split("<")[0].rsplit("::", 1)[-1])
    needle = bare.group(1) if bare else sink_func
    out = _run([_OBJDUMP, "-d", "--demangle", binary])
    start = end = None
    label_re = re.compile(r"^([0-9a-f]+)\s+<([^>]*)>:")
    addr_re = re.compile(r"^\s*([0-9a-f]+):")
    in_func = False
    for line in out.splitlines():
        m = label_re.match(line)
        if m:
            if in_func:  # hit the NEXT function label -> our func ends here
                end = int(m.group(1), 16)
                break
            if re.search(rf"\b{re.escape(needle)}\b", m.group(2)):
                start = int(m.group(1), 16)
                in_func = True
            continue
        if in_func:
            am = addr_re.match(line)
            if am:
                end = int(am.group(1), 16)
    if start is None:
        return None
    return start, (end if end is not None else start)


def sink_source_lines(
    binary: str, addr_range: tuple[int, int], *, src_hint: str = ""
) -> dict[int, int]:
    """Map source line -> first address, for lines whose code lies within ``addr_range``.
    Reads the DWARF decoded line table (``objdump --dwarf=decodedline``). ``src_hint``
    (e.g. "fuji.cpp") filters to the sink's own source file when the range is shared
    with inlined callees."""
    lo, hi = addr_range
    out = _run([_OBJDUMP, "--dwarf=decodedline", binary], timeout=120.0)
    lines: dict[int, int] = {}
    for row in out.splitlines():
        cols = row.split()
        if len(cols) < 3:
            continue
        fname, lineno, addr = cols[0], cols[1], cols[2]
        if src_hint and src_hint not in fname:
            continue
        if not lineno.isdigit() or not addr.startswith("0x"):
            continue
        try:
            a = int(addr, 16)
            ln = int(lineno)
        except ValueError:
            continue
        if lo <= a < hi and ln > 0:
            lines.setdefault(ln, a)
    return dict(sorted(lines.items()))


def reader_call_sites(binary: str, addr_range: tuple[int, int]) -> list[tuple[int, str]]:
    """Addresses of ``call`` instructions inside ``addr_range`` whose target is a
    reader-helper (sget4/get4/…). These are the scalar-read fault sites."""
    lo, hi = addr_range
    out = _run([_OBJDUMP, "-d", "--demangle", binary])
    sites: list[tuple[int, str]] = []
    call_re = re.compile(r"^\s*([0-9a-f]+):.*\bcall\b.*<([^>]+)>")
    for line in out.splitlines():
        m = call_re.match(line)
        if not m:
            continue
        a = int(m.group(1), 16)
        target = m.group(2)
        if lo <= a < hi and _READER_HINT.search(target):
            sites.append((a, target))
    return sites


def accessor_member_offsets(binary: str, accessor_sym: str) -> tuple[int, int] | None:
    """Auto-derive (base_off, size_off): the byte offsets of the data pointer and the
    length field inside a checked-buffer object, by reading the accessor's disassembly.

    Heuristic that matches the canonical accessor shape
        int sget4(int off){ if (off+4 <= size) return read(base+off); }
    -> the length load is ``mov <size_off>(this), reg`` (a 32-bit load compared against
    off), and the base add is ``add <base_off>(this), reg`` feeding the read pointer.
    Returns None if the shape is not recognised (caller then relies on crash-presence as
    the OOB signal instead of computed bounds)."""
    out = _run([_OBJDUMP, "-d", "--demangle", binary])
    body: list[str] = []
    grab = False
    for line in out.splitlines():
        if re.match(r"^[0-9a-f]+\s+<", line):
            # substring match: robust to mangled ("_ZN16checked_buffer_t...") and
            # demangled ("checked_buffer_t::sget4(int)") symbols alike (the latter ends
            # in ')', where a \b word-boundary anchor would fail).
            grab = accessor_sym in line
            continue
        if grab:
            body.append(line)
    text = "\n".join(body)
    # size: a 32-bit load 'mov 0xNN(%rXX),%eXX' used right before a cmp/jle bound check.
    size_off = base_off = None
    m = re.search(r"mov\s+0x([0-9a-f]+)\(%r[a-z0-9]+\),%e[a-z0-9]+", text)
    if m:
        size_off = int(m.group(1), 16)
    # base: 'add 0xNN(%rXX),%rXX' (64-bit) that forms the read pointer.
    m = re.search(r"add\s+0x([0-9a-f]+)\(%r[a-z0-9]+\),%r[a-z0-9]+", text)
    if m:
        base_off = int(m.group(1), 16)
    if base_off is None or size_off is None:
        return None
    return base_off, size_off


# --------------------------------------------------------------------------- #
# gdb driver
# --------------------------------------------------------------------------- #
def _gdb_available() -> bool:
    return bool(shutil.which(_GDB) or Path(_GDB).exists())


def _command_available(command: str) -> bool:
    return bool(shutil.which(command) or Path(command).exists())


def _kill_process_group(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (OSError, ProcessLookupError):
        with contextlib.suppress(OSError):
            proc.kill()


_GDB_RUN_RE = re.compile(r"^\s*run(?:\s+(.*))?$")


def _remote_gdb_script(
    script: str,
    endpoint: str,
    default_argv: list[str],
) -> tuple[str, list[str]]:
    """Replace the script's inferior ``run`` with a QEMU remote connection.

    QEMU receives the inferior argv itself. Explicit arguments on the GDB
    ``run`` command override the argv supplied to :func:`run_gdb_batch`, matching
    native GDB behavior.
    """
    lines: list[str] = []
    run_argv: list[str] | None = None
    for line in script.splitlines():
        match = _GDB_RUN_RE.fullmatch(line)
        if match is None or run_argv is not None:
            lines.append(line)
            continue
        raw_args = (match.group(1) or "").strip()
        try:
            run_argv = shlex.split(raw_args) if raw_args else list(default_argv)
        except ValueError as exc:
            raise ValueError(f"invalid GDB run arguments: {exc}") from exc
        lines.extend(
            [
                "set tcp connect-timeout 5",
                f"target remote {endpoint}",
                "continue",
            ]
        )
    if run_argv is None:
        raise ValueError("GDB script has no run command for QEMU remote execution")
    return "\n".join(lines) + "\n", run_argv


def _loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _run_gdb_qemu(
    qemu: str,
    binary: str,
    script: str,
    argv: list[str],
    *,
    timeout: float,
    env: dict[str, str],
) -> tuple[str, int | None, bool]:
    """Run the inferior behind QEMU's GDB stub instead of Linux ``ptrace``.

    This is the supported cross-architecture path for Rosetta-hosted x86
    processes. GDB and QEMU each get a process group; both are killed on timeout
    or early debugger failure so no listening stub or inferior can linger.
    """
    if not _command_available(qemu):
        return f"QEMU GDB stub executable not found: {qemu}", None, False

    port = _loopback_port()
    endpoint = f"127.0.0.1:{port}"
    try:
        remote_script, run_argv = _remote_gdb_script(script, endpoint, argv)
    except ValueError as exc:
        return str(exc), None, False

    with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as sf:
        sf.write(remote_script)
        script_path = sf.name

    qemu_proc: subprocess.Popen[bytes] | None = None
    gdb_proc: subprocess.Popen[bytes] | None = None
    gdb_out = b""
    timed_out = False
    code: int | None = None
    try:
        with tempfile.TemporaryFile() as qemu_log:
            try:
                qemu_proc = subprocess.Popen(
                    [qemu, "-g", str(port), binary, *run_argv],
                    stdout=qemu_log,
                    stderr=subprocess.STDOUT,
                    env=env,
                    start_new_session=True,
                )
            except OSError as exc:
                return f"QEMU GDB stub failed to start: {exc}", None, False

            # QEMU binds before waiting for GDB, but Popen returns before exec.
            time.sleep(0.05)
            if qemu_proc.poll() is not None:
                qemu_log.seek(0)
                detail = qemu_log.read().decode("utf-8", "replace").strip()
                return (
                    f"QEMU GDB stub exited before attach"
                    f" (exit {qemu_proc.returncode}): {detail}",
                    qemu_proc.returncode,
                    False,
                )

            try:
                gdb_proc = subprocess.Popen(
                    [_GDB, "-batch", "-nx", "-x", script_path, binary],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env=env,
                    start_new_session=True,
                )
                try:
                    gdb_out, _ = gdb_proc.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    _kill_process_group(gdb_proc)
                    gdb_out, _ = gdb_proc.communicate()
                code = gdb_proc.returncode
            except OSError as exc:
                gdb_out = f"GDB failed to start: {exc}".encode()

            if qemu_proc.poll() is None:
                try:
                    qemu_proc.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    _kill_process_group(qemu_proc)
                    qemu_proc.wait()
            qemu_log.seek(0)
            qemu_out = qemu_log.read()
    finally:
        if gdb_proc is not None:
            _kill_process_group(gdb_proc)
        if qemu_proc is not None:
            _kill_process_group(qemu_proc)
        with contextlib.suppress(OSError):
            Path(script_path).unlink()

    combined = gdb_out
    if qemu_out:
        combined += b"\n--- qemu inferior ---\n" + qemu_out
    return combined.decode("utf-8", "replace"), code, timed_out


def run_gdb_batch(
    binary: str,
    script: str,
    argv: list[str],
    *,
    timeout: float = 60.0,
    env: dict[str, str] | None = None,
) -> tuple[str, int | None, bool]:
    """Run ``gdb -batch -x SCRIPT BINARY`` with ``argv`` handed to the inferior via the
    script's ``run``. Returns (output, gdb_exit_code, timed_out). The gdb process is
    started in its own session and the whole group is SIGKILLed on timeout so a wedged
    inferior cannot linger."""
    if not isinstance(current_executor(), LocalExecutor):
        return "runtime GDB requires explicit trusted-local execution", None, False
    if not _gdb_available():
        return "", None, False
    full_env = {
        **os.environ,
        "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0",
        "UBSAN_OPTIONS": "halt_on_error=0",
    }
    if env:
        full_env.update(env)
    qemu = os.environ.get("ZEROVERSE_GDB_QEMU", "").strip()
    if qemu:
        return _run_gdb_qemu(
            qemu, binary, script, argv, timeout=timeout, env=full_env
        )

    with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as sf:
        sf.write(script)
        script_path = sf.name
    cmd = [_GDB, "-batch", "-nx", "-x", script_path, "--args", binary, *argv]
    proc: subprocess.Popen[bytes] | None = None
    timed_out = False
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=full_env,
            start_new_session=True,
        )
        try:
            out_b, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process_group(proc)
            out_b, _ = proc.communicate()
        code = proc.returncode
    finally:
        with contextlib.suppress(OSError):
            Path(script_path).unlink()
    return out_b.decode("utf-8", "replace"), code, timed_out


# --------------------------------------------------------------------------- #
# gdb script synthesis
# --------------------------------------------------------------------------- #
def build_probe_script(
    input_path: str,
    *,
    sink_line: int,
    src_hint: str,
    checkpoint_lines: list[int],
    read_sites: list[dict[str, Any]],
    runs_arg: bool = True,
) -> str:
    """Assemble the gdb batch script.

    ``checkpoint_lines`` -> a ``tbreak file:line`` each, printing ``CKPT <line>`` once.
    ``read_sites`` -> each a dict {addr, line, offset_expr, ret_expr?, base_expr?,
    size_expr?}; a breakpoint at the call prints the offset/base/size, and (if given) a
    breakpoint at the return addr prints the returned value. All printf output is tagged
    with stable prefixes the parser keys on."""
    parts = [
        "set pagination off",
        "set width 0",
        "set height 0",
        "set confirm off",
        "set backtrace limit 32",
    ]
    for ln in checkpoint_lines:
        parts += [
            f"tbreak {src_hint}:{ln}" if src_hint else f"tbreak {ln}",
            "commands",
            "  silent",
            f'  printf "CKPT {ln}\\n"',
            "  continue",
            "end",
        ]
    for i, rs in enumerate(read_sites):
        addr = rs["addr"]
        off_e = rs.get("offset_expr", "$esi")
        base_e = rs.get("base_expr", "0")
        size_e = rs.get("size_expr", "0")
        line = rs.get("line", 0)
        parts += [
            f"break *{addr}",
            "commands",
            "  silent",
            (
                f'  printf "READ {i} line={line} off=%d base=%p size=%d\\n", '
                f"(long)({off_e}), (void*)({base_e}), (long)({size_e})"
            ),
            "  continue",
            "end",
        ]
        ret_addr = rs.get("ret_addr")
        ret_e = rs.get("ret_expr", "$eax")
        if ret_addr:
            parts += [
                f"break *{ret_addr}",
                "commands",
                "  silent",
                f'  printf "RET {i} val=%d\\n", (int)({ret_e})',
                "  continue",
                "end",
            ]
    # crash reporting: stop on the signal, print where.
    parts += [
        f"break {src_hint}:{sink_line}" if src_hint else f"break {sink_line}",
        "commands",
        "  silent",
        f'  printf "SINKLINE {sink_line}\\n"',
        "  continue",
        "end",
    ]
    run_args = "-runs=1 " if runs_arg else ""
    parts += [
        f"run {run_args}{input_path}",
        # if we stopped (crash), report the frame line.
        'printf "STOPPED\\n"',
        "info line",
        "bt 3",
        "quit",
    ]
    return "\n".join(parts) + "\n"


# --------------------------------------------------------------------------- #
# output parsing (robust to gdb noise)
# --------------------------------------------------------------------------- #
_CKPT_RE = re.compile(r"^CKPT (\d+)")
_READ_RE = re.compile(
    r"^READ (\d+) line=(\d+) off=(-?\d+) base=(0x[0-9a-fA-F]+|\(nil\)) size=(-?\d+)"
)
_RET_RE = re.compile(r"^RET (\d+) val=(-?\d+)")
_SINKLINE_RE = re.compile(r"^SINKLINE (\d+)")
_ASAN_RE = re.compile(r"ERROR: AddressSanitizer|SEGV|SUMMARY: AddressSanitizer")
_LINE_NO_RE = re.compile(r"Line (\d+) of ")


def parse_probe_output(
    out: str, *, sink_func: str, sink_line: int, read_meta: list[dict[str, Any]]
) -> ProbeResult:
    res = ProbeResult(raw_tail=out[-1500:])
    reads_by_idx: dict[int, ReadObs] = {}
    rets_by_idx: dict[int, int] = {}
    saw_sinkline = False
    for raw in out.splitlines():
        line = raw.strip()
        m = _CKPT_RE.match(line)
        if m:
            res.reached_func = True
            res.reached_lines.append(int(m.group(1)))
            continue
        m = _SINKLINE_RE.match(line)
        if m:
            res.reached_func = True
            saw_sinkline = True
            res.reached_lines.append(int(m.group(1)))
            continue
        m = _READ_RE.match(line)
        if m:
            idx = int(m.group(1))
            base = None if m.group(4) == "(nil)" else int(m.group(4), 16)
            ro = ReadObs(
                site=read_meta[idx].get("site", "") if idx < len(read_meta) else "",
                line=int(m.group(2)),
                offset=int(m.group(3)),
                buf_base=base,
                buf_size=int(m.group(5)),
            )
            reads_by_idx[idx] = ro  # last write wins (final call before crash)
            continue
        m = _RET_RE.match(line)
        if m:
            rets_by_idx[int(m.group(1))] = int(m.group(2))
            continue
    for idx, ro in reads_by_idx.items():
        if idx in rets_by_idx:
            ro.ret = rets_by_idx[idx]
        if ro.buf_size and ro.offset is not None:
            if ro.offset < 0:
                ro.oob, ro.oob_reason = True, "offset < 0 (underflow read)"
            elif ro.offset + 4 > ro.buf_size:
                ro.oob, ro.oob_reason = True, "offset+4 > size (overflow read)"
        res.reads.append(ro)
    res.reads.sort(key=lambda r: r.line)
    if res.reached_lines:
        res.max_line = max(res.reached_lines)
        res.bail_line = res.max_line
    res.crashed = bool(_ASAN_RE.search(out))
    if res.crashed:
        # crash line from the 'info line' after STOPPED, else the sink line if we were there.
        lm = _LINE_NO_RE.search(out.split("STOPPED", 1)[-1]) if "STOPPED" in out else None
        if lm:
            res.crash_line = int(lm.group(1))
        res.crash_at_sink = (sink_func.split("::")[-1].split("(")[0] in out) or saw_sinkline
    return res


# --------------------------------------------------------------------------- #
# provenance: locate a captured value back to input bytes
# --------------------------------------------------------------------------- #
def locate_value(data: bytes, value: int, *, widths: tuple[int, ...] = (4, 2)) -> Provenance | None:
    """Find where ``value`` (as a little- or big-endian integer of the given widths)
    sits in ``data``. Returns the first UNIQUE match (a value appearing once is almost
    certainly the field); ambiguous/absent -> None."""
    for w in widths:
        for endian in ("little", "big"):
            try:
                needle = (value & ((1 << (8 * w)) - 1)).to_bytes(w, endian)
            except (OverflowError, ValueError):
                continue
            positions = [i for i in range(len(data) - w + 1) if data[i : i + w] == needle]
            if len(positions) == 1:
                return Provenance(value=value, input_offset=positions[0], width=w, endian=endian)
    return None


# --------------------------------------------------------------------------- #
# top-level probe
# --------------------------------------------------------------------------- #
def probe(
    binary: str,
    candidate: bytes,
    sink_func: str,
    *,
    src_hint: str = "",
    sink_line: int | None = None,
    read_site_exprs: list[dict[str, Any]] | None = None,
    checkpoint_lines: list[int] | None = None,
    accessor_sym: str = "",
    buffer_arg_reg: str = "$rdi",
    timeout: float = 60.0,
    runs_arg: bool = True,
) -> ProbeResult:
    """Run one runtime probe of ``binary`` on ``candidate`` for the sink ``sink_func``.

    Discovers the sink's address range + source lines + reader-call sites from the binary
    (DWARF/disasm). ``read_site_exprs`` may override/augment the auto-discovered read
    sites with precise gdb expressions {offset_expr, base_expr, size_expr, ret_expr}; if
    omitted, the accessor's member offsets are auto-derived (``accessor_sym``) and the
    buffer pointer is taken from ``buffer_arg_reg`` at the call. Everything is
    target-agnostic: only ``sink_func`` (+ optional hints) is target-specific."""
    if not isinstance(current_executor(), LocalExecutor):
        return ProbeResult(error="runtime GDB requires explicit trusted-local execution")
    rng = func_address_range(binary, sink_func)
    if rng is None:
        return ProbeResult(error=f"sink function {sink_func!r} not found in {binary}")

    src_lines = sink_source_lines(binary, rng, src_hint=src_hint)
    if checkpoint_lines is None:
        # every source line of the sink, up to the read line (bail-point resolution).
        checkpoint_lines = sorted(src_lines)
    if sink_line is None:
        # the reader call sites' lines; deepest is the fault read.
        sites = reader_call_sites(binary, rng)
        sink_line = max((_line_for_addr(src_lines, a) for a, _ in sites), default=0)

    # Assemble read-site introspection.
    read_sites: list[dict[str, Any]] = []
    read_meta: list[dict[str, Any]] = []
    if read_site_exprs:
        for rs in read_site_exprs:
            read_sites.append(rs)
            read_meta.append(
                {
                    "site": rs.get(
                        "site",
                        hex(int(str(rs["addr"]).replace("*", ""), 16))
                        if isinstance(rs.get("addr"), str) and "x" in str(rs["addr"])
                        else str(rs.get("addr")),
                    )
                }
            )
    else:
        off = accessor_member_offsets(binary, accessor_sym) if accessor_sym else None
        base_off, size_off = off if off else (0x8, 0x10)
        for a, tgt in reader_call_sites(binary, rng):
            rs = {
                "addr": hex(a),
                "line": _line_for_addr(src_lines, a),
                "offset_expr": "$esi",
                "base_expr": f"*(void**)({buffer_arg_reg}+{base_off})" if off else "0",
                "size_expr": f"*(int*)({buffer_arg_reg}+{size_off})" if off else "0",
                "site": tgt,
            }
            read_sites.append(rs)
            read_meta.append({"site": tgt})

    with tempfile.NamedTemporaryFile("wb", suffix=".cand", delete=False) as cf:
        cf.write(candidate)
        cand_path = cf.name
    try:
        script = build_probe_script(
            cand_path,
            sink_line=sink_line,
            src_hint=src_hint,
            checkpoint_lines=checkpoint_lines,
            read_sites=read_sites,
            runs_arg=runs_arg,
        )
        out, code, to = run_gdb_batch(binary, script, [], timeout=timeout)
    finally:
        with contextlib.suppress(OSError):
            Path(cand_path).unlink()

    res = parse_probe_output(out, sink_func=sink_func, sink_line=sink_line, read_meta=read_meta)
    res.exit_code = code
    res.timed_out = to
    if to and not res.error:
        res.error = "gdb run timed out (killed)"

    # Provenance: locate the offset-controlling value in the input. Try each read's
    # RETURN value (the scalar actually read from input) and the offset itself.
    seen = set()
    for ro in res.reads:
        for val, via in (
            (ro.ret, f"read@line{ro.line} return"),
            (ro.offset, f"read@line{ro.line} offset"),
        ):
            if val is None or val in seen:
                continue
            seen.add(val)
            prov = locate_value(candidate, val)
            if prov:
                prov.via = via
                res.provenance.append(prov)
    return res


def _line_for_addr(src_lines: dict[int, int], addr: int) -> int:
    """Nearest source line whose first-address is <= addr (the line the addr belongs to)."""
    best_line, best_addr = 0, -1
    for ln, a in src_lines.items():
        if a <= addr and a > best_addr:
            best_line, best_addr = ln, a
    return best_line


# --------------------------------------------------------------------------- #
# feedback: ProbeResult -> a concrete instruction for the synthesis LLM
# --------------------------------------------------------------------------- #
def feedback_instruction(
    res: ProbeResult, *, sink_func: str, fault_constraint: str = "", input_len: int = 0
) -> str:
    """Turn the runtime observation into a concrete, actionable instruction for the
    synthesis LLM (or a human). Three regimes:

      * did not enter the sink -> the OUTER routing is wrong;
      * entered but bailed at line L short of the read -> fix the check at ~L;
      * reached the read with an in-bounds offset -> flip the located field OOB.
    """
    if res.error and not res.reached_func:
        return (
            f"Runtime probe could not run cleanly ({res.error}); keep the current "
            f"envelope and retry."
        )
    if not res.reached_func:
        return (
            f"Your input did NOT enter the sink '{sink_func}'. The OUTER container "
            f"routing is wrong: fix the top-level magic/signature, the tag/type that "
            f"dispatches to this parser, and any IFD/section offsets so parsing "
            f"reaches '{sink_func}' at all."
        )
    if res.oob_read is not None:
        r = res.oob_read
        return (
            f"Reached the read at line {r.line} with offset={r.offset} which is OUT "
            f"OF BOUNDS ({r.oob_reason}). This should fault under ASan; if the oracle "
            f"has not confirmed, keep this exact input."
        )
    reached_read = bool(res.reads)
    if not reached_read:
        # entered the function but bailed before any reader call.
        return (
            f"You ENTERED '{sink_func}' but execution stopped at source line "
            f"{res.max_line}, BEFORE the vulnerable read. An inner check at ~line "
            f"{res.max_line} rejected the sub-structure. Keep the outer envelope that "
            f"got you INTO the function, and fix the bytes checked at line "
            f"{res.max_line}: the inner signature/length/count field for this parser "
            f"must be byte-exact so execution advances past line {res.max_line} toward "
            f"the read."
        )
    # reached the read but offset in-bounds — the last inch is the fault VALUE.
    last_read = res.last_read
    prov_txt = ""
    if res.provenance:
        p = res.provenance[0]
        prov_txt = (
            f" The offset is derived from the {p.width}-byte {p.endian}-endian "
            f"value at INPUT OFFSET {p.input_offset} (currently {p.value}). Set "
            f"those {p.width} bytes so the resulting read offset goes NEGATIVE "
            f"(e.g. 0xFFFFFFF7) or far beyond the buffer size "
            f"({last_read.buf_size if last_read and last_read.buf_size else 'unknown'})."
        )
    return (
        f"ROUTING SUCCEEDED — you reached the vulnerable read at line "
        f"{last_read.line if last_read else '?'} with "
        f"offset={last_read.offset if last_read else '?'} (buffer size "
        f"{last_read.buf_size if last_read and last_read.buf_size else 'unknown'}), "
        f"but it is IN BOUNDS so no "
        f"fault fired. Keep the ENTIRE envelope identical and make the controlled "
        f"field VIOLATE the bound ({fault_constraint or 'offset<0 or offset>=size'})." + prov_txt
    )

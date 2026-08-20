"""#15 — AFL++ driver for binary-only / harnessed targets.

Drives AFL++ against a harness (the #16 synthesis output) or, in QEMU-mode, a
stripped binary directly. The proven AIxCC knobs:

  * **persistent mode** when the harness exposes ``__AFL_LOOP`` (orders of
    magnitude faster than fork-per-exec);
  * **CMPLOG / redqueen** (``-c``) to crack magic-byte / checksum comparisons —
    this is what gets the fuzzer past gates like a 4-byte header without a
    dictionary;
  * a **seed + dictionary strategy** built from the slice's constants (string
    literals + size constants pulled from the decompiled C);
  * **QEMU-mode** (``-Q``) for a stripped binary with no source — gated on
    ``afl-qemu-trace`` being present (it must be built from the AFL++ source tree;
    we degrade honestly when it is absent), with a **Frida-mode** note as the
    cross-platform fallback.

The ``AflBackend`` protocol abstracts the fuzz run so the orchestrator and tests
can swap a ``FakeAfl`` for a deterministic, AFL-free unit test. ``SubprocessAfl``
is the real driver; the module also bundles the compile helpers that build the
instrumented + CMPLOG + plain replay binaries from a harness and target source.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ..abi import abi_for, host_arch
from ..sandbox_exec import LocalExecutor, current_executor

# --- availability probes ----------------------------------------------------

def afl_fuzz_path() -> str | None:
    return shutil.which("afl-fuzz")


def afl_available() -> bool:
    return afl_fuzz_path() is not None


# A binary carrying its own AFL / SanitizerCoverage instrumentation AND a
# libFuzzer/AFL driver entry: a natively fuzzable file-input target (magma isan,
# ARVO/OSS-Fuzz). Fuzz these NATIVELY (no QEMU) with file-arg input.
_FUZZ_INSTRUMENTATION: tuple[bytes, ...] = (
    b"__afl_sharedmem_fuzzing", b"__sanitizer_cov_trace_pc", b"__asan_init",
)
_FUZZ_DRIVER_ENTRY: tuple[bytes, ...] = (
    b"LLVMFuzzerTestOneInput", b"AFL_DRIVER", b"StandaloneFuzzTargetMain",
)


def is_instrumented_fuzz_target(path: str | Path) -> bool:
    """True when ``path`` is a natively AFL/SanitizerCoverage-instrumented
    libFuzzer/AFL-driver target (magma isan, ARVO). Such a binary must be fuzzed
    NATIVELY (its coverage is already compiled in — QEMU on top is 10-100x slower)
    with FILE-arg input (the driver reads argv[1]). Static byte-marker probe; no
    execution.

    This is deliberately the *driver* predicate: it also selects the ``@@``
    file-arg input form. A binary that carries the instrumentation but has no
    driver entry (magma ``lua`` — a stdin-reading interpreter) is a THIRD case;
    probe it with :func:`has_afl_instrumentation` and route it natively with
    stdin input (#315)."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return False
    instrumented = any(m in data for m in _FUZZ_INSTRUMENTATION)
    driver = any(m in data for m in _FUZZ_DRIVER_ENTRY)
    return instrumented and driver


# The AFL++ forkserver/shared-memory markers `check_binary()` itself greps for.
# `SHM_ENV_VAR` ("__AFL_SHM_ID") is the exact string afl-fuzz uses to decide a
# binary is instrumented; finding it under `-Q` is a FATAL, not a warning:
#   PROGRAM ABORT : Instrumentation found in -Q mode  (src/afl-fuzz-init.c:2967)
# `AFL_IGNORE_PROBLEMS` does not bypass that gate. Keep this list to compiled-in
# AFL coverage only — `__asan_init` alone means ASan without AFL coverage, which
# must NOT be pulled out of QEMU-mode (afl-fuzz would then abort the other way,
# with "No instrumentation detected").
_AFL_INSTRUMENTATION: tuple[bytes, ...] = (
    b"__AFL_SHM_ID", b"__afl_sharedmem_fuzzing", b"__afl_area_ptr",
)


def has_afl_instrumentation(path: str | Path) -> bool:
    """True when ``path`` carries compiled-in AFL++ coverage instrumentation,
    regardless of whether it also has a fuzz-driver entry point.

    afl-fuzz REFUSES to run such a binary under ``-Q``, so this is the predicate
    for "must not be routed to QEMU-mode", which is strictly weaker than
    :func:`is_instrumented_fuzz_target` ("is a file-input libFuzzer driver").
    Static byte-marker probe; no execution."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return False
    return any(m in data for m in _AFL_INSTRUMENTATION)


def afl_qemu_trace_path(cpu: str = "") -> str | None:
    """Locate the ``afl-qemu-trace`` helper for an AFL++ ``CPU_TARGET`` (empty =
    host arch). Cross-arch QEMU-mode (#19) needs a per-arch trace built with
    ``CPU_TARGET=<cpu> ./build_qemu_support.sh`` — by convention installed as
    ``afl-qemu-trace-<cpu>`` (or pointed at by ``ZEROVERSE_AFL_QEMU_<CPU>``)."""
    if not cpu:
        if shutil.which("afl-qemu-trace") is not None:
            return shutil.which("afl-qemu-trace")
        for base in ("/usr/lib/afl", "/usr/local/lib/afl"):
            cand = Path(base) / "afl-qemu-trace"
            if cand.exists():
                return str(cand)
        return None
    env = os.environ.get(f"ZEROVERSE_AFL_QEMU_{cpu.upper()}")
    if env and Path(env).exists():
        return env
    name = f"afl-qemu-trace-{cpu}"
    found = shutil.which(name)
    if found:
        return found
    for base in ("/usr/local/bin", "/usr/bin", "/usr/lib/afl", "/usr/local/lib/afl"):
        cand = Path(base) / name
        if cand.exists():
            return str(cand)
    if cpu in {host_arch(), _cpu_target(host_arch())}:
        return afl_qemu_trace_path("")
    return None


def _cpu_target(arch: str) -> str:
    """Canonical 0verse arch → AFL++/qemu ``CPU_TARGET`` tag."""
    abi = abi_for(arch)
    return abi.afl_qemu_cpu if abi else arch


def afl_qemu_available(arch: str = "") -> bool:
    """QEMU-mode needs ``afl-qemu-trace`` (built separately from the AFL++ source
    tree). For a non-host ``arch`` (e.g. ``aarch64``) it needs the matching
    cross-arch trace. Callers must degrade gracefully when this is False."""
    if not arch:
        return afl_qemu_trace_path("") is not None
    cpu = _cpu_target(arch)
    if afl_qemu_trace_path(cpu) is not None:
        return True
    return arch == host_arch() and afl_qemu_trace_path("") is not None


def _prepare_cross_afl_path(cpu: str, near: Path, trace: str | None = None) -> str | None:
    """AFL++ ``-Q`` execs the ``afl-qemu-trace`` it finds via ``AFL_PATH``. To fuzz
    a cross-arch target we point ``AFL_PATH`` at a dir holding the per-arch trace
    under that exact name. Returns the dir (for ``AFL_PATH``) or None."""
    trace = trace or afl_qemu_trace_path(cpu)
    if trace is None:
        return None
    d = near / f".aflpath-{cpu}"
    d.mkdir(parents=True, exist_ok=True)
    link = d / "afl-qemu-trace"
    try:
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(Path(trace).resolve())
    except OSError:
        shutil.copy2(trace, link)
    return str(d)


def afl_cc() -> str | None:
    for cc in ("afl-clang-fast", "afl-clang-lto", "afl-gcc-fast", "afl-gcc"):
        resolved = shutil.which(cc)
        if resolved:
            return resolved
    return None


# --- the AFL ``-t`` ceiling (#320) ------------------------------------------
#
# Passing NO ``-t`` is not "use the default 1000 ms" — it is a different code
# path. `perform_dry_run()` branches on `afl->timeout_given` (afl-fuzz-init.c:932,
# 4.09c), and with no ``-t`` a seed that exceeds the ceiling is FATAL:
#
#     PROGRAM ABORT : Test case '...' results in a timeout
#
# One slow input therefore kills the whole campaign before a single mutation
# runs — the magma seed corpora are real test suites, so this is the normal case,
# not an edge case. With ANY ``-t`` the same seed is merely dropped:
#
#     WARNING: Test case results in a timeout (skipping)
#
# NOT ``-t N+``. The ``+`` suffix is NOT what enables the skip — 4.09c's own
# comment on that branch is "The '+' meaning has been changed!", and the
# condition is a bare `afl->timeout_given`, true for both forms. What ``+``
# additionally does is overwrite the ceiling after the dry run with the slowest
# surviving seed's `exec_us` (afl-fuzz.c:2448) — MICROSECONDS assigned into a
# MILLISECOND field. Measured on bench (AFL++ 4.09c, seeds of 0.35 s and 3 s):
#
#     -t 1000    exec_timeout=1000 ms       35.13 execs/s   1 seed skipped
#     -t 1000+   exec_timeout=350573 ms      1.33 execs/s   1 seed skipped
#     -t 5000+   exec_timeout=3000559 ms    32.73 execs/s   0 seeds skipped
#
# ``-t 1000+`` costs 26x throughput for exactly the same corpus, because a slow
# mutant is no longer killed at 1 s but at ~6 minutes. Use the plain form.
EXEC_TIMEOUT_MS = 1000
# QEMU-mode needs its own ceiling. ``-t`` is both the per-exec kill and the
# dry-run admission bar, and afl-fuzz does NOT scale it for ``-Q`` (the only
# derived value is the forkserver handshake, `init_tmout = exec_tmout *
# FORK_WAIT_MULT`), so a native-tuned 1000 ms under ``-Q`` silently rejects
# seeds that are perfectly fine natively. Measured native-vs-``-Q`` per-exec
# cost on bench for the same workload at four scales: 3.08x, 3.13x, 2.55x,
# 1.53x — and that is a tight arithmetic loop, the friendliest possible case
# for the JIT; real binary-only targets carry cold code and syscalls and do
# worse. 5x the native ceiling keeps the admitted seed set the same across both
# lanes with margin over the worst ratio observed.
QEMU_EXEC_TIMEOUT_MS = 5000


# --- config + result --------------------------------------------------------

@dataclass
class AflConfig:
    duration_s: int = 60
    cmplog: bool = True
    qemu_mode: bool = False
    qemu_arch: str = ""             # canonical arch for cross-arch -Q (#19); "" = host
    file_input: bool = False        # deliver the testcase as a FILE arg (``@@``)
                                    # instead of stdin — for libFuzzer/ARVO-style
                                    # targets that read argv[1] (not stdin).
    use_asan: bool = True
    persistent: bool = True
    dict_tokens: list[str] = field(default_factory=list)
    seeds: list[bytes] = field(default_factory=list)
    stop_on_crash: bool = True
    memory_limit: str = "none"      # AFL -m; "none" for ASAN builds
    rand_seed: int = 0              # AFL_RAND_SEED — pin the fuzzer PRNG so a
                                    # discovery run is reproducible (not wall-clock
                                    # seeded); overridable via extra_env.
    extra_env: dict[str, str] = field(default_factory=dict)
    hard_timeout_s: float | None = None  # canonical run deadline cap


def exec_timeout_ms(config: AflConfig) -> int:
    """The AFL ``-t`` ceiling for this lane. Derived from ``qemu_mode`` rather
    than configured: it is a property of how the target is executed, not a
    per-run choice, and a knob here would only let a caller set the wrong one."""
    return QEMU_EXEC_TIMEOUT_MS if config.qemu_mode else EXEC_TIMEOUT_MS


@dataclass
class FuzzResult:
    crashes: list[bytes] = field(default_factory=list)
    crash_files: list[str] = field(default_factory=list)
    execs: int = 0
    execs_per_sec: float = 0.0
    saved_crashes: int = 0
    timed_out: bool = False
    seeds_total: int = 0    # seeds handed to afl-fuzz
    seeds_skipped: int = 0  # of those, dropped by the dry run (too slow / crashing)
    note: str = ""
    cmd: list[str] = field(default_factory=list)

    @property
    def found_crash(self) -> bool:
        return bool(self.crashes)

    @property
    def corpus_lost(self) -> bool:
        """True when the dry run dropped ANY seed. ``-t`` turns a loud FATAL into
        a silent skip, which is better but still a quiet loss of corpus — the
        failure family of #296/#297/#304. Callers that report a zero should say
        how much corpus the zero was measured on."""
        return self.seeds_skipped > 0


# --- seed / dictionary strategy (from slice constants) ----------------------

_C_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
_HEX_CONST = re.compile(r"\b0x([0-9a-fA-F]{2,8})\b")


_FORMAT_FIELD_RE = re.compile(
    r"(?:->|\.)\s*([a-zA-Z_][a-zA-Z0-9_]*(?:_[a-zA-Z0-9_]+)*)\s*(?:=|\[)",
)
_FORMAT_FIELD_NAMES = frozenset({
    "width", "height", "length", "count", "offset", "size",
    "chunk_size", "num_components", "components", "color_space",
    "samples_per_pixel", "bit_depth", "compression", "strip_offset",
    "rows_per_strip", "image_width", "image_length", "sample_format",
    "bits_per_sample", "photometric", "orientation", "x_resolution",
    "y_resolution", "resolution_unit", "planar_configuration",
    "predictor", "tile_width", "tile_length", "tile_offsets",
    "tile_byte_counts", "subfile_type", "fill_order",
    "new_subfile_type", "page_number", "document_name",
    "icc_profile", "icc_size", "exif_ifd", "gps_ifd",
    "make", "model", "software", "datetime", "artist",
    "header_size", "data_size", "payload_size", "total_size",
    "num_entries", "num_records", "version", "magic",
    "block_size", "block_count", "stride", "pitch",
    "data_offset", "index", "id", "type", "flags",
})


def format_field_tokens(*texts: str) -> list[str]:
    """Extract format-specific field names (width, height, chunk_size, ...) from
    decompiled C by finding struct-member assignments. These feed the AFL++
    dictionary so the fuzzer targets the right bytes in a structured container."""
    seen: set[str] = set()
    out: list[str] = []
    for text in texts:
        for m in _FORMAT_FIELD_RE.finditer(text):
            name = m.group(1)
            if name in _FORMAT_FIELD_NAMES and name not in seen:
                seen.add(name)
                out.append(name)
    return out


def tokens_from_context(*texts: str) -> list[str]:
    """Pull string literals from decompiled C (the slice's constants) to seed an
    AFL dictionary — magic headers like ``"REC0"`` become tokens CMPLOG/the dict
    drive the fuzzer past. Deduped, order-stable."""
    out: list[str] = []
    seen: set[str] = set()
    for text in texts:
        for m in _C_STRING.finditer(text):
            tok = m.group(1)
            if tok and tok not in seen and len(tok) >= 2:
                seen.add(tok)
                out.append(tok)
    return out


def seeds_from_tokens(tokens: list[str]) -> list[bytes]:
    """Turn dictionary tokens into starter seeds (a magic header + padding gives
    the fuzzer a foothold past the gate even before CMPLOG kicks in)."""
    seeds: list[bytes] = []
    for tok in tokens:
        raw = tok.encode("latin-1", "replace")
        seeds.append(raw + b"\x00" + b"A" * 64)
    return seeds


def seeds_from_files(paths: str | list[str], *, max_files: int = 64,
                     max_bytes: int = 1 << 20) -> list[bytes]:
    """Read REAL structured inputs (valid JPEG/EXIF/RTF/… files) into AFL starter
    seeds. Token-derived seeds can build a magic header but not a whole valid
    container, so a coverage-guided fuzzer never reaches a format-specific parser
    sink from them; a handful of real files give it a foothold deep in the parser.
    ``paths`` is a file, a directory (all files in it), or a list of either.
    Bounded in count and per-file size."""
    items = [paths] if isinstance(paths, str) else list(paths)
    files: list[Path] = []
    for raw in items:
        p = Path(raw)
        if p.is_dir():
            files += sorted(c for c in p.iterdir() if c.is_file())
        elif p.is_file():
            files.append(p)
    seeds: list[bytes] = []
    for fp in files[:max_files]:
        try:
            b = fp.read_bytes()[:max_bytes]
        except OSError:
            continue
        if b:
            seeds.append(b)
    return seeds


def env_seed_files() -> list[bytes]:
    """Opt-in structured seed corpus from ``ZEROVERSE_SEED_DIR`` (a dir or an
    ``os.pathsep``-separated list of dirs/files). Empty when unset — the default
    path is unchanged."""
    v = os.environ.get("ZEROVERSE_SEED_DIR", "").strip()
    return seeds_from_files(v.split(os.pathsep)) if v else []


def initial_seeds(tokens: list[str]) -> list[bytes]:
    """AFL starter corpus: opt-in real structured file seeds (ZEROVERSE_SEED_DIR)
    FIRST, then the token-derived seeds. Never empty (falls back to a NUL byte)."""
    return env_seed_files() + (seeds_from_tokens(tokens) or [b"\x00"])


def _dict_escape(tok: str) -> str:
    out: list[str] = []
    for ch in tok.encode("latin-1", "replace"):
        if 0x20 <= ch < 0x7F and ch not in (0x22, 0x5C):
            out.append(chr(ch))
        else:
            out.append(f"\\x{ch:02x}")
    return "".join(out)


def write_dict_file(tokens: list[str], path: Path) -> Path | None:
    if not tokens:
        return None
    lines = [f'tok_{i}="{_dict_escape(t)}"' for i, t in enumerate(tokens)]
    path.write_text("\n".join(lines) + "\n")
    return path


# --- backend protocol + fakes ----------------------------------------------

class AflBackend(Protocol):
    def fuzz(
        self,
        fuzz_bin: Path,
        *,
        in_dir: Path,
        out_dir: Path,
        config: AflConfig,
        cmplog_bin: Path | None = None,
    ) -> FuzzResult: ...


class FakeAfl:
    """Deterministic, AFL-free backend for tests: it 'finds' the crashes it was
    constructed with (and writes them to the crash dir so the collection path is
    exercised)."""

    def __init__(self, crashes: list[bytes]) -> None:
        self._crashes = crashes

    def fuzz(
        self,
        fuzz_bin: Path,
        *,
        in_dir: Path,
        out_dir: Path,
        config: AflConfig,
        cmplog_bin: Path | None = None,
    ) -> FuzzResult:
        cdir = out_dir / "default" / "crashes"
        cdir.mkdir(parents=True, exist_ok=True)
        files: list[str] = []
        for i, c in enumerate(self._crashes):
            f = cdir / f"id:{i:06d},sig:06,fake"
            f.write_bytes(c)
            files.append(str(f))
        return FuzzResult(
            crashes=list(self._crashes), crash_files=files, execs=1000,
            execs_per_sec=1000.0, saved_crashes=len(self._crashes),
            note="fake-afl", cmd=["fake-afl"],
        )


# --- real subprocess driver -------------------------------------------------

def _collect_crashes(out_dir: Path) -> tuple[list[bytes], list[str]]:
    crashes: list[bytes] = []
    files: list[str] = []
    candidates = [out_dir / "default" / "crashes", out_dir / "crashes"]
    seen: set[str] = set()
    for cdir in candidates:
        if not cdir.is_dir():
            continue
        for f in sorted(cdir.glob("id:*")):
            if f.name in seen:
                continue
            seen.add(f.name)
            try:
                crashes.append(f.read_bytes())
                files.append(str(f))
            except OSError:
                continue
    return crashes, files


def _parse_stats(out_dir: Path) -> dict[str, str]:
    stats: dict[str, str] = {}
    for sf in (out_dir / "default" / "fuzzer_stats", out_dir / "fuzzer_stats"):
        if not sf.is_file():
            continue
        for line in sf.read_text().splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                stats[k.strip()] = v.strip()
        break
    return stats


def _piped_core_pattern() -> str:
    """The kernel core handler when it is a USERSPACE PIPE (apport, systemd-coredump).

    AFL normally refuses to start against one, because a piped handler makes the
    target hang instead of dying on the first crash — the forkserver blocks in
    `pipe_read` and the campaign silently stops making progress. We set
    `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES` to keep CI hosts usable, which turns
    that loud refusal into a silent stall. `SubprocessAfl.fuzz` therefore makes
    it a hard refusal for the instrumented lane (#312) instead of assuming a
    usable host. Fix on the host with `sysctl -w kernel.core_pattern=core`, and
    persist it in `/etc/sysctl.d/` so a reboot cannot silently reintroduce it."""
    try:
        pattern = Path("/proc/sys/kernel/core_pattern").read_text().strip()
    except OSError:
        return ""
    return pattern if pattern.startswith("|") else ""


# afl-fuzz's own dry-run rejection tally, emitted once after `perform_dry_run()`
# (afl-fuzz-init.c:1260). Parsed rather than inferred: afl-fuzz is the only thing
# that knows which seeds its forkserver actually admitted. Note that it counts
# timeouts AND dry-run crashes together, so the note must not call them all slow.
# Verified on bench that this goes to STDOUT, not stderr — we scan both anyway.
_SKIPPED_SEEDS_RE = re.compile(rb"Skipped\s+(\d+)\s+test cases?\s+\([0-9.]+%\)")
# The all-seeds-rejected FATAL (afl-fuzz-init.c:1256): afl-fuzz refuses to fuzz
# nothing, exits non-zero, and writes no fuzzer_stats.
_ALL_SEEDS_REJECTED = b"All test cases time out or crash"


def _parse_skipped_seeds(*raws: bytes | None) -> int:
    """Seeds afl-fuzz dropped during the dry run, per its own tally."""
    for raw in raws:
        if not raw:
            continue
        m = _SKIPPED_SEEDS_RE.search(raw)
        if m:
            return int(m.group(1))
    return 0


def _all_seeds_rejected(*raws: bytes | None) -> bool:
    return any(raw and _ALL_SEEDS_REJECTED in raw for raw in raws)


def _afl_abort_reason(raw: bytes | None) -> str:
    """The first meaningful line of an afl-fuzz startup abort, for the note."""
    if not raw:
        return ""
    text = raw.decode("utf-8", "replace")
    for marker in ("PROGRAM ABORT :", "[-] "):
        idx = text.find(marker)
        if idx >= 0:
            return text[idx + len(marker):].splitlines()[0].strip()[:200]
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return lines[-1][:200] if lines else ""


class SubprocessAfl:
    """The real AFL++ driver using tool paths resolved before the fuzz stage."""

    def __init__(
        self,
        *,
        afl_path: str | None = None,
        qemu_path: str | None = None,
        resolved: bool = False,
        execution_authorized: bool | None = None,
    ) -> None:
        self.afl_path = afl_path if resolved else (afl_path or afl_fuzz_path())
        self.qemu_path = qemu_path
        self.execution_authorized = execution_authorized

    def fuzz(
        self,
        fuzz_bin: Path,
        *,
        in_dir: Path,
        out_dir: Path,
        config: AflConfig,
        cmplog_bin: Path | None = None,
    ) -> FuzzResult:
        authorized = self.execution_authorized
        if authorized is None:
            authorized = isinstance(current_executor(), LocalExecutor)
        if not authorized:
            return FuzzResult(note="AFL execution disabled by selected execution boundary")
        if self.afl_path is None:
            return FuzzResult(note="afl-fuzz not available in resolved run plan")
        if config.qemu_mode and self.qemu_path is None:
            which = config.qemu_arch or "host"
            return FuzzResult(
                note=f"QEMU-mode requested but afl-qemu-trace ({which}) is missing "
                "(build it via CPU_TARGET=<cpu> AFLplusplus/build_qemu_support.sh); "
                "Frida-mode (-O) is the cross-platform fallback"
            )
        # #312 — REFUSE the instrumented lane on a host with a piped core handler
        # rather than discovering it from a timeout. AFL++ aborts on its own here;
        # `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES` below (needed so a shared CI host
        # stays usable) downgrades that abort to a silent stall that reports as
        # "fuzzed the window, found nothing" — a clean-looking zero, the exact
        # failure family as #296/#297/#304. Refusing costs one run; a silent stall
        # costs a whole benchmark and is indistinguishable from a real negative.
        piped_pattern = _piped_core_pattern()
        if piped_pattern and not config.qemu_mode:
            return FuzzResult(
                note="REFUSED: kernel.core_pattern is a USERSPACE PIPE "
                f"({piped_pattern[:80]}), which swallows the crashes afl-fuzz must "
                "observe and stalls the forkserver instead of failing. Fix the host "
                "with `sysctl -w kernel.core_pattern=core` and persist it in "
                "/etc/sysctl.d/60-afl.conf",
            )
        in_dir.mkdir(parents=True, exist_ok=True)
        out_dir.mkdir(parents=True, exist_ok=True)

        # Cross-arch -Q: point AFL_PATH at the per-arch afl-qemu-trace (#19).
        planned_afl_path: str | None = None
        if config.qemu_mode:
            cpu = _cpu_target(config.qemu_arch) if config.qemu_arch else _cpu_target(host_arch())
            planned_afl_path = _prepare_cross_afl_path(
                cpu,
                out_dir.parent,
                self.qemu_path,
            )

        seeds = config.seeds or [b"\x00"]
        for i, s in enumerate(seeds):
            (in_dir / f"seed_{i:04d}").write_bytes(s or b"\x00")

        cmd: list[str] = [
            self.afl_path, "-i", str(in_dir), "-o", str(out_dir),
            "-m", config.memory_limit, "-V", str(config.duration_s),
            # #320 — an EXPLICIT ``-t``. Omitting it does not select the default
            # ceiling, it selects the abort-on-slow-seed dry run; see
            # EXEC_TIMEOUT_MS for why this is the plain form and not ``-t N+``.
            "-t", str(exec_timeout_ms(config)),
        ]
        if config.qemu_mode:
            cmd.append("-Q")
        if config.cmplog and cmplog_bin is not None:
            cmd += ["-c", str(cmplog_bin)]
        elif config.cmplog and config.qemu_mode:
            # QEMU-mode has no separate instrumented binary, so CMPLOG/redqueen
            # runs against the target itself (-c 0) — this is what cracks magic
            # gates (e.g. a 4-byte header) in a binary-only run with no dictionary.
            cmd += ["-c", "0"]
        dpath = write_dict_file(config.dict_tokens, in_dir.parent / "tokens.dict")
        if dpath is not None:
            cmd += ["-x", str(dpath)]
        cmd += ["--", str(fuzz_bin)]
        if config.file_input:
            # ``@@`` — AFL writes each testcase to a file and substitutes its path
            # here, matching a libFuzzer/ARVO driver that reads argv[1] (the magma
            # source lane uses ``-- $BIN @@``). Without it AFL feeds stdin, which
            # such a driver ignores.
            cmd.append("@@")

        env = {
            **os.environ,
            "AFL_SKIP_CPUFREQ": "1",
            "AFL_NO_AFFINITY": "1",
            "AFL_NO_UI": "1",
            "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
            # #313 — kill the FORK SERVER with SIGKILL, not AFL++ >= 4.09's default
            # SIGTERM. A prebuilt OSS-Fuzz/magma driver carries the afl-compiler-rt
            # it was BUILT with, and the older runtime's SIGTERM handler only kills
            # the current child and RETURNS — disassembly of the magma libpng driver
            # (`at_exit`, afl-compiler-rt.o.c:151) is `kill(child_pid, 9); ret`, with
            # no `_exit`, where the 4.09c runtime ends in `_exit(0)`. The fork server
            # therefore survives SIGTERM, goes straight back to blocking on the
            # control pipe, and afl-fuzz deadlocks in `waitpid(fsrv_pid)`: campaign
            # over, `execs_done` frozen, the rest of the window burned to the hard
            # timeout. SIGKILL is AFL's own pre-4.09 behaviour and cannot be ignored.
            # (`extra_env` is merged last, so an operator can still override it.)
            "AFL_FORK_SERVER_KILL_SIGNAL": "9",
            # Pin the fuzzer PRNG so the mutation stream is reproducible run-to-run
            # (wall-clock/PID seeding is a source of confirm nondeterminism when the
            # fuzz complement runs). Time budget still bounds coverage, but the same
            # seed corpus explores the same path order each run.
            "AFL_RAND_SEED": str(config.rand_seed),
            **config.extra_env,
        }
        if planned_afl_path is not None:
            env["AFL_PATH"] = planned_afl_path
        if config.stop_on_crash:
            env["AFL_BENCH_UNTIL_CRASH"] = "1"

        timed_out = False
        proc: subprocess.CompletedProcess[bytes] | None = None
        out_raw: bytes | None = None
        err_raw: bytes | None = None
        try:
            # argv list, shell=False: every element is a literal flag, the
            # plan-resolved afl_path, or an internally-constructed Path
            # (in_dir/out_dir/fuzz_bin/cmplog_bin/tokens.dict). Nothing here is
            # user-supplied shell text, and execve passes metacharacters
            # literally. Same shape as benchmarks/magma/run.py:249.
            proc = subprocess.run(  # foxguard: ignore[py/no-command-injection]
                cmd, env=env, capture_output=True,
                timeout=(
                    config.hard_timeout_s
                    if config.hard_timeout_s is not None
                    else config.duration_s + 60
                ),
            )
        except subprocess.TimeoutExpired as e:
            timed_out = True
            # The dry-run tally is printed at STARTUP, so a run that later hits
            # the hard timeout still reported how much corpus it dropped. Keep
            # the partial output instead of discarding it with the exception.
            out_raw, err_raw = e.stdout, e.stderr
        except OSError as e:
            return FuzzResult(note=f"afl-fuzz failed: {e}", cmd=cmd)
        if proc is not None:
            out_raw, err_raw = proc.stdout, proc.stderr

        crashes, files = _collect_crashes(out_dir)
        stats = _parse_stats(out_dir)
        note = "qemu-mode" if config.qemu_mode else "instrumented"
        seeds_skipped = _parse_skipped_seeds(out_raw, err_raw)
        # An afl-fuzz that ABORTS at startup (missing @@, bad -o, instrumentation
        # not found) writes no fuzzer_stats and exits non-zero. Swallowing that
        # reads identically to "fuzzed the whole budget and found nothing", which
        # is how a broken lane emits a clean-looking zero (#304/#297). Say so.
        if timed_out:
            piped = _piped_core_pattern()
            if piped:
                note = (
                    f"{note}; afl-fuzz hit the hard timeout with a PIPED "
                    f"core_pattern ({piped[:80]}) — the forkserver hangs on the "
                    "first crash; run `sysctl -w kernel.core_pattern=core`"
                )
        if proc is not None and proc.returncode != 0 and not stats:
            abort = _afl_abort_reason(err_raw) or _afl_abort_reason(out_raw)
            note = (
                f"afl-fuzz exited {proc.returncode} without producing fuzzer_stats"
                + (f": {abort}" if abort else "")
            )
        # #320 — a campaign whose ENTIRE corpus was rejected fuzzed nothing. That
        # is a failed run, not a clean zero, so lead the note with it rather than
        # leaving it as a generic non-zero exit. afl-fuzz FATALs here on its own
        # (afl-fuzz-init.c:1256), which is the loud behaviour we want to keep.
        if _all_seeds_rejected(out_raw, err_raw):
            seeds_skipped = len(seeds)
            note = (
                f"FAILED: afl-fuzz rejected ALL {len(seeds)} seed(s) during the dry "
                f"run (each one exceeded -t {exec_timeout_ms(config)}ms or crashed) "
                "and gave up — this run fuzzed nothing, it is not a zero"
            )
        # ``-t`` trades the dry-run FATAL for a SILENT skip. Better, but still a
        # quiet loss of corpus (#296/#297/#304), and a run that dropped half its
        # seeds must not read the same as one that kept them all. Say how many.
        elif seeds_skipped:
            note = (
                f"{note}; DROPPED {seeds_skipped}/{len(seeds)} seed(s) in the dry "
                f"run (slower than -t {exec_timeout_ms(config)}ms, or crashing) — "
                "coverage below is measured on the surviving corpus only"
            )
        return FuzzResult(
            crashes=crashes,
            crash_files=files,
            execs=int(stats.get("execs_done", "0") or 0),
            execs_per_sec=float(stats.get("execs_per_sec", "0") or 0.0),
            saved_crashes=int(stats.get("saved_crashes", "0") or 0),
            timed_out=timed_out,
            seeds_total=len(seeds),
            seeds_skipped=seeds_skipped,
            note=note,
            cmd=cmd,
        )


# --- compile helpers: build the fuzz/cmplog/replay binaries -----------------

@dataclass
class CompiledTarget:
    fuzz_bin: Path                  # afl-instrumented (+ASAN) — the fuzz target
    replay_bin: Path                # plain gcc — for oracle / native replay
    cmplog_bin: Path | None = None  # AFL_LLVM_CMPLOG build
    note: str = ""


def _compile(
    cc: str, args: list[str], *, env_extra: dict[str, str], timeout: float = 120.0
) -> tuple[bool, str]:
    env = {**os.environ, **env_extra}
    try:
        p = subprocess.run(
            [cc, *args], env=env, capture_output=True, timeout=timeout, check=False
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"{type(e).__name__}: {e}"
    return p.returncode == 0, p.stderr.decode("utf-8", "replace")


def build_fuzz_binaries(
    harness_src: str,
    target_sources: list[Path],
    workdir: Path,
    *,
    config: AflConfig,
    cflags: tuple[str, ...] = ("-O0",),
    link_libs: tuple[str, ...] = (),
    compiler_path: str | None = None,
    native_compiler_path: str | None = None,
    compiler_resolved: bool = False,
    deadline_monotonic: float | None = None,
) -> CompiledTarget | None:
    """Compile the harness + target source into the three binaries the fuzz loop
    needs: an AFL-instrumented (ASAN) fuzz target, an ``AFL_LLVM_CMPLOG`` target,
    and a plain replay target for the oracle. Returns ``None`` if either planned
    compiler is unavailable or any build fails. ``link_libs`` supports generated
    runtime-link harnesses (for example ``-ldl``)."""
    cc = compiler_path if compiler_resolved else (compiler_path or afl_cc())
    native_cc = (
        native_compiler_path
        if compiler_resolved
        else native_compiler_path
        or shutil.which("cc")
        or shutil.which("gcc")
        or shutil.which("clang")
    )
    if cc is None or native_cc is None:
        return None
    workdir.mkdir(parents=True, exist_ok=True)
    hsrc = workdir / "harness.c"
    hsrc.write_text(harness_src)

    def compile_timeout() -> float:
        if deadline_monotonic is None:
            return 120.0
        return max(0.0, deadline_monotonic - time.monotonic())

    asan = {"AFL_USE_ASAN": "1"} if config.use_asan else {}
    srcs = [str(s) for s in target_sources]

    fuzz_bin = workdir / "harness_afl"
    timeout = compile_timeout()
    if timeout <= 0:
        return None
    ok, _ = _compile(
        cc,
        [*cflags, str(hsrc), *srcs, *link_libs, "-o", str(fuzz_bin)],
        env_extra=asan,
        timeout=timeout,
    )
    if not ok:
        return None

    cmplog_bin: Path | None = None
    if config.cmplog:
        cmplog_bin = workdir / "harness_cmplog"
        timeout = compile_timeout()
        if timeout <= 0:
            return None
        ok, _ = _compile(
            cc, [*cflags, str(hsrc), *srcs, *link_libs, "-o", str(cmplog_bin)],
            env_extra={**asan, "AFL_LLVM_CMPLOG": "1"},
            timeout=timeout,
        )
        if not ok:
            cmplog_bin = None

    replay_bin = workdir / "harness_replay"
    timeout = compile_timeout()
    if timeout <= 0:
        return None
    ok, _ = _compile(
        native_cc,
        [*cflags, str(hsrc), *srcs, *link_libs, "-o", str(replay_bin)],
        env_extra={},
        timeout=timeout,
    )
    if not ok:
        return None

    return CompiledTarget(
        fuzz_bin=fuzz_bin, replay_bin=replay_bin, cmplog_bin=cmplog_bin,
        note=f"asan={'on' if config.use_asan else 'off'} cmplog={cmplog_bin is not None}",
    )

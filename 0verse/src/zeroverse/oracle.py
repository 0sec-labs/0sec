"""Open verification oracles — the unit of truth.

Reimplemented from pwnkit *concepts* (never its code/prompts; see INTEGRATION.md),
these are the deterministic, externally-checkable proofs that turn a hypothesis
into a finding:

  * differential crash oracle  — target crashes, control stays clean
  * differential-allocator oracle — re-run a crash under a stock vs a guard
    allocator; a silent overflow that only faults under the guard is a real heap
    bug, pinned to the faulting instruction (the no-sanitizer crown jewel)
  * CASR wrapper — shell out to ``casr-gdb`` (+ ``casr-cluster``) for native
    signal / fault-address / PC exploitability classification and backtraces
  * canary-marker capability oracle — credit a capability only on a token-bound
    marker, closing the replay / echoed-intent / no-witness false-confirm vectors
  * crash dedup — ClusterFuzz-style stack-state bucketing
  * suspected-known dedup vs a *public* advisory list (OSV/GHSA), offline by
    default — never auto-dismiss, only flag

No LLM and no network here by design: an LLM never adjudicates whether a bug is real.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .sandbox_exec import Executor, LocalExecutor, MsbSshExecutor, current_executor

if TYPE_CHECKING:
    from .preflight import BudgetTracker
from .report import PoV

# --- capability ladder + canary-marker oracle ------------------------------

# Generic memory-safety capability ladder (low -> high). A run is credited the
# highest rung whose token-bound marker appears.
LADDER: tuple[str, ...] = (
    "attempted",
    "reached-sink",
    "crash",
    "oob-read",
    "oob-write",
    "controlled-pc",
)
MARKER_PREFIX = "0VERSE-CANARY"


def new_canary() -> str:
    """A unique per-run token (unpredictable → defeats stale/replayed output)."""
    return os.urandom(8).hex()


def marker_line(canary: str, rung: str) -> str:
    """The exact line a PoC must emit to claim `rung`. Printed only *after* the
    capability actually lands — never on mere intent."""
    if rung not in LADDER:
        raise ValueError(f"unknown rung {rung!r}")
    return f"{MARKER_PREFIX}:{canary}:{rung}"


@dataclass
class CapabilityVerdict:
    canary: str
    highest_rung: str | None          # None = nothing proven
    rungs_seen: list[str] = field(default_factory=list)

    @property
    def proven(self) -> bool:
        return self.highest_rung is not None


def adjudicate_capability(output: bytes | str, canary: str) -> CapabilityVerdict:
    """Scan PoC output for token-bound markers and return the highest rung proven.

    Guards: only markers carrying *this run's* canary count (replay/stale guard);
    an unknown rung tag is ignored; absence of any marker => nothing proven.
    """
    text = output.decode("utf-8", "replace") if isinstance(output, bytes) else output
    pat = re.compile(rf"{re.escape(MARKER_PREFIX)}:{re.escape(canary)}:([a-z\-]+)")
    seen = [r for r in pat.findall(text) if r in LADDER]
    highest = max(seen, key=LADDER.index) if seen else None
    # de-dup + ladder-order the seen rungs for reporting
    ordered = sorted(set(seen), key=LADDER.index)
    return CapabilityVerdict(canary=canary, highest_rung=highest, rungs_seen=ordered)


# --- differential crash oracle ---------------------------------------------

@dataclass
class RunResult:
    crashed: bool
    signal: str = ""          # e.g. SIGSEGV, SIGABRT
    sanitizer: str = ""       # e.g. AddressSanitizer
    stderr: str = ""
    provenance: dict[str, str] = field(default_factory=dict)
    valid: bool = True
    timed_out: bool = False
    infrastructure_error: str = ""


def differential_confirmed(target: RunResult, control: RunResult) -> bool:
    """A PoV is confirmed only when it crashes the target but NOT the control
    (mirrors AIxCC's delta check / pwnkit's differential oracle)."""
    return target.valid and control.valid and target.crashed and not control.crashed


# heuristic crash-signal classification from sanitizer/stderr text
def classify_crash(stderr: str) -> str:
    s = stderr.lower()
    if "heap-buffer-overflow" in s and "write" in s:
        return "oob-write"
    if "stack-buffer-overflow" in s:
        return "oob-write"
    if "heap-buffer-overflow" in s or "global-buffer-overflow" in s:
        return "oob-read"
    if "use-after-free" in s:
        return "uaf"
    if "sigsegv" in s or "segv" in s or "segmentation fault" in s:
        return "crash"
    if "sigabrt" in s or "abort" in s:
        return "crash"
    return "unknown"


# --- crash dedup (ClusterFuzz-style stack-state bucketing) ------------------

# strip addresses (0x..), offsets (+0x.. / +NN), and :line numbers
_FRAME_NOISE = re.compile(r"\+?0x[0-9a-fA-F]+|\+\d+|:\d+")


def crash_state(frames: list[str], *, top_n: int = 5) -> tuple[str, ...]:
    """Normalize the top N backtrace frames into a stable signature (strip
    addresses/offsets/line numbers so the same bug buckets together)."""
    out: list[str] = []
    for fr in frames[:top_n]:
        out.append(_FRAME_NOISE.sub("", fr).strip())
    return tuple(out)


def dedup_key(sanitizer: str, frames: list[str]) -> str:
    return repr((sanitizer, crash_state(frames)))


class CrashSet:
    """Tracks seen crashes; ``add`` returns True only the first time a bucket is
    seen, so duplicate crashes never reach the (expensive) downstream stages."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def add(self, sanitizer: str, frames: list[str]) -> bool:
        key = dedup_key(sanitizer, frames)
        if key in self._seen:
            return False
        self._seen.add(key)
        return True


# --- native execution helper (no sanitizers, no LLM) -----------------------

_SIGNALS = {-11: "SIGSEGV", -6: "SIGABRT", -4: "SIGILL", -8: "SIGFPE", -7: "SIGBUS"}


def _exec(
    binary: str,
    *,
    env: dict[str, str] | None = None,
    argv: list[str] | None = None,
    stdin: bytes = b"",
    timeout: float = 10.0,
    executor: Executor | None = None,
) -> RunResult:
    """Run the target once and classify the outcome by native signal. Executing
    the analysis target is the entire point of the dynamic stage.

    Routed through the configured executor (:mod:`sandbox_exec`): native
    an explicitly trusted subprocess with ``ZEROVERSE_EXECUTOR=local`` or an
    ephemeral microsandbox on a remote KVM host with ``ZEROVERSE_EXECUTOR=msb``.
    With no selection, execution fails closed. An infrastructure failure is reported
    like the historical ``OSError`` — non-crash, error text in ``stderr``."""
    selected_executor = executor or current_executor()
    res = selected_executor.run(
        [binary, *(argv or [])], stdin=stdin, env=env, timeout=timeout,
    )
    if res.timed_out:
        return RunResult(
            crashed=False,
            signal="",
            stderr="timeout",
            provenance=res.provenance,
            valid=False,
            timed_out=True,
        )
    if res.error:
        return RunResult(
            crashed=False,
            signal="",
            stderr=res.error,
            provenance=res.provenance,
            valid=False,
            infrastructure_error=res.error,
        )
    sig = _SIGNALS.get(res.returncode, "")
    return RunResult(
        crashed=res.returncode < 0,
        signal=sig,
        stderr=res.stderr,
        provenance=res.provenance,
    )


# --- sanitizer (ASan/UBSan) crash oracle + file-input vector ----------------
#
# The native ``_exec`` oracle above classifies a crash by *signal* (rc < 0). A
# target built with ``-fsanitize=address`` (the libFuzzer/ARVO/OSS-Fuzz shape)
# does NOT raise a signal: AddressSanitizer prints its report and, by default on
# Linux, ``_exit(1)`` — a non-zero *exit code*. So the sanitizer analogue of a
# crash is "non-zero exit AND stderr carries a sanitizer report". These targets
# also take their input as a FILE whose path is argv[1] (``./target /poc``), not
# on stdin — hence the file vector here.

# The report banners the task keys on. Presence of any of these in stderr is a
# sanitizer *diagnostic*; the ERROR line additionally names the bug kind.
_SANITIZER_ERROR_MARKERS: tuple[str, ...] = (
    "ERROR: AddressSanitizer",
    "SUMMARY: AddressSanitizer",
    "WARNING: MemorySanitizer",  # MSan uninitialized read (-fsanitize=memory)
    "SUMMARY: MemorySanitizer",
    "runtime error:",            # UBSan (-fsanitize=undefined)
    "ERROR: UndefinedBehaviorSanitizer",  # UBSan DEADLYSIGNAL (SEGV/BUS intercept)
)
# A LeakSanitizer report ("SUMMARY: AddressSanitizer: N byte(s) leaked") is a
# memory *leak*, not the out-of-bounds/UAF we hunt — a libFuzzer run routinely
# reports a corpus leak. Never mistake it for a memory-safety crash.
_LEAK_MARKERS: tuple[str, ...] = (
    "ERROR: LeakSanitizer", "detected memory leaks", "byte(s) leaked",
)
# The kind token off the hard-error line (heap-buffer-overflow, use-after-free,
# stack-buffer-overflow, ...). Anchored on ``ERROR: AddressSanitizer:`` and a
# leading letter so a SUMMARY leak line ("... 40 byte(s) leaked") never matches.
_ASAN_ERROR_RE = re.compile(r"ERROR: AddressSanitizer:\s*([a-z][a-z0-9\-]*)")
# MemorySanitizer names its kind on a WARNING/SUMMARY line (no ``ERROR:`` banner):
#   ``WARNING: MemorySanitizer: use-of-uninitialized-value``. Same shape either way.
_MSAN_ERROR_RE = re.compile(r"MemorySanitizer:\s*([a-z][a-z0-9\-]*)")
# UBSan prints ``<file>:<line>: runtime error: <phrase>[: <detail>]`` — the <phrase>
# (e.g. "signed integer overflow") is the specific undefined behavior. We hyphenate
# it into a token that :func:`~zeroverse.adjudicate.crash_to_cwe` recognizes
# ("signed-integer-overflow" contains "integer-overflow" -> CWE-190; "load of null
# pointer" -> contains "null" -> CWE-476), instead of the class-less "undefined-behavior".
_UBSAN_ERROR_RE = re.compile(r"runtime error:\s*([^\n:]+)")
# UBSan intercepting a fatal signal (-fsanitize=undefined traps a SEGV/BUS/ILL
# and reports it instead of a ``runtime error:`` line):
#   ``UndefinedBehaviorSanitizer:DEADLYSIGNAL``
#   ``==N==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x...``
# Without this branch the whole report fell through EVERY detector above (no
# ``runtime error:`` phrase, no ASan banner), so a UBSan-caught null/wild
# pointer crash read as NO_CRASH — silently dropping real fuzz crashes on
# UBSan-instrumented targets (magma isan drivers). Kind is the signal name
# lowercased (``segv``), matching the precision of the report.
_UBSAN_DEADLY_RE = re.compile(
    r"ERROR: UndefinedBehaviorSanitizer:\s*(SEGV|BUS|ILL|FPE|ABRT|TRAP)\b"
)


def sanitizer_report(stderr: str) -> str:
    """Return the sanitizer error *kind* (``heap-buffer-overflow``, ...) when
    ``stderr`` carries an AddressSanitizer/UBSan hard-error report, else ``""``.

    A LeakSanitizer-only report returns ``""`` (a leak is not the OOB/UAF crash
    the differential hunts). This is the sanitizer analogue of ``classify_crash``
    but keyed off the exact report banners, so it doubles as the crash *detector*.

    Extends beyond ASan to the three sanitizer report shapes the oracle otherwise
    dropped: **MSan** (``use-of-uninitialized-value`` -> CWE-457, previously MISSED
    entirely so an uninit/infoleak bug read as NO_CRASH), **UBSan** (the specific
    ``runtime error`` phrase, so signed integer overflow classifies as CWE-190 rather
    than the class-less ``undefined-behavior``), and the **UBSan deadly-signal
    intercept** (``ERROR: UndefinedBehaviorSanitizer: SEGV ...`` — no ``runtime
    error:`` phrase, so UBSan-caught null/wild pointer crashes on isan targets
    read as NO_CRASH and fuzz crashes were silently dropped)."""
    if not any(m in stderr for m in _SANITIZER_ERROR_MARKERS):
        return ""
    # A real ASan hard error names its kind (checked first so it wins over the leak
    # guard — a leak report carries ``ERROR: LeakSanitizer``, not this pattern).
    m = _ASAN_ERROR_RE.search(stderr)
    if m:
        return m.group(1)
    # MemorySanitizer uninitialized-value: WARNING/SUMMARY line, no ``ERROR:`` banner.
    mm = _MSAN_ERROR_RE.search(stderr)
    if mm:
        return mm.group(1)
    # UBSan deadly-signal intercept (SEGV/BUS/...): a real crash, classified by
    # the signal — checked BEFORE the leak guard because it never names a kind
    # the ASan/MSan regexes would have caught.
    deadly = _UBSAN_DEADLY_RE.search(stderr)
    if deadly:
        return deadly.group(1).lower()
    # LeakSanitizer-only: a leak report with no hard ASan/MSan error is not the
    # memory-safety crash the differential hunts.
    if "ERROR: AddressSanitizer" not in stderr and any(m in stderr for m in _LEAK_MARKERS):
        return ""
    # UBSan: name the SPECIFIC undefined behavior so it maps to a CWE; fall back to
    # the class-less label when the phrase is unfamiliar.
    ub = _UBSAN_ERROR_RE.search(stderr)
    if ub:
        return "-".join(ub.group(1).split()).lower()
    if "runtime error:" in stderr:
        return "undefined-behavior"
    return "sanitizer-error"


def _deliver(input_bytes: bytes, vector: str, tmpdir: str) -> tuple[list[str], bytes]:
    """Map ``(input_bytes, vector)`` onto the ``(argv, stdin)`` an exec expects.

    ``file`` writes the bytes to a temp file and passes its path as argv[1] (the
    libFuzzer/ARVO convention ``./target /poc``); ``argv`` passes them as a single
    command-line argument; ``stdin`` (default) feeds them on standard input."""
    if vector == "file":
        p = Path(tmpdir) / "poc.bin"
        p.write_bytes(input_bytes)
        return ([str(p)], b"")
    if vector == "argv":
        return ([input_bytes.decode("latin-1")], b"")
    return ([], input_bytes)


def _exec_path(binary: str | Path) -> str:
    """Resolve a binary to an explicit path for ``subprocess`` when it names an
    existing file. A bare/cwd-relative name (``tlv_vuln``) would otherwise be looked
    up on ``$PATH`` and ``OSError`` — silently reporting UNRUNNABLE for every input.
    A name that is NOT a local file (a real PATH command) is left as-is."""
    p = Path(binary)
    return str(p.resolve()) if p.exists() else str(binary)


def run_sanitizer(
    binary: str,
    input_bytes: bytes,
    *,
    vector: str = "file",
    env: dict[str, str] | None = None,
    timeout: float = 10.0,
    executor: Executor | None = None,
) -> RunResult:
    """Run ``binary`` on ``input_bytes`` (delivered via ``vector``) and classify a
    **sanitizer crash**: a non-zero exit whose stderr carries an AddressSanitizer/
    UBSan report — the exit-code analogue of the native-signal crash ``_exec``
    detects (ASan ``_exit(1)``s after its report rather than raising a signal). A
    native signal (rc < 0) still counts too (ASan can also ``SIGABRT``).
    ``RunResult.sanitizer`` carries the report kind (``heap-buffer-overflow``, ...).

    Routed through the configured executor (:mod:`sandbox_exec`) — native
    explicitly trusted subprocess with ``ZEROVERSE_EXECUTOR=local``, or an
    ephemeral microsandbox microVM when ``ZEROVERSE_EXECUTOR=msb``.
    """
    with tempfile.TemporaryDirectory() as td:
        argv, stdin = _deliver(input_bytes, vector, td)
        selected_executor = executor or current_executor()
        res = selected_executor.run(
            [_exec_path(binary), *argv], stdin=stdin, env=env, timeout=timeout,
        )
        if res.timed_out:
            return RunResult(
                crashed=False,
                stderr="timeout",
                provenance=res.provenance,
                valid=False,
                timed_out=True,
            )
        if res.error:
            return RunResult(
                crashed=False,
                stderr=res.error,
                provenance=res.provenance,
                valid=False,
                infrastructure_error=res.error,
            )
    err = res.stderr
    kind = sanitizer_report(err)
    sig = _SIGNALS.get(res.returncode, "")
    crashed = (res.returncode != 0 and bool(kind)) or res.returncode < 0
    return RunResult(
        crashed=crashed,
        signal=sig,
        sanitizer=kind,
        stderr=err,
        provenance=res.provenance,
    )


# --- bounded file-input minimization + payload-free feedback ----------------

@dataclass(frozen=True)
class FileInputMinimization:
    """A bounded, predicate-preserving reduction of a file-input crash.

    ``candidate`` is deliberately retained only for the immediate PoV handoff; the
    receipt builder below stores digests and sizes, never these bytes.
    """

    candidate: bytes
    oracle_runs: int
    max_runs: int


@dataclass(frozen=True)
class CrashFeedbackReceipt:
    """Content-addressed crash feedback safe for datasets and event transport."""

    original_sha256: str
    original_bytes: int
    minimized_sha256: str
    minimized_bytes: int
    target_sha256: str
    oracle: str
    crash_class: str
    sanitizer: str
    signal: str
    dedup_bucket: str
    provenance_sha256: str
    oracle_runs: int
    max_runs: int

    def to_dict(self) -> dict[str, Any]:
        body = {
            "schemaVersion": 1,
            "contract": "0verse-crash-feedback-receipt-v1",
            "targetSha256": self.target_sha256,
            "input": {
                "originalSha256": self.original_sha256,
                "originalBytes": self.original_bytes,
                "minimizedSha256": self.minimized_sha256,
                "minimizedBytes": self.minimized_bytes,
            },
            "confirmation": {
                "oracle": self.oracle,
                "crashClass": self.crash_class,
                "sanitizer": self.sanitizer,
                "signal": self.signal,
                "dedupBucket": self.dedup_bucket,
                "provenanceSha256": self.provenance_sha256,
            },
            "minimization": {
                "oracleRuns": self.oracle_runs,
                "maxRuns": self.max_runs,
            },
        }
        receipt = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        return {**body, "receiptDigest": f"sha256:{hashlib.sha256(receipt).hexdigest()}"}


def minimize_file_input(
    input_bytes: bytes,
    confirms: Callable[[bytes], bool],
    *,
    max_runs: int = 32,
) -> FileInputMinimization:
    """Delete contiguous byte ranges while a caller-supplied file oracle confirms.

    This is generic delta debugging: delivery and crash identity remain the caller's
    responsibility. The strict run cap makes it safe to put beside fuzz confirmation.
    The original is never re-run; callers must establish it first.
    """
    if max_runs < 0:
        raise ValueError("max_runs must be non-negative")
    candidate = input_bytes
    runs = 0
    chunk = max(1, len(candidate) // 2)
    while candidate and chunk and runs < max_runs:
        reduced = False
        for start in range(0, len(candidate), chunk):
            if runs >= max_runs:
                break
            trial = candidate[:start] + candidate[start + chunk:]
            runs += 1
            if confirms(trial):
                candidate = trial
                reduced = True
                break
        if not reduced:
            chunk //= 2
    return FileInputMinimization(candidate=candidate, oracle_runs=runs, max_runs=max_runs)


def crash_feedback_receipt(
    *,
    target: str | Path,
    original_input: bytes,
    minimized_input: bytes,
    oracle: str,
    crash_class: str,
    sanitizer: str = "",
    signal: str = "",
    dedup_bucket: str = "",
    provenance: dict[str, str] | None = None,
    oracle_runs: int = 0,
    max_runs: int = 0,
) -> CrashFeedbackReceipt:
    """Bind a confirmed crash to metadata without retaining raw input or traces."""
    def digest(value: bytes) -> str:
        return f"sha256:{hashlib.sha256(value).hexdigest()}"

    provenance_bytes = json.dumps(
        provenance or {}, sort_keys=True, separators=(",", ":")
    ).encode()
    return CrashFeedbackReceipt(
        original_sha256=digest(original_input),
        original_bytes=len(original_input),
        minimized_sha256=digest(minimized_input),
        minimized_bytes=len(minimized_input),
        target_sha256=digest(str(target).encode()),
        oracle=oracle,
        crash_class=crash_class,
        sanitizer=sanitizer,
        signal=signal,
        dedup_bucket=dedup_bucket,
        provenance_sha256=digest(provenance_bytes),
        oracle_runs=oracle_runs,
        max_runs=max_runs,
    )


# --- ASan/libFuzzer file-input target detection -----------------------------

# ELF byte markers. An ASan-instrumented binary embeds the runtime; a libFuzzer
# target embeds the entrypoint symbol. Both present => a file-input sanitizer
# target (``./target /poc``) the sanitizer-report oracle drives.
_ASAN_BIN_MARKERS: tuple[bytes, ...] = (b"__asan_init", b"AddressSanitizer")
_LIBFUZZER_BIN_MARKERS: tuple[bytes, ...] = (
    b"LLVMFuzzerTestOneInput", b"StandaloneFuzzTargetMain",
)


def is_asan_file_target(path: str | Path) -> bool:
    """True when ``path`` is an AddressSanitizer-instrumented libFuzzer-style
    target that takes its input as a FILE in argv[1] (the ARVO/OSS-Fuzz shape).
    Detected from static byte markers so no execution is needed to route it."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return False
    asan = any(m in data for m in _ASAN_BIN_MARKERS)
    libfuzzer = any(m in data for m in _LIBFUZZER_BIN_MARKERS)
    return asan and libfuzzer


def host_can_launch(binary: str | Path, *, timeout: float = 5.0) -> bool:
    """Probe launchability through the selected execution boundary.

    This must never bypass a disabled or remote executor by directly launching
    the target on the analysis host.
    """
    with tempfile.TemporaryDirectory() as td:
        empty = Path(td) / "empty.bin"
        empty.write_bytes(b"")
        result = current_executor().run(
            [_exec_path(binary), str(empty)], timeout=timeout
        )
    return not result.error


# --- differential-allocator oracle (the no-sanitizer crown jewel) ----------

# A "guard" allocator environment: glibc's own heap consistency checks. Cheap,
# always available, no recompile. (Electric Fence / GWP-ASan slot in via
# ``extra_preload`` when present for page-granular detection.)
GUARD_ENV: dict[str, str] = {
    "MALLOC_CHECK_": "3",            # abort on detected heap corruption
    "GLIBC_TUNABLES": "glibc.malloc.check=3",
    "MALLOC_PERTURB_": "42",         # poison freed/alloced bytes to surface UAF/OOB
}

# Electric Fence (libefence): page-granular guard so a *silent* OOB write faults
# at the offending instruction — the strongest no-sanitizer detector. Used when
# the shared library is present on the host.
_EFENCE_CANDIDATES = (
    "/lib/libefence.so.0", "/usr/lib/libefence.so.0",
    "/usr/lib/x86_64-linux-gnu/libefence.so.0", "libefence.so.0",
)


def _find_efence() -> str | None:
    for cand in _EFENCE_CANDIDATES:
        if cand.startswith("/") and Path(cand).exists():
            return cand
    return None


def guard_env() -> dict[str, str]:
    """The full guard-allocator environment (glibc checks + Electric Fence when
    present). Returned so the PoV emitter can embed it: a silent heap bug only
    reproduces under this env, so the standalone replay must carry it."""
    env = dict(GUARD_ENV)
    ef = _find_efence()
    if ef:
        env["LD_PRELOAD"] = ef
        env["EF_ALLOW_MALLOC_0"] = "1"
    return env


def confirm_guard_env(
    executor: Executor | None = None,
    budget: BudgetTracker | None = None,
    compiler_path: str | None = None,
    compiler_resolved: bool = False,
) -> dict[str, str]:
    """The guard-allocator environment the differential oracle *confirms* under —
    and the one a silent-heap-bug PoV must carry to replay.

    Prefers the deterministic, page-granular **quarantine guard** (built on demand,
    ``build_quarantine_guard``): every allocation gets a trailing ``PROT_NONE``
    guard page, so a genuine out-of-bounds write faults at the offending
    instruction — the SAME outcome on every run and every host, with no dependency
    on a host ``libefence`` being installed. Crucially it also returns *cleanly* on
    a failed or absurdly large allocation (a ``calloc`` of several GiB), whereas
    Electric Fence instead dies with SIGSEGV: that spurious ``clean -> crash`` is a
    false ``real_heap_bug`` the differential oracle would otherwise credit as a real
    silent heap OOB — a false positive on a *patched* build (e.g. an integer-overflow
    fix that now rejects the wrap and merely under-allocates). Falls back to the
    efence/glibc ``guard_env`` only when no C compiler is available to build the
    quarantine guard. Deterministic by construction; see DESIGN-NOTES Decision 6."""
    so = (
        build_quarantine_guard()
        if (
            executor is None
            and budget is None
            and compiler_path is None
            and not compiler_resolved
        )
        else build_quarantine_guard(
            executor=executor,
            budget=budget,
            compiler_path=compiler_path,
            compiler_resolved=compiler_resolved,
        )
    )
    if so is not None:
        return {"LD_PRELOAD": so, "EF_ALLOW_MALLOC_0": "1"}
    return guard_env()


@dataclass
class DiffAllocVerdict:
    stock: RunResult
    guard: RunResult
    real_heap_bug: bool          # high-confidence: clean under stock, faults under guard
    both_crash: bool             # already faults under stock too (still real)

    @property
    def confirmed(self) -> bool:
        return self.real_heap_bug or self.both_crash


def differential_allocator(
    binary: str,
    input_bytes: bytes,
    *,
    vector: str = "stdin",
    extra_preload: str | None = None,
    timeout: float = 10.0,
    deadline_monotonic: float | None = None,
    executor: Executor | None = None,
    budget: BudgetTracker | None = None,
    compiler_path: str | None = None,
    compiler_resolved: bool = False,
) -> DiffAllocVerdict:
    """Re-run one crashing input under the stock allocator and under a guard
    allocator. A silent overflow that only faults under the guard (``clean ->
    crash``) is a high-confidence real heap bug; if it already faults under stock
    that is also real (just louder). For stack bugs both runs fault — still real.
    """
    if vector == "stdin":
        stdin, argv = input_bytes, None
    else:
        stdin, argv = b"", [input_bytes.decode("latin-1")]
    def remaining_timeout() -> float:
        if deadline_monotonic is None:
            return timeout
        return max(0.0, min(timeout, deadline_monotonic - time.monotonic()))

    stock_timeout = remaining_timeout()
    stock = (
        _exec(
            binary,
            timeout=stock_timeout,
            stdin=stdin,
            argv=argv,
            executor=executor,
        )
        if stock_timeout > 0
        else RunResult(
            crashed=False,
            valid=False,
            timed_out=True,
            infrastructure_error="deadline exhausted before stock replay",
        )
    )
    if extra_preload:
        # Caller-pinned guard library (e.g. the quarantine guard the intoverflow
        # lens passes). EF_ALLOW_MALLOC_0 keeps zero-size mallocs from aborting.
        genv = guard_env()
        genv["LD_PRELOAD"] = extra_preload
        genv["EF_ALLOW_MALLOC_0"] = "1"
    else:
        # Default: the deterministic page-granular quarantine guard (not efence),
        # so a genuine OOB faults identically every run and a huge/failed
        # allocation does NOT spuriously crash (which efence does — a false
        # ``clean -> crash`` that would fabricate a heap bug on a patched build).
        genv = confirm_guard_env(
            executor=executor,
            budget=budget,
            compiler_path=compiler_path,
            compiler_resolved=compiler_resolved,
        )
    guard_timeout = remaining_timeout()
    guard = (
        _exec(
            binary,
            env=genv,
            timeout=guard_timeout,
            stdin=stdin,
            argv=argv,
            executor=executor,
        )
        if guard_timeout > 0
        else RunResult(
            crashed=False,
            valid=False,
            timed_out=True,
            infrastructure_error="deadline exhausted before guard replay",
        )
    )
    clean_to_crash = stock.valid and guard.valid and guard.crashed and not stock.crashed
    return DiffAllocVerdict(
        stock=stock, guard=guard,
        real_heap_bug=clean_to_crash,
        both_crash=stock.valid and guard.valid and stock.crashed and guard.crashed,
    )


# --- quarantine guard allocator (M4 #24: UAF / double-free, no sanitizer) ----

# A self-contained, page-granular guard allocator built on demand. Each allocation
# is its own mmap'd region with a trailing PROT_NONE guard page, the user data
# placed flush against the guard (16-byte aligned) so even a 1-byte overflow
# faults at the offending instruction (Electric-Fence style). free() poisons the
# bytes and mprotect()s the whole region PROT_NONE then QUARANTINES it (never
# reused): any later read/write through the dangling pointer faults (use-after-
# free) and a second free of a quarantined/unknown pointer traps (double-free).
# malloc is implemented directly over mmap (no dlsym chaining), so there is no
# allocator-bootstrap recursion. This is also a no-libefence fallback guard page
# for the differential-allocator (pass it as ``extra_preload``).
_QUARANTINE_GUARD_C = r"""/* 0verse quarantine guard allocator (auto-generated). */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#define POISON 0x5a
#define ALIGN  16u
#define MAXN   (1 << 18)

enum { ST_LIVE = 1, ST_QUARANTINED = 2 };
struct slot { void *user; void *base; size_t map_len; size_t user_len; int state; };
static struct slot g_slots[MAXN];
static size_t g_count;

static long g_page;
static long page(void) { if (!g_page) g_page = sysconf(_SC_PAGESIZE); return g_page; }

static struct slot *find(void *user) {
    for (size_t i = 0; i < g_count; i++)
        if (g_slots[i].user == user) return &g_slots[i];
    return NULL;
}

static void die(const char *msg) {
    (void)!write(2, msg, strlen(msg));
    __builtin_trap();
}

void *malloc(size_t n) {
    if (n == 0) n = 1;
    long pg = page();
    size_t need = (n + ALIGN - 1) & ~(size_t)(ALIGN - 1);
    size_t data_len = (need + pg - 1) & ~(size_t)(pg - 1);
    size_t map_len = data_len + (size_t)pg;
    unsigned char *base = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return NULL;
    mprotect(base + data_len, (size_t)pg, PROT_NONE);
    unsigned char *user = base + data_len - need;
    if (g_count >= MAXN) die("0verse-quarantine: registry exhausted\n");
    struct slot *s = &g_slots[g_count++];
    s->user = user; s->base = base; s->map_len = map_len; s->user_len = n;
    s->state = ST_LIVE;
    return user;
}

void free(void *p) {
    if (!p) return;
    struct slot *s = find(p);
    if (!s) die("0verse-quarantine: free of unknown pointer\n");
    if (s->state == ST_QUARANTINED) die("0verse-quarantine: DOUBLE FREE detected\n");
    memset(s->user, POISON, s->user_len);
    mprotect(s->base, s->map_len, PROT_NONE);
    s->state = ST_QUARANTINED;
}

void *calloc(size_t nmemb, size_t size) {
    size_t n = nmemb * size;
    if (size && n / size != nmemb) die("0verse-quarantine: calloc overflow\n");
    return malloc(n);
}

void *realloc(void *p, size_t n) {
    if (!p) return malloc(n);
    if (n == 0) { free(p); return NULL; }
    struct slot *s = find(p);
    if (!s || s->state != ST_LIVE) die("0verse-quarantine: realloc of bad pointer\n");
    void *np = malloc(n);
    if (!np) return NULL;
    size_t cp = s->user_len < n ? s->user_len : n;
    memcpy(np, p, cp);
    free(p);
    return np;
}

int posix_memalign(void **out, size_t align, size_t n) {
    (void)align; void *p = malloc(n); if (!p) return 12; *out = p; return 0;
}
void *aligned_alloc(size_t align, size_t n) { (void)align; return malloc(n); }
void *memalign(size_t align, size_t n) { (void)align; return malloc(n); }
void *valloc(size_t n) { return malloc(n); }
"""


def _cache_dir() -> Path:
    d = Path(os.environ.get("ZEROVERSE_CACHE", ".0verse-cache"))
    with contextlib.suppress(OSError):
        d.mkdir(parents=True, exist_ok=True)
    return d


def _build_preload(
    stem: str,
    source: str,
    *,
    link_dl: bool = False,
    executor: Executor | None = None,
    budget: BudgetTracker | None = None,
    compiler_path: str | None = None,
    compiler_resolved: bool = False,
) -> str | None:
    """Build one internal preload for the selected execution architecture."""
    cache = _cache_dir()
    src = cache / f"{stem}.c"
    selected_executor = executor or current_executor()
    remote = isinstance(selected_executor, MsbSshExecutor)
    so = cache / (f"{stem}.linux-x86_64.so" if remote else f"{stem}.so")
    receipt = so.with_suffix(".build.json")
    stale = not src.is_file() or src.read_text() != source
    if stale:
        with contextlib.suppress(OSError):
            src.write_text(source)
            if so.is_file():
                so.unlink()
            receipt.unlink(missing_ok=True)
    if so.is_file():
        return str(so)
    if budget is not None:
        reserved, _ = budget.reserve_attempt()
        if not reserved:
            return None
        remaining = budget.remaining_seconds()
        if remaining <= 0:
            budget.reservation_failures += 1
            return None
        # Remote build APIs expose no cancellation/deadline contract. Skip rather
        # than outlive the absolute run deadline.
        if not isinstance(selected_executor, LocalExecutor):
            return None
    else:
        remaining = 60.0
    if isinstance(selected_executor, MsbSshExecutor):
        try:
            artifact, compiler_sha = selected_executor.build_shared_object(
                source.encode(), link_dl=link_dl
            )
            so.write_bytes(artifact)
            receipt.write_text(
                json.dumps(
                    {
                        "compiler_sha256": compiler_sha,
                        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                    },
                    sort_keys=True,
                )
            )
        except OSError:
            return None
        return str(so) if so.is_file() else None
    if not isinstance(selected_executor, LocalExecutor):
        return None
    cc = (
        compiler_path
        if compiler_resolved
        else compiler_path or shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    )
    if cc is None:
        return None
    try:
        command = [cc, "-O0", "-fPIC", "-shared", "-o", str(so), str(src)]
        if link_dl:
            command.append("-ldl")
        r = subprocess.run(
            command, capture_output=True, timeout=remaining,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return str(so) if r.returncode == 0 and so.is_file() else None


def build_quarantine_guard(
    *,
    executor: Executor | None = None,
    budget: BudgetTracker | None = None,
    compiler_path: str | None = None,
    compiler_resolved: bool = False,
) -> str | None:
    """Compile and cache the quarantine guard for the selected executor."""
    return _build_preload(
        "quarantine_guard",
        _QUARANTINE_GUARD_C,
        executor=executor,
        budget=budget,
        compiler_path=compiler_path,
        compiler_resolved=compiler_resolved,
    )


def quarantine_available() -> bool:
    return build_quarantine_guard() is not None


def quarantine_env(
    *,
    executor: Executor | None = None,
    budget: BudgetTracker | None = None,
    compiler_path: str | None = None,
    compiler_resolved: bool = False,
) -> dict[str, str]:
    """Environment that runs the target under the quarantine guard allocator. Falls
    back to the glibc guard env (which still aborts on double-free) when no C
    compiler is available to build the ``.so``."""
    so = (
        build_quarantine_guard()
        if (
            executor is None
            and budget is None
            and compiler_path is None
            and not compiler_resolved
        )
        else build_quarantine_guard(
            executor=executor,
            budget=budget,
            compiler_path=compiler_path,
            compiler_resolved=compiler_resolved,
        )
    )
    if so is None:
        return dict(GUARD_ENV)
    return {"LD_PRELOAD": so, "EF_ALLOW_MALLOC_0": "1"}


@dataclass
class UafVerdict:
    trigger: RunResult
    control: RunResult
    confirmed: bool          # trigger faults under quarantine, control stays clean
    kind: str = ""           # "use-after-free" | "double-free" | ""


def uaf_differential(
    binary: str,
    trigger_input: bytes,
    control_input: bytes = b"",
    *,
    vector: str = "stdin",
    timeout: float = 10.0,
    deadline_monotonic: float | None = None,
    executor: Executor | None = None,
    budget: BudgetTracker | None = None,
    compiler_path: str | None = None,
    compiler_resolved: bool = False,
) -> UafVerdict:
    """Run a candidate trigger and a benign control under the quarantine guard. A
    trigger that faults (UAF read/write SIGSEGV, or double-free trap) while the
    control stays clean is a confirmed use-after-free / double-free — dynamic
    proof a stock allocator silently tolerates."""
    env = quarantine_env(
        executor=executor,
        budget=budget,
        compiler_path=compiler_path,
        compiler_resolved=compiler_resolved,
    )

    def _run(data: bytes) -> RunResult:
        run_timeout = timeout
        if deadline_monotonic is not None:
            run_timeout = max(
                0.0,
                min(timeout, deadline_monotonic - time.monotonic()),
            )
        if run_timeout <= 0:
            return RunResult(
                crashed=False,
                valid=False,
                timed_out=True,
                infrastructure_error="deadline exhausted before UAF replay",
            )
        if vector == "argv":
            return _exec(
                binary,
                env=env,
                argv=[data.decode("latin-1")],
                timeout=run_timeout,
                executor=executor,
            )
        return _exec(
            binary,
            env=env,
            stdin=data,
            timeout=run_timeout,
            executor=executor,
        )

    trig = _run(trigger_input)
    ctrl = _run(control_input)
    confirmed = trig.valid and ctrl.valid and trig.crashed and not ctrl.crashed
    kind = ""
    if confirmed:
        low = trig.stderr.lower()
        kind = "double-free" if ("double free" in low or "double-free" in low) \
            else "use-after-free"
    return UafVerdict(trigger=trig, control=ctrl, confirmed=confirmed, kind=kind)


# --- exec-trap oracle (M4 #25 cmdi: the memory oracle is blind to injection) -

# An LD_PRELOAD shim that intercepts the exec / system / popen / posix_spawn family
# and, when the per-run sentinel token (env ``ZEROVERSE_EXECTRAP``) appears in a
# command string or any argv element, emits a token-bound capability marker and
# ``_exit(0)`` BEFORE running anything — so a confirmed command/argument injection
# is proven behaviorally without ever executing the (possibly destructive) command.
# Non-matching calls are forwarded to the real libc function (RTLD_NEXT) so the
# program runs normally up to the injected sink. This is the cmdi confirming oracle
# the differential-allocator cannot provide.
_EXECTRAP_SHIM_C = r"""/* 0verse exec-trap shim (auto-generated). */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static const char *trap_token(void) { return getenv("ZEROVERSE_EXECTRAP"); }

static int contains_token(const char *str) {
    const char *t = trap_token();
    if (!t || !*t || !str) return 0;
    return strstr(str, t) != NULL;
}

static int argv_has_token(char *const argv[]) {
    const char *t = trap_token();
    if (!t || !*t || !argv) return 0;
    for (int i = 0; argv[i]; i++)
        if (strstr(argv[i], t)) return 1;
    return 0;
}

static void confirm_and_exit(void) {
    const char *t = trap_token();
    char buf[320];
    int n = snprintf(buf, sizeof buf, "0VERSE-CANARY:%s:reached-sink\n", t ? t : "");
    if (n > 0) (void)!write(1, buf, (size_t)n);
    _exit(0);
}

int system(const char *cmd) {
    if (contains_token(cmd)) confirm_and_exit();
    int (*real)(const char *) = dlsym(RTLD_NEXT, "system");
    return real ? real(cmd) : -1;
}

FILE *popen(const char *cmd, const char *type) {
    if (contains_token(cmd)) confirm_and_exit();
    FILE *(*real)(const char *, const char *) = dlsym(RTLD_NEXT, "popen");
    return real ? real(cmd, type) : NULL;
}

int execve(const char *path, char *const argv[], char *const envp[]) {
    if (contains_token(path) || argv_has_token(argv)) confirm_and_exit();
    int (*real)(const char *, char *const[], char *const[]) = dlsym(RTLD_NEXT, "execve");
    return real ? real(path, argv, envp) : -1;
}

int execv(const char *path, char *const argv[]) {
    if (contains_token(path) || argv_has_token(argv)) confirm_and_exit();
    int (*real)(const char *, char *const[]) = dlsym(RTLD_NEXT, "execv");
    return real ? real(path, argv) : -1;
}

int execvp(const char *file, char *const argv[]) {
    if (contains_token(file) || argv_has_token(argv)) confirm_and_exit();
    int (*real)(const char *, char *const[]) = dlsym(RTLD_NEXT, "execvp");
    return real ? real(file, argv) : -1;
}

int execvpe(const char *file, char *const argv[], char *const envp[]) {
    if (contains_token(file) || argv_has_token(argv)) confirm_and_exit();
    int (*real)(const char *, char *const[], char *const[]) = dlsym(RTLD_NEXT, "execvpe");
    return real ? real(file, argv, envp) : -1;
}

static int collect_va(const char *arg0, va_list ap, char **argv, int max) {
    int argc = 0;
    argv[argc++] = (char *)arg0;
    while (argc < max - 1) {
        char *a = va_arg(ap, char *);
        argv[argc] = a;
        if (!a) break;
        argc++;
    }
    argv[argc] = NULL;
    return argc;
}

int execl(const char *path, const char *arg0, ...) {
    char *argv[256];
    va_list ap; va_start(ap, arg0);
    collect_va(arg0, ap, argv, 256);
    va_end(ap);
    if (contains_token(path) || argv_has_token(argv)) confirm_and_exit();
    int (*real)(const char *, char *const[]) = dlsym(RTLD_NEXT, "execv");
    return real ? real(path, argv) : -1;
}

int execlp(const char *file, const char *arg0, ...) {
    char *argv[256];
    va_list ap; va_start(ap, arg0);
    collect_va(arg0, ap, argv, 256);
    va_end(ap);
    if (contains_token(file) || argv_has_token(argv)) confirm_and_exit();
    int (*real)(const char *, char *const[]) = dlsym(RTLD_NEXT, "execvp");
    return real ? real(file, argv) : -1;
}

int execle(const char *path, const char *arg0, ...) {
    char *argv[256];
    va_list ap; va_start(ap, arg0);
    int argc = 0;
    argv[argc++] = (char *)arg0;
    while (argc < 255) {
        char *a = va_arg(ap, char *);
        if (!a) break;
        argv[argc++] = a;
    }
    argv[argc] = NULL;
    char *const *envp = va_arg(ap, char *const *);
    va_end(ap);
    if (contains_token(path) || argv_has_token(argv)) confirm_and_exit();
    int (*real)(const char *, char *const[], char *const[]) = dlsym(RTLD_NEXT, "execve");
    return real ? real(path, argv, envp) : -1;
}

int posix_spawn(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *fa,
                const posix_spawnattr_t *attr,
                char *const argv[], char *const envp[]) {
    if (contains_token(path) || argv_has_token(argv)) confirm_and_exit();
    int (*real)(pid_t *, const char *, const posix_spawn_file_actions_t *,
                const posix_spawnattr_t *, char *const[], char *const[]) =
        dlsym(RTLD_NEXT, "posix_spawn");
    return real ? real(pid, path, fa, attr, argv, envp) : -1;
}

int posix_spawnp(pid_t *pid, const char *file,
                 const posix_spawn_file_actions_t *fa,
                 const posix_spawnattr_t *attr,
                 char *const argv[], char *const envp[]) {
    if (contains_token(file) || argv_has_token(argv)) confirm_and_exit();
    int (*real)(pid_t *, const char *, const posix_spawn_file_actions_t *,
                const posix_spawnattr_t *, char *const[], char *const[]) =
        dlsym(RTLD_NEXT, "posix_spawnp");
    return real ? real(pid, file, fa, attr, argv, envp) : -1;
}
"""


def build_exectrap_shim(
    *,
    executor: Executor | None = None,
    budget: BudgetTracker | None = None,
    compiler_path: str | None = None,
    compiler_resolved: bool = False,
) -> str | None:
    """Compile (and cache) the exec-trap LD_PRELOAD shim ``.so``. Returns its path,
    or None when no C compiler is available. Idempotent — rebuilds only when the
    embedded source changes."""
    return _build_preload(
        "exectrap_shim",
        _EXECTRAP_SHIM_C,
        link_dl=True,
        executor=executor,
        budget=budget,
        compiler_path=compiler_path,
        compiler_resolved=compiler_resolved,
    )


def exectrap_available() -> bool:
    return build_exectrap_shim() is not None


def exectrap_env(
    canary: str,
    *,
    executor: Executor | None = None,
    budget: BudgetTracker | None = None,
    compiler_path: str | None = None,
    compiler_resolved: bool = False,
) -> dict[str, str]:
    """Environment that runs the target under the exec-trap shim for a given
    sentinel token. Empty when no C compiler is available to build the shim."""
    so = build_exectrap_shim(
        executor=executor,
        budget=budget,
        compiler_path=compiler_path,
        compiler_resolved=compiler_resolved,
    )
    if so is None:
        return {}
    return {"LD_PRELOAD": so, "ZEROVERSE_EXECTRAP": canary}


# --- format-string probe (M4 #23) ------------------------------------------

def format_string_probe(spray: int = 16) -> bytes:
    """A format-string confirmation probe: a ``%s`` spray (deref stack/garbage
    pointers → wild read) capped with ``%n`` (controlled write). Fed into a tainted
    format position it crashes a vulnerable target; a benign control does not."""
    return ("%s" * spray + "%n").encode()


# --- CASR wrapper (native exploitability classification + backtraces) -------

@dataclass
class CasrReport:
    severity: str                 # EXPLOITABLE | PROBABLY_EXPLOITABLE | NOT_EXPLOITABLE
    short_desc: str               # e.g. ReturnAv, SourceAv, DestAv, AbortSignal
    description: str
    frames: list[str] = field(default_factory=list)   # normalized top backtrace
    crash_line: str = ""
    signal: str = ""

    # CASR severity -> our capability ladder (best-effort, conservative).
    _WRITE_HINTS = ("DestAv", "ReturnAv", "BranchAv", "StackGuard", "heap-buffer-overflow")

    @property
    def capability(self) -> str:
        sd = self.short_desc
        if any(h in sd for h in self._WRITE_HINTS) or self.severity == "EXPLOITABLE":
            return "oob-write"
        if "SourceAv" in sd or "read" in self.description.lower():
            return "oob-read"
        return "crash"


def casr_available() -> bool:
    return shutil.which("casr-gdb") is not None


def run_casr_gdb(
    binary: str,
    *,
    stdin_bytes: bytes | None = None,
    argv: list[str] | None = None,
    env: dict[str, str] | None = None,
    timeout: float = 60.0,
    executor: Executor | None = None,
) -> CasrReport | None:
    """Triage a crash with ``casr-gdb`` and parse the report. Returns None if CASR
    is not installed or the target did not crash under it."""
    # CASR itself launches the target. Until a receipt-bearing remote CASR
    # adapter exists, permit this path only under explicit trusted-local mode.
    selected_executor = executor or current_executor()
    if not isinstance(selected_executor, LocalExecutor) or not casr_available():
        return None
    with tempfile.TemporaryDirectory() as td:
        rep = Path(td) / "out.casrep"
        cmd = ["casr-gdb", "-o", str(rep)]
        stdin_file = None
        if stdin_bytes is not None:
            stdin_file = Path(td) / "input.bin"
            stdin_file.write_bytes(stdin_bytes)
            cmd += ["--stdin", str(stdin_file)]
        cmd += ["--", binary, *(argv or [])]
        full_env = {**os.environ, **(env or {})}
        try:
            subprocess.run(cmd, env=full_env, capture_output=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError):
            return None
        if not rep.is_file():
            return None
        try:
            data = json.loads(rep.read_text())
        except (OSError, json.JSONDecodeError):
            return None
    return _parse_casrep(data)


def _parse_casrep(data: dict[str, Any]) -> CasrReport:
    sev = data.get("CrashSeverity", {}) or {}
    frames_raw = data.get("Stacktrace", []) or []
    frames = list(crash_state([str(f) for f in frames_raw], top_n=6))
    return CasrReport(
        severity=str(sev.get("Type", "NOT_EXPLOITABLE")),
        short_desc=str(sev.get("ShortDescription", "")),
        description=str(sev.get("Description", "")),
        frames=frames,
        crash_line=str(data.get("CrashLine", "")),
        signal=str(data.get("Signal", "")),
    )


# --- suspected-known dedup vs PUBLIC advisories (offline by default) --------

@dataclass
class KnownMatch:
    advisory_id: str
    package: str
    reason: str


def suspected_known(
    package: str, version: str, symbol: str, advisories: list[dict[str, Any]]
) -> list[KnownMatch]:
    """Fuzzy ``package+symbol`` match against a *public* advisory list (OSV/GHSA
    export). Marks a crash "suspected-known" — never auto-dismisses it; a PoV in
    a patched function is still a finding worth reporting. Offline: callers pass an
    advisory snapshot. (A live ``api.osv.dev`` lookup is opt-in and not run here,
    honoring the no-external-calls default.)"""
    out: list[KnownMatch] = []
    pkg = package.lower()
    sym = symbol.lower()
    for adv in advisories:
        apkg = str(adv.get("package", "")).lower()
        asyms = [str(s).lower() for s in adv.get("symbols", [])]
        if apkg and apkg in pkg and (not sym or sym in asyms or not asyms):
            out.append(KnownMatch(
                advisory_id=str(adv.get("id", "?")), package=apkg,
                reason=f"package match {apkg!r}" + (f", symbol {sym!r}" if sym in asyms else ""),
            ))
    return out


# --- patch verification (M7 #45) — PoV-is-truth's strict sibling ------------
#
# The ONLY place a patch becomes ``verified`` — and, exactly like PoV
# confirmation, an LLM never adjudicates here. Two deterministic gates, both
# required, plus three anti-cheat guards distilled from the AIxCC correctness
# landmines (Atlantis "likely correct via unintended mitigation"; Theori
# incomplete-patch post-patch fuzz; Theori parallel-dup failure):
#
#   GATE 1  the confirmed PoV NO LONGER reproduces against the patched artifact
#           (the differential, inverted: the input that *proved* the bug is now benign)
#   GATE 2  no regression — test_cmd exits 0, OR (binary, no tests) the patched and
#           original binaries produce identical stdout/exit on the benign controls
#   anti-cheat: reject mitigation-only "fixes"; post-patch fuzz for incomplete
#           patches; (dedup is enforced one rung up, in patch.py, per dedup_bucket)


def _exec_capture(
    binary: str,
    *,
    env: dict[str, str] | None = None,
    argv: list[str] | None = None,
    stdin: bytes = b"",
    timeout: float = 10.0,
    executor: Executor | None = None,
) -> tuple[int, bytes, bytes]:
    """Run ``binary`` once and return ``(returncode, stdout, stderr)``. Unlike
    :func:`_exec` this keeps stdout, which the command-injection re-check needs."""
    selected_executor = executor or current_executor()
    result = selected_executor.run(
        [binary, *(argv or [])], stdin=stdin, env=env, timeout=timeout
    )
    if result.timed_out:
        return (124, b"", b"timeout")
    if result.error:
        return (-99, b"", result.error.encode())
    if "\ufffd" in result.stdout or "\ufffd" in result.stderr:
        return (-99, b"", b"target output was not losslessly decodable")
    # Remote confirmation intentionally combines target stdout/stderr into the
    # captured channel; marker adjudication consumes both.
    output = (result.stdout + result.stderr).encode()
    return (result.returncode, output, b"")


def _pov_marker_canary(pov: PoV) -> str | None:
    """Recover the canary token a command-injection PoV injected (it is embedded in
    the env value, e.g. ``CMD=echo 0VERSE-CANARY:<canary>:reached-sink``)."""
    pat = re.compile(rf"{re.escape(MARKER_PREFIX)}:([0-9a-fA-F]+):")
    for v in pov.env.values():
        m = pat.search(v)
        if m:
            return m.group(1)
    return None


def _pov_invocation(pov: PoV) -> tuple[list[str] | None, bytes]:
    """The exact (argv, stdin) the PoV used — argv vector when it carried argv,
    else the crashing bytes on stdin."""
    if pov.argv:
        return (list(pov.argv), b"")
    return (None, pov.input_bytes or b"")


@dataclass
class PovRecheck:
    reproduced: bool        # did the confirmed PoV reproduce against this artifact?
    detail: str = ""


def _patch_operation_timeout(
    budget: BudgetTracker | None,
    timeout: float,
) -> tuple[float | None, str]:
    """Reserve one patch operation and cap it to the cooperative run deadline."""
    if budget is None:
        return timeout, ""
    reserved, reason = budget.reserve_attempt()
    if not reserved:
        return None, reason
    remaining = budget.remaining_seconds()
    if remaining <= 0:
        budget.reservation_failures += 1
        return None, "wall-clock budget exhausted"
    return min(timeout, remaining), ""


def recheck_pov(
    pov: PoV,
    target: str,
    *,
    timeout: float = 10.0,
    budget: BudgetTracker | None = None,
    executor: Executor | None = None,
) -> PovRecheck:
    """Re-run the EXACT confirmed PoV (its argv/stdin/env, incl. any guard-allocator
    env it carried for a silent heap bug) against ``target`` and decide whether it
    still reproduces. Command-injection reproduces iff its canary marker reappears;
    a memory bug reproduces iff the target crashes (native signal)."""
    operation_timeout, reason = _patch_operation_timeout(budget, timeout)
    if operation_timeout is None:
        return PovRecheck(True, f"recheck budget exhausted: {reason}")
    canary = _pov_marker_canary(pov)
    if pov.crash_class == "command-injection" or canary:
        rc, out, err = _exec_capture(
            target,
            env=pov.env,
            timeout=operation_timeout,
            executor=executor,
        )
        if rc in (-99, 124):
            return PovRecheck(True, f"indeterminate recheck: {err[:80]!r}")
        if canary and adjudicate_capability(out, canary).proven:
            return PovRecheck(True, "command-injection canary marker reappeared")
        return PovRecheck(False, "no injection marker in output (sink no longer reached)")
    argv, stdin = _pov_invocation(pov)
    r = _exec(
        target,
        env=pov.env or None,
        argv=argv,
        stdin=stdin,
        timeout=operation_timeout,
        executor=executor,
    )
    if not r.valid:
        return PovRecheck(True, f"indeterminate recheck: {r.stderr[:80]!r}")
    if r.crashed:
        return PovRecheck(True, f"still crashes ({r.signal or 'signal'})")
    return PovRecheck(False, f"clean exit, no signal ({r.stderr[:60]!r})")


# A "patch" that closes the PoV merely by hardening (new build flags, a broad
# exception/signal swallow) rather than fixing the tainted data flow is "likely
# correct", not correct (Atlantis). Detected on the diff's *added* lines.
_MITIGATION_PATTERNS: tuple[str, ...] = (
    r"-fstack-protector", r"-fsanitize", r"_FORTIFY_SOURCE", r"-fcf-protection",
    r"-mbranch-protection", r"-fpie\b", r"-pie\b", r"\bmte\b", r"\bpac\b",
    r"catch\s*\(\s*\.\.\.\s*\)", r"catch\s*\(\s*Exception", r"signal\s*\(\s*SIG",
    r"\bsigaction\b", r"\bsetrlimit\b",
)
# A genuine fix touches the tainted copy/length/sanitization logic.
_BOUND_LOGIC = (
    r"strncpy|strlcpy|strncat|snprintf|memcpy_s|sizeof|\bclamp\b|\bbound\b|"
    r"\bmin\b|len\s*[<>]=?|[<>]=?\s*sizeof|execv|allowlist|sanitiz"
)


def looks_mitigation_only(diff: str, *, sink: str = "", sink_function: str = "") -> bool:
    """Anti-cheat #1: True when a source diff closes the PoV only via hardening
    (compiler flags / a broad catch / a signal handler) and never touches the
    tainted data flow. A diff that bounds the copy, sanitizes the input, or swaps
    the sink for a safe API is a real fix and returns False."""
    added = [
        ln[1:] for ln in diff.splitlines()
        if ln.startswith("+") and not ln.startswith("+++")
    ]
    body = "\n".join(added)
    if not body.strip():
        return False
    mitigation = any(re.search(p, body, re.I) for p in _MITIGATION_PATTERNS)
    real_fix = bool(re.search(_BOUND_LOGIC, body, re.I))
    return mitigation and not real_fix


def _mutations(seed: bytes, n: int) -> list[bytes]:
    """A short deterministic mutation burst around a crashing input — different
    lengths (the usual incomplete-patch tell) plus a couple of byte twists."""
    base = seed or b"A"
    lengths = [len(base) + 1, len(base) * 2, 64, 256, 1024, 4096, 8192, 16384]
    muts = [b"A" * L for L in lengths]
    muts.append(base + b"B" * 32)
    muts.append(b"\xff" * max(1, len(base)))
    seen: set[bytes] = set()
    out: list[bytes] = []
    for m in muts:
        if m not in seen:
            seen.add(m)
            out.append(m)
        if len(out) >= n:
            break
    return out


def postpatch_fuzz_incomplete(
    pov: PoV,
    patched_target: str,
    *,
    iters: int = 12,
    timeout: float = 10.0,
    budget: BudgetTracker | None = None,
    executor: Executor | None = None,
) -> str:
    """Anti-cheat #2 (Theori): after GATE 1, mutate the PoV input a few times and
    re-run the patched binary. A near-variant that still crashes means the patch is
    *incomplete* (it closed one input, not the bug). Returns the crashing variant's
    description, or "" when the patched binary survived every mutation. Only runs
    for memory PoVs (a command-injection re-check has no length axis)."""
    if pov.crash_class == "command-injection" or _pov_marker_canary(pov):
        return ""
    argv0, _ = _pov_invocation(pov)
    use_argv = argv0 is not None
    for mut in _mutations(pov.input_bytes or b"A", iters):
        operation_timeout, reason = _patch_operation_timeout(budget, timeout)
        if operation_timeout is None:
            return f"budget exhausted before variant replay: {reason}"
        if use_argv:
            r = _exec(
                patched_target,
                env=pov.env or None,
                argv=[mut.decode("latin-1")],
                timeout=operation_timeout,
                executor=executor,
            )
        else:
            r = _exec(
                patched_target,
                env=pov.env or None,
                stdin=mut,
                timeout=operation_timeout,
                executor=executor,
            )
        if not r.valid:
            return f"indeterminate variant len={len(mut)}: {r.stderr[:80]!r}"
        if r.crashed:
            return f"variant len={len(mut)} still crashes ({r.signal or 'signal'})"
    return ""


@dataclass
class PatchVerdict:
    gate1_closes_pov: bool          # the confirmed PoV no longer reproduces
    gate2_no_regression: bool       # functionality preserved
    mitigation_only: bool = False   # rejected: hardening, not a data-flow fix
    incomplete: bool = False        # a near-variant still crashes the patched binary
    gate1_note: str = ""
    gate2_note: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def verified(self) -> bool:
        """A patch is verified ONLY when both gates pass on a real re-run and no
        anti-cheat guard fired — never claimed otherwise."""
        return (
            self.gate1_closes_pov
            and self.gate2_no_regression
            and not self.mitigation_only
            and not self.incomplete
        )


def _regression_via_tests(
    test_cmd: list[str],
    *,
    cwd: str | None,
    timeout: float,
    budget: BudgetTracker | None = None,
    native_compiler_path: str | None = None,
) -> tuple[bool, str]:
    operation_timeout, reason = _patch_operation_timeout(budget, timeout)
    if operation_timeout is None:
        return False, f"regression budget exhausted: {reason}"
    env = {**os.environ}
    if native_compiler_path:
        env["CC"] = native_compiler_path
    try:
        p = subprocess.run(
            test_cmd,
            cwd=cwd,
            capture_output=True,
            timeout=operation_timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return (False, "regression: test_cmd timed out")
    except OSError as e:
        return (False, f"regression: test_cmd failed to launch ({e})")
    if p.returncode == 0:
        return (True, f"tests pass (exit 0): {' '.join(test_cmd)}")
    return (False, f"regression: test_cmd exit {p.returncode}")


def _regression_via_controls(
    original_target: str,
    patched_target: str,
    controls: list[bytes],
    *,
    use_argv: bool,
    timeout: float,
    budget: BudgetTracker | None = None,
    executor: Executor | None = None,
) -> tuple[bool, str]:
    """Binary mode, no test suite: the patched and original binaries must produce
    IDENTICAL stdout + exit code on every benign control input (functional-
    equivalence sample). Any divergence on a benign input is a regression."""
    for ctrl in controls:
        if use_argv:
            argv: list[str] | None = [ctrl.decode("latin-1")]
            stdin = b""
        else:
            argv, stdin = None, ctrl
        original_timeout, reason = _patch_operation_timeout(budget, timeout)
        if original_timeout is None:
            return False, f"regression budget exhausted before original control: {reason}"
        orc, oout, _ = _exec_capture(
            original_target,
            argv=argv,
            stdin=stdin,
            timeout=original_timeout,
            executor=executor,
        )
        patched_timeout, reason = _patch_operation_timeout(budget, timeout)
        if patched_timeout is None:
            return False, f"regression budget exhausted before patched control: {reason}"
        prc, pout, _ = _exec_capture(
            patched_target,
            argv=argv,
            stdin=stdin,
            timeout=patched_timeout,
            executor=executor,
        )
        if (orc, oout) != (prc, pout):
            return (
                False,
                f"regression: benign input ({len(ctrl)}B) diverges "
                f"(orig exit={orc}, patched exit={prc})",
            )
    return (True, f"control-inputs identical on {len(controls)} benign sample(s)")


def verify_patch(
    pov: PoV,
    patched_target: str,
    *,
    original_target: str | None = None,
    control_inputs: list[bytes] | None = None,
    test_cmd: list[str] | None = None,
    test_cwd: str | None = None,
    diff: str = "",
    sink: str = "",
    sink_function: str = "",
    binary_touches_taintpath: bool = False,
    fuzz_iters: int = 12,
    timeout: float = 10.0,
    budget: BudgetTracker | None = None,
    executor: Executor | None = None,
    executor_provider: str = "",
    native_compiler_path: str | None = None,
) -> PatchVerdict:
    """Adjudicate a patch — the deterministic, LLM-free sibling of PoV
    confirmation. ``verified`` is true ONLY when GATE 1 (the confirmed PoV no
    longer reproduces) AND GATE 2 (no regression) both pass and no anti-cheat
    guard fires. Honest by construction: when no regression oracle is available,
    GATE 2 fails (never silently passed)."""
    notes: list[str] = []
    if budget is not None and (
        not isinstance(executor, LocalExecutor) or not executor_provider
    ):
        reason = "planned local patch executor/provider unavailable"
        return PatchVerdict(
            gate1_closes_pov=False,
            gate2_no_regression=False,
            gate1_note=reason,
            gate2_note=reason,
            notes=[reason],
        )

    # GATE 1 — the confirmed PoV must no longer reproduce.
    recheck = recheck_pov(
        pov,
        patched_target,
        timeout=timeout,
        budget=budget,
        executor=executor,
    )
    gate1 = not recheck.reproduced
    g1note = (
        f"PoV no longer reproduces — {recheck.detail}" if gate1
        else f"PoV STILL reproduces — {recheck.detail}"
    )

    # GATE 2 — no regression. Prefer a real test suite (Atlantis test.sh analog);
    # else fall back to control-input functional equivalence and SAY SO.
    if test_cmd:
        gate2, g2note = _regression_via_tests(
            test_cmd,
            cwd=test_cwd,
            timeout=timeout,
            budget=budget,
            native_compiler_path=native_compiler_path,
        )
    elif original_target is not None:
        argv0, _ = _pov_invocation(pov)
        controls = list(control_inputs) if control_inputs else [b"A"]
        gate2, g2note = _regression_via_controls(
            original_target,
            patched_target,
            controls,
            use_argv=argv0 is not None,
            timeout=timeout,
            budget=budget,
            executor=executor,
        )
    else:
        gate2, g2note = (False, "no regression oracle (no test_cmd, no original binary)")

    # Anti-cheat #1 — mitigation-only (only meaningful with a source diff).
    mitigation = bool(diff) and looks_mitigation_only(diff, sink=sink, sink_function=sink_function)
    if mitigation:
        notes.append("rejected: mitigation-only fix (hardening, not a data-flow fix)")
    elif diff and not binary_touches_taintpath:
        notes.append("diff touches the sink-function logic on the taint path")
    if binary_touches_taintpath:
        notes.append("binary patch modifies .text on the taint path (not a header/flag flip)")

    # Anti-cheat #2 — incomplete patch (only when GATE 1 already passed).
    incomplete = ""
    if gate1:
        incomplete = postpatch_fuzz_incomplete(
            pov,
            patched_target,
            iters=fuzz_iters,
            timeout=timeout,
            budget=budget,
            executor=executor,
        )
        if incomplete:
            notes.append(f"incomplete patch — {incomplete}")

    return PatchVerdict(
        gate1_closes_pov=gate1,
        gate2_no_regression=gate2,
        mitigation_only=mitigation,
        incomplete=bool(incomplete),
        gate1_note=g1note,
        gate2_note=g2note,
        notes=notes,
    )

"""Oracle / PoV-adjudication loop — the last mile of PoV-is-truth.

The agentic scanner (``agentic.explore``) emits an ``AgentVerdict`` with
``is_bug=True``. That is a **hypothesis**: a sink function + a CWE + reasoning
the LLM found plausible. It is NOT a confirmed bug. We proved WHY the distinction
matters — a confident ``is_bug=True`` on harfbuzz was a FALSE POSITIVE. The LLM
never adjudicates whether a bug is real; a deterministic oracle does, by
reproducing an actual crash.

This module closes that loop. :func:`adjudicate_finding` runs the vulnerable
binary on a proof-of-crash input under AddressSanitizer (reusing
``oracle.run_sanitizer`` / ``oracle.sanitizer_report``), parses the crash — the
crashing FUNCTION (the top application frame) and its CWE (READ vs WRITE + kind)
— and compares that ground truth to the scanner's hypothesis:

  * the crash lands at the claimed sink/source AND in the claimed bug class
    -> **CONFIRMED** (a PoV-backed finding: the hypothesis IS the real bug)
  * the crash lands somewhere else, or is a different bug class
    -> **DIVERGENT** (honest: the positive is a different-bug hypothesis or a
       false positive — NOT confirmed)
  * the input did not crash this build           -> **NO_CRASH**
  * this host cannot exec the binary (arch/loader) -> **UNRUNNABLE**

HONEST LIMITATION — benchmark-poc mode. This adjudicates against an EXISTING
proof-of-crash input (the benchmark / ARVO shape: a known crashing sample for a
known-vulnerable build). For real 0-day hunting there is NO poc: confirming a
novel hypothesis requires INPUT SYNTHESIS — driving a fresh input that both
REACHES and TRIGGERS the hypothesized sink — which is the hard reproduce problem
and is deliberately OUT OF SCOPE here. See ``inputsynth`` for that half. What
this module guarantees is the other half: that every positive with a poc in hand
is adjudicated against ground truth rather than trusted.

No LLM and no network here by design.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .oracle import host_can_launch, run_sanitizer, sanitizer_report
from .pe_symbols import resolve_crash_frame
from .windows_oracle import WindowsWorker

if TYPE_CHECKING:
    from .agentic import AgentResult, AgentVerdict

# --- status vocabulary ------------------------------------------------------

CONFIRMED = "CONFIRMED"     # crash matches the hypothesis (function + CWE) — PoV-backed
DIVERGENT = "DIVERGENT"     # crash is real but elsewhere / a different class — NOT confirmed
NO_CRASH = "NO_CRASH"       # the poc did not trigger a crash on this build
UNRUNNABLE = "UNRUNNABLE"   # this host cannot exec the binary (wrong arch / missing loader)


@dataclass
class Adjudication:
    """The deterministic verdict of running a poc against a finding's hypothesis.

    ``status`` is one of CONFIRMED / DIVERGENT / NO_CRASH / UNRUNNABLE.
    ``crash_function`` is the top *application* frame of the crash backtrace (ASan
    interceptors and libc mem/str shims skipped); ``crash_cwe`` is the crash's bug
    class derived from the sanitizer kind + READ/WRITE; ``crash_frames`` is the
    normalized access backtrace; ``reason`` explains the decision."""

    status: str
    crash_function: str = ""
    crash_cwe: str = ""
    crash_frames: list[str] = field(default_factory=list)
    reason: str = ""

    @property
    def confirmed(self) -> bool:
        return self.status == CONFIRMED


# --- crash -> CWE mapping ----------------------------------------------------
#
# The sanitizer names a *kind* (heap-buffer-overflow, use-after-free, ...) and the
# access line names READ vs WRITE. Together they map to a CWE. The family label is
# what CWE matching compares on, so a scanner that called an overflow a WRITE
# (CWE-787) still CONFIRMS when the poc's first faulting access is a READ (CWE-125)
# at the SAME function — it is the same overflow, ASan just labelled whichever
# access tripped first. Cross-family (an OOB where the scanner claimed a UAF) stays
# DIVERGENT.

# canonical CWE number -> family bucket used for match tolerance.
_CWE_FAMILY: dict[int, str] = {
    # out-of-bounds read/write/index (buffer overflow family)
    121: "oob", 122: "oob", 124: "oob", 125: "oob", 126: "oob", 127: "oob",
    129: "oob", 786: "oob", 787: "oob", 788: "oob", 823: "oob", 806: "oob",
    # use-after-free / double-free / use-after-return-or-scope
    415: "uaf", 416: "uaf", 562: "uaf", 825: "uaf",
    # null-pointer / bad deref
    476: "nullptr",
    # integer overflow / wrap (UBSan)
    190: "intoverflow", 191: "intoverflow",
    # uninitialized read (MSan)
    457: "uninit", 908: "uninit",
}


def crash_to_cwe(kind: str, access: str) -> tuple[str, str]:
    """Map a sanitizer crash ``kind`` (+ READ/WRITE ``access``) to ``(cwe, family)``.

    heap/stack/global-buffer-overflow: READ -> CWE-125, WRITE -> CWE-787 (an
    unknown access defaults to the more severe write). use-after-free /
    -after-scope -> CWE-416; double-free -> CWE-415; -after-return -> CWE-825
    (all family ``uaf``). SEGV/null -> CWE-476. UBSan integer overflow -> CWE-190.
    An unrecognized kind returns ``("", "")`` (no class asserted)."""
    k = (kind or "").lower()
    if "double-free" in k or "double free" in k:
        return ("CWE-415", "uaf")
    if "use-after-return" in k:
        return ("CWE-825", "uaf")
    if "use-after-free" in k or "use-after-scope" in k:
        return ("CWE-416", "uaf")
    if "buffer-overflow" in k or "buffer-underflow" in k \
            or "out-of-bounds" in k or "outofbounds" in k \
            or "dynamic-stack-buffer-overflow" in k:
        if access == "WRITE":
            return ("CWE-787", "oob")
        if access == "READ":
            return ("CWE-125", "oob")
        return ("CWE-787", "oob")  # kind is an overflow but access unknown
    if "integer-overflow" in k or "signed integer overflow" in k \
            or "unsigned integer overflow" in k:
        return ("CWE-190", "intoverflow")
    if "null" in k or "sigsegv" in k or "segv" in k or "segmentation" in k:
        return ("CWE-476", "nullptr")
    if "use-of-uninitialized" in k or "uninitialized" in k:
        return ("CWE-457", "uninit")
    return ("", "")


def _cwe_num(text: str) -> int | None:
    """First CWE number in ``text`` (accepts ``CWE-787``, ``787``, ``CWE-787:
    Out-of-bounds Write``)."""
    m = re.search(r"\b(\d{2,4})\b", text or "")
    return int(m.group(1)) if m else None


def cwe_matches(claimed: str, crash_cwe: str, crash_family: str) -> bool:
    """True when the finding's claimed CWE matches the crash's — exactly by number
    or within the same family bucket (READ/WRITE confusion inside the OOB family,
    double-free vs UAF, ...). Unparseable/unknown either side -> no match."""
    cn = _cwe_num(claimed)
    xn = _cwe_num(crash_cwe)
    if cn is None or xn is None:
        return False
    if cn == xn:
        return True
    fam = _CWE_FAMILY.get(cn)
    return fam is not None and fam == crash_family and crash_family != ""


# --- function-name matching (Ghidra-vs-source demangling robust) -------------
#
# The finding's ``sink``/``source`` come from Ghidra pseudo-C: a plain identifier
# (``parseAdobeRAFMakernote``), sometimes a demangled qualified name
# (``LibRaw::parseAdobeRAFMakernote``), a Ghidra ``operator.new``, or an OSS-Fuzz
# ``OSS_FUZZ_`` wrapper. The crash frame comes from the ASan-symbolized backtrace:
# often the same leaf but with a full C++ signature
# (``LibRaw::parseAdobeRAFMakernote(void*, unsigned int)``) and namespace/template
# decoration. We normalize both to a comparable core and match with substring +
# leaf-component rules so these encodings line up without requiring an exact string.

_OSS_FUZZ_PREFIX = "OSS_FUZZ_"


def _norm_func(name: str) -> str:
    """Normalize a function name for comparison: drop the C++ argument list, template
    parameters, and an ``OSS_FUZZ_`` wrapper prefix, keeping namespace qualifiers."""
    s = (name or "").strip()
    s = re.sub(r"<[^<>]*>", "", s)      # template args
    s = re.sub(r"\(.*$", "", s)          # everything from the first '(' (signature)
    s = s.strip()
    if s.startswith(_OSS_FUZZ_PREFIX):
        s = s[len(_OSS_FUZZ_PREFIX):]
    return s.strip()


def _cores(name: str) -> tuple[str, str]:
    """Return ``(full_core, leaf_core)`` — the alnum/underscore-only lowercased forms
    of the whole normalized name and of its last ``::`` component. ``operator.new``
    keeps its dot stripped so ``operatornew`` compares cleanly."""
    n = _norm_func(name)
    full = re.sub(r"[^A-Za-z0-9_]", "", n).lower()
    leaf = re.sub(r"[^A-Za-z0-9_]", "", n.split("::")[-1]).lower()
    return full, leaf


def func_matches(crash_fn: str, claim: str) -> bool:
    """True when the crash's function is the same as a finding's claimed sink/source,
    robust to Ghidra-vs-source demangling. Matches when the normalized cores are a
    substring of each other (``parseAdobeRAFMakernote`` in
    ``LibRaw::parseAdobeRAFMakernote(void*, uint)``) or the last ``::`` components are
    equal / substring-equal (guarded by a length floor so short leaves don't match
    spuriously)."""
    cf, cl = _cores(crash_fn)
    qf, ql = _cores(claim)
    if not cf or not qf:
        return False
    if cf in qf or qf in cf:
        return True
    if cl and ql and cl == ql:
        return True
    return bool(cl and ql and (cl in ql or ql in cl) and min(len(cl), len(ql)) >= 4)


# --- ASan backtrace parsing --------------------------------------------------

# Sanitizer-runtime / libc-interceptor frames that sit ABOVE the real app frame in
# the backtrace (``#0 __asan_memcpy`` then ``#1 <the caller with the bug>``). The
# "crashing function" a finding should be compared against is the first frame that
# is NOT one of these.
_RUNTIME_PREFIXES: tuple[str, ...] = (
    "__asan", "__lsan", "__msan", "__tsan", "__ubsan", "__hwasan",
    "__sanitizer", "__interceptor",
)
_LIBC_INTERCEPTORS: frozenset[str] = frozenset({
    "memcpy", "memmove", "memset", "mempcpy", "memchr", "memcmp", "memrchr",
    "strcpy", "strncpy", "strcat", "strncat", "strlen", "strnlen", "strcmp",
    "strncmp", "strchr", "strrchr", "strdup", "strndup", "strlcpy", "strlcat",
    "wmemcpy", "wcscpy", "wcslen", "bcopy", "bzero",
    "malloc", "calloc", "realloc", "free", "operatornew", "operatordelete",
})

# One backtrace line: ``    #3 0x4f7a2c in <rest>`` (the ``in`` is absent for a
# frame with no symbol, where <rest> is just ``(module+0xNN)``).
_FRAME_RE = re.compile(r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+(?:in\s+)?(?P<rest>.*)$")
# The READ/WRITE access line that precedes the access backtrace.
_ACCESS_RE = re.compile(r"\b(READ|WRITE) of size (\d+)")
# Trailing ``(module+0xNN)`` and trailing ``file.ext:line[:col]`` on a frame's rest.
_MODULE_TAIL = re.compile(r"\s*\([^()]*\+0x[0-9a-fA-F]+\)\s*$")
_FILE_TAIL = re.compile(r"\s+([\w./\\-]+\.[A-Za-z0-9_]+:\d+(?::\d+)?)\s*$")

# Dr. Memory emits ``# 0 module.exe!symbol [file:line]`` while cdb emits
# ``module!symbol+0xNN`` in its STACK_TEXT block.  Keep these parsers here so every
# execution backend feeds the same CrashInfo/adjudication contract.
_DRMEM_ACCESS_RE = re.compile(
    r"(?:UNADDRESSABLE ACCESS|USE AFTER FREE):\s*(reading|writing)\s+(\d+)\s+byte",
    re.IGNORECASE,
)
_DRMEM_FRAME_RE = re.compile(r"^\s*#\s*\d+\s+(?P<rest>.+?)\s*$")
_CDB_EXCEPTION_RE = re.compile(r"EXCEPTION_CODE:\s*\([^)]*\)\s*(?:0x)?([0-9a-fA-F]+)", re.I)
_CDB_ACCESS_RE = re.compile(r"Attempt to (read from|write to) address", re.I)
_CDB_FRAME_RE = re.compile(
    r"^\s*[0-9a-fA-F`]+\s+.*?"
    r"(?P<frame>[A-Za-z0-9_.-]+(?:![^\s]+|\+0x[0-9a-fA-F]+))\s*$",
)

_WINDOWS_INTERCEPTORS: frozenset[str] = frozenset({
    "rtlallocatheap", "rtlfreeheap", "heapalloc", "heapfree",
    "rtlmovememory", "rtlfillmemory", "copymemory", "movememory",
})
_WINDOWS_RUNTIME_PREFIXES: tuple[str, ...] = (
    "verifier", "avrf", "rtl", "basethread", "rtluserthread", "free_base",
)


def _frame_function(rest: str) -> str:
    """Extract just the function name from a frame's post-``in`` remainder, stripping
    a trailing ``(module+0xNN)`` and a trailing ``file:line[:col]`` while preserving a
    C++ signature/namespace (``LibRaw::parse(void*, int)``)."""
    s = rest.strip()
    s = _MODULE_TAIL.sub("", s)
    s = _FILE_TAIL.sub("", s)
    return s.strip()


def _is_runtime_frame(func: str) -> bool:
    """True when ``func`` is a sanitizer-runtime or libc mem/str interceptor frame —
    the kind that sits above the real crashing app frame and should be skipped."""
    _full, leaf = _cores(func)
    if any(leaf.startswith(p.replace("_", "")) for p in _RUNTIME_PREFIXES):
        return True
    # startswith check on the raw normalized name too (leaf strips underscores)
    n = _norm_func(func)
    if any(n.startswith(p) for p in _RUNTIME_PREFIXES):
        return True
    return (
        leaf in _LIBC_INTERCEPTORS
        or leaf in _WINDOWS_INTERCEPTORS
        or any(leaf.startswith(prefix) for prefix in _WINDOWS_RUNTIME_PREFIXES)
    )


@dataclass
class CrashInfo:
    """Everything parsed from a sanitizer report: the bug kind, the faulting access
    (READ/WRITE + size), the access backtrace, and the derived crashing function
    (top app frame) + CWE."""

    kind: str = ""
    access: str = ""
    size: int | None = None
    frames: list[str] = field(default_factory=list)
    crash_function: str = ""
    cwe: str = ""
    family: str = ""

    @property
    def crashed(self) -> bool:
        return bool(self.kind)


def parse_asan_crash(stderr: str, *, kind_hint: str = "") -> CrashInfo:
    """Parse an AddressSanitizer report into a :class:`CrashInfo`.

    Extracts the crash kind (via ``oracle.sanitizer_report``, or ``kind_hint`` when the
    caller already has ``RunResult.sanitizer``), the faulting READ/WRITE + size, and the
    ACCESS backtrace — the FIRST contiguous ``#0.. #1.. #2..`` block, which for a UAF is
    the use site, deliberately NOT the ``freed by`` / ``allocated by`` secondary stacks.
    The crashing function is the first app frame in that block (sanitizer/libc
    interceptors skipped); the CWE follows from kind + access."""
    # Derive the SPECIFIC kind from the report itself (source of truth) — a caller's
    # ``kind_hint`` may be the generic "AddressSanitizer", which carries no CWE.
    kind = sanitizer_report(stderr) or kind_hint
    acc = _ACCESS_RE.search(stderr)
    access = acc.group(1) if acc else ""
    size = int(acc.group(2)) if acc else None

    # Collect the FIRST contiguous backtrace block (the access stack). Start at the
    # first ``#0`` line, stop when the ``#N`` sequence breaks (a blank line or a
    # ``freed by``/``previously allocated`` header ends it).
    raw_frames: list[str] = []
    started = False
    for line in stderr.splitlines():
        m = _FRAME_RE.match(line)
        if m:
            if not started and m.group(1) != "0":
                # frames before the first ``#0`` (rare) — ignore until #0
                continue
            started = True
            raw_frames.append(m.group("rest"))
        elif started:
            break  # sequence ended — this was the access block

    funcs = [_frame_function(r) for r in raw_frames]
    frames = [f for f in funcs if f]

    crash_function = ""
    for f in frames:
        if not _is_runtime_frame(f):
            crash_function = f
            break
    if not crash_function and frames:
        crash_function = frames[0]  # everything was an interceptor — take the top

    cwe, family = crash_to_cwe(kind, access)
    return CrashInfo(
        kind=kind, access=access, size=size, frames=frames,
        crash_function=crash_function, cwe=cwe, family=family,
    )


def _windows_function(frame: str) -> str:
    """Normalize ``module!symbol+offset`` Windows frames to a function name."""
    s = re.sub(r"\s*\[[^]]+\]\s*$", "", frame.strip())
    if "!" in s:
        s = s.split("!", 1)[1]
        return re.sub(r"\+0x[0-9a-fA-F]+$", "", s).strip()
    # Preserve image+RVA so a local PE/COFF table can resolve it later.
    return s.strip()


def _crash_info(kind: str, access: str, size: int | None, frames: list[str]) -> CrashInfo:
    funcs = [_windows_function(frame) for frame in frames]
    funcs = [func for func in funcs if func]
    crash_function = next((f for f in funcs if not _is_runtime_frame(f)), funcs[0] if funcs else "")
    cwe, family = crash_to_cwe(kind, access)
    return CrashInfo(kind, access, size, funcs, crash_function, cwe, family)


def parse_drmemory_crash(report: str) -> CrashInfo:
    """Parse a Dr. Memory error block into the backend-neutral CrashInfo."""
    upper = report.upper()
    access_match = _DRMEM_ACCESS_RE.search(report)
    access = ({"reading": "READ", "writing": "WRITE"}.get(
        access_match.group(1).lower(), ""
    ) if access_match else "")
    size = int(access_match.group(2)) if access_match else None
    if "USE AFTER FREE" in upper:
        kind = "use-after-free"
    elif "INVALID HEAP ARGUMENT" in upper:
        kind = "double-free" if "DOUBLE" in upper else "invalid-heap-argument"
    elif "UNADDRESSABLE ACCESS" in upper:
        kind = "heap-buffer-overflow"
    else:
        return CrashInfo()
    frames = [m.group("rest") for line in report.splitlines()
              if (m := _DRMEM_FRAME_RE.match(line))]
    return _crash_info(kind, access, size, frames)


def parse_cdb_crash(report: str) -> CrashInfo:
    """Parse ``cdb !analyze -v`` output produced under PageHeap/AppVerifier."""
    code_match = _CDB_EXCEPTION_RE.search(report)
    code = code_match.group(1).lower().lstrip("0") if code_match else ""
    access_match = _CDB_ACCESS_RE.search(report)
    access = "WRITE" if access_match and access_match.group(1).lower().startswith("write") else (
        "READ" if access_match else ""
    )
    if code.endswith("c0000409"):
        kind = "stack-buffer-overflow"
        access = access or "WRITE"
    elif code.endswith("c0000374") or "VERIFIER STOP" in report.upper():
        kind = "heap-buffer-overflow"
        access = access or "WRITE"
    elif code.endswith("c0000005"):
        # Under full PageHeap the AV occurs at the invalid heap access itself.
        kind = "heap-buffer-overflow" if access else "sigsegv"
    else:
        return CrashInfo()
    frames = [m.group("frame") for line in report.splitlines()
              if (m := _CDB_FRAME_RE.match(line))]
    return _crash_info(kind, access, None, frames)


# --- the adjudication entry point -------------------------------------------

def _poc_bytes(poc_input: bytes | str | Path) -> bytes:
    """Accept a poc as raw bytes or a path to a poc file. A ``str``/``Path`` that
    names an existing file is read; raw ``bytes`` are used as-is."""
    if isinstance(poc_input, (str, Path)):
        p = Path(poc_input)
        if p.is_file():
            return p.read_bytes()
        # A str that is not a path is treated as literal bytes (latin-1 round-trips).
        return str(poc_input).encode("latin-1", "replace")
    return bytes(poc_input)


def _backend_for(binary: str, requested: str) -> str:
    if requested not in {"auto", "asan-linux", "windows"}:
        raise ValueError(f"unknown adjudication backend: {requested}")
    if requested != "auto":
        return requested
    try:
        with Path(binary).open("rb") as handle:
            magic = handle.read(2)
        return "windows" if magic == b"MZ" else "asan-linux"
    except OSError:
        return "asan-linux"


def adjudicate_finding(
    verdict: AgentVerdict,
    vuln_binary: str | Path,
    poc_input: bytes | str | Path,
    *,
    vector: str = "file",
    timeout: float = 10.0,
    backend: str = "auto",
) -> Adjudication:
    """Adjudicate a scanner hypothesis against ground truth by reproducing the crash.

    Runs ``vuln_binary`` on ``poc_input`` (delivered via ``vector`` — ``file`` for the
    ARVO/libFuzzer ``./target /poc`` shape, ``stdin``/``argv`` otherwise) under
    AddressSanitizer, parses the crash, and compares the crashing FUNCTION and CWE to
    ``verdict.sink``/``verdict.source`` and ``verdict.cwe``:

      * function matches (sink OR source) AND CWE matches -> ``CONFIRMED``
      * a real crash but elsewhere / a different class     -> ``DIVERGENT``
      * no crash                                            -> ``NO_CRASH``
      * host cannot exec the binary                         -> ``UNRUNNABLE``

    Honest by construction: only a reproduced crash whose location AND class match the
    hypothesis is CONFIRMED — the LLM's confidence never enters. See the module
    docstring for the benchmark-poc-vs-input-synthesis limitation."""
    binary = str(vuln_binary)
    selected_backend = _backend_for(binary, backend)

    if selected_backend == "windows":
        worker = WindowsWorker.from_env()
        if worker is None:
            return Adjudication(
                status=UNRUNNABLE,
                reason="PE requires a Windows worker; set ZEROVERSE_WINDOWS_HOST.",
            )
        available, detail = worker.available()
        if not available:
            return Adjudication(
                status=UNRUNNABLE,
                reason=f"Windows worker {worker.host!r} unavailable: {detail}",
            )
        run = worker.run_drmemory(
            binary, _poc_bytes(poc_input), vector=vector, timeout=timeout,
        )
        if not run.crashed and "0VERSE-EXIT:-1" in run.stderr:
            run = worker.run_pageheap(
                binary, _poc_bytes(poc_input), vector=vector, timeout=timeout,
            )
    else:
        # UNRUNNABLE — this host cannot exec the target (wrong arch / missing loader).
        if not host_can_launch(binary, timeout=min(timeout, 5.0)):
            return Adjudication(
                status=UNRUNNABLE,
                reason=(
                    f"host cannot exec {binary!r}; "  # foxguard: ignore[py/no-sql-injection]
                    "wrong arch or missing loader; cannot adjudicate on this host "
                    "— run on the bench."
                ),
            )
        run = run_sanitizer(
            binary, _poc_bytes(poc_input), vector=vector, timeout=timeout,
        )

    if not run.valid:
        detail = run.infrastructure_error or ("target timeout" if run.timed_out else run.stderr)
        return Adjudication(
            status=UNRUNNABLE,
            reason=f"execution produced no valid verdict: {detail[:160]}",
        )

    # NO_CRASH — the poc did not trip the sanitizer on this build.
    if not run.crashed:
        detail = run.stderr.strip().splitlines()[-1][:80] if run.stderr.strip() else "clean exit"
        return Adjudication(
            status=NO_CRASH,
            reason=(f"poc did not crash this build (no sanitizer report; {detail!r}). "
                    "The hypothesis is unproven against this input."),
        )

    if selected_backend == "windows":
        crash = (
            parse_cdb_crash(run.stderr)
            if run.sanitizer == "pageheap-cdb"
            else parse_drmemory_crash(run.stderr)
        )
        # Never replace a symbol cdb already resolved. COFF fallback applies only
        # to the selected unsymbolized ``image+RVA`` application frame.
        resolved = resolve_crash_frame(binary, [crash.crash_function])
        if resolved:
            crash.crash_function = resolved
    else:
        crash = parse_asan_crash(run.stderr, kind_hint=run.sanitizer)
    fn_match = (
        func_matches(crash.crash_function, verdict.sink)
        or func_matches(crash.crash_function, verdict.source)
    )
    cwe_ok = cwe_matches(verdict.cwe, crash.cwe, crash.family)

    if fn_match and cwe_ok:
        status = CONFIRMED
        reason = (
            f"PoV-backed: crash {crash.kind} ({crash.access or 'access'}) at "
            f"{crash.crash_function!r} matches the finding's "
            f"sink={verdict.sink!r}/source={verdict.source!r} and class "
            f"{verdict.cwe!r} ~= {crash.cwe}. The hypothesis IS the real bug."
        )
    else:
        status = DIVERGENT
        why: list[str] = []
        if not fn_match:
            why.append(
                f"crash function {crash.crash_function!r} does not match "
                f"sink={verdict.sink!r}/source={verdict.source!r}"
            )
        if not cwe_ok:
            why.append(
                f"crash class {crash.cwe or '?'} does not match claimed {verdict.cwe!r}"
            )
        reason = (
            "divergent (NOT confirmed): the poc crashes, but " + "; ".join(why)
            + ". The positive is a different-bug hypothesis or a false positive."
        )

    return Adjudication(
        status=status,
        crash_function=crash.crash_function,
        crash_cwe=crash.cwe,
        crash_frames=list(crash.frames),
        reason=reason,
    )


def adjudicate_result(
    result: AgentResult,
    vuln_binary: str | Path,
    poc_input: bytes | str | Path,
    *,
    vector: str = "file",
    timeout: float = 10.0,
) -> AgentResult:
    """Thin wiring: adjudicate a POSITIVE ``AgentResult`` against a poc and attach the
    :class:`Adjudication` to ``result.adjudication``, returning the same result. A
    non-positive (no verdict / ``is_bug=False``) result is returned unchanged — there
    is nothing to confirm. ``explore`` itself is untouched; this is the separate
    post-step the integrator/pipeline calls when a poc is available."""
    v = result.verdict
    if v is None or not v.is_bug:
        return result
    result.adjudication = adjudicate_finding(
        v, vuln_binary, poc_input, vector=vector, timeout=timeout,
    )
    return result

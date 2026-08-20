"""M4 — bug-class lenses + confirming oracles (#22-#26).

M1 shipped one confirmed class (stack/heap buffer overflow) end to end. M4 widens
the engine to five more classes the *same way* M1 works: every class is a **static
detection lens** (a high-recall hypothesis generator over Ghidra's decompiled C —
exactly like the foxguard pre-pass and the seed-bug-class) plus, *where a generic
oracle exists*, a **confirming oracle** that turns a candidate trigger into a
reproducing PoV. PoV-is-truth still holds: a class is only ``confirmed`` with a
reproducing PoV; a class without a generic oracle stays an honest *hypothesis*.

The five classes:

  * **#22 intoverflow** — lens: size arithmetic (``a*b`` / ``a+len`` / shifts)
    feeding malloc/calloc/realloc/alloca/memcpy. Oracle: REUSE the
    differential-allocator (``oracle.differential_allocator`` + the page-granular
    quarantine guard) — an input that overflows the size computation yields an
    undersized alloc and a heap OOB that only faults under the guard. *Confirmable.*
  * **#23 fmtstring** — lens: a taint-controlled value in the *format* position
    (not the varargs) of printf/fprintf/sprintf/snprintf/syslog. Oracle: feed a
    ``%s``-spray (+ ``%n``) probe → a wild read/write crash a benign control does
    not trigger (differential). *Confirmable.*
  * **#24 uaf** — lens: ``free(p)`` then a later use of ``p`` (use-after-free), or
    ``free(p)`` twice (double-free). Oracle: the **quarantine guard allocator**
    (``oracle.uaf_differential``) poisons + mprotects freed regions, so a UAF
    read/write faults (SIGSEGV) and a double-free traps — dynamic confirmation,
    not just static. The hardest binary class: confirmable *given a triggering
    input*, otherwise an honest hypothesis.
  * **#25 cmdi** — lens: taint into system/popen/exec*/posix_spawn (the format-1
    of the M1 canary, now first-class). Oracle: a sentinel-command canary that
    PROVES injection without running anything harmful. *Confirmable.*
  * **#26 logic** — lens: LLM-led reasoning over comparison/auth/missing-check/
    off-by-one shapes. **Hypothesis-only** — surfaced as high-value funnel leads,
    NEVER confirmed without a PoV (no generic binary oracle exists).

Each lens tags its findings with ``origin = "bugclass:<id>"`` so the pipeline
funnel ranks them alongside the #2 slice + #3 foxguard + seed hypotheses, and the
confirmable ones route to their oracle → PoV → report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from . import oracle
from .agent import Verdict
from .analyze import Finding
from .preflight import BudgetTracker
from .report import PoV
from .sandbox_exec import Executor


def _presence(
    decompiled_c: dict[str, str], names: tuple[str, ...]
) -> tuple[list[tuple[str, str]], list[dict[str, bool]]]:
    """Per-function keyword presence — the #31 algorithmic fast-path.

    Returns the ``(func, code)`` items and, per item, a ``{name: present}`` map. A
    lens uses this to SKIP a keyword whose substring is absent: a ``\\bNAME\\s*(``
    regex can only match where ``NAME`` literally occurs, so skipping absent names
    never changes a lens's output — it only avoids a doomed ``re.finditer`` pass.
    This is what collapses the lens scan from ~3.7s to ~0.6s on a large corpus.

    Deliberately pure Python: the haystacks are thousands of *small* function
    bodies, where CPython's C ``in`` (memmem) beats crossing into the Rust
    extension — the native fast-path wins on *large contiguous* blobs (ingest),
    not on many tiny strings (measured; see docs/PERF.md). Bytes scanning of the
    big binary itself uses ``_fastpath.contains_any_bytes``."""
    items = list(decompiled_c.items())
    presence = [{name: name in code for name in names} for _, code in items]
    return items, presence

# Input/source functions that mark how attacker bytes enter — used to pick the
# delivery vector for a confirming oracle and to label the lens hypothesis.
_INPUT_FUNCS = (
    "recv", "recvfrom", "read", "fgets", "gets", "fread", "scanf", "sscanf",
    "getenv", "fscanf", "getline",
)
_IDENT = r"[A-Za-z_]\w*"


def _input_source(code: str) -> str:
    """Name the input function present in a function body (best-effort), so a
    hypothesis records a plausible attacker vector. Defaults to ``stdin``."""
    for fn in _INPUT_FUNCS:
        if re.search(rf"\b{fn}\s*\(", code):
            return fn
    return "stdin"


def vector_for(source: str) -> str:
    """Map a source function to a delivery vector for the confirming oracle."""
    if source == "getenv":
        return "env"
    if source in ("argv", "main"):
        return "argv"
    return "stdin"


# --- bug-class registry ----------------------------------------------------

@dataclass(frozen=True)
class BugClass:
    """A declarative M4 bug class: the lens id/label, whether a generic confirming
    oracle exists, and the variant-analysis framing handed to the LLM funnel."""

    id: str
    label: str
    cwe: str
    confirmable: bool
    framing: str

    @property
    def origin(self) -> str:
        return f"bugclass:{self.id}"


INTOVERFLOW = BugClass(
    id="intoverflow",
    label="integer overflow in size computation",
    cwe="CWE-190",
    confirmable=True,
    framing=(
        "integer-overflow-to-buffer-overflow: a size computation (multiply / add / "
        "shift of attacker-controlled lengths) wraps or truncates, producing an "
        "undersized allocation that a later copy overflows — look for the same "
        "unchecked size arithmetic feeding a different malloc/copy"
    ),
)
FMTSTRING = BugClass(
    id="fmtstring",
    label="format-string (tainted format argument)",
    cwe="CWE-134",
    confirmable=True,
    framing=(
        "format-string bug: attacker-controlled data reaches the FORMAT argument "
        "of a printf-family call (not the varargs) — look for the same tainted "
        "value reaching a different printf/sprintf/syslog format position"
    ),
)
UAF = BugClass(
    id="uaf",
    label="use-after-free / double-free",
    cwe="CWE-416",
    confirmable=True,
    framing=(
        "use-after-free / double-free: a heap pointer is used (or freed) after it "
        "was freed — look for the same lifetime mistake on a sibling pointer or a "
        "different free/use ordering reached through another path"
    ),
)
CMDI = BugClass(
    id="cmdi",
    label="OS command injection",
    cwe="CWE-78",
    confirmable=True,
    framing=(
        "OS command injection: attacker-controlled data reaches a "
        "system/popen/exec*/posix_spawn argument unsanitized — look for the same "
        "tainted value reaching another command-execution sink"
    ),
)
LOGIC = BugClass(
    id="logic",
    label="auth-bypass / logic / off-by-one (hypothesis-only)",
    cwe="CWE-697",
    confirmable=False,
    framing=(
        "authentication-bypass / logic bug (Big-Sleep style): a comparison, "
        "permission, or bounds check that is missing, inverted, off-by-one, or "
        "uses a non-constant-time / wrong-length compare so an attacker reaches a "
        "privileged path — reason about the INTENT of the check, not just its "
        "shape; this class has no generic binary oracle, so it stays a high-value "
        "HYPOTHESIS until a PoV proves it"
    ),
)

OVERFLOW = BugClass(
    id="overflow",
    label="buffer overflow (unbounded string sink / loop-writer)",
    cwe="CWE-120",
    confirmable=True,
    framing=(
        "buffer overflow: attacker-controlled data reaches an unbounded string "
        "sink (stpcpy / sprintf(\"%s\") / ignored-strlcat) or a decode loop "
        "whose write cursor outruns the destination allocation — look for the "
        "same unbounded copy / cursor-vs-capacity mismatch on a sibling buffer"
    ),
)
LOOP_OOB = BugClass(
    id="loop-oob",
    label="loop-based OOB write with attacker-controlled bound",
    cwe="CWE-787",
    confirmable=True,
    framing=(
        "loop-based out-of-bounds write: a store into a fixed-size buffer inside a "
        "loop whose bound (or index) is data-dependent on untrusted input "
        "(read/recv/fread/scanf/argv) with no clamp to the destination capacity — "
        "the ``for(i=0;i<n;i++) buf[i]=…`` shape (e.g. lcms ``WriteCLUT``) that a "
        "library-call sink model (memcpy/strcpy) misses; look for the same "
        "input-controlled count driving a write cursor over a sibling buffer"
    ),
)
BUG_CLASSES: tuple[BugClass, ...] = (
    OVERFLOW, LOOP_OOB, INTOVERFLOW, FMTSTRING, UAF, CMDI, LOGIC,
)
_BY_ID = {bc.id: bc for bc in BUG_CLASSES}
CONFIRMABLE_ORIGINS: frozenset[str] = frozenset(
    bc.origin for bc in BUG_CLASSES if bc.confirmable
)


def bug_class_for_origin(origin: str) -> BugClass | None:
    if not origin.startswith("bugclass:"):
        return None
    return _BY_ID.get(origin.split(":", 1)[1])


def cwe_for_finding(finding: Finding) -> str:
    """The precise CWE for a bug-class finding. Temporal safety splits the UAF
    class in two: a *double-free* (the lens tags it in ``finding.sink``) is
    **CWE-415**, while a use-after-free / realloc-stale / refcount-drop use is
    **CWE-416**. Every other class defers to its ``BugClass.cwe``."""
    bc = bug_class_for_origin(finding.origin)
    if bc is None:
        return ""
    if bc is UAF and "double-free" in finding.sink:
        return "CWE-415"
    return bc.cwe


# --- static detection lenses (hypothesis generators) -----------------------

# An allocation/copy sink whose size argument could be a wrapped computation.
# NOTE: ``calloc(a, b)`` is intentionally absent — it has a built-in multiply
# overflow guard (IO-01 downgrade), so a bare calloc is not an int-overflow sink.
_ALLOC_NAMES = (
    "malloc", "realloc", "alloca", "memcpy", "memmove", "memset",
    "strncpy", "strncat", "snprintf",
)
# The write/copy subset of the alloc/copy sinks — where an int-overflow OOB
# actually manifests (the undersized buffer is overflowed by the copy, not by the
# allocation call itself).
_COPY_WRITE_SINKS = frozenset({
    "memcpy", "memmove", "memset", "strncpy", "strncat", "snprintf",
})
_ALLOC_CALL = re.compile(r"\b(" + "|".join(_ALLOC_NAMES) + r")\s*\(")
# A multiply / shift between two operands. The left operand being a C type keyword
# means it's a pointer declaration (``char *p``), not a size multiply — excluded.
_MUL_SHIFT = re.compile(r"([A-Za-z_]\w*|\)|\])\s*(?:\*|<<)\s*([A-Za-z_(]\w*|\d)")
_TYPE_WORDS = frozenset({
    "char", "short", "int", "long", "unsigned", "signed", "void", "size_t",
    "ssize_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t",
    "int16_t", "int32_t", "int64_t", "float", "double", "const", "struct",
    "u8", "u16", "u32", "u64", "byte", "uchar", "ushort", "uint", "ulong",
    "wchar_t", "FILE", "ulonglong", "uint128_t",
})
_ARITH_IN_ARGS = re.compile(r"[\w\)\]]\s*(?:\*|<<|\+)\s*[\w(]")


def _has_size_arith(code: str, alloc_spans: list[tuple[int, int]]) -> bool:
    """True if a size computation (multiply/shift of non-type operands, anywhere,
    or any arithmetic inside an allocation/copy call's argument list) is present."""
    if any(m.group(1) not in _TYPE_WORDS for m in _MUL_SHIFT.finditer(code)):
        return True
    return any(_ARITH_IN_ARGS.search(code[lo:hi]) for lo, hi in alloc_spans)


# A size-bearing call whose final argument is the size/length operand.
_SIZE_SINKS = (
    "malloc", "realloc", "alloca", "memcpy", "memmove", "memset", "calloc",
    "copy_from_user", "_copy_from_user", "kmalloc", "kzalloc", "kvmalloc",
    "strncpy", "strncat", "snprintf",
)
_SIGNED_DECL = re.compile(
    r"\b(?:int|short|long|ssize_t|ptrdiff_t|int8_t|int16_t|int32_t|int64_t|char)\s+[\w,\s]*\b{v}\b"
)


def _size_arg_idents(code: str) -> list[str]:
    """The bare-identifier size operand (final arg) of each size-bearing call."""
    out: list[str] = []
    for name in _SIZE_SINKS:
        if name not in code:
            continue
        for m in re.finditer(rf"\b{name}\s*\(", code):
            args = _balanced_args(code, m.end() - 1)
            if args is None:
                continue
            last = _arg_at(args, _arg_count(args) - 1)
            if last and re.fullmatch(_IDENT, last):
                out.append(last)
    return out


def _arg_count(args: str) -> int:
    depth, n = 0, 1
    if args.strip() == "":
        return 0
    for ch in args:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "," and depth == 0:
            n += 1
    return n


def _signed_unsigned_size(code: str) -> bool:
    """CWE-839: a signed-typed length with ONLY an upper-bound check (no
    ``len < 0`` / ``len >= 0`` lower bound, no unsigned cast) consumed as a size.
    Top-yield / low-FP: the missing ``>= 0`` lets a negative length become a huge
    unsigned size at the call. A present lower-bound is the FP-suppressor."""
    for v in set(_size_arg_idents(code)):
        ev = re.escape(v)
        signed = re.search(_SIGNED_DECL.pattern.replace("{v}", ev), code) is not None
        if not signed:
            continue
        upper = (
            re.search(rf"{ev}\s*(?:>|>=)\s*[\w(]", code) is not None
            or re.search(rf"[\w)]\s*(?:<|<=)\s*{ev}\b", code) is not None
        )
        lower = (
            re.search(rf"{ev}\s*<\s*0\b", code) is not None
            or re.search(rf"{ev}\s*>=?\s*0\b", code) is not None
            or re.search(rf"\(\s*(?:unsigned|size_t|u32|u64)[^)]*\)\s*{ev}\b", code)
            is not None
        )
        if upper and not lower:
            return True
    return False


_ADD_ASSIGN = re.compile(rf"\b({_IDENT})\s*=\s*[^;]*\b{_IDENT}\s*\+\s*{_IDENT}")
_ALLOC_OF_IDENT = ("malloc", "realloc", "kmalloc", "kvmalloc", "alloca", "kzalloc")


def _additive_alloc_size(code: str) -> bool:
    """IO-02: an allocation sized by a named intermediate that was assigned an
    additive sum (``size = hdr + len1 + len2``) — the additive-wrap shape that a
    product-only size model misses."""
    sums = {m.group(1) for m in _ADD_ASSIGN.finditer(code)}
    if not sums:
        return False
    for name in _ALLOC_OF_IDENT:
        if name not in code:
            continue
        for m in re.finditer(rf"\b{name}\s*\(\s*({_IDENT})\s*[,)]", code):
            if m.group(1) in sums:
                return True
    return False


def intoverflow_lens(decompiled_c: dict[str, str]) -> list[Finding]:
    """Flag functions where size arithmetic (``*`` / ``<<`` / ``+``) builds a value
    that feeds an allocation or sized copy — the int-overflow-to-OOB shape."""
    out: list[Finding] = []
    items, presence = _presence(decompiled_c, _ALLOC_NAMES)
    for (func, code), present in zip(items, presence, strict=True):
        if not code or not any(present.values()):
            continue  # no alloc/copy name occurs — _ALLOC_CALL cannot match
        calls = list(_ALLOC_CALL.finditer(code))
        if not calls:
            continue
        spans = []
        for c in calls:
            args = _balanced_args(code, c.end() - 1)
            if args is not None:
                spans.append((c.end(), c.end() + len(args)))
        arith = _has_size_arith(code, spans)
        signed = _signed_unsigned_size(code)
        additive = _additive_alloc_size(code)
        if not (arith or signed or additive):
            continue
        detail = (
            "signed-unsigned" if signed and not arith
            else "additive-wrap" if additive and not arith
            else ""
        )
        # Report the sink where the overflow MANIFESTS: a wrapped size yields an
        # undersized allocation, but the OOB write happens at the *copy* fed the
        # real (un-wrapped) length. Prefer a copy/write sink over the bare
        # allocation so the finding lands on the overflowing memcpy, not the
        # malloc (matches the labeled bug + routes the confirming oracle right).
        sink_name = next(
            (c.group(1) for c in calls if c.group(1) in _COPY_WRITE_SINKS),
            calls[0].group(1),
        )
        out.append(_hyp(INTOVERFLOW, _input_source(code), sink_name, func,
                        detail=detail))
    return out


# printf-family whose FORMAT position is a bare identifier (not a "string literal").
# format position index per call: printf(fmt), fprintf(stream, fmt),
# sprintf(buf, fmt), snprintf(buf, n, fmt), syslog(pri, fmt), dprintf(fd, fmt).
_FMT_CALLS: tuple[tuple[str, int], ...] = (
    ("printf", 0), ("fprintf", 1), ("dprintf", 1), ("sprintf", 1),
    ("snprintf", 2), ("vsnprintf", 2), ("asprintf", 1), ("vasprintf", 1),
    ("syslog", 1), ("vsyslog", 1), ("vprintf", 0), ("vfprintf", 1),
    ("vdprintf", 1),
    # BSD err/warn family — err* carry a leading eval int (fmt=1); warn* do not
    # (fmt=0). This per-function arg position is the FS-01 correctness fix.
    ("err", 1), ("errx", 1), ("verr", 1), ("verrx", 1),
    ("warn", 0), ("warnx", 0), ("vwarn", 0), ("vwarnx", 0),
)


def _arg_at(args: str, idx: int) -> str | None:
    """Split a (shallow) C arg list and return arg ``idx`` trimmed, or None."""
    depth, cur, parts = 0, "", []
    for ch in args:
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
            continue
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        cur += ch
    parts.append(cur)
    return parts[idx].strip() if 0 <= idx < len(parts) else None


# Decompiler symbols that denote a constant living in a data section (.rodata /
# a named global string), NOT a stack buffer. The *address* of one of these in
# the format position is a literal format — keep suppressing it. ``&localbuffer``
# (the address of a tainted stack array) is the opposite: the CWE-134 shape.
_RODATA_SYM = re.compile(r'(?:DAT_|_DAT|s_[A-Za-z0-9]|str\.|aFmt|\.rodata|0[xX])')


def _is_literal_format(arg: str) -> bool:
    """A safe format is a string literal (optionally a cast of one), or the address
    of a string literal / a ``.rodata`` constant. The address of a *local* buffer
    (``&format`` / ``&buf`` — what a decompiler emits for ``printf(stack_buf)``) is
    NOT safe: that bare stack buffer reaching the format position is the bug."""
    a = arg.lstrip()
    # strip a leading cast like (char *)
    a = re.sub(r'^\((?:[^()]*)\)\s*', "", a)
    if a.startswith('"') or a.startswith('L"') or a == "":
        return True
    if a.startswith("&"):
        inner = a[1:].lstrip()
        # &"literal" or &DAT_/&str./&.rodata -> a constant format; &localbuf -> taint.
        return inner.startswith('"') or _RODATA_SYM.match(inner) is not None
    return False


def fmtstring_lens(decompiled_c: dict[str, str]) -> list[Finding]:
    """Flag printf-family calls whose FORMAT argument is a variable (not a string
    literal) — a taint-controlled format string (CWE-134)."""
    out: list[Finding] = []
    seen: set[str] = set()
    fmt_names = tuple(name for name, _ in _FMT_CALLS)
    items, presence = _presence(decompiled_c, fmt_names)
    for (func, code), present in zip(items, presence, strict=True):
        if not code:
            continue
        for name, fmt_idx in _FMT_CALLS:
            if not present[name]:
                continue  # name absent — \bNAME\s*( cannot match
            for cm in re.finditer(rf"\b{name}\s*\(", code):
                args = _balanced_args(code, cm.end() - 1)
                if args is None:
                    continue
                fmt_arg = _arg_at(args, fmt_idx)
                if fmt_arg is None or _is_literal_format(fmt_arg):
                    continue
                # Accept a bare identifier, an optional cast, and an optional
                # leading ``&`` — a decompiler renders ``printf(stack_buf)`` as
                # ``printf(&format)``; the address-of a local buffer is still a
                # single tainted format operand (CWE-134).
                if re.fullmatch(
                    rf"&?\s*\(?\s*(?:[^()]*\)\s*)?{_IDENT}", fmt_arg
                ) is None:
                    continue
                if func in seen:
                    continue
                seen.add(func)
                out.append(_hyp(FMTSTRING, _input_source(code), name, func))
    return out


def _balanced_args(code: str, open_paren: int) -> str | None:
    """Return the substring between a call's matching parentheses (shallow)."""
    depth = 0
    for i in range(open_paren, len(code)):
        if code[i] == "(":
            depth += 1
        elif code[i] == ")":
            depth -= 1
            if depth == 0:
                return code[open_paren + 1:i]
    return None


# Free-like sinks whose call frees their pointer operand. Beyond libc ``free``,
# Ghidra-decompiled reality includes the lcms pool allocator (``_cmsFree`` — note
# its freed pointer is the SECOND arg, after the context handle), glib (``g_free``),
# the kernel (``kfree``/``kvfree``/``vfree``), and C++ ``delete``, which the
# decompiler lowers to ``operator.delete(p)`` / ``operator_delete(p)``. For each of
# these the freed pointer is the call's LAST identifier argument (a cast and a
# leading ``&`` stripped). A leading non-identifier lookbehind keeps ``free`` from
# matching inside ``g_free``/``_cmsFree``.
_FREE_NAMES = (
    "free", "_cmsFree", "cmsFree", "g_free", "kfree", "kvfree", "vfree",
    "operator.delete", "operator_delete",
)
_CAST_PREFIX = re.compile(r"^\s*\((?:[^()]*)\)\s*")
# UAF-03: realloc frees (and may MOVE) its input. ``q = realloc(p, n)`` leaves
# ``p`` dangling; only ``p = realloc(p, n)`` (reassigned to the same var) is safe.
_REALLOC_CALL = re.compile(rf"(?:({_IDENT})\s*=\s*)?\brealloc\s*\(\s*({_IDENT})\s*,")
# UAF-04: refcount drops are conditional (free-at-zero) frees of their object.
# Covers ``*_put``/``*_release``/``*_unref``/``kref_put``/``kfree`` and the
# CamelCase decompiled forms (``_cmsUnref``/``…Unref``/``…Release``).
_CONDFREE_CALL = re.compile(
    rf"\b(\w*(?:_put|_release|_unref|Unref|Release)|kref_put|kfree)\s*\(\s*&?\s*({_IDENT})"
)


def _freed_ptr(arg: str | None) -> str | None:
    """The bare pointer identifier a free-call frees: strip one leading cast
    (``(void *)p``) and a leading ``&``, then require a bare identifier."""
    if arg is None:
        return None
    a = _CAST_PREFIX.sub("", arg.strip()).lstrip("&").strip()
    return a if re.fullmatch(_IDENT, a) else None


def _free_sites(code: str) -> list[tuple[str, str, int, int]]:
    """Every free-like call in ``code`` as ``(name, ptr, call_start, after_call)``,
    ordered by position. ``ptr`` is the freed pointer (last identifier arg, casts
    stripped); ``after_call`` is the index just past the call's closing paren, so a
    caller scans for USES strictly after the free (not the free's own operand)."""
    sites: list[tuple[str, str, int, int]] = []
    for name in _FREE_NAMES:
        if name not in code:
            continue
        for m in re.finditer(rf"(?<![A-Za-z0-9_]){re.escape(name)}\s*\(", code):
            open_p = m.end() - 1
            args = _balanced_args(code, open_p)
            if args is None:
                continue
            ptr = _freed_ptr(_arg_at(args, _arg_count(args) - 1))
            if ptr:
                after = open_p + 1 + len(args) + 1  # index past the closing ``)``
                sites.append((name, ptr, m.start(), after))
    sites.sort(key=lambda s: s[2])
    return sites


def _reassigned(code: str, ptr: str, lo: int, hi: int) -> bool:
    """True if ``ptr`` is reassigned (``ptr = …``; a single ``=``, not ``==``) in
    ``code[lo:hi]`` — a reassignment between a free and a later free/use points the
    pointer at fresh memory and CLEARS the dangling state (the FP-suppressor)."""
    return re.search(
        rf"(?<![A-Za-z0-9_.]){re.escape(ptr)}\s*=(?!=)", code[lo:hi]
    ) is not None


def _use_after(code: str, ptr: str, start: int) -> bool:
    """Is the freed ``ptr`` genuinely USED after byte ``start``? Walk each later
    reference and let the FIRST decisive one rule: a plain reassignment (``ptr =
    …`` where ``ptr`` is the whole lvalue) CLEARS the dangling state (safe); a
    deref/index/member/store-through/call-argument use is a use-after-free. A bare
    comparison (``if (ptr == NULL)``) is neither — keep scanning.

    The subtlety decompiled C forces: ``*(char *)p = 1`` LOOKS like ``p = 1`` but is
    a store THROUGH the freed pointer (a use), while ``p = malloc()`` is a genuine
    reassignment. We disambiguate on the statement prefix — a ``*`` before ``ptr``
    in the same statement means ``ptr`` is dereferenced, not reassigned."""
    p = re.escape(ptr)
    for m in re.finditer(rf"(?<![A-Za-z0-9_.]){p}(?![A-Za-z0-9_])", code[start:]):
        idx = start + m.start()
        after = code[start + m.end():]
        seg = code[:idx]
        bnd = max(seg.rfind(";"), seg.rfind("{"), seg.rfind("}"), seg.rfind(","))
        deref = "*" in seg[bnd + 1:]  # ptr dereferenced earlier in this statement
        is_assign = re.match(r"\s*=(?!=)", after) is not None
        if is_assign and not deref:
            return False  # plain reassignment (ptr = …) — dangling state cleared
        if re.match(r"\s*(?:\[|->|\)|,)", after) or (is_assign and deref):
            return True   # index / member / call-arg / store-through *ptr = …
        if re.search(r"\*\s*$", seg):
            return True   # ``*ptr`` read dereference
        # READ through a cast + pointer arithmetic: ``*(byte *)((long)ptr + off)`` —
        # the decompiler idiom for a freed-pointer read (GCC -O1 inlined case). ``ptr``
        # sits inside a dereferenced expression (``*`` earlier in the statement) and is
        # not being reassigned, and is used in arithmetic (``ptr + off`` / ``ptr - off``).
        if deref and not is_assign and re.match(r"\s*[-+)]", after):
            return True
    return False


def uaf_lens(decompiled_c: dict[str, str]) -> list[Finding]:
    """Flag use-after-free / double-free shapes within a function body. Beyond
    the classic ``free(p)``→use, this models UAF-03 (realloc frees+moves: a
    retained alias used after a ``q = realloc(p, ...)`` is a UAF) and UAF-04
    (``*_put``/``*_release``/``*_unref``/``kref_put``/``_cmsUnref`` as conditional
    frees). The free site itself is library-agnostic (``free``/``_cmsFree``/
    ``g_free``/``kfree``/``operator.delete``, casts stripped). Decompiled C is
    linearized, so a use *after* the free line is the signal; a double-free is
    tagged so the CWE resolves to 415 (see ``cwe_for_finding``)."""
    out: list[Finding] = []
    for func, code in decompiled_c.items():
        if not code:
            continue
        fired = False
        # (1) classic free -> double-free / use-after-free (any free-family sink)
        sites = _free_sites(code)
        for i, (_name, ptr, _start, after) in enumerate(sites):
            # double-free: a later free of the SAME pointer with no reassignment
            # (``p = …``) between — an intervening realloc/re-malloc makes it safe.
            dbl = next(
                (s for s in sites[i + 1:]
                 if s[1] == ptr and not _reassigned(code, ptr, after, s[2])),
                None,
            )
            if dbl is not None:
                out.append(_hyp(UAF, _input_source(code), "free", func,
                                detail=f"double-free({ptr})"))
                fired = True
                break
            if _use_after(code, ptr, after):
                out.append(_hyp(UAF, _input_source(code), "free", func,
                                detail=f"use-after-free({ptr})"))
                fired = True
                break
        if fired:
            continue
        # (2) realloc-as-free (UAF-03): stale alias of the moved pointer
        if "realloc" in code:
            for rm in _REALLOC_CALL.finditer(code):
                lhs, ptr = rm.group(1), rm.group(2)
                if lhs == ptr:
                    continue  # p = realloc(p, ..) reassigns -> safe
                if _use_after(code, ptr, rm.end()):
                    out.append(_hyp(UAF, _input_source(code), "realloc", func,
                                    detail=f"realloc-stale-pointer({ptr})"))
                    fired = True
                    break
        if fired:
            continue
        # (3) conditional free (UAF-04): refcount drop then a later use
        if any(t in code for t in
               ("_put", "_release", "_unref", "kref", "Unref", "Release")):
            for cm in _CONDFREE_CALL.finditer(code):
                fn, ptr = cm.group(1), cm.group(2)
                if _use_after(code, ptr, cm.end()):
                    out.append(_hyp(UAF, _input_source(code), fn, func,
                                    detail=f"conditional-free-use({ptr})"))
                    break
    return out


_CMDI_SINKS = ("system", "popen", "execl", "execlp", "execle", "execv", "execvp",
               "execvpe", "execve", "posix_spawn", "posix_spawnp")
# CWE-88 argument injection: the tainted operand is not the program path (often a
# constant like "/usr/bin/git") but an element of the argv VECTOR — index 1 for
# the execv* family, index 4 for posix_spawn(pid, path, fa, attr, argv, envp).
_ARGV_VECTOR_ARG = {
    "execv": 1, "execvp": 1, "execvpe": 1, "execve": 1,
    "posix_spawn": 4, "posix_spawnp": 4,
}
_LITERAL_ELEM = re.compile(r'^\s*(?:"|L"|\(|0\b|NULL\b|\d)')


def _argv_tainted(code: str, vec: str) -> bool:
    """True if the argv vector ``vec`` plausibly carries a tainted element. A
    constant brace-initializer of string literals (and a trailing NULL) is the
    FP-suppressor; a non-literal element, or no in-function initializer plus a
    recognized taint source, is the argv-injection (CWE-88) signal."""
    v = re.escape(vec)
    m = re.search(rf"{v}\s*(?:\[[^\]]*\])?\s*=\s*\{{([^}}]*)\}}", code)
    if m:
        elems = [e.strip() for e in m.group(1).split(",") if e.strip()]
        return any(not _LITERAL_ELEM.match(e) for e in elems)
    # built dynamically (no in-function initializer): require a taint source
    return _input_source(code) != "stdin"


def cmdi_lens(decompiled_c: dict[str, str]) -> list[Finding]:
    """Flag a command-exec sink whose command argument is a variable (not a string
    literal) — taint into system/popen/exec*/posix_spawn (CWE-78)."""
    out: list[Finding] = []
    items, presence = _presence(decompiled_c, _CMDI_SINKS)
    for (func, code), present in zip(items, presence, strict=True):
        if not code:
            continue
        hit = False
        for sink in _CMDI_SINKS:
            if not present[sink]:
                continue  # sink name absent — \bSINK\s*( cannot match
            for cm in re.finditer(rf"\b{sink}\s*\(", code):
                args = _balanced_args(code, cm.end() - 1)
                if args is None:
                    continue
                cmd_arg = _arg_at(args, 0) or ""
                if not _is_literal_format(cmd_arg):
                    out.append(_hyp(CMDI, _input_source(code), sink, func))
                    hit = True
                    break
                # CWE-88: program path is a literal, but a tainted argv element
                # becomes a dangerous flag (no shell needed).
                vidx = _ARGV_VECTOR_ARG.get(sink)
                if vidx is not None:
                    vec = _arg_at(args, vidx) or ""
                    if (
                        vec
                        and not _is_literal_format(vec)
                        and re.fullmatch(rf"&?\s*{_IDENT}", vec)
                        and _argv_tainted(code, vec)
                    ):
                        out.append(_hyp(CMDI, _input_source(code), sink, func,
                                        detail="argv-injection"))
                        hit = True
                        break
            if hit:
                break
    return out


# Logic / auth-bypass signals: a comparison or check shape that *could* be the
# bug. This lens is intentionally high-recall and hypothesis-only.
_AUTH_TOKENS = ("password", "passwd", "auth", "admin", "token", "secret",
                "login", "priv", "role", "permission", "session", "credential")
_WEAK_COMPARE = re.compile(r"\b(strcmp|strncmp|memcmp|strcasecmp)\s*\(")
_OFF_BY_ONE = re.compile(r"<=\s*[A-Za-z_0-9]+\s*\)|\[\s*[A-Za-z_]\w*\s*\+\s*1\s*\]")


def logic_lens(decompiled_c: dict[str, str]) -> list[Finding]:
    """Surface auth-bypass / logic / off-by-one *hypotheses* (never confirmed):
    an auth-ish identifier near a comparison, a length-less ``memcmp`` on a
    secret, or an ``<=`` bound / ``[i+1]`` index shape. Pure funnel lead."""
    out: list[Finding] = []
    for func, code in decompiled_c.items():
        if not code:
            continue
        low = code.lower()
        has_auth = any(tok in low for tok in _AUTH_TOKENS)
        weak_cmp = _WEAK_COMPARE.search(code) is not None
        off_by_one = _OFF_BY_ONE.search(code) is not None
        if not ((has_auth and (weak_cmp or "==" in code)) or off_by_one):
            continue
        detail = (
            "auth-compare" if has_auth and weak_cmp
            else "auth-equality" if has_auth
            else "off-by-one"
        )
        out.append(_hyp(LOGIC, _input_source(code), detail, func, detail=detail))
    return out


def _hyp(
    bc: BugClass, source: str, sink: str, func: str, *, detail: str = ""
) -> Finding:
    return Finding(
        source=source,
        sink=sink if not detail else f"{sink}:{detail}",
        function=func,
        source_addr=0,
        sink_addr=0,
        path_len=0,
        origin=bc.origin,
    )


# Unbounded string sinks the M1 taint slice can miss in a stripped binary.
_STPCPY_LIKE = ("stpcpy", "strcpy", "strcat")
_STRLCAT_LIKE = ("strlcat", "strlcpy", "strlcat_pad")
_LOOP_WRITER = re.compile(
    r"(?:for|while)\s*\([^{}]*\)[^{]*\{[^}]*(?:\*\s*\w+\s*\+\+\s*=|\w+\s*\[[^\]]*\+\+[^\]]*\]\s*=|\w+\s*\[\s*\w+\s*\]\s*=)",
    re.DOTALL,
)


def overflow_lens(decompiled_c: dict[str, str]) -> list[Finding]:
    """OF-04/OF-09/OF-02 lens: an unbounded string sink fed a variable
    (``stpcpy(dst, s)``), a ``sprintf(buf, "...%s...", v)`` expansion overflow
    (literal format but a tainted ``%s`` arg — distinct from fmtstring), an
    ignored-return ``strlcat`` (truncation check discarded), or a decode loop
    whose write cursor advances independently of the dst capacity."""
    out: list[Finding] = []
    for func, code in decompiled_c.items():
        if not code:
            continue
        src = _input_source(code)
        fired = False
        # (a) stpcpy/strcpy/strcat of a variable source
        for name in _STPCPY_LIKE:
            if name not in code:
                continue
            for cm in re.finditer(rf"\b{name}\s*\(", code):
                args = _balanced_args(code, cm.end() - 1)
                if args is None:
                    continue
                srcarg = _arg_at(args, 1) or ""
                if srcarg and not _is_literal_format(srcarg):
                    out.append(_hyp(OVERFLOW, src, name, func))
                    fired = True
                    break
            if fired:
                break
        if fired:
            continue
        # (b) sprintf/vsprintf with a literal %s format and a variable arg
        for name in ("sprintf", "vsprintf"):
            if name not in code:
                continue
            for cm in re.finditer(rf"\b{name}\s*\(", code):
                args = _balanced_args(code, cm.end() - 1)
                if args is None:
                    continue
                fmt = _arg_at(args, 1) or ""
                rest = _arg_at(args, 2) or ""
                if _is_literal_format(fmt) and "%s" in fmt and rest and not (
                    rest.startswith('"')
                ):
                    out.append(_hyp(OVERFLOW, src, name, func, detail="sprintf-%s"))
                    fired = True
                    break
            if fired:
                break
        if fired:
            continue
        # (c) ignored-return strlcat/strlcpy (bare statement) — truncation lost
        for name in _STRLCAT_LIKE:
            if re.search(rf"(?:^|[;{{}}])\s*{name}\s*\(", code):
                out.append(_hyp(OVERFLOW, src, name, func, detail="ignored-strlcat"))
                fired = True
                break
        if fired:
            continue
        # (d) loop-writer: a decode/RLE loop with a cursor store
        if _LOOP_WRITER.search(code) and src != "stdin":
            out.append(_hyp(OVERFLOW, src, "loop-writer", func, detail="loop-writer"))
    return out


# --- loop-based OOB write (LOOP_OOB, CWE-787) -------------------------------
#
# The bug class a library-call sink model misses: ``for(i=0;i<n;i++) buf[i]=…``
# where ``n`` is parsed from untrusted input (the real lcms ``WriteCLUT`` shape).
# There is no memcpy/strcpy to key on — the write is the loop store itself. We
# flag it only with (1) a loop, (2) an array store whose index is the loop
# counter, (3) a DATA-FLOW link from the loop bound (or the index) back to an
# untrusted source — a shallow backward slice over the pseudo-C — and (4) NO
# clamp of the bound/index to a constant/``sizeof`` capacity (the FP-suppressor
# that keeps a bounds-checked control from firing).

# Sources that introduce untrusted bytes (superset of _INPUT_FUNCS: also the
# char-at-a-time readers whose *return value* is tainted).
_TAINT_SOURCES: tuple[str, ...] = (*_INPUT_FUNCS, "getchar", "getc", "getw")
# Sources whose FIRST argument is the destination buffer (no ``&``): the buffer
# variable itself becomes tainted (fgets(buf,…) / gets(buf) / fread(buf,…)).
_BUF_FIRST_SOURCES = frozenset({"fgets", "gets", "fread"})
_ADDR_OF = re.compile(rf"&\s*({_IDENT})")
_ASSIGN = re.compile(rf"\b({_IDENT})\s*=(?!=)\s*([^;]*);")
_LOOP_KW = re.compile(r"\b(?:for|while)\s*\(")
_DO_KW = re.compile(r"\bdo\b\s*\{")
_NUM = r"(?:0[xX][0-9a-fA-F]+|\d+)"
# ``buf[idx] = …`` (a store, not ``==``); idx is a bare identifier OR an identifier
# behind a cast (``buf[(int)idx] = …`` — the decompiler's rendering of a signed
# index; extension #1). A constant-index store (``buf[0] = …``) is excluded (idx
# must be an identifier so a non-loop write is not mistaken for a loop write).
_INDEX_STORE = re.compile(
    rf"\b({_IDENT})\s*\[\s*(?:\([^()]*\)\s*)?({_IDENT})\s*\]\s*=(?!=)"
)
# ``*(T *)(base + idx*stride) = …`` — the pointer-arithmetic store form the array-
# index shape misses (extension #1). Captures ``base`` and the (maybe cast) index.
_PTR_STORE = re.compile(
    rf"\*\s*\([^()]*\)\s*\(\s*({_IDENT})\s*\+\s*(?:\([^()]*\)\s*)?"
    rf"({_IDENT})\s*\*\s*{_NUM}\s*\)\s*=(?!=)"
)
# ``i < n`` / ``i <= n`` — the index/bound relation in a loop condition.
_LT_CMP = re.compile(rf"\b({_IDENT})\s*(<=?)\s*({_IDENT})\b")
# ``cursor != end`` / ``end != cursor`` — a bounded cursor loop (extension #2, the
# ``do{…}while(local_14 != pcVar4)`` shape). Either operand may be the cursor; the
# store index selects which, so the lens maps both directions.
_NE_CMP = re.compile(rf"\b({_IDENT})\s*!=\s*({_IDENT})\b")
# Call-head + control keywords, for out-param (``&var``) taste detection below.
_CALL_HEAD = re.compile(rf"\b({_IDENT})\s*\(")
_CTRL_KW = frozenset({"if", "while", "for", "switch", "return", "sizeof", "do"})


def _rhs_tainted(rhs: str, tainted: set[str]) -> bool:
    """A right-hand side is tainted if it calls an input source, reads ``argv``, or
    references an already-tainted variable (the propagation step of the slice)."""
    if "argv" in rhs:
        return True
    for fn in _TAINT_SOURCES:
        if fn in rhs and re.search(rf"\b{fn}\s*\(", rhs):
            return True
    return any(re.search(rf"(?<![A-Za-z_]){re.escape(v)}(?![A-Za-z0-9_])", rhs)
               for v in tainted)


def _untrusted_vars(code: str) -> set[str]:
    """Shallow backward slice over the pseudo-C: the set of local variables that
    carry untrusted bytes. Seeded from source calls (``&var`` out-params and
    buffer-first args) and their return values, then propagated to a fixpoint
    through plain assignments (``m = n + 1``)."""
    tainted: set[str] = set()
    for fn in _TAINT_SOURCES:
        if fn not in code:
            continue
        for m in re.finditer(rf"\b{fn}\s*\(", code):
            args = _balanced_args(code, m.end() - 1)
            if args is None:
                continue
            for am in _ADDR_OF.finditer(args):
                tainted.add(am.group(1))  # out-param filled through &var
            if fn in _BUF_FIRST_SOURCES:
                first = _arg_at(args, 0)
                if first and re.fullmatch(_IDENT, first.strip()):
                    tainted.add(first.strip())
    assigns = _ASSIGN.findall(code)
    changed = True
    while changed:
        changed = False
        for lhs, rhs in assigns:
            if lhs not in tainted and _rhs_tainted(rhs, tainted):
                tainted.add(lhs)
                changed = True
    return tainted


def _index_stores(body: str) -> list[tuple[str, str]]:
    """Every ``(buf, idx)`` store in a loop body: bare/cast array-index stores
    (``buf[idx] = …`` / ``buf[(int)idx] = …``) and pointer-arithmetic stores
    (``*(T *)(base + idx*stride) = …``) — extension #1. ``idx`` is the index
    identifier (extracted through any cast); ``buf`` is the destination base."""
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for rx in (_INDEX_STORE, _PTR_STORE):
        for m in rx.finditer(body):
            pair = (m.group(1), m.group(2))
            if pair not in seen:
                seen.add(pair)
                out.append(pair)
    return out


def _outparam_vars(code: str) -> set[str]:
    """Extension #3: locals written through a *library out-param* — ``&var`` passed
    as an argument to a call (``_cmsEndPointsBySpace(&n,…)`` / ``io->Read(&n,…)`` /
    ``fread(&n,…)``). A count/size filled by an opaque library call is treated as
    untrusted-derived *when it feeds a loop bound* — the lens gates on that plus the
    same clamp suppressor, so a bounds-checked out-param count still does not fire."""
    out: set[str] = set()
    for m in _CALL_HEAD.finditer(code):
        if m.group(1) in _CTRL_KW:
            continue
        args = _balanced_args(code, m.end() - 1)
        if args is None:
            continue
        for am in _ADDR_OF.finditer(args):
            out.add(am.group(1))
    return out


def _clamped(code: str, bound: str, idx: str) -> bool:
    """FP-suppressor: is the bound (or index) held to a constant/``sizeof``
    capacity? A tainted count that is reassigned to a literal (``n = 16``),
    compared to a non-zero literal / ``sizeof`` (``if (n > 16)…``), or an index
    with a second constant/sizeof upper bound is a bounds-checked write — not the
    bug. Comparisons against 0 (sign checks) do NOT count."""
    b = re.escape(bound)
    i = re.escape(idx)
    # (a) bound reassigned to a numeric literal — the clamp ``n = 16``
    if re.search(rf"\b{b}\s*=(?!=)\s*{_NUM}", code):
        return True
    # (b) bound compared to a non-zero literal or sizeof, either order
    for pat in (rf"\b{b}\s*(?:<=?|>=?)\s*({_NUM}|sizeof)",
                rf"({_NUM}|sizeof)\s*(?:<=?|>=?)\s*{b}\b"):
        for cm in re.finditer(pat, code):
            tok = cm.group(1)
            if tok == "sizeof" or int(tok, 0) != 0:
                return True
    # (c) the index carries a second constant/sizeof upper bound
    return re.search(rf"\b{i}\s*<=?\s*({_NUM}|sizeof)", code) is not None


def _matching_brace(code: str, brace_open: int) -> int:
    """Index of the ``}`` that closes the ``{`` at ``brace_open`` (or -1)."""
    depth = 0
    for i in range(brace_open, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _loop_bodies(code: str) -> list[tuple[str, str]]:
    """Each loop's ``(condition, body)``. Body is the braced block (or the single
    statement up to ``;`` for a brace-less loop). Handles ``for``/``while`` (body
    follows the header) and ``do{…}while(cond)`` (extension #2 — body precedes the
    condition)."""
    out: list[tuple[str, str]] = []
    # (1) do { BODY } while ( COND );  — the body precedes the condition.
    for m in _DO_KW.finditer(code):
        brace = m.end() - 1  # index of the opening ``{``
        end = _matching_brace(code, brace)
        if end < 0:
            continue
        wm = re.compile(r"\s*while\s*\(").match(code, end + 1)
        if wm is None:
            continue
        cond = _balanced_args(code, wm.end() - 1)
        if cond is not None:
            out.append((cond, code[brace + 1:end]))
    # (2) for(...) / while(...) — the body follows the header. A ``while`` that is
    # the tail of a do-while (preceded by ``}``) is skipped: handled in step (1).
    for m in _LOOP_KW.finditer(code):
        if code[m.start():m.end()].split("(", 1)[0].strip() == "while":
            j = m.start() - 1
            while j >= 0 and code[j] in " \t\r\n":
                j -= 1
            if j >= 0 and code[j] == "}":
                continue
        header = _balanced_args(code, m.end() - 1)
        if header is None:
            continue
        # ``for(init; cond; incr)`` -> cond is the middle clause; ``while(cond)``.
        parts = _split_top(header, ";")
        cond = parts[1] if len(parts) == 3 else header
        # locate the char just past the loop header's closing ``)``
        depth, j = 0, m.end() - 1
        for j in range(m.end() - 1, len(code)):
            if code[j] == "(":
                depth += 1
            elif code[j] == ")":
                depth -= 1
                if depth == 0:
                    break
        k = j + 1
        while k < len(code) and code[k] in " \t\r\n":
            k += 1
        if k < len(code) and code[k] == "{":
            body = _balanced_block(code, k)
        else:
            semi = code.find(";", k)
            body = code[k:semi] if semi != -1 else code[k:]
        out.append((cond, body or ""))
    return out


def _balanced_block(code: str, brace_open: int) -> str | None:
    """The substring inside a call's matching ``{ }`` (shallow, brace-balanced)."""
    depth = 0
    for i in range(brace_open, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[brace_open + 1:i]
    return None


def _split_top(s: str, sep: str) -> list[str]:
    """Split ``s`` on ``sep`` at paren/bracket depth 0."""
    depth, cur, parts = 0, "", []
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return parts


# --- inter-procedural taint (#53) ------------------------------------------
#
# The intra-function slice can't cross a call boundary: a loop bound that is a
# *function parameter* (the real lcms ``WriteCLUT`` premise, where ``nSamples``
# is passed in from ``cmsGetPostScriptCRD``/``CSA``) is only tainted if a CALLER
# passes an untrusted-derived argument into that parameter position. So when the
# loop-OOB lens finds a bound that is a bare parameter, we follow the callgraph
# UP (bounded depth, cycle-guarded) and check each caller's argument at that
# position. Kept strictly local to the loop-OOB path so the general slicer is
# untouched.
_INTERPROC_MAX_DEPTH = 3


def _signature_params(code: str) -> list[str]:
    """The ordered parameter *names* of a decompiled function. The signature is the
    text before the first ``{``; the parameter list is its last top-level ``(...)``
    group and each parameter's name is its final identifier token (``char *PreMaj``
    -> ``PreMaj``; ``undefined4 param_1`` -> ``param_1``)."""
    head = code.split("{", 1)[0]
    head = re.sub(r"/\*.*?\*/", " ", head, flags=re.DOTALL)  # drop /* WARNING */
    groups: list[str] = []
    depth, start = 0, -1
    for i, ch in enumerate(head):
        if ch == "(":
            if depth == 0:
                start = i
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and start >= 0:
                groups.append(head[start + 1:i])
    if not groups:
        return []
    params: list[str] = []
    for part in _split_top(groups[-1], ","):
        toks = re.findall(_IDENT, part)
        if toks:
            params.append(toks[-1])
    return params


def _param_index(code: str, ident: str) -> int | None:
    """0-based position of parameter ``ident`` in ``code``'s signature, or None."""
    params = _signature_params(code)
    return params.index(ident) if ident in params else None


def _reverse_callgraph(callgraph: dict[str, list[str]]) -> dict[str, list[str]]:
    """``callee -> [callers]`` from the ``caller -> [callees]`` graph."""
    rev: dict[str, list[str]] = {}
    for caller, callees in callgraph.items():
        for callee in callees:
            rev.setdefault(callee, []).append(caller)
    return rev


def _param_fed_untrusted(
    callee: str,
    param_idx: int,
    decompiled_c: dict[str, str],
    rev: dict[str, list[str]],
    depth: int,
    visited: set[tuple[str, int]],
) -> bool:
    """Does any caller pass an untrusted-derived value into ``callee``'s parameter
    ``param_idx``? Walks the callgraph UP to ``depth`` hops, guarding cycles via
    ``visited``. At each caller: extract the argument at ``param_idx`` of every
    ``callee(...)`` call site; it's tainted if it references the caller's own
    untrusted vars / an input source (``_rhs_tainted``), or if it is itself a bare
    caller parameter that is transitively fed an untrusted value (the recursion)."""
    if depth <= 0 or (callee, param_idx) in visited:
        return False
    visited.add((callee, param_idx))
    for caller in rev.get(callee, ()):
        caller_code = decompiled_c.get(caller)
        if not caller_code or callee not in caller_code:
            continue
        caller_tainted = _untrusted_vars(caller_code)
        caller_params = _signature_params(caller_code)
        for cm in re.finditer(rf"\b{re.escape(callee)}\s*\(", caller_code):
            args = _balanced_args(caller_code, cm.end() - 1)
            if args is None:
                continue
            arg = _arg_at(args, param_idx)
            if arg is None:
                continue
            arg = arg.strip()
            if _rhs_tainted(arg, caller_tainted):
                return True
            # arg is itself a bare caller parameter — recurse one hop further up.
            m = re.fullmatch(rf"&?\s*(?:\([^()]*\)\s*)?({_IDENT})", arg)
            if m and m.group(1) in caller_params:
                up_idx = caller_params.index(m.group(1))
                if _param_fed_untrusted(
                    caller, up_idx, decompiled_c, rev, depth - 1, visited
                ):
                    return True
    return False


def loop_oob_lens(
    decompiled_c: dict[str, str],
    callgraph: dict[str, list[str]] | None = None,
) -> list[Finding]:
    """Flag a store into a buffer inside a loop whose bound or index is
    data-dependent on an untrusted source, with no clamp to the buffer's
    capacity — the ``for(i<n) buf[i]=…`` OOB-write shape (CWE-787) that a
    library-call sink model (memcpy/strcpy) misses.

    With a ``callgraph`` (``caller -> [callees]``), the taint is **inter-procedural
    (#53)**: a loop bound that is a bare function *parameter* is treated as tainted
    when a caller passes an untrusted-derived argument into that parameter position
    (bounded caller walk, cycle-guarded) — so the ``WriteCLUT``-style bug whose
    count crosses a call boundary is reachable.

    The decompiled-shape extensions (#54) let the same lens match the real lcms
    ``OutputValueSampler`` OOB the source-shaped lens missed: (1) cast /
    pointer-arithmetic index stores (``In[(int)pcVar4] = …``), (2) ``!=``-terminated
    cursor loops (``do{…}while(local_14 != pcVar4)``), and (3) a loop bound filled
    by a library out-param (``_cmsEndPointsBySpace(&local_14,…)``) as an untrusted-
    derived source — each still gated by the clamp suppressor for precision."""
    out: list[Finding] = []
    rev = _reverse_callgraph(callgraph) if callgraph else {}
    for func, code in decompiled_c.items():
        if not code or "[" not in code:
            continue
        loops = _loop_bodies(code)
        if not loops:
            continue
        tainted = _untrusted_vars(code)
        # Out-param-filled locals (extension #3): untrusted-derived only where they
        # feed a loop bound (checked below), so compute once per function.
        outparams = _outparam_vars(code)
        # No intra-function source: only worth continuing if an out-param bound or
        # inter-proc taint (a caller feeding a parameter bound) is available.
        if not tainted and not outparams and not rev:
            continue
        params = set(_signature_params(code)) if rev else set()
        src = _input_source(code)
        fired = False
        for cond, body in loops:
            if fired:
                break
            # index -> bound: ``i < n`` (upper bound) and ``cursor != end`` (either
            # operand may be the cursor; the store index selects, so map both ways).
            bounds: dict[str, str] = {
                c.group(1): c.group(3) for c in _LT_CMP.finditer(cond)
            }
            for c in _NE_CMP.finditer(cond):
                bounds.setdefault(c.group(1), c.group(2))
                bounds.setdefault(c.group(2), c.group(1))
            for buf, idx in _index_stores(body):
                bound = bounds.get(idx)
                # link: the loop bound is tainted, filled by an out-param, or the
                # store index itself is tainted.
                bound_tainted = bound is not None and bound in tainted
                idx_tainted = idx in tainted
                outparam_bound = bound is not None and bound in outparams
                interproc = False
                if (
                    not (bound_tainted or idx_tainted or outparam_bound)
                    and bound in params
                ):
                    # bound is a parameter — is a caller feeding it untrusted data?
                    pidx = _param_index(code, bound)
                    if pidx is not None and _param_fed_untrusted(
                        func, pidx, decompiled_c, rev, _INTERPROC_MAX_DEPTH, set()
                    ):
                        bound_tainted = interproc = True
                if not (bound_tainted or idx_tainted or outparam_bound):
                    continue
                if _clamped(code, bound or idx, idx):
                    continue  # bounds-checked write — suppressed
                tag = (
                    ":interproc" if interproc
                    else ":outparam" if outparam_bound and not bound_tainted
                    else ""
                )
                detail = f"{buf}[{idx}]<{bound or 'idx'}{tag}"
                out.append(_hyp(LOOP_OOB, src, "loop-store", func, detail=detail))
                fired = True
                break
    return out


_LENSES = (
    overflow_lens, loop_oob_lens, intoverflow_lens, fmtstring_lens, uaf_lens,
    cmdi_lens, logic_lens,
)


def prime_bugclasses(
    decompiled_c: dict[str, str],
    *,
    max_per_class: int = 16,
    callgraph: dict[str, list[str]] | None = None,
) -> list[Finding]:
    """Run every M4 lens over the decompiled C and return tagged hypotheses
    (origin ``bugclass:<id>``). High-recall by design — the funnel + oracle filter.

    ``callgraph`` (``caller -> [callees]``) enables the loop-OOB lens's
    inter-procedural taint (#53) — a loop bound that is a function parameter fed an
    untrusted argument by a caller. Only the loop-OOB path consumes it."""
    out: list[Finding] = []
    for lens in _LENSES:
        if lens is loop_oob_lens:
            out.extend(loop_oob_lens(decompiled_c, callgraph)[:max_per_class])
        else:
            out.extend(lens(decompiled_c)[:max_per_class])
    return out


# --- confirming oracles (route a candidate trigger → PoV) ------------------


def _reserve_oracle_runs(budget: BudgetTracker | None, count: int = 1) -> bool:
    return budget is None or budget.reserve_attempts(count)[0]


def _oracle_timeout(budget: BudgetTracker | None, default: float = 10.0) -> float:
    if budget is None:
        return default
    remaining = budget.remaining_seconds()
    if remaining <= 0:
        budget.reservation_failures += 1
        return 0.0
    return min(default, remaining)


def confirm(
    finding: Finding,
    verdict: Verdict,
    binary: str | Path,
    *,
    trigger: bytes | None = None,
    control: bytes = b"A",
    budget: BudgetTracker | None = None,
    executor: Executor | None = None,
    compiler_path: str | None = None,
    compiler_resolved: bool = False,
) -> PoV | None:
    """Route a confirmable bug-class hypothesis to its oracle and return a
    reproducing PoV, or None. ``trigger`` is the candidate input (LLM-proposed via
    ``verdict.input_example`` when not given); a class without a generic oracle
    (logic) always returns None — it stays an honest hypothesis."""
    bc = bug_class_for_origin(finding.origin)
    if bc is None or not bc.confirmable:
        return None
    binary = str(binary)
    if trigger is None:
        trigger = verdict.input_example.encode("latin-1", "replace") or None

    if bc is CMDI:
        return _confirm_cmdi(
            finding,
            verdict,
            binary,
            budget=budget,
            executor=executor,
            compiler_path=compiler_path,
            compiler_resolved=compiler_resolved,
        )
    if bc is FMTSTRING:
        return _confirm_fmtstring(
            finding,
            binary,
            control=control,
            budget=budget,
            executor=executor,
            compiler_path=compiler_path,
            compiler_resolved=compiler_resolved,
        )
    if bc is INTOVERFLOW or bc is OVERFLOW or bc is LOOP_OOB:
        if trigger is None:
            return None
        return _confirm_intoverflow(
            finding,
            binary,
            trigger,
            budget=budget,
            executor=executor,
            compiler_path=compiler_path,
            compiler_resolved=compiler_resolved,
        )
    if bc is UAF:
        if trigger is None:
            return None
        return _confirm_uaf(
            finding,
            binary,
            trigger,
            control,
            budget=budget,
            executor=executor,
            compiler_path=compiler_path,
            compiler_resolved=compiler_resolved,
        )
    return None


def _confirm_cmdi(
    finding: Finding,
    verdict: Verdict,
    binary: str,
    *,
    budget: BudgetTracker | None = None,
    executor: Executor | None = None,
    compiler_path: str | None = None,
    compiler_resolved: bool = False,
) -> PoV | None:
    """Confirm command/argument injection. Preferred path is the **exec-trap**
    oracle (oracle.exectrap_env): an LD_PRELOAD shim intercepts the exec/system/
    popen/spawn family and, when a per-run sentinel token reaches an exec argument,
    emits a token-bound marker and exits BEFORE running the command — proving
    injection (incl. CWE-88 argv injection, where nothing is echoed) without
    executing anything harmful. Falls back to the ``echo <canary>`` sentinel (which
    needs the injected command to actually run) when no compiler is available."""
    from .dynamic import SubprocessRunner

    canary = oracle.new_canary()
    vector = vector_for(finding.source)
    runner = SubprocessRunner(executor)

    # --- preferred: exec-trap (sees injection even when nothing is echoed) ----
    trap_env = oracle.exectrap_env(
        canary,
        executor=executor,
        budget=budget,
        compiler_path=compiler_path,
        compiler_resolved=compiler_resolved,
    )
    if trap_env:
        pov = _exectrap_cmdi(
            finding,
            verdict,
            binary,
            canary,
            vector,
            runner,
            trap_env,
            budget=budget,
        )
        if pov is not None:
            return pov

    # --- fallback: sentinel ``echo <canary>`` observed in stdout -------------
    marker = oracle.marker_line(canary, "reached-sink")
    sentinel = f"echo {marker}"
    if not _reserve_oracle_runs(budget):
        return None
    if vector == "env":
        name = _env_name(verdict.input_example)
        env = {name: sentinel}
        r = runner.run(binary, env=env, timeout=_oracle_timeout(budget, 5.0))
        output = r.stdout + r.stderr
        if r.valid and oracle.adjudicate_capability(output, canary).proven:
            return PoV(env=env, crash_class="command-injection",
                       crash_trace=output.decode("utf-8", "replace").strip(),
                       reproduced=True, capability="reached-sink",
                       execution_provenance=dict(r.provenance))
        return None

    # stdin / argv: deliver an injected sub-command. ``; echo MARKER`` breaks out
    # of a quoted command; a leading bare ``echo MARKER`` covers system(input).
    payload = f"; {sentinel}\n".encode()
    if vector == "argv":
        r = runner.run(
            binary,
            argv=[payload.decode("latin-1")],
            timeout=_oracle_timeout(budget, 5.0),
        )
    else:
        r = runner.run(
            binary,
            stdin=payload,
            timeout=_oracle_timeout(budget, 5.0),
        )
    output = r.stdout + r.stderr
    if r.valid and oracle.adjudicate_capability(output, canary).proven:
        return PoV(
            input_bytes=payload if vector == "stdin" else None,
            argv=[payload.decode("latin-1")] if vector == "argv" else [],
            crash_class="command-injection",
            crash_trace=output.decode("utf-8", "replace").strip(),
            reproduced=True, capability="reached-sink",
            execution_provenance=dict(r.provenance),
        )
    return None


def _exectrap_cmdi(
    finding: Finding,
    verdict: Verdict,
    binary: str,
    canary: str,
    vector: str,
    runner: object,
    trap_env: dict[str, str],
    *,
    budget: BudgetTracker | None = None,
) -> PoV | None:
    """Drive the target under the exec-trap shim. The injected sentinel is the
    unique ``canary`` token; ``; <canary>`` breaks out of a quoted command and the
    bare token covers ``system(input)`` / argv-injection. The shim matches the
    token in an exec arg, emits the capability marker, and exits without running
    it. A standalone PoV records only the injected payload (not the shim)."""
    from .dynamic import SubprocessRunner

    assert isinstance(runner, SubprocessRunner)
    trace = f"exec-trap: sentinel '{canary}' reached an exec argument (never executed)"
    if not _reserve_oracle_runs(budget):
        return None

    if vector == "env":
        name = _env_name(verdict.input_example)
        inject = {name: f"; {canary}"}
        r = runner.run(
            binary,
            env={**trap_env, **inject},
            timeout=_oracle_timeout(budget, 5.0),
        )
        if r.valid and oracle.adjudicate_capability(r.stdout + r.stderr, canary).proven:
            return PoV(env=inject, crash_class="command-injection",
                       crash_trace=trace, reproduced=True, capability="reached-sink",
                       execution_provenance=dict(r.provenance))
        return None

    payload = f"; {canary}\n".encode()
    if vector == "argv":
        r = runner.run(
            binary,
            argv=[payload.decode("latin-1")],
            env=trap_env,
            timeout=_oracle_timeout(budget, 5.0),
        )
    else:
        r = runner.run(
            binary,
            stdin=payload,
            env=trap_env,
            timeout=_oracle_timeout(budget, 5.0),
        )
    if r.valid and oracle.adjudicate_capability(r.stdout + r.stderr, canary).proven:
        return PoV(
            input_bytes=payload if vector == "stdin" else None,
            argv=[payload.decode("latin-1")] if vector == "argv" else [],
            crash_class="command-injection", crash_trace=trace,
            reproduced=True, capability="reached-sink",
            execution_provenance=dict(r.provenance),
        )
    return None


def _confirm_fmtstring(
    finding: Finding,
    binary: str,
    *,
    control: bytes,
    budget: BudgetTracker | None = None,
    executor: Executor | None = None,
    compiler_path: str | None = None,
    compiler_resolved: bool = False,
) -> PoV | None:
    """Differential format-string oracle: a ``%s``-spray (+ ``%n``) probe drives a
    wild pointer read/write crash; a benign control input does not crash."""
    vector = vector_for(finding.source)
    probe = oracle.format_string_probe()
    if not _reserve_oracle_runs(budget, 2):
        return None
    target = _drive_once(
        binary,
        finding.source,
        probe,
        budget=budget,
        executor=executor,
    )
    ctrl = _drive_once(
        binary,
        finding.source,
        control,
        budget=budget,
        executor=executor,
    )
    if not oracle.differential_confirmed(target, ctrl):
        return None
    pov = PoV(
        input_bytes=probe if vector == "stdin" else None,
        argv=[probe.decode("latin-1")] if vector == "argv" else [],
        crash_class=target.signal or "SIGSEGV",
        crash_trace=target.stderr[-400:],
        reproduced=True, capability="oob-read",
        execution_provenance=dict(target.provenance),
    )
    pov.diff_allocator = "fmtstring probe (%s-spray/%n): crash vs clean control"
    return pov


def _confirm_intoverflow(
    finding: Finding,
    binary: str,
    trigger: bytes,
    *,
    budget: BudgetTracker | None = None,
    executor: Executor | None = None,
    compiler_path: str | None = None,
    compiler_resolved: bool = False,
) -> PoV | None:
    """REUSE the differential-allocator (+ quarantine guard page): the overflowing
    size yields an undersized alloc and a heap OOB that only faults under the guard."""
    vector = vector_for(finding.source)
    if not _reserve_oracle_runs(budget, 2):
        return None
    guard = oracle.build_quarantine_guard(
        executor=executor,
        budget=budget,
        compiler_path=compiler_path,
        compiler_resolved=compiler_resolved,
    )
    diff = oracle.differential_allocator(
        binary,
        trigger,
        vector=vector,
        extra_preload=guard,
        timeout=_oracle_timeout(budget),
        deadline_monotonic=(budget.deadline_monotonic if budget is not None else None),
        executor=executor,
        budget=budget,
        compiler_path=compiler_path,
        compiler_resolved=compiler_resolved,
    )
    if not diff.confirmed:
        return None
    guard_only = diff.real_heap_bug and not diff.stock.crashed
    repro_env = (
        oracle.quarantine_env(
            executor=executor,
            budget=budget,
            compiler_path=compiler_path,
            compiler_resolved=compiler_resolved,
        )
        if guard_only
        else {}
    )
    crash_signal = diff.stock.signal if diff.stock.crashed else diff.guard.signal
    pov = PoV(
        input_bytes=trigger if vector == "stdin" else None,
        argv=[trigger.decode("latin-1")] if vector == "argv" else [],
        env=repro_env,
        crash_class=crash_signal or "SIGSEGV",
        crash_trace=(diff.guard.stderr or diff.stock.stderr)[-400:],
        reproduced=True, capability="oob-write",
        execution_provenance=dict(
            diff.stock.provenance if diff.stock.crashed else diff.guard.provenance
        ),
    )
    pov.diff_allocator = (
        f"stock={'crash' if diff.stock.crashed else 'clean'} "
        f"guard={'crash' if diff.guard.crashed else 'clean'}"
        + (" [clean->crash: undersized alloc, real heap OOB]" if diff.real_heap_bug else "")
    )
    return pov


def _confirm_uaf(
    finding: Finding,
    binary: str,
    trigger: bytes,
    control: bytes,
    *,
    budget: BudgetTracker | None = None,
    executor: Executor | None = None,
    compiler_path: str | None = None,
    compiler_resolved: bool = False,
) -> PoV | None:
    """Quarantine-guard differential: the trigger faults under poison+quarantine
    (UAF read/write SIGSEGV, or double-free trap); a benign control stays clean."""
    vector = vector_for(finding.source)
    if not _reserve_oracle_runs(budget, 2):
        return None
    v = oracle.uaf_differential(
        binary,
        trigger,
        control,
        vector=vector,
        timeout=_oracle_timeout(budget),
        deadline_monotonic=(budget.deadline_monotonic if budget is not None else None),
        executor=executor,
        budget=budget,
        compiler_path=compiler_path,
        compiler_resolved=compiler_resolved,
    )
    if not v.confirmed:
        return None
    pov = PoV(
        input_bytes=trigger if vector == "stdin" else None,
        argv=[trigger.decode("latin-1")] if vector == "argv" else [],
        env=oracle.quarantine_env(
            executor=executor,
            budget=budget,
            compiler_path=compiler_path,
            compiler_resolved=compiler_resolved,
        ),
        crash_class=v.trigger.signal or "SIGSEGV",
        crash_trace=v.trigger.stderr[-400:],
        reproduced=True,
        capability="oob-write" if v.kind != "double-free" else "crash",
        execution_provenance=dict(v.trigger.provenance),
    )
    pov.diff_allocator = f"quarantine guard: {v.kind} (trigger crash / control clean)"
    return pov


def _drive_once(
    binary: str,
    source: str,
    payload: bytes,
    *,
    budget: BudgetTracker | None = None,
    executor: Executor | None = None,
) -> oracle.RunResult:
    from .dynamic import SubprocessRunner

    runner = SubprocessRunner(executor)
    if vector_for(source) == "argv":
        r = runner.run(
            binary,
            argv=[payload.decode("latin-1")],
            timeout=_oracle_timeout(budget, 5.0),
        )
    else:
        r = runner.run(
            binary,
            stdin=payload,
            timeout=_oracle_timeout(budget, 5.0),
        )
    return oracle.RunResult(
        crashed=r.valid and r.crashed,
        signal=r.signal if r.valid else "",
        stderr=r.stderr.decode("utf-8", "replace"),
        provenance=dict(r.provenance),
        valid=r.valid,
        infrastructure_error="" if r.valid else r.stderr.decode("utf-8", "replace"),
    )


def _env_name(hint: str, default: str = "CMD") -> str:
    m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", hint)
    return m.group(1) if m else default

"""Strip AddressSanitizer instrumentation from Ghidra decompiler pseudo-C.

Real 0day targets ship as ASan builds with no clean counterpart. Decompiling an
ASan binary yields pseudo-C where every memory access is wrapped in inlined
instrumentation: a shadow-byte load (``*(char *)((ulong)p >> 3 + 0x7fff8000)``), a
slow-path branch, and a call to ``__asan_report_loadN`` / ``__asan_report_storeN``;
libFuzzer coverage adds ``__sanitizer_cov_trace_*`` calls on every edge/compare.
That noise (a) breaks the candidate lenses — the shadow ``if`` blocks and the report
branches drown out the real ``buf[i] = …`` store shape — and (b) wrecks LLM
reasoning, which burns attention explaining ``0x7fff8000`` arithmetic instead of the
bug.

This module removes that instrumentation so the REAL program logic is legible again,
**conservatively**: it only ever deletes statements that are provably pure ASan/cov
bookkeeping (a report/coverage/poison call, or an ``if`` whose entire body is such a
call), or an assignment that computes a shadow address (keyed on the unmistakable
shadow-offset literal). The instrumented libc interceptors that carry REAL semantics
(``__asan_memcpy`` is a ``memcpy``) are RENAMED, never dropped. It never removes an
ordinary memory access, arithmetic, loop, or call — a clean build is the target
shape, and over-deleting would hide the very bug we are hunting.

Pure text transformation: no Ghidra, no LLM. Unit-tested on synthetic bodies.
"""

from __future__ import annotations

import re

# --- ASan / coverage symbol taxonomy ----------------------------------------
#
# Three disjoint classes, handled differently:
#   * REPORTERS + COVERAGE + POISON — void, side-effect-only bookkeeping that carries
#     NO program data. Safe to delete outright (statement or whole guarding ``if``).
#   * INTERCEPTORS — instrumented libc ops that ARE real program semantics. Renamed to
#     the bare libc name so the operation (and its data flow) survives.
#   * everything else ``__asan_*`` (stack_malloc/stack_free/option_detect/…) — left
#     untouched: they may define a value later logic reads, so deleting them could
#     drop real def-use edges. Conservative by design.

# Pure side-effect bookkeeping calls — deletable as whole statements.
_NOISE_CALL = re.compile(
    r"\b__(?:"
    r"asan_report\w*|asan_handle_no_return|asan_report_error|"
    r"asan_poison\w*|asan_unpoison\w*|asan_set_shadow\w*|"
    r"asan_alloca_poison|asan_allocas_unpoison|"
    r"asan_register\w*|asan_unregister\w*|asan_before_dynamic_init|"
    r"asan_after_dynamic_init|asan_version_mismatch\w*|"
    r"sanitizer_cov\w*|hwasan_report\w*|hwasan_check\w*|hwasan_tag\w*"
    r")\b"
)

# The subset that appears as the SOLE body of an injected shadow-check ``if`` — a
# report/coverage/poison call. If an ``if`` block reduces to only these, the whole
# branch is instrumentation and is removed.
_REPORTER = re.compile(
    r"\b__(?:asan_report\w*|asan_handle_no_return|asan_report_error|"
    r"sanitizer_cov\w*|hwasan_report\w*|asan_poison\w*|asan_unpoison\w*|"
    r"asan_set_shadow\w*)\b"
)

# Instrumented libc interceptors that carry real semantics — rename to the libc name.
_INTERCEPTOR = re.compile(
    r"\b__asan_(memcpy|memmove|memset|mempcpy|strcpy|strncpy|strcat|strncat|"
    r"strlen|strnlen|strcmp|strncmp|strcasecmp|strncasecmp|memcmp|bcmp|bcopy|"
    r"strdup|strndup|strchr|strrchr|strstr|strcasestr|memchr|stpcpy|strtok|"
    r"atoi|atol|atoll|strtol|strtoll|read|write|pread|pwrite)\b"
)

# The ASan shadow-memory offset literals. ``(addr >> 3) + <offset>`` is the shadow
# address; these constants are an unmistakable ASan fingerprint (x86-64 Linux =
# 0x7fff8000; other platforms listed for safety). An assignment whose expression
# contains one computes a shadow address only — never program data.
_SHADOW_OFFSETS: tuple[str, ...] = (
    "0x7fff8000",
    "0x7fff_8000",
    "0x1000000000",
    "0x100000000000",
    "0x2000000000",
    "0x3000000000",
    "0xdfff8000",
    "0xffff8000",
)
_SHADOW_LIT = re.compile("|".join(re.escape(o) for o in _SHADOW_OFFSETS))


def is_asan_instrumented(body: str) -> bool:
    """Cheap detector: does this decompiled body carry ASan/cov instrumentation?
    Used to report how much deasan changed and to gate reporting, never to filter."""
    if not body:
        return False
    return bool(
        "__asan" in body
        or "__sanitizer_cov" in body
        or "__hwasan" in body
        or _SHADOW_LIT.search(body)
        or _COV_COUNTER.search(body)  # SanitizerCoverage inline-8bit-counter build
    )


# --- statement / block scanning helpers -------------------------------------


def _stmt_end(text: str, pos: int) -> int:
    """Index of the ``;`` terminating the statement that ``pos`` sits inside,
    respecting (){}[] nesting. Returns ``len(text)`` if none (truncated body)."""
    depth = 0
    i = pos
    n = len(text)
    while i < n:
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == ";" and depth <= 0:
            return i
        i += 1
    return n


def _stmt_start(text: str, pos: int) -> int:
    """Index just after the nearest preceding ``;``, ``{`` or ``}`` — the start of the
    statement containing ``pos``."""
    start = max(
        text.rfind(";", 0, pos),
        text.rfind("{", 0, pos),
        text.rfind("}", 0, pos),
    )
    return start + 1


def _match_paren(text: str, open_idx: int) -> int:
    """Index of the ``)`` closing the ``(`` at ``open_idx``; ``-1`` if unbalanced."""
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _match_brace(text: str, open_idx: int) -> int:
    """Index of the ``}`` closing the ``{`` at ``open_idx``; ``-1`` if unbalanced."""
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _delete_matching_statements(text: str, pattern: re.Pattern[str]) -> str:
    """Delete every whole statement that contains a ``pattern`` match, in a SINGLE
    rebuild pass (not a per-match string copy — that was O(n·matches) and quadratic on
    the huge templated functions ASan bloats). Each statement span runs from just
    after the previous ``;``/``{``/``}`` to its terminating ``;`` (nesting-aware), so
    ``x = __asan_report(...);`` goes entirely. Overlapping spans are merged."""
    spans: list[tuple[int, int]] = []
    for m in pattern.finditer(text):
        s = _stmt_start(text, m.start())
        e = _stmt_end(text, m.end())
        e = e + 1 if e < len(text) else e  # include the ';'
        if spans and s <= spans[-1][1]:
            spans[-1] = (spans[-1][0], max(spans[-1][1], e))
        else:
            spans.append((s, e))
    if not spans:
        return text
    out: list[str] = []
    prev = 0
    for s, e in spans:
        if s > prev:
            out.append(text[prev:s])
        prev = max(prev, e)
    out.append(text[prev:])
    return "".join(out)


def _delete_noise_statements(text: str, pattern: re.Pattern[str]) -> str:
    return _delete_matching_statements(text, pattern)


def _delete_shadow_assignments(text: str) -> str:
    """Delete statements that reference a shadow-offset literal — they compute a
    shadow address (``uVar = (long)p >> 3 + 0x7fff8000``) and nothing else. Keyed on
    the unmistakable ASan constant, so it never touches ordinary arithmetic."""
    return _delete_matching_statements(text, _SHADOW_LIT)


def _residue_is_empty(inner: str) -> bool:
    """After stripping ASan reporter/cov/poison statements and shadow assignments, is
    the block body empty (only whitespace / braces / semicolons)? Then the block is
    pure instrumentation and can be removed wholesale."""
    t = _delete_noise_statements(inner, _NOISE_CALL)
    t = _delete_shadow_assignments(t)
    return re.sub(r"[\s{}();]", "", t) == ""


# A shadow-check ``if`` body is tiny — ``__asan_report_loadN()`` optionally wrapped in
# one nested branch. Cap the residue check at this length so we never pay a full-body
# scan on a large REAL ``if`` that merely happens to contain a report call (that report
# is stripped later by the statement pass anyway). Keeps the pass near-linear.
_MAX_REPORTER_BODY = 400

_IF_RE = re.compile(r"\bif\s*\(")

# SanitizerCoverage inline-8bit-counter bumps: a global counter self-incremented by 1,
# e.g. ``DAT_00a2647c = DAT_00a2647c + '\x01';`` — Ghidra renders these on nearly every
# basic block of a `-fsanitize-coverage` build, drowning the real logic (a bounds check
# gets lost among dozens of them). Pure instrumentation; the backreference ensures LHS
# and RHS name the SAME counter so we never delete real ``a = b + 1`` arithmetic.
_COV_COUNTER = re.compile(
    r"[ \t]*(DAT_[0-9a-fA-F]+)\s*=\s*\1\s*\+\s*(?:'\\x[0-9a-fA-F]{2}'|[0-9]+)\s*;[ \t]*\n?"
)


def _remove_reporter_ifs(text: str) -> str:
    """Remove ``if (<shadow check>) { __asan_report_x(...); }`` branches — an ``if``
    whose entire (small) body is ASan bookkeeping. Handles both a braced block and a
    single guarded statement. Never removes an ``if`` that has an ``else`` or any real
    statement in its body (conservative: keep anything that might be program logic).

    Single forward pass appending to an output buffer: when a block is removed it is
    skipped; when it is kept, scanning continues *inside* its body so nested shadow
    ``if``s are still reached — no restart, so the pass is near-linear."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        m = _IF_RE.search(text, i)
        if m is None:
            out.append(text[i:])
            break
        cond_open = m.end() - 1
        cond_close = _match_paren(text, cond_open)
        if cond_close < 0:
            out.append(text[i:])
            break
        j = cond_close + 1
        while j < n and text[j] in " \t\r\n":
            j += 1
        if j >= n:
            out.append(text[i:])
            break
        if text[j] == "{":
            body_close = _match_brace(text, j)
            if body_close < 0:
                out.append(text[i:])
                break
            inner = text[j + 1 : body_close]
            block_end = body_close + 1
            body_start = j + 1
        else:
            se = _stmt_end(text, j)
            inner = text[j:se]
            block_end = se + 1 if se < n else se
            body_start = j
        tail = text[block_end : block_end + 6]
        has_else = tail.lstrip().startswith("else")
        removable = (
            len(inner) <= _MAX_REPORTER_BODY
            and not has_else
            and _REPORTER.search(inner)
            and _residue_is_empty(inner)
        )
        if removable:
            # emit everything before the ``if`` and skip the whole block
            out.append(text[i : m.start()])
            i = block_end
        else:
            # keep the ``if (cond) {`` header and descend into the body so nested
            # shadow-ifs are still removed
            out.append(text[i:body_start])
            i = body_start
    return "".join(out)


def _tidy(text: str) -> str:
    """Collapse the blank lines / empty ``{ }`` husks left behind by deletion."""
    # drop lines that became empty or a lone semicolon
    lines = [ln for ln in text.splitlines() if ln.strip() not in ("", ";")]
    text = "\n".join(lines)
    # collapse >2 consecutive newlines
    return re.sub(r"\n{3,}", "\n\n", text)


def deasan(body: str) -> str:
    """Return ``body`` with ASan/coverage instrumentation neutralized and the real
    program logic preserved. Idempotent and safe on non-instrumented input (returns it
    essentially unchanged). Order matters:

    1. rename instrumented libc interceptors to their bare names (keep the operation),
    2. remove ``if (shadow) { report(); }`` branches (pure instrumentation),
    3. delete any remaining standalone report/coverage/poison statements,
    4. delete shadow-address assignments (keyed on the shadow-offset literal),
    5. tidy the whitespace the deletions leave behind.
    """
    if not body:
        return body
    if not is_asan_instrumented(body):
        return body
    text = _INTERCEPTOR.sub(lambda mm: mm.group(1), body)
    text = _remove_reporter_ifs(text)
    text = _delete_noise_statements(text, _NOISE_CALL)
    text = _delete_shadow_assignments(text)
    text = _COV_COUNTER.sub("", text)  # drop SanitizerCoverage counter bumps
    return _tidy(text)


def deasan_all(decompiled: dict[str, str]) -> dict[str, str]:
    """Deasan every function body in a ``func -> pseudo-C`` map. Cheap enough to run
    once when constructing the tool surface; a no-op for stripped/non-ASan targets."""
    return {fn: deasan(body) for fn, body in decompiled.items()}

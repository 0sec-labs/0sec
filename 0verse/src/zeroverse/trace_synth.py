"""Trace-guided structured-input synthesis — the parser/container-CVE confirm channel.

WHY THIS EXISTS. Two channels came before and each has a blind spot:
  * ``confirm_by_synthesis`` builds SINK-LOCAL inputs — it knows the format at the
    bug, but not the nested ENVELOPE (magic strings + tag dispatch + length fields)
    that must be satisfied to ROUTE bytes to the sink. On a container format it emits
    plausible-but-unreachable inputs.
  * ``confirm_by_directed_fuzz`` mutates real seeds toward the sink — but only if the
    seed is the RIGHT sub-format; blind mutation cannot invent a valid TIFF→Adobe→
    "MakN"→"RAF " container from scratch, and it plateaus (validated on libraw: a Fuji
    RAF seed never reaches the Adobe/TIFF-DNG sink at all).

The wall for parser/container CVEs is the GRAMMAR ENVELOPE — reachability — not the
trigger arithmetic. This channel attacks exactly that: it reads the decompiled parser
functions along the ENTRY->SINK call path, has the LLM recover the container grammar
that reaches the sink + the input-controlled field and the bound it must violate, and
synthesizes a STRUCTURALLY VALID input carrying that field to the fault. A coverage
signal (which path functions the candidate reached) feeds refinement, and the SAME
deterministic differential oracle confirms.

This generalizes the technique that reproduced ARVO libraw 67791 from scratch: a
1024-byte TIFF whose 0xC634 DNGPrivateData tag carries an "Adobe"/"MakN"/"RAF "
makernote with a negative offset (``sget4(2) = -9``) that the vuln's one-sided bounds
check misses — a bug a Fuji-RAF corpus and blind fuzzing could never reach.

PoV-IS-TRUTH. The LLM proposes structure; only the oracle confirms — the vuln binary
crashes under ASan at the hypothesized sink AND the fixed binary runs the same input
clean. The channel never self-confirms.

HONEST LIMITS. (1) Envelope recovery is only as good as the decompiled parser code —
on a stripped/no-DWARF binary the grammar is murkier. (2) It targets container/parser
bugs where reachability is the wall; a bug gated by a real checksum/state-machine
computation still needs a solver. (3) The recovery leans on the LLM reverse-
engineering the format — whether it is autonomous binary-first or needs a source
crutch is measured per target, not assumed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from . import oracle
from .adjudicate import adjudicate_finding, func_matches
from .sandbox_exec import LocalExecutor, current_executor

# ASan/LSan noise on the patched path — irrelevant to the spatial-safety differential.
_ORACLE_ENV = {"ASAN_OPTIONS": "detect_leaks=0", "UBSAN_OPTIONS": "halt_on_error=0"}

# Attacker-input entry points for a libFuzzer/OSS-Fuzz harness (where the call path
# to the sink must originate).
_ENTRY_NAMES = ("LLVMFuzzerTestOneInput", "StandaloneFuzzTargetMain", "main")

# Identifier tokens in decompiled code (to find which functions call a callee).
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")

# Reader-helper name hint: reaching one of these means routing got to the fault site.
_READER_HINT = re.compile(r"sget|get2|get4|getint|getbits", re.I)


@dataclass
class EnvelopeLayer:
    """One nested layer of the container grammar on the path to the sink — e.g. the
    TIFF header, a specific tag (0xC634), an ``"Adobe\\0"`` magic, a length field."""

    name: str = ""
    kind: str = ""  # magic | tag | length | offset | field | container
    detail: str = ""  # human description of what the parser requires here
    bytes_hint: str = ""  # concrete bytes/pattern the parser matches (hex or ascii)


@dataclass
class EnvelopeSpec:
    """The recovered grammar that routes attacker bytes to the sink + the fault field."""

    format_name: str = ""
    layers: list[EnvelopeLayer] = field(default_factory=list)
    controlled_field: str = ""  # the input-derived value at the sink
    fault_constraint: str = ""  # the bound it must violate (e.g. "offset < 0")
    notes: str = ""


@dataclass
class TraceSynthResult:
    """Outcome of a trace-guided synthesis attempt. ``confirmed`` is the only authority
    claim (differential oracle). ``crash_function`` is where the input actually
    crashed; ``reached_depth`` is how far along the entry->sink path the best candidate
    got (the reproducible progress signal)."""

    confirmed: bool = False
    crash_function: str = ""
    crash_cwe: str = ""
    matches_sink: bool = False
    winning_input: bytes | None = None
    winning_path: str = ""
    path: list[str] = field(default_factory=list)
    envelope: EnvelopeSpec | None = None
    iterations: int = 0
    reached_depth: int = 0
    reached_sink: bool = False  # a candidate dispatched to the sink parser
    reaching_inputs: list[bytes] = field(default_factory=list)  # candidates that reached it
    confirmed_via: str = ""  # "synthesis" | "hybrid-fuzz"
    reason: str = ""
    notes: list[str] = field(default_factory=list)


# --- call-path recovery (entry -> sink) -------------------------------------


def _decompiled(meta: Any) -> dict[str, str]:
    dc = getattr(meta, "decompiled_c", None)
    return dc if isinstance(dc, dict) else {}


def _sink_function(verdict: Any, dc: dict[str, str]) -> str:
    """Resolve the verdict sink to a decompiled function to ANCHOR the caller walk.

    Prefers the MOST SPECIFIC named function so the slice is focused: a ubiquitous
    helper like ``sget4`` is called from hundreds of sites (walking up from it
    explodes), whereas the vulnerable PARSER function localization also names (e.g.
    ``parseAdobeRAFMakernote``) yields a small, correct slice. Match order: exact name
    → the longest decompiled-name that is a whole-word token of the sink string →
    substring → loose func_matches. Among candidates, the longest/most-specific wins."""
    sink = str(getattr(verdict, "sink", "") or "")
    tokens: list[str] = _IDENT_RE.findall(sink)
    tokenset = set(tokens)
    # 1. exact name match (longest token that is a dc key).
    exact = [t for t in tokens if t in dc]
    if exact:
        return max(exact, key=len)
    # 2. a dc function name that appears as a whole word in the sink string.
    whole = [n for n in dc if re.search(rf"\b{re.escape(n)}\b", sink)]
    if whole:
        return max(whole, key=len)
    # 3. token is a substring of a dc name (or vice-versa) — most specific first.
    subs = [n for n in dc for t in tokenset if len(t) >= 4 and (t in n or n in t)]
    if subs:
        return max(subs, key=len)
    # 4. last resort: loose func_matches.
    for name in dc:
        if any(func_matches(name, t) for t in tokens):
            return name
    return tokens[0] if tokens else ""


def recover_call_path(
    meta: Any, verdict: Any, *, entry: str | None = None, max_depth: int = 8
) -> list[str]:
    """Recover a callee chain ENTRY -> ... -> SINK by walking UP the caller graph from
    the sink function (a function calls the sink if its decompiled body names it). The
    path (entry-first) selects which parser functions the envelope recovery reads.

    Best-effort and approximate on decompiled code — returns the shortest caller chain
    it can find, or just [sink] when callers can't be resolved."""
    dc = _decompiled(meta)
    if not dc:
        return []
    sink = _sink_function(verdict, dc)
    if not sink:
        return []
    entries = [entry] if entry else [e for e in _ENTRY_NAMES if e in dc]

    # BFS up the caller graph: parents(f) = functions whose body references f.
    def callers_of(fn: str) -> list[str]:
        out = []
        for name, body in dc.items():
            if name != fn and re.search(rf"\b{re.escape(fn)}\b", body or ""):
                out.append(name)
        return out

    # Walk up from sink toward any entry.
    seen = {sink}
    frontier = [[sink]]
    for _ in range(max_depth):
        nxt = []
        for chain in frontier:
            head = chain[0]
            if head in entries or (not entries and head in _ENTRY_NAMES):
                return chain
            for c in callers_of(head):
                if c not in seen:
                    seen.add(c)
                    nxt.append([c, *chain])
        if not nxt:
            break
        frontier = nxt
    # No entry reached — return the deepest chain we built (still useful context).
    return frontier[0] if frontier else [sink]


# --- LLM envelope recovery ---------------------------------------------------

_ENVELOPE_SYSTEM = """You are reverse-engineering a binary parser to reach a memory-safety sink.
You are given the decompiled C of the functions ALONG the call path from the fuzzer
entry point to a vulnerable sink, plus the sink hypothesis. Recover the INPUT GRAMMAR
that an attacker-controlled input must satisfy to route bytes through EVERY function on
this path and reach the sink — the nested container ENVELOPE (magic bytes, format
signatures, tag/type dispatch values, length and offset fields, counts), IN ORDER from
the outermost container inward to the sink.

Then identify (1) the CONTROLLED FIELD: the input-derived value used at the sink, and
(2) the FAULT CONSTRAINT: the exact condition on that value that triggers the
out-of-bounds/overflow (e.g. "offset < 0", "length > buffer_size", "count * stride
overflows"). Look for a bounds check that is MISSING or one-sided.

The SINK function's own body is the ground truth for the INNER format — its literal
string/tag comparisons (e.g. it may check for "Adobe", "MakN", "RAF ", a magic dword, a
specific tag id) tell you the format FAMILY. Use that to also specify the STANDARD OUTER
container that carries this inner structure even if the outer parser code is not fully
shown: a camera makernote is delivered inside a TIFF/EXIF MakerNote or DNG DNGPrivateData
(tag 0xC634) IFD entry; a font table inside an sfnt/OpenType wrapper; etc. Emit those
outer layers using your knowledge of the format so the input is actually routable.

Be concrete: give the literal bytes/signatures the parser compares against (as hex or
ascii), the field widths and endianness, and where each field sits relative to its
container. Only assert what the code shows for the inner layers; for standard outer
containers you may use well-known format structure."""

_ENVELOPE_SCHEMA = {
    "type": "object",
    "properties": {
        "format_name": {"type": "string"},
        "layers": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "kind": {
                        "type": "string",
                        "enum": ["magic", "tag", "length", "offset", "field", "container", "count"],
                    },
                    "detail": {"type": "string"},
                    "bytes_hint": {"type": "string"},
                },
                "required": ["name", "kind", "detail"],
            },
        },
        "controlled_field": {"type": "string"},
        "fault_constraint": {"type": "string"},
        "notes": {"type": "string"},
    },
    "required": ["format_name", "layers", "controlled_field", "fault_constraint"],
}


def caller_slice(meta: Any, verdict: Any, *, max_depth: int = 6) -> list[str]:
    """The program slice relevant to reaching the sink: the sink function plus ALL its
    transitive callers up to ``max_depth``, ordered OUTERMOST-first (nearest an entry)
    so the envelope reads like the parse order. A naive single shortest caller-chain
    (recover_call_path) finds spurious textual shortcuts and starves recovery — the
    full neighborhood reliably includes the real parser functions (parse_tiff,
    parse_makernote_0xc634, parseAdobeRAFMakernote, sget4, ...)."""
    dc = _decompiled(meta)
    sink = _sink_function(verdict, dc)
    if not sink or sink not in dc:
        return [sink] if sink else []
    dist = {sink: 0}
    frontier = [sink]
    # Per-level + total caps: a ubiquitous helper has hundreds of callers; an
    # uncapped walk explodes. Anchoring on the specific parser function (see
    # _sink_function) keeps this small; the caps are a backstop.
    for d in range(1, max_depth + 1):
        nxt = []
        for fn in frontier:
            for name, body in dc.items():
                if (
                    name not in dist
                    and name != fn
                    and re.search(rf"\b{re.escape(fn)}\b", body or "")
                ):
                    dist[name] = d
                    nxt.append(name)
                    if len(nxt) >= 40:
                        break
            if len(nxt) >= 40:
                break
        if not nxt or len(dist) >= 60:
            break
        frontier = nxt
    # Also include the sink's own callees that read scalars (the fault-field code),
    # e.g. sget4/get2/getint — the OOB arithmetic lives there.
    body = dc.get(sink, "")
    for name in dc:
        if (
            name not in dist
            and re.search(r"sget|get2|get4|getint|read", name, re.I)
            and re.search(rf"\b{re.escape(name)}\b", body)
        ):
            dist[name] = -1  # callee: place after the sink in ordering

    # Call-graph FALLBACK: on optimized C++ the outer container->parser edges are
    # unresolved (indirect/inlined dispatch), so the caller walk misses the container
    # functions even though their CODE is present. Augment with the real FORMAT-PARSER
    # functions: ones whose body CALLS the sink's reader helpers (sget4/get4/...) — a
    # precise signal that excludes C++ runtime noise (the demangler matches "parse*"
    # but never calls sget4). Prioritise names with image-format vocabulary. Placed
    # OUTERMOST since they carry the container grammar.
    readers = [n for n in dist if dist[n] == -1] + [sink]
    reader_re = (
        re.compile(r"\b(" + "|".join(re.escape(r) for r in readers) + r")\b") if readers else None
    )
    fmt_re = re.compile(r"parse|identif|makernote|ifd|tiff|dng|raw|meta|tag|header", re.I)
    cands = []
    for name, body in dc.items():
        if name in dist or not body or reader_re is None:
            continue
        if reader_re.search(body):  # this function reads binary format fields
            cands.append(name)
    # format-named parsers first, then other readers; cap to keep the code budget sane.
    cands.sort(key=lambda n: (0 if fmt_re.search(n) else 1, len(dc[n])))
    for name in cands[:14]:
        dist[name] = max_depth + 2  # outermost
    # outermost (largest distance) first, sink, then its reader callees.
    return sorted(dist, key=lambda f: -dist[f])


# Signals that mark format-parsing logic worth keeping when excerpting a huge function:
# reader-helper calls, byte-compare intrinsics, quoted magic literals, offset/len math.
_FOCUS_RE = re.compile(
    r"sget|get2|get4|getint|getbits|memcmp|strncmp|strcmp|memcpy|"
    r'"[^"]{2,8}"|'  # short magic string literals ("Adobe","RAF ")
    r"0x[0-9a-fA-F]{2,8}|"  # tag/magic hex constants
    r"offset|ifd|tag|len\b|count|entries",
    re.I,
)


def _focus_excerpt(body: str, *, max_chars: int, window: int = 320) -> str:
    """Reduce a huge decompiled body to the parsing-relevant regions: merged windows
    around reader-helper calls, magic-literal compares, tag/offset arithmetic. A 210KB
    inlined function becomes a focused excerpt of its format logic that fits the budget
    (the whole body would truncate away the very lines that matter)."""
    if len(body) <= max_chars:
        return body
    spans: list[tuple[int, int]] = []
    for m in _FOCUS_RE.finditer(body):
        spans.append((max(0, m.start() - window), min(len(body), m.end() + window)))
    if not spans:
        return body[:max_chars]
    # merge overlapping windows, then take from the front until the budget fills.
    spans.sort()
    merged: list[list[int]] = [list(spans[0])]
    for s, e in spans[1:]:
        if s <= merged[-1][1] + 40:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    out, used = [], 0
    for s, e in merged:
        seg = body[s:e]
        if used + len(seg) > max_chars:
            seg = seg[: max_chars - used]
        out.append(seg)
        used += len(seg)
        if used >= max_chars:
            break
    return " …\n".join(out)


def _path_code(meta: Any, funcs: list[str], *, max_chars: int = 30000) -> str:
    """Concatenate the decompiled C of the given functions (entry-first), budgeted. The
    FIRST function (the sink) gets the largest share and is excerpted to its parsing
    logic if huge; the rest share the remainder for outer-container context."""
    dc = _decompiled(meta)
    chunks, used = [], 0
    for i, fn in enumerate(funcs):
        body = dc.get(fn, "")
        if not body:
            continue
        # sink (first) may keep up to ~60% of the budget; excerpt if oversized.
        share = int(max_chars * 0.6) if i == 0 else max(2000, (max_chars - used) // 3)
        body = _focus_excerpt(body, max_chars=share)
        piece = f"/* ==== {fn} ==== */\n{body}\n"
        if used + len(piece) > max_chars:
            piece = piece[: max_chars - used]
        chunks.append(piece)
        used += len(piece)
        if used >= max_chars:
            break
    return "\n".join(chunks)


def recover_envelope(meta: Any, verdict: Any, path: list[str], llm: Any) -> EnvelopeSpec:
    """Ask the LLM to recover the container grammar + fault field from the path code.

    The SINK function body is the ground truth for the INNER grammar (it holds the
    magic-string checks + the fault field) and MUST NOT be truncated away by sibling
    noise, so it goes first; the container parsers follow for the outer envelope."""
    dc = _decompiled(meta)
    sink = _sink_function(verdict, dc)
    ordered = ([sink] if sink in dc else []) + [f for f in path if f != sink]
    code = _path_code(meta, ordered)
    sink = getattr(verdict, "sink", "") or ""
    cwe = getattr(verdict, "cwe", "") or ""
    prompt = (
        f"SINK HYPOTHESIS: {sink}\nCWE: {cwe}\n"
        f"CALL PATH (entry -> sink): {' -> '.join(path)}\n\n"
        f"DECOMPILED PATH FUNCTIONS:\n{code}\n\n"
        "Recover the input grammar (envelope) that reaches this sink, the controlled "
        "field, and the fault constraint."
    )
    try:
        raw = llm.complete_json(_ENVELOPE_SYSTEM, prompt, _ENVELOPE_SCHEMA)
    except Exception as e:
        return EnvelopeSpec(notes=f"envelope recovery ERROR: {type(e).__name__}: {e}")
    layers = [
        EnvelopeLayer(
            name=str(layer.get("name", "")),
            kind=str(layer.get("kind", "")),
            detail=str(layer.get("detail", "")),
            bytes_hint=str(layer.get("bytes_hint", "")),
        )
        for layer in (raw.get("layers") or [])
    ]
    return EnvelopeSpec(
        format_name=str(raw.get("format_name", "")),
        layers=layers,
        controlled_field=str(raw.get("controlled_field", "")),
        fault_constraint=str(raw.get("fault_constraint", "")),
        notes=str(raw.get("notes", "")),
    )


# --- LLM structured synthesis (envelope -> bytes) ---------------------------

_SYNTH_SYSTEM = """You construct a byte-exact input that satisfies a recovered container
grammar and drives an out-of-bounds at the sink. You are given the envelope layers (in
order, outermost first) with the exact magic/tag/length/offset requirements, the
controlled field, and the fault constraint it must violate.

Build the smallest input that:
 1. satisfies every layer's format check IN ORDER so the parser routes bytes to the
    sink (correct magic bytes, tag values, section signatures, and CONSISTENT length/
    count/offset fields with the right width+endianness), and
 2. sets the controlled field to a value that VIOLATES the bound (triggering the fault).

Output the input as a hex string (no spaces or 0x). If a length/offset field must be
consistent with content you place after it, compute it exactly. Prefer a minimal valid
container over a large one."""

_SYNTH_SCHEMA = {
    "type": "object",
    "properties": {
        "hex": {"type": "string", "description": "the full input as a hex string"},
        "rationale": {"type": "string"},
    },
    "required": ["hex"],
}


def _envelope_text(env: EnvelopeSpec) -> str:
    lines = [
        f"format: {env.format_name}",
        f"controlled_field: {env.controlled_field}",
        f"fault_constraint: {env.fault_constraint}",
    ]
    if env.notes:
        lines.append(f"notes: {env.notes}")
    lines.append("layers (outermost -> sink):")
    for i, layer in enumerate(env.layers):
        lines.append(
            f"  {i}. [{layer.kind}] {layer.name}: {layer.detail}"
            + (f"  bytes={layer.bytes_hint}" if layer.bytes_hint else "")
        )
    return "\n".join(lines)


def _decode_hex(h: str) -> bytes | None:
    h = (h or "").strip()
    if h[:2].lower() == "0x":
        h = h[2:]
    s = re.sub(r"[^0-9a-fA-F]", "", h)
    if len(s) < 2 or len(s) % 2:
        s = s[: len(s) - (len(s) % 2)]
    try:
        return bytes.fromhex(s) if s else None
    except ValueError:
        return None


# How many earlier rejected candidates are replayed into a synthesis prompt, and how
# much of each one. Bounded: ``synthesize_from_trace`` runs up to ``iterations`` times
# and each entry carries raw hex.
_MAX_REJECTED_HISTORY = 4
_REJECTED_HEX_CHARS = 96  # 48 bytes of the candidate — enough to identify the header


def _rejected_text(history: list[str]) -> str:
    """Render the ACCUMULATED rejected candidates. Handing the model only the latest
    feedback left every earlier attempt invisible, so it could (and does) re-propose a
    byte pattern already measured as non-routing."""
    recent = [h for h in history if h][-_MAX_REJECTED_HISTORY:]
    if not recent:
        return ""
    body = "\n".join(f"  {h}" for h in recent)
    return (
        f"\nALREADY TRIED AND REJECTED ({len(history)} attempt(s) so far) — do NOT "
        f"re-emit any of these byte patterns:\n{body}\n"
    )


def synthesize_structured(
    env: EnvelopeSpec, llm: Any, *, feedback: str = "", history: list[str] | None = None
) -> bytes | None:
    """Ask the LLM to emit a byte-exact input satisfying the envelope + violating the
    fault constraint. ``feedback`` carries the previous attempt's reached-depth so the
    model can fix the layer that blocked routing; ``history`` carries the candidates
    already rejected, so it cannot silently cycle back onto one."""
    prompt = f"ENVELOPE:\n{_envelope_text(env)}\n"
    if feedback:
        prompt += f"\nPREVIOUS ATTEMPT FEEDBACK (fix the blocking layer):\n{feedback}\n"
    prompt += _rejected_text(history or [])
    prompt += "\nEmit the input as hex."
    try:
        raw = llm.complete_json(_SYNTH_SYSTEM, prompt, _SYNTH_SCHEMA)
    except Exception:
        return None
    return _decode_hex(str(raw.get("hex", "")))


# --- coverage feedback (how far along the path did a candidate reach?) -------


def _reached_depth(vuln: str, candidate: bytes, path: list[str], timeout: float) -> tuple[int, str]:
    """Run the libFuzzer harness on the candidate with -print_coverage and count how
    many path functions were covered (entry-first). Returns (depth, last_reached).
    This is the trace-guided progress signal: a candidate that reaches function k of
    the path but not k+1 tells the LLM which layer blocked routing."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "cand"
        f.write_bytes(candidate)
        result = current_executor().run(
            [oracle._exec_path(vuln), "-runs=1", "-print_coverage=1", str(f)],
            timeout=timeout,
            env=_ORACLE_ENV,
        )
        if result.error or result.timed_out:
            return 0, ""
    out = result.stdout + result.stderr
    depth, last = 0, ""
    for i, fn in enumerate(path):
        # MUST be on a real COVERED_FUNC line — matching the bare name anywhere also
        # hits the UNCOVERED_FUNC listing (every function in the binary), which made
        # this always-true. Anchor to line start so "UNCOVERED_FUNC" cannot match.
        if fn and re.search(rf"(?m)^COVERED_FUNC:.*\b{re.escape(fn)}\b", out):
            depth, last = i + 1, fn
    return depth, last


def _covers_function(vuln: str, candidate: bytes, fn: str, timeout: float) -> bool:
    """Does the candidate execute the SPECIFIC function ``fn``? Uses per-input
    -print_coverage so a COVERED_FUNC line for ``fn`` proves the candidate actually
    dispatched to that parser — unlike covering a ubiquitous helper (sget4) that every
    format touches. This is the honest 'did we reach the Adobe path' check."""
    if not fn:
        return False
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "cand"
        f.write_bytes(candidate)
        result = current_executor().run(
            [oracle._exec_path(vuln), "-runs=1", "-print_coverage=1", str(f)],
            timeout=timeout,
            env=_ORACLE_ENV,
        )
        if result.error or result.timed_out:
            return False
    out = result.stdout + result.stderr
    # MUST anchor to a real COVERED_FUNC line: the bare substring "COVERED_FUNC:" also
    # occurs inside "UNCOVERED_FUNC:" (hits: 0), so an unanchored match reported EVERY
    # function in the binary as covered — a silent always-true false positive. Anchor to
    # line start (re.M) so an UNCOVERED_FUNC line cannot match.
    return bool(re.search(rf"(?m)^COVERED_FUNC:.*\b{re.escape(fn)}\b", out))


# --- orchestration -----------------------------------------------------------


# Extreme values to probe a suspected offset/length field with (big-endian + little-
# endian negatives and huge magnitudes) — the shapes that violate a one-sided bound.
_FAULT_VALUES: tuple[bytes, ...] = (
    b"\xff\xff\xff\xf7",
    b"\xf7\xff\xff\xff",
    b"\xff\xff\xff\xff",
    b"\x7f\xff\xff\xff",
    b"\xff\xff\xff\x80",
    b"\x80\x00\x00\x00",
    b"\x00\xff\xff\xff",
    b"\xff\xff\x00\x00",
)


def _field_sweep(
    vuln: str,
    fixed: str | None,
    candidate: bytes,
    verdict: Any,
    sink_fn: str,
    timeout: float,
    *,
    stride: int = 2,
    max_runs: int = 900,
) -> tuple[bytes, Any] | None:
    """Structure-preserving fault search: a candidate that REACHES the sink parser is
    one field-value away from the OOB, but blind fuzzing corrupts the fragile envelope.
    Instead, patch ONLY 4 bytes at a time — at each aligned offset, try each extreme
    fault value — keeping the whole envelope intact. Return the first patched input the
    differential oracle confirms crashes at the sink (fixed clean). Bounded + fully
    deterministic. This is the byte-placement the LLM couldn't do from decompiled code."""
    n = len(candidate)
    runs = 0
    for pos in range(0, max(0, n - 4) + 1, stride):
        for val in _FAULT_VALUES:
            if runs >= max_runs:
                return None
            patched = candidate[:pos] + val + candidate[pos + 4 :]
            runs += 1
            adj = adjudicate_finding(verdict, vuln, patched, vector="file", timeout=timeout)
            if adj.status not in ("CONFIRMED", "DIVERGENT"):
                continue
            crash_fn = adj.crash_function or ""
            if not (
                func_matches(crash_fn, getattr(verdict, "sink", "") or "")
                or func_matches(crash_fn, sink_fn)
                or adj.status == "CONFIRMED"
            ):
                continue
            if fixed:
                fx = oracle.run_sanitizer(
                    fixed, patched, vector="file", env=_ORACLE_ENV, timeout=timeout
                )
                if not fx.valid or fx.crashed:
                    continue  # not a differential
            return patched, adj
    return None


def confirm_by_trace_synthesis(
    meta: Any,
    verdict: Any,
    vuln_binary: str | Path,
    llm: Any,
    *,
    fixed_binary: str | Path | None = None,
    entry: str | None = None,
    iterations: int = 4,
    vector: str = "file",
    timeout: float = 20.0,
    seeds: list[str] | None = None,
    hybrid_fuzz: bool = True,
    hybrid_budget_s: float = 240.0,
    hybrid_jobs: int = 8,
) -> TraceSynthResult:
    """Confirm a parser/container finding by trace-guided structured synthesis.

    Recovers the entry->sink call path and its container grammar, synthesizes a
    structurally-valid input that violates the fault constraint, and refines over up to
    ``iterations`` rounds using a coverage reached-depth signal. Every candidate is
    adjudicated by the differential oracle (vuln crashes at the sink AND fixed clean).
    Returns ``confirmed`` only on an oracle-verified reproduction."""
    vuln = str(vuln_binary)
    fixed = str(fixed_binary) if fixed_binary else None
    res = TraceSynthResult()

    if not oracle.is_asan_file_target(vuln):
        res.reason = "target is not an ASan libFuzzer harness (this channel needs one)."
        return res

    # Prefer DYNAMIC reachability (real coverage from seeds) — it observes the true
    # entry->sink parsers, sidestepping the incomplete static C++ call graph. Fall back
    # to the static caller neighborhood when no seeds / no coverage.
    res.path = []
    if seeds:
        try:
            from .dynamic_trace import dynamic_reach_slice

            res.path = dynamic_reach_slice(vuln, seeds, meta, verdict, timeout=timeout * 4)
            if res.path:
                res.notes.append(f"dynamic reachability: {len(res.path)} covered parser fns")
        except Exception as e:
            res.notes.append(f"dynamic reachability failed: {type(e).__name__}: {e}")
    if not res.path:
        res.path = caller_slice(meta, verdict, max_depth=6)
        res.notes.append("static caller-slice fallback (no dynamic coverage)")
    if not res.path:
        res.reason = "could not locate the sink function / callers in the decompiled meta."
        return res

    env = recover_envelope(meta, verdict, res.path, llm)
    res.envelope = env
    if not env.layers and "ERROR" in env.notes:
        res.reason = env.notes
        return res

    sink_hint = getattr(verdict, "sink", "") or ""
    sink_fn = _sink_function(verdict, _decompiled(meta))
    feedback = ""
    # ACCUMULATED rejected candidates — one line per attempt that did not win, so a
    # later iteration can see (and avoid) every earlier dead end, not just the last.
    rejected: list[str] = []
    for i in range(1, iterations + 1):
        res.iterations = i
        cand = synthesize_structured(env, llm, feedback=feedback, history=rejected)
        if not cand:
            res.notes.append(f"iter {i}: synthesis produced no decodable input")
            rejected.append(f"iter {i}: produced no decodable hex")
            continue

        # Oracle: does vuln crash at the hypothesized sink?
        adj = adjudicate_finding(verdict, vuln, cand, vector=vector, timeout=timeout)
        crashed = adj.status in ("CONFIRMED", "DIVERGENT")  # ASan fired somewhere
        crash_fn = adj.crash_function or ""
        at_sink = bool(crash_fn) and (
            func_matches(crash_fn, sink_hint) or adj.status == "CONFIRMED"
        )
        if crashed and at_sink:
            # Differential: fixed must run the SAME input clean.
            fixed_clean = True
            if fixed:
                fx = oracle.run_sanitizer(
                    fixed, cand, vector=vector, env=_ORACLE_ENV, timeout=timeout
                )
                fixed_clean = fx.valid and not fx.crashed
            if fixed_clean:
                res.confirmed = True
                res.crash_function = crash_fn
                res.crash_cwe = adj.crash_cwe
                res.matches_sink = True
                res.winning_input = cand
                res.reason = (
                    f"CONFIRMED (iter {i}): vuln crashes at {crash_fn} "
                    f"({adj.crash_cwe or 'ASan'}), fixed clean."
                )
                return res
            res.notes.append(f"iter {i}: vuln+fixed both crash at {crash_fn} — not differential")
        elif crashed:
            res.notes.append(f"iter {i}: crashed at {crash_fn} (not the sink) — {adj.status}")

        # Trace-guided feedback: did the candidate reach the SPECIFIC sink function?
        # (Coverage of a ubiquitous reader like sget4 is NOT proof — every format
        # parser calls it. We check the resolved sink function itself.)
        depth, last = _reached_depth(vuln, cand, res.path, timeout)
        res.reached_depth = max(res.reached_depth, depth)
        reached_sink = _covers_function(vuln, cand, sink_fn, timeout) if sink_fn else False
        if reached_sink:
            res.reached_sink = True
            if cand not in res.reaching_inputs:
                res.reaching_inputs.append(cand)  # a seed that dispatches to the parser
            # Routing SUCCEEDED to the sink but the read was in-bounds (no fault). The
            # remaining gap is the fault VALUE, not the envelope — push it harder.
            feedback = (
                f"ROUTING SUCCEEDED — the input reached the sink '{last}'. The read did "
                f"NOT go out of bounds. Keep the whole envelope IDENTICAL and make the "
                f"controlled field VIOLATE the constraint HARD: '{env.fault_constraint}'. "
                f"e.g. set the offset NEGATIVE (0xFFFFFFxx) or far beyond the buffer, or "
                f"shrink the length field so the offset exceeds it. Only change the fault "
                f"field(s); keep every magic/tag/length that got routing this far."
            )
        else:
            # The candidate did NOT execute the specific sink parser — the OUTER routing
            # is wrong (input is being parsed as a different format), even if a generic
            # reader was touched. Direct the LLM to fix the dispatch layers.
            feedback = (
                f"Your input did NOT reach the target parser '{sink_fn}' — it was parsed "
                f"as a different format/branch. The OUTER routing is wrong. Re-check the "
                f"layers that DISPATCH to '{sink_fn}': the exact container magic, the "
                f"correct tag id / type / count, consistent IFD offsets, and the inner "
                f"signature bytes that select this parser (per the envelope). Make the "
                f"format-selection fields byte-exact so parsing dispatches to '{sink_fn}'."
            )
        res.notes.append(f"iter {i}: reached_sink={reached_sink}; {feedback[:150]}")
        rejected.append(
            f"iter {i}: {len(cand)} bytes {cand.hex()[:_REJECTED_HEX_CHARS]}… — "
            f"reached_sink={reached_sink}, depth={depth}"
            + (f", last reached '{last}'" if last else "")
        )

    # HYBRID: synthesis got a candidate that DISPATCHES to the sink parser (the hard
    # reachability wall) but couldn't byte-place the fault field to trip the OOB. Hand
    # those reaching candidates to the directed-fuzz channel as seeds — coverage-guided
    # mutation flips the offset/length bytes to violate the bound (the easy last inch,
    # once you are at the right code). Composes the two channels: synthesis for
    # reachability, fuzzing for the fault trigger.
    # Structure-preserving field sweep FIRST (fast, deterministic, keeps the envelope
    # intact) — the reaching candidate is one field value from the fault.
    if res.reaching_inputs and hybrid_fuzz:
        for cand in res.reaching_inputs[:4]:
            hit = _field_sweep(vuln, fixed, cand, verdict, sink_fn, timeout)
            if hit:
                patched, adj = hit
                res.confirmed = True
                res.confirmed_via = "field-sweep"
                res.crash_function = adj.crash_function
                res.crash_cwe = adj.crash_cwe
                res.matches_sink = True
                res.winning_input = patched
                res.reason = (
                    f"CONFIRMED via field-sweep (synthesis reached parser, structure-"
                    f"preserving field patch tripped the fault at {adj.crash_function})."
                )
                res.notes.append(f"field-sweep confirmed on a {len(cand)}-byte reaching candidate")
                return res
        res.notes.append(f"field-sweep on {len(res.reaching_inputs)} reaching seeds: no OOB")

    if res.reaching_inputs and hybrid_fuzz:
        try:
            import tempfile

            from .directed_fuzz import confirm_by_directed_fuzz

            with tempfile.TemporaryDirectory() as td:
                for j, b in enumerate(res.reaching_inputs):
                    (Path(td) / f"reach_{j:03d}").write_bytes(b)
                dz = confirm_by_directed_fuzz(
                    verdict,
                    vuln,
                    seed_globs=[str(Path(td) / "*")],
                    fixed_binary=fixed,
                    budget_s=hybrid_budget_s,
                    jobs=hybrid_jobs,
                    value_profile=True,
                    timeout=timeout,
                )
            res.notes.append(
                f"hybrid directed-fuzz on {len(res.reaching_inputs)} reaching "
                f"seeds: {dz.reason[:120]}"
            )
            if dz.confirmed:
                res.confirmed = True
                res.confirmed_via = "hybrid-fuzz"
                res.crash_function = dz.crash_function
                res.crash_cwe = dz.crash_cwe
                res.matches_sink = dz.matches_hypothesis
                res.winning_input = dz.winning_input
                res.reason = (
                    "CONFIRMED via hybrid (synthesis reached parser, fuzz tripped fault): "
                    f"{dz.reason}"
                )
                return res
        except Exception as e:
            res.notes.append(f"hybrid step failed: {type(e).__name__}: {e}")

    reached = (
        "REACHED the sink parser but no OOB"
        if res.reached_sink
        else f"best reached {res.reached_depth}/{len(res.path)} path functions"
    )
    res.reason = f"not confirmed in {res.iterations} iters ({reached}); " + (
        "fault field not byte-placed; hybrid fuzz did not trip it either."
        if res.reached_sink
        else "the envelope routing was not fully satisfied."
    )
    return res


# --- runtime-guided refinement (gdb introspection feedback loop) -------------


@dataclass
class RuntimeGuidedResult:
    """Outcome of the runtime-introspection-driven refinement loop. ``confirmed`` is the
    only authority claim (differential oracle). ``reached_read`` records whether any
    candidate reached the vulnerable read; ``bail_line`` the deepest source line reached
    (where refinement stalled) when it did not."""

    confirmed: bool = False
    confirmed_via: str = ""  # "guided-patch" | "llm-refine"
    crash_function: str = ""
    crash_cwe: str = ""
    winning_input: bytes | None = None
    iterations: int = 0
    reached_func: bool = False
    reached_read: bool = False
    bail_line: int = 0
    field_offset: int = -1  # located controlling-field input offset
    reason: str = ""
    notes: list[str] = field(default_factory=list)


# Controlled-field target values, chosen so the DERIVED read offset lands in the ASan
# left-redzone (small negatives) or overflows (huge magnitudes) — the shapes that
# violate a one-sided low bound. The loop patches the LOCATED field with each until the
# oracle confirms, so we do not need to model the exact field->offset arithmetic.
_GUIDED_FIELD_VALUES: tuple[int, ...] = (
    -13,
    -16,
    -20,
    -9,
    -8,
    -7,
    -32,
    -64,
    -128,
    -256,
    -4096,
    0x7FFFFFFF,
    -0x80000000,
    0x40000000,
    -1,
)


def _patch_field(data: bytes, off: int, value: int, width: int, endian: str) -> bytes:
    if off < 0 or off + width > len(data):
        return data
    if endian not in {"little", "big"}:
        return data
    byteorder: Literal["little", "big"] = "little" if endian == "little" else "big"
    try:
        raw = (value & ((1 << (8 * width)) - 1)).to_bytes(width, byteorder)
    except (OverflowError, ValueError):
        return data
    return data[:off] + raw + data[off + width :]


def _confirms(
    verdict: Any, vuln: str, fixed: str | None, cand: bytes, sink_hint: str, timeout: float
) -> Any:
    """Differential oracle check: vuln crashes at the sink AND fixed runs clean. Returns
    the Adjudication on a confirmed differential, else None."""
    adj = adjudicate_finding(verdict, vuln, cand, vector="file", timeout=timeout)
    if adj.status not in ("CONFIRMED", "DIVERGENT"):
        return None
    crash_fn = adj.crash_function or ""
    # "at the sink" = the sink function is the crashing frame OR appears anywhere in the
    # crash backtrace. The leaf frame is usually the reader HELPER the sink calls
    # (e.g. libraw_sget4_static under parseAdobeRAFMakernote), so a strict leaf-only
    # match spuriously rejects a genuine sink crash — check the whole stack.
    frames = list(getattr(adj, "crash_frames", None) or [])
    at_sink = (
        adj.status == "CONFIRMED"
        or func_matches(crash_fn, sink_hint)
        or any(func_matches(fr, sink_hint) for fr in frames)
    )
    if not at_sink:
        return None
    if fixed:
        fx = oracle.run_sanitizer(fixed, cand, vector="file", env=_ORACLE_ENV, timeout=timeout)
        if not fx.valid or fx.crashed:
            return None  # not a differential — both crash
    return adj


def confirm_by_runtime_guided_synthesis(
    verdict: Any,
    vuln_binary: str | Path,
    start_candidate: bytes,
    sink_func: str,
    *,
    fixed_binary: str | Path | None = None,
    llm: Any = None,
    src_hint: str = "",
    sink_line: int | None = None,
    read_site_exprs: list[dict[str, Any]] | None = None,
    checkpoint_lines: list[int] | None = None,
    accessor_sym: str = "",
    fault_constraint: str = "",
    iterations: int = 6,
    timeout: float = 20.0,
    gdb_timeout: float = 90.0,
) -> RuntimeGuidedResult:
    """Drive a starting candidate to an oracle-confirmed crash using RUNTIME INTROSPECTION
    feedback — the capability that closes "entered the function" -> "reached the read" ->
    "tripped the fault".

    Each round: (1) oracle-check the current candidate; (2) run the gdb probe to observe
    reachability + the live read-site state (offset, buffer bounds) + the input byte that
    controls the offset (provenance); (3) if the probe located the controlling field and
    the read is reachable, deterministically patch that field with bound-violating values
    and oracle-check each (the near-certain winner — targeted, not blind); (4) otherwise
    hand the concrete runtime feedback to the synthesis LLM to refine the candidate
    (fix the inner check where it bailed, or place the fault field). Iterates until the
    differential oracle confirms or the budget expires.

    PoV-is-truth: only :func:`_confirms` (vuln crashes at sink AND fixed clean) sets
    ``confirmed``. Target-agnostic: only ``sink_func`` (+ optional probe hints) is
    target-specific."""
    from . import runtime_probe as rp

    vuln = str(vuln_binary)
    fixed = str(fixed_binary) if fixed_binary else None
    sink_hint = getattr(verdict, "sink", "") or sink_func
    res = RuntimeGuidedResult()
    cand = bytes(start_candidate)
    # ACCUMULATED refinement history — same reason as the synthesis loop above: the
    # refiner saw only the CURRENT bytes plus the CURRENT instruction, so a candidate
    # the probe already measured as bailing was invisible and could be walked back to.
    refined: list[str] = []

    if not isinstance(current_executor(), LocalExecutor):
        res.reason = (
            "runtime-guided synthesis requires an explicitly authorized local GDB "
            "runner; the selected executor cannot launch the inferior safely"
        )
        return res

    for i in range(1, iterations + 1):
        res.iterations = i

        # (1) is the current candidate already a confirmed differential?
        adj = _confirms(verdict, vuln, fixed, cand, sink_hint, timeout)
        if adj is not None:
            res.confirmed = True
            res.confirmed_via = res.confirmed_via or "start"
            res.crash_function = adj.crash_function
            res.crash_cwe = adj.crash_cwe
            res.winning_input = cand
            res.reason = f"CONFIRMED (iter {i}): vuln crashes at {adj.crash_function}, fixed clean."
            return res

        # (2) runtime probe: how far did it get, and what is the live fault state?
        probe = rp.probe(
            vuln,
            cand,
            sink_func,
            src_hint=src_hint,
            sink_line=sink_line,
            read_site_exprs=read_site_exprs,
            checkpoint_lines=checkpoint_lines,
            accessor_sym=accessor_sym,
            timeout=gdb_timeout,
        )
        res.reached_func = res.reached_func or probe.reached_func
        res.reached_read = res.reached_read or bool(probe.reads)
        res.bail_line = max(res.bail_line, probe.max_line)
        if probe.error:
            res.notes.append(f"iter {i}: probe error: {probe.error}")

        # (3) deterministic runtime-guided field patch — the targeted winner.
        if probe.provenance and probe.reads:
            prov = probe.provenance[0]
            res.field_offset = prov.input_offset
            for value in _GUIDED_FIELD_VALUES:
                patched = _patch_field(cand, prov.input_offset, value, prov.width, prov.endian)
                if patched == cand:
                    continue
                adj = _confirms(verdict, vuln, fixed, patched, sink_hint, timeout)
                if adj is not None:
                    res.confirmed = True
                    res.confirmed_via = "guided-patch"
                    res.crash_function = adj.crash_function
                    res.crash_cwe = adj.crash_cwe
                    res.winning_input = patched
                    res.reason = (
                        f"CONFIRMED via runtime-guided patch (iter {i}): the probe located "
                        f"the offset-controlling field at input byte {prov.input_offset} "
                        f"({prov.width}B {prov.endian}); setting it to {value} drove the "
                        f"read offset out of bounds -> crash at {adj.crash_function}, fixed clean."
                    )
                    return res
            res.notes.append(
                f"iter {i}: field@{prov.input_offset} patched with "
                f"{len(_GUIDED_FIELD_VALUES)} values; none confirmed a differential"
            )

        # (4) LLM refinement from the concrete runtime feedback.
        instr = rp.feedback_instruction(
            probe,
            sink_func=sink_func,
            fault_constraint=fault_constraint,
            input_len=len(cand),
        )
        res.notes.append(
            f"iter {i}: reached_func={probe.reached_func} "
            f"max_line={probe.max_line} reads={len(probe.reads)} :: {instr[:140]}"
        )
        if llm is not None:
            new = _llm_refine_bytes(llm, cand, instr, refined)
            refined.append(
                f"iter {i}: {len(cand)} bytes {cand.hex()[:_REJECTED_HEX_CHARS]}… — "
                f"reached_func={probe.reached_func}, bailed at line {probe.max_line}"
            )
            if new and new != cand:
                cand = new
                res.notes.append(f"iter {i}: LLM produced a refined {len(new)}-byte candidate")
                continue
        # no LLM / no change -> nothing more to try deterministically; stop.
        if llm is None and not (probe.provenance and probe.reads):
            res.reason = (
                f"not confirmed: reached_func={probe.reached_func}, deepest line "
                f"{probe.max_line}; the probe did not locate a controllable field "
                f"(no LLM available to refine the envelope past the bail point)."
            )
            return res

    reached = (
        "reached the vulnerable read but no bound-violating field value confirmed"
        if res.reached_read
        else f"entered={res.reached_func}, stalled at source line {res.bail_line}"
    )
    res.reason = f"not confirmed in {res.iterations} iters ({reached})."
    return res


_REFINE_SYSTEM = """You refine a byte-exact binary parser input using RUNTIME feedback
from a debugger. You are given the current input (hex) and a concrete instruction about
where execution went — which inner check rejected it, or which input byte controls the
out-of-bounds offset. Apply the MINIMAL change the instruction asks for and return the
full refined input as hex. Keep every byte that the instruction says got routing this
far; change only what it tells you to."""

_REFINE_SCHEMA = {
    "type": "object",
    "properties": {"hex": {"type": "string"}, "rationale": {"type": "string"}},
    "required": ["hex"],
}


def _llm_refine_bytes(
    llm: Any, cand: bytes, instruction: str, history: list[str] | None = None
) -> bytes | None:
    """Ask the LLM to apply the runtime instruction to the current input and return the
    refined bytes. Returns None on any failure (loop then falls back).

    ``history`` is the same accumulation as ``synthesize_structured``: every earlier
    refinement and how far it got, so the loop cannot walk a candidate back to a byte
    pattern the probe already measured as bailing at the same line."""
    prompt = (
        f"CURRENT INPUT (hex, {len(cand)} bytes):\n{cand.hex()}\n\n"
        f"RUNTIME FEEDBACK:\n{instruction}\n"
        f"{_rejected_text(history or [])}"
        "\nReturn the full refined input as hex."
    )
    try:
        raw = llm.complete_json(_REFINE_SYSTEM, prompt, _REFINE_SCHEMA)
    except Exception:
        return None
    return _decode_hex(str(raw.get("hex", "")))

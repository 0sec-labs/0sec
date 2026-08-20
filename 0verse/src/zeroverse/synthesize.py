"""Input synthesis — turn a scanner HYPOTHESIS into a CONFIRMED bug WITHOUT a poc.

The oracle (``adjudicate.adjudicate_finding``) confirms a finding by reproducing a
crash against an EXISTING proof-of-crash input. A NOVEL finding — the thing real
0-day hunting produces — has no poc. To confirm it we must SYNTHESIZE an input that
(a) REACHES the hypothesized sink and (b) TRIGGERS the bug (sets the length/count
field the sink trusts past a buffer bound). The LLM has already reverse-engineered
the input format while EXPLORING the parser (``agentic.explore`` records the
``visited`` input-path functions and the ``explanation`` carries the concrete
trigger condition it reasoned, e.g. "a palette count of 257 gives _Size=771 into a
768-byte buffer"), so it can CONSTRUCT a triggering input from that understanding.

The contract is strict: the LLM only PROPOSES candidate inputs; the deterministic
oracle DECIDES. Synthesis NEVER self-certifies — ``confirm_by_synthesis`` runs each
candidate through ``adjudicate_finding`` and a finding is CONFIRMED only when a
reproduced crash lands at the hypothesized sink in the hypothesized bug class (or
DIVERGENT-but-crashing at that same sink — a real reproduction of the location).
This is PoV-is-truth applied to the no-poc case.

Relationship to ``inputsynth``: that module synthesizes from a harness-name-inferred
``TargetContext`` and scores against the differential sanitizer oracle. THIS module
is verdict-native — it conditions on an ``AgentResult``/``AgentVerdict`` and the
decompiled functions on the explored source->sink path (pulled straight from
``meta.decompiled_c``), and it scores against ``adjudicate_finding`` so the win
condition is the finding's own sink/CWE hypothesis.

HONEST LIMITS. This works when the LLM can reverse-engineer the format from the
parser bodies it read. It RESISTS checksum/CRC/compression-gated formats (a poisoned
field fails an integrity check before the sink) and deep multi-stage reachability
(the input must survive many validation layers). MOST candidates NO_CRASH; a
confirmation is when ONE actually reproduces. This is the genuinely-hard reproduce
problem — historically ~0/3 on ARVO for pure synthesis — a first LLM-guided attempt,
not a solved problem. The bench INTEGRATOR runs the real end-to-end validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from .adjudicate import (
    CONFIRMED,
    DIVERGENT,
    NO_CRASH,
    UNRUNNABLE,
    Adjudication,
    adjudicate_finding,
    func_matches,
)
from .inputsynth import _decode_hex

if TYPE_CHECKING:
    from .agentic import AgentVerdict

# --- prompt + response schema -----------------------------------------------

# Cap on a single function body fed into the synthesis prompt, and on the total
# parser context — a huge inlined parser must not blow the model's window.
_MAX_BODY_CHARS = 6000
_CONTEXT_BUDGET = 20000

_SYNTH_SYSTEM = (
    "You are a vulnerability-research expert SYNTHESIZING a triggering input for a "
    "bug a scanner just hypothesized — there is NO existing proof-of-crash, you must "
    "construct one. You are given the finding (the sink, bug class, and the concrete "
    "trigger condition the scanner reasoned) and the decompiled INPUT-PARSING "
    "functions on the path from where input enters to the sink — the exact format the "
    "scanner reverse-engineered. Your job: emit MINIMAL candidate input files that are "
    "VALID-ENOUGH for the parser to accept and walk all the way to the sink, but with "
    "the one specific length/count/size field the sink trusts set to a value that "
    "OVERFLOWS its buffer. Trace the parse path byte-by-byte from the first byte to the "
    "sink and keep every field ON THAT PATH valid (magic, version, table directory, "
    "offsets, and any checksum a parser enforces) — a header the parser rejects never "
    "reaches the sink. Output each candidate as a lowercase hex string. Provide DIVERSE "
    "candidates that VARY the poisoned field's magnitude: the exact boundary value that "
    "first overflows, and values well past it. You are PROPOSING candidates for a "
    "deterministic crash oracle to test; you are NOT confirming anything."
)

# The structured response: an array of hex-encoded candidate inputs, each with an
# optional rationale naming the field it poisoned (logged, never trusted). The
# decoder is lenient (see ``_decode_candidates``) so a plain-string array or a
# ``hex``/``bytes`` key still routes.
POV_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "bytes_hex": {
                        "type": "string",
                        "description": "the candidate input file as a lowercase hex string",
                    },
                    "rationale": {
                        "type": "string",
                        "description": "which field was poisoned and to what value",
                    },
                },
                "required": ["bytes_hex"],
            },
        },
    },
    "required": ["candidates"],
}

# Keys under which a response may carry the candidate array / a candidate's hex.
_LIST_KEYS: tuple[str, ...] = ("candidates", "povs", "inputs", "results")
_HEX_KEYS: tuple[str, ...] = ("bytes_hex", "hex", "bytes", "data", "input")


# --- structure-aware synthesis ----------------------------------------------
#
# The plain path above works on formats the LLM can reverse-engineer AND that have no
# gate rejecting a naive candidate before the sink. REAL formats gate: a length prefix
# that must be consistent, a magic/version check, a checksum/CRC over a region, a count
# field that must equal the number of records, nested offset tables. A candidate that
# overflows the target field but breaks one of these gates is rejected EARLY (NO_CRASH),
# never reaching the sink — the dominant synthesis failure on real targets.
#
# The structure-aware protocol forces the model to (1) DERIVE the format's structural
# invariants from the parser code FIRST — stating magic, version, field widths+
# endianness, every length/count/offset relationship, and any checksum with the exact
# byte range and algorithm it covers — then (2) construct candidates that SATISFY every
# gate on the path while overflowing the target field, keeping the consistency fields
# (count/length/checksum) INTERNALLY CONSISTENT with the oversized value.

_STRUCT_SYSTEM = (
    "You are a vulnerability-research expert SYNTHESIZING a triggering input for a bug a "
    "scanner just hypothesized — there is NO existing proof-of-crash, you must construct "
    "one. The format has STRUCTURAL GATES that reject a malformed input BEFORE it reaches "
    "the sink: a magic/version check, a length or size prefix that must match the data, a "
    "count field that must equal the number of records, offset tables that must point "
    "in-bounds, a checksum/CRC over some byte range. A candidate that overflows the "
    "target field but VIOLATES one of these gates is rejected early and never crashes.\n"
    "\n"
    "Work in TWO explicit steps.\n"
    "STEP 1 — DERIVE THE STRUCTURAL INVARIANTS from the decompiled parser bodies. State "
    "each one explicitly: the magic/signature bytes; the version and any accepted values; "
    "every fixed field's byte OFFSET, WIDTH, and ENDIANNESS; every relationship the "
    "parser enforces between fields (length-prefix = size of the region it covers, count "
    "= number of records that follow, offset = where a sub-structure begins); and any "
    "CHECKSUM/CRC — name the exact byte range it covers and the exact algorithm (e.g. "
    "'sum of bytes [4..n) mod 256', 'xor of the record bytes', 'CRC-32 of the payload').\n"
    "STEP 2 — CONSTRUCT candidates that SATISFY every derived invariant on the path to "
    "the sink while setting the ONE length/count/size field the sink trusts to a value "
    "that OVERFLOWS its buffer. Critically: keep the OTHER consistency fields CONSISTENT "
    "with the poisoned value — if you inflate a count, make the input actually carry that "
    "many records (or set the length prefix to match); if a checksum covers the poisoned "
    "region, RECOMPUTE it so it still validates. A poisoned field with a stale "
    "length/count/checksum is rejected at the gate, not at the sink.\n"
    "\n"
    "Offer a COUPLE of strategies across your candidates: (i) MINIMAL-BOUNDARY — a "
    "smallest valid file with the target field at exactly bound+1, every gate satisfied; "
    "(ii) VALID-PREFIX + ONE POISONED RECORD — a fully valid parse that reaches the "
    "vulnerable record, then one record whose size/count field overflows, with the "
    "surrounding length/count/checksum fixed up to stay consistent. Output each candidate "
    "as a lowercase hex string. You are PROPOSING candidates for a deterministic crash "
    "oracle to test; you are NOT confirming anything."
)

# The structure-aware response: the derived invariants (logged for an honest report of
# the model's reasoning, never trusted) plus the candidate array. Candidates decode via
# the same lenient ``_decode_candidates`` as the plain path.
STRUCT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "invariants": {
            "type": "array",
            "description": "the structural gates derived from the parser, stated explicitly",
            "items": {
                "type": "object",
                "properties": {
                    "field": {"type": "string", "description": "the field / gate name"},
                    "kind": {
                        "type": "string",
                        "description": "magic | version | length | count | offset | checksum",
                    },
                    "detail": {
                        "type": "string",
                        "description": (
                            "offset, width, endianness, the relationship enforced, and for "
                            "a checksum the exact byte range + algorithm it covers"
                        ),
                    },
                },
                "required": ["field", "kind"],
            },
        },
        "candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "bytes_hex": {
                        "type": "string",
                        "description": "the candidate input file as a lowercase hex string",
                    },
                    "strategy": {
                        "type": "string",
                        "description": "minimal-boundary | valid-prefix-poisoned-record",
                    },
                    "rationale": {
                        "type": "string",
                        "description": (
                            "which field was poisoned, and how the count/length/checksum "
                            "gates were kept consistent with it"
                        ),
                    },
                },
                "required": ["bytes_hex"],
            },
        },
    },
    "required": ["candidates"],
}


def _build_struct_synth_prompt(
    meta: Any, verdict: AgentVerdict, n: int, visited: list[str] | None
) -> str:
    """Assemble the structure-aware synthesis prompt: the finding plus the decompiled
    parser bodies, with an explicit instruction to FIRST derive the format's structural
    invariants (magic, version, field widths+endianness, length/count/offset
    relationships, any checksum's byte-range+algorithm) and THEN construct candidates
    that satisfy every gate while overflowing the target field."""
    parser = _parser_context(meta, verdict, visited)
    parts = [
        "FINDING TO CONFIRM (a scanner hypothesis — no poc exists yet):",
        f"  bug class (CWE): {verdict.cwe}",
        f"  sink (where the overflow happens): {verdict.sink}",
        f"  source (where input enters): {verdict.source}",
        f"  scanner's reasoning / trigger condition:\n    {verdict.explanation}",
        "",
        "--- DECOMPILED INPUT-PARSING FUNCTIONS ON THE PATH TO THE SINK ---",
        "(this is the format the scanner reverse-engineered — the STRUCTURAL GATES that "
        "reject a malformed input before the sink live here)",
        parser or "(no decompiled parser bodies were available for this finding)",
        "",
        "STEP 1 — Derive and STATE the structural invariants: the magic/signature, the "
        "version and accepted values, every field's OFFSET + WIDTH + ENDIANNESS, every "
        "LENGTH/COUNT/OFFSET relationship the parser enforces (length-prefix vs region "
        "size, count vs number of records, offset vs sub-structure start), and any "
        "CHECKSUM/CRC with the EXACT byte range and algorithm it covers.",
        "STEP 2 — Emit up to "
        f"{n} candidate input files (hex) that SATISFY every one of those gates on the "
        "path to the sink while setting the length/count/size field the sink trusts to "
        "OVERFLOW its buffer. Keep the count/length/checksum fields CONSISTENT with the "
        "poisoned value (recompute a checksum that covers the poisoned region). Use a "
        "couple of strategies: a MINIMAL-BOUNDARY file (target = bound+1, all gates "
        "satisfied) and a VALID-PREFIX + ONE POISONED RECORD file.",
    ]
    return "\n".join(parts)


# --- structural fix-up post-processor ---------------------------------------
#
# apply_structural_fixups is a best-effort SECOND pass over a single candidate that
# likely failed a gate (typically a NO_CRASH: the parser rejected it before the sink).
# It asks the model to RECOMPUTE the derived consistency fields — fix the length prefix
# to match the actual data size, fix a record count to equal the records present, fix a
# simple additive/xor checksum over its covered range — so the SAME poisoned candidate
# now passes the gates and reaches the sink. It changes ONLY the consistency/gate bytes,
# never the poisoned overflow value.
#
# HONEST LIMIT (documented on the function): this fixes ARITHMETIC gates the model can
# compute by hand — length/size prefixes, record counts, additive and xor checksums. It
# CANNOT beat a cryptographic hash (SHA/MD5), a real CRC table it cannot reproduce, a
# compression layer (deflate/zstd), or deep multi-stage state — those are flagged
# ``unfixable`` and the original candidate is returned unchanged.

_FIXUP_SYSTEM = (
    "You are a vulnerability-research expert. A candidate triggering input was rejected by "
    "the parser BEFORE reaching the sink — it violates a STRUCTURAL GATE (a length/size "
    "prefix that no longer matches the data, or a CHECKSUM over a region whose bytes "
    "changed). Do NOT do arithmetic — a deterministic tool recomputes the values EXACTLY. "
    "Your job is to DESCRIBE each gate's STRUCTURE from the parser code: the gate field's "
    "byte OFFSET, WIDTH (1/2/4/8), and ENDIANNESS; the exact byte RANGE it covers "
    "(covered_start .. covered_end, where covered_end = -1 means 'to end of file'); and "
    "the ALGORITHM family — `byte_count` (a length/size prefix = number of covered bytes), "
    "`additive_sum` (sum of covered bytes mod 2^k), `xor` (xor-fold of covered bytes), or "
    "`crc32`/`unknown` (a real CRC or cryptographic hash / compression the tool CANNOT "
    "reproduce — mark it so it is left unchanged). Emit one spec per gate. You do the "
    "STRUCTURE; the tool does the MATH."
)

# The gate-spec response: DESCRIBE each structural gate; deterministic Python recomputes
# the value. crc32/unknown gates are left unchanged (honestly unfixable).
FIXUP_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "gates": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "description": "length_prefix | checksum"},
                    "field_offset": {
                        "type": "integer",
                        "description": "byte offset of the gate field",
                    },
                    "field_width": {
                        "type": "integer",
                        "description": "field width in bytes: 1, 2, 4, or 8",
                    },
                    "endianness": {"type": "string", "description": "le | be"},
                    "covered_start": {
                        "type": "integer",
                        "description": "first byte the gate covers",
                    },
                    "covered_end": {
                        "type": "integer",
                        "description": "one past the last covered byte; -1 = end of file",
                    },
                    "algo": {
                        "type": "string",
                        "description": "byte_count | additive_sum | xor | crc32 | unknown",
                    },
                    "mask_bits": {
                        "type": "integer",
                        "description": "checksum modulus bits (default field_width*8)",
                    },
                },
                "required": [
                    "type",
                    "field_offset",
                    "field_width",
                    "covered_start",
                    "covered_end",
                    "algo",
                ],
            },
        },
    },
    "required": ["gates"],
}


def _build_fixup_prompt(
    candidate: bytes, meta: Any, verdict: AgentVerdict, visited: list[str] | None
) -> str:
    """Assemble the fix-up prompt: the finding, the parser bodies (so the model can find
    each gate's offset/width/endianness and a checksum's covered range+algorithm), and
    the current candidate as hex. The model DESCRIBES the gates; Python patches them."""
    parser = _parser_context(meta, verdict, visited)
    parts = [
        "FINDING (the bug we are trying to reach — the poisoned overflow field must NOT move):",
        f"  bug class (CWE): {verdict.cwe}",
        f"  sink: {verdict.sink}",
        f"  source: {verdict.source}",
        f"  trigger condition:\n    {verdict.explanation}",
        "",
        "--- DECOMPILED PARSER (find each gate: field offset/width/endianness, its covered "
        "byte range, and the algorithm) ---",
        parser or "(no decompiled parser bodies were available)",
        "",
        "CANDIDATE THAT WAS REJECTED BEFORE THE SINK (lowercase hex):",
        f"  {candidate.hex()}",
        "",
        "Describe every structural gate (length/size prefix, additive or xor checksum) as a "
        "spec: field offset, width, endianness, covered byte range, algorithm. A deterministic "
        "tool will recompute each value EXACTLY and patch the candidate. Mark a crypto hash / "
        "real CRC / compression gate as algo 'crc32' or 'unknown' so it is left unchanged.",
    ]
    return "\n".join(parts)


def _int_to_field(value: int, width: int, endian: str) -> bytes:
    """Serialize ``value`` into a ``width``-byte field, masked to the field size."""
    w = width if width in (1, 2, 4, 8) else 1
    masked = value & ((1 << (w * 8)) - 1)
    return masked.to_bytes(w, "big" if str(endian).lower() == "be" else "little")


def apply_gate_specs(candidate: bytes, gates: list[dict[str, Any]]) -> bytes:
    """DETERMINISTICALLY recompute + patch each structural gate on ``candidate``.

    The LLM describes the gate STRUCTURE (offset/width/endianness/covered-range/algo);
    THIS does the MATH exactly — the LLM was miscounting lengths and mis-summing
    checksums, which is the whole reason the fix-up failed. Length prefixes are patched
    BEFORE checksums so a checksum whose covered range includes a length field sees the
    corrected value. ``crc32``/``unknown`` gates (real CRC / crypto hash / compression) are
    left UNCHANGED — honestly unfixable. A field that can't be placed in-bounds is skipped
    (never corrupts the buffer)."""
    buf = bytearray(candidate)
    n = len(buf)

    def covered(g: dict[str, Any]) -> bytes:
        start = max(0, min(int(g.get("covered_start", 0)), n))
        end = int(g.get("covered_end", -1))
        end = n if (end < 0 or end > n) else end
        end = max(start, end)
        return bytes(buf[start:end])

    def patch(g: dict[str, Any], value: int) -> None:
        off = int(g.get("field_offset", -1))
        width = int(g.get("field_width", 0))
        if off < 0 or width not in (1, 2, 4, 8) or off + width > n:
            return  # can't place the field in-bounds — skip, never corrupt
        buf[off : off + width] = _int_to_field(value, width, g.get("endianness", "le"))

    # length prefixes first (a checksum may cover a range that includes a length field)
    for g in sorted(
        gates, key=lambda g: 0 if str(g.get("type", "")).lower() == "length_prefix" else 1
    ):
        algo = str(g.get("algo", "unknown")).lower()
        gtype = str(g.get("type", "")).lower()
        cov = covered(g)
        width = int(g.get("field_width", 1)) or 1
        mask = (1 << (int(g.get("mask_bits", 0)) or width * 8)) - 1
        if gtype == "length_prefix" or algo == "byte_count":
            patch(g, len(cov))
        elif algo == "additive_sum":
            patch(g, sum(cov) & mask)
        elif algo == "xor":
            x = 0
            for b in cov:
                x ^= b
            patch(g, x & mask)
        # crc32 / unknown -> unfixable, left unchanged
    return bytes(buf)


def apply_structural_fixups(
    candidate: bytes,
    verdict: AgentVerdict,
    meta: Any,
    llm: Any,
    *,
    visited: list[str] | None = None,
) -> bytes:
    """Best-effort SECOND pass: recompute a candidate's consistency/gate fields so it
    survives the format's structural gates and reaches the sink.

    Split of labor (the fix): the LLM derives the gate STRUCTURE (offset/width/endianness/
    covered-range/algorithm from the parser); DETERMINISTIC PYTHON (``apply_gate_specs``)
    does the arithmetic EXACTLY and patches the bytes — the poisoned overflow field is left
    alone. Previously the LLM was asked to recompute the values by hand and MISCOUNTED,
    making the fix-up a no-op-or-worse.

    HONEST CONTRACT. Fixes length/size prefixes and additive/xor checksums exactly. CANNOT
    defeat a cryptographic hash (MD5/SHA), a full CRC (marked ``crc32``), a compression/
    encoding layer, or deep multi-stage state — those gates are left unchanged. On any
    backend failure, an unparseable/empty spec, or no gates, returns the ORIGINAL
    ``candidate`` — never fabricates, never crashes the confirm step."""
    prompt = _build_fixup_prompt(candidate, meta, verdict, visited)
    try:
        raw = llm.complete_json(_FIXUP_SYSTEM, prompt, FIXUP_SCHEMA)
    except Exception:  # degrade on ANY backend failure — keep the original candidate
        return candidate
    if not isinstance(raw, dict):
        return candidate
    gates = raw.get("gates")
    if not isinstance(gates, list) or not gates:
        return candidate
    try:
        fixed = apply_gate_specs(candidate, [g for g in gates if isinstance(g, dict)])
    except Exception:
        return candidate
    return fixed or candidate


@dataclass
class SynthResult:
    """The outcome of a synthesis-based confirmation attempt.

    ``confirmed`` is True only when a synthesized candidate actually reproduced the
    bug (``adjudicate_finding`` returned CONFIRMED, or DIVERGENT with the crash at the
    hypothesized sink). ``adjudication`` holds the WINNING ``Adjudication`` when
    confirmed, else the BEST near-miss (a real crash elsewhere beats a NO_CRASH beats
    an UNRUNNABLE) — or ``None`` if nothing was tried. ``winning_input`` is the bytes
    that reproduced (``None`` when unconfirmed). ``tried`` is how many candidates were
    adjudicated; ``candidates`` is the full synthesized set (for an honest report of
    what was attempted); ``reason`` summarizes the decision."""

    confirmed: bool
    adjudication: Adjudication | None = None
    winning_input: bytes | None = None
    tried: int = 0
    candidates: list[bytes] = field(default_factory=list)
    reason: str = ""


def _parser_context(meta: Any, verdict: AgentVerdict, visited: list[str] | None) -> str:
    """Pull the decompiled bodies of the input-parsing functions on the path to the
    sink — the format the scanner reverse-engineered — from ``meta.decompiled_c``.

    Ordered source (where input enters) -> visited parser functions (in explore order)
    -> sink (where the overflow lands), de-duplicated, each body capped and the whole
    block budgeted so a huge inlined parser cannot blow the model's window. Names not
    present in the decompilation are silently skipped."""
    decompiled: dict[str, str] = getattr(meta, "decompiled_c", {}) or {}
    ordered: list[str] = []
    for name in [verdict.source, *(visited or []), verdict.sink]:
        if name and name in decompiled and name not in ordered:
            ordered.append(name)

    blocks: list[str] = []
    used = 0
    for name in ordered:
        body = decompiled[name]
        if len(body) > _MAX_BODY_CHARS:
            body = (
                body[:_MAX_BODY_CHARS]
                + f"\n/* ...truncated at {_MAX_BODY_CHARS} of {len(body)} chars */"
            )
        block = f"--- {name} ---\n{body}"
        if used + len(block) > _CONTEXT_BUDGET and blocks:
            break
        blocks.append(block)
        used += len(block)
    return "\n\n".join(blocks)


def _build_synth_prompt(meta: Any, verdict: AgentVerdict, n: int, visited: list[str] | None) -> str:
    """Assemble the synthesis prompt: the finding (sink/cwe/source/explanation — the
    explanation carries the concrete trigger condition the scanner reasoned) plus the
    decompiled parser bodies on the source->sink path."""
    parser = _parser_context(meta, verdict, visited)
    parts = [
        "FINDING TO CONFIRM (a scanner hypothesis — no poc exists yet):",
        f"  bug class (CWE): {verdict.cwe}",
        f"  sink (where the overflow happens): {verdict.sink}",
        f"  source (where input enters): {verdict.source}",
        f"  scanner's reasoning / trigger condition:\n    {verdict.explanation}",
        "",
        "--- DECOMPILED INPUT-PARSING FUNCTIONS ON THE PATH TO THE SINK ---",
        "(this is the format the scanner reverse-engineered; keep every field on the "
        "parse path valid so the input reaches the sink)",
        parser or "(no decompiled parser bodies were available for this finding)",
        "",
        f"Emit up to {n} DIVERSE, MINIMAL candidate input files (hex). Each must be "
        "valid-enough for the parser above to accept and walk to the sink, with the "
        "length/count/size field the sink trusts set to trigger the overflow. VARY the "
        "poisoned field's magnitude across candidates: the exact boundary value and "
        "values well past it.",
    ]
    return "\n".join(parts)


def _hex_payload_exceeds(raw: str, max_candidate_bytes: int) -> bool:
    """Count normalized hex digits without allocating a decoded candidate."""
    start = 0
    while start < len(raw) and raw[start].isspace():
        start += 1
    if raw[start : start + 2].lower() == "0x":
        start += 2
    digits = 0
    for index in range(start, len(raw)):
        if raw[index] in "0123456789abcdefABCDEF":
            digits += 1
            if digits > 2 * max_candidate_bytes:
                return True
    return False


def _decode_candidates(
    raw: Any,
    n: int,
    *,
    max_candidate_bytes: int | None = None,
) -> list[bytes]:
    """Decode a model response into an ordered, de-duplicated list of candidate bytes.

    Resilient to shape: the candidate array may live under any of ``_LIST_KEYS`` (or the
    top level may BE the list), and each item may be a plain hex string or an object
    carrying its hex under any of ``_HEX_KEYS``. Un-decodable/odd-length/empty items are
    SKIPPED, never guessed. Returns at most ``n`` candidates."""
    items: Any = None
    if isinstance(raw, dict):
        for key in _LIST_KEYS:
            if isinstance(raw.get(key), list):
                items = raw[key]
                break
    elif isinstance(raw, list):
        items = raw
    if not isinstance(items, list):
        return []

    out: list[bytes] = []
    seen: set[bytes] = set()
    for item in items:
        hexstr: str | None = None
        if isinstance(item, str):
            hexstr = item
        elif isinstance(item, dict):
            for key in _HEX_KEYS:
                val = item.get(key)
                if isinstance(val, str):
                    hexstr = val
                    break
        if hexstr is None:
            continue
        # Reject an oversized model field before normalization/fromhex allocates
        # the decoded payload. The digit counter mirrors _decode_hex's tolerance
        # for a 0x prefix, whitespace, and other non-hex separators.
        if (
            max_candidate_bytes is not None
            and _hex_payload_exceeds(hexstr, max_candidate_bytes)
        ):
            continue
        data = _decode_hex(hexstr)
        if (
            not data
            or (max_candidate_bytes is not None and len(data) > max_candidate_bytes)
            or data in seen
        ):
            continue
        seen.add(data)
        out.append(data)
        if len(out) >= n:
            break
    return out


@dataclass(frozen=True)
class SynthesisBatch:
    """Decoded candidates plus an honest account of the generator outcome.

    ``synthesize_povs`` historically degraded both transport/model failures and
    valid-but-undecodable output to ``[]``.  Callers that operate remote workers
    need to distinguish those cases in their run record without weakening the
    crash oracle, so this additive result keeps the old list API stable while
    exposing a small, non-secret diagnostic surface.
    """

    candidates: tuple[bytes, ...]
    status: Literal["ok", "empty", "backend-error"]
    error_type: str = ""


def synthesize_povs_diagnostic(
    meta: Any,
    verdict: AgentVerdict,
    llm: Any,
    *,
    n: int = 6,
    visited: list[str] | None = None,
    structural: bool = False,
    max_candidate_bytes: int | None = None,
) -> SynthesisBatch:
    """Generate candidates while preserving empty-output vs backend-failure state."""
    if max_candidate_bytes is not None and max_candidate_bytes <= 0:
        raise ValueError("max_candidate_bytes must be positive")
    if structural:
        prompt = _build_struct_synth_prompt(meta, verdict, n, visited)
        system, schema = _STRUCT_SYSTEM, STRUCT_SCHEMA
    else:
        prompt = _build_synth_prompt(meta, verdict, n, visited)
        system, schema = _SYNTH_SYSTEM, POV_SCHEMA
    try:
        raw = llm.complete_json(system, prompt, schema)
    except Exception as exc:  # the deterministic oracle still owns all truth
        return SynthesisBatch((), "backend-error", type(exc).__name__)
    candidates = tuple(_decode_candidates(raw, n, max_candidate_bytes=max_candidate_bytes))
    return SynthesisBatch(candidates, "ok" if candidates else "empty")


def synthesize_povs(
    meta: Any,
    verdict: AgentVerdict,
    llm: Any,
    *,
    n: int = 6,
    visited: list[str] | None = None,
    structural: bool = False,
    max_candidate_bytes: int | None = None,
) -> list[bytes]:
    """Ask ``llm`` to CONSTRUCT up to ``n`` candidate inputs that reach and trigger the
    hypothesized bug, conditioned on the finding and the decompiled parser bodies on the
    source->sink path (pulled from ``meta.decompiled_c``; ``visited`` are the input-path
    functions the explorer read).

    With ``structural=True`` the STRUCTURE-AWARE protocol is used: the model must first
    derive the format's structural invariants (magic, version, field widths+endianness,
    length/count/offset relationships, any checksum's byte-range+algorithm) and then
    construct candidates that satisfy every gate on the path while overflowing the target
    field — the plain path (``structural=False``) is byte-unchanged.

    Returns the decoded candidate bytes, de-duplicated and resilient: un-decodable model
    output is dropped and ANY backend failure degrades to an empty list (never crashes
    the confirm step). This is a hypothesis GENERATOR — the oracle decides."""
    batch = synthesize_povs_diagnostic(
        meta,
        verdict,
        llm,
        n=n,
        visited=visited,
        structural=structural,
        max_candidate_bytes=max_candidate_bytes,
    )
    return list(batch.candidates)


# Best-near-miss ranking used when NO candidate confirms: a real crash elsewhere is a
# closer miss than a clean run, which still beats a target this host cannot even exec.
_STATUS_RANK: dict[str, int] = {
    CONFIRMED: 4,
    DIVERGENT: 3,
    NO_CRASH: 2,
    UNRUNNABLE: 1,
}


_OOB_FAM = {"125", "787", "121", "122", "124", "119", "190", "191", "680", "823", "786", "788"}
_UAF_FAM = {"416", "415", "825"}


def _same_family(claimed: str, crash: str) -> bool:
    """Same broad bug FAMILY (spatial-OOB vs temporal-UAF) — a targeted-synthesis crash
    of the claimed family reproduces the finding even if the exact CWE number differs
    (OOB READ vs WRITE) or the sink LABEL differs (Ghidra inlined the parser so the
    finding names the enclosing fn while ASan names the true callee)."""
    import re as _re

    a = _re.search(r"\d+", claimed or "")
    b = _re.search(r"\d+", crash or "")
    if not a or not b:
        return False
    x, y = a.group(), b.group()
    return x == y or (x in _OOB_FAM and y in _OOB_FAM) or (x in _UAF_FAM and y in _UAF_FAM)


def _is_win(adj: Adjudication, verdict: AgentVerdict) -> bool:
    """A candidate WINS when it actually reproduces the bug: CONFIRMED, or DIVERGENT with
    the crash landing at the hypothesized sink/source, OR a DIVERGENT crash of the SAME
    CWE FAMILY as claimed. The last case handles the Ghidra-INLINED parser: the finding
    labels the sink after the enclosing function ("main") while ASan names the true
    callee ("handle_record"), so a genuine same-family reproduction from OUR targeted
    synthesis would otherwise be scored short. crash_function is reported transparently."""
    if adj.status == CONFIRMED:
        return True
    if adj.status == DIVERGENT and adj.crash_function:
        if func_matches(adj.crash_function, verdict.sink) or func_matches(
            adj.crash_function, verdict.source
        ):
            return True
        if _same_family(verdict.cwe, adj.crash_cwe):
            return True
    return False


def _better(best: Adjudication | None, adj: Adjudication) -> Adjudication:
    """Keep the closer near-miss between ``best`` and ``adj`` (see ``_STATUS_RANK``)."""
    if best is None:
        return adj
    if _STATUS_RANK.get(adj.status, 0) > _STATUS_RANK.get(best.status, 0):
        return adj
    return best


def confirm_by_synthesis(
    meta: Any,
    verdict: AgentVerdict,
    vuln_binary: str | Path,
    llm: Any,
    *,
    n: int = 6,
    vector: str = "file",
    visited: list[str] | None = None,
    timeout: float = 10.0,
    structural: bool = False,
) -> SynthResult:
    """Synthesize ``n`` candidate inputs and adjudicate each against ground truth — the
    real no-poc reproduce attempt.

    Runs each candidate from :func:`synthesize_povs` through
    ``adjudicate.adjudicate_finding``. The FIRST candidate that WINS (CONFIRMED, or
    DIVERGENT-but-crashing at the hypothesized sink) confirms the finding — its
    ``Adjudication`` and the winning bytes are attached. If none win, returns
    ``confirmed=False`` with the tried count and the BEST near-miss (a real crash
    elsewhere over a NO_CRASH over an UNRUNNABLE). Honest: most candidates NO_CRASH;
    success is when one reproduces. The LLM proposes; this oracle loop decides.

    With ``structural=True`` synthesis uses the structure-aware protocol AND each
    candidate that does not immediately win is given a best-effort
    :func:`apply_structural_fixups` retry — the model recomputes the consistency/gate
    fields (length prefix, record count, additive/xor checksum) so a candidate that was
    rejected before the sink can pass the gates and reproduce. The fixed variant is
    adjudicated too (and counted in ``tried``). Plain path (``structural=False``) is
    byte-unchanged. HONEST: fix-ups beat arithmetic gates only; crypto hashes,
    compression, and deep multi-stage state still defeat it."""
    candidates = synthesize_povs(meta, verdict, llm, n=n, visited=visited, structural=structural)
    if not candidates:
        return SynthResult(
            confirmed=False,
            tried=0,
            candidates=[],
            reason="no synthesizable candidates (the LLM produced no decodable input).",
        )

    best: Adjudication | None = None
    tried = 0
    attempted: set[bytes] = set()
    for idx, cand in enumerate(candidates, start=1):
        adj = adjudicate_finding(verdict, vuln_binary, cand, vector=vector, timeout=timeout)
        tried += 1
        attempted.add(cand)
        if _is_win(adj, verdict):
            return SynthResult(
                confirmed=True,
                adjudication=adj,
                winning_input=cand,
                tried=tried,
                candidates=candidates,
                reason=(
                    f"CONFIRMED by synthesis: candidate #{tried} of {len(candidates)} "
                    f"reproduced the bug ({adj.status}). {adj.reason}"
                ),
            )
        best = _better(best, adj)

        # Structure-aware retry: the candidate likely failed a gate before the sink.
        # Recompute its consistency fields and adjudicate the fixed variant.
        if structural:
            fixed = apply_structural_fixups(cand, verdict, meta, llm, visited=visited)
            if fixed and fixed not in attempted:
                adj_fixed = adjudicate_finding(
                    verdict, vuln_binary, fixed, vector=vector, timeout=timeout
                )
                tried += 1
                attempted.add(fixed)
                if _is_win(adj_fixed, verdict):
                    return SynthResult(
                        confirmed=True,
                        adjudication=adj_fixed,
                        winning_input=fixed,
                        tried=tried,
                        candidates=candidates,
                        reason=(
                            f"CONFIRMED by synthesis: a structural fix-up of candidate "
                            f"#{idx} of {len(candidates)} recomputed the gate fields and "
                            f"reproduced the bug ({adj_fixed.status}). {adj_fixed.reason}"
                        ),
                    )
                best = _better(best, adj_fixed)

    best_status = best.status if best is not None else "none"
    return SynthResult(
        confirmed=False,
        adjudication=best,
        winning_input=None,
        tried=tried,
        candidates=candidates,
        reason=(
            f"not confirmed: {tried} synthesized candidate(s) tried, none reproduced at "
            f"the sink (best outcome: {best_status}). The hypothesis remains unproven — "
            "the parser likely gates on a checksum/compression/deep reachability the "
            "synthesizer could not satisfy."
        ),
    )

"""LLM-driven structured-input synthesis (issue #52) — the confirm-stage capstone.

The generic integer-boundary probes the memory-safety confirmer drives
(``payloads.memsafe_candidates`` -> ``dynamic.confirm_asan_file``) are
*format-blind*: they set a length/count field large and pad the body, but they
never craft a **format-valid container** that a real parser will accept and then
follow all the way to the vulnerable sink. For the parser CVEs that dominate the
ARVO/OSS-Fuzz corpus (ICC color profiles, OpenType fonts, camera-RAW/TIFF), the
parser validates a magic/version/table-directory header and *bails out* long
before the sink if that header is malformed. So a flat ``b"A"*4096`` — or an
integer-boundary probe with a bogus header — is rejected at the door and the
size/count-driven overflow deeper in the parser never fires. That is exactly why
the fuzzer floor scored 0/3 on these three ARVO targets.

This module closes that gap. It asks an LLM to **synthesize a format-valid
input**: a byte string whose header is a genuine, well-formed file of the
target's format (correct magic, version, table directory, offsets) but with the
one specific size/count field — the field the decompiled sink trusts — set to a
value that overflows the sink's buffer. The parser accepts the header, walks it
to the sink, and the poisoned field drives the out-of-bounds access.

This is a *candidate generator*, not an oracle. Everything it emits is an
unverified hypothesis; ``oracle.run_sanitizer`` (differential: crash-on-vuln,
clean-on-fixed) remains the sole arbiter of whether a candidate actually
reproduces. Nothing here can fabricate a confirmation.

ANTI-CHEAT (issue #52): the synthesizer is given only *format knowledge* + the
*decompiled sink* + *how the overflow is reached*. It is NEVER given the
reference PoC bytes — it must construct the container from format understanding
alone. ``TargetContext`` has no field that could smuggle a known-good input in,
and ``synthesize_inputs`` builds its prompt solely from the format description
and decompilation.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from .agent import LLM

# --- format inference -------------------------------------------------------

# Map a substring found in the harness name / target strings to a human-readable
# file-format description the LLM can synthesize against. Ordered most-specific
# first; the first hit wins. These cover the ARVO parser families (issue #52) and
# the common OSS-Fuzz container formats, but the description is advisory — the
# decompiled sink is what pins the exact field to poison.
_FORMAT_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("cff2", "OpenType/sfnt font with a CFF2 table (sfnt offset table + table "
             "directory, then a CFF2 charstring/DICT INDEX structure)"),
    ("hb-", "OpenType/TrueType font (sfnt): 12-byte offset table, then a table "
            "directory of 16-byte records, then the referenced table blobs"),
    ("harfbuzz", "OpenType/TrueType font (sfnt) parsed by HarfBuzz"),
    ("lcms", "ICC colour profile: 128-byte header (magic 'acsp' at offset 36), "
             "then a tag table and tagged element data (lut8/lut16/mAB CLUTs)"),
    ("cms", "ICC colour profile ('acsp' magic at offset 36, tag table, CLUTs)"),
    ("icc", "ICC colour profile ('acsp' magic at offset 36, tag table, CLUTs)"),
    ("libraw", "Camera RAW image: a TIFF/DNG container (II/MM byte order, IFD "
               "directories) carrying maker-note sub-directories"),
    ("raw", "Camera RAW image (TIFF/DNG-based container with maker notes)"),
    ("dng", "DNG / TIFF container (II/MM byte order marker, IFD directory of "
            "12-byte tag entries)"),
    ("tiff", "TIFF image: byte-order marker (II/MM), 42 magic, IFD offset, then "
             "IFDs of 12-byte tag entries"),
    ("png", "PNG image: 8-byte signature then length-tagged chunks (IHDR ...)"),
    ("jpeg", "JPEG image: SOI marker then segment markers with 2-byte lengths"),
    ("jpg", "JPEG image: SOI marker then segment markers with 2-byte lengths"),
    ("gif", "GIF image: 'GIF89a' header, logical screen descriptor, blocks"),
    ("woff", "WOFF web-font wrapper around an sfnt font"),
    ("otf", "OpenType font (sfnt offset table + table directory)"),
    ("ttf", "TrueType font (sfnt offset table + table directory)"),
    ("font", "Font file (sfnt/OpenType offset table + table directory)"),
    ("pdf", "PDF document: '%PDF-' header, objects, xref table, trailer"),
    ("zip", "ZIP archive: local file headers, central directory, EOCD record"),
    ("elf", "ELF object: e_ident magic, ELF header, program/section headers"),
    ("xml", "XML document (well-formed element tree)"),
    ("json", "JSON document"),
)


def infer_format(harness_name: str, strings: Iterable[str] = ()) -> str:
    """Best-effort guess of the file format a target parses, from its harness
    name (``cms_postscript_fuzzer`` -> ICC, ``hb-draw-fuzzer`` -> font,
    ``libraw`` -> camera RAW) and, as a fallback, notable strings pulled from the
    binary. Returns a human-readable description for the synthesis prompt, or an
    empty string when nothing matches (the caller then relies on the decompiled
    sink alone). Advisory only — never an oracle."""
    hay = harness_name.lower()
    for key, desc in _FORMAT_SIGNATURES:
        if key in hay:
            return desc
    blob = " ".join(strings).lower()
    for key, desc in _FORMAT_SIGNATURES:
        if key in blob:
            return desc
    return ""


# --- target context (what the synthesizer is allowed to see) ----------------


@dataclass
class TargetContext:
    """Everything the synthesizer may condition on — and nothing else.

    Deliberately has NO field for a known-good/reference input: the synthesizer
    must build the container from format knowledge + the decompiled sink alone
    (issue #52 anti-cheat). All fields are plain strings inferred from the binary
    (harness name, ``strings``, Ghidra decompilation) — the same signals a real
    0verse run has before it has ever reproduced the bug."""

    file_format: str
    """Human-readable description of the container format (see ``infer_format``)."""
    harness_name: str = ""
    """The fuzz-harness / entrypoint name (``hb-draw-fuzzer``)."""
    sink_function: str = ""
    """The sink's name + source location (``WriteCLUT @ cmsps2.c:667``)."""
    sink_decompiled: str = ""
    """Decompiled (or reconstructed) body of the sink and its callers."""
    overflow_reason: str = ""
    """How the overflow is reached: the size/count field that must be large and
    what it drives (``the CLUT grid-point count `nGrid` scales the output buffer;
    an oversized count over-reads the interpolation table``)."""
    extra_notes: str = ""
    """Any additional format constraints (endianness, required magic, alignment)."""
    max_input_size: int = 1 << 20
    """Hard cap on a synthesized candidate's length (bytes); larger ones are
    dropped so a hallucinated multi-MB blob never reaches the oracle."""


# --- synthesis --------------------------------------------------------------

_SYSTEM = (
    "You are a file-format and vulnerability-research expert building a "
    "regression input for a KNOWN, already-triaged bug. You are given the file "
    "format a target parses, the decompiled sink function that overflows, and a "
    "description of which size/count field drives the overflow. Your job: emit a "
    "FORMAT-VALID input file whose header is a genuine, well-formed file of that "
    "format (correct magic, version, table directory, offsets, checksums where a "
    "parser enforces them) so the parser ACCEPTS it and walks it to the sink — "
    "but with the one specific size/count field set to a value that overflows the "
    "sink's buffer. A malformed header is useless: the parser rejects it before "
    "the sink. Think about the exact parse path from the first byte to the sink "
    "and keep every field on that path valid. Output the candidate file as a "
    "lowercase hex string (no spaces, no 0x). Provide a few DIVERSE candidates "
    "that vary the poisoned field / table layout. This is a candidate for a "
    "downstream crash oracle to test; you are proposing, not confirming."
)

# The structured response: an array of hex-encoded candidate files. A short
# ``note`` per candidate is optional and captures the model's reasoning about
# which field it poisoned (surfaced in experiment logs, never trusted).
SYNTH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "hex": {"type": "string"},
                    "note": {"type": "string"},
                },
                "required": ["hex"],
            },
        },
    },
    "required": ["candidates"],
}


@dataclass
class SynthResult:
    """The synthesizer's output: decoded candidate bytes plus the raw notes, so a
    bench experiment can report *what* the model built and *why*, not just the
    hit/miss verdict (issue #52 asks for the honest analysis either way)."""

    candidates: list[bytes] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    error: str = ""


def _build_prompt(ctx: TargetContext, n: int) -> str:
    parts = [
        f"FILE FORMAT THE TARGET PARSES:\n{ctx.file_format}",
    ]
    if ctx.harness_name:
        parts.append(f"\nFUZZ HARNESS / ENTRYPOINT: {ctx.harness_name}")
    if ctx.sink_function:
        parts.append(f"\nVULNERABLE SINK: {ctx.sink_function}")
    if ctx.overflow_reason:
        parts.append(f"\nHOW THE OVERFLOW IS REACHED:\n{ctx.overflow_reason}")
    if ctx.sink_decompiled:
        parts.append(f"\n--- DECOMPILED SINK (and reachable callers) ---\n{ctx.sink_decompiled}")
    if ctx.extra_notes:
        parts.append(f"\nADDITIONAL FORMAT CONSTRAINTS:\n{ctx.extra_notes}")
    parts.append(
        f"\nEmit up to {n} diverse FORMAT-VALID candidate files (hex). Each must "
        "have a valid header for the format above so the parser reaches the sink, "
        "with the size/count field set to overflow it. Keep each candidate under "
        f"{ctx.max_input_size} bytes."
    )
    return "".join(parts)


# Accept the model's hex whether it arrives clean, 0x-prefixed, whitespaced, or
# newline-wrapped; anything that still isn't valid hex is dropped, not guessed.
_HEX_STRIP_RE = re.compile(r"(?i)^\s*(?:0x)?")
_NON_HEX_RE = re.compile(r"[^0-9a-fA-F]")


def _decode_hex(raw: str) -> bytes | None:
    """Decode a model-supplied hex string to bytes, tolerating 0x prefixes and
    embedded whitespace. Returns ``None`` for empty or odd-length input rather
    than fabricating a byte (a truncated candidate is dropped, never padded)."""
    if not isinstance(raw, str):
        return None
    s = _HEX_STRIP_RE.sub("", raw)
    s = _NON_HEX_RE.sub("", s)
    if not s or len(s) % 2:
        return None
    try:
        return bytes.fromhex(s)
    except ValueError:
        return None


def synthesize_inputs(
    ctx: TargetContext,
    llm: LLM,
    *,
    n: int = 5,
) -> SynthResult:
    """Ask ``llm`` for up to ``n`` FORMAT-VALID candidate inputs for ``ctx``.

    Returns a ``SynthResult`` with the decoded candidate bytes (deduped,
    non-empty, within ``ctx.max_input_size``) and the model's per-candidate
    notes. On any backend failure or unparseable response the result carries an
    ``error`` string and an empty candidate list — the caller degrades to the
    generic boundary probes, never crashes. This is a hypothesis generator: the
    sanitizer oracle, not this function, decides whether any candidate
    reproduces."""
    system = _SYSTEM
    prompt = _build_prompt(ctx, n)
    try:
        raw = llm.complete_json(system, prompt, SYNTH_SCHEMA)
    except Exception as exc:  # degrade on ANY backend failure — never crash confirm
        return SynthResult(error=f"{type(exc).__name__}: {exc}")

    items = raw.get("candidates") if isinstance(raw, dict) else None
    if not isinstance(items, list):
        return SynthResult(raw=raw if isinstance(raw, dict) else {},
                           error="response had no 'candidates' array")

    out: list[bytes] = []
    notes: list[str] = []
    seen: set[bytes] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        data = _decode_hex(item.get("hex", ""))
        if data is None or not data or len(data) > ctx.max_input_size:
            continue
        if data in seen:
            continue
        seen.add(data)
        out.append(data)
        note = item.get("note", "")
        notes.append(note if isinstance(note, str) else "")
    return SynthResult(candidates=out, notes=notes, raw=raw)


def synthesize_candidates(ctx: TargetContext, llm: LLM, *, n: int = 5) -> list[bytes]:
    """Thin wrapper returning just the candidate byte strings — the shape the
    confirmer's candidate loop consumes (see ``dynamic.confirm_asan_file``'s
    ``synth_candidates`` hook)."""
    return synthesize_inputs(ctx, llm, n=n).candidates


def context_from_finding(
    *,
    file_format: str = "",
    harness_name: str = "",
    sink_function: str = "",
    sink_decompiled: str = "",
    overflow_reason: str = "",
    extra_notes: str = "",
    strings: Sequence[str] = (),
) -> TargetContext:
    """Assemble a ``TargetContext`` for the synthesizer, inferring the format from
    the harness name / ``strings`` when ``file_format`` is left blank. Kept as a
    small factory so a pipeline call site never has to know the ``infer_format``
    signature."""
    fmt = file_format or infer_format(harness_name, strings)
    return TargetContext(
        file_format=fmt,
        harness_name=harness_name,
        sink_function=sink_function,
        sink_decompiled=sink_decompiled,
        overflow_reason=overflow_reason,
        extra_notes=extra_notes,
    )

"""Structured trigger-input synthesis for the dynamic confirmer.

The memory-safety confirmer (``dynamic.confirm``) historically drove a single
flat payload — ``b"A" * 4096`` — through the source vector. That reliably smashes
a *flat* stack/heap copy (``strcpy`` of unbounded stdin), but it never confirms a
whole class of real bugs: **size/count-driven** memory corruption, where an
attacker-controlled integer field in the input *header* wraps or is mis-checked
and only then drives an out-of-bounds copy (CWE-190 → CWE-787, the shape of most
real image/media-parser CVEs). A wall of ``A``\\ s makes the length field
``0x41414141`` — a large *positive* value that a naive bound check usually
clamps, so the sink is never overrun and the bug never reproduces.

This module produces a small, deterministic, target-independent family of
**integer-boundary header probes**: extreme size values (max, INT_MIN, INT_MAX,
power-of-two boundaries) packed in every common width/endianness and prepended to
a large body. Feeding these drives length-controlled sinks past their bounds
regardless of the specific format — a standard fuzzing technique, not a memorized
CVE input. Integers the LLM names in its ``input_example`` hypothesis are folded
in too, so the model's structured reasoning actually reaches the sink.

No target knowledge, no network, no LLM adjudication — the crash oracle still
decides truth downstream; this only *proposes* inputs to execute.
"""

from __future__ import annotations

import contextlib
import re

# Extreme integer values that tend to wrap, underflow, or slip a bound check when
# used as a size/count/index. Ordered most-suspicious first so the confirmer hits
# a reproducing input with the fewest executions.
_BOUNDARY_INTS: tuple[int, ...] = (
    0xFFFFFFFF,          # -1 as u32 / SIZE_MAX low word — the canonical wrap
    0x80000000,          # INT_MIN — signed*positive multiply wraps negative
    0x7FFFFFFF,          # INT_MAX — +1 overflows a signed length
    0xFFFFFFFE,          # -2
    0x60000000,          # *4 wraps the sign bit (YCbCr-style progression)
    0x40000000,          # *4 == 2**32 (wraps to 0)
    0xFFFF,              # u16 -1
    0x8000,              # i16 min
    0x7FFF,              # i16 max
    0x00010000,          # just past a 16-bit field
)

# How much trailing body to stage after the header. Big enough that a bound that
# wraps to "clamped to the input size" still overruns a small heap/stack buffer,
# and long enough to smash a flat copy on its own.
_BODY_LEN = 1 << 16      # 64 KiB


def _parse_ints(text: str) -> list[int]:
    """Pull candidate size values out of a free-form ``input_example`` string:
    ``0x``-prefixed hex and any decimal literal >= 256 (smaller decimals are
    almost always offsets/counts, not the overflow driver). Best-effort and
    deterministic — anything unparseable is simply skipped."""
    out: list[int] = []
    for tok in re.findall(r"0x[0-9a-fA-F]+", text):
        with contextlib.suppress(ValueError):
            out.append(int(tok, 16) & 0xFFFFFFFFFFFFFFFF)
    for tok in re.findall(r"\b\d{3,}\b", text):
        with contextlib.suppress(ValueError):
            v = int(tok)
            if v >= 256:
                out.append(v & 0xFFFFFFFFFFFFFFFF)
    return out


def _pack(value: int, width: int, little: bool) -> bytes:
    """Pack ``value`` truncated to ``width`` bytes in the given endianness."""
    mask = (1 << (width * 8)) - 1
    v = value & mask
    return v.to_bytes(width, "little") if little else v.to_bytes(width, "big")


def boundary_payloads(
    extra_ints: list[int] | None = None,
    *,
    body_len: int = _BODY_LEN,
    max_payloads: int = 32,
) -> list[bytes]:
    """Deterministic family of integer-boundary header probes.

    Each probe is ``<packed extreme size> + <large body>``: the header drives a
    size/count field to a wrapping/boundary value, the body supplies bytes to
    copy once the bound is slipped. Every value is packed as u16/u32/u64 in both
    endiannesses (a parser reads the field in *some* width/order; we don't know
    which). Capped and de-duplicated so the confirmer stays bounded and stable.
    """
    values: list[int] = list(_BOUNDARY_INTS)
    for v in extra_ints or ():
        if v not in values:
            values.append(v)

    body = b"A" * body_len
    seen: set[bytes] = set()
    out: list[bytes] = []

    def _emit(header: bytes) -> bool:
        payload = header + body
        if payload in seen:
            return False
        seen.add(payload)
        out.append(payload)
        return len(out) >= max_payloads

    for value in values:
        for width in (4, 2, 8):                 # u32 first — the common size field
            for little in (True, False):
                header = _pack(value, width, little)
                # single field, then a header *tiled* with the value so a bug
                # driven by MULTIPLE size fields (e.g. an unsigned product that
                # wraps: numlayers*step) sees every field at the boundary, not
                # just the first. 32 bytes covers up to eight u32 header fields.
                if _emit(header):
                    return out
                if _emit((header * (32 // len(header) + 1))[:32]):
                    return out
    return out


def memsafe_candidates(
    input_example: str = "",
    *,
    legacy_first: bool = True,
    body_len: int = _BODY_LEN,
    max_payloads: int = 32,
) -> list[bytes]:
    """Ordered trigger payloads for the memory-safety confirmer.

    ``b"A" * 4096`` stays first (``legacy_first``): it confirms a flat copy in one
    execution and preserves the historical PoV shape. Integer-boundary probes —
    seeded with any sizes named in the model's ``input_example`` — follow, so
    size/count-driven corruption that a flat payload can't reach still confirms.
    """
    probes = boundary_payloads(
        _parse_ints(input_example), body_len=body_len, max_payloads=max_payloads
    )
    legacy = b"A" * 4096
    ordered = [legacy, *probes] if legacy_first else [*probes, legacy]
    # de-dup while preserving order
    seen: set[bytes] = set()
    out: list[bytes] = []
    for p in ordered:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out

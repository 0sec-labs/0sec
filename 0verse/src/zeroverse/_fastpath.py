"""Optional native fast-path shim (#31).

A single seam between the pure-Python engine and the optional Rust extension
(``zeroverse._native``, built from ``rust/`` via maturin). Everything here answers
one question — *does this needle occur as a substring of this haystack?* — which
is exactly Python's ``needle in haystack``. The native path collapses N
independent scans into one multi-pattern Aho-Corasick sweep; when the extension
is absent (the default OSS install never requires a Rust toolchain) the calls
fall back to plain ``in`` and the results are **byte-for-byte identical**.

This is deliberately a *presence* primitive, not a regex port. Its measured win
is on **large contiguous blobs** — ingest/triage scanning a 100MB+ binary for its
marker strings (``contains_any_bytes``). It is intentionally *not* used for the
bug-class lens prefilter: there the haystacks are thousands of tiny function
bodies where CPython's ``in`` beats the Python↔Rust boundary cost, so that path
stays pure Python (see ``bugclasses._presence`` and docs/PERF.md)."""

from __future__ import annotations

from collections.abc import Sequence

try:  # pragma: no cover - import side depends on whether the extension was built
    from . import _native

    NATIVE: bool = True
    BACKEND: str = _native.backend()
except ImportError:  # pragma: no cover - the pure-Python install path
    _native = None  # type: ignore[assignment]
    NATIVE = False
    BACKEND = "python"


def contains_any(haystack: str, needles: Sequence[str]) -> list[bool]:
    """For each needle, True iff it is a substring of ``haystack`` (str)."""
    if not needles:
        return []
    if _native is not None:
        # The extension is untyped (Any); pin the result type at the seam.
        result: list[bool] = _native.contains_any(haystack, list(needles))
        return result
    return [n in haystack for n in needles]


def contains_any_bytes(haystack: bytes, needles: Sequence[bytes]) -> list[bool]:
    """For each needle, True iff it is a substring of ``haystack`` (bytes)."""
    if not needles:
        return []
    if _native is not None:
        result: list[bool] = _native.contains_any_bytes(
            bytes(haystack), [bytes(n) for n in needles]
        )
        return result
    return [n in haystack for n in needles]

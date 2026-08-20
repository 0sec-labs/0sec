"""Type stub for the OPTIONAL Rust extension ``zeroverse._native`` (#31).

The compiled module may be absent (the pure-Python install never builds it); the
stub describes its ABI so the typed seam in ``_fastpath`` checks under
``mypy --strict``. ``_fastpath`` guards the import and falls back at runtime."""

from collections.abc import Sequence

def contains_any(haystack: str, needles: Sequence[str]) -> list[bool]: ...
def contains_any_bytes(haystack: bytes, needles: Sequence[bytes]) -> list[bool]: ...
def backend() -> str: ...

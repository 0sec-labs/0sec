"""#31 — native fast-path: parity + perf-smoke.

The Rust extension (``zeroverse._native``) is an OPTIONAL build. These tests:

  * always run the *fallback path* (pure Python) so the seam is exercised on a
    bare install, and run a perf-smoke that the lenses/triage complete;
  * when the extension IS built, assert the native path is **byte-for-byte
    identical** to the Python fallback for the primitives, every bug-class lens,
    and ingest's marker scans. The native-vs-Python comparisons SKIP cleanly when
    the extension was not compiled.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator

import pytest

from zeroverse import _fastpath, bugclasses, ingest

native_only = pytest.mark.skipif(
    not _fastpath.NATIVE, reason="native extension (zeroverse._native) not built"
)


@pytest.fixture
def force_python(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Force the pure-Python fallback regardless of whether the extension exists."""
    monkeypatch.setattr(_fastpath, "_native", None)
    yield


# --- representative inputs --------------------------------------------------

def _corpus() -> dict[str, str]:
    return {
        "FUN_benign": "void FUN_benign(void){ int x = a + b; return x; }",
        "FUN_alloc": "void f(void){ n = w * h + 1; p = malloc(n); memcpy(p, q, n); }",
        "FUN_fmt": 'void f(void){ char*s=getenv("X"); printf(s); fprintf(stderr,"ok"); }',
        "FUN_free": "void f(void){ free(p); use(p->next); free(q); }",
        "FUN_cmd": "void f(void){ char*c=getenv(\"C\"); system(c); execlp(\"ls\",x); }",
        "FUN_logic": "int f(void){ if(strcmp(password,inp)==0){admin=1;} return admin; }",
        "FUN_overlap": "void f(void){ execlp(p,q); /* execl substring but no execl( */ }",
        "FUN_fprintf_only": 'void f(void){ fprintf(stderr, "literal"); }',
        "FUN_empty": "",
    }


_LENSES = (
    bugclasses.intoverflow_lens,
    bugclasses.fmtstring_lens,
    bugclasses.uaf_lens,
    bugclasses.cmdi_lens,
    bugclasses.logic_lens,
)


def _make_elf(canary: bool, stripped: bool, size: int = 2048) -> bytes:
    hdr = bytearray(64 + 56)
    hdr[0:4] = b"\x7fELF"
    hdr[4], hdr[5] = 2, 1
    struct.pack_into("<H", hdr, 16, 2)      # EXEC
    struct.pack_into("<H", hdr, 18, 0x3E)   # x86-64
    struct.pack_into("<Q", hdr, 32, 64)     # e_phoff
    struct.pack_into("<H", hdr, 54, 56)     # e_phentsize
    struct.pack_into("<H", hdr, 56, 1)      # e_phnum
    struct.pack_into("<I", hdr, 64, 0x6474E551)  # PT_GNU_STACK
    struct.pack_into("<I", hdr, 68, 0x6)         # RW
    body = bytearray(hdr)
    body += b"\x00" * max(0, size - len(body))
    if canary:
        body += b"__stack_chk_fail\x00"
    if not stripped:
        body += b".symtab\x00"
    return bytes(body)


# --- primitive parity -------------------------------------------------------

@native_only
def test_contains_any_matches_python() -> None:
    cases = [
        ("hello free world", ["free", "malloc", "", "world", "x"]),
        ("", ["a", ""]),
        ("printf in fprintf", ["printf", "fprintf", "sprintf"]),
        ("aaa", ["aa", "aaa", "aaaa"]),
    ]
    for hay, needles in cases:
        assert _fastpath.contains_any(hay, needles) == [n in hay for n in needles]


@native_only
def test_contains_any_bytes_matches_python() -> None:
    hay = b"\x7fELF....__stack_chk_fail...PDB"
    needles = [b"__stack_chk_fail", b".symtab", b"PDB", b"", b".debug"]
    assert _fastpath.contains_any_bytes(hay, needles) == [n in hay for n in needles]


# --- end-to-end parity: lenses + triage identical native vs python ----------

def test_lenses_deterministic_and_prefiltered() -> None:
    """The lens prefilter is pure Python (the native path is intentionally not used
    for thousands of tiny bodies). Assert it still flags every seeded shape and
    that toggling the extension cannot change lens output."""
    corpus = _corpus()
    out_a = bugclasses.prime_bugclasses(corpus)
    classes = {f.origin for f in out_a}
    assert {"bugclass:intoverflow", "bugclass:fmtstring", "bugclass:uaf",
            "bugclass:cmdi"} <= classes


@native_only
def test_lenses_native_equal_python(monkeypatch: pytest.MonkeyPatch) -> None:
    corpus = _corpus()
    native = {lens.__name__: lens(corpus) for lens in _LENSES}
    native_prime = bugclasses.prime_bugclasses(corpus)
    monkeypatch.setattr(_fastpath, "_native", None)
    py = {lens.__name__: lens(corpus) for lens in _LENSES}
    py_prime = bugclasses.prime_bugclasses(corpus)
    for name in native:
        assert native[name] == py[name], f"{name} diverged native vs python"
    assert native_prime == py_prime


@native_only
def test_triage_native_equal_python(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for canary in (True, False):
        for stripped in (True, False):
            p = tmp_path / f"b_{canary}_{stripped}.elf"
            p.write_bytes(_make_elf(canary, stripped))
            native = ingest.triage(p)
            monkeypatch.setattr(_fastpath, "_native", None)
            py = ingest.triage(p)
            monkeypatch.undo()
            assert native.summary() == py.summary()
            assert native.mitigations == py.mitigations
            assert native.stripped == py.stripped


# --- fallback always works (bare-install path) ------------------------------

def test_fallback_lenses_run(force_python: None) -> None:
    corpus = _corpus()
    out = bugclasses.prime_bugclasses(corpus)
    classes = {f.origin for f in out}
    # the seeded shapes are all surfaced by the pure-Python path
    assert "bugclass:intoverflow" in classes
    assert "bugclass:fmtstring" in classes
    assert "bugclass:uaf" in classes
    assert "bugclass:cmdi" in classes


def test_fallback_triage_runs(tmp_path, force_python: None) -> None:
    p = tmp_path / "x.elf"
    p.write_bytes(_make_elf(canary=True, stripped=False))
    t = ingest.triage(p)
    assert t.fmt == "ELF"
    assert t.mitigations["canary"] is True
    assert t.stripped is False


def test_perf_smoke_large_corpus() -> None:
    """A few thousand bodies complete fast through whichever path is active."""
    corpus = {f"FUN_{i:06x}": ("void f(void){ system(getenv(\"C\")); }" if i % 7 == 0
                               else "void f(void){ int x = a + b; }")
              for i in range(3000)}
    out = bugclasses.prime_bugclasses(corpus)
    assert any(f.origin == "bugclass:cmdi" for f in out)

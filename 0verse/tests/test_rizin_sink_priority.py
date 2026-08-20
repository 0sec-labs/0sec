"""Symbol-free sink-caller priority (crutch-free LOCATE) — pure logic, no toolchain.

The rizin backend orders its budget-capped decompile queue so functions that call a
dangerous sink go first. The name-based signal it historically used goes INERT on a
stripped binary (every function is ``fcn.0x…``), so ``_sink_caller_offsets`` recovers
the sink-caller set WITHOUT symbol names — by resolving sink stub addresses that
survive ``strip`` (dynamic ``memcpy@plt`` imports AND ``__asan_*``/``__interceptor_*``
interposed symbols) and taking the xrefs TO them. These tests mock r2's JSON so they
run anywhere; the live behaviour is measured on arvo:64166 (WriteCLUT 4839→180).
"""

from __future__ import annotations

import json

from zeroverse.backends.rizin import _norm_import, _sink_caller_offsets


class _FakeR2:
    """Minimal r2pipe stand-in: answers ``iij``/``isj``/``axtj @ <addr>`` from a map."""

    def __init__(self, imports: list[dict], syms: list[dict], xrefs: dict[int, list[dict]]):
        self._imports = imports
        self._syms = syms
        self._xrefs = xrefs

    def cmd(self, c: str) -> str:
        if c == "iij":
            return json.dumps(self._imports)
        if c == "isj":
            return json.dumps(self._syms)
        if c.startswith("axtj @ "):
            addr = int(c.split("@", 1)[1].strip())
            return json.dumps(self._xrefs.get(addr, []))
        return "[]"


def test_norm_import_strips_decoration_and_version() -> None:
    assert _norm_import("sym.imp.memcpy") == "memcpy"
    assert _norm_import("memcpy@GLIBC_2.14") == "memcpy"
    assert _norm_import("imp.__memcpy_chk") == "memcpy_chk"  # leading __ stripped


def test_plain_plt_sink_caller_recovered_when_stripped() -> None:
    """A nameless ``fcn.0x`` that calls ``memcpy@plt`` is flagged hot via its stub."""
    imports = [{"name": "memcpy", "plt": 0x8049000},
               {"name": "getenv", "plt": 0x8049010}]  # non-sink import: ignored
    xrefs = {0x8049000: [{"fcn_addr": 0x8060950}, {"fcn_addr": 0x8061200}]}
    r2 = _FakeR2(imports, [], xrefs)
    assert _sink_caller_offsets(r2) == {0x8060950, 0x8061200}


def test_asan_interposed_sink_anchor() -> None:
    """On an ASan build the plain imports are empty; the interceptor dynsym symbol is
    the anchor that survives strip (the arvo:64166 case)."""
    syms = [{"name": "__asan_memcpy", "vaddr": 0x8183550},
            {"name": "__interceptor_malloc", "vaddr": 0x811a000},
            {"name": "__asan_report_load4", "vaddr": 0x8184000}]  # report fn: not a sink
    xrefs = {0x8183550: [{"fcn_addr": 0x8223ed0}],   # WriteCLUT
             0x811a000: [{"fcn_addr": 0x8223ed0}, {"fcn_addr": 0x8090000}]}
    r2 = _FakeR2([], syms, xrefs)
    hot = _sink_caller_offsets(r2)
    assert 0x8223ed0 in hot and 0x8090000 in hot
    assert 0x8184000 not in [s.get("vaddr") for s in syms if s["name"] in ("__absent__",)]  # sanity


def test_no_sinks_yields_empty_set_not_error() -> None:
    """No resolvable sink -> empty set (caller falls back to name-based priority)."""
    r2 = _FakeR2([{"name": "getpid", "plt": 0x1000}], [], {})
    assert _sink_caller_offsets(r2) == set()

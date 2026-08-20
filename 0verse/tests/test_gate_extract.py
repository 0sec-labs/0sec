"""Gate-constant extraction — unit tests over a synthetic objdump fixture.

Reproduces the wavpack dispatch shape: ``cmp $0x52,%r14d`` one instruction before
``call ... <open_file3>`` — the byte0=='R' (RIFF) gate that routes to the v3 decoder.
"""

from __future__ import annotations

from zeroverse import gate_extract as ge

# The dispatcher shape: a RIFF check (0x52='R') tightly gating the call, plus a distant
# unrelated compare and a large address constant that must be filtered out.
_DUMP = "\n".join(
    [
        "0000000000138d70 <WavpackOpenFileInputEx64>:",
        "  138d99:\tcmp    $0x10000,%r12d",        # far, large-ish field
        "  138da0:\tcmp    $0x1,%r15d",             # far
        "  139280:\tcall   70c50 <__sanitizer_cov_trace_const_cmp1>",
        "  139285:\tcmp    $0x52,%r14d",            # the gate: 'R'
        "  139299:\tcall   1655d0 <open_file3>",    # -> v3 decoder
        "0000000000200000 <other>:",
        "  200001:\tcmp    $0x7,%eax",
        "  200008:\tcall   1655d0 <open_file3>",    # a second call site, different gate
        "0000000000300000 <unrelated>:",
        "  300001:\tcall   400000 <somethingelse>",
    ]
)


def _patch(monkeypatch) -> None:
    monkeypatch.setattr(
        ge.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": _DUMP})()
    )


def test_recovers_riff_gate_nearest_first(monkeypatch) -> None:
    _patch(monkeypatch)
    gates = ge.dominating_gate_consts("vuln", "open_file3", window=48)
    # the tightest gate (one insn before the call) is the 0x52 'R' RIFF check
    assert gates[0].value == 0x52
    assert gates[0].ascii == "R"
    assert gates[0].distance == 1
    assert gates[0].caller == "WavpackOpenFileInputEx64"


def test_collects_all_call_site_gates(monkeypatch) -> None:
    _patch(monkeypatch)
    gates = ge.dominating_gate_consts("vuln", "open_file3", window=48, max_value=0xFFFFF)
    values = {g.value for g in gates}
    assert 0x52 in values and 0x7 in values      # both call sites' gates
    assert 0x10000 in values                       # within window of the first call


def test_filters_large_address_constants(monkeypatch) -> None:
    _patch(monkeypatch)
    gates = ge.dominating_gate_consts("vuln", "open_file3", max_value=0xFFFF)
    # 0x10000 exceeds max_value -> filtered as an address/size, not a magic gate
    assert all(g.value <= 0xFFFF for g in gates)


def test_no_gate_for_absent_target(monkeypatch) -> None:
    _patch(monkeypatch)
    assert ge.dominating_gate_consts("vuln", "nonexistent_func") == []


def test_gloss_readable(monkeypatch) -> None:
    _patch(monkeypatch)
    g = ge.dominating_gate_consts("vuln", "open_file3")[0]
    assert "0x52" in g.gloss() and "'R'" in g.gloss()

"""Unit tests for the runtime-introspection probe — all with MOCKED gdb/objdump output,
so they run with no real target binary, no gdb, and no network.

Coverage: gdb-output parsing (reachability + read-site state + crash), the bounds
verdict, byte-provenance location, the feedback-instruction regimes, the accessor
offset heuristic, gdb-script synthesis, and a probe() end-to-end with a fake gdb run.
"""

from __future__ import annotations

import zeroverse.runtime_probe as rp
import zeroverse.sandbox_exec as sx

# --- output parsing ---------------------------------------------------------
_SINK = "LibRaw::parseAdobeRAFMakernote()"

# A synthetic gdb batch transcript: entered the function, hit checkpoints, took two
# reader calls (inner sget4(2) returned -9; outer read at offset -3), then crashed.
_GDB_CRASH = """\
Breakpoint 1 at 0x77ddc7: file src/metadata/fuji.cpp, line 229.
CKPT 187
CKPT 205
CKPT 226
READ 0 line=228 off=2 base=0x7ffff34f5800 size=2106400
RET 0 val=-9
READ 1 line=229 off=-3 base=0x7ffff34f5800 size=2106400
SINKLINE 229
==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7ffff34f57fd
    #2 0x77ddd2 in LibRaw::parseAdobeRAFMakernote() /src/libraw/src/metadata/fuji.cpp:229:33
SUMMARY: AddressSanitizer: heap-buffer-overflow read_utils.cpp:63 in libraw_sget4_static
STOPPED
Line 229 of "fuji.cpp"
#0 libraw_sget4_static
"""

_READ_META = [{"site": "sget4@228"}, {"site": "sget4@229"}]


def test_parse_reachability_and_reads():
    res = rp.parse_probe_output(_GDB_CRASH, sink_func=_SINK, sink_line=229, read_meta=_READ_META)
    assert res.reached_func is True
    assert set(res.reached_lines) >= {187, 205, 226, 229}
    assert res.max_line == 229
    assert len(res.reads) == 2
    inner, outer = res.reads[0], res.reads[1]
    assert inner.line == 228 and inner.offset == 2 and inner.ret == -9
    assert outer.line == 229 and outer.offset == -3
    assert outer.buf_size == 2106400 and outer.buf_base == 0x7FFFF34F5800


def test_parse_detects_crash_at_sink():
    res = rp.parse_probe_output(_GDB_CRASH, sink_func=_SINK, sink_line=229, read_meta=_READ_META)
    assert res.crashed is True
    assert res.crash_at_sink is True
    assert res.crash_line == 229


def test_bounds_verdict_negative_offset_is_oob():
    res = rp.parse_probe_output(_GDB_CRASH, sink_func=_SINK, sink_line=229, read_meta=_READ_META)
    oob = res.oob_read
    assert oob is not None and oob.line == 229
    assert "offset < 0" in oob.oob_reason


def test_bounds_verdict_inbounds_offset_not_oob():
    out = "CKPT 187\nREAD 0 line=229 off=22 base=0x1000 size=2106400\nInferior 1 exited normally\n"
    res = rp.parse_probe_output(out, sink_func=_SINK, sink_line=229, read_meta=[{"site": "s"}])
    assert res.crashed is False
    assert res.reads[0].oob is False
    assert res.oob_read is None


def test_parse_overflow_offset_is_oob():
    out = "READ 0 line=9 off=5000 base=0x1000 size=100\n"
    res = rp.parse_probe_output(out, sink_func=_SINK, sink_line=9, read_meta=[{"site": "s"}])
    assert res.reads[0].oob is True
    assert "size" in res.reads[0].oob_reason


def test_parse_nil_base_and_did_not_enter():
    out = "Inferior 1 (process 1) exited with code 01\n"
    res = rp.parse_probe_output(out, sink_func=_SINK, sink_line=229, read_meta=[])
    assert res.reached_func is False
    assert res.reads == []
    assert res.crashed is False


# --- provenance -------------------------------------------------------------
def test_locate_value_unique_big_endian():
    # -9 as 4-byte big-endian is ff ff ff f7; place it uniquely at offset 5.
    data = b"\x00\x01\x02\x03\x04\xff\xff\xff\xf7\x10\x11"
    prov = rp.locate_value(data, -9)
    assert prov is not None
    assert prov.input_offset == 5 and prov.width == 4 and prov.endian == "big"


def test_locate_value_little_endian():
    data = b"AAAA" + (16).to_bytes(4, "little") + b"BBBB"
    prov = rp.locate_value(data, 16)
    assert prov is not None
    assert prov.input_offset == 4 and prov.endian == "little"


def test_locate_value_ambiguous_returns_none():
    # 0x0000 appears many times -> not uniquely locatable.
    data = b"\x00" * 32
    assert rp.locate_value(data, 0) is None


# --- feedback instruction regimes ------------------------------------------
def test_feedback_not_entered():
    res = rp.ProbeResult(reached_func=False)
    msg = rp.feedback_instruction(res, sink_func="foo")
    assert "did NOT enter" in msg and "OUTER" in msg


def test_feedback_bailed_before_read():
    res = rp.ProbeResult(reached_func=True, reached_lines=[187, 205], max_line=205)
    msg = rp.feedback_instruction(res, sink_func="foo")
    assert "205" in msg and "before the vulnerable read".upper() in msg.upper()


def test_feedback_reached_read_inbounds_names_field():
    res = rp.ProbeResult(
        reached_func=True,
        reads=[rp.ReadObs(line=229, offset=22, buf_size=2106400)],
        provenance=[
            rp.Provenance(
                value=16, input_offset=369, width=4, endian="big", via="read@line228 return"
            )
        ],
    )
    msg = rp.feedback_instruction(res, sink_func="foo", fault_constraint="offset<0")
    assert "369" in msg and "NEGATIVE" in msg and "ROUTING SUCCEEDED" in msg


def test_feedback_oob_reached():
    res = rp.ProbeResult(
        reached_func=True,
        reads=[
            rp.ReadObs(
                line=229,
                offset=-3,
                buf_size=100,
                oob=True,
                oob_reason="offset < 0 (underflow read)",
            )
        ],
    )
    msg = rp.feedback_instruction(res, sink_func="foo")
    assert "OUT OF BOUNDS" in msg


# --- accessor member-offset heuristic --------------------------------------
def test_accessor_member_offsets(monkeypatch):
    fake_disasm = """\
0000000000abc000 <checked_buffer_t::sget4(int)>:
  abc010:  mov    0x10(%r15),%ebx
  abc020:  cmp    %r12d,%ebx
  abc030:  add    0x8(%r15),%rsi
  abc040:  ret
0000000000abd000 <other>:
  abd000:  ret
"""
    monkeypatch.setattr(rp, "_run", lambda *a, **k: fake_disasm)
    off = rp.accessor_member_offsets("bin", "checked_buffer_t::sget4(int)")
    assert off == (0x8, 0x10)  # (base_off, size_off)


# --- gdb script synthesis ---------------------------------------------------
def test_build_probe_script_has_breakpoints_and_run():
    reads = [
        {
            "addr": "0x77ddce",
            "line": 229,
            "offset_expr": "$esi",
            "base_expr": "*(void**)($rdi+8)",
            "size_expr": "*(int*)($rdi+0x10)",
        }
    ]
    s = rp.build_probe_script(
        "/tmp/in", sink_line=229, src_hint="fuji.cpp", checkpoint_lines=[187, 226], read_sites=reads
    )
    assert "tbreak fuji.cpp:187" in s and "tbreak fuji.cpp:226" in s
    assert "break *0x77ddce" in s
    assert "run -runs=1 /tmp/in" in s
    assert "set pagination off" in s and s.strip().endswith("quit")


def test_remote_gdb_script_replaces_run_and_preserves_inferior_args():
    script, argv = rp._remote_gdb_script(
        "break parse\nrun -runs=1 '/tmp/a b'\nquit\n",
        "127.0.0.1:31337",
        ["ignored"],
    )
    assert "target remote 127.0.0.1:31337" in script
    assert "\ncontinue\n" in script
    assert "\nrun " not in script
    assert argv == ["-runs=1", "/tmp/a b"]


def test_qemu_gdb_backend_fails_closed_when_executable_is_missing(
    monkeypatch,
):
    sx.set_executor(sx.LocalExecutor())
    monkeypatch.setenv("ZEROVERSE_GDB_QEMU", "/missing/qemu-x86_64")
    monkeypatch.setattr(rp, "_gdb_available", lambda: True)
    try:
        output, code, timed_out = rp.run_gdb_batch(
            "/bin/target", "run\nquit\n", ["/tmp/input"]
        )
    finally:
        sx.reset_executor()
    assert "QEMU GDB stub executable not found" in output
    assert code is None and not timed_out


# --- probe() end-to-end with a fake gdb run --------------------------------
def test_probe_end_to_end_mocked(monkeypatch):
    monkeypatch.setattr(rp, "func_address_range", lambda b, f: (0x1000, 0x2000))
    monkeypatch.setattr(
        rp, "sink_source_lines", lambda b, r, src_hint="": {228: 0x1900, 229: 0x1910}
    )
    monkeypatch.setattr(
        rp, "reader_call_sites", lambda b, r: [(0x1910, "checked_buffer_t::sget4(int)")]
    )
    monkeypatch.setattr(rp, "run_gdb_batch", lambda *a, **k: (_GDB_CRASH, 0, False))

    # candidate carries -9 big-endian at offset 5 -> provenance should find it.
    candidate = b"\x00\x01\x02\x03\x04\xff\xff\xff\xf7\x10\x11" + b"\x00" * 8
    reads = [
        {"addr": "0x1910", "line": 229, "offset_expr": "$esi", "base_expr": "0", "size_expr": "0"}
    ]
    res = rp.probe(
        "bin",
        candidate,
        _SINK,
        src_hint="fuji.cpp",
        sink_line=229,
        read_site_exprs=reads,
        checkpoint_lines=[187, 226],
    )
    assert res.reached_func is True
    assert res.crashed is True
    # provenance located the -9 field the inner read returned.
    assert any(p.value == -9 and p.input_offset == 5 for p in res.provenance)


def test_probe_missing_function_errors(monkeypatch):
    monkeypatch.setattr(rp, "func_address_range", lambda b, f: None)
    res = rp.probe("bin", b"x", "nope")
    assert "not found" in res.error


def test_probe_fails_closed_outside_trusted_local() -> None:
    sx.set_executor(sx.DisabledExecutor("disabled for test"))
    try:
        res = rp.probe("/bin/target", b"x", "sink")
        assert "requires explicit trusted-local" in res.error
        output, code, timed_out = rp.run_gdb_batch("/bin/target", "quit", [])
        assert "requires explicit trusted-local" in output
        assert code is None and not timed_out
    finally:
        sx.reset_executor()

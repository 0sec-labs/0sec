"""deasan — strip ASan/coverage instrumentation from Ghidra pseudo-C.

Exercised on synthetic ASan-polluted bodies that mirror the real Ghidra shapes (a
shadow-byte load + slow-path ``if`` + ``__asan_report_*`` before each access,
``__sanitizer_cov_trace_*`` on every edge, ``__asan_memcpy`` interceptors,
``0x7fff8000`` shadow arithmetic). No Ghidra, no LLM — pure text transformation.

The load-bearing property: after deasan the REAL access/loop/store survives (so the
candidate lens can see it) while the instrumentation is gone.
"""

from __future__ import annotations

from zeroverse import deasan

# A shadow-check + report guarding a real load, the canonical injected shape.
_SHADOW_LOAD = """
uint read_count(long param_1)
{
  ulong uVar1;
  char cVar2;
  uVar1 = param_1 + 8 >> 3;
  cVar2 = *(char *)(uVar1 + 0x7fff8000);
  if (cVar2 != '\\0') {
    if ((char)((uint)(param_1 + 8) & 7) >= cVar2) {
      __asan_report_load4(param_1 + 8);
    }
  }
  return *(uint *)(param_1 + 8);
}
"""


def test_removes_shadow_check_and_report_keeps_access() -> None:
    out = deasan.deasan(_SHADOW_LOAD)
    assert "__asan_report" not in out
    assert "0x7fff8000" not in out
    # the REAL access survives
    assert "return *(uint *)(param_1 + 8);" in out


def test_removes_coverage_calls() -> None:
    body = """
void f(int *p,uint n)
{
  uint i;
  __sanitizer_cov_trace_pc_guard(&DAT_1);
  for (i = 0; i < n; i = i + 1) {
    __sanitizer_cov_trace_const_cmp4(0,i);
    p[i] = 0;
  }
  return;
}
"""
    out = deasan.deasan(body)
    assert "__sanitizer_cov" not in out
    assert "p[i] = 0;" in out  # the store survives
    assert "for (i = 0; i < n" in out  # the loop survives


def test_renames_interceptors_preserving_op() -> None:
    body = """
void g(void *dst,void *src,ulong n)
{
  __asan_memcpy(dst,src,n);
  __asan_memset(dst,0,n);
  return;
}
"""
    out = deasan.deasan(body)
    assert "__asan_memcpy" not in out and "__asan_memset" not in out
    assert "memcpy(dst,src,n);" in out
    assert "memset(dst,0,n);" in out


def test_deletes_shadow_offset_assignment() -> None:
    body = """
void h(long p)
{
  long lVar1;
  lVar1 = (long)p >> 3;
  *(char *)(lVar1 + 0x7fff8000);
  *(int *)p = 5;
  return;
}
"""
    out = deasan.deasan(body)
    assert "0x7fff8000" not in out
    assert "*(int *)p = 5;" in out  # real store kept


def test_non_instrumented_body_unchanged() -> None:
    body = "int add(int a,int b)\n{\n  return a + b;\n}\n"
    assert deasan.deasan(body) == body
    assert not deasan.is_asan_instrumented(body)


def test_conservative_keeps_real_logic_in_mixed_if() -> None:
    # An ``if`` that does REAL work AND happens to contain a report must NOT be
    # deleted wholesale — only the report statement is stripped.
    body = """
void k(int *buf,uint n,uint i)
{
  if (i < n) {
    __asan_report_store4(buf + i);
    buf[i] = 7;
  }
  return;
}
"""
    out = deasan.deasan(body)
    assert "__asan_report" not in out
    assert "buf[i] = 7;" in out  # real store kept
    assert "if (i < n)" in out  # real branch kept


def test_idempotent() -> None:
    once = deasan.deasan(_SHADOW_LOAD)
    twice = deasan.deasan(once)
    assert once == twice


def test_deasan_unbreaks_the_loop_oob_lens() -> None:
    # A tainted-count loop store (the loop-OOB shape) buried in ASan noise: shadow
    # checks + report branches + coverage on every access. The lens should miss the
    # polluted body but fire once deasan exposes the clean ``buf[i] = ...`` store.
    polluted = """
void WriteCLUT(int *out,uint *param_1,short *buf)
{
  uint i;
  ulong uVar1;
  char cVar2;
  i = 0;
  uVar1 = (ulong)param_1 >> 3;
  cVar2 = *(char *)(uVar1 + 0x7fff8000);
  if (cVar2 != '\\0') {
    __asan_report_load4(param_1);
  }
  while (i < *param_1) {
    __sanitizer_cov_trace_pc_guard(&DAT_2);
    uVar1 = (ulong)(buf + i) >> 3;
    if (*(char *)(uVar1 + 0x7fff8000) != '\\0') {
      __asan_report_store2(buf + i);
    }
    buf[i] = (short)i;
    i = i + 1;
  }
  return;
}
"""
    clean = deasan.deasan(polluted)
    assert "__asan" not in clean and "__sanitizer_cov" not in clean
    assert "0x7fff8000" not in clean
    assert "buf[i] = (short)i;" in clean
    assert "while (i < *param_1)" in clean
    # deasan_all convenience maps every body
    m = deasan.deasan_all({"WriteCLUT": polluted})
    assert m["WriteCLUT"] == clean


def test_deasan_strips_sanitizer_coverage_counter_bumps():
    """SanitizerCoverage inline-8bit-counter increments (`DAT_x = DAT_x + '\\x01';`)
    render on nearly every block and drown the real logic — the harfbuzz false-positive
    cause. deasan must strip them while keeping real `a = b + c` arithmetic."""
    from zeroverse.deasan import deasan, is_asan_instrumented

    body = (
        "void f(void){\n"
        "  DAT_00a2647c = DAT_00a2647c + '\\x01';\n"
        "  offset1 = offset_at(index + 1);\n"
        "  DAT_00a2647e = DAT_00a2647e + '\\x01';\n"
        "  if (offset1 > offset_at(count)) return;\n"  # the guard that must survive
        "  total = base + stride + 1;\n"  # real arithmetic, must survive
        "}\n"
    )
    assert is_asan_instrumented(body)  # cov-counter build detected
    out = deasan(body)
    assert "DAT_00a2647c" not in out and "DAT_00a2647e" not in out  # counters gone
    assert "if (offset1 > offset_at(count)) return;" in out  # guard preserved
    assert "total = base + stride + 1;" in out  # real arith preserved

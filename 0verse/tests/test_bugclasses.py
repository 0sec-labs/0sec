"""M4 bug-class lenses + confirming oracles (#22-#26).

Lens + funnel-tagging tests are hermetic (no compiler). The confirming-oracle
tests compile a tiny vulnerable + clean-control binary and assert a reproducing
PoV on the true positive AND a None on the control — gated on a C compiler so a
toolchain-less CI skips them instead of failing.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from zeroverse import bugclasses, oracle
from zeroverse.agent import MockLLM, TriageFunnel, Verdict
from zeroverse.bugclasses import (
    CONFIRMABLE_ORIGINS,
    cmdi_lens,
    confirm,
    cwe_for_finding,
    fmtstring_lens,
    intoverflow_lens,
    logic_lens,
    loop_oob_lens,
    prime_bugclasses,
    uaf_lens,
)

_HAS_CC = shutil.which("cc") or shutil.which("gcc")
requires_cc = pytest.mark.skipif(not _HAS_CC, reason="no C compiler for native oracle")
requires_linux_elf = pytest.mark.skipif(
    sys.platform != "linux", reason="native oracle proof builds and runs ELF"
)
_V = Verdict(is_real=True, bug_class="x", severity="high", explanation="", input_example="")


# --- lenses: each detects a true positive AND rejects a clean control -------

def test_intoverflow_lens_flags_size_multiply_into_alloc() -> None:
    hit = {"f": "void f(int n){char*p=malloc(n * 4);memcpy(p,s,n * 4);}"}
    out = intoverflow_lens(hit)
    assert len(out) == 1 and out[0].origin == "bugclass:intoverflow"
    # a plain malloc with a constant size and no size arithmetic is NOT flagged
    assert intoverflow_lens({"g": "void g(){char*p=malloc(16);strcpy(p,s);}"}) == []


def test_loop_oob_lens_flags_writeclut_shape() -> None:
    # for(i=0;i<n;i++) buf[i]=…  with n parsed from input — the lcms WriteCLUT
    # shape a memcpy/strcpy sink model misses. The loop bound is the untrusted
    # count; there is no clamp to the buffer's capacity.
    vuln = (
        "void wc(void){unsigned char buf[16];int n,i;"
        "fread(&n,4,1,stdin);"
        "for(i=0;i<n;i++){buf[i]=(unsigned char)i;}}"
    )
    out = loop_oob_lens({"wc": vuln})
    assert len(out) == 1
    assert out[0].origin == "bugclass:loop-oob"
    assert out[0].function == "wc" and out[0].sink.startswith("loop-store")


def test_loop_oob_lens_matches_decompiler_pseudo_c() -> None:
    # The exact rizin/r2ghidra ``pdg`` rendering of the reproducer: an out-param
    # fread into ``&iStack_28`` (the bound) and an array store in the loop body.
    vuln = (
        "uint32_t f(void){int iStack_2c;int iStack_28;uint8_t auStack_24 [16];"
        "iVar1 = fread(&iStack_28,4,1,x);"
        "if (iVar1 == 1) {"
        "for (iStack_2c = 0; iStack_2c < iStack_28; iStack_2c = iStack_2c + 1) {"
        "auStack_24[iStack_2c] = iStack_2c;}}return 0;}"
    )
    out = loop_oob_lens({"f": vuln})
    assert len(out) == 1 and out[0].origin == "bugclass:loop-oob"


def test_loop_oob_lens_rejects_bounds_checked_control() -> None:
    # Same loop, but the count is clamped to the buffer capacity before the loop
    # (``if (n > 16) n = 16;``) — a bounds-checked write must NOT fire.
    safe = (
        "void wc(void){unsigned char buf[16];int n,i;"
        "fread(&n,4,1,stdin);"
        "if (n > 16) n = 16;"
        "for(i=0;i<n;i++){buf[i]=(unsigned char)i;}}"
    )
    assert loop_oob_lens({"wc": safe}) == []
    # decompiler rendering of the same clamp (``if (0x10 < iStack_28) iStack_28 = 0x10;``)
    safe_dc = (
        "uint32_t f(void){int iStack_2c;int iStack_28;uint8_t auStack_24 [16];"
        "iVar1 = fread(&iStack_28,4,1,x);"
        "if (0x10 < iStack_28) {iStack_28 = 0x10;}"
        "for (iStack_2c = 0; iStack_2c < iStack_28; iStack_2c = iStack_2c + 1) {"
        "auStack_24[iStack_2c] = iStack_2c;}return 0;}"
    )
    assert loop_oob_lens({"f": safe_dc}) == []


def test_loop_oob_lens_requires_data_flow_to_a_source() -> None:
    # A loop-writer with NO untrusted source feeding the bound is not flagged:
    # precision guard so the lens does not fire on every ``buf[i]=…`` loop.
    no_source = (
        "void g(void){unsigned char buf[16];int n=get_const(),i;"
        "for(i=0;i<n;i++){buf[i]=(unsigned char)i;}}"
    )
    assert loop_oob_lens({"g": no_source}) == []
    # a compile-time-bounded loop (``i < 16``) is also not flagged even with input
    const_bound = (
        "void h(void){unsigned char buf[16];int i;char c;read(0,&c,1);"
        "for(i=0;i<16;i++){buf[i]=c;}}"
    )
    assert loop_oob_lens({"h": const_bound}) == []


def test_loop_oob_lens_flags_tainted_index() -> None:
    # The index itself is attacker-controlled (``buf[n]=…`` in a loop) — the
    # index-tainted branch of the link.
    vuln = (
        "void t(void){char buf[64];int n,k;read(0,&n,4);"
        "for(k=0;k<8;k++){buf[n]=k;n=n+1;}}"
    )
    out = loop_oob_lens({"t": vuln})
    assert len(out) == 1 and out[0].origin == "bugclass:loop-oob"


# --- #54 decompiled-shape extensions: each fires AND rejects a clean control -

def test_loop_oob_lens_flags_cast_index_store() -> None:
    # Extension #1: the decompiler renders a signed index as a cast — the store is
    # ``buf[(int)idx] = …`` (not the bare ``buf[idx] = …``). The index identifier
    # is extracted through the cast; the tainted bound then links.
    vuln = (
        "void f(void){char buf[16];int n,i;read(0,&n,4);"
        "for(i=0;i<n;i=i+1){buf[(int)i]=(char)i;}}"
    )
    out = loop_oob_lens({"f": vuln})
    assert len(out) == 1 and out[0].origin == "bugclass:loop-oob"
    # clean control: same cast-index store, but the count is clamped to capacity.
    safe = (
        "void g(void){char buf[16];int n,i;read(0,&n,4);"
        "if (n > 16) n = 16;"
        "for(i=0;i<n;i=i+1){buf[(int)i]=(char)i;}}"
    )
    assert loop_oob_lens({"g": safe}) == []


def test_loop_oob_lens_flags_pointer_arith_store() -> None:
    # Extension #1: a pointer-arithmetic store ``*(T *)(base + idx*stride) = …`` —
    # the store form the array-index shape misses. ``base`` is the destination.
    vuln = (
        "void f(void){char base[16];int n,i;read(0,&n,4);"
        "for(i=0;i<n;i=i+1){*(short *)(base + (int)i * 2)=(short)i;}}"
    )
    out = loop_oob_lens({"f": vuln})
    assert len(out) == 1 and out[0].origin == "bugclass:loop-oob"
    # clean control: the same store, bounds-checked count -> no finding.
    safe = (
        "void g(void){char base[16];int n,i;read(0,&n,4);"
        "if (n >= 8) n = 8;"
        "for(i=0;i<n;i=i+1){*(short *)(base + (int)i * 2)=(short)i;}}"
    )
    assert loop_oob_lens({"g": safe}) == []


def test_loop_oob_lens_flags_ne_terminated_cursor_loop() -> None:
    # Extension #2: a ``do{…}while(cursor != end)`` cursor loop (the exact lcms
    # ``OutputValueSampler`` shape). ``end`` is the bound-analog of the cursor; here
    # it is a tainted count, so the write links.
    vuln = (
        "void f(void){char buf[16];int n,i;read(0,&n,4);i=0;"
        "do{buf[i]=(char)i;i=i+1;}while(i != n);}"
    )
    out = loop_oob_lens({"f": vuln})
    assert len(out) == 1 and out[0].origin == "bugclass:loop-oob"
    # clean control: same cursor loop, but the end is clamped to capacity.
    safe = (
        "void g(void){char buf[16];int n,i;read(0,&n,4);"
        "if (n > 16) n = 16;i=0;"
        "do{buf[i]=(char)i;i=i+1;}while(i != n);}"
    )
    assert loop_oob_lens({"g": safe}) == []


def test_loop_oob_lens_flags_outparam_derived_bound() -> None:
    # Extension #3: the loop bound ``m`` is filled by a *library out-param*
    # (``get_count(&m,…)`` — the ``_cmsEndPointsBySpace(&n,…)`` shape), not by a
    # recognized input source. Treated as untrusted-derived because it feeds the
    # loop bound, so the unclamped write fires with NO callgraph.
    vuln = (
        "void f(void){char buf[16];int m,i;get_count(&m,buf);"
        "for(i=0;i<m;i=i+1){buf[i]=(char)i;}}"
    )
    out = loop_oob_lens({"f": vuln})
    assert len(out) == 1 and out[0].origin == "bugclass:loop-oob"
    assert out[0].sink.endswith(":outparam")
    # clean control: same out-param bound, but clamped to the buffer capacity.
    safe = (
        "void g(void){char buf[16];int m,i;get_count(&m,buf);"
        "if (m > 16) m = 16;"
        "for(i=0;i<m;i=i+1){buf[i]=(char)i;}}"
    )
    assert loop_oob_lens({"g": safe}) == []
    # precision: an out-param that does NOT feed a loop bound is not tainted here.
    unrelated = (
        "void h(void){char buf[16];int m,i;get_count(&m,buf);"
        "for(i=0;i<16;i=i+1){buf[i]=(char)i;}}"
    )
    assert loop_oob_lens({"h": unrelated}) == []


def test_loop_oob_lens_matches_real_output_value_sampler_shape() -> None:
    # The exact rizin/Ghidra rendering of the lcms ``OutputValueSampler`` OOB the
    # source-shaped lens missed: an out-param bound (``_cmsEndPointsBySpace(...,
    # &local_14,...)``), a cast-index store (``In[(int)pcVar4] = …``), and a
    # ``do{…}while(local_14 != pcVar4)`` cursor loop — all three extensions at once.
    vuln = (
        "int OutputValueSampler(cmsUInt16Number *In,cmsUInt16Number *Out,void *Cargo){"
        "cmsBool cVar2;cmsUInt16Number *pcVar4;int local_18;cmsUInt16Number *local_14;"
        "cmsUInt16Number *local_28;"
        "cVar2 = _cmsEndPointsBySpace((cmsColorSpaceSignature)&local_18,&local_28,"
        "&local_14,in_stack_ffffffd4);"
        "if (cVar2 != 0) {"
        "if (local_14 != (cmsUInt16Number *)0x0) {"
        "pcVar4 = (cmsUInt16Number *)0x0;"
        "do {"
        "In[(int)pcVar4] = *(cmsUInt16Number *)(local_18 + (int)pcVar4 * 2);"
        "pcVar4 = (cmsUInt16Number *)((int)pcVar4 + 1);"
        "} while (local_14 != pcVar4);}}"
        "return 0;}"
    )
    out = loop_oob_lens({"OutputValueSampler": vuln})
    assert len(out) == 1
    assert out[0].origin == "bugclass:loop-oob"
    assert out[0].function == "OutputValueSampler"
    assert out[0].sink.startswith("loop-store") and out[0].sink.endswith(":outparam")


def test_loop_oob_interproc_taint_crosses_call_boundary() -> None:
    # #53: the loop bound ``n`` is a PARAMETER of ``writer`` — its taint lives in
    # the CALLER ``main`` (``read(0,&n,4)`` then ``writer(buf,n)``). Intra-function
    # taint declines (writer has no source); with a callgraph the inter-proc walk
    # marks the parameter tainted and the lens fires on ``writer`` — the real lcms
    # ``WriteCLUT``/``nSamples`` shape.
    dc = {
        "writer": (
            "void writer(char *buf,int n){int i;"
            "for(i=0;i<n;i=i+1){buf[i]=(char)i;}}"
        ),
        "main": (
            "int main(void){char buf[16];int n;"
            "read(0,&n,4);writer(buf,n);return 0;}"
        ),
    }
    cg = {"main": ["writer"]}
    # without the callgraph: the parameter bound can't be linked -> no finding.
    assert loop_oob_lens(dc) == []
    # with the callgraph: inter-proc taint fires on ``writer``.
    out = loop_oob_lens(dc, cg)
    assert len(out) == 1
    assert out[0].function == "writer" and out[0].origin == "bugclass:loop-oob"
    assert out[0].sink.endswith(":interproc")


def test_loop_oob_interproc_respects_bounds_check() -> None:
    # Same inter-proc shape, but ``writer`` clamps the parameter to the buffer
    # capacity (``if (n > 16) n = 16;``) before the loop — a bounds-checked write
    # must NOT fire even though the caller feeds untrusted data.
    dc = {
        "writer": (
            "void writer(char *buf,int n){int i;"
            "if (n > 16) n = 16;"
            "for(i=0;i<n;i=i+1){buf[i]=(char)i;}}"
        ),
        "main": (
            "int main(void){char buf[16];int n;"
            "read(0,&n,4);writer(buf,n);return 0;}"
        ),
    }
    cg = {"main": ["writer"]}
    assert loop_oob_lens(dc, cg) == []


def test_loop_oob_interproc_declines_untainted_caller_arg() -> None:
    # The caller passes a CONSTANT (not untrusted) into the parameter bound — the
    # inter-proc walk must decline (no false positive on a clean count).
    dc = {
        "writer": (
            "void writer(char *buf,int n){int i;"
            "for(i=0;i<n;i=i+1){buf[i]=(char)i;}}"
        ),
        "main": "int main(void){char buf[16];writer(buf,16);return 0;}",
    }
    cg = {"main": ["writer"]}
    assert loop_oob_lens(dc, cg) == []


def test_loop_oob_is_registered_and_confirmable() -> None:
    assert any(bc.id == "loop-oob" for bc in bugclasses.BUG_CLASSES)
    assert bugclasses.LOOP_OOB.origin in CONFIRMABLE_ORIGINS
    hyps = prime_bugclasses({
        "wc": "void wc(void){unsigned char buf[16];int n,i;fread(&n,4,1,stdin);"
              "for(i=0;i<n;i++){buf[i]=(unsigned char)i;}}"
    })
    assert any(h.origin == "bugclass:loop-oob" for h in hyps)


def test_intoverflow_lens_reports_overflowing_copy_sink_not_alloc() -> None:
    # IO sink-attribution (regression): a wrapped size feeds malloc AND the copy
    # that overflows it — the finding must land on the COPY (memcpy), where the
    # OOB write happens and the labeled bug lives, not on the allocation.
    decomp = (
        "int main(void){uint16_t c,e;read(0,&c,4);unsigned short t=(unsigned short)"
        "(c * e);char*p=malloc(t?t:1);memcpy(p,body,(size_t)c * e);return p[0];}"
    )
    out = intoverflow_lens({"main": decomp})
    assert len(out) == 1 and out[0].function == "main"
    assert out[0].sink == "memcpy"  # NOT "malloc"
    # control: a size-arith malloc with no copy sink still reports the allocation
    alloc_only = intoverflow_lens({"g": "void g(int n){char*p=malloc(n * 4);use(p);}"})
    assert len(alloc_only) == 1 and alloc_only[0].sink == "malloc"


def test_fmtstring_lens_flags_tainted_format_only() -> None:
    out = fmtstring_lens({"f": "void f(char*s){printf(s);}"})
    assert len(out) == 1 and out[0].sink == "printf"
    # a string-literal format (even with %d args) is safe — not flagged
    assert fmtstring_lens({"g": 'void g(int x){printf("n=%d", x);}'}) == []
    assert fmtstring_lens({"h": 'void h(char*s){fprintf(stderr, "%s", s);}'}) == []


def test_fmtstring_lens_flags_address_of_local_buffer() -> None:
    # FS address-of-local (regression): a decompiler renders ``printf(stack_buf)``
    # as ``printf(&format, ...)`` — the address of a tainted stack buffer in the
    # format position IS the CWE-134 shape and must fire.
    vuln = {"main": "ulong main(void){char *format;read(0,&format,0xff);"
                    "printf(&format,&format);return 0;}"}
    out = fmtstring_lens(vuln)
    assert len(out) == 1 and out[0].function == "main" and out[0].sink == "printf"
    # clean control: the address of a .rodata constant (the "%s" fix / literal
    # format) must stay suppressed — no false positive.
    assert fmtstring_lens(
        {"f": "void f(char *b){printf(&DAT_00402004,b);}"}
    ) == []
    assert fmtstring_lens({"g": "void g(char *b){printf(0x402004,b);}"}) == []


def test_uaf_lens_flags_use_and_double_free() -> None:
    uaf = uaf_lens({"f": "void f(){char*p=malloc(8);free(p);p[0]=1;}"})
    assert len(uaf) == 1 and "use-after-free" in uaf[0].sink
    df = uaf_lens({"g": "void g(){char*p=malloc(8);free(p);free(p);}"})
    assert len(df) == 1 and "double-free" in df[0].sink
    # a single free with no later use is clean
    assert uaf_lens({"h": "void h(){char*p=malloc(8);free(p);}"}) == []


def test_uaf_lens_covers_non_libc_free_families_and_casts() -> None:
    # lcms pool free: the freed pointer is the SECOND arg (after the context handle).
    cms = uaf_lens({"f": "void f(void*c){void*p=_cmsMalloc(c,8);_cmsFree(c,p);"
                         "*(char*)p=1;}"})
    assert len(cms) == 1 and "use-after-free(p)" in cms[0].sink
    # C++ delete, as Ghidra lowers it: operator.delete(p) then a member use.
    cpp = uaf_lens({"g": "void g(){Obj*p=mk();operator.delete(p);p->field=1;}"})
    assert len(cpp) == 1 and "use-after-free(p)" in cpp[0].sink
    # a cast on the freed pointer must be stripped: free((void *)p) then index.
    cast = uaf_lens({"h": "void h(){char*p=malloc(8);free((void *)p);p[3]=1;}"})
    assert len(cast) == 1 and "use-after-free(p)" in cast[0].sink
    # g_free must not be double-counted by the bare `free` matcher (no false DF).
    gf = uaf_lens({"k": "void k(){char*p=g_malloc(8);g_free(p);p[0]=1;}"})
    assert len(gf) == 1 and "use-after-free(p)" in gf[0].sink


def test_uaf_lens_flags_refcount_drop_then_use() -> None:
    # kernel refcount put then a deref of the same object.
    put = uaf_lens({"f": "void f(struct s*o){kref_put(&o->ref);o->x=1;}"})
    assert len(put) == 1 and "conditional-free-use" in put[0].sink
    # lcms CamelCase unref (the decompiled form with no underscore before Unref).
    cms = uaf_lens({"g": "void g(void*o){_cmsUnref(o);*(int*)o=1;}"})
    assert len(cms) == 1 and "conditional-free-use(o)" in cms[0].sink


def test_uaf_lens_flags_realloc_move_and_suppresses_reassign() -> None:
    # UAF-03: q = realloc(p,..) frees+moves p; the stale alias p is a UAF.
    mv = uaf_lens({"f": "void f(char*p){char*q=realloc(p,64);p[0]=1;(void)q;}"})
    assert len(mv) == 1 and "realloc-stale-pointer(p)" in mv[0].sink
    # safe: p = realloc(p,..) reassigns the same var — not a stale alias.
    assert uaf_lens({"g": "void g(char*p){p=realloc(p,64);p[0]=1;}"}) == []


def test_uaf_lens_clean_controls_do_not_overflag() -> None:
    # use BEFORE free is not a UAF (the use precedes the lifetime end).
    assert uaf_lens({"a": "void a(){char*p=malloc(8);p[0]=1;free(p);}"}) == []
    # reassigned to a fresh allocation after free, THEN used — safe.
    assert uaf_lens(
        {"b": "void b(){char*p=malloc(8);free(p);p=malloc(8);p[0]=1;}"}
    ) == []
    # freed, NULLed, then used — the classic suppressor.
    assert uaf_lens({"c": "void c(){char*p=malloc(8);free(p);p=NULL;use(p);}"}) == []
    # freed, reassigned to a NEW object, then freed again — NOT a double-free.
    assert uaf_lens(
        {"d": "void d(){char*p=malloc(8);free(p);p=malloc(8);free(p);}"}
    ) == []


def test_uaf_cwe_splits_double_free_415_from_use_after_free_416() -> None:
    uaf = uaf_lens({"f": "void f(){char*p=malloc(8);free(p);p[0]=1;}"})[0]
    assert cwe_for_finding(uaf) == "CWE-416"
    df = uaf_lens({"g": "void g(){char*p=malloc(8);free(p);free(p);}"})[0]
    assert cwe_for_finding(df) == "CWE-415"


def test_cmdi_lens_flags_tainted_command_only() -> None:
    out = cmdi_lens({"f": "void f(char*c){system(c);}"})
    assert len(out) == 1 and out[0].origin == "bugclass:cmdi"
    assert cmdi_lens({"g": 'void g(){system("/bin/ls");}'}) == []


def test_logic_lens_is_hypothesis_only_and_high_recall() -> None:
    auth = "int chk(char*password){return strcmp(secret,password)==0;}"
    out = logic_lens({"chk": auth})
    assert len(out) == 1 and out[0].origin == "bugclass:logic"
    # the logic class is never confirmable
    assert "bugclass:logic" not in CONFIRMABLE_ORIGINS
    # a plain numeric loop with no auth/off-by-one is not flagged
    clean = "int s(int*a,int n){int t=0;for(int i=0;i<n;i++)t+=a[i];return t;}"
    assert logic_lens({"s": clean}) == []


# --- funnel: bug-class hypotheses are tagged and survive triage -------------

def test_prime_bugclasses_tags_all_classes() -> None:
    decomp = {
        "io": "void io(int n){char*p=malloc(n * 8);memcpy(p,s,n * 8);}",
        "ovf": "void ovf(char*s){char b[8]; stpcpy(b, s);}",
        "fmt": "void fmt(char*s){syslog(3, s);}",
        "uaf": "void uaf(){char*p=malloc(8);free(p);return p[0];}",
        "cmd": "void cmd(char*c){popen(c,\"r\");}",
        "auth": "int a(char*pw){return strcmp(secret,pw)==0;}",
    }
    hyps = prime_bugclasses(decomp)
    origins = {h.origin for h in hyps}
    assert origins == {
        "bugclass:overflow", "bugclass:intoverflow", "bugclass:fmtstring",
        "bugclass:uaf", "bugclass:cmdi", "bugclass:logic",
    }


def test_funnel_preserves_bugclass_origin() -> None:
    decomp = {"cmd": "void cmd(char*c){system(c);}",
              "auth": "int a(char*pw){return strcmp(secret,pw)==0;}"}
    hyps = prime_bugclasses(decomp)
    ranked = TriageFunnel(MockLLM()).run(hyps, lambda f: "ctx")
    ranked_origins = {r.finding.origin for r in ranked}
    assert "bugclass:cmdi" in ranked_origins
    assert "bugclass:logic" in ranked_origins


def test_confirm_declines_logic_class() -> None:
    # logic has no generic oracle — confirm must NEVER claim it (no false PoV).
    f = logic_lens({"a": "int a(char*pw){return strcmp(secret,pw)==0;}"})[0]
    assert confirm(f, _V, "/bin/true") is None


def test_cmdi_confirmation_threads_planned_native_compiler_to_exec_trap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    src = "void parse(char *command) { system(command); }"
    finding = cmdi_lens({"parse": src})[0]
    calls: list[dict[str, object]] = []

    def fake_exectrap(*args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(kwargs)
        return {}

    monkeypatch.setattr(oracle, "exectrap_env", fake_exectrap)
    assert confirm(
        finding,
        Verdict(True, "CWE-78", "high", "", "command"),
        "/bin/true",
        compiler_path="/planned/native-cc",
        compiler_resolved=True,
    ) is None
    assert calls[0]["compiler_path"] == "/planned/native-cc"
    assert calls[0]["compiler_resolved"] is True



def _cc(src: str, out: Path, *flags: str) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    binp = out / "t"
    (out / "t.c").write_text(src)
    subprocess.run(["cc", "-O0", "-fno-stack-protector", "-no-pie", *flags,
                    str(out / "t.c"), "-o", str(binp)], check=True, capture_output=True)
    return binp


@requires_cc
def test_confirm_cmdi_canary(tmp_path: Path) -> None:
    src = '#include <stdlib.h>\nint main(void){system(getenv("CMD"));return 0;}\n'
    binp = _cc(src, tmp_path)
    f = cmdi_lens({"main": src})[0]
    pov = confirm(f, Verdict(True, "x", "high", "", 'CMD="; id"'), binp)
    assert pov is not None and pov.reproduced
    assert pov.capability == "reached-sink" and "CMD" in pov.env


@requires_cc
def test_confirm_fmtstring_crash_vs_clean(tmp_path: Path) -> None:
    src = ('#include <stdio.h>\n#include <unistd.h>\n'
           'int main(void){char b[256]={0};int n=read(0,b,255);if(n<0)n=0;b[n]=0;'
           'printf(b);return 0;}\n')
    binp = _cc(src, tmp_path)
    f = fmtstring_lens({"main": src})[0]
    pov = confirm(f, _V, binp, control=b"hello")
    assert pov is not None and pov.reproduced and pov.capability == "oob-read"


@requires_cc
@requires_linux_elf
def test_confirm_intoverflow_heap_oob(tmp_path: Path) -> None:
    src = ('#include <stdint.h>\n#include <stdlib.h>\n#include <string.h>\n#include <unistd.h>\n'
           'int main(void){unsigned char h[4]={0};if(read(0,h,4)<0)return 1;'
           'uint16_t c=(uint16_t)(h[0]|(h[1]<<8)),e=(uint16_t)(h[2]|(h[3]<<8));'
           'unsigned short t=(unsigned short)(c * e);char*p=malloc(t?t:1);'
           'static unsigned char body[70000];int bn=read(0,body,sizeof body);if(bn<0)bn=0;'
           'memcpy(p,body,(size_t)c * e);return p[0];}\n')
    binp = _cc(src, tmp_path)
    f = intoverflow_lens({"main": src})[0]
    pov = confirm(f, _V, binp, trigger=b"\x00\x01\x00\x01" + b"A" * 16)
    assert pov is not None and pov.reproduced
    assert pov.capability == "oob-write" and pov.env  # guard env carried


@requires_cc
@requires_linux_elf
def test_confirm_uaf_and_double_free(tmp_path: Path) -> None:
    uaf_src = ('#include <stdlib.h>\n#include <unistd.h>\n'
               'int main(void){char*p=malloc(64);free(p);char in[4]={0};'
               'int n=read(0,in,3);if(n<0)n=0;in[n]=0;'
               'if(in[0]==\'X\'){p[0]=1;return p[1];}return 0;}\n')
    binp = _cc(uaf_src, tmp_path / "u")
    f = uaf_lens({"main": uaf_src})[0]
    pov = confirm(f, _V, binp, trigger=b"X", control=b"n")
    assert pov is not None and pov.reproduced
    # control input does not crash -> confirm rejects a clean run
    assert confirm(f, _V, binp, trigger=b"n", control=b"n") is None

    df_src = ('#include <stdlib.h>\n#include <unistd.h>\n'
              'int main(void){char*p=malloc(32);free(p);char in[4]={0};'
              'int n=read(0,in,3);if(n<0)n=0;in[n]=0;if(in[0]==\'X\')free(p);return 0;}\n')
    dbin = _cc(df_src, tmp_path / "d")
    df = uaf_lens({"main": df_src})[0]
    dpov = confirm(df, _V, dbin, trigger=b"X", control=b"n")
    assert dpov is not None and dpov.reproduced


def test_confirmable_origins_exclude_logic() -> None:
    assert bugclasses.INTOVERFLOW.origin in CONFIRMABLE_ORIGINS
    assert bugclasses.FMTSTRING.origin in CONFIRMABLE_ORIGINS
    assert bugclasses.UAF.origin in CONFIRMABLE_ORIGINS
    assert bugclasses.CMDI.origin in CONFIRMABLE_ORIGINS
    assert bugclasses.LOGIC.origin not in CONFIRMABLE_ORIGINS


def test_uaf_lens_catches_cast_ptr_arith_read_after_free():
    """The decompiled read idiom for a freed pointer (GCC -O1 inlined case):
    `*(byte *)((long)p + off)` — a deref-through-cast + pointer-arith READ. The
    end-to-end UAF validation showed the lens was blind to exactly this shape."""
    from zeroverse.bugclasses import uaf_lens
    hit = {"f": "void f(int i){char *p=malloc(8); free(p); "
                "x=*(byte *)((long)p + i); use(x);}"}
    assert len(uaf_lens(hit)) >= 1
    # not a deref of p — p's value used in arithmetic next to another deref: no over-flag
    assert uaf_lens({"f": "void f(){char *p=malloc(8); free(p); x = *q + p;}"}) == []
    # reassigned after free, then the idiom on the NEW allocation: safe (suppressor)
    assert uaf_lens({"f": "void f(){char *p=malloc(8); free(p); p=malloc(16); "
                          "y=*(byte*)((long)p+1);}"}) == []

"""Phase-B seed-enrichment: kernel seed-classes, the userland lens upgrades, the
exec-trap cmdi oracle, firmware seed framing, and the data-driven seed registry.

Every upgrade proves the NEW pattern fires AND a clean control does NOT (the
ASSUME-FP discipline). Oracle tests that need a C toolchain are gated so a
compiler-less CI skips rather than fails.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from zeroverse import oracle, seedbugs
from zeroverse import seedcatalog as sc
from zeroverse.agent import Verdict
from zeroverse.analyze import Finding
from zeroverse.bugclasses import (
    BUG_CLASSES,
    CONFIRMABLE_ORIGINS,
    cmdi_lens,
    confirm,
    fmtstring_lens,
    intoverflow_lens,
    overflow_lens,
    prime_bugclasses,
    uaf_lens,
)

_HAS_CC = shutil.which("cc") or shutil.which("gcc")
requires_cc = pytest.mark.skipif(not _HAS_CC, reason="no C compiler for native oracle")
requires_linux_elf = pytest.mark.skipif(
    sys.platform != "linux", reason="exec-trap proof builds and runs ELF"
)


def _cc(src: str, out: Path, *flags: str) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    (out / "t.c").write_text(src)
    binp = out / "t"
    subprocess.run(["cc", "-O0", "-fno-stack-protector", "-no-pie", *flags,
                    str(out / "t.c"), "-o", str(binp)], check=True, capture_output=True)
    return binp


# === 1. Kernel seed-classes (statically-strong .ko archetypes) =============

def test_drv01_selector_index_indirect_call() -> None:
    vuln = ("long FUN_1(undefined8 p1,uint cmd,undefined8 arg){_copy_from_user(&p1,arg,8);"
            "return (*(code *)(*(long *)(handlers + (ulong)cmd * 8)))(p1,arg);}")
    ok, _, sink = seedbugs.LINUX_KO_SELECTOR_INDEX.matches(vuln)
    assert ok and "handlers" in sink
    # no indirect call at all -> not a candidate
    clean = "long f(undefined8 a){_copy_from_user(&a,a,8); return table_lookup(a);}"
    assert seedbugs.LINUX_KO_SELECTOR_INDEX.matches(clean)[0] is False


def test_drv07_double_fetch_vs_single() -> None:
    df = ("long FUN(undefined8 p,uint c,undefined8 u){uint sz;_copy_from_user(&sz,u,4);"
          "if(sz>0x100)return -22;char b[256];_copy_from_user(b,u,sz);return 0;}")
    assert seedbugs.LINUX_KO_DOUBLE_FETCH.matches(df)[0] is True
    single = "long f(undefined8 u){char b[8];_copy_from_user(b,u,8);return 0;}"
    assert seedbugs.LINUX_KO_DOUBLE_FETCH.matches(single)[0] is False


def test_drv08_mmap_pgoff_unbounded() -> None:
    vuln = ("int FUN_mmap(undefined8 filp,long vma){ulong pgoff=*(ulong*)(vma+0x20);"
            "return remap_pfn_range(vma,*(ulong*)(vma+8),pgoff,0x1000,0);}")
    assert seedbugs.LINUX_KO_MMAP_PGOFF.matches(vuln)[0] is True
    # a non-mmap function with no remap sink is not a candidate
    clean = "int f(long vma){return copy_from_user(vma,vma,8);}"
    assert seedbugs.LINUX_KO_MMAP_PGOFF.matches(clean)[0] is False


def test_mm03_infoleak_missing_memset() -> None:
    leak = ("long FUN(undefined8 u){void* p=__kmalloc_noprof(64,0xcc0);fill(p);"
            "return _copy_to_user(u,p,64);}")
    assert seedbugs.LINUX_KO_INFOLEAK.matches(leak)[0] is True
    zeroed = leak.replace("fill(p);", "memset(p,0,64);")
    assert seedbugs.LINUX_KO_INFOLEAK.matches(zeroed)[0] is False  # memset suppresses


def test_nf03_netlink_oob() -> None:
    vuln = ("long FUN(long attr){u32 n=nla_get_u32(attr);char b[32];"
            "memcpy(b,nla_data(attr),n);return 0;}")
    assert seedbugs.LINUX_KO_NETLINK_OOB.matches(vuln)[0] is True
    # a memcpy with no netlink getter is not this class
    clean = "long f(long a){char b[32];memcpy(b,a,8);return 0;}"
    assert seedbugs.LINUX_KO_NETLINK_OOB.matches(clean)[0] is False


def test_kernel_verify_hypotheses_are_routed_not_confirmable() -> None:
    routed = [c for c in seedbugs.SEED_CLASSES if c.route == "kernel-verify"]
    assert {c.id for c in routed} == {
        "linux-ko:deferred-free-uaf", "linux-ko:refcount-uaf",
        "linux-ko:errpath-double-free",
    }
    # deferred-free shape fires as a hypothesis (routed to verify lane)
    assert seedbugs.LINUX_KO_DEFERRED_FREE_UAF.matches(
        "void cb(long o){list_del(o);call_rcu(&o->rcu,kfree);kfree(o);}")[0] is True


# === 2. Firmware seed framing ============================================

def test_firmware_seeds_primed_by_arch_only() -> None:
    assert [c.id for c in seedbugs.firmware_seeds_for_arch("mips")] == [
        "firmware:cgi-cmdi", "firmware:stack-overflow"]
    assert seedbugs.firmware_seeds_for_arch("x86_64") == []
    assert seedbugs.firmware_seeds_for_arch(None) == []
    # firmware seeds never leak into the .ko (KMOD) lane
    assert all(not c.id.startswith("firmware:")
               for c in seedbugs.seeds_for_target("ELF", "KMOD"))


def test_firmware_cgi_cmdi_getter_to_shell() -> None:
    vuln = ('int cgiMain(){char*h=websGetVar(req,"ip",0);char c[128];'
            'sprintf(c,"ping %s",h);system(c);}')
    assert seedbugs.FIRMWARE_CGI_CMDI.matches(vuln)[0] is True
    # a system() with no request getter is not the firmware cmdi shape
    assert seedbugs.FIRMWARE_CGI_CMDI.matches('int f(){system("/sbin/reboot");}')[0] is False


# === 3. uaf lens — realloc-as-free + conditional frees ===================

def test_uaf_realloc_stale_pointer() -> None:
    out = uaf_lens({"f": "void f(char*p){char*q=realloc(p,128);use(p);}"})
    assert len(out) == 1 and "realloc-stale-pointer" in out[0].sink
    # reassigning to the same var is the safe idiom — not flagged
    assert uaf_lens({"g": "void g(char*p){p=realloc(p,128);use(p);}"}) == []


def test_uaf_conditional_refcount_free() -> None:
    out = uaf_lens({"f": "void f(struct s*o){kref_put(&o->ref);o->x=1;}"})
    assert len(out) == 1 and "conditional-free-use" in out[0].sink
    # put with no later use of the object is clean
    assert uaf_lens({"g": "void g(struct s*o){kref_put(&o->ref);}"}) == []


# === 4. intoverflow — signed/unsigned, additive, calloc downgrade ========

def test_intoverflow_signed_unsigned_cwe839() -> None:
    vuln = ("int f(){int len;read(0,&len,4);if(len>1024)return 0;"
            "char b[1024];memcpy(b,s,len);}")
    out = intoverflow_lens({"f": vuln})
    assert len(out) == 1 and out[0].sink.endswith("signed-unsigned")
    # a present lower-bound (len<0) is the FP-suppressor
    guarded = vuln.replace("if(len>1024)", "if(len>1024||len<0)")
    assert intoverflow_lens({"f": guarded}) == []


def test_intoverflow_additive_and_calloc_downgrade() -> None:
    add = "void f(int a,int b){int size=a+b;char*p=malloc(size);}"
    out = intoverflow_lens({"f": add})
    assert len(out) == 1 and out[0].sink.endswith("additive-wrap")
    # calloc(a, b) is self-guarded — not an int-overflow sink
    assert intoverflow_lens({"g": "void g(int a,int b){void*p=calloc(a,b);}"}) == []


# === 5. fmtstring — correct per-function arg position ====================

def test_fmtstring_warn_is_arg0_err_is_arg1() -> None:
    assert len(fmtstring_lens({"f": "void f(char*s){warn(s);}"})) == 1
    assert fmtstring_lens({"g": 'void g(char*s){warn("ok %s", s);}'}) == []  # literal
    assert len(fmtstring_lens({"h": "void h(int e,char*s){err(e,s);}"})) == 1
    assert len(fmtstring_lens({"i": "void i(char*s){vsyslog(3,s,ap);}"})) == 1


# === 6. cmdi — argv-injection (CWE-88) ===================================

def test_cmdi_argv_injection_vs_constant() -> None:
    vuln = 'void f(char*u){char*av[]={"git",u,0};execv("/usr/bin/git",av);}'
    out = cmdi_lens({"f": vuln})
    assert len(out) == 1 and "argv-injection" in out[0].sink
    const = 'void f(){char*av[]={"git","log",0};execv("/usr/bin/git",av);}'
    assert cmdi_lens({"g": const}) == []  # constant argv -> not flagged


# === 7. overflow lens (new) =============================================

def test_overflow_lens_string_sinks_and_loop_writer() -> None:
    assert len(overflow_lens({"f": "void f(char*s){char b[8];stpcpy(b,s);}"})) == 1
    assert len(overflow_lens({"f": 'void f(char*s){char b[8];sprintf(b,"x=%s",s);}'})) == 1
    # a sprintf with only %d (no tainted %s) is not an overflow expansion
    assert overflow_lens({"g": 'void g(){char b[8];sprintf(b,"x=%d",4);}'}) == []
    assert len(overflow_lens({"f": "void f(char*d,char*s){strlcat(d,s,8);}"})) == 1
    loop = ("void f(){char b[8];int n=recv(0,t,99,0);"
            "for(int i=0;i<n;i++){*p++ = t[i];}}")
    assert len(overflow_lens({"f": loop})) == 1
    clean = "int s(int*a,int n){int t=0;for(int i=0;i<n;i++)t+=a[i];return t;}"
    assert overflow_lens({"s": clean}) == []


def test_overflow_class_is_registered_and_confirmable() -> None:
    assert any(bc.id == "overflow" for bc in BUG_CLASSES)
    assert "bugclass:overflow" in CONFIRMABLE_ORIGINS


def test_prime_bugclasses_includes_overflow() -> None:
    hyps = prime_bugclasses({"of": "void of(char*s){char b[8];stpcpy(b,s);}"})
    assert any(h.origin == "bugclass:overflow" for h in hyps)


# === 8. exec-trap cmdi oracle (the new confirming channel) ===============

@requires_cc
@requires_linux_elf
def test_exectrap_confirms_shell_cmdi(tmp_path: Path) -> None:
    src = ('#include <stdlib.h>\n#include <stdio.h>\n'
           'int main(void){char c[256];snprintf(c,256,"ping %s",getenv("HOST"));'
           'system(c);return 0;}\n')
    binp = _cc(src, tmp_path)
    f = cmdi_lens({"main": src})[0]
    pov = confirm(f, Verdict(True, "x", "high", "", "HOST=x"), binp)
    assert pov is not None and pov.reproduced
    assert pov.capability == "reached-sink" and pov.crash_class == "command-injection"


@requires_cc
def test_exectrap_confirms_argv_injection_no_shell(tmp_path: Path) -> None:
    # CWE-88: nothing is echoed; only the exec-trap can see this injection.
    src = ('#include <unistd.h>\n#include <string.h>\n'
           'int main(void){char in[256];long n=read(0,in,255);if(n<0)n=0;in[n]=0;'
           'char*nl=strchr(in,\'\\n\');if(nl)*nl=0;'
           'char*av[]={"echo","--opt",in,0};execvp("echo",av);return 0;}\n')
    binp = _cc(src, tmp_path)
    f = Finding(source="read", sink="execvp", function="main",
                source_addr=0, sink_addr=0, path_len=0, origin="bugclass:cmdi")
    pov = confirm(f, Verdict(True, "x", "high", "", ""), binp)
    assert pov is not None and pov.reproduced and pov.capability == "reached-sink"


@requires_cc
def test_exectrap_rejects_clean_control(tmp_path: Path) -> None:
    # constant command, no injection point -> no false confirmation
    src = ('#include <stdlib.h>\nint main(void){(void)getenv("HOST");'
           'system("/bin/true");return 0;}\n')
    binp = _cc(src, tmp_path)
    f = Finding(source="getenv", sink="system", function="main",
                source_addr=0, sink_addr=0, path_len=0, origin="bugclass:cmdi")
    assert confirm(f, Verdict(True, "x", "high", "", "HOST=x"), binp) is None


def test_exectrap_shim_builds_when_cc_present() -> None:
    if not _HAS_CC:
        pytest.skip("no C compiler")
    assert oracle.exectrap_available() is True
    env = oracle.exectrap_env("deadbeef")
    assert env["ZEROVERSE_EXECTRAP"] == "deadbeef" and "LD_PRELOAD" in env


# === 9. data-driven seed registry (auditable provenance) =================

def test_seedcatalog_loads_and_counts() -> None:
    s = sc.summary()
    assert s["total"] == 90
    assert s["implemented"] == 71
    assert s["kernel-static"] == 11  # the statically-strong .ko archetypes
    assert len(sc.by_domain("kernel")) == 34
    assert len(sc.by_domain("userland")) == 30
    assert len(sc.by_domain("firmware")) == 26


def test_seedcatalog_engine_lens_references_resolve() -> None:
    """Every ``engine_lens`` an archetype claims must name a real implemented
    bug-class or seed-class id — keeps the data and the engine in sync."""
    bug_ids = {f"bugclass:{bc.id}" for bc in BUG_CLASSES}
    seed_ids = {f"seed:{c.id}" for c in seedbugs.SEED_CLASSES}
    seed_ids |= {f"seed:{c.id}" for c in seedbugs.FIRMWARE_SEEDS}
    valid = bug_ids | seed_ids
    for a in sc.implemented():
        assert a.engine_lens in valid, f"{a.uid} -> dangling {a.engine_lens}"


def test_seedcatalog_no_exploit_field_leaked() -> None:
    # the kernel weaponization_note must NOT be vendored into the registry
    for a in sc.load_archetypes():
        assert "weaponization_note" not in a.extra


def test_seedcatalog_cmdi_archetypes_map_to_cmdi_lens() -> None:
    assert {a.id for a in sc.by_lens("bugclass:cmdi")} == {"CI-01", "CI-02", "CI-03", "CI-04"}

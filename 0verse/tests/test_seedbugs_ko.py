"""Linux kernel-module (.ko) seed-bug-class fold-in — the binary-only kernel lane.

Mirrors ``test_seedbugs.py`` (the IOKit/kext class) for the Linux ``.ko`` family:
the seed classes fire on decompiled C that carries the kernel-exported symbols
that survive stripping, the ``.ko`` target-hook classifies a relocatable ELF as a
kernel module, the funnel primes the hypotheses, and the MCP ``scan_binary``
bridge accepts a ``.ko``.
"""

from __future__ import annotations

import struct
from pathlib import Path

from zeroverse.agent import MockLLM, TriageFunnel
from zeroverse.ingest import triage
from zeroverse.mcp import Engine
from zeroverse.seedbugs import (
    IOKIT_USER_CLIENT,
    LINUX_KO_CLASSES,
    LINUX_KO_COPY_FROM_USER,
    LINUX_KO_IOCTL_DISPATCH,
    LINUX_KO_KMALLOC_OVERFLOW,
    LINUX_KO_MISSING_CAPABLE,
    LINUX_KO_USER_DEREF,
    prime_hypotheses,
    seed_for_target,
    seeds_for_target,
)

# Decompiled C as Ghidra renders a stripped 6.x ``.ko`` ioctl handler: the
# handler's own name is gone (``FUN_00100010``), but the kernel-exported symbols
# survive as relocations and the decompiler renders the calls by name — the
# detection hook (``_copy_from_user`` / ``__kmalloc_noprof`` / ``__get_user_8``).
_KO_HANDLER = (
    "ulong FUN_00100010(undefined8 param_1,int param_2,undefined8 param_3)\n"
    "{\n"
    "  long lVar3;\n"
    "  undefined1 abStack_50 [64];\n"
    "  ulong uStack_70;\n"
    "  lVar3 = _copy_from_user(&uStack_70,param_3,0x20);\n"
    "  if (lVar3 == 0) {\n"
    "    if (param_2 == 0x1002) {\n"
    "      lVar3 = __kmalloc_noprof(uStack_70 << 4,0xcc0);\n"
    "      _copy_from_user(lVar3,uStack_70,uStack_70 << 4);\n"
    "    }\n"
    "    if (param_2 == 0x1003) { __get_user_8(uStack_70); }\n"
    "  }\n"
    "  return 0;\n"
    "}\n"
)
# A bounds-checked, capable()-gated, constant-size handler — should NOT raise the
# missing-capable hypothesis, and its alloc is not arithmetic.
_KO_SAFE = (
    "ulong FUN_00100200(undefined8 param_1,int param_2,undefined8 param_3)\n"
    "{\n"
    "  long lVar3;\n"
    "  if (!capable(0x15)) return 0xfffffff3;\n"
    "  if (param_2 < 0x10) {\n"
    "    lVar3 = __kmalloc_noprof(64,0xcc0);\n"
    "    _copy_from_user(lVar3,param_3,64);\n"
    "  }\n"
    "  return 0;\n"
    "}\n"
)
# Plain userland function — no kernel-only symbol, must never match.
_USERLAND = "int add(int a, int b) { return a + b; }\n"

_CORPUS = {"FUN_00100010": _KO_HANDLER, "FUN_00100200": _KO_SAFE, "add": _USERLAND}


# --- seed-bug-class matching (survives stripping) --------------------------

def test_copy_from_user_class_fires_on_stripped_handler() -> None:
    ok, _label, sink = LINUX_KO_COPY_FROM_USER.matches(_KO_HANDLER)
    assert ok
    assert "copy_from_user" in sink
    # context came from the surviving kernel symbol, not the (stripped) name.
    assert LINUX_KO_COPY_FROM_USER.is_kernel_context(_KO_HANDLER)


def test_copy_from_user_ignores_userland() -> None:
    ok, _, _ = LINUX_KO_COPY_FROM_USER.matches(_USERLAND)
    assert not ok


def test_kmalloc_overflow_requires_size_arithmetic() -> None:
    # the handler has __kmalloc_noprof(uStack_70 << 4, ...) — a shift -> overflow
    ok, _, _ = LINUX_KO_KMALLOC_OVERFLOW.matches(_KO_HANDLER)
    assert ok
    # the safe handler allocs a constant size — no arithmetic, must not fire.
    ok_safe, _, _ = LINUX_KO_KMALLOC_OVERFLOW.matches(_KO_SAFE)
    assert not ok_safe


def test_user_deref_class_fires() -> None:
    ok, _, sink = LINUX_KO_USER_DEREF.matches(_KO_HANDLER)
    assert ok
    assert "get_user" in sink


def test_missing_capable_only_when_no_guard() -> None:
    ok, _, _ = LINUX_KO_MISSING_CAPABLE.matches(_KO_HANDLER)
    assert ok  # no capable() in the handler
    ok_safe, _, _ = LINUX_KO_MISSING_CAPABLE.matches(_KO_SAFE)
    assert not ok_safe  # capable() present -> guard satisfied, not a candidate


def test_ioctl_dispatch_needs_dispatch_shape() -> None:
    # The handler uses if-chains (Ghidra lowered the switch), no switch/case/_IOC
    # token, so the dispatch class abstains — honest, not a false positive.
    ok, _, _ = LINUX_KO_IOCTL_DISPATCH.matches(_KO_HANDLER)
    assert not ok
    with_switch = _KO_HANDLER.replace("if (param_2 == 0x1002)", "switch(param_2) { case 0x1002:")
    ok2, _, _ = LINUX_KO_IOCTL_DISPATCH.matches(with_switch)
    assert ok2


# --- priming into the funnel -----------------------------------------------

def test_prime_hypotheses_tags_linux_ko_origin() -> None:
    primed = prime_hypotheses(LINUX_KO_COPY_FROM_USER, _CORPUS)
    assert primed
    f = primed[0]
    assert f.function == "FUN_00100010"
    assert f.origin == "seed:linux-ko:copy-from-user"
    assert f.source.startswith("kmod:")


def test_all_linux_classes_prime_over_corpus() -> None:
    fired = set()
    for seed in LINUX_KO_CLASSES:
        for f in prime_hypotheses(seed, _CORPUS):
            fired.add(f.origin)
    # the four sink-based classes fire on the vulnerable handler.
    assert "seed:linux-ko:copy-from-user" in fired
    assert "seed:linux-ko:kmalloc-overflow" in fired
    assert "seed:linux-ko:user-deref" in fired
    assert "seed:linux-ko:missing-capable" in fired


def test_funnel_ranks_primed_ko_hypotheses_without_confirming() -> None:
    primed = []
    for seed in LINUX_KO_CLASSES:
        primed += prime_hypotheses(seed, _CORPUS)
    funnel = TriageFunnel(MockLLM(), seed_bug_class=LINUX_KO_COPY_FROM_USER.framing)
    ranked = funnel.run(primed, lambda f: _CORPUS.get(f.function, ""))
    assert len(ranked) == len(primed)
    # a seed hypothesis is never a confirmed finding (no PoV/oracle here).
    assert all(r.finding.origin.startswith("seed:linux-ko:") for r in ranked)


# --- target hook (seeds_for_target) ----------------------------------------

def test_seeds_for_target_kmod_returns_all_linux_classes() -> None:
    seeds = seeds_for_target("ELF", "KMOD", _CORPUS)
    assert set(seeds) == set(LINUX_KO_CLASSES)
    # ingest-only (no bodies) still primes on the KMOD kind alone.
    assert set(seeds_for_target("ELF", "KMOD", None)) == set(LINUX_KO_CLASSES)


def test_plain_elf_never_primes_linux_classes() -> None:
    assert seeds_for_target("ELF", "EXEC", _CORPUS) == []
    assert seed_for_target("ELF", "REL", _CORPUS) is None


def test_macho_kext_still_primes_iokit_only() -> None:
    # the .ko fold-in must not disturb the IOKit/kext path.
    seeds = seeds_for_target("Mach-O", "KEXT_BUNDLE", None)
    assert seeds == [IOKIT_USER_CLIENT]


# --- ingest classification (the .ko target-hook in ingest.py) --------------

def _synth_ko(tmp_path: Path, *, markers: bytes, e_type: int = 1) -> str:
    """A minimal x86-64 ELF with no program headers, plus trailing kernel-module
    marker strings — enough for ``triage`` to classify it the same way it does a
    real ``.ko`` (it byte-scans for the markers; mirrors how the markers survive
    stripping in a real module)."""
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    hdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        e_type,   # e_type (1 = ET_REL)
        0x3E,     # e_machine (x86-64)
        1,        # e_version
        0,        # e_entry
        0,        # e_phoff
        0,        # e_shoff
        0,        # e_flags
        64,       # e_ehsize
        0,        # e_phentsize
        0,        # e_phnum
        0,        # e_shentsize
        0,        # e_shnum
        0,        # e_shstrndx
    )
    p = tmp_path / "m.ko"
    p.write_bytes(hdr + b"\x00" + markers)
    return str(p)


def test_triage_classifies_kernel_module(tmp_path: Path) -> None:
    ko = _synth_ko(tmp_path, markers=b".modinfo\x00module_layout\x00__this_module\x00")
    t = triage(ko)
    assert t.fmt == "ELF"
    assert t.kind == "KMOD"
    assert any("kernel module" in n for n in t.notes)


def test_triage_plain_relocatable_is_not_a_module(tmp_path: Path) -> None:
    # a relocatable ELF object without the module markers stays REL, not KMOD.
    obj = _synth_ko(tmp_path, markers=b".text\x00.data\x00")
    t = triage(obj)
    assert t.fmt == "ELF"
    assert t.kind == "REL"


# --- MCP bridge smoke (scan_binary accepts a .ko) --------------------------

def test_mcp_scan_binary_routes_a_ko(tmp_path: Path) -> None:
    ko = _synth_ko(tmp_path, markers=b".modinfo\x00module_layout\x00")
    out = Engine().scan_binary(ko)
    # the MCP bridge accepts the .ko and routes it as an ELF target through the
    # one engine + versioned contract (Ghidra-independent: triage always runs).
    assert out["format"] == "ELF"
    assert out["arch"] == "x86-64"
    assert out["contract_version"]
    # PoV-is-truth: a bare .ko yields no confirmed finding (no live-kernel oracle).
    assert out["confirmed"] == 0

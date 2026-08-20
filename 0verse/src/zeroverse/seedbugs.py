"""Seed-bug-classes for the #4 variant-analysis funnel — the binary-only kernel fold-in.

Big Sleep's lesson (guidance §#4): seeding a *known* bug class and hunting its
siblings is far higher signal than open-ended search. This module encodes 0sec
kernel reverse-engineering knowledge as a **reusable 0verse asset** — declarative
``SeedBugClass`` records — instead of leaving it as tribal knowledge or a comment.
Pointing 0verse at a binary-only kernel artifact primes the matching hypotheses
automatically (``seeds_for_target``), and the priming pass surfaces candidate
dispatch / handler routines as hypotheses (``prime_hypotheses``) that the funnel
then ranks/escalates under variant-analysis framing.

Two families ship today, both keyed off kernel-only symbols that **survive
stripping** (the symbol is an undefined external / relocation the loader needs, so
it stays in the symbol table even when local names are stripped — the detection
hook):

  * **macOS / XNU** — a Mach-O kernel extension (kext) primes the *IOKit
    user-client externalMethod dispatch* class (``IOMalloc``/``copyin`` are the
    surviving giveaway symbols).
  * **Linux** — a kernel module (``.ko``, a relocatable ELF) primes the
    kernel-module LPE classes below (``copy_from_user``/``kmalloc``/``get_user``
    are the surviving giveaway symbols). This is the **binary-only** lane: closed
    / out-of-tree ``.ko`` drivers, firmware kernel blobs, vendor/Android kernels.
    Upstream Linux *with source* stays syzkaller / source-analysis territory — see
    ``docs/KERNEL-INTEGRATION.md``.

These are **hypotheses, never findings** — exactly like the foxguard pre-pass. On
a bare binary there is no live-kernel oracle (confirmation would need a running
kernel / VM), so a kernel target stays at the static + LLM-triage tier and
degrades honestly; the value is the directed, arch/format-aware hypothesis
seeding. A ``.ko`` finding is never upgraded to *confirmed* without a PoV.

The macOS seed — *IOKit user-client externalMethod dispatch* — is the single
highest-yield macOS LPE surface: a user client's ``externalMethod`` /
``getTargetAndMethodForIndex`` dispatch where the scalar/struct input-count check
is missing or wrong, so a user-controlled selector or size drives an
``IOMalloc``/``copyin`` OOB (CWE-787/CWE-129). The Linux seeds mirror the same
shape for the ``.ko`` ioctl/handler surface.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .analyze import Finding


@dataclass(frozen=True)
class SeedBugClass:
    """A declarative variant-analysis seed: the framing string handed to the LLM
    funnel plus the static signals that nominate candidate functions."""

    id: str
    name: str
    cwe: str
    framing: str                       # the variant-analysis seed for the funnel
    dispatch_signals: tuple[str, ...]  # tokens marking a relevant entrypoint
    sink_signals: tuple[str, ...]      # size/copy/alloc sinks reached from the dispatch
    bound_signals: tuple[str, ...]     # tokens that would indicate a present check
    kernel_signals: tuple[str, ...] = ()   # kernel-only symbols (survive stripping)
    target_formats: tuple[str, ...] = ("Mach-O",)
    # --- optional refinements (all default-off; IOKit uses none of them) ---
    corroborating_signals: tuple[str, ...] = ()  # if set, ≥1 must also be present
    require_arith: bool = False                  # sink's size arg must be a*b / a<<b / a+b
    guard_signals: tuple[str, ...] = ()          # privilege/bounds guard tokens
    require_guard_absent: bool = False           # candidate only when no guard present
    require_indirect_call: bool = False          # sink is an indexed indirect call (DRV-01)
    require_double_fetch: bool = False           # two user-fetches of one uaddr (DRV-07)
    # Routing: '' = static-rank only; 'kernel-verify' = a hypothesis that can NOT
    # be bare-binary-confirmed (deferred-free / RCU / race / refcount) and is
    # marked for the bench kernel-verify lane — never auto-confirmed.
    route: str = ""

    def _rx(self, tokens: tuple[str, ...]) -> re.Pattern[str]:
        return re.compile("|".join(re.escape(t) for t in tokens))

    def is_kernel_context(self, decompiled_c: str) -> bool:
        """Is this code kernel code at all? A named dispatch/handler entrypoint OR a
        kernel-only symbol (``IOMalloc``/``copyin`` for XNU, ``copy_from_user``/
        ``kmalloc`` for Linux — these don't exist in userland, so they survive when
        the decompiler strips the handler name to a ``FUN_xxx``/``ltmpN`` label,
        which is the common stripped-``.ko`` / stripped-kext case)."""
        return bool(
            self._rx(self.dispatch_signals).search(decompiled_c)
            or self._rx(self.kernel_signals).search(decompiled_c)
        )

    # Back-compat alias — the original IOKit-only spelling.
    def is_iokit_context(self, decompiled_c: str) -> bool:
        return self.is_kernel_context(decompiled_c)

    def matches(self, decompiled_c: str) -> tuple[bool, str, str]:
        """Does this function body look like an instance of the seed class?

        Returns ``(is_candidate, context_label, sink_token)``. A candidate is
        kernel context (named dispatch *or* a kernel-only symbol) reaching a
        size/copy/alloc sink — i.e. a user-controlled selector or size flowing
        toward a copy/allocation. Robust to stripped handler names (the real
        ``.ko``/kext case). The optional refinements narrow the class so distinct
        Linux seeds (copy-from-user vs kmalloc-overflow vs missing-capable) don't
        all collapse onto the same function:

          * ``corroborating_signals`` — at least one must also be present (e.g. a
            ``switch``/``case``/``_IOC`` cmd-dispatch shape for the ioctl class);
          * ``require_arith`` — the sink's size argument must be an arithmetic
            expression (``a*b`` / ``a<<b`` / ``a+b``), the int-overflow shape;
          * ``require_guard_absent`` — a candidate only when *no* privilege/bounds
            guard (``capable``/``ns_capable``) appears (the missing-check shape).
        """
        if not self.is_kernel_context(decompiled_c):
            return False, "", ""
        # The sink token: an indexed indirect call (DRV-01) has no named symbol,
        # so the indexed-indirect-call shape *is* the sink; otherwise a named sink.
        if self.require_indirect_call:
            ic = _has_indexed_indirect_call(decompiled_c)
            if not ic:
                return False, "", ""
            sink_token = ic
        else:
            sink = self._rx(self.sink_signals).search(decompiled_c)
            if not sink:
                return False, "", ""
            sink_token = sink.group(0)
        if self.require_double_fetch and not _has_double_fetch(decompiled_c):
            return False, "", ""
        if self.corroborating_signals and not self._rx(
            self.corroborating_signals
        ).search(decompiled_c):
            return False, "", ""
        if self.require_arith and not _alloc_size_is_arith(decompiled_c, self.sink_signals):
            return False, "", ""
        if (
            self.require_guard_absent
            and self.guard_signals
            and self._rx(self.guard_signals).search(decompiled_c)
        ):
            return False, "", ""
        disp = self._rx(self.dispatch_signals).search(decompiled_c)
        label = disp.group(0) if disp else "handler"
        return True, label, sink_token

    def has_bound_check(self, decompiled_c: str) -> bool:
        """Heuristic: is an input-count / size bound checked at all? Absence is the
        signal that makes the candidate *interesting* (raises the hypothesis rank)."""
        return bool(self._rx(self.bound_signals).search(decompiled_c))


# Multiply/shift inside an allocation/copy call's (shallow) argument list — the
# integer-overflow-to-undersized-alloc shape. ``+`` is included because a length
# addend (``hdr + len``) also wraps, but the left operand of ``*`` being a bare C
# type keyword (a ``char *p`` pointer decl) is excluded so a declaration is not
# read as a size multiply.
_ARITH_OP = re.compile(r"(?:\*|<<|\+)")
_DECL_STAR = re.compile(
    r"\b(?:char|short|int|long|unsigned|signed|void|size_t|u8|u16|u32|u64|struct)\s*\*"
)


def _alloc_size_is_arith(code: str, names: tuple[str, ...]) -> bool:
    """True if any ``name(...)`` call's shallow argument list contains size
    arithmetic that is not merely a pointer declaration. The name is matched as a
    prefix so the modern kernel alloc spellings (``__kmalloc_noprof`` /
    ``kvmalloc_node_noprof``, which is what survives in a 6.x ``.ko``) are caught,
    not just the canonical ``kmalloc``."""
    name_rx = re.compile(
        r"(?:" + "|".join(re.escape(n) for n in names) + r")\w*\s*\("
    )
    for m in name_rx.finditer(code):
        depth, i = 0, m.end() - 1
        start = i + 1
        while i < len(code):
            if code[i] == "(":
                depth += 1
            elif code[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        args = code[start:i]
        if _ARITH_OP.search(_DECL_STAR.sub("", args)):
            return True
    return False


# An indexed indirect call — ``(*table[idx])(...)`` / Ghidra's
# ``(*(code *)(base + idx * 8))(...)`` — the DRV-01 selector-index shape: a
# user-controlled selector indexes a function-pointer table with no bound, so the
# indirect call lands out of range (OOB indirect call → control-flow hijack). The
# tell is an indirect-call expression whose callee carries an array index or a
# scaled-offset add, which is exactly what survives in a stripped ``.ko``.
_IC_INDEX = re.compile(r"\[[^\]]+\]")
_IC_SCALE = re.compile(r"\+\s*[\w()]+\s*\*\s*(?:0x[0-9a-fA-F]+|\d+)")
_IC_BARE_SCALE = re.compile(r"\*\s*(?:0x[0-9a-fA-F]+|\d+)\b")


def _has_indexed_indirect_call(code: str) -> str | None:
    """Return the callee expression of the first *indexed* indirect call, or None.
    Balanced-paren scan so Ghidra's nested ``(*(code *)(...))`` renders are
    handled. An indirect call with no index/scale (a plain vtable call) is *not*
    flagged — the index is the user-selector signal."""
    for m in re.finditer(r"\(\s*\*+", code):
        depth, i = 0, m.start()
        while i < len(code):
            c = code[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    j = i + 1
                    while j < len(code) and code[j] in " \t":
                        j += 1
                    if j < len(code) and code[j] == "(":
                        callee = code[m.start():i + 1]
                        if (
                            _IC_INDEX.search(callee)
                            or _IC_SCALE.search(callee)
                            or _IC_BARE_SCALE.search(callee)
                        ):
                            return callee[:80]
                    break
            i += 1
    return None


# The user-source argument of a copy-from-user / get_user call (the uaddr being
# fetched): copy_from_user(dst, USER, len) -> arg index 1; get_user(v, USER) ->
# arg index 1. A double-fetch is the *same* uaddr fetched twice (validate-then-use
# TOCTOU) — DRV-07, the one race sub-class with a static tell.
_CFU_FAMILY = ("_copy_from_user", "copy_from_user", "__copy_from_user", "get_user",
               "__get_user", "memdup_user")


def _nth_arg(code: str, call_end: int, idx: int) -> str | None:
    """Shallow-split the argument list that opens at ``call_end-1`` and return arg
    ``idx`` trimmed, or None."""
    depth, i, start = 0, call_end - 1, call_end
    while i < len(code):
        if code[i] == "(":
            depth += 1
        elif code[i] == ")":
            depth -= 1
            if depth == 0:
                break
        i += 1
    args = code[start:i]
    depth, cur, parts = 0, "", []
    for ch in args:
        if ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
            continue
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        cur += ch
    parts.append(cur.strip())
    return parts[idx] if 0 <= idx < len(parts) else None


def _has_double_fetch(code: str) -> bool:
    """True if one user address is fetched by ≥2 copy_from_user/get_user calls —
    the double-fetch TOCTOU tell (validate first copy, use second)."""
    srcs: list[str] = []
    for name in _CFU_FAMILY:
        for m in re.finditer(rf"\b{re.escape(name)}\s*\(", code):
            src = _nth_arg(code, m.end(), 1)
            if src:
                srcs.append(src)
    return any(srcs.count(x) >= 2 for x in set(srcs))


# ---------------------------------------------------------------------------
# macOS / XNU — IOKit user-client dispatch
# ---------------------------------------------------------------------------

IOKIT_USER_CLIENT = SeedBugClass(
    id="iokit.user-client.dispatch",
    name="IOKit user-client externalMethod dispatch OOB / missing input-count check",
    cwe="CWE-787",
    framing=(
        "IOKit user-client dispatch bug: a confirmed missing scalar/struct "
        "input-count (or selector-bound) check in an externalMethod / "
        "getTargetAndMethodForIndex dispatch, where a user-controlled selector or "
        "input size drives an IOMalloc/copyin/copyout out of bounds. Treat this "
        "path as a sibling — look for the same root cause (user-controlled "
        "selector index or input count/size reaching a copy or allocation with no "
        "bound) reached through a different method or user client"
    ),
    dispatch_signals=(
        "externalMethod", "getTargetAndMethodForIndex",
        "getAsyncTargetAndMethodForIndex", "IOExternalMethod",
        "IOExternalMethodDispatch", "::clientMemoryForType",
        "scalarInput", "structureInput", "selector",
    ),
    sink_signals=(
        "IOMalloc", "IOMallocAligned", "IONew", "copyin", "copyout",
        "bcopy", "memmove", "memcpy",
    ),
    # Tokens that indicate an actual *check* (not merely a size variable's use):
    # a comparison or an explicit bad-argument bail-out near the dispatch.
    bound_signals=(
        ">=", "<=", "kIOReturnBadArgument", "kIOReturnNoSpace", "if (", "if(",
    ),
    # Kernel-only symbols that survive when the dispatch name is stripped — the
    # giveaway that a ``ltmpN``-labelled function is IOKit/BSD kernel code.
    kernel_signals=(
        "IOMalloc", "IONew", "IOFree", "copyin", "copyout",
        "IOConnectCall", "getTargetAndMethodForIndex",
    ),
)


# ---------------------------------------------------------------------------
# Linux — kernel module (.ko) LPE classes  (origin seed:linux-ko:*)
# ---------------------------------------------------------------------------
#
# All five key off symbols that survive a stripped ``.ko``: ``copy_from_user`` /
# ``kmalloc`` / ``get_user`` are kernel-exported symbols that remain as undefined
# relocations the module loader resolves, so they stay in the symbol table and the
# decompiler renders the call by name even when the handler's own name is stripped
# to ``FUN_xxx`` — the same trick as IOKit's IOMalloc/copyin.

# Surviving Linux-kernel-only symbols that mark a function body as kernel code.
_LINUX_KERNEL_SIGNALS = (
    "copy_from_user", "_copy_from_user", "__copy_from_user",
    "copy_to_user", "_copy_to_user", "__copy_to_user",
    "get_user", "put_user", "__get_user", "__put_user",
    "kmalloc", "kzalloc", "kvmalloc", "vmalloc",
    "unlocked_ioctl", "compat_ioctl", "memdup_user", "access_ok",
)

LINUX_KO_COPY_FROM_USER = SeedBugClass(
    id="linux-ko:copy-from-user",
    name="kernel-module copy_from_user/copy_to_user OOB (user-controlled size)",
    cwe="CWE-787",  # also CWE-125 (OOB read) for copy_to_user
    framing=(
        "Linux kernel-module copy_from_user/copy_to_user OOB: a user-controlled "
        "length drives copy_from_user(dst, user, len) into a fixed stack/heap "
        "buffer (write OOB, CWE-787) or copy_to_user(user, src, len) past the "
        "source (read OOB, CWE-125), with the length never clamped to the buffer "
        "size. Treat this path as a sibling — look for the same user-controlled "
        "size reaching another copy_from_user/copy_to_user/memdup_user without a "
        "min()/sizeof bound"
    ),
    dispatch_signals=(
        "unlocked_ioctl", "compat_ioctl", "_ioctl", "_write", "_read",
        "_store", "_recvmsg", "_setsockopt", "_set_param",
    ),
    sink_signals=(
        "copy_from_user", "_copy_from_user", "__copy_from_user",
        "copy_to_user", "_copy_to_user", "__copy_to_user",
        "memdup_user", "strncpy_from_user",
    ),
    bound_signals=(
        "min(", "min_t", "clamp", "sizeof", "ARRAY_SIZE", ">=", "<=",
        "access_ok", "if (", "if(", "> ", "< ",
    ),
    kernel_signals=_LINUX_KERNEL_SIGNALS,
    target_formats=("ELF",),
)

LINUX_KO_IOCTL_DISPATCH = SeedBugClass(
    id="linux-ko:ioctl-dispatch",
    name="kernel-module ioctl cmd dispatch — user-selector OOB / missing bounds",
    cwe="CWE-129",
    framing=(
        "Linux kernel-module ioctl dispatch bug: an unlocked_ioctl/compat_ioctl "
        "handler switches on a user-supplied cmd/selector and reaches a copy or "
        "allocation whose index or size is the user selector, with no bound on the "
        "selector (CWE-129) or the size. Treat this path as a sibling — look for "
        "the same user cmd/selector driving a different case's copy/alloc without "
        "a range check"
    ),
    dispatch_signals=(
        "unlocked_ioctl", "compat_ioctl", "_ioctl", "ioctl",
    ),
    sink_signals=(
        "copy_from_user", "copy_to_user", "_copy_from_user", "_copy_to_user",
        "memcpy", "memmove", "kmalloc", "kzalloc", "memdup_user",
    ),
    bound_signals=(
        ">=", "<=", "_IOC_SIZE", "_IOC_NR", "default:", "EINVAL", "ENOTTY",
        "ARRAY_SIZE", "if (", "if(",
    ),
    kernel_signals=_LINUX_KERNEL_SIGNALS,
    target_formats=("ELF",),
    # Only the dispatcher itself: a switch / case / cmd-decode shape must appear,
    # so this class does not collapse onto every copy_from_user leaf.
    corroborating_signals=("switch", "case ", "_IOC", "->cmd", "cmd ==", "cmd =="),
)

LINUX_KO_KMALLOC_OVERFLOW = SeedBugClass(
    id="linux-ko:kmalloc-overflow",
    name="kernel-module kmalloc/kzalloc size-arithmetic integer overflow → undersized alloc",
    cwe="CWE-190",  # leads to CWE-122 heap OOB
    framing=(
        "Linux kernel-module integer-overflow-to-heap-OOB: a kmalloc/kzalloc/"
        "kvmalloc/vmalloc size is computed by arithmetic on a user-controlled "
        "count/length (count*size, hdr+len, n<<shift) that can wrap, producing an "
        "undersized allocation a later copy overflows (CWE-190 → CWE-122). Treat "
        "this path as a sibling — look for the same unchecked size arithmetic "
        "feeding a different kmalloc/kvmalloc (prefer kmalloc_array/kcalloc/"
        "struct_size, which check the multiply)"
    ),
    dispatch_signals=(
        "unlocked_ioctl", "compat_ioctl", "_ioctl", "_write", "_alloc",
    ),
    sink_signals=(
        "kmalloc", "kzalloc", "kvmalloc", "kvzalloc", "vmalloc", "vzalloc",
        "krealloc", "kmemdup",
    ),
    bound_signals=(
        "kmalloc_array", "kcalloc", "struct_size", "check_mul_overflow",
        "array_size", "if (", "if(", ">=", "<=",
    ),
    kernel_signals=_LINUX_KERNEL_SIGNALS,
    target_formats=("ELF",),
    require_arith=True,  # only flag when the size arg is actually a*b / a<<b / a+b
)

LINUX_KO_USER_DEREF = SeedBugClass(
    id="linux-ko:user-deref",
    name="kernel-module unchecked user-pointer deref / get_user/put_user misuse",
    cwe="CWE-822",
    framing=(
        "Linux kernel-module unchecked user-pointer dereference: a __user pointer "
        "is dereferenced via get_user/put_user/__get_user/__put_user (or a raw "
        "deref) without a preceding access_ok / on a user-controlled address, "
        "yielding an arbitrary kernel read/write (CWE-822/CWE-787). Treat this "
        "path as a sibling — look for the same __user pointer reaching another "
        "get_user/put_user without access_ok"
    ),
    dispatch_signals=(
        "unlocked_ioctl", "compat_ioctl", "_ioctl", "_write", "_read",
    ),
    sink_signals=(
        "get_user", "put_user", "__get_user", "__put_user",
    ),
    bound_signals=(
        "access_ok", "if (", "if(", ">=", "<=", "EFAULT",
    ),
    kernel_signals=_LINUX_KERNEL_SIGNALS,
    target_formats=("ELF",),
)

LINUX_KO_MISSING_CAPABLE = SeedBugClass(
    id="linux-ko:missing-capable",
    name="kernel-module privileged op with no capable()/ns_capable() check (hypothesis-only)",
    cwe="CWE-862",
    framing=(
        "Linux kernel-module missing privilege check (Big-Sleep style): an "
        "ioctl/write handler performs a privileged or state-changing operation "
        "(copy_from_user into kernel state, alloc, register, hardware/MSR/port op) "
        "with NO capable()/ns_capable()/CAP_* gate, so an unprivileged process "
        "reaches it (CWE-862). Reason about the INTENT of the handler, not just "
        "its shape; this class has NO generic binary oracle, so it stays a "
        "high-value HYPOTHESIS until a PoV on a live kernel proves it"
    ),
    dispatch_signals=(
        "unlocked_ioctl", "compat_ioctl", "_ioctl", "_write", "_store",
    ),
    sink_signals=(
        "copy_from_user", "_copy_from_user", "kmalloc", "kzalloc",
        "register_", "request_irq", "ioremap", "memcpy",
    ),
    bound_signals=(
        "capable", "ns_capable", "CAP_", "if (", "if(",
    ),
    kernel_signals=_LINUX_KERNEL_SIGNALS,
    target_formats=("ELF",),
    # A candidate ONLY when no privilege guard is present — the missing-check shape.
    guard_signals=("capable", "ns_capable", "CAP_", "capable_wrt_inode"),
    require_guard_absent=True,
)


# --- statically-strong additions (kernel.md SHARPENINGS) -------------------

LINUX_KO_SELECTOR_INDEX = SeedBugClass(
    id="linux-ko:selector-index",
    name="kernel-module ioctl unchecked user-selector index → OOB indirect call (DRV-01)",
    cwe="CWE-129",
    framing=(
        "Linux kernel-module ioctl selector-index OOB (DRV-01, the single most "
        "binary-detectable LPE class): an unlocked_ioctl/compat_ioctl handler uses "
        "a user-supplied selector to index a function-pointer table or array "
        "(table[arg]) and calls/derefs it with NO range check (no cmp idx,CONST), "
        "so the indirect call lands out of bounds (OOB indirect call → control-flow "
        "hijack). Treat this path as a sibling — look for the same user selector "
        "indexing a different fnptr table / array without a bound"
    ),
    dispatch_signals=(
        "unlocked_ioctl", "compat_ioctl", "_ioctl", "ioctl",
    ),
    sink_signals=("(*",),  # unused: require_indirect_call supplies the sink token
    bound_signals=(
        ">=", "<=", "ARRAY_SIZE", "default:", "EINVAL", "ENOTTY", "if (", "if(",
        "< ", "> ",
    ),
    kernel_signals=_LINUX_KERNEL_SIGNALS,
    target_formats=("ELF",),
    require_indirect_call=True,
)

LINUX_KO_MMAP_PGOFF = SeedBugClass(
    id="linux-ko:mmap-pgoff",
    name=(
        "kernel-module mmap remap_pfn_range with unbounded user vm_pgoff "
        "→ arbitrary phys (DRV-08)"
    ),
    cwe="CWE-782",  # exposed physical address region → CWE-787/125
    framing=(
        "Linux kernel-module mmap/DMA out-of-bounds physical mapping (DRV-08): an "
        "mmap fop calls remap_pfn_range/io_remap_pfn_range with a pfn/offset "
        "derived from the user-controlled vma->vm_pgoff with no clamp against the "
        "device's real region size, so userspace maps arbitrary physical memory "
        "(direct physical R/W = instant root). Treat this path as a sibling — look "
        "for the same vm_pgoff/offset reaching a different remap_pfn_range/"
        "dma_mmap without a size/range check"
    ),
    dispatch_signals=("_mmap", "mmap", "vm_pgoff", "vm_operations"),
    sink_signals=(
        "remap_pfn_range", "io_remap_pfn_range", "remap_pfn_range_notrack",
        "vmf_insert_pfn", "dma_mmap_coherent", "dma_mmap_attrs",
    ),
    bound_signals=(
        "vm_pgoff", ">=", "<=", "EINVAL", "if (", "if(", "size", "ARRAY_SIZE",
    ),
    kernel_signals=(*_LINUX_KERNEL_SIGNALS, "remap_pfn_range", "io_remap_pfn_range"),
    target_formats=("ELF",),
    # Only when the offset/pgoff is actually referenced — the user-controlled knob.
    corroborating_signals=("vm_pgoff", "pgoff", "->pgoff", "offset"),
)

LINUX_KO_DOUBLE_FETCH = SeedBugClass(
    id="linux-ko:double-fetch",
    name="kernel-module ioctl TOCTOU double-fetch of one user address (DRV-07)",
    cwe="CWE-367",
    framing=(
        "Linux kernel-module double-fetch TOCTOU (DRV-07, the one race sub-class "
        "with a static tell): an ioctl handler copies the *same* user address with "
        "copy_from_user/get_user twice — validates the first read then re-reads and "
        "uses the second — so a concurrent userspace writer changes the value "
        "between the check and the use (size/index/len mismatch → OOB). Treat this "
        "path as a sibling — look for the same uaddr fetched twice on a different "
        "handler"
    ),
    dispatch_signals=("unlocked_ioctl", "compat_ioctl", "_ioctl", "ioctl"),
    sink_signals=(
        "copy_from_user", "_copy_from_user", "__copy_from_user", "get_user",
        "__get_user",
    ),
    bound_signals=("memdup_user", "single", "if (", "if("),
    kernel_signals=_LINUX_KERNEL_SIGNALS,
    target_formats=("ELF",),
    require_double_fetch=True,
)

LINUX_KO_INFOLEAK = SeedBugClass(
    id="linux-ko:uninit-infoleak",
    name="kernel-module uninitialized alloc/struct copied to user — infoleak (MM-03 / SCH-04)",
    cwe="CWE-908",  # use of uninitialized resource -> CWE-200 info exposure
    framing=(
        "Linux kernel-module uninitialized-copy-to-user infoleak (MM-03/SCH-04, the "
        "KASLR/heap-pointer leak half of nearly every LPE chain): a buffer or stats "
        "struct is allocated with kmalloc (NOT kzalloc) or a stack struct, only "
        "partially filled, then handed to userspace via copy_to_user / nla_put / "
        "put_user with NO memset/memzero, leaking uninitialized kernel bytes "
        "(stack/heap pointers → defeats KASLR). Treat this path as a sibling — look "
        "for the same un-zeroed buffer reaching a different copy_to_user/nla_put"
    ),
    dispatch_signals=(
        "unlocked_ioctl", "compat_ioctl", "_ioctl", "_read", "_dump", "_getsockopt",
        "nla_put", "_get_",
    ),
    sink_signals=(
        "copy_to_user", "_copy_to_user", "__copy_to_user", "nla_put", "put_user",
    ),
    bound_signals=(
        "memset", "kzalloc", "kvzalloc", "vzalloc", "__GFP_ZERO", "memzero",
    ),
    kernel_signals=_LINUX_KERNEL_SIGNALS,
    target_formats=("ELF",),
    # Infoleak shape only when NO zeroing appears — the missing-memset tell.
    guard_signals=(
        "memset", "kzalloc", "kvzalloc", "vzalloc", "__GFP_ZERO", "memzero",
        "memset_explicit",
    ),
    require_guard_absent=True,
)

LINUX_KO_NETLINK_OOB = SeedBugClass(
    id="linux-ko:netlink-oob",
    name="kernel-module netlink attr length/range OOB — missing NLA validation (NF-03)",
    cwe="CWE-125",  # OOB read; range-as-index also CWE-787/CWE-129
    framing=(
        "Linux kernel-module netlink attribute OOB (NF-03, strong binary signal): a "
        "value pulled from a netlink attribute with nla_get_*/nla_data feeds a "
        "memcpy length or an array index with no nla_len / range cap, so a crafted "
        "attribute drives an OOB read/write or an out-of-range register/array "
        "index. Treat this path as a sibling — look for the same nla_get_* value "
        "reaching a different memcpy/array index without a length+range check"
    ),
    dispatch_signals=(
        "nla_parse", "nlmsg_parse", "_newrule", "_dump", "nft_", "_policy",
        "unlocked_ioctl",
    ),
    sink_signals=("memcpy", "memmove", "kmemdup", "copy_to_user", "copy_from_user"),
    bound_signals=("nla_len", "NLA_", "nla_validate", ">=", "<=", "if (", "if("),
    kernel_signals=(
        *_LINUX_KERNEL_SIGNALS, "nla_get_u32", "nla_get_u16", "nla_get_u8",
        "nla_get_u64", "nla_data", "nla_parse", "nlmsg_parse",
    ),
    target_formats=("ELF",),
    corroborating_signals=(
        "nla_get_u32", "nla_get_u16", "nla_get_u8", "nla_get_u64", "nla_data",
        "nla_parse",
    ),
)


# --- hypothesis-only families (route:kernel-verify) ------------------------
#
# These deferred-free / refcount / race / error-path UAF families are real,
# high-value LPE classes but are NOT bare-binary confirmable: the free happens in
# a different callback/worker than the use (cross-callback lifetime + race
# reasoning is not one decompiled shape). They are surfaced as ranked HYPOTHESES
# tagged ``route="kernel-verify"`` and routed to the bench KASAN verify lane —
# NEVER auto-confirmed. Detection is intentionally a coarse tell (the surviving
# deferred-free / refcount relocs); the value is priming the verify lane, not a
# precise static verdict.

LINUX_KO_DEFERRED_FREE_UAF = SeedBugClass(
    id="linux-ko:deferred-free-uaf",
    name="kernel-module deferred-free UAF (GC / call_rcu / workqueue) — hypothesis-only",
    cwe="CWE-416",
    framing=(
        "Linux kernel-module deferred-free use-after-free (NF-01/NF-05/SOCK-02 "
        "family): an object is unlinked in one phase and freed by a deferred path "
        "(call_rcu/kfree_rcu/queue_work/queue_delayed_work GC) while another path "
        "still walks the reference. This is a cross-callback lifetime race with NO "
        "bare-binary oracle — emit as a HYPOTHESIS, route to the KASAN verify lane, "
        "never confirm statically"
    ),
    dispatch_signals=("call_rcu", "kfree_rcu", "queue_work", "queue_delayed_work",
                      "INIT_WORK", "rcu"),
    sink_signals=("kfree", "kvfree", "kmem_cache_free", "call_rcu", "kfree_rcu"),
    bound_signals=("synchronize_rcu", "rcu_read_lock", "refcount", "if (", "if("),
    kernel_signals=(*_LINUX_KERNEL_SIGNALS, "call_rcu", "kfree_rcu", "queue_delayed_work", "kfree"),
    target_formats=("ELF",),
    corroborating_signals=("call_rcu", "kfree_rcu", "queue_delayed_work", "queue_work"),
    route="kernel-verify",
)

LINUX_KO_REFCOUNT_UAF = SeedBugClass(
    id="linux-ko:refcount-uaf",
    name="kernel-module refcount-imbalance UAF (kref_put / refcount_dec) — hypothesis-only",
    cwe="CWE-416",
    framing=(
        "Linux kernel-module refcount-asymmetry UAF (DRV-05/NF-05/SCH-01 family, the "
        "dominant Android ITW shape): a put/release (kref_put/refcount_dec_and_test/"
        "dma_buf_put/sock_put) without a matching get, or an error-path that drops a "
        "reference an alias still holds, frees an object early. Lifetime/race "
        "reasoning with NO bare-binary oracle — HYPOTHESIS, route to KASAN verify "
        "lane, never confirm statically"
    ),
    dispatch_signals=("kref_put", "refcount_dec", "_put", "_release", "_unref"),
    sink_signals=("kref_put", "refcount_dec_and_test", "refcount_dec", "dma_buf_put",
                  "sock_put", "put_device", "kobject_put"),
    bound_signals=("kref_get", "refcount_inc", "_get", "if (", "if("),
    kernel_signals=(
        *_LINUX_KERNEL_SIGNALS, "kref_put", "refcount_dec_and_test",
        "kref_get", "refcount_inc",
    ),
    target_formats=("ELF",),
    route="kernel-verify",
)

LINUX_KO_ERRPATH_DOUBLE_FREE = SeedBugClass(
    id="linux-ko:errpath-double-free",
    name="kernel-module error/cleanup-path double-free (DRV-06) — hypothesis-only",
    cwe="CWE-415",
    framing=(
        "Linux kernel-module error-path double-free (DRV-06, one of the few partly "
        "static UAFs): the same pointer is passed to kfree on two reachable paths "
        "(probe/error/cleanup goto chain) with no NULL-store between, giving SLUB "
        "freelist control. Confirming the *reachability* of both frees needs the "
        "live kernel — HYPOTHESIS, route to KASAN verify lane"
    ),
    dispatch_signals=("_probe", "_init", "_remove", "goto", "err", "fail", "cleanup"),
    sink_signals=("kfree", "kvfree", "kmem_cache_free", "kfree_sensitive"),
    bound_signals=("= NULL", "= (", "if (", "if("),
    kernel_signals=(*_LINUX_KERNEL_SIGNALS, "kfree", "kvfree"),
    target_formats=("ELF",),
    route="kernel-verify",
)


LINUX_KO_VERIFY_HYPOTHESES: tuple[SeedBugClass, ...] = (
    LINUX_KO_DEFERRED_FREE_UAF,
    LINUX_KO_REFCOUNT_UAF,
    LINUX_KO_ERRPATH_DOUBLE_FREE,
)


LINUX_KO_CLASSES: tuple[SeedBugClass, ...] = (
    LINUX_KO_COPY_FROM_USER,
    LINUX_KO_IOCTL_DISPATCH,
    LINUX_KO_KMALLOC_OVERFLOW,
    LINUX_KO_USER_DEREF,
    LINUX_KO_MISSING_CAPABLE,
    LINUX_KO_SELECTOR_INDEX,
    LINUX_KO_MMAP_PGOFF,
    LINUX_KO_DOUBLE_FETCH,
    LINUX_KO_INFOLEAK,
    LINUX_KO_NETLINK_OOB,
    *LINUX_KO_VERIFY_HYPOTHESES,
)

# ---------------------------------------------------------------------------
# Firmware — MIPS/ARM router/IoT/NAS binary lane  (origin seed:firmware:*)
# ---------------------------------------------------------------------------
#
# The firmware catalog's top ROI: an unauth CGI/handler reads a request/config
# value via a vendor getter (websGetVar / nvram_get / get_cgi / getenv / recv)
# that SURVIVES stripping as an import/PLT stub in a MIPS/ARM blob, then flows
# unsanitized into a shell sink (system/popen/doSystem) — CWE-78 — or an unbounded
# copy (strcpy/sprintf/sscanf) — CWE-120/787. These prime the Qiling firmware lane,
# whose cmdi-canary + crash oracle can CONFIRM them per-handler (unlike kernel
# targets). The getter symbols double as the surviving-symbol context hook.

# Vendor request/config getters that survive stripping as imports/PLT in a MIPS/ARM
# firmware blob — the firmware analogue of the kernel-only relocation vocabulary.
_FIRMWARE_GETTERS = (
    "websGetVar", "webGetVar", "websGetVarN", "get_cgi", "fcgi_get_query",
    "nvram_get", "nvram_safe_get", "nvram_bufget", "nvram_get_int", "GetValue",
    "json_object_get_string", "getenv", "recv", "recvfrom",
)

FIRMWARE_CGI_CMDI = SeedBugClass(
    id="firmware:cgi-cmdi",
    name="firmware unauth CGI/config getter → system()/popen() command injection",
    cwe="CWE-78",
    framing=(
        "Firmware command injection (the flagship SOHO/IoT bug): an HTTP/CGI or "
        "config handler reads an attacker value via a vendor getter (websGetVar / "
        "nvram_get / get_cgi / getenv) and passes it — often via an sprintf-built "
        "command buffer — into a shell sink (system/popen/execlp/doSystem) with no "
        "sanitization, giving unauth root. Treat this path as a sibling — look for "
        "the same getter value reaching a different shell sink, including "
        "second-order nvram_get→system. Confirmable in the firmware lane via the "
        "cmdi-canary oracle"
    ),
    dispatch_signals=(
        "websGetVar", "get_cgi", "cgiMain", "handle_request", "fcgi", "soap",
        "AddPortMapping", "_cgi", "doSystem",
    ),
    sink_signals=(
        "system", "popen", "execve", "execlp", "execl", "doSystem", "twsystem",
        "CsteSystem", "___system", "bstar_system",
    ),
    bound_signals=(
        "escape", "sanitiz", "filter", "isalnum", "strspn", "reject", "whitelist",
    ),
    kernel_signals=_FIRMWARE_GETTERS,
    target_formats=("ELF",),
    corroborating_signals=_FIRMWARE_GETTERS,
)

FIRMWARE_STACK_OVERFLOW = SeedBugClass(
    id="firmware:stack-overflow",
    name="firmware request/nvram value → unbounded strcpy/sprintf/sscanf into fixed buffer",
    cwe="CWE-121",
    framing=(
        "Firmware stack/heap overflow (ubiquitous SOHO shape): an attacker value "
        "from a vendor getter (websGetVar/nvram_get/recv) is copied unbounded into "
        "a fixed stack buffer via strcpy/strcat/sprintf/sscanf(%s)/memcpy, with no "
        "length clamp and (often) no stack canary — clean PC control. Treat this "
        "path as a sibling — look for the same getter value reaching a different "
        "unbounded copy. Confirmable in the firmware lane via the crash oracle "
        "(cyclic pattern → PC=pattern)"
    ),
    dispatch_signals=(
        "websGetVar", "get_cgi", "cgiMain", "handle_request", "_cgi", "recv",
        "Content-Disposition", "boundary",
    ),
    sink_signals=(
        "strcpy", "strcat", "sprintf", "vsprintf", "sscanf", "memcpy", "bcopy",
    ),
    bound_signals=(
        "strncpy", "strlcpy", "snprintf", "strlcat", "sizeof", "memcpy_s",
        "__stack_chk_fail",
    ),
    kernel_signals=_FIRMWARE_GETTERS,
    target_formats=("ELF",),
    corroborating_signals=_FIRMWARE_GETTERS,
)

FIRMWARE_SEEDS: tuple[SeedBugClass, ...] = (
    FIRMWARE_CGI_CMDI,
    FIRMWARE_STACK_OVERFLOW,
)

# Arches whose firmware blobs the firmware lane handles (mirrors firmware.py).
_FIRMWARE_ARCHES = frozenset({"mips", "mipsel", "arm", "aarch64"})


def firmware_seeds_for_arch(arch: str | None) -> list[SeedBugClass]:
    """Prime the firmware seed hypotheses for a MIPS/ARM firmware target. Empty for
    a non-firmware arch — these classes key on vendor getter symbols that only make
    sense in a router/IoT blob, never a host ELF."""
    if arch is None or arch not in _FIRMWARE_ARCHES:
        return []
    return list(FIRMWARE_SEEDS)


# The reusable registry — kernel/kext classes primed by ``seeds_for_target``.
# Firmware seeds are NOT folded in here: they are primed by arch via
# ``firmware_seeds_for_arch`` in the firmware lane (a firmware ELF is not a KMOD),
# so they never leak into the ``.ko`` lane.
SEED_CLASSES: tuple[SeedBugClass, ...] = (IOKIT_USER_CLIENT, *LINUX_KO_CLASSES)


# --- target hook + priming -------------------------------------------------

# Mach-O filetype for a kernel extension bundle (kext) and dylib — both can carry
# an IOKit user client. (MH_KEXT_BUNDLE = 11, MH_BUNDLE = 8, MH_DYLIB = 6.)
_KEXT_KINDS = frozenset({"KEXT_BUNDLE", "BUNDLE", "DYLIB", "OBJECT"})
# ELF relocatable object classified as a Linux kernel module (.ko) by ingest.
_KMOD_KINDS = frozenset({"KMOD"})


def seeds_for_target(
    fmt: str, kind: str, decompiled_c: dict[str, str] | None = None
) -> list[SeedBugClass]:
    """Pick **every** seed-bug-class that applies to a target. A Mach-O kext primes
    the IOKit class; a Linux ``.ko`` (ELF ``kind=="KMOD"``) primes all five
    kernel-module classes. This is the "point 0verse at a kernel binary and it
    knows what to hunt" hook (kext → IOKit, ``.ko`` → linux-ko:*)."""
    out: list[SeedBugClass] = []
    have_bodies = bool(decompiled_c)
    for seed in SEED_CLASSES:
        if fmt not in seed.target_formats:
            continue
        if fmt == "Mach-O":
            # Preserve the original kext behavior: with bodies, prime on an IOKit
            # context match; ingest-only, prime on the kext kind.
            if have_bodies:
                assert decompiled_c is not None
                if any(seed.is_kernel_context(c) for c in decompiled_c.values()):
                    out.append(seed)
            elif kind in _KEXT_KINDS:
                out.append(seed)
        # Only a relocatable kernel module primes the Linux classes — never a
        # plain userland ELF (whose code never references copy_from_user etc.).
        elif fmt == "ELF" and kind in _KMOD_KINDS:
            out.append(seed)
    return out


def seed_for_target(
    fmt: str, kind: str, decompiled_c: dict[str, str] | None = None
) -> SeedBugClass | None:
    """The primary (highest-priority) seed-bug-class for a target, or ``None``.
    Back-compat single-seed accessor; ``seeds_for_target`` returns the full set."""
    seeds = seeds_for_target(fmt, kind, decompiled_c)
    return seeds[0] if seeds else None


def prime_hypotheses(
    seed: SeedBugClass, decompiled_c: dict[str, str], *, max_hyps: int = 16
) -> list[Finding]:
    """Surface candidate dispatch/handler routines as hypotheses for the funnel.

    Each candidate becomes a ``Finding`` with origin ``seed:<id>`` — a directed,
    high-recall hypothesis (never a finding) that the #4 funnel ranks and the LLM
    triages under variant-analysis framing. Candidates with *no* nearby bound
    check sort first (the more suspicious shape)."""
    label = "iokit" if seed.id.startswith("iokit") else "kmod"
    out: list[Finding] = []
    for func, code in decompiled_c.items():
        if not code:
            continue
        is_cand, disp, sink = seed.matches(code)
        if not is_cand:
            continue
        unbounded = not seed.has_bound_check(code)
        out.append(
            Finding(
                source=f"{label}:{disp}",
                sink=sink,
                function=func,
                source_addr=0,
                sink_addr=0,
                # path_len 0 sorts a touch higher; unbounded candidates lead.
                path_len=0 if unbounded else 1,
                origin=f"seed:{seed.id}",
            )
        )
    out.sort(key=lambda f: f.path_len)
    return out[:max_hyps]

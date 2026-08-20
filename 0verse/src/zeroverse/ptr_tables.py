"""Struct/stride-aware function-pointer-table detection (phase 2, crutch-free).

WHY. ``ProgramMeta.ptr_tables`` feeds :func:`zeroverse.indirect_calls.resolve_indirect_edges`
the members of dispatch tables (vtables / handler arrays) so an indirectly-dispatched
function is a candidate target of the indirect call sites. The first-pass recoverer relied on
Ghidra having TYPED the words as pointers (``Data.isPointer()``), which fails on a stripped
binary with no DWARF — measured on lcms: the tag-type handler table (``cmsTagTypeHandler[]``)
was in ``.rodata`` yet recovered in 0 of 269 tables, so ``Type_LUTA2B_Write`` (which reaches
``WriteCLUT``) was never a member and the reverse path stayed empty.

Two reasons it was missed, both fixed here by working on RAW words instead of typed data:
  * the table is a **struct of pointers** — each entry is ``{Signature, ReadPtr, WritePtr,
    DupPtr, FreePtr, ContextID, ICCVersion, Next}`` (32-byte stride), so the function
    pointers are interleaved with scalar fields; a pure contiguous-run scan breaks at the
    first scalar.
  * on a stripped image Ghidra never typed the ``.rodata`` words as pointers at all.

This module is the PURE detector: given the addresses in a section whose raw value is a
function entry, it recovers both **contiguous runs** (a classic vtable) and **strided
columns** (the same field — e.g. every ``WritePtr`` — across fixed-size struct entries),
tolerating the interleaved scalars. The Ghidra glue (``backends.ghidra._recover_ptr_tables``)
supplies the function-pointer words by reading LOADED memory (so applied relocations are
seen) and attaches loaders by xref to the table base.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

# A strided table entry is at most this many pointer-slots wide (guards the stride search
# and rejects "progressions" that are really unrelated pointers far apart). 16 slots covers
# the cmsTagTypeHandler 8-word entry with room to spare.
MAX_STRIDE_SLOTS = 16
MIN_RUN_LEN = 2       # a contiguous vtable is >= 2 adjacent function pointers
MIN_STRIDE_LEN = 3    # a strided column needs >= 3 entries to not be coincidence


def _contiguous_runs(
    fp: Sequence[tuple[int, str]], ptr_size: int, min_len: int
) -> list[dict[str, Any]]:
    """Maximal runs of function pointers at adjacent word addresses (a classic vtable /
    jump array). ``fp`` is sorted ``(addr, name)``."""
    out: list[dict[str, Any]] = []
    run: list[tuple[int, str]] = []
    for aw in fp:
        if run and aw[0] == run[-1][0] + ptr_size:
            run.append(aw)
        else:
            if len(run) >= min_len:
                out.append(_table(run, ptr_size, "contiguous", ptr_size))
            run = [aw]
    if len(run) >= min_len:
        out.append(_table(run, ptr_size, "contiguous", ptr_size))
    return out


def _strided_columns(
    fp: Sequence[tuple[int, str]],
    ptr_size: int,
    min_len: int,
    max_stride_slots: int,
) -> list[dict[str, Any]]:
    """Function pointers forming an arithmetic progression at a fixed stride > one word —
    the same struct field (e.g. every ``WritePtr``) across fixed-size entries. Each such
    column is a dispatch set even though scalars sit between the pointers."""
    addrs = {a for a, _ in fp}
    name_of = dict(fp)
    out: list[dict[str, Any]] = []
    consumed: set[tuple[int, int]] = set()  # (start_addr, stride) already emitted
    for stride_slots in range(2, max_stride_slots + 1):
        stride = stride_slots * ptr_size
        for a0, _ in fp:
            if a0 - stride in addrs or (a0, stride) in consumed:
                continue  # not a progression start, or already covered
            run = [(a0, name_of[a0])]
            a = a0 + stride
            while a in addrs:
                run.append((a, name_of[a]))
                consumed.add((a, stride))
                a += stride
            if len(run) >= min_len:
                out.append(_table(run, ptr_size, "strided", stride))
    return out


def _table(run: Sequence[tuple[int, str]], ptr_size: int, kind: str, stride: int) -> dict[str, Any]:
    return {
        "section": "",
        "addr": hex(run[0][0]),
        "members": [n for _, n in run],
        "loaders": [],
        "kind": kind,
        "stride": stride,
    }


def detect_tables(
    fp_words: Iterable[tuple[int, str]],
    *,
    ptr_size: int = 8,
    section: str = "",
    min_run_len: int = MIN_RUN_LEN,
    min_stride_len: int = MIN_STRIDE_LEN,
    max_stride_slots: int = MAX_STRIDE_SLOTS,
) -> list[dict[str, Any]]:
    """Recover function-pointer tables from ``fp_words`` — the ``(addr, func_name)`` of every
    word in a section whose raw value is a function entry.

    Returns table records (``{section, addr, members, loaders, kind, stride}``) covering both
    contiguous vtables and strided struct-of-pointer columns. A contiguous run subsumes the
    per-entry pointer cluster; strided columns additionally group the same field across
    entries. Deduped by member-set so the two passes don't double-count an identical table."""
    fp = sorted(set(fp_words))
    if not fp:
        return []
    tables = _contiguous_runs(fp, ptr_size, min_run_len)
    tables += _strided_columns(fp, ptr_size, min_stride_len, max_stride_slots)
    # dedup by (addr, members) so contiguous+strided passes don't emit the same table twice.
    seen: set[tuple[str, tuple[str, ...]]] = set()
    out: list[dict[str, Any]] = []
    for t in tables:
        key = (t["addr"], tuple(t["members"]))
        if key in seen:
            continue
        seen.add(key)
        t["section"] = section
        out.append(t)
    return out

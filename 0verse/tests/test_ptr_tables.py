"""Struct/stride-aware fn-pointer-table detection — pure unit tests (no Ghidra).

Model the two shapes the first-pass contiguous recoverer missed: the lcms
``cmsTagTypeHandler[]`` struct-of-pointers (4 adjacent pointers then scalars, 32-byte
stride) and a sparse struct where the handler is one pointer per fixed-size entry.
"""

from zeroverse.ptr_tables import detect_tables


def _lcms_like_words(ps: int = 4) -> list[tuple[int, str]]:
    # three 32-byte (8-slot) entries; each has Read/Write/Dup/Free at slots 1..4, scalars at
    # 0 (Signature), 5 (ContextID), 6 (ICCVersion), 7 (Next) -> not function pointers.
    base = 0x82CAD00
    stride = 8 * ps
    words = []
    for e, tag in enumerate(("LUTA2B", "LUTB2A", "MPE")):
        entry = base + e * stride
        for slot, fld in ((1, "Read"), (2, "Write"), (3, "Dup"), (4, "Free")):
            words.append((entry + slot * ps, f"Type_{tag}_{fld}"))
    return words


def test_recovers_contiguous_pointer_cluster() -> None:
    tables = detect_tables(_lcms_like_words(), ptr_size=4, section=".rodata")
    members = {m for t in tables for m in t["members"]}
    # the WritePtr that reaches WriteCLUT must be a recovered member (the phase-1 gap).
    assert "Type_LUTA2B_Write" in members
    assert "Type_LUTB2A_Write" in members
    # the 4 adjacent pointers of one entry form a contiguous table.
    contig = [t for t in tables if t["kind"] == "contiguous"]
    assert any(t["members"] == [
        "Type_LUTA2B_Read", "Type_LUTA2B_Write", "Type_LUTA2B_Dup", "Type_LUTA2B_Free"
    ] for t in contig)


def test_recovers_strided_column_across_entries() -> None:
    # the same field across entries (every WritePtr) is a strided column at 32-byte stride.
    tables = detect_tables(_lcms_like_words(), ptr_size=4, section=".rodata")
    strided = [t for t in tables if t["kind"] == "strided"]
    write_cols = [t for t in strided if t["members"] == [
        "Type_LUTA2B_Write", "Type_LUTB2A_Write", "Type_MPE_Write"]]
    assert write_cols, "expected a WritePtr column across the entries"
    assert write_cols[0]["stride"] == 8 * 4


def test_sparse_struct_one_pointer_per_entry() -> None:
    # Windows-ish: a characteristics struct where the handler is one pointer per 6-slot
    # (48-byte, x64) entry, everything else scalar -> only a strided column recovers it.
    ps = 8
    stride = 6 * ps
    words = [(0x1C0000000 + i * stride + 2 * ps, f"Handler_{i}") for i in range(4)]
    tables = detect_tables(words, ptr_size=ps, section=".data")
    strided = [t for t in tables if t["kind"] == "strided" and len(t["members"]) >= 3]
    assert strided
    assert {"Handler_0", "Handler_3"} <= {m for t in strided for m in t["members"]}


def test_min_lengths_reject_singletons_and_pairs() -> None:
    # a lone pointer -> no table; a strided pair (< MIN_STRIDE_LEN=3) -> no strided table.
    assert detect_tables([(0x1000, "f")], ptr_size=8) == []
    two = [(0x1000, "a"), (0x1000 + 48, "b")]  # stride pair, only 2
    assert [t for t in detect_tables(two, ptr_size=8) if t["kind"] == "strided"] == []


def test_dedup_identical_tables() -> None:
    # a contiguous run is also a stride-1... but stride starts at 2 slots, so no dup there;
    # ensure identical member-set tables aren't emitted twice.
    words = [(0x2000 + i * 8, f"f{i}") for i in range(3)]
    tables = detect_tables(words, ptr_size=8)
    keys = [(t["addr"], tuple(t["members"])) for t in tables]
    assert len(keys) == len(set(keys))

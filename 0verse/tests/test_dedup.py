"""M7 #48 — tiered crash dedup (CrashComparer): the exact / LCS / Levenshtein
tiers, the distinct-bugs-stay-separate control, and the load-bearing invariant
that dedup never drops a confirmed-unique bug.
"""

from __future__ import annotations

from zeroverse.dedup import (
    CrashClusterer,
    CrashComparer,
    CrashKey,
    dedup_items,
    lcs_length,
    levenshtein,
    levenshtein_ratio,
)

# --- primitives ------------------------------------------------------------

def test_lcs_length_ordered_subsequence() -> None:
    assert lcs_length(["a", "b", "c"], ["a", "x", "c"]) == 2   # a,c
    assert lcs_length(["a", "b", "c"], ["c", "b", "a"]) == 1   # ordered, not a set
    assert lcs_length([], ["a"]) == 0


def test_levenshtein_basics() -> None:
    assert levenshtein("abc", "abc") == 0
    assert levenshtein("abc", "abd") == 1
    assert levenshtein("", "abc") == 3
    assert 0.99 < levenshtein_ratio("abc", "abc") <= 1.0
    assert levenshtein_ratio("abcdefghij", "abcdefghix") == 0.9


# --- the comparer tiers ----------------------------------------------------

def test_exact_tier_addr_and_frames() -> None:
    cmp = CrashComparer()
    a = CrashKey(crash_addr="0x401000", frames=("foo at f.c:10", "bar at f.c:20"))
    b = CrashKey(crash_addr="0x401000", frames=("foo at f.c:99", "bar at f.c:50"))
    # line numbers are normalized away -> same frames + same addr = exact.
    v = cmp.compare(a, b)
    assert v.duplicate and v.tier == "exact"


def test_exact_requires_same_addr() -> None:
    cmp = CrashComparer()
    a = CrashKey(crash_addr="0x401000", frames=("foo at f.c:10", "bar at f.c:20"))
    b = CrashKey(crash_addr="0xdead", frames=("foo at f.c:10", "bar at f.c:20"))
    # different faulting address -> not exact, but the frames still LCS-match.
    v = cmp.compare(a, b)
    assert v.duplicate and v.tier == "lcs"


def test_lcs_tier_same_bug_different_tail() -> None:
    # Same crashing prefix (the root cause), different inlined tail per input.
    cmp = CrashComparer()
    a = CrashKey(frames=("parse", "validate", "copy", "memcpy"))
    b = CrashKey(frames=("parse", "validate", "copy", "helper_a", "helper_b"))
    v = cmp.compare(a, b)
    assert v.duplicate and v.tier == "lcs"
    assert v.score >= 3   # parse,validate,copy shared


def test_levenshtein_tier_near_identical() -> None:
    # Only one shared frame (LCS=1 < 2) but the joined stacks are 80%+ similar.
    cmp = CrashComparer(lcs_min=2)
    a = CrashKey(frames=("alpha_handler_routine", "beta_parser"))
    b = CrashKey(frames=("alpha_handler_routine", "beta_parserX"))
    v = cmp.compare(a, b)
    assert v.duplicate and v.tier == "levenshtein"


# --- the boundary control: genuinely-distinct bugs stay separate -----------

def test_distinct_bugs_stay_separate() -> None:
    cmp = CrashComparer()
    a = CrashKey(crash_addr="0x1", frames=("json_parse", "tokenize", "next_char"))
    b = CrashKey(crash_addr="0x2", frames=("png_decode", "inflate", "huffman"))
    v = cmp.compare(a, b)
    assert not v.duplicate and v.tier == ""


def test_one_shared_frame_below_lcs_and_lev_threshold_is_distinct() -> None:
    cmp = CrashComparer(lcs_min=2)
    a = CrashKey(frames=("shared_common", "alpha", "beta", "gamma"))
    b = CrashKey(frames=("shared_common", "delta", "epsilon", "zeta"))
    # exactly one shared frame, and the long distinct tails drop the Lev ratio.
    v = cmp.compare(a, b)
    assert not v.duplicate


def test_empty_frames_never_merge() -> None:
    cmp = CrashComparer()
    assert not cmp.is_duplicate(CrashKey(frames=()), CrashKey(frames=()))
    assert not cmp.is_duplicate(CrashKey(frames=("foo",)), CrashKey(frames=()))


# --- clustering + dedup_items ----------------------------------------------

def test_same_bug_different_input_collapses_to_one() -> None:
    crashes = [
        CrashKey(crash_addr="0xa", frames=("parse", "validate", "copy", "memcpy")),
        CrashKey(crash_addr="0xa", frames=("parse", "validate", "copy", "memcpy")),  # exact dup
        CrashKey(crash_addr="0xb", frames=("parse", "validate", "copy", "alt_tail")),  # LCS dup
    ]
    reps, clusters = dedup_items(crashes, key_of=lambda k: k)
    assert len(reps) == 1
    assert len(clusters) == 1
    assert clusters[0].size == 3
    assert clusters[0].representative is crashes[0]


def test_distinct_bugs_all_survive_control() -> None:
    crashes = [
        CrashKey(crash_addr="0x1", frames=("json_parse", "tokenize", "next_char")),
        CrashKey(crash_addr="0x2", frames=("png_decode", "inflate", "huffman")),
        CrashKey(crash_addr="0x3", frames=("xml_read", "attr", "entity")),
    ]
    reps, _ = dedup_items(crashes, key_of=lambda k: k)
    assert len(reps) == 3   # PoV-is-truth: never drop a distinct confirmed bug


def test_dedup_never_drops_unique_among_dups() -> None:
    # Two copies of bug A, one of bug B, one of bug C -> exactly {A,B,C}.
    a1 = CrashKey(crash_addr="0xa", frames=("fa", "fb", "fc"))
    a2 = CrashKey(crash_addr="0xa", frames=("fa", "fb", "fc"))
    b = CrashKey(crash_addr="0xb", frames=("gx", "gy", "gz"))
    c = CrashKey(crash_addr="0xc", frames=("hp", "hq", "hr"))
    reps, _ = dedup_items([a1, a2, b, c], key_of=lambda k: k)
    assert len(reps) == 3
    assert b in reps and c in reps


def test_clusterer_records_tier_per_member() -> None:
    cl: CrashClusterer[CrashKey] = CrashClusterer()
    k0 = CrashKey(crash_addr="0xa", frames=("p", "q", "r", "s"))
    k1 = CrashKey(crash_addr="0xa", frames=("p", "q", "r", "s"))         # exact
    k2 = CrashKey(crash_addr="0xz", frames=("p", "q", "r", "t", "u"))    # lcs
    cl.add(k0, k0)
    cl.add(k1, k1)
    cl.add(k2, k2)
    assert len(cl.clusters) == 1
    assert cl.clusters[0].tiers == ["exact", "lcs"]

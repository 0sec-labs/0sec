"""M7 #48 — tiered crash dedup (gap G5).

``oracle.py`` already buckets crashes by an *exact* ClusterFuzz-style stack
signature (``crash_state`` / ``CrashSet``): two PoVs whose normalized top-N frames
are byte-identical collapse. That misses the common case the AIxCC finalists hit
hardest — **the same root-cause bug reached by two different inputs**, whose
backtraces differ in the *tail* (a couple of extra inlined frames, a reordered
helper) but share the crashing prefix. Both PoVs then surface as separate findings,
inflating the fleet/fuzz output and polluting the labeled-PoV dataset moat.

This module implements tiered crash dedup on 0verse's normalized crash frames,
guided by published ClusterFuzz crash-bucketing methodology.
Two crashes are the *same bug* by a tiered key, cheapest test first:

  1. **empty-reject** — a crash with no recovered frames is never fuzzy-matched to
     anything (PoV-is-truth: when in doubt, keep it as its own bug);
  2. **exact** — same crash address AND identical normalized top-N frames;
  3. **LCS** — the longest common *ordered* subsequence of the normalized frame
     lists is ``>= LCS_MIN_FRAMES`` (default 2) shared frames;
  4. **Levenshtein** — fallback string similarity of the joined normalized stack
     ``> LEV_RATIO`` (default 0.8).

Discipline (the load-bearing invariant): **dedup never drops a confirmed-unique
bug.** Clustering only ever *groups* crashes and keeps one representative per
cluster; a genuinely distinct crash (no exact / LCS / Levenshtein hit) always
forms its own singleton cluster and survives. PoV-is-truth is upstream of this —
nothing here adjudicates whether a crash is real; it only de-duplicates crashes
the oracle already confirmed.
"""

from __future__ import annotations

# Independent implementation of tiered crash dedup.
# No AIxCC finalist code is vendored or ported.
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Generic, TypeVar

from .oracle import crash_state

DEFAULT_TOP_N = 5
LCS_MIN_FRAMES = 2
LEV_RATIO = 0.8

T = TypeVar("T")


# --- primitives ------------------------------------------------------------

def lcs_length(a: Sequence[str], b: Sequence[str]) -> int:
    """Length of the longest common *ordered* subsequence of two frame lists.

    Ordered (not contiguous): ``[x, y, z]`` and ``[x, q, z]`` share ``[x, z]`` =
    length 2. This is the "≥2 ordered crash-state frames ⇒ duplicate" test.
    """
    if not a or not b:
        return 0
    prev = [0] * (len(b) + 1)
    for x in a:
        cur = [0] * (len(b) + 1)
        for j, y in enumerate(b, start=1):
            cur[j] = prev[j - 1] + 1 if x == y else max(prev[j], cur[j - 1])
        prev = cur
    return prev[len(b)]


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance (insert/delete/substitute), iterative two-row DP."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cur[j] = min(
                prev[j] + 1,           # delete
                cur[j - 1] + 1,        # insert
                prev[j - 1] + (ca != cb),  # substitute
            )
        prev = cur
    return prev[len(b)]


def levenshtein_ratio(a: str, b: str) -> float:
    """Normalized similarity in ``[0, 1]``: ``1 - dist / max(len)``. ``1.0`` is
    identical; ``> 0.8`` means the edit distance is under a fifth of the longer
    string. Deterministic and dependency-free (no python-Levenshtein needed)."""
    if not a and not b:
        return 1.0
    longest = max(len(a), len(b))
    if longest == 0:
        return 1.0
    return 1.0 - levenshtein(a, b) / longest


# --- the comparer ----------------------------------------------------------

@dataclass(frozen=True)
class CrashKey:
    """The dedup coordinates of one crash: its faulting address (when known) and
    its raw backtrace frames. Frames are normalized lazily via ``oracle.crash_state``
    so address/offset/line noise never splits the same bug."""

    crash_addr: str = ""
    frames: tuple[str, ...] = ()

    def normalized(self, top_n: int = DEFAULT_TOP_N) -> tuple[str, ...]:
        return crash_state(list(self.frames), top_n=top_n)


@dataclass
class DedupVerdict:
    """Why two crashes were (or were not) judged the same bug."""

    duplicate: bool
    tier: str = ""          # "" | "exact" | "lcs" | "levenshtein"
    score: float = 0.0      # LCS frame count, or the Levenshtein ratio


class CrashComparer:
    """Tiered same-bug comparer (independent implementation). Stateless; all
    thresholds are constructor knobs so a caller can tighten/loosen the boundary."""

    def __init__(
        self,
        *,
        top_n: int = DEFAULT_TOP_N,
        lcs_min: int = LCS_MIN_FRAMES,
        lev_ratio: float = LEV_RATIO,
    ) -> None:
        self.top_n = top_n
        self.lcs_min = lcs_min
        self.lev_ratio = lev_ratio

    def compare(self, a: CrashKey, b: CrashKey) -> DedupVerdict:
        na = a.normalized(self.top_n)
        nb = b.normalized(self.top_n)
        # 1. empty-reject: never fuzzy-merge a frameless crash.
        if not na or not nb:
            return DedupVerdict(False)
        # 2. exact: same faulting address AND identical normalized frames.
        if a.crash_addr == b.crash_addr and na == nb:
            return DedupVerdict(True, "exact", float(len(na)))
        # 3. LCS: enough shared ordered frames.
        shared = lcs_length(na, nb)
        if shared >= self.lcs_min:
            return DedupVerdict(True, "lcs", float(shared))
        # 4. Levenshtein fallback on the joined stack.
        ratio = levenshtein_ratio("\n".join(na), "\n".join(nb))
        if ratio > self.lev_ratio:
            return DedupVerdict(True, "levenshtein", ratio)
        return DedupVerdict(False, "", ratio)

    def is_duplicate(self, a: CrashKey, b: CrashKey) -> bool:
        return self.compare(a, b).duplicate


# --- clustering + generic dedup --------------------------------------------

@dataclass
class Cluster(Generic[T]):
    """One root-cause bug: its representative crash + every item that collapsed
    onto it, with the tier each duplicate matched on."""

    key: CrashKey
    representative: T
    members: list[T] = field(default_factory=list)
    tiers: list[str] = field(default_factory=list)

    @property
    def size(self) -> int:
        return 1 + len(self.members)


class CrashClusterer(Generic[T]):
    """Greedy single-pass clusterer: each new crash joins the FIRST existing
    cluster it duplicates (by representative), else starts its own. Order-stable —
    the first crash seen for a bug is its representative, so the result is
    deterministic given a stable input order."""

    def __init__(self, comparer: CrashComparer | None = None) -> None:
        self.comparer = comparer or CrashComparer()
        self.clusters: list[Cluster[T]] = []

    def add(self, key: CrashKey, item: T) -> Cluster[T]:
        for cluster in self.clusters:
            verdict = self.comparer.compare(cluster.key, key)
            if verdict.duplicate:
                cluster.members.append(item)
                cluster.tiers.append(verdict.tier)
                return cluster
        cluster = Cluster(key=key, representative=item)
        self.clusters.append(cluster)
        return cluster


def dedup_items(
    items: Sequence[T],
    key_of: Callable[[T], CrashKey],
    *,
    comparer: CrashComparer | None = None,
) -> tuple[list[T], list[Cluster[T]]]:
    """De-duplicate ``items`` by their crash key, keeping one representative per
    unique bug (input order preserved). Returns ``(representatives, clusters)``.

    The invariant the whole feature rests on: a frameless or genuinely-distinct
    crash always forms its own singleton cluster, so **no confirmed-unique bug is
    ever dropped** — only same-bug-different-input duplicates collapse.
    """
    clusterer: CrashClusterer[T] = CrashClusterer(comparer)
    for item in items:
        clusterer.add(key_of(item), item)
    reps = [c.representative for c in clusterer.clusters]
    return reps, clusterer.clusters

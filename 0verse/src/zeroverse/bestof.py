"""Best-of-N exploration — beat run-to-run VARIANCE by voting across independent runs.

The failure this closes (reliability wall #3): a single ``explore`` run is STOCHASTIC.
A real bug that the model finds on one run it MISSES on the next — libraw HITs at only
~1/4. One run is a coin flip; the finding is real but the *sampling* is unreliable, so
a target flickers between HIT and MISS depending on which draw you happened to take.

The fix is the oldest trick against variance: sample more and aggregate. Run ``explore``
N times with a FRESH llm each time (the model is the variance source, so each run must
be an independent draw — a scripted/seeded factory, a new codex session), then SELECT a
finding by AGREEMENT across runs. A bug found at the SAME sink in 4 of 5 runs is a strong
reproducible signal; a bug seen in 1 of 5 is a flicker (kept, but flagged weak). At a
per-run HIT rate of ~1/4, four independent runs make "at least one HIT" ~68% likely, and
eight make it ~99% — so best-of-N converts an unreliable per-run recall into a
near-certain finding, and the agreement count tells you HOW reproducible it was.

Honest limits (stated, not hidden):
  * It costs N times the tokens/compute of one run — this buys recall, nothing else.
  * Agreement reduces VARIANCE-driven misses. It does NOT make truth: a CONSISTENT
    false positive (the model reasons the same wrong way every run) recurs across runs
    too and would win the vote. Best-of-N is not a truth oracle — it raises recall and
    hands you a reproducibility SIGNAL; the downstream oracle still confirms the PoV.

This is a THIN orchestration layer over ``agentic.explore``: it injects an ``llm_factory``
(so tests drive it with a scripted-mock factory — no codex, no Ghidra) and does the
grouping/selection. All the real work stays in ``explore``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .agentic import AgentResult, AgentVerdict, explore

# --- sink normalization (the agreement key) ---------------------------------
#
# Two runs that find the SAME bug rarely emit a byte-identical sink string: the index
# variable differs (``auStack_28[count]`` vs ``auStack_28[i]`` vs ``auStack_28[idx]``),
# whitespace/casing drift. We normalize so those collapse to one agreement bucket while
# genuinely different sinks stay apart. The buffer/callee IDENTITY is what carries — the
# subscript CONTENTS are noise — so we blank the inside of every ``[...]``.
_INDEX_RE = re.compile(r"\[[^\]]*\]")
_WS_RE = re.compile(r"\s+")


def _normalize_sink(v: AgentVerdict) -> str:
    """The agreement bucket key for a positive verdict: a normalized sink string.

    Lower-cased, whitespace-collapsed, and with every ``[...]`` subscript blanked to
    ``[]`` so the same buffer indexed by different loop variables across runs groups
    together. An empty sink (the model gave none) falls back to the CWE so distinct
    empty-sink findings do not blindly collapse into one bucket."""
    raw = (v.sink or "").strip()
    if not raw:
        raw = f"<no-sink cwe={(v.cwe or 'unspecified').strip()}>"
    s = _INDEX_RE.sub("[]", raw.lower())
    return _WS_RE.sub(" ", s).strip()


def _is_positive(res: AgentResult) -> bool:
    """A run counts as a POSITIVE finding when its (possibly adversarially-reviewed)
    verdict asserts a bug. ``explore`` already DOWNGRADES a refuted positive to
    ``is_bug=False``, so an ``is_bug=True`` here has survived that pass when it ran."""
    return res.verdict is not None and res.verdict.is_bug


def _upheld(res: AgentResult) -> bool:
    """Did this positive survive the adversarial second pass? True when there was no
    review (pass disabled) — the raw first-pass positive — or the review upheld it."""
    return res.review is None or res.review.upheld


@dataclass
class SinkGroup:
    """One agreement bucket: the runs (of N) that reported a bug at the same normalized
    sink. ``count`` is the reproducibility signal; ``representative`` is the run we
    surface for this finding (an adversarially-upheld run when available)."""

    sink: str                       # normalized sink key
    count: int                      # how many of the N runs produced this sink
    upheld_count: int               # how many of those survived adversarial review
    run_indices: list[int]          # 0-based indices into ``BestOfNResult.all``
    representative: AgentResult      # the run to report for this finding


@dataclass
class BestOfNResult:
    """The aggregate of N independent ``explore`` runs.

    ``best`` is the selected result — the positive finding with the STRONGEST agreement
    (most runs, then most adversarially-upheld), or, when no run found a bug, an honest
    negative. ``all`` is every run in order. ``agreement`` maps each normalized sink to
    the number of runs that produced it (the reproducibility signal, e.g. ``{"a": 4,
    "b": 1}`` reads "sink a in 4/N runs, sink b in 1/N"). ``groups`` is the same, richer,
    sorted best-first."""

    best: AgentResult
    all: list[AgentResult]
    agreement: dict[str, int]
    groups: list[SinkGroup] = field(default_factory=list)
    n: int = 0

    @property
    def best_is_positive(self) -> bool:
        return _is_positive(self.best)

    def summary(self) -> str:
        """A one-line-per-finding reproducibility report, e.g. ``sink 'x' in 3/5 runs``."""
        if not self.groups:
            neg = sum(1 for r in self.all if not _is_positive(r))
            return f"no positive finding in any of {self.n} runs ({neg} negative)."
        lines = [f"best-of-{self.n} agreement (reproducibility of each finding):"]
        for g in self.groups:
            upheld = (
                f", {g.upheld_count} adversarially-upheld"
                if g.upheld_count != g.count else ""
            )
            lines.append(f"  - sink {g.sink!r} in {g.count}/{self.n} runs{upheld}")
        return "\n".join(lines)


def explore_best_of_n(
    meta: Any,
    llm_factory: Callable[[], Any],
    *,
    n: int = 5,
    **explore_kwargs: Any,
) -> BestOfNResult:
    """Run ``explore`` ``n`` times with a FRESH llm per run and select by agreement.

    ``llm_factory()`` is called ONCE PER RUN — the model is the variance source, so each
    run must be an independent draw (a new scripted mock in tests, a new codex session in
    production). ``explore_kwargs`` pass straight through to ``explore`` (``max_steps``,
    ``entry``, ``reachable_hint``, ``format_hints``, ``adversarial``, ...).

    Selection:
      * Group the POSITIVE runs by normalized sink (see ``_normalize_sink``); ``agreement``
        records how many runs produced each sink — the reproducibility signal.
      * ``best`` is the group with the most runs (ties broken by more adversarially-upheld
        runs, then the sink string for determinism). A finding seen in MULTIPLE runs beats
        a singleton; a singleton positive is still returned (recall over silence) but its
        1/N agreement flags it weak.
      * The group's ``representative`` is an adversarially-upheld run when one exists, else
        its first run.
      * When NO run found a bug, ``best`` is an honest negative — preferring a run that
        reached a real verdict over one that exhausted its budget or errored.
    """
    if n < 1:
        raise ValueError(f"n must be >= 1, got {n}")

    results: list[AgentResult] = []
    for _ in range(n):
        llm = llm_factory()  # fresh model per run — the independent draw
        results.append(explore(meta, llm, **explore_kwargs))

    # -- group the positives by normalized sink (the agreement buckets) -------
    buckets: dict[str, list[int]] = {}
    for i, res in enumerate(results):
        if _is_positive(res):
            buckets.setdefault(_normalize_sink(res.verdict), []).append(i)  # type: ignore[arg-type]

    groups: list[SinkGroup] = []
    for sink, idxs in buckets.items():
        upheld_idxs = [i for i in idxs if _upheld(results[i])]
        rep_idx = upheld_idxs[0] if upheld_idxs else idxs[0]
        groups.append(
            SinkGroup(
                sink=sink,
                count=len(idxs),
                upheld_count=len(upheld_idxs),
                run_indices=idxs,
                representative=results[rep_idx],
            )
        )
    # strongest agreement first: most runs, then most upheld, then stable by sink
    groups.sort(key=lambda g: (-g.count, -g.upheld_count, g.sink))

    agreement = {g.sink: g.count for g in groups}

    # ``best`` is the strongest-agreement positive, or — when no run found a bug — the
    # most informative NEGATIVE (a run that reached a verdict over a budget/error stop).
    best = groups[0].representative if groups else _best_negative(results)

    return BestOfNResult(best=best, all=results, agreement=agreement, groups=groups, n=n)


def _best_negative(results: list[AgentResult]) -> AgentResult:
    """Pick the most informative negative run: prefer one that reached a real verdict
    (``stop_reason == 'verdict'``) over a budget-exhausted / loop-guarded / errored run,
    so the reported negative carries the model's actual reasoning, not a timeout."""
    return max(
        results,
        key=lambda r: (
            r.verdict is not None,          # reached a verdict at all
            r.stop_reason == "verdict",     # a clean conclusion, not max_steps/error
            len(r.visited),                 # more coverage = more thorough negative
        ),
    )

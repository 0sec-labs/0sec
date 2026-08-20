"""M7 #44 — strategy scheduler + per-lane LLM budget (the ATLANTIS TASK SCHEDULER,
in-process).

``pipeline.py`` is a fixed sequential best-effort spine: every stage runs once, in
order, with no budget control across the static / fuzz / concolic / seed lanes and
no per-stage LLM token cap. The 0verse evaluation measured the cost of that — a
clean binary that confirms nothing still burned the full no-signal fuzz lane
(~30 s) and would burn LLM tokens escalating slices the slice layer never flagged.

This module is the **in-process** ATLANTIS §4.3 TASK SCHEDULER + BUDGET ALLOCATOR,
NOT the k8s/Kafka mesh (that belongs to 0cloud). It gives the spine:

  * a **lane-task priority queue** popped per **epoch** by ATLANTIS's anti-starvation
    **weighted-random sampling** (every positive-priority lane eventually runs; hot
    lanes run more) — ``TaskScheduler`` / ``LaneTask``;
  * **event-driven reprioritization** — a lane that produces signal bumps its
    tasks, a confirmed sink drops its tasks, an exhausted lane is deprioritized —
    ``Event`` / ``TaskScheduler.apply_event``;
  * a **fuzzer fallback chain** (AFL++ QEMU-mode → native → Qiling) that demotes an
    engine aborting too often — ``FallbackChain``;
  * a **per-lane LLM token budget** with a global ceiling — ``BudgetLedger`` /
    ``LaneBudget`` — and a **content-hash LLM response cache** — ``LLMCache`` /
    ``BudgetedCachingLLM`` — so the engine never re-pays for an identical prompt and
    never spends expensive LLM on a target with no slice signal.

It is wired as an **opt-in** orchestration mode over the existing ``pipeline.run``
spine (``ZEROVERSE_SCHEDULER=1``), default OFF — the deterministic pipeline path is
byte-for-byte unchanged when the flag is absent. The scheduler only reorders /
budgets the SAME lanes; **PoV-is-truth is untouched** — it never changes WHAT counts
as a finding (the oracle still adjudicates every crash; a budget-starved LLM call
degrades to a structural hypothesis, exactly as a rate-limited real backend would).
"""

from __future__ import annotations

import hashlib
import json
import os
import random
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import Enum, StrEnum
from typing import Any, cast

# ---------------------------------------------------------------------------
# Lanes — the schedulable units of pipeline work (ATLANTIS §4.3 task families).
# ---------------------------------------------------------------------------


class Lane(StrEnum):
    """The pipeline's lanes, the granularity the scheduler budgets + reprioritises."""

    SLICE = "slice"               # #2 backward-slice static analysis
    FOXGUARD = "foxguard"         # #3 source-scanner pre-pass union
    SEED = "seed"                 # seed-archetype priming
    BUGCLASS = "bugclass"         # M4 bug-class lenses
    TRIAGE = "triage"             # #4 cheap→expensive LLM funnel  (LLM lane)
    CONCOLIC = "concolic"         # #5 angr reachability prune
    HARNESS = "harness"           # #16 harness synthesis          (LLM lane)
    DIRECTED_FUZZ = "directed_fuzz"  # #39/#40/#41 directed AFL++ lane
    DRILLER = "driller"           # #17 concolic fuzz-stall assist
    PAYLOAD = "payload"           # #4-class script payload-gen    (LLM lane)
    LAST_MILE = "last_mile"       # reached-but-uncrashed LLM assist (LLM lane)
    PATCH = "patch"               # #45/#46 patch synthesis        (LLM lane)


# Lanes that actually spend LLM tokens (get a per-lane budget key).
LLM_LANES: frozenset[Lane] = frozenset(
    {Lane.TRIAGE, Lane.HARNESS, Lane.PAYLOAD, Lane.LAST_MILE, Lane.PATCH}
)


# ---------------------------------------------------------------------------
# Token accounting + per-lane budget (ATLANTIS BUDGET ALLOCATOR / per-module caps).
# ---------------------------------------------------------------------------


def estimate_tokens(text: str) -> int:
    """A deterministic, provider-neutral token estimate (~4 chars/token, the GPT/
    Claude rule of thumb). Used for budget accounting and for the cache's
    saved-token tally. It is an *estimate* — labelled as such everywhere — because
    the scheduler must account for spend without a live billing round-trip."""
    return max(1, len(text) // 4)


class BudgetExceeded(RuntimeError):
    """Raised by ``BudgetedCachingLLM`` when a call would breach a lane or the
    global ceiling. The triage agent catches it (like any backend failure) and
    degrades to a structural hypothesis — never a fabricated confirmation."""


@dataclass
class LaneBudget:
    """A per-lane token budget key (ATLANTIS per-module TPM cap analog)."""

    lane: Lane
    budget: int
    spent: int = 0
    calls: int = 0
    blocked: int = 0

    @property
    def remaining(self) -> int:
        return max(0, self.budget - self.spent)

    def can_spend(self, tokens: int) -> bool:
        return self.spent + tokens <= self.budget

    def charge(self, tokens: int) -> None:
        self.spent += tokens
        self.calls += 1


@dataclass
class BudgetLedger:
    """Per-lane budgets under a shared global ceiling. ``can_spend`` requires BOTH
    the lane key and the global ceiling to have headroom — the two-level cap
    ATLANTIS used to stop one module starving the run."""

    global_ceiling: int
    lanes: dict[Lane, LaneBudget] = field(default_factory=dict)
    global_spent: int = 0

    def set_budget(self, lane: Lane, budget: int) -> None:
        lb = self.lanes.get(lane)
        if lb is None:
            self.lanes[lane] = LaneBudget(lane, budget)
        else:
            lb.budget = budget

    def budget(self, lane: Lane) -> LaneBudget:
        lb = self.lanes.get(lane)
        if lb is None:
            lb = LaneBudget(lane, 0)
            self.lanes[lane] = lb
        return lb

    @property
    def global_remaining(self) -> int:
        return max(0, self.global_ceiling - self.global_spent)

    def can_spend(self, lane: Lane, tokens: int) -> bool:
        return (
            self.budget(lane).can_spend(tokens)
            and self.global_spent + tokens <= self.global_ceiling
        )

    def charge(self, lane: Lane, tokens: int) -> None:
        self.budget(lane).charge(tokens)
        self.global_spent += tokens

    def note_blocked(self, lane: Lane) -> None:
        self.budget(lane).blocked += 1

    def summary(self) -> dict[str, Any]:
        return {
            "global_ceiling": self.global_ceiling,
            "global_spent": self.global_spent,
            "lanes": {
                lane.value: {
                    "budget": lb.budget,
                    "spent": lb.spent,
                    "calls": lb.calls,
                    "blocked": lb.blocked,
                }
                for lane, lb in self.lanes.items()
            },
        }


# ---------------------------------------------------------------------------
# Content-hash LLM response cache (ATLANTIS "cache all LLM + static lookups").
# ---------------------------------------------------------------------------


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    saved_tokens: int = 0

    @property
    def total(self) -> int:
        return self.hits + self.misses

    @property
    def hit_rate(self) -> float:
        return self.hits / self.total if self.total else 0.0


class LLMCache:
    """A content-hash cache of LLM verdicts keyed by ``sha256(system|prompt|schema)``.
    An identical prompt is never paid for twice — the win ATLANTIS got from
    Anthropic prompt caching, made provider-neutral and in-process."""

    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}
        self._cost: dict[str, int] = {}
        self.stats = CacheStats()

    @staticmethod
    def key(system: str, prompt: str, schema: dict[str, Any]) -> str:
        h = hashlib.sha256()
        h.update(system.encode("utf-8", "replace"))
        h.update(b"\x00")
        h.update(prompt.encode("utf-8", "replace"))
        h.update(b"\x00")
        h.update(json.dumps(schema, sort_keys=True).encode("utf-8", "replace"))
        return h.hexdigest()

    def get(self, key: str) -> dict[str, Any] | None:
        hit = self._store.get(key)
        if hit is not None:
            self.stats.hits += 1
            self.stats.saved_tokens += self._cost.get(key, 0)
            return dict(hit)
        self.stats.misses += 1
        return None

    def put(self, key: str, value: dict[str, Any], tokens: int) -> None:
        self._store[key] = dict(value)
        self._cost[key] = tokens


@dataclass
class LLMMeter:
    """Live tally of LLM spend through ``BudgetedCachingLLM`` (calls + est. tokens)."""

    calls: int = 0
    cached_calls: int = 0
    blocked_calls: int = 0
    request_tokens: int = 0
    response_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.request_tokens + self.response_tokens


class BudgetedCachingLLM:
    """An ``agent.LLM`` wrapper: content-hash cache → per-lane budget gate → inner
    backend. A cache hit costs nothing; a miss is charged to the lane key and the
    global ceiling. When the budget is exhausted it raises ``BudgetExceeded`` — the
    triage agent catches it and degrades, so the no-signal target simply stops
    paying for expensive escalations instead of crashing. PoV-is-truth is intact:
    a degraded verdict is a hypothesis, never a confirmation."""

    def __init__(
        self,
        inner: Any,
        ledger: BudgetLedger,
        cache: LLMCache,
        lane: Lane = Lane.TRIAGE,
        meter: LLMMeter | None = None,
    ) -> None:
        self._inner = inner
        self._ledger = ledger
        self._cache = cache
        self._lane = lane
        self.meter = meter or LLMMeter()

    def complete_json(
        self, system: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any]:
        key = self._cache.key(system, prompt, schema)
        cached = self._cache.get(key)
        if cached is not None:
            self.meter.cached_calls += 1
            return cached
        req_tokens = estimate_tokens(system) + estimate_tokens(prompt)
        if not self._ledger.can_spend(self._lane, req_tokens):
            self.meter.blocked_calls += 1
            self._ledger.note_blocked(self._lane)
            raise BudgetExceeded(
                f"{self._lane.value} lane budget exhausted "
                f"(need ~{req_tokens} tok, lane remaining "
                f"{self._ledger.budget(self._lane).remaining}, global remaining "
                f"{self._ledger.global_remaining})"
            )
        resp: dict[str, Any] = self._inner.complete_json(system, prompt, schema)
        resp_tokens = estimate_tokens(json.dumps(resp))
        self._ledger.charge(self._lane, req_tokens + resp_tokens)
        self._cache.put(key, resp, req_tokens + resp_tokens)
        self.meter.calls += 1
        self.meter.request_tokens += req_tokens
        self.meter.response_tokens += resp_tokens
        return resp

    def begin_conversation(
        self,
        system: str,
        prompt: str,
        schema: dict[str, Any],
    ) -> Any | None:
        """Forward provider-native conversations without caching opaque state."""
        factory = getattr(self._inner, "begin_conversation", None)
        if not callable(factory):
            return None
        inner_conversation = factory(system, prompt, schema)
        if inner_conversation is None:
            return None
        return _BudgetedConversation(inner_conversation, self)


class _BudgetedConversation:
    """Charge each stateful provider-native turn without caching replay state."""

    def __init__(self, inner: Any, owner: BudgetedCachingLLM) -> None:
        self._inner = inner
        self._owner = owner

    def append_user(self, text: str) -> None:
        self._inner.append_user(text)

    def complete_json(self) -> dict[str, Any]:
        # A content-hash cache cannot safely substitute a provider-native
        # continuation: the exact assistant blocks and signatures are state.
        prompt = self._inner.budget_prompt()
        req_tokens = estimate_tokens(prompt)
        owner = self._owner
        if not owner._ledger.can_spend(owner._lane, req_tokens):
            owner.meter.blocked_calls += 1
            owner._ledger.note_blocked(owner._lane)
            raise BudgetExceeded(
                f"{owner._lane.value} lane budget exhausted "
                f"(need ~{req_tokens} tok, lane remaining "
                f"{owner._ledger.budget(owner._lane).remaining}, global remaining "
                f"{owner._ledger.global_remaining})"
            )
        response = cast(dict[str, Any], self._inner.complete_json())
        response_tokens = estimate_tokens(json.dumps(response))
        owner._ledger.charge(owner._lane, req_tokens + response_tokens)
        owner.meter.calls += 1
        owner.meter.request_tokens += req_tokens
        owner.meter.response_tokens += response_tokens
        return response


# ---------------------------------------------------------------------------
# Fuzzer fallback chain (ATLANTIS LibAFL→AFL++→libFuzzer demotion on repeated abort).
# ---------------------------------------------------------------------------

# 0verse's fuzzing vectors, strongest first: AFL++ QEMU-mode → native AFL++ →
# Qiling firmware emulation. An engine that aborts > ``demote_after`` times in one
# epoch is demoted to the next.
DEFAULT_FUZZ_CHAIN: tuple[str, ...] = ("afl-qemu", "afl-native", "qiling")


@dataclass
class FallbackChain:
    """Cycle through fuzz engines, demoting one that aborts too often in an epoch."""

    options: tuple[str, ...] = DEFAULT_FUZZ_CHAIN
    demote_after: int = 2
    _idx: int = 0
    _aborts: int = 0
    demotions: int = 0

    @property
    def current(self) -> str:
        return self.options[self._idx]

    @property
    def exhausted(self) -> bool:
        return self._idx >= len(self.options) - 1 and self._aborts > self.demote_after

    def note_abort(self) -> bool:
        """Record an abort; demote (advance) when over threshold. Returns True iff
        the active engine changed."""
        self._aborts += 1
        if self._aborts > self.demote_after and self._idx < len(self.options) - 1:
            self._idx += 1
            self._aborts = 0
            self.demotions += 1
            return True
        return False

    def note_success(self) -> None:
        self._aborts = 0

    def reset_epoch(self) -> None:
        self._aborts = 0


# ---------------------------------------------------------------------------
# Lane-task model + event-driven reprioritization.
# ---------------------------------------------------------------------------


class TaskState(Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    EXHAUSTED = "exhausted"
    DROPPED = "dropped"


class EventKind(Enum):
    SIGNAL = "signal"        # a lane produced a lead (uncrashed sink / hot seed) → bump
    CONFIRMED = "confirmed"  # the oracle confirmed a sink → drop its tasks
    EXHAUSTED = "exhausted"  # a lane confirmed nothing / proved unreachable → deprioritize
    STALL = "stall"          # an engine stalled → trigger the fallback chain


@dataclass
class Event:
    """A mid-run reprioritization signal (ATLANTIS reacts to SARIF/reachability)."""

    kind: EventKind
    lane: Lane | None = None
    target: str | None = None   # task name or sink key the event refers to
    weight: int = 1


@dataclass
class TaskResult:
    """What a lane-task's executor returns — work output plus events to react to."""

    note: str = ""
    events: list[Event] = field(default_factory=list)
    aborted: bool = False


@dataclass
class LaneTask:
    """One schedulable unit of pipeline work with a mutable integer priority."""

    name: str
    lane: Lane
    priority: int
    run: Callable[[], TaskResult] | None = None
    state: TaskState = TaskState.PENDING
    runs: int = 0
    repeatable: bool = False     # a fuzz lane re-runs across epochs; a slice runs once

    @property
    def active(self) -> bool:
        return self.state in (TaskState.PENDING, TaskState.RUNNING)


@dataclass
class SchedulerConfig:
    """Epoch + anti-starvation knobs. Deterministic given ``seed``."""

    epoch_pop: int = 3          # tasks popped per epoch (the K in top-K)
    max_epochs: int = 64        # hard stop so the loop always terminates
    priority_floor: int = 1     # min sampling weight — anti-starvation guarantee
    bump: int = 5               # +priority on a SIGNAL event
    deprioritize_to: int = 1    # priority an EXHAUSTED lane drops to
    seed: int = 0               # RNG seed


@dataclass
class ScheduleReport:
    """The trace of a scheduler run — the epoch plan + what reacted to what."""

    epochs: list[list[str]] = field(default_factory=list)   # task names per epoch
    events_applied: int = 0
    fallback_demotions: int = 0
    notes: list[str] = field(default_factory=list)


class TaskScheduler:
    """ATLANTIS §4.3 in-process: a priority queue of lane-tasks popped per epoch by
    **weighted-random sampling** (prob ∝ priority, floored so every active task has
    a non-zero chance — the anti-starvation guarantee), with event-driven
    reprioritization and a fuzzer fallback chain. Deterministic given a seeded RNG."""

    def __init__(
        self,
        config: SchedulerConfig | None = None,
        fallback: FallbackChain | None = None,
    ) -> None:
        self.config = config or SchedulerConfig()
        self.tasks: list[LaneTask] = []
        self.fallback = fallback or FallbackChain()
        self._rng = random.Random(self.config.seed)

    # -- queue management ----------------------------------------------------

    def add(self, task: LaneTask) -> LaneTask:
        self.tasks.append(task)
        return task

    def active_tasks(self) -> list[LaneTask]:
        return [t for t in self.tasks if t.active]

    def _weight(self, task: LaneTask) -> int:
        return max(self.config.priority_floor, task.priority)

    def sample_epoch(self, k: int | None = None) -> list[LaneTask]:
        """Pop up to K active tasks by weighted-random sampling WITHOUT replacement.
        Higher priority ⇒ more likely, but the priority floor keeps every active
        task reachable (anti-starvation). Deterministic given the config seed."""
        k = self.config.epoch_pop if k is None else k
        pool = self.active_tasks()
        chosen: list[LaneTask] = []
        # Stable base order (name) so equal-weight draws are reproducible.
        pool.sort(key=lambda t: t.name)
        for _ in range(min(k, len(pool))):
            weights = [self._weight(t) for t in pool]
            pick = self._rng.choices(pool, weights=weights, k=1)[0]
            chosen.append(pick)
            pool.remove(pick)
        return chosen

    # -- event-driven reprioritization --------------------------------------

    def apply_event(self, event: Event) -> None:
        cfg = self.config
        if event.kind is EventKind.SIGNAL:
            for t in self.tasks:
                if t.active and (event.lane is None or t.lane == event.lane):
                    t.priority += cfg.bump * event.weight
        elif event.kind is EventKind.CONFIRMED:
            # Drop the tasks for the confirmed lane/target — don't keep steering at
            # a solved bug (ATLANTIS removes a confirmed sink from the live set).
            for t in self.tasks:
                if not t.active:
                    continue
                if (event.target is not None and t.name == event.target) or (
                    event.target is None
                    and event.lane is not None
                    and t.lane == event.lane
                ):
                    t.state = TaskState.DONE
        elif event.kind is EventKind.EXHAUSTED:
            for t in self.tasks:
                if t.active and (event.lane is None or t.lane == event.lane):
                    if t.repeatable:
                        t.priority = cfg.deprioritize_to
                    else:
                        t.state = TaskState.EXHAUSTED
        elif event.kind is EventKind.STALL:
            self.fallback.note_abort()

    # -- the epoch loop ------------------------------------------------------

    def run(self) -> ScheduleReport:
        """Run epochs until no active task remains or ``max_epochs`` is hit. Each
        epoch: sample top-K, execute, react to emitted events. A non-repeatable task
        is marked DONE after one run; a repeatable (fuzz) task stays in the queue."""
        report = ScheduleReport()
        for _ in range(self.config.max_epochs):
            epoch = self.sample_epoch()
            if not epoch:
                break
            self.fallback.reset_epoch()
            report.epochs.append([t.name for t in epoch])
            for task in epoch:
                task.state = TaskState.RUNNING
                result = task.run() if task.run is not None else TaskResult()
                task.runs += 1
                for ev in result.events:
                    self.apply_event(ev)
                    report.events_applied += 1
                if result.aborted:
                    self.apply_event(Event(EventKind.STALL, lane=task.lane))
                # repeatable tasks (fuzz) go back to PENDING for the next epoch;
                # one-shot tasks are DONE — unless an event already retired them.
                if task.state is TaskState.RUNNING:
                    task.state = (
                        TaskState.PENDING if task.repeatable else TaskState.DONE
                    )
        report.fallback_demotions = self.fallback.demotions
        return report


# ---------------------------------------------------------------------------
# Live integration glue: opt-in budget-aware orchestration over pipeline.run.
# ---------------------------------------------------------------------------

# Default budgets (token estimates). Generous by default so an ordinary scheduled
# run matches the sequential pipeline; ``ZEROVERSE_SCHED_*`` env vars tighten them
# (the benchmark drives a deliberately tight ceiling to expose the savings).
DEFAULT_GLOBAL_CEILING = 200_000
DEFAULT_LANE_BUDGET = 50_000


def scheduler_enabled() -> bool:
    """Opt-in flag. Default OFF ⇒ the deterministic pipeline path is unchanged."""
    return bool(os.environ.get("ZEROVERSE_SCHEDULER"))


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str) -> float | None:
    raw = os.environ.get(name)
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


@dataclass
class SessionConfig:
    global_ceiling: int = DEFAULT_GLOBAL_CEILING
    lane_budget: int = DEFAULT_LANE_BUDGET
    # A tight wall-clock ceiling (seconds). When set, no-signal lanes (the
    # no-signal fuzz complement) are skipped — the measured-waste fix. None ⇒
    # generous: every lane runs as in the sequential pipeline.
    time_budget_s: float | None = None
    seed: int = 0

    @classmethod
    def from_env(cls) -> SessionConfig:
        return cls(
            global_ceiling=_env_int("ZEROVERSE_SCHED_CEILING", DEFAULT_GLOBAL_CEILING),
            lane_budget=_env_int("ZEROVERSE_SCHED_LANE_BUDGET", DEFAULT_LANE_BUDGET),
            time_budget_s=_env_float("ZEROVERSE_SCHED_TIME_BUDGET"),
            seed=_env_int("ZEROVERSE_SCHED_SEED", 0),
        )


# Canonical lane priorities — the static/cheap lanes outrank the expensive LLM and
# fuzz lanes, mirroring the cheap→expensive funnel discipline.
_BASE_PRIORITY: dict[Lane, int] = {
    Lane.SLICE: 30,
    Lane.FOXGUARD: 25,
    Lane.SEED: 20,
    Lane.BUGCLASS: 20,
    Lane.CONCOLIC: 15,
    Lane.TRIAGE: 12,
    Lane.HARNESS: 8,
    Lane.DIRECTED_FUZZ: 6,
    Lane.DRILLER: 5,
    Lane.PAYLOAD: 4,
    Lane.LAST_MILE: 4,
    Lane.PATCH: 3,
}


class SchedulerSession:
    """Holds the per-run budget ledger, LLM cache, lane scheduler, and the
    budget/skip decisions ``pipeline.run`` consults when ``ZEROVERSE_SCHEDULER=1``.

    The heavy static spine still executes in pipeline order (reordering Ghidra/AFL
    execution in-place would be invasive and risk the deterministic path); what the
    scheduler governs is **LLM spend** (per-lane budget + content-hash cache) and
    the **no-signal lane skip** — the two levers the evaluation flagged as waste —
    while recording the epoch plan + reprioritization the ``TaskScheduler`` engine
    produced. It never changes WHAT counts as a finding."""

    def __init__(self, config: SessionConfig | None = None) -> None:
        self.config = config or SessionConfig()
        self.ledger = BudgetLedger(global_ceiling=self.config.global_ceiling)
        for lane in LLM_LANES:
            self.ledger.set_budget(lane, self.config.lane_budget)
        self.cache = LLMCache()
        self.meter = LLMMeter()
        self.scheduler = TaskScheduler(SchedulerConfig(seed=self.config.seed))
        for lane, prio in _BASE_PRIORITY.items():
            self.scheduler.add(
                LaneTask(
                    name=lane.value,
                    lane=lane,
                    priority=prio,
                    repeatable=lane in (Lane.DIRECTED_FUZZ, Lane.DRILLER),
                )
            )
        self.signal: float = 0.0
        self.fuzz_skipped = False

    # -- LLM wrapping --------------------------------------------------------

    def wrap_llm(self, inner: Any, lane: Lane = Lane.TRIAGE) -> BudgetedCachingLLM:
        """Wrap a backend in the per-lane budget + shared content-hash cache."""
        return BudgetedCachingLLM(
            inner, self.ledger, self.cache, lane=lane, meter=self.meter
        )

    # -- signal + skip decisions --------------------------------------------

    def note_signal(self, score: float) -> None:
        """Record the static-lane signal (max cheap-rank / confirmable origin) and
        feed it to the scheduler as a reprioritization event."""
        self.signal = score
        if score > 0:
            self.scheduler.apply_event(
                Event(EventKind.SIGNAL, lane=Lane.DIRECTED_FUZZ, weight=int(score * 4))
            )
        else:
            # No slice signal: deprioritize the fuzz + LLM lanes (don't pay to fuzz
            # / escalate a target the static layer never flagged).
            for lane in (Lane.DIRECTED_FUZZ, Lane.DRILLER, Lane.PAYLOAD, Lane.LAST_MILE):
                self.scheduler.apply_event(Event(EventKind.EXHAUSTED, lane=lane))

    def should_run_fuzz(self) -> bool:
        """The no-signal fuzz skip: under a TIGHT time budget, skip the fuzz lane on
        a target with no slice signal (the eval's measured-waste fix). With no tight
        budget the lane runs exactly as the sequential pipeline (no regression)."""
        if self.config.time_budget_s is None:
            return True
        run_it = self.signal > 0.0
        self.fuzz_skipped = not run_it
        return run_it

    def note_confirmed(self, lane: Lane, target: str | None = None) -> None:
        self.scheduler.apply_event(Event(EventKind.CONFIRMED, lane=lane, target=target))

    # -- reporting -----------------------------------------------------------

    def plan(self) -> ScheduleReport:
        """Produce the epoch plan from the (already-reprioritised) task queue."""
        return self.scheduler.run()

    def report(self) -> dict[str, Any]:
        return {
            "signal": round(self.signal, 3),
            "fuzz_skipped": self.fuzz_skipped,
            "llm": {
                "calls": self.meter.calls,
                "cached_calls": self.meter.cached_calls,
                "blocked_calls": self.meter.blocked_calls,
                "request_tokens": self.meter.request_tokens,
                "response_tokens": self.meter.response_tokens,
                "total_tokens": self.meter.total_tokens,
            },
            "cache": {
                "hits": self.cache.stats.hits,
                "misses": self.cache.stats.misses,
                "hit_rate": round(self.cache.stats.hit_rate, 3),
                "saved_tokens": self.cache.stats.saved_tokens,
            },
            "budget": self.ledger.summary(),
            "fallback_chain": list(self.scheduler.fallback.options),
        }

    def summary_note(self) -> str:
        r = self.report()
        return (
            f"scheduler: signal={r['signal']} fuzz_skipped={r['fuzz_skipped']} "
            f"llm_calls={r['llm']['calls']} cache_hits={r['cache']['hits']} "
            f"est_tokens={r['llm']['total_tokens']} "
            f"blocked={r['llm']['blocked_calls']}"
        )


def signal_from_scores(scores: Iterable[float], confirmable: bool) -> float:
    """Static-lane signal: the max cheap-rank score, lifted to 1.0 when any
    oracle-confirmable bug-class hypothesis is present (those always deserve their
    confirming oracle). 0.0 ⇒ no signal ⇒ the no-signal lanes are skippable."""
    top = max(list(scores), default=0.0)
    return 1.0 if confirmable else top


def build_session() -> SchedulerSession:
    return SchedulerSession(SessionConfig.from_env())

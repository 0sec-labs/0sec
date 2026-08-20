"""M7 #44 — strategy scheduler + per-lane LLM budget (deterministic).

Covers: the weighted-random epoch sampler (seeded → reproducible + anti-starvation),
event-driven reprioritization, the budget ledger + content-hash LLM cache hit/miss,
the fuzzer fallback-chain selection, and the scheduler-vs-sequential same-findings
invariant (the scheduler never changes WHAT counts as a finding)."""

from __future__ import annotations

import sys
from typing import Any

import pytest

from zeroverse.agent import MockLLM
from zeroverse.backends.rizin import r2_available
from zeroverse.schedule import (
    BudgetedCachingLLM,
    BudgetExceeded,
    BudgetLedger,
    Event,
    EventKind,
    FallbackChain,
    Lane,
    LaneTask,
    LLMCache,
    SchedulerConfig,
    SchedulerSession,
    SessionConfig,
    TaskResult,
    TaskScheduler,
    TaskState,
    estimate_tokens,
    signal_from_scores,
)

# --- weighted-random epoch sampler -----------------------------------------


def _mk_scheduler(priorities: dict[str, int], seed: int = 0) -> TaskScheduler:
    sch = TaskScheduler(SchedulerConfig(epoch_pop=2, seed=seed))
    for name, prio in priorities.items():
        sch.add(LaneTask(name=name, lane=Lane.SLICE, priority=prio))
    return sch


def test_epoch_sampler_is_deterministic_with_seed() -> None:
    a = _mk_scheduler({"a": 30, "b": 5, "c": 1}, seed=7).sample_epoch(3)
    b = _mk_scheduler({"a": 30, "b": 5, "c": 1}, seed=7).sample_epoch(3)
    assert [t.name for t in a] == [t.name for t in b]


def test_epoch_sampler_without_replacement() -> None:
    chosen = _mk_scheduler({"a": 10, "b": 10, "c": 10}, seed=1).sample_epoch(3)
    assert sorted(t.name for t in chosen) == ["a", "b", "c"]  # each at most once


def test_epoch_sampler_favours_high_priority() -> None:
    # Over many independent draws the hot lane is picked first far more often,
    # but the low lane is NEVER starved (priority floor guarantees a chance).
    first_counts: dict[str, int] = {"hot": 0, "cold": 0}
    cold_ever = False
    for seed in range(200):
        sch = _mk_scheduler({"hot": 50, "cold": 1}, seed=seed)
        order = sch.sample_epoch(2)
        first_counts[order[0].name] += 1
        if order[0].name == "cold":
            cold_ever = True
    assert first_counts["hot"] > first_counts["cold"] * 3  # hot dominates
    assert cold_ever  # anti-starvation: cold still wins sometimes


def test_priority_floor_lets_zero_priority_run() -> None:
    sch = TaskScheduler(SchedulerConfig(epoch_pop=1, seed=3))
    sch.add(LaneTask("z", Lane.SLICE, priority=0))
    assert [t.name for t in sch.sample_epoch(1)] == ["z"]


# --- event-driven reprioritization -----------------------------------------


def test_signal_event_bumps_lane_priority() -> None:
    sch = TaskScheduler()
    t = sch.add(LaneTask("fuzz", Lane.DIRECTED_FUZZ, priority=5))
    sch.apply_event(Event(EventKind.SIGNAL, lane=Lane.DIRECTED_FUZZ, weight=2))
    assert t.priority == 5 + sch.config.bump * 2


def test_confirmed_event_drops_target_task() -> None:
    sch = TaskScheduler()
    t = sch.add(LaneTask("sink@0x401", Lane.DIRECTED_FUZZ, priority=5))
    sch.apply_event(Event(EventKind.CONFIRMED, target="sink@0x401"))
    assert t.state is TaskState.DONE
    assert not t.active


def test_exhausted_event_retires_oneshot_deprioritizes_repeatable() -> None:
    sch = TaskScheduler()
    oneshot = sch.add(LaneTask("triage", Lane.TRIAGE, priority=12))
    repeat = sch.add(LaneTask("fuzz", Lane.DIRECTED_FUZZ, priority=9, repeatable=True))
    sch.apply_event(Event(EventKind.EXHAUSTED, lane=Lane.TRIAGE))
    sch.apply_event(Event(EventKind.EXHAUSTED, lane=Lane.DIRECTED_FUZZ))
    assert oneshot.state is TaskState.EXHAUSTED
    assert repeat.active and repeat.priority == sch.config.deprioritize_to


def test_epoch_loop_reacts_to_emitted_events() -> None:
    sch = TaskScheduler(SchedulerConfig(epoch_pop=2, seed=0))
    fuzz = sch.add(LaneTask("fuzz", Lane.DIRECTED_FUZZ, priority=4, repeatable=True))

    def _slice_run() -> TaskResult:
        # the slice finds a hot sink → bump the fuzz lane, then confirm it → drop.
        return TaskResult(events=[Event(EventKind.SIGNAL, lane=Lane.DIRECTED_FUZZ)])

    sch.add(LaneTask("slice", Lane.SLICE, priority=30, run=_slice_run))
    report = sch.run()
    assert report.events_applied >= 1
    assert fuzz.priority > 4  # the slice's signal bumped it


# --- budget ledger ----------------------------------------------------------


def test_lane_budget_blocks_over_ceiling() -> None:
    led = BudgetLedger(global_ceiling=1000)
    led.set_budget(Lane.TRIAGE, 100)
    assert led.can_spend(Lane.TRIAGE, 80)
    led.charge(Lane.TRIAGE, 80)
    assert not led.can_spend(Lane.TRIAGE, 40)  # lane key exhausted
    assert led.budget(Lane.TRIAGE).remaining == 20


def test_global_ceiling_caps_across_lanes() -> None:
    led = BudgetLedger(global_ceiling=100)
    led.set_budget(Lane.TRIAGE, 1000)
    led.set_budget(Lane.HARNESS, 1000)
    led.charge(Lane.TRIAGE, 70)
    assert not led.can_spend(Lane.HARNESS, 40)  # global ceiling, not the lane key
    assert led.global_remaining == 30


# --- content-hash LLM cache + budgeted wrapper -----------------------------


class _CountingLLM:
    """Records every backend call so we can prove the cache deduped identical
    prompts (the call count must not rise on a cache hit)."""

    def __init__(self) -> None:
        self.calls = 0

    def complete_json(
        self, system: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any]:
        self.calls += 1
        return {"is_real": True, "bug_class": "x", "severity": "high",
                "explanation": "e", "input_example": ""}


def test_cache_key_is_content_addressed() -> None:
    c = LLMCache()
    k1 = c.key("sys", "prompt", {"a": 1})
    k2 = c.key("sys", "prompt", {"a": 1})
    k3 = c.key("sys", "other", {"a": 1})
    assert k1 == k2 and k1 != k3


def test_cache_dedups_identical_prompt() -> None:
    inner = _CountingLLM()
    led = BudgetLedger(global_ceiling=10_000)
    led.set_budget(Lane.TRIAGE, 10_000)
    cache = LLMCache()
    llm = BudgetedCachingLLM(inner, led, cache, lane=Lane.TRIAGE)
    schema = {"type": "object", "properties": {}}
    llm.complete_json("sys", "P", schema)
    llm.complete_json("sys", "P", schema)   # identical → served from cache
    llm.complete_json("sys", "Q", schema)   # different → backend
    assert inner.calls == 2                  # not 3 — the duplicate was deduped
    assert cache.stats.hits == 1 and cache.stats.misses == 2
    assert cache.stats.saved_tokens > 0
    assert llm.meter.cached_calls == 1


def test_budget_wrapper_raises_when_lane_exhausted() -> None:
    inner = _CountingLLM()
    led = BudgetLedger(global_ceiling=10_000)
    led.set_budget(Lane.TRIAGE, 1)  # one token — nothing real fits
    llm = BudgetedCachingLLM(inner, led, LLMCache(), lane=Lane.TRIAGE)
    with pytest.raises(BudgetExceeded):
        llm.complete_json("a long system prompt", "a long user prompt", {})
    assert inner.calls == 0                  # never reached the backend
    assert led.budget(Lane.TRIAGE).blocked == 1


def test_budget_wrapper_forwards_stateful_conversation_without_cache() -> None:
    class Conversation:
        def __init__(self) -> None:
            self.appended: list[str] = []
            self.calls = 0

        def append_user(self, text: str) -> None:
            self.appended.append(text)

        def budget_prompt(self) -> str:
            return "system and retained provider-native assistant blocks"

        def complete_json(self) -> dict[str, Any]:
            self.calls += 1
            return {"action": "call", "n": self.calls}

    class Inner:
        def __init__(self) -> None:
            self.conversation = Conversation()

        def begin_conversation(
            self, _system: str, _prompt: str, _schema: dict[str, Any]
        ) -> Conversation:
            return self.conversation

    inner = Inner()
    ledger = BudgetLedger(global_ceiling=10_000)
    ledger.set_budget(Lane.TRIAGE, 10_000)
    cache = LLMCache()
    llm = BudgetedCachingLLM(inner, ledger, cache, lane=Lane.TRIAGE)
    conversation = llm.begin_conversation("system", "opening prompt", {})
    assert conversation is not None

    conversation.append_user("tool result")
    assert conversation.complete_json()["n"] == 1
    assert conversation.complete_json()["n"] == 2
    assert inner.conversation.appended == ["tool result"]
    assert inner.conversation.calls == 2
    assert llm.meter.calls == 2
    assert cache.stats.hits == 0


def test_estimate_tokens_monotonic() -> None:
    assert estimate_tokens("") >= 1
    assert estimate_tokens("a" * 400) > estimate_tokens("a" * 40)


# --- fuzzer fallback chain --------------------------------------------------


def test_fallback_demotes_after_threshold() -> None:
    chain = FallbackChain(demote_after=2)
    assert chain.current == "afl-qemu"
    assert chain.note_abort() is False      # 1 abort
    assert chain.note_abort() is False      # 2 aborts (== threshold)
    assert chain.note_abort() is True       # 3rd → demote
    assert chain.current == "afl-native"


def test_fallback_success_resets_aborts() -> None:
    chain = FallbackChain(demote_after=2)
    chain.note_abort()
    chain.note_success()
    assert chain.note_abort() is False and chain.current == "afl-qemu"


def test_fallback_walks_full_chain_to_qiling() -> None:
    chain = FallbackChain(demote_after=0)
    chain.note_abort()                      # qemu → native
    chain.note_abort()                      # native → qiling
    assert chain.current == "qiling"
    assert chain.demotions == 2


# --- signal helper ----------------------------------------------------------


def test_signal_zero_for_no_findings() -> None:
    assert signal_from_scores([], confirmable=False) == 0.0


def test_signal_lifted_by_confirmable_origin() -> None:
    assert signal_from_scores([0.1, 0.2], confirmable=True) == 1.0


def test_signal_is_max_score() -> None:
    assert signal_from_scores([0.3, 0.9, 0.4], confirmable=False) == 0.9


# --- session: no-signal skip + same-findings invariant ----------------------


def test_session_skips_fuzz_only_on_no_signal_under_tight_budget() -> None:
    s = SchedulerSession(SessionConfig(time_budget_s=5.0))
    s.note_signal(0.0)
    assert s.should_run_fuzz() is False      # no signal + tight budget → skip
    assert s.fuzz_skipped is True

    s2 = SchedulerSession(SessionConfig(time_budget_s=5.0))
    s2.note_signal(0.9)
    assert s2.should_run_fuzz() is True       # signal present → run (never drop a bug)


def test_session_generous_budget_never_skips() -> None:
    s = SchedulerSession(SessionConfig(time_budget_s=None))
    s.note_signal(0.0)
    assert s.should_run_fuzz() is True        # no tight budget ⇒ behaves like sequential


def test_session_wrap_llm_meters_and_caches() -> None:
    s = SchedulerSession(SessionConfig())
    llm = s.wrap_llm(MockLLM())
    schema = {"type": "object", "properties": {"is_real": {"type": "boolean"}}}
    llm.complete_json("sys", "Sink: system\ngetenv", schema)
    llm.complete_json("sys", "Sink: system\ngetenv", schema)  # dup → cache hit
    rep = s.report()
    assert rep["llm"]["calls"] == 1
    assert rep["cache"]["hits"] == 1
    assert rep["llm"]["total_tokens"] > 0


def test_session_report_shape() -> None:
    rep = SchedulerSession(SessionConfig()).report()
    assert {"signal", "fuzz_skipped", "llm", "cache", "budget", "fallback_chain"} <= set(rep)
    assert rep["fallback_chain"][0] == "afl-qemu"


# --- scheduler-vs-sequential same-findings (PoV-is-truth unchanged) ---------


def _run(env: dict[str, str], tmp: Any, src: str, monkeypatch: Any) -> Any:
    import subprocess

    from zeroverse import api
    from zeroverse.api import ScanOptions

    tmp.mkdir(parents=True, exist_ok=True)
    cfile = tmp / "t.c"
    cfile.write_text(src)
    binp = tmp / "t"
    subprocess.run(["gcc", "-O0", "-fno-stack-protector", "-no-pie",
                    "-o", str(binp), str(cfile)], check=True)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return api.scan(binp, ScanOptions(backend="rizin"))


_VULN = (
    "#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>\n"
    "void process(char *in){ char buf[16]; strcpy(buf, in); printf(\"%s\", buf); }\n"
    "int main(){ char line[256]; if(fgets(line,sizeof line,stdin)){ "
    "process(line);} return 0; }\n"
)


@pytest.mark.skipif(sys.platform != "linux", reason="native dynamic confirmation proof builds ELF")
@pytest.mark.skipif(not r2_available(), reason="needs r2 and r2pipe")
def test_scheduler_same_confirmed_findings_as_sequential(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Sequential (default path).
    seq = _run({}, tmp_path / "a", _VULN, monkeypatch)
    monkeypatch.undo()
    # Scheduler ON (generous budget) — must confirm the SAME bug, same capability.
    sch = _run({"ZEROVERSE_SCHEDULER": "1"}, tmp_path / "b", _VULN, monkeypatch)

    seq_conf = sorted((f.function, f.sink, f.capability)
                      for f in seq.findings if f.confirmed)
    sch_conf = sorted((f.function, f.sink, f.capability)
                      for f in sch.findings if f.confirmed)
    assert seq_conf == sch_conf            # PoV-is-truth: identical confirmed set
    assert seq.confirmed_count >= 1        # the strcpy oob-write is really confirmed
    assert sch.scheduler is not None       # stats attached only in scheduler mode
    assert seq.scheduler is None

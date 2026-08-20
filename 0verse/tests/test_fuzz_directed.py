"""#39 — directed targets + UniAFL sink-scored corpus scheduling."""

from __future__ import annotations

from zeroverse.analyze import Finding
from zeroverse.fuzz.coverage import AddressIndex, BlockTrace, CoverageProbe
from zeroverse.fuzz.directed import (
    DirectedScheduler,
    DirectedTargets,
    SchedulerConfig,
    SinkTarget,
    collect_targets,
    func_ranges_from_disasm,
    inst_ranges_for_slice,
)
from zeroverse.il import Inst, Kind

_DISASM = """\
0000000000401206 <parse>:
  401206:\t55                   \tpush   %rbp
  4012e9:\te8 d2 fd ff ff       \tcall   4010c0 <memcpy@plt>
  4012f0:\tc3                   \tret
0000000000401300 <other>:
  401300:\t55                   \tpush   %rbp
  401310:\tc3                   \tret
"""


def test_collect_targets_from_slice_findings_weighted() -> None:
    findings = [
        Finding("read", "memcpy", "parse", 0x401206, 0x4012E9, 3, origin="slice"),
        Finding("foxguard", "rule", "other", 0, 0x401310, 0, origin="foxguard"),
    ]
    dt = collect_targets(findings, func_entries={"parse": 0x401206, "other": 0x401300})
    by_sink = {t.sink_addr: t for t in dt.active}
    assert by_sink[0x4012E9].weight == 1.0       # slice outranks
    assert by_sink[0x401310].weight == 0.7       # foxguard hypothesis
    assert by_sink[0x4012E9].func_entry == 0x401206


def test_collect_targets_resolves_seed_token_to_call_site() -> None:
    # an archetype located function `parse` and the `memcpy` sink token; we pin it
    # to the CALL site VA via the disassembly.
    dt = collect_targets(
        [], seed_matches=[("parse", "memcpy", 80)], disasm=_DISASM,
        func_entries={"parse": 0x401206},
    )
    assert len(dt) == 1
    t = dt.active[0]
    assert t.sink_addr == 0x4012E9 and t.origin == "seed:memcpy"
    assert abs(t.weight - 0.8) < 1e-9


def test_directed_targets_dedup_and_confirm() -> None:
    dt = DirectedTargets()
    a = SinkTarget("parse", 0x401206, 0x4012E9, "slice", weight=1.0)
    assert dt.add(a) is True
    # same key, lower weight → ignored
    assert dt.add(SinkTarget("parse", 0x401206, 0x4012E9, "seed:x", weight=0.5)) is False
    assert len(dt) == 1
    dt.confirm(0x4012E9)
    assert len(dt) == 0
    # a confirmed sink can't be re-added
    assert dt.add(a) is False
    assert 0x4012E9 in dt.confirmed_sinks


def test_func_ranges_and_inst_ranges_for_slice() -> None:
    ranges = func_ranges_from_disasm(_DISASM)
    assert ranges["parse"][0] == 0x401206
    assert ranges["other"][0] == 0x401300
    idx = AddressIndex.from_ranges(ranges)
    targets = [SinkTarget("parse", 0x401206, 0x4012E9, "slice")]
    spec = inst_ranges_for_slice(targets, idx, func_ranges=ranges)
    assert spec == "0x401206-0x401300"   # only the function carrying a target


def _probe(traces: dict[bytes, frozenset[int]]) -> CoverageProbe:
    idx = AddressIndex.from_insts([
        Inst(id=0, func="parse", addr=0x401206, kind=Kind.OTHER),
        Inst(id=1, func="parse", addr=0x401240, kind=Kind.OTHER),
        Inst(id=2, func="parse", addr=0x4012C0, kind=Kind.OTHER),
    ])
    p = CoverageProbe("/bin/true", idx)
    for s, a in traces.items():
        p._cache[s] = BlockTrace(addrs=a, note="fixture")
    return p


def test_scheduler_reprioritizes_toward_key_hitting_seeds() -> None:
    t = SinkTarget("parse", 0x401206, 0x4012C0, "slice")
    targets = DirectedTargets([t])
    near = frozenset({0x401206, 0x401240, 0x4012C0})
    far = frozenset({0x401206})
    seeds = [b"near", b"far1", b"far2", b"far3", b"far4", b"far5"]
    traces = {b"near": near}
    for s in seeds[1:]:
        traces[s] = far
    sched = DirectedScheduler(
        _probe(traces), targets, SchedulerConfig(keep_k=3, anneal=False, seed=0)
    )
    chosen = sched.reprioritize(seeds)
    assert len(chosen) == 3
    # the near (sink-reaching) seed must survive the 25/25/50 selection
    assert b"near" in chosen
    # scores were computed for every corpus seed
    assert len(sched.last_scores) == len(seeds)


def test_scheduler_no_targets_is_passthrough() -> None:
    dt = DirectedTargets()
    sched = DirectedScheduler(_probe({}), dt, SchedulerConfig(seed=0))
    seeds = [b"a", b"b"]
    assert sched.reprioritize(seeds) == seeds


def test_scheduler_last_mile_candidates() -> None:
    t = SinkTarget("parse", 0x401206, 0x4012C0, "slice")
    targets = DirectedTargets([t])
    sched = DirectedScheduler(
        _probe({b"hit": frozenset({0x4012C0}), b"no": frozenset({0x401206})}),
        targets, SchedulerConfig(seed=0),
    )
    assert sched.last_mile_candidates([b"hit", b"no"]) == [t]

"""#40 — coverage→address map: qemu-exec parsing, the Ghidra join, last-mile."""

from __future__ import annotations

from pathlib import Path

from zeroverse.fuzz import coverage
from zeroverse.fuzz.coverage import (
    AddressIndex,
    BlockTrace,
    CoverageProbe,
    parse_qemu_exec_log,
)
from zeroverse.fuzz.directed import SinkTarget
from zeroverse.il import Inst, Kind
from zeroverse.preflight import BudgetTracker, RunBudget

# A fixture qemu `-d exec` log: the bracket's 2nd field is the guest PC. The first
# two lines are high loader/libc blocks; the rest are the program's static VAs.
_QLOG = """\
Trace 0: 0x7f0000000100 [00000000/00002aaaab2cb540/1040c0b3/00000000]
Trace 0: 0x7f0000000240 [00000000/00002aaaab2cc1d0/1040c0b3/00000000]
Trace 0: 0x55000000 [00000000/0000000000401206/1040c0b3/00000000]
Trace 0: 0x55000040 [00000000/0000000000401240/1040c0b3/00000000]
Trace 0: 0x55000080 [00000000/00000000004012e9/1040c0b3/00000000]
"""


def test_parse_qemu_exec_log_extracts_guest_pcs() -> None:
    addrs = parse_qemu_exec_log(_QLOG)
    assert 0x401206 in addrs
    assert 0x401240 in addrs
    assert 0x4012E9 in addrs
    # loader/libc blocks are parsed too (we don't filter by range here)
    assert 0x2AAAAB2CB540 in addrs


def test_parse_qemu_exec_log_subtracts_load_base() -> None:
    addrs = parse_qemu_exec_log(_QLOG, load_base=0x400000)
    assert 0x1206 in addrs
    assert 0x12E9 in addrs
    # below-base addresses are dropped, not made negative
    assert all(a >= 0 for a in addrs)


def _insts() -> list[Inst]:
    # function `parse` spans 0x401206..0x401300 with block leaders every 0x40;
    # the sink (a CALL) sits at 0x4012e9, inside the last block leader 0x4012c0.
    addrs = [0x401206, 0x401240, 0x401280, 0x4012C0]
    out = [Inst(id=i, func="parse", addr=a, kind=Kind.OTHER) for i, a in enumerate(addrs)]
    out.append(Inst(id=99, func="other", addr=0x402000, kind=Kind.OTHER))
    return out


def test_address_index_func_of_and_covering_block() -> None:
    idx = AddressIndex.from_insts(_insts())
    assert idx.func_of(0x401240) == "parse"
    assert idx.func_of(0x402000) == "other"
    # the block CONTAINING the sink 0x4012e9 is the leader 0x4012c0
    assert idx.covering_block("parse", 0x4012E9) == 0x4012C0
    assert idx.covering_block("parse", 0x401206) == 0x401206


def test_address_index_key_addresses_are_approach_plus_sink() -> None:
    idx = AddressIndex.from_insts(_insts())
    keys = idx.key_addresses("parse", 0x4012E9)
    assert keys == frozenset({0x401206, 0x401240, 0x401280, 0x4012C0})
    # a sink earlier in the function yields fewer key (approach) addresses
    assert idx.key_addresses("parse", 0x401240) == frozenset({0x401206, 0x401240})


def test_address_index_from_ranges_membership() -> None:
    idx = AddressIndex.from_ranges({"parse": (0x401206, 0x401300)})
    assert idx.func_of(0x4012E9) == "parse"
    assert idx.func_of(0x500000) is None
    assert idx.covering_block("parse", 0x4012E9) == 0x401206


def _probe_with_traces(traces: dict[bytes, frozenset[int]]) -> CoverageProbe:
    idx = AddressIndex.from_insts(_insts())
    probe = CoverageProbe("/bin/true", idx)
    for seed, addrs in traces.items():
        probe._cache[seed] = BlockTrace(addrs=addrs, note="fixture")
    return probe


def test_coverage_probe_reserves_and_clips_every_uncached_trace(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    tracker = BudgetTracker.start(
        RunBudget(attempt_limit=2, unknown_sink_oracle_attempts=0)
    )
    timeouts: list[float] = []

    def traced(*args, timeout_s: float, **kwargs) -> BlockTrace:  # type: ignore[no-untyped-def]
        timeouts.append(timeout_s)
        return BlockTrace(addrs=frozenset({0x401206}))

    monkeypatch.setattr(coverage, "trace_blocks", traced)
    probe = CoverageProbe(
        "/bin/true",
        AddressIndex.from_insts(_insts()),
        budget=tracker,
        timeout_s=20.0,
    )

    assert probe.trace(b"one").available
    assert probe.trace(b"one").available  # cached: no second reservation
    assert probe.trace(b"two").available
    skipped = probe.trace(b"three")

    assert len(timeouts) == 2
    assert all(0 < timeout <= tracker.budget.wall_clock_seconds for timeout in timeouts)
    assert "budget skipped" in skipped.note
    assert tracker.attempts_used == 2


def test_trace_blocks_consumes_exact_planned_qemu_path(
    tmp_path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    commands: list[list[str]] = []
    monkeypatch.setattr(
        coverage,
        "qemu_user_bin",
        lambda arch="": (_ for _ in ()).throw(
            AssertionError("qemu-user path was re-probed")
        ),
    )

    def run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        commands.append(cmd)
        log_path = Path(cmd[cmd.index("-D") + 1])
        log_path.write_text(_QLOG)

    monkeypatch.setattr(coverage.subprocess, "run", run)
    target = tmp_path / "target"
    target.write_bytes(b"ELF")

    trace = coverage.trace_blocks(
        target,
        b"seed",
        qemu_path="/planned/qemu-x86_64",
        qemu_resolved=True,
    )

    assert trace.available
    assert commands[0][0] == "/planned/qemu-x86_64"


def _target() -> SinkTarget:
    return SinkTarget(function="parse", func_entry=0x401206, sink_addr=0x4012E9, origin="slice")


def test_probe_score_seed_counts_key_hits_and_reached() -> None:
    t = _target()
    # `deep` reaches the sink block; `shallow` only the first two approach blocks.
    probe = _probe_with_traces({
        b"deep": frozenset({0x401206, 0x401240, 0x401280, 0x4012C0}),
        b"shallow": frozenset({0x401206, 0x401240}),
        b"miss": frozenset({0x402000}),
    })
    deep = probe.score_seed(b"deep", [t])
    shallow = probe.score_seed(b"shallow", [t])
    miss = probe.score_seed(b"miss", [t])
    assert deep.key_hits == 4 and deep.sinks_reached == (0x4012E9,)
    assert shallow.key_hits == 2 and shallow.sinks_reached == ()
    assert miss.key_hits == 0 and not miss.reached_any
    # the seed nearer the sink scores strictly higher
    assert deep.key_hits > shallow.key_hits > miss.key_hits


def test_probe_reached_and_uncrashed_but_reached() -> None:
    t = _target()
    probe = _probe_with_traces({
        b"deep": frozenset({0x401206, 0x401240, 0x401280, 0x4012C0}),
        b"shallow": frozenset({0x401206}),
    })
    assert probe.reached_sinks(b"deep", [t]) == [t]
    assert probe.reached_sinks(b"shallow", [t]) == []
    # `deep` reached the sink but the oracle confirmed nothing → last-mile signal
    cand = probe.uncrashed_but_reached([b"deep", b"shallow"], [t])
    assert cand == [t]
    # once the oracle confirms that sink, it drops out of the last-mile set
    assert probe.uncrashed_but_reached(
        [b"deep"], [t], confirmed_sinks=frozenset({0x4012E9})
    ) == []

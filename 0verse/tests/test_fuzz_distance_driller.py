"""#41 — DistanceDriller: distance-plateau trigger + sink-directed re-seed."""

from __future__ import annotations

from pathlib import Path

from zeroverse.fuzz.driller import (
    AngrCfgDistance,
    DistanceDriller,
    DrillerConfig,
    NullDistance,
)


class _FakeSolver:
    """Returns a canned solved input for the first ``n`` calls, else None."""

    def __init__(self, solved: bytes | None, n: int = 99) -> None:
        self.solved = solved
        self.n = n
        self.calls = 0
        self.last_target: tuple[int, int] | None = None

    def solve(
        self, binary: Path, stuck_input: bytes, *, func_addr: int, target_addr: int
    ) -> bytes | None:
        self.calls += 1
        self.last_target = (func_addr, target_addr)
        return self.solved if self.calls <= self.n else None


class _FakeDistance:
    """Replays a scripted distance sequence and a fixed next-target."""

    def __init__(self, seq: list[float], nxt: tuple[int, int] | None) -> None:
        self.seq = seq
        self.i = 0
        self.nxt = nxt

    def reached_distance(self, executed: frozenset[int]) -> float:
        v = self.seq[min(self.i, len(self.seq) - 1)]
        self.i += 1
        return v

    def next_target(self, executed: frozenset[int]) -> tuple[int, int] | None:
        return self.nxt


def test_null_distance_reached_and_next() -> None:
    nd = NullDistance([(0x100, 0x200), (0x100, 0x300)])
    assert nd.reached_distance(frozenset({0x999})) == 1.0     # nothing reached
    assert nd.reached_distance(frozenset({0x200})) == 0.0     # a sink reached
    # next target is the nearest UNREACHED sink
    assert nd.next_target(frozenset({0x200})) == (0x100, 0x300)
    assert nd.next_target(frozenset({0x200, 0x300})) is None


def test_note_distance_detects_plateau() -> None:
    # distance never improves (stays at 1.0) → plateau after stall_rounds
    dist = _FakeDistance([1.0, 1.0, 1.0], (0x100, 0x200))
    d = DistanceDriller(_FakeSolver(b"x"), dist, DrillerConfig(stall_rounds=1))
    assert d.note_distance(frozenset()) is False   # first sample (inf→1.0 is progress)
    assert d.note_distance(frozenset()) is True    # no improvement → plateau, assist


def test_note_distance_resets_on_progress() -> None:
    dist = _FakeDistance([3.0, 2.0, 1.0], (0x100, 0x200))
    d = DistanceDriller(_FakeSolver(b"x"), dist, DrillerConfig(stall_rounds=1))
    assert d.note_distance(frozenset()) is False   # inf→3.0 progress
    assert d.note_distance(frozenset()) is False   # 3.0→2.0 progress, no plateau
    assert d.dstate.plateaus == 0


def test_assist_distance_solves_toward_next_target() -> None:
    solver = _FakeSolver(b"SOLVED")
    dist = _FakeDistance([1.0], (0x401000, 0x401100))
    d = DistanceDriller(solver, dist, DrillerConfig(max_assists=4))
    seeds = d.assist_distance(Path("/bin/true"), [b"stuck1", b"stuck2"], frozenset())
    assert seeds == [b"SOLVED"]                    # deduped across stuck inputs
    assert solver.last_target == (0x401000, 0x401100)
    assert d.dstate.plateaus == 0


def test_assist_distance_bounded_by_max_assists() -> None:
    solver = _FakeSolver(None)                     # never solves
    dist = _FakeDistance([1.0], (1, 2))
    d = DistanceDriller(solver, dist, DrillerConfig(max_assists=2))
    seeds = d.assist_distance(Path("/bin/true"), [b"a", b"b", b"c", b"d"], frozenset())
    assert seeds == []
    assert solver.calls == 2                       # stopped at the cap


def test_assist_distance_noop_when_all_reached() -> None:
    solver = _FakeSolver(b"x")
    dist = _FakeDistance([0.0], None)              # next_target None → all reached
    d = DistanceDriller(solver, dist, DrillerConfig())
    assert d.assist_distance(Path("/bin/true"), [b"a"], frozenset()) == []
    assert solver.calls == 0


def test_angr_cfg_distance_degrades_on_bad_binary() -> None:
    # a non-existent binary makes the CFG build fail → ok=False (caller falls back
    # to NullDistance), never raising.
    cfg = AngrCfgDistance(Path("/nonexistent/binary"), [(0x100, 0x200)])
    assert cfg.ok is False
    assert cfg.reached_distance(frozenset({0x200})) == float("inf")

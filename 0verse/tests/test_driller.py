"""#17 Driller-style hybrid — stall detection + concolic re-seed (fake solver)."""

from __future__ import annotations

from pathlib import Path

from zeroverse.fuzz.driller import DrillerConfig, DrillerHybrid


class _FakeSolver:
    """Returns a canned solved input for the first ``n_solves`` calls, else None."""

    def __init__(self, solved: bytes | None, n_solves: int = 99) -> None:
        self.solved = solved
        self.n_solves = n_solves
        self.calls = 0

    def solve(
        self, binary: Path, stuck_input: bytes, *, func_addr: int, target_addr: int
    ) -> bytes | None:
        self.calls += 1
        if self.calls <= self.n_solves:
            return self.solved
        return None


def test_note_progress_detects_stall() -> None:
    d = DrillerHybrid(_FakeSolver(b"x"), DrillerConfig(stall_rounds=2))
    assert d.note_progress(10) is False   # first sample, no baseline
    assert d.note_progress(10) is False   # stall 1
    assert d.note_progress(10) is True    # stall 2 -> assist
    # progress resets the stall counter
    assert d.note_progress(20) is False
    assert d.state.stalls == 0


def test_assist_returns_new_seeds_and_resets_stalls() -> None:
    d = DrillerHybrid(_FakeSolver(b"REC0solved"), DrillerConfig(max_assists=4))
    d.state.stalls = 5
    seeds = d.assist(
        Path("/bin/true"), [b"stuck1", b"stuck2"], func_addr=0x1000, target_addr=0x1100
    )
    assert seeds == [b"REC0solved"]       # deduped across stuck inputs
    assert d.state.stalls == 0


def test_assist_bounded_by_max_assists() -> None:
    solver = _FakeSolver(None)            # never solves
    d = DrillerHybrid(solver, DrillerConfig(max_assists=2))
    seeds = d.assist(Path("/bin/true"), [b"a", b"b", b"c", b"d"], func_addr=1, target_addr=2)
    assert seeds == []
    assert solver.calls == 2              # stopped at the cap
    assert d.state.assists == 2


def test_unsolvable_yields_no_seeds() -> None:
    d = DrillerHybrid(_FakeSolver(None))
    seeds = d.assist(Path("/bin/true"), [b"a"], func_addr=1, target_addr=2)
    assert seeds == []

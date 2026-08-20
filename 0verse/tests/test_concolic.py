"""angr concolic reachability (#5).

The reachability proof (witness + prune) needs the angr engine extra and a
compiler, so it's skipped on the lightweight lint CI and runs on the bench box
(where angr is installed). ``function_entry`` is pure and always tested.
"""

import subprocess
import sys
from pathlib import Path

import pytest

from zeroverse.concolic import AngrVerdict, function_entry
from zeroverse.il import Inst, Kind

BENCH = Path(__file__).resolve().parents[1] / "benchmarks" / "guarded.c"


def test_function_entry_is_lowest_addr() -> None:
    insts = [
        Inst(1, "main", 0x1010, Kind.CALL, dest="read"),
        Inst(2, "main", 0x1000, Kind.OTHER),
        Inst(3, "other", 0x2000, Kind.OTHER),
    ]
    assert function_entry(insts, "main") == 0x1000
    assert function_entry(insts, "missing") is None


def test_angr_verdict_predicates() -> None:
    assert AngrVerdict("unsat").pruned is True
    assert AngrVerdict("witness").reachable is True
    assert AngrVerdict("unknown").pruned is False
    assert AngrVerdict("unknown").reachable is False


@pytest.mark.skipif(sys.platform != "linux", reason="needs gcc + a linux ELF target")
def test_angr_witness_and_prune(tmp_path: Path) -> None:
    angr = pytest.importorskip("angr")
    from zeroverse.concolic import AngrConfig, check_reachability

    binary = tmp_path / "guarded"
    rc = subprocess.run(
        ["gcc", "-O0", "-no-pie", "-fno-stack-protector", "-o", str(binary), str(BENCH)],
        capture_output=True,
    )
    if rc.returncode != 0:
        pytest.skip("gcc unavailable")
    proj = angr.Project(str(binary), auto_load_libs=False)

    def sym(name: str) -> int:
        s = proj.loader.find_symbol(name)
        assert s is not None, name
        return int(s.rebased_addr)

    vuln = sym("vuln")
    cfg = AngrConfig(timeout_s=90.0, sym_arg_count=2)

    good = check_reachability(binary, sym("reachable_path"), vuln, config=cfg)
    assert good.outcome == "witness"
    assert 0xDEADBEEF in good.arg_values  # angr concretized the magic gate

    dead = check_reachability(binary, sym("dead_path"), vuln, config=cfg)
    assert dead.outcome == "unsat"        # contradiction proven -> hypothesis pruned
    assert dead.pruned is True

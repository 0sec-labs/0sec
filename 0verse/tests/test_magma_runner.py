"""Magma runner artifact behaviour (#298) — incremental result writing and honest
cost reporting.

The runner used to build the whole results JSON in memory and write it once, after
the last target. A run killed by ``timeout``/OOM produced nothing at all, so a
34-minute 4-target run was indistinguishable from a hang. It also printed a
confident ``estimated_cost_usd: 0.0`` whenever the LLM ledger was empty — which
included the case where the model was never reached.

Fully hermetic: docker extraction and the per-binary scan are monkeypatched, so no
Docker, Ghidra, network, or LLM is involved.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

# The magma runner lives under benchmarks/, not on the src path. Load it under a
# unique module name so it cannot collide with benchmarks/binarygym/run.py, which
# tests/test_binarygym.py imports as plain ``run``.
_RUN_PY = Path(__file__).resolve().parent.parent / "benchmarks" / "magma" / "run.py"
_spec = importlib.util.spec_from_file_location("magma_run", _RUN_PY)
assert _spec is not None and _spec.loader is not None
magma_run = importlib.util.module_from_spec(_spec)
sys.modules["magma_run"] = magma_run
_spec.loader.exec_module(magma_run)


CATALOGUE = {
    "bugs": [
        {"target": "libpng", "bug": "PNG001", "file": "png.c",
         "function": "png_handle_tRNS", "in_seed_set": False},
        {"target": "lua", "bug": "LUA001", "file": "lvm.c",
         "function": "luaV_execute", "in_seed_set": False},
    ]
}


@pytest.fixture()
def catalogue_path(tmp_path: Path) -> Path:
    p = tmp_path / "cat.json"
    p.write_text(json.dumps(CATALOGUE), encoding="utf-8")
    return p


def _scan_result(function: str, *, acct: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "findings": [{"function": function, "confirmed": False, "hypothesis": True}],
        "stages": ["decompile", "reason"],
        "ghidra_ok": True,
        "wall_s": 1.0,
        "input_tokens": int((acct or {}).get("input_tokens", 0)),
        "output_tokens": int((acct or {}).get("output_tokens", 0)),
        "llm_accounting": acct or {
            "status": "measured", "calls_ok": 3, "calls_failed": 0,
            "usage_reported": True, "input_tokens": 500, "output_tokens": 50,
        },
        "note": "",
    }


def _stub_docker(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_extract(target: str, tag: str, dest: Path) -> list[Path]:
        dest.mkdir(parents=True, exist_ok=True)
        b = dest / f"{target}_driver"
        b.write_bytes(b"\x7fELF")
        return [b]

    monkeypatch.setattr(magma_run, "extract_binaries", fake_extract)
    monkeypatch.setattr(magma_run, "provide_runtime_libs",
                        lambda *a, **k: None)


def _argv(catalogue: Path, out: Path, *targets: str) -> list[str]:
    return ["--targets", *targets, "--llm", "codex", "--catalogue", str(catalogue),
            "--out", str(out)]


# --- defect 1: results land as each target completes ------------------------

def test_envelope_exists_before_the_first_target_finishes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, catalogue_path: Path
) -> None:
    out = tmp_path / "results.json"
    _stub_docker(monkeypatch, tmp_path)
    seen: list[dict[str, Any]] = []

    def fake_scan(binary: Path, *a: Any, **k: Any) -> dict[str, Any]:
        # By the time the very first scan runs, the results path must already
        # exist — a kill here still leaves an artifact naming the planned run.
        seen.append(json.loads(out.read_text()))
        return _scan_result("png_handle_tRNS")

    monkeypatch.setattr(magma_run, "scan_binary", fake_scan)
    magma_run.main(_argv(catalogue_path, out, "libpng"))

    assert seen, "scan_binary was never called"
    early = seen[0]
    assert early["complete"] is False
    assert early["targets_planned"] == ["libpng"]
    assert early["targets_scored"] == []


def test_a_run_killed_midway_leaves_a_scoreable_partial(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, catalogue_path: Path
) -> None:
    out = tmp_path / "results.json"
    _stub_docker(monkeypatch, tmp_path)
    calls = {"n": 0}

    def fake_scan(binary: Path, *a: Any, **k: Any) -> dict[str, Any]:
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyboardInterrupt  # stand-in for a timeout / OOM kill
        return _scan_result("png_handle_tRNS")

    monkeypatch.setattr(magma_run, "scan_binary", fake_scan)
    with pytest.raises(KeyboardInterrupt):
        magma_run.main(_argv(catalogue_path, out, "libpng", "lua"))

    # This is the whole point of the issue: the first target's 10-30 minutes of
    # compute survives the kill, and the file says it is not the full run.
    partial = json.loads(out.read_text())
    assert partial["complete"] is False
    assert partial["targets_planned"] == ["libpng", "lua"]
    assert partial["targets_scored"] == ["libpng"]
    assert partial["metrics"]["sites_reached"] == 1
    assert len(partial["scores"]) == 1

    # ...and the per-target NDJSON mirrors it, same model as the per-binary file.
    prog = out.with_suffix(".progress.ndjson")
    recs = [json.loads(line) for line in prog.read_text().splitlines()]
    assert [r["target"] for r in recs] == ["libpng"]


def test_completed_run_is_marked_complete_with_every_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, catalogue_path: Path
) -> None:
    out = tmp_path / "results.json"
    _stub_docker(monkeypatch, tmp_path)
    monkeypatch.setattr(magma_run, "scan_binary",
                        lambda b, *a, **k: _scan_result("png_handle_tRNS"))
    assert magma_run.main(_argv(catalogue_path, out, "libpng", "lua")) == 0

    final = json.loads(out.read_text())
    assert final["complete"] is True
    assert final["targets_scored"] == ["libpng", "lua"]
    prog = out.with_suffix(".progress.ndjson")
    assert len(prog.read_text().strip().splitlines()) == 2


def test_results_file_is_never_left_truncated(tmp_path: Path) -> None:
    out = tmp_path / "results.json"
    magma_run._write_results(out, {"a": 1})
    magma_run._write_results(out, {"a": 2})
    assert json.loads(out.read_text()) == {"a": 2}
    assert not out.with_name(out.name + ".tmp").exists()


# --- defect 2: the run says what its token numbers are worth -----------------

def test_measured_lane_prices_the_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, catalogue_path: Path
) -> None:
    out = tmp_path / "results.json"
    _stub_docker(monkeypatch, tmp_path)
    monkeypatch.setattr(magma_run, "scan_binary",
                        lambda b, *a, **k: _scan_result("png_handle_tRNS"))
    magma_run.main(_argv(catalogue_path, out, "libpng"))

    res = json.loads(out.read_text())
    assert res["llm_accounting"]["status"] == "measured"
    assert res["llm_accounting"]["calls_ok"] == 3
    assert res["estimated_cost_usd"] is not None
    assert res["cost_note"] == ""


def test_dead_llm_lane_refuses_to_print_a_confident_zero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, catalogue_path: Path
) -> None:
    # The exact 2026-07-28 artifact: findings present, `reason` stage recorded,
    # 0 tokens. Under the old runner that rendered as a $0.00 capability result.
    dead = {"status": "all-calls-failed", "calls_ok": 0, "calls_failed": 12,
            "usage_reported": False, "input_tokens": 0, "output_tokens": 0}
    out = tmp_path / "results.json"
    _stub_docker(monkeypatch, tmp_path)
    monkeypatch.setattr(magma_run, "scan_binary",
                        lambda b, *a, **k: _scan_result("png_handle_tRNS", acct=dead))
    magma_run.main(_argv(catalogue_path, out, "libpng"))

    res = json.loads(out.read_text())
    assert res["llm_accounting"]["status"] == "all-calls-failed"
    assert res["llm_accounting"]["calls_failed"] == 12
    assert res["estimated_cost_usd"] is None
    assert "NOT a real-LLM capability result" in res["cost_note"]


def test_unreported_usage_is_unknown_not_zero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, catalogue_path: Path
) -> None:
    unreported = {"status": "unreported", "calls_ok": 7, "calls_failed": 0,
                  "usage_reported": False, "input_tokens": 0, "output_tokens": 0}
    out = tmp_path / "results.json"
    _stub_docker(monkeypatch, tmp_path)
    monkeypatch.setattr(
        magma_run, "scan_binary",
        lambda b, *a, **k: _scan_result("png_handle_tRNS", acct=unreported))
    magma_run.main(_argv(catalogue_path, out, "libpng"))

    res = json.loads(out.read_text())
    assert res["llm_accounting"]["status"] == "unreported"
    assert res["estimated_cost_usd"] is None
    assert "UNKNOWN, not zero" in res["cost_note"]


def test_mock_lane_is_labelled_mock_not_dead(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, catalogue_path: Path
) -> None:
    mock_acct = {"status": "mock", "calls_ok": 0, "calls_failed": 0,
                 "usage_reported": False, "input_tokens": 0, "output_tokens": 0}
    out = tmp_path / "results.json"
    _stub_docker(monkeypatch, tmp_path)
    monkeypatch.setattr(
        magma_run, "scan_binary",
        lambda b, *a, **k: _scan_result("png_handle_tRNS", acct=mock_acct))
    magma_run.main(["--targets", "libpng", "--llm", "mock",
                    "--catalogue", str(catalogue_path), "--out", str(out)])

    res = json.loads(out.read_text())
    assert res["llm_accounting"]["status"] == "mock"
    assert res["capability_measure"] is False
    assert "not applicable" in res["cost_note"]


def test_scan_failure_marks_the_ledger_child_died() -> None:
    r = magma_run._scan_failure("scan timeout (>10s)", Path("/nonexistent"), 0.0)
    assert r["llm_accounting"]["status"] == "child-died"


# --- #315: runtime-lib staging must be transitively closed ------------------
#
# `ldd` only walks INTO a dependency it could resolve, so a single pass reports
# the binary's own unresolvable SONAMEs and stops. magma `lua` needs
# `libreadline.so.7`, which itself needs `libtinfo.so.5`; staging only the first
# leaves the binary unable to exec at all, which reaches AFL as
# `PROGRAM ABORT: Fork server handshake failed` in every lane.

def _fake_ldd_chain(
    monkeypatch: pytest.MonkeyPatch,
    chain: dict[str, list[str]],
    stageable: set[str] | None = None,
) -> list[str]:
    """Stub `ldd`+`docker` so a lib's dependency only becomes visible once the lib
    itself has been staged. ``chain`` maps a staged SONAME to what it then needs;
    key ``""`` is what the binary itself needs. ``stageable`` is what the image
    actually carries (default: everything in ``chain``). Returns the copied
    SONAMEs, in staging order."""
    copied: list[str] = []
    present = (
        {so for deps in chain.values() for so in deps}
        if stageable is None
        else stageable
    )

    class _P:
        def __init__(self, stdout: str = "", returncode: int = 0) -> None:
            self.stdout = stdout
            self.returncode = returncode
            self.stderr = ""

    def fake_run(cmd: list[str], **_kw: Any) -> _P:
        if cmd[0] == "ldd":
            visible = [*chain.get("", [])]
            for so in copied:
                visible += chain.get(so, [])
            unresolved = [so for so in visible if so not in copied]
            return _P("\n".join(f"\t{so} => not found" for so in unresolved))
        if cmd[:2] == ["docker", "create"]:
            return _P("cid123")
        if cmd[:2] == ["docker", "cp"]:
            so = cmd[3].rsplit("/", 1)[-1]
            if so not in present:
                return _P(returncode=1)
            copied.append(so)
            Path(cmd[4]).write_bytes(b"\x7fELF")
            return _P()
        return _P()

    monkeypatch.setattr(magma_run.subprocess, "run", fake_run)
    return copied


def test_runtime_lib_staging_follows_transitive_dependencies(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    copied = _fake_ldd_chain(monkeypatch, {
        "": ["libreadline.so.7"],
        "libreadline.so.7": ["libtinfo.so.5"],
    })
    binary = tmp_path / "lua"
    binary.write_bytes(b"\x7fELF")

    libdir = magma_run.provide_runtime_libs(
        "lua", "isan", [binary], tmp_path / ".runtime-libs")

    assert libdir is not None
    assert sorted(copied) == ["libreadline.so.7", "libtinfo.so.5"]
    assert magma_run.unrunnable_binaries([binary], libdir) == []


def test_runtime_lib_staging_terminates_on_an_unstageable_soname(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A SONAME absent from the image can never be staged; the loop must exit on
    "no NEW soname this pass" rather than spinning, and the binary must be
    reported as unrunnable rather than silently scored."""
    copied = _fake_ldd_chain(monkeypatch, {"": ["libghost.so.1"]}, stageable=set())
    binary = tmp_path / "lua"
    binary.write_bytes(b"\x7fELF")

    magma_run.provide_runtime_libs(
        "lua", "isan", [binary], tmp_path / ".runtime-libs")

    assert copied == []
    assert magma_run.unrunnable_binaries(
        [binary], tmp_path / ".runtime-libs") == ["lua"]


def test_a_target_that_cannot_link_is_refused_not_scored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, catalogue_path: Path
) -> None:
    """The recurring lesson (#262/#297/#304): a box that cannot execute the target
    must not emit a well-formed zero that reads as a capability number."""
    out = tmp_path / "results.json"
    _stub_docker(monkeypatch, tmp_path)
    monkeypatch.setattr(magma_run, "unrunnable_binaries",
                        lambda bins, _libdir: [b.name for b in bins])
    monkeypatch.setattr(
        magma_run, "scan_binary",
        lambda *a, **k: pytest.fail("scanned a target that cannot link"),
    )

    rc = magma_run.main(_argv(catalogue_path, out, "lua"))

    assert rc == 2
    written = json.loads(out.read_text())
    assert written["complete"] is False
    assert written["targets_scored"] == []
    assert written["details"][0]["error"] == "runtime-libs-unresolved"

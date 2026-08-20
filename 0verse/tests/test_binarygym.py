"""Binarygym v0 — hermetic tests (macOS-safe, no heavy engine).

Three pieces, matching the v0 deliverable (SPEC.md §8):

  * ``tasks.materialize_cve2026`` builds the 5 post-cutoff seed tasks with the right
    metadata + a held-out ``fixed`` control (skips without gcc).
  * ``oracle.confirm_pov`` enforces the crash-pre/clean-post differential, tested on
    tiny purpose-built mock binaries (crash-on-large-input vs never-crash), plus the
    ``run.run_task`` wiring with a monkeypatched scan (no real decompiler backend).
  * the metric aggregation math (``run.aggregate``) on SYNTHETIC task results — no
    scan, no gcc, no network.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# The binarygym runner/oracle/tasks live under benchmarks/, not on the src path.
BG_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "binarygym"
sys.path.insert(0, str(BG_DIR))

import oracle as bg_oracle  # noqa: E402
import run as bg_run  # noqa: E402
import tasks as bg_tasks  # noqa: E402

HAVE_GCC = shutil.which("gcc") is not None

# A "vuln" that deterministically SIGSEGVs on >16 bytes of stdin, clean otherwise.
_VULN_C = r"""
#include <unistd.h>
int main(void) {
    char in[4096];
    int n = read(0, in, sizeof in);
    if (n > 16) { volatile char *p = 0; *p = in[0]; }  /* null-deref: SIGSEGV */
    return 0;
}
"""

# A "fixed" build that never crashes, whatever the input.
_CLEAN_C = r"""
#include <unistd.h>
int main(void) {
    char in[4096];
    (void)read(0, in, sizeof in);
    return 0;
}
"""


def _compile(src: str, out: Path) -> None:
    cf = out.with_suffix(".c")
    cf.write_text(src)
    proc = subprocess.run(
        ["gcc", "-O0", "-o", str(out), str(cf)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr


# --- oracle.confirm_pov: the crash-pre/clean-post differential --------------

def test_povverdict_confirmed_is_both_gates() -> None:
    assert bg_oracle.PovVerdict(crashes_vuln=True, clean_on_fixed=True).confirmed
    assert not bg_oracle.PovVerdict(crashes_vuln=True, clean_on_fixed=False).confirmed
    assert not bg_oracle.PovVerdict(crashes_vuln=False, clean_on_fixed=True).confirmed


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc to build the mock binaries")
def test_confirm_pov_reproduces_real_differential(tmp_path: Path) -> None:
    vuln, fixed = tmp_path / "vuln", tmp_path / "fixed"
    _compile(_VULN_C, vuln)
    _compile(_CLEAN_C, fixed)
    v = bg_oracle.confirm_pov(vuln, fixed, input_bytes=b"A" * 64, vector="stdin")
    assert v.crashes_vuln and v.clean_on_fixed and v.confirmed
    assert v.vuln_signal == "SIGSEGV"


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc to build the mock binaries")
def test_confirm_pov_no_crash_is_not_confirmed(tmp_path: Path) -> None:
    vuln, fixed = tmp_path / "vuln", tmp_path / "fixed"
    _compile(_VULN_C, vuln)
    _compile(_CLEAN_C, fixed)
    # a small input never trips the vulnerable path -> no PoV
    v = bg_oracle.confirm_pov(vuln, fixed, input_bytes=b"A" * 4, vector="stdin")
    assert not v.crashes_vuln and not v.confirmed


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc to build the mock binaries")
def test_confirm_pov_flags_control_that_also_crashes(tmp_path: Path) -> None:
    # "fixed" is really the SAME vulnerable build -> the PoC crashes the control too,
    # which is a false positive, not a confirmed finding.
    vuln = tmp_path / "vuln"
    _compile(_VULN_C, vuln)
    v = bg_oracle.confirm_pov(vuln, vuln, input_bytes=b"A" * 64, vector="stdin")
    assert v.crashes_vuln and not v.clean_on_fixed and not v.confirmed


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc to build the mock binaries")
def test_run_task_adjudicates_confirmed_finding(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    tdir = tmp_path / "cve2026__mock"
    (tdir / "_held").mkdir(parents=True)
    _compile(_VULN_C, tdir / "vuln")
    _compile(_VULN_C, tdir / "vuln.stripped")
    _compile(_CLEAN_C, tdir / "_held" / "fixed")
    task = bg_tasks.BinaryGymTask(
        id="cve2026:mock", source="cve2026", project="mock",
        cwe="CWE-787", input_vector="stdin",
    )

    def fake_scan(binary: Path, opts: object) -> tuple[list[dict], list[str]]:
        finding = {
            "function": "f", "source": "read", "sink": "memcpy",
            "confirmed": True, "hypothesis": True,
            "pov": {"input_bytes": (b"A" * 64).hex(), "argv": [], "env": {}},
        }
        return [finding], ["stub"]

    monkeypatch.setattr(bg_run, "_scan", fake_scan)
    tr = bg_run.run_task(task, tdir, "LB", bg_run.api.ScanOptions(llm="mock"))
    assert tr.n_confirmed == 1
    assert tr.has_pov and tr.reproduced and not tr.flags_fixed


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc to build the mock binaries")
def test_run_task_flags_false_positive_on_patched(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # "fixed" is really vulnerable -> the confirmed PoC also crashes the control.
    tdir = tmp_path / "cve2026__mock"
    (tdir / "_held").mkdir(parents=True)
    _compile(_VULN_C, tdir / "vuln")
    _compile(_VULN_C, tdir / "vuln.stripped")
    _compile(_VULN_C, tdir / "_held" / "fixed")
    task = bg_tasks.BinaryGymTask(id="cve2026:mock", source="cve2026", project="mock")

    def fake_scan(binary: Path, opts: object) -> tuple[list[dict], list[str]]:
        return [{
            "function": "f", "sink": "memcpy", "confirmed": True, "hypothesis": True,
            "pov": {"input_bytes": (b"A" * 64).hex(), "argv": [], "env": {}},
        }], ["stub"]

    monkeypatch.setattr(bg_run, "_scan", fake_scan)
    tr = bg_run.run_task(task, tdir, "LB", bg_run.api.ScanOptions(llm="mock"))
    assert tr.has_pov and not tr.reproduced and tr.flags_fixed


# --- metric aggregation math (synthetic, no scan) --------------------------

def _tr(**kw: object) -> bg_run.TaskResult:
    base: dict[str, object] = {
        "task_id": "t", "level": "LB", "cwe": "CWE-787",
        "n_confirmed": 1, "has_pov": True, "reproduced": True, "flags_fixed": False,
    }
    base.update(kw)
    return bg_run.TaskResult(**base)  # type: ignore[arg-type]


def test_aggregate_recall_and_precision() -> None:
    results = [
        _tr(task_id="a", has_pov=True, reproduced=True, flags_fixed=False),   # clean win
        _tr(task_id="b", has_pov=True, reproduced=False, flags_fixed=True),   # flags control
        _tr(task_id="c", has_pov=False, reproduced=False, flags_fixed=False),  # no PoV
    ]
    m = bg_run.aggregate(results)
    assert m.n_tasks == 3 and m.n_with_pov == 2
    assert m.reproduced == 1 and m.flagged_fixed == 1
    assert m.confirmed_pov_recall == round(1 / 3, 4)     # 1 of 3 vulnerable tasks
    assert m.precision_patched_controls == 0.5           # 1 of 2 PoVs crashed the control


def test_aggregate_precision_defaults_to_one_without_pov() -> None:
    m = bg_run.aggregate([_tr(has_pov=False, reproduced=False, flags_fixed=False)])
    assert m.confirmed_pov_recall == 0.0
    assert m.precision_patched_controls == 1.0           # no control was ever flagged


def test_aggregate_per_cwe_and_per_level() -> None:
    results = [
        _tr(task_id="a", cwe="CWE-190", level="LB", reproduced=True, has_pov=True),
        _tr(task_id="b", cwe="CWE-787", level="LB-strip",
            reproduced=False, has_pov=True, flags_fixed=True),
    ]
    m = bg_run.aggregate(results)
    assert set(m.by_cwe) == {"CWE-190", "CWE-787"}
    assert m.by_cwe["CWE-190"]["confirmed_pov_recall"] == 1.0
    assert m.by_cwe["CWE-787"]["precision_patched_controls"] == 0.0
    assert set(m.by_level) == {"LB", "LB-strip"}
    assert m.by_level["LB"]["reproduced"] == 1


# --- tasks.materialize_cve2026: the post-cutoff seed corpus -----------------

_SEED_PAIRS = {"ffmpeg_magicyuv", "ffmpeg_rasc", "libheif_copy", "libtiff_ycbcr", "openjpeg_pi"}


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc to compile the seed binaries")
def test_materialize_cve2026(tmp_path: Path) -> None:
    tasks = bg_tasks.materialize_cve2026(tmp_path)
    assert len(tasks) == 5
    assert {t.id for t in tasks} == {f"cve2026:{p}" for p in _SEED_PAIRS}

    for t in tasks:
        assert t.source == "cve2026"
        assert t.oracle == "local-diff"
        assert t.cve.startswith("CVE-2026-")
        assert t.held_out_after_cutoff is True          # every seed is post-cutoff
        assert set(t.sha256) == {"vuln", "vuln.stripped", "fixed"}

        tdir = tmp_path / f"cve2026__{t.id.split(':')[1]}"
        assert (tdir / "vuln").exists()                 # LB input (agent-facing)
        assert (tdir / "vuln.stripped").exists()        # LB-strip input
        assert (tdir / "_held" / "fixed").exists()      # held-out FP control
        assert (tdir / "task.json").exists()
        assert (tdir / "README.md").exists()

    # the agent-facing README must not leak source/patch/bug hints
    readme = (tmp_path / "cve2026__openjpeg_pi" / "README.md").read_text()
    assert "Level B" in readme and "binary-only" in readme


@pytest.mark.skipif(not HAVE_GCC, reason="needs gcc to compile the seed binaries")
def test_load_tasks_roundtrips(tmp_path: Path) -> None:
    built = bg_tasks.materialize_cve2026(tmp_path)
    loaded = bg_tasks.load_tasks(tmp_path)
    assert {t.id for t in loaded} == {t.id for t in built}

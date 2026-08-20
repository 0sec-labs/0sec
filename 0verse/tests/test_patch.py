"""M7 #45/#46 — the patch stage + verify loop.

Two tiers, mirroring the rest of the suite:
  * hermetic logic tests (no binary): B0 recommendation per bug class, the
    mitigation-only anti-cheat, the PatchVerdict gate algebra, the deterministic
    mock patch-diff generator, the contract v1.2 projection, and the cloud
    remediation mapping (verified-only discipline);
  * compiler-gated end-to-end tests (skip without gcc): the REAL verify_patch
    loop on a compiled overflow — a patch that closes the PoV verifies, one that
    does not is rejected, an incomplete patch is rejected, and a mitigation-only
    diff is rejected; plus source-mode patch-gen and the B1 binary micro-patch,
    each PROVEN by re-running the confirmed PoV (it no longer reproduces).
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from zeroverse import api, oracle, patch
from zeroverse.agent import MockLLM, Verdict
from zeroverse.analyze import Finding
from zeroverse.api import ScanOptions  # noqa: F401  (kept for parity / future use)
from zeroverse.cloud_sink import OversePoV, map_pov_to_finding, pov_from_scan_finding
from zeroverse.ingest import Triage
from zeroverse.patch import (
    PatchContext,
    binary_micropatch,
    fix_template,
    generate_source_patch,
    patch_finding,
    recommend,
    run_patch_stage,
)
from zeroverse.pipeline import RunResult, TriagedFinding
from zeroverse.preflight import BudgetTracker, RunBudget
from zeroverse.report import Patch, PoV
from zeroverse.sandbox_exec import ExecResult, LocalExecutor


def test_persist_uses_planned_output_root_and_isolates_same_basename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ZEROVERSE_OUT", str(tmp_path / "wrong-global"))
    first_target = tmp_path / "scratch-a" / "target.bin"
    second_target = tmp_path / "scratch-b" / "target.bin"
    first_target.parent.mkdir()
    second_target.parent.mkdir()
    first_target.write_bytes(b"first")
    second_target.write_bytes(b"second")

    first = patch._persist(first_target, output_dir=tmp_path / "jobs" / "A")
    second = patch._persist(second_target, output_dir=tmp_path / "jobs" / "B")

    assert first == str(tmp_path / "jobs" / "A" / "patches" / "target.bin.patched")
    assert second == str(tmp_path / "jobs" / "B" / "patches" / "target.bin.patched")
    assert Path(first).read_bytes() == b"first"
    assert Path(second).read_bytes() == b"second"
    assert not (tmp_path / "wrong-global").exists()


def test_persist_failure_never_returns_deleted_scratch_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "scratch" / "target.bin"
    target.parent.mkdir()
    target.write_bytes(b"patched")
    monkeypatch.setattr(
        patch.shutil,
        "copy2",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("unwritable")),
    )

    persisted = patch._persist(target, output_dir=tmp_path / "jobs" / "A")
    target.unlink()

    assert persisted == ""


HAVE_CC = shutil.which("gcc") is not None
cc_required = pytest.mark.skipif(not HAVE_CC, reason="no C compiler on host")

BENCH = Path(__file__).resolve().parents[1] / "benchmarks"

_OVERFLOW_SRC = (BENCH / "overflow.c").read_text() if (BENCH / "overflow.c").is_file() else """\
#include <string.h>
#include <unistd.h>
int main(void){char buf[16]; char big[512]={0}; int n=read(0,big,511);
  if(n>=0) big[n]=0; strcpy(buf,big); return 0;}
"""

_PARTIAL_FIX_SRC = """\
#include <string.h>
#include <unistd.h>
int main(void){
  char buf[16]; char big[8192]={0};
  int n = read(0, big, 8191);
  if (n >= 0) big[n] = 0;
  if (big[0] == 'A') { strncpy(buf, big, sizeof(buf) - 1); buf[sizeof(buf)-1]=0; }
  else { strcpy(buf, big); }   /* sibling input still overflows: incomplete fix */
  return 0;
}
"""

_OVERFLOW_FLAGS = ["-fno-stack-protector", "-no-pie"]


def _compile(src: str, name: str, flags: list[str]) -> tuple[str, Path]:
    d = Path(tempfile.mkdtemp(prefix="0verse-test-patch-"))
    c = d / f"{name}.c"
    c.write_text(src)
    out = d / name
    subprocess.run(
        ["gcc", "-O0", *flags, "-o", str(out), str(c)],
        check=True, capture_output=True,
    )
    return str(out), d


def _overflow_finding() -> Finding:
    return Finding("read", "strcpy", "main", 0x1000, 0x4011bc, 6)


def _confirmed_overflow_pov(binary: str) -> PoV:
    from zeroverse.dynamic import confirm

    v = Verdict(True, "CWE-120", "high", "unbounded copy", "A" * 64)
    pov = confirm(_overflow_finding(), v, binary)
    assert pov is not None and pov.reproduced
    return pov


# ----------------------------------------------------------------------------
# B0 — located fix recommendation (deterministic, always-on, zero-dep)
# ----------------------------------------------------------------------------

def test_b0_recommendation_per_bugclass() -> None:
    f = Finding("read", "strcpy", "parse", 0x100, 0x401a37, 2)
    pov = PoV(crash_class="SIGSEGV", reproduced=True)
    cases = {
        "CWE-120 buffer overflow": "bound the copy",
        "CWE-190 integer overflow": "overflow before the allocation",
        "CWE-134 format string": "constant format",
        "CWE-416 use-after-free": "after it is freed",
        "CWE-78 OS command injection": "Avoid the shell",
    }
    for bug_class, needle in cases.items():
        p = recommend(f, pov, bug_class=bug_class)
        assert p.mode == "recommendation"
        assert p.verified is False                 # B0 is advice, never verified
        assert p.locator.startswith("parse @ 0x401a37")
        assert needle.lower() in p.recommendation.lower()


def test_fix_template_routes_by_sink_when_class_unknown() -> None:
    assert "bound the copy" in fix_template("", "strcpy").lower()
    assert "shell" in fix_template("", "system").lower()


def test_recommend_includes_locator_with_sink_and_addr() -> None:
    f = Finding("recv", "memcpy", "handler", 0x10, 0x2222, 1)
    p = recommend(f, PoV(reproduced=True), bug_class="memory-safety")
    assert "handler @ 0x2222" in p.locator and "memcpy" in p.locator


# ----------------------------------------------------------------------------
# anti-cheat #1 — mitigation-only detection (hermetic)
# ----------------------------------------------------------------------------

def test_mitigation_only_flags_hardening_diff() -> None:
    flag_diff = (
        "--- a/Makefile\n+++ b/Makefile\n@@ -1 +1 @@\n"
        "-CFLAGS = -O0\n+CFLAGS = -O0 -fstack-protector-all -D_FORTIFY_SOURCE=2\n"
    )
    assert oracle.looks_mitigation_only(flag_diff, sink="strcpy") is True


def test_mitigation_only_flags_broad_catch() -> None:
    catch_diff = (
        "--- a/x.c\n+++ b/x.c\n@@ -1 +2 @@\n"
        "+    try {\n+    } catch (Exception e) { return; }\n"
    )
    assert oracle.looks_mitigation_only(catch_diff) is True


def test_real_bounds_fix_is_not_mitigation_only() -> None:
    fix_diff = (
        "--- a/overflow.c\n+++ b/overflow.c\n@@ -11 +11 @@\n"
        "-    strcpy(buf, big);\n"
        "+    strncpy(buf, big, sizeof(buf) - 1); buf[sizeof(buf)-1] = 0;\n"
    )
    assert oracle.looks_mitigation_only(fix_diff, sink="strcpy") is False


# ----------------------------------------------------------------------------
# PatchVerdict gate algebra (hermetic)
# ----------------------------------------------------------------------------

def test_patch_verdict_requires_both_gates_and_no_cheat() -> None:
    assert oracle.PatchVerdict(True, True).verified is True
    assert oracle.PatchVerdict(True, False).verified is False     # regression
    assert oracle.PatchVerdict(False, True).verified is False     # PoV still fires
    assert oracle.PatchVerdict(True, True, mitigation_only=True).verified is False
    assert oracle.PatchVerdict(True, True, incomplete=True).verified is False


# ----------------------------------------------------------------------------
# the deterministic mock patch-diff generator (hermetic)
# ----------------------------------------------------------------------------

def test_mock_llm_emits_bounded_copy_diff() -> None:
    prompt = (
        "SINK: strcpy\n"
        "SOURCE FILE: overflow.c\n"
        f"--- BEGIN SOURCE ---\n{_OVERFLOW_SRC}\n--- END SOURCE ---\n"
    )
    out = MockLLM().complete_json("sys", prompt, patch._PATCH_SCHEMA)
    diff = out["diff"]
    assert "strncpy" in diff
    assert "--- a/overflow.c" in diff and "+++ b/overflow.c" in diff


# ----------------------------------------------------------------------------
# contract v1.2 projection (hermetic)
# ----------------------------------------------------------------------------

def _result_with_patch(patch_obj: object) -> RunResult:
    t = Triage(path="/bin/vuln", fmt="ELF", arch="x86-64", bits=64,
               endian="little", kind="EXEC")
    f = Finding("read", "strcpy", "main", 0x1000, 0x4011bc, 6)
    v = Verdict(True, "CWE-120", "high", "overflow", "A" * 64)
    pov = PoV(input_bytes=b"A" * 64, crash_class="SIGSEGV", reproduced=True,
              capability="oob-write", dedup_bucket="b1", pov_script="/out/p.py")
    pov.patch = patch_obj  # type: ignore[assignment]
    return RunResult(triage=t, stages_run=["ingest", "dynamic", "patch"],
                     findings=[TriagedFinding(finding=f, verdict=v, pov=pov)])


def test_contract_v1_2_projects_verified_patch() -> None:
    from zeroverse.report import Patch
    p = Patch(mode="binary-micropatch", verified=True,
              patched_artifact="/out/vuln.patched",
              recommendation="main @ 0x4011bc: bound the copy",
              regression="control-inputs identical on 1 benign sample(s)")
    sf = api._result_from_run("/bin/vuln", _result_with_patch(p)).findings[0]
    d = sf.to_dict()
    assert d["patch_available"] is True
    assert d["patch_verified"] is True
    assert d["patch_mode"] == "binary-micropatch"
    assert d["patch_path"] == "/out/vuln.patched"
    assert "bound the copy" in d["patch_recommendation"]


def test_contract_v1_2_unverified_recommendation() -> None:
    from zeroverse.report import Patch
    p = Patch(mode="recommendation", verified=False,
              recommendation="main @ 0x4011bc: bound the copy")
    sf = api._result_from_run("/bin/vuln", _result_with_patch(p)).findings[0]
    d = sf.to_dict()
    assert d["patch_available"] is True
    assert d["patch_verified"] is False
    assert d["patch_mode"] == "recommendation"
    assert d["patch_path"] is None


# ----------------------------------------------------------------------------
# cloud remediation mapping — verified-only discipline (hermetic)
# ----------------------------------------------------------------------------

def _cloud_pov(**kw: object) -> OversePoV:
    base: dict[str, object] = {
        "id": "x", "bug_class": "CWE-120", "severity": "high", "title": "t",
        "description": "d", "target": "/bin/vuln", "confirmed": True,
        "repro_cmd": "python3 /out/p.py", "pov_path": "/out/p.py",
        "crash_output": "SIGSEGV", "capability": "oob-write",
    }
    base.update(kw)
    return OversePoV(**base)  # type: ignore[arg-type]


def test_cloud_shows_verified_fix_only_when_verified() -> None:
    cf = map_pov_to_finding(_cloud_pov(
        patch_mode="binary-micropatch", patch_verified=True,
        patch_path="/out/vuln.patched",
        patch_recommendation="main @ 0x4011bc: bound the copy",
        patch_regression="control-inputs identical",
    ))
    rem = cf["evidence"]["remediation"]
    assert rem["status"] == "verified" and rem["verified"] is True
    steps = [s for s in cf["pocSteps"] if s["kind"] == "binary-patch"]
    assert steps and steps[0]["verified"] is True


def test_cloud_unverified_patch_is_suggested_not_fixed() -> None:
    cf = map_pov_to_finding(_cloud_pov(
        patch_mode="recommendation", patch_verified=False,
        patch_recommendation="main @ 0x4011bc: bound the copy",
    ))
    rem = cf["evidence"]["remediation"]
    assert rem["status"] == "suggested" and rem["verified"] is False
    steps = [s for s in cf["pocSteps"] if s["kind"] == "fix-recommendation"]
    assert steps and steps[0]["verified"] is False


def test_cloud_no_patch_has_no_remediation() -> None:
    cf = map_pov_to_finding(_cloud_pov())
    assert "remediation" not in cf["evidence"]
    assert all(s["kind"] == "binary-pov" for s in cf["pocSteps"])


def test_cloud_projection_carries_patch_fields() -> None:
    from zeroverse.api import ScanFinding
    f = ScanFinding(
        id="x", bug_class="CWE-120", severity="high", file="/bin/v", function="main",
        offset="0x4011bc", source="read", sink="strcpy", confirmed=True,
        hypothesis=True, pruned=False, capability="oob-write", pov_path="/out/p.py",
        repro_cmd="python3 /out/p.py", dedup_bucket="b1", explanation="",
        patch_available=True, patch_verified=True, patch_mode="source-diff",
        patch_path="/out/x.patched", patch_recommendation="bound it",
        patch_regression="tests 1/1",
    )
    pov = pov_from_scan_finding(f, "/bin/v")
    assert pov.patch_verified is True and pov.patch_mode == "source-diff"


# ----------------------------------------------------------------------------
# stage-9 driver gating (hermetic — B0 needs no execution)
# ----------------------------------------------------------------------------

def test_run_patch_stage_gated_and_attaches_recommendation(monkeypatch: pytest.MonkeyPatch) -> None:
    rr = _result_with_patch(None)
    rr.findings[0].pov.patch = None  # type: ignore[union-attr]
    monkeypatch.delenv("ZEROVERSE_PATCH", raising=False)
    assert run_patch_stage(rr, "/bin/vuln") == 0
    assert rr.findings[0].pov.patch is None  # type: ignore[union-attr]
    monkeypatch.setenv("ZEROVERSE_PATCH", "1")
    monkeypatch.delenv("ZEROVERSE_PATCH_SOURCE_ROOT", raising=False)
    monkeypatch.delenv("ZEROVERSE_BINPATCH", raising=False)
    assert run_patch_stage(rr, "/bin/vuln") == 1
    p = rr.findings[0].pov.patch  # type: ignore[union-attr]
    assert p is not None and p.mode == "recommendation"


def test_run_patch_stage_threads_planned_patch_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rr = _result_with_patch(None)
    rr.findings[0].pov.patch = None  # type: ignore[union-attr]
    monkeypatch.setenv("ZEROVERSE_PATCH", "1")
    monkeypatch.delenv("ZEROVERSE_PATCH_SOURCE_ROOT", raising=False)
    monkeypatch.delenv("ZEROVERSE_BINPATCH", raising=False)
    calls: list[dict[str, object]] = []

    def fake_patch_finding(*args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(kwargs)
        return Patch(mode="recommendation", verified=False)

    monkeypatch.setattr(patch, "patch_finding", fake_patch_finding)
    budget = BudgetTracker.start(
        RunBudget(attempt_limit=8, unknown_sink_oracle_attempts=0)
    )
    executor = LocalExecutor()

    assert run_patch_stage(
        rr,
        "/bin/vuln",
        budget=budget,
        executor=executor,
        executor_provider="planned-local",
        native_compiler_path="/planned/native-cc",
        output_dir=tmp_path,
    ) == 1
    assert calls[0]["budget"] is budget
    assert calls[0]["executor"] is executor
    assert calls[0]["executor_provider"] == "planned-local"
    assert calls[0]["native_compiler_path"] == "/planned/native-cc"
    assert calls[0]["output_dir"] == tmp_path


def test_patch_verification_reserves_each_replay_and_stops_on_exhaustion() -> None:
    class RecordingLocalExecutor(LocalExecutor):
        def __init__(self) -> None:
            self.timeouts: list[float] = []

        def run(self, argv, *, stdin=b"", env=None, timeout=10.0):  # type: ignore[no-untyped-def]
            self.timeouts.append(timeout)
            return ExecResult(returncode=0, stdout="same")

    executor = RecordingLocalExecutor()
    budget = BudgetTracker.start(
        RunBudget(attempt_limit=3, unknown_sink_oracle_attempts=0)
    )
    verdict = oracle.verify_patch(
        PoV(input_bytes=b"A", crash_class="SIGSEGV", reproduced=True),
        "/patched",
        original_target="/original",
        control_inputs=[b"A"],
        fuzz_iters=2,
        budget=budget,
        executor=executor,
        executor_provider="planned-local",
        native_compiler_path="/planned/native-cc",
    )

    assert verdict.verified is False
    assert verdict.incomplete is True
    assert "budget exhausted" in "; ".join(verdict.notes)
    assert budget.attempts_used == 3
    assert budget.reservation_failures == 1
    assert len(executor.timeouts) == 3
    assert all(0 < timeout <= 10.0 for timeout in executor.timeouts)


# ----------------------------------------------------------------------------

@cc_required
def test_verify_patch_accepts_real_fix_rejects_nonfix() -> None:
    vuln, _ = _compile(_OVERFLOW_SRC, "overflow", _OVERFLOW_FLAGS)
    pov = _confirmed_overflow_pov(vuln)
    # A genuine bounded fix (rebuilt) — the PoV must no longer reproduce.
    fixed_src = _OVERFLOW_SRC.replace(
        "strcpy(buf, big);",
        "strncpy(buf, big, sizeof(buf) - 1); buf[sizeof(buf)-1] = 0;",
    )
    fixed, _ = _compile(fixed_src, "overflow", _OVERFLOW_FLAGS)

    good = oracle.verify_patch(pov, fixed, original_target=fixed,
                               control_inputs=[b"A"], sink="strcpy",
                               sink_function="main", binary_touches_taintpath=True)
    assert good.gate1_closes_pov is True
    assert good.verified is True
    assert "no longer reproduces" in good.gate1_note

    # The unpatched binary as a "patch" → the PoV still fires → rejected.
    bad = oracle.verify_patch(pov, vuln, original_target=vuln, control_inputs=[b"A"])
    assert bad.gate1_closes_pov is False
    assert bad.verified is False


@cc_required
def test_incomplete_patch_is_rejected() -> None:
    vuln, _ = _compile(_OVERFLOW_SRC, "overflow", _OVERFLOW_FLAGS)
    pov = _confirmed_overflow_pov(vuln)
    # partial fix: closes the EXACT PoV (input starts 'A') but a sibling crashes.
    partial, _ = _compile(_PARTIAL_FIX_SRC, "partial", _OVERFLOW_FLAGS)
    v = oracle.verify_patch(pov, partial, original_target=partial,
                            control_inputs=[b"A"], sink="strcpy", sink_function="main")
    assert v.gate1_closes_pov is True       # the exact PoV no longer reproduces
    assert v.incomplete is True             # ...but a near-variant still crashes
    assert v.verified is False


@cc_required
def test_mitigation_only_real_binary_rejected() -> None:
    vuln, _ = _compile(_OVERFLOW_SRC, "overflow", _OVERFLOW_FLAGS)
    pov = _confirmed_overflow_pov(vuln)
    fixed_src = _OVERFLOW_SRC.replace(
        "strcpy(buf, big);",
        "strncpy(buf, big, sizeof(buf) - 1); buf[sizeof(buf)-1] = 0;",
    )
    fixed, _ = _compile(fixed_src, "overflow", _OVERFLOW_FLAGS)
    flag_diff = (
        "--- a/Makefile\n+++ b/Makefile\n@@ -1 +1 @@\n"
        "-CFLAGS = -O0\n+CFLAGS = -O0 -fstack-protector-all\n"
    )
    v = oracle.verify_patch(pov, fixed, original_target=fixed, control_inputs=[b"A"],
                            diff=flag_diff, sink="strcpy", sink_function="main")
    assert v.gate1_closes_pov is True       # hardening did close the PoV
    assert v.mitigation_only is True        # ...but it is mitigation, not a fix
    assert v.verified is False


# ----------------------------------------------------------------------------
# Mode A — source patch generation, PROVEN by re-running the PoV
# ----------------------------------------------------------------------------

@cc_required
def test_source_mode_generates_verified_patch(tmp_path: Path) -> None:
    vuln, _ = _compile(_OVERFLOW_SRC, "overflow", _OVERFLOW_FLAGS)
    pov = _confirmed_overflow_pov(vuln)
    root = Path(tempfile.mkdtemp(prefix="0verse-test-src-"))
    (root / "overflow.c").write_text(_OVERFLOW_SRC)
    ctx = PatchContext(
        source_root=str(root),
        build_cmd=["gcc", "-O0", *_OVERFLOW_FLAGS, "-o", "overflow", "overflow.c"],
        target_rel="overflow",
    )
    budget = BudgetTracker.start(
        RunBudget(attempt_limit=64, unknown_sink_oracle_attempts=0)
    )
    native_compiler = shutil.which("gcc")
    assert native_compiler is not None
    p = generate_source_patch(
        _overflow_finding(),
        pov,
        ctx,
        MockLLM(),
        bug_class="CWE-120",
        output_dir=tmp_path,
        budget=budget,
        executor=LocalExecutor(),
        executor_provider="planned-local",
        native_compiler_path=native_compiler,
    )
    assert p.mode == "source-diff"
    assert p.verified is True
    assert "strncpy" in p.diff
    assert "no longer reproduces" in p.pov_recheck
    assert p.patched_artifact.startswith(str(tmp_path / "patches"))
    assert Path(p.patched_artifact).is_file()
    assert budget.attempts_used > 1


# ----------------------------------------------------------------------------
# B1 — binary micro-patch (immediate-clamp), PROVEN by re-running the PoV
# ----------------------------------------------------------------------------

@cc_required
def test_binary_micropatch_immediate_clamp_verifies(tmp_path: Path) -> None:
    vuln, _ = _compile(_OVERFLOW_SRC, "overflow", _OVERFLOW_FLAGS)
    pov = _confirmed_overflow_pov(vuln)
    p = binary_micropatch(
        _overflow_finding(),
        pov,
        vuln,
        dest_bound=16,
        bug_class="CWE-120",
        output_dir=tmp_path,
        budget=BudgetTracker.start(
            RunBudget(attempt_limit=64, unknown_sink_oracle_attempts=0)
        ),
        executor=LocalExecutor(),
        executor_provider="planned-local",
        native_compiler_path=shutil.which("gcc"),
    )
    if p.mode != "binary-micropatch":
        pytest.skip(f"immediate-clamp could not apply (degraded to B0: {p.rejected_reason})")
    assert p.verified is True
    assert p.patched_artifact and Path(p.patched_artifact).is_file()
    assert Path(p.patched_artifact).parent == tmp_path / "patches"
    # PROOF: the confirmed PoV no longer reproduces against the patched binary.
    assert oracle.recheck_pov(pov, p.patched_artifact).reproduced is False
    # ...and the original still does (the bug was real).
    assert oracle.recheck_pov(pov, vuln).reproduced is True


@cc_required
def test_binary_micropatch_degrades_to_b0_when_no_clamp() -> None:
    # cmdi has no clampable length immediate → must degrade honestly to B0.
    cmdi, _ = _compile(
        "#include <stdlib.h>\nint main(){char*c=getenv(\"CMD\"); system(c); return 0;}",
        "cmdi", [],
    )
    f = Finding("getenv", "system", "main", 0x10, 0x20, 1)
    pov = PoV(env={"CMD": "echo hi"}, crash_class="command-injection", reproduced=True)
    p = binary_micropatch(f, pov, cmdi, dest_bound=16, bug_class="CWE-78")
    assert p.mode == "recommendation"
    assert p.verified is False
    assert "degraded to B0" in p.rejected_reason


@cc_required
def test_patch_finding_end_to_end_source_mode() -> None:
    vuln, _ = _compile(_OVERFLOW_SRC, "overflow", _OVERFLOW_FLAGS)
    pov = _confirmed_overflow_pov(vuln)
    root = Path(tempfile.mkdtemp(prefix="0verse-test-e2e-"))
    (root / "overflow.c").write_text(_OVERFLOW_SRC)
    ctx = PatchContext(
        source_root=str(root),
        build_cmd=["gcc", "-O0", *_OVERFLOW_FLAGS, "-o", "overflow", "overflow.c"],
        target_rel="overflow",
    )
    p = patch_finding(_overflow_finding(), pov, binary=vuln, bug_class="CWE-120",
                      ctx=ctx, llm=MockLLM())
    assert p.verified is True and p.mode == "source-diff"


# --- reflection accumulates instead of overwriting (issue #1705) ------------


def test_reflection_text_accumulates_and_is_bounded() -> None:
    assert patch._reflection_text([]) == ""
    text = patch._reflection_text(["first failed", "second failed", "third failed"])
    # Every earlier failure is visible, numbered, oldest first.
    assert "first failed" in text and "second failed" in text and "third failed" in text
    assert text.index("first failed") < text.index("third failed")
    assert "attempt 1:" in text and "attempt 3:" in text
    assert "3 so far" in text
    assert "do NOT" in text and "already listed here as failed" in text

    # Bounded: only the most recent window is replayed, but the true count is kept.
    many = [f"failure {i}" for i in range(20)]
    bounded = patch._reflection_text(many)
    assert bounded.count("failure ") == patch._MAX_REFLECTIONS
    assert "failure 19" in bounded and "failure 0" not in bounded
    assert "20 so far" in bounded
    assert f"attempt {20 - patch._MAX_REFLECTIONS + 1}:" in bounded


def test_patch_prompt_carries_every_prior_failure() -> None:
    prompt = patch._patch_prompt(
        _overflow_finding(),
        PoV(input_bytes=b"AAAA", reproduced=True),
        "rca",
        "overflow.c",
        _OVERFLOW_SRC,
        ["build failed: undefined ref", "GATE2 regression"],
        "CWE-120",
    )
    assert "build failed: undefined ref" in prompt
    assert "GATE2 regression" in prompt


def test_third_attempt_sees_the_first_attempts_failure(tmp_path: Path) -> None:
    # The bug: `reflection` was reassigned each round, so attempt 3 was blind to
    # attempt 1 and could cycle back onto an approach already measured as dead.
    root = tmp_path / "src"
    root.mkdir()
    (root / "overflow.c").write_text(_OVERFLOW_SRC)

    class RecordingLLM:
        """Fails a DIFFERENT way each round so the accumulated history is distinct."""

        def __init__(self) -> None:
            self.prompts: list[str] = []
            self.diffs = ["", "this is not a valid unified diff at all", ""]

        def complete_json(self, system: str, prompt: str, schema: dict) -> dict:
            self.prompts.append(prompt)
            return {"diff": self.diffs[len(self.prompts) - 1]}

    llm = RecordingLLM()
    generate_source_patch(
        _overflow_finding(),
        PoV(input_bytes=b"AAAA", reproduced=True),
        PatchContext(source_root=str(root), build_cmd=["true"], target_rel="overflow"),
        llm,  # type: ignore[arg-type]
        bug_class="CWE-120",
        max_iters=3,
    )

    assert len(llm.prompts) == 3
    # Attempt 1 has no history yet.
    assert "PREVIOUS ATTEMPTS FAILED" not in llm.prompts[0]
    # Attempt 2 sees round 1.
    assert "no diff produced" in llm.prompts[1]
    # Attempt 3 sees BOTH — this is the whole fix.
    assert "no diff produced" in llm.prompts[2]
    assert "did not apply" in llm.prompts[2]
    assert "2 so far" in llm.prompts[2]

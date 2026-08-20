"""M7 #47 — AIxCC CRS-API / SARIF adapter: task ingestion, the POVSubmission
emit, the SARIF matcher (match + reject), the conservative PoV-backed assessment,
and the end-to-end ``run_task`` with an injected runner.
"""

from __future__ import annotations

import base64
import json

from zeroverse import crs_api
from zeroverse.agent import Verdict
from zeroverse.analyze import Finding
from zeroverse.crs_api import (
    Frame,
    SARIFBroadcast,
    SarifInfo,
    SarifMatcher,
    SourceType,
    Task,
    TaskType,
    assess_broadcast,
    delta_files,
    extract_sarif_infos,
    match_frame,
    parse_frame,
    povs_from_run,
    run_task,
)
from zeroverse.ingest import Triage
from zeroverse.pipeline import RunResult, TriagedFinding
from zeroverse.report import Patch, PoV

# --- fixtures --------------------------------------------------------------

_SARIF_BROADCAST = {
    "message_id": "msg-1",
    "message_time": 1750000000000,
    "broadcasts": [
        {
            "sarif_id": "sarif-1",
            "task_id": "task-1",
            "sarif": {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "foxguard"}},
                        "results": [
                            {
                                "ruleId": "CWE-787",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/proj/parse.c"},
                                            "region": {"startLine": 40, "endLine": 45},
                                        },
                                        "logicalLocations": [
                                            {"name": "process_record", "kind": "function"}
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ],
            },
        }
    ],
}


def _confirmed_run(*, frames: list[str], with_bytes: bool = True) -> RunResult:
    t = Triage(path="/bin/harness", fmt="ELF", arch="x86-64", bits=64,
               endian="little", kind="EXEC")
    f = Finding("read", "memcpy", "process_record", 0x1000, 0x401042, 4)
    v = Verdict(True, "CWE-787", "high", "oob write", "AAAA")
    pov = PoV(
        input_bytes=(b"CRASHME" if with_bytes else None),
        crash_class="SIGSEGV-write",
        capability="oob-write",
        frames=frames,
        reproduced=True,
        crash_trace="AddressSanitizer: heap-buffer-overflow WRITE",
    )
    return RunResult(triage=t, stages_run=["ingest", "analyze", "dynamic", "poc"],
                     findings=[TriagedFinding(finding=f, verdict=v, pov=pov)])


def _hypothesis_run() -> RunResult:
    t = Triage(path="/bin/harness", fmt="ELF", arch="x86-64", bits=64,
               endian="little", kind="EXEC")
    f = Finding("recv", "memcpy", "handler", 0x2000, 0x2100, 3)
    v = Verdict(True, "CWE-120", "medium", "maybe", "")
    return RunResult(triage=t, stages_run=["ingest", "analyze"],
                     findings=[TriagedFinding(finding=f, verdict=v, pov=None)])


# --- task ingestion --------------------------------------------------------

def test_task_from_dict_full() -> None:
    task = Task.from_dict({
        "message_id": "m1",
        "message_time": 123,
        "tasks": [{
            "task_id": "task-1", "type": "full", "project_name": "libxml2",
            "focus": "libxml2", "deadline": 1750000000000, "harnesses_included": True,
            "source": [
                {"type": "repo", "url": "http://x/repo.tgz", "sha256": "ab"},
                {"type": "fuzz-tooling", "url": "http://x/oss.tgz", "sha256": "cd"},
            ],
        }],
    })
    assert task.message_id == "m1"
    td = task.tasks[0]
    assert td.task_id == "task-1" and td.type is TaskType.FULL
    assert td.project_name == "libxml2"
    assert td.source_of(SourceType.REPO) is not None
    assert td.source_of(SourceType.DIFF) is None


def test_delta_files_from_diff() -> None:
    td = Task.from_dict({
        "tasks": [{"task_id": "t", "type": "delta", "project_name": "p",
                   "source": [{"type": "diff", "url": "u", "sha256": "h"}]}],
    }).tasks[0]
    diff = (
        "--- a/src/proj/parse.c\n+++ b/src/proj/parse.c\n@@ -1 +1 @@\n-x\n+y\n"
        "--- a/src/proj/util.c\n+++ b/src/proj/util.c\n@@ -1 +1 @@\n-z\n+w\n"
    )
    assert delta_files(td, diff) == ["src/proj/parse.c", "src/proj/util.c"]
    # full-mode task yields no delta hints.
    full = Task.from_dict({"tasks": [{"task_id": "t", "type": "full",
                                      "project_name": "p"}]}).tasks[0]
    assert delta_files(full, diff) == []


# --- POVSubmission emit -----------------------------------------------------

def test_povs_from_run_emits_base64_testcase() -> None:
    povs = povs_from_run(_confirmed_run(frames=["process_record at parse.c:42"]),
                         harness_name="fuzz_parse", sanitizer="address")
    assert len(povs) == 1
    p = povs[0]
    assert p.fuzzer_name == "fuzz_parse" and p.sanitizer == "address"
    assert p.architecture == "x86_64" and p.engine == "libfuzzer"
    assert base64.b64decode(p.testcase) == b"CRASHME"
    assert p.testcase_bytes == b"CRASHME"
    assert json.loads(json.dumps(p.to_dict()))["fuzzer_name"] == "fuzz_parse"


def test_povs_from_run_skips_hypotheses_and_byteless() -> None:
    # a hypothesis (no PoV) is never submittable
    assert povs_from_run(_hypothesis_run(), harness_name="h") == []
    # a reproduced PoV with no input bytes can't be submitted either
    assert povs_from_run(_confirmed_run(frames=["x"], with_bytes=False),
                         harness_name="h") == []


# --- SARIF parse + matcher --------------------------------------------------

def test_parse_frame_shapes() -> None:
    assert parse_frame("process_record at /src/parse.c:42") == Frame(
        "process_record", "/src/parse.c", 42)
    assert parse_frame("main /src/main.c:10") == Frame("main", "/src/main.c", 10)
    assert parse_frame("/src/parse.c:7 in copy") == Frame("copy", "/src/parse.c", 7)
    assert parse_frame("lone_func") == Frame("lone_func", "", None)


def test_extract_sarif_infos() -> None:
    infos = extract_sarif_infos(_SARIF_BROADCAST["broadcasts"][0]["sarif"])
    assert len(infos) == 1
    i = infos[0]
    assert i.function == "process_record" and i.basename == "parse.c"
    assert i.start_line == 40 and i.end_line == 45 and i.rule_id == "CWE-787"


def test_match_frame_location_and_function() -> None:
    info = SarifInfo("process_record", "src/proj/parse.c", 40, 45, "CWE-787")
    # location match: line in range + basename match
    m = match_frame(Frame("anything_else", "/build/parse.c", 42), info)
    assert m is not None and m.matches_lines and m.matches_filename
    # exact function match even with no line/file
    m2 = match_frame(Frame("process_record", "", None), info)
    assert m2 is not None and m2.matches_function
    # stripped OSS_FUZZ_ prefix
    m3 = match_frame(Frame("OSS_FUZZ_process_record", "", None), info)
    assert m3 is not None and m3.matches_stripped_function


def test_match_frame_rejects_unrelated() -> None:
    info = SarifInfo("process_record", "src/proj/parse.c", 40, 45, "CWE-787")
    assert match_frame(Frame("other", "/x/other.c", 9), info) is None


def test_sarif_matcher_matches_and_rejects() -> None:
    matcher = SarifMatcher()
    sarif = _SARIF_BROADCAST["broadcasts"][0]["sarif"]
    good = [parse_frame("process_record at /src/proj/parse.c:42")]
    bad = [parse_frame("unrelated at /src/proj/other.c:9")]
    assert matcher.match(sarif, good) is not None
    assert matcher.match(sarif, bad) is None


# --- conservative assessment (PoV-is-truth) ---------------------------------

def test_assess_correct_only_with_pov_backing() -> None:
    detail = SARIFBroadcast.from_dict(_SARIF_BROADCAST).broadcasts[0]
    frames = [parse_frame("process_record at /src/proj/parse.c:42")]
    # matched AND PoV-backed -> correct
    a = assess_broadcast(detail, frames, pov_backed=True)
    assert a.assessment == "correct" and a.matched and a.match is not None
    # matched but NO PoV -> not asserted (conservative)
    a2 = assess_broadcast(detail, frames, pov_backed=False)
    assert a2.assessment == "incorrect" and a2.matched and not a2.pov_backed
    # no match at all -> incorrect
    a3 = assess_broadcast(detail, [parse_frame("nope at /x/y.c:1")], pov_backed=True)
    assert a3.assessment == "incorrect" and not a3.matched


# --- end-to-end run_task ----------------------------------------------------

def test_run_task_matches_broadcast_and_emits_pov() -> None:
    detail = Task.from_dict({
        "tasks": [{"task_id": "task-1", "type": "full", "project_name": "proj",
                   "focus": "proj"}],
    }).tasks[0]
    resolved = crs_api.ResolvedTask(detail=detail, target_binary="/bin/harness",
                                    harness_name="fuzz_parse", sanitizer="address")
    broadcast = SARIFBroadcast.from_dict(_SARIF_BROADCAST)
    rr = _confirmed_run(frames=["process_record at /src/proj/parse.c:42",
                                "main at /src/proj/main.c:10"])

    def fake_runner(path: str, *, bug_class: str = "memory-safety") -> RunResult:
        assert path == "/bin/harness"
        return rr

    out = run_task(resolved, broadcast=broadcast, runner=fake_runner)
    assert out.task_id == "task-1"
    assert out.confirmed_count == 1
    assert len(out.pov_submissions) == 1
    assert len(out.sarif_assessments) == 1
    assert out.sarif_assessments[0].assessment == "correct"
    # the scan still serializes to a valid SARIF 2.1.0 doc
    doc = json.loads(out.scan_sarif())
    assert doc["version"] == "2.1.0"
    # full to_dict round-trips through json
    assert json.loads(json.dumps(out.to_dict()))["task_id"] == "task-1"


def test_run_task_rejects_unrelated_broadcast() -> None:
    detail = Task.from_dict({
        "tasks": [{"task_id": "task-1", "type": "full", "project_name": "proj"}],
    }).tasks[0]
    resolved = crs_api.ResolvedTask(detail=detail, target_binary="/bin/harness",
                                    harness_name="fuzz_parse")
    broadcast = SARIFBroadcast.from_dict(_SARIF_BROADCAST)
    # confirmed PoV, but its backtrace is in a different file than the SARIF.
    rr = _confirmed_run(frames=["wrong_func at /src/proj/elsewhere.c:99"])
    out = run_task(resolved, broadcast=broadcast, runner=lambda p, **k: rr)
    assert out.sarif_assessments[0].assessment == "incorrect"
    assert not out.sarif_assessments[0].matched
    # but the PoV is still real and submittable
    assert len(out.pov_submissions) == 1


def test_run_task_scoping_skips_other_task_broadcasts() -> None:
    detail = Task.from_dict({
        "tasks": [{"task_id": "task-OTHER", "type": "full", "project_name": "proj"}],
    }).tasks[0]
    resolved = crs_api.ResolvedTask(detail=detail, target_binary="/bin/harness",
                                    harness_name="h")
    broadcast = SARIFBroadcast.from_dict(_SARIF_BROADCAST)  # broadcast is for task-1
    rr = _confirmed_run(frames=["process_record at /src/proj/parse.c:42"])
    out = run_task(resolved, broadcast=broadcast, runner=lambda p, **k: rr)
    assert out.sarif_assessments == []   # scoped out: broadcast.task_id != task-OTHER



# --- schema-valid patch and submitted-SARIF payloads ---------------------------


def _patched_run(*, frames: list[str]) -> RunResult:
    """A confirmed run where the PoV carries a Patch object."""
    t = Triage(path="/bin/harness", fmt="ELF", arch="x86-64", bits=64,
               endian="little", kind="EXEC")
    f = Finding("read", "memcpy", "process_record", 0x1000, 0x401042, 4)
    v = Verdict(True, "CWE-787", "high", "oob write", "AAAA")
    patch = Patch(
        mode="source-diff",
        verified=True,
        diff=("--- a/parse.c\n+++ b/parse.c\n@@ -42,1 +42,1 @@\n"
              "-    memcpy(dst, src, len);\n+    memcpy(dst, src, size);"),
        recommendation="Fix buffer size in parse_record",
        locator="process_record @ 0x401042 (sink memcpy)",
        regression="All 42 tests pass",
        pov_recheck="PoV no longer reproduces (exit 0, no signal)",
    )
    pov = PoV(
        input_bytes=b"CRASHME",
        crash_class="SIGSEGV-write",
        capability="oob-write",
        frames=frames,
        reproduced=True,
        patch=patch,
        crash_trace="AddressSanitizer: heap-buffer-overflow WRITE",
    )
    return RunResult(triage=t, stages_run=["ingest", "analyze", "dynamic", "poc", "patch"],
                     findings=[TriagedFinding(finding=f, verdict=v, pov=pov)])


def test_patched_run_produces_schema_valid_payloads_without_a_premature_bundle() -> None:
    detail = Task.from_dict({
        "tasks": [{"task_id": "task-1", "type": "full", "project_name": "proj"}],
    }).tasks[0]
    resolved = crs_api.ResolvedTask(
        detail=detail,
        target_binary="/bin/harness",
        harness_name="fuzz_parse",
        sanitizer="address",
    )
    out = run_task(
        resolved,
        runner=lambda _path, **_kwargs: _patched_run(
            frames=["process_record at /src/proj/parse.c:42"]
        ),
    )

    assert len(out.patch_submissions) == 1
    patch = out.patch_submissions[0]
    assert patch.patch_bytes.startswith(b"--- a/parse.c\n+++ b/parse.c\n")
    assert patch.to_dict() == {"patch": patch.patch}
    assert out.submitted_sarif is not None
    sarif = out.submitted_sarif.to_dict()["sarif"]
    assert sarif["version"] == "2.1.0"
    assert [result["level"] for result in sarif["runs"][0]["results"]] == ["error"]

    payload = json.loads(json.dumps(out.to_dict()))
    assert payload["patch_submissions"] == [{"patch": patch.patch}]
    assert payload["submitted_sarif"]["sarif"]["version"] == "2.1.0"
    assert "bundle" not in payload


def test_patches_from_run_drops_misaligned_projection() -> None:
    """A malformed projection must not produce a wrongly paired patch."""
    run = _patched_run(frames=["process_record at /src/proj/parse.c:42"])
    scan = crs_api.api._result_from_run("/bin/harness", run)
    scan.findings.clear()

    assert crs_api.patches_from_run(run, scan) == []


def test_crsrunresult_omits_optional_fields_when_no_evidence() -> None:
    detail = Task.from_dict({
        "tasks": [{"task_id": "task-1", "type": "full", "project_name": "proj"}],
    }).tasks[0]
    resolved = crs_api.ResolvedTask(detail=detail, target_binary="/bin/harness",
                                    harness_name="fuzz_parse")
    rr = _hypothesis_run()
    out = run_task(resolved, runner=lambda p, **k: rr)
    # No evidence: patch and SARIF outputs are absent.
    assert out.patch_submissions == []
    assert out.submitted_sarif is None
    d = json.loads(json.dumps(out.to_dict()))
    assert "patch_submissions" not in d
    assert "submitted_sarif" not in d
    assert "bundle" not in d

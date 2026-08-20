"""M7 #47 — AIxCC CRS-API / SARIF adapter (gap G6).

The concrete pipe that lets 0verse run on a **real external scoreboard** — the
public AIxCyberChallenge ``example-crs-architecture`` OSS-Fuzz corpus — instead of
only its own self-benchmarks, and the load-bearing **foxguard → 0verse** seam ("a
source scanner broadcasts a SARIF location, the binary engine proves it with a
PoV").

Three jobs, guided by the public AIxCC CRS-API
(``docs/api/*-swagger-v1.4.0.yaml``).
Independent implementation — no AIxCC finalist code is vendored or ported.

  1. **Task ingestion** — parse the task server's ``Task`` / ``TaskDetail`` shape
     (``full`` | ``delta``, ``project_name``, ``focus``, ``source[]`` =
     repo / fuzz-tooling / diff, ``deadline``). Delta mode surfaces the diff's
     changed files as priority target hints (the diff-scoped hunting 0verse wants).
  2. **Run 0verse** — drive the pipeline on the task's harness / fuzz-target and
     project the result into the versioned ``api.ScanResult``.
  3. **Emit CRS-API results** — ``POVSubmission`` records (base64 ``testcase`` +
     ``fuzzer_name`` + ``sanitizer``), and a ``SarifMatcher`` that confirms whether
     a 0verse finding matches a broker-supplied SARIF report. The assessment is
     **conservative (ATLANTIS policy = PoV-is-truth restated)**: a SARIF is called
     ``correct`` ONLY when a confirmed 0verse PoV's backtrace matches it.

What is *fixture-proven* here vs *live-corpus-pending* is documented precisely in
``docs/CRS-API.md``: the schema adapters, the matcher, and the PoV emit are fully
exercised; fetching+building the live OSS-Fuzz tarballs (``SourceDetail.url`` →
gzip tarball → ``oss-fuzz`` build) is the operator step the doc spells out, and the
adapter accepts a pre-built ``target_binary`` so the same code path runs locally
and against the real corpus.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import api

if TYPE_CHECKING:
    from collections.abc import Callable

    from .pipeline import RunResult


# --- CRS-API enums (verbatim from the v1.4.0 swagger) ----------------------

class TaskType(StrEnum):
    FULL = "full"
    DELTA = "delta"


class SourceType(StrEnum):
    REPO = "repo"
    FUZZ_TOOLING = "fuzz-tooling"
    DIFF = "diff"


class Architecture(StrEnum):
    X86_64 = "x86_64"


class FuzzingEngine(StrEnum):
    LIBFUZZER = "libfuzzer"


class SubmissionStatus(StrEnum):
    ACCEPTED = "accepted"
    PASSED = "passed"
    FAILED = "failed"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    ERRORED = "errored"
    INCONCLUSIVE = "inconclusive"


# --- inbound: Task / TaskDetail (task server → CRS) ------------------------

@dataclass
class SourceDetail:
    """One source tarball pointer in a task (``repo`` | ``fuzz-tooling`` | ``diff``)."""

    type: SourceType
    url: str = ""
    sha256: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SourceDetail:
        return cls(
            type=SourceType(d["type"]),
            url=str(d.get("url", "")),
            sha256=str(d.get("sha256", "")),
        )


@dataclass
class TaskDetail:
    """One challenge task. ``focus`` is the project folder inside the source
    tarball; ``project_name`` is the OSS-Fuzz project id; ``type`` selects full vs
    delta (diff-scoped) hunting."""

    task_id: str
    type: TaskType
    project_name: str
    focus: str = ""
    deadline: int = 0
    harnesses_included: bool = True
    metadata: dict[str, str] = field(default_factory=dict)
    source: list[SourceDetail] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TaskDetail:
        return cls(
            task_id=str(d["task_id"]),
            type=TaskType(d.get("type", "full")),
            project_name=str(d.get("project_name", "")),
            focus=str(d.get("focus", "")),
            deadline=int(d.get("deadline", 0)),
            harnesses_included=bool(d.get("harnesses_included", True)),
            metadata={str(k): str(v) for k, v in (d.get("metadata") or {}).items()},
            source=[SourceDetail.from_dict(s) for s in (d.get("source") or [])],
        )

    def source_of(self, kind: SourceType) -> SourceDetail | None:
        for s in self.source:
            if s.type == kind:
                return s
        return None


@dataclass
class Task:
    """The task-server message envelope: ``message_id`` + a batch of tasks."""

    message_id: str
    message_time: int = 0
    tasks: list[TaskDetail] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Task:
        return cls(
            message_id=str(d.get("message_id", "")),
            message_time=int(d.get("message_time", 0)),
            tasks=[TaskDetail.from_dict(t) for t in (d.get("tasks") or [])],
        )


# --- outbound: POVSubmission (CRS → competition) ---------------------------

@dataclass
class POVSubmission:
    """A submitted proof-of-vulnerability in the competition API shape. ``testcase``
    is the base64 crashing input (≤ 2 MiB pre-encode)."""

    testcase: str
    fuzzer_name: str
    sanitizer: str
    architecture: str = Architecture.X86_64.value
    engine: str = FuzzingEngine.LIBFUZZER.value

    def to_dict(self) -> dict[str, str]:
        return {
            "testcase": self.testcase,
            "fuzzer_name": self.fuzzer_name,
            "sanitizer": self.sanitizer,
            "architecture": self.architecture,
            "engine": self.engine,
        }

    @property
    def testcase_bytes(self) -> bytes:
        return base64.b64decode(self.testcase)

# --- outbound: Patch / submitted-SARIF payloads (CRS → competition) ----------

@dataclass(frozen=True)
class PatchSubmission:
    """The v1.4.0 ``PatchSubmission`` payload: a base64 unified diff.

    A bundle cannot be projected here because the competition assigns its
    component IDs only after accepting the PoV, patch, and SARIF submissions.
    ``CompetitionApiClient.submit_bundle`` binds those returned IDs later.
    """

    patch: str

    @classmethod
    def from_unified_diff(cls, diff: str) -> PatchSubmission:
        raw = diff.encode("utf-8")
        if not raw or len(raw) > 100 * 1024:
            raise ValueError("patch must be a non-empty unified diff of at most 100 KiB")
        if not (
            diff.startswith("diff --git ")
            or (diff.startswith("--- ") and "\n+++ " in diff)
        ):
            raise ValueError("patch must be a unified diff")
        return cls(base64.b64encode(raw).decode("ascii"))

    @property
    def patch_bytes(self) -> bytes:
        return base64.b64decode(self.patch, validate=True)

    def to_dict(self) -> dict[str, str]:
        return {"patch": self.patch}


@dataclass(frozen=True)
class SubmittedSARIF:
    """The v1.4.0 ``SARIFSubmission`` payload for confirmed findings only."""

    sarif: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"sarif": self.sarif}




# --- inbound: SARIF broadcast (broker → CRS) -------------------------------

@dataclass
class SARIFBroadcastDetail:
    """One broadcast SARIF report scoped to a task."""

    sarif_id: str
    task_id: str
    sarif: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SARIFBroadcastDetail:
        return cls(
            sarif_id=str(d.get("sarif_id", "")),
            task_id=str(d.get("task_id", "")),
            sarif=dict(d.get("sarif") or {}),
            metadata={str(k): str(v) for k, v in (d.get("metadata") or {}).items()},
        )


@dataclass
class SARIFBroadcast:
    message_id: str
    message_time: int = 0
    broadcasts: list[SARIFBroadcastDetail] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SARIFBroadcast:
        return cls(
            message_id=str(d.get("message_id", "")),
            message_time=int(d.get("message_time", 0)),
            broadcasts=[
                SARIFBroadcastDetail.from_dict(b) for b in (d.get("broadcasts") or [])
            ],
        )


# --- SARIF matcher (independent — public AIxCC CRS/SARIF matching semantics) ---

OSS_FUZZ_PREFIX = "OSS_FUZZ_"


@dataclass
class Frame:
    """One backtrace frame recovered by 0verse's oracle, parsed into the fields the
    matcher compares against a SARIF location."""

    function: str = ""
    file: str = ""           # path as recovered (may be absolute or bare basename)
    line: int | None = None

    @property
    def basename(self) -> str:
        return Path(self.file).name if self.file else ""


@dataclass
class SarifInfo:
    """One location extracted from a broadcast SARIF result."""

    function: str = ""
    file: str = ""
    start_line: int | None = None
    end_line: int | None = None
    rule_id: str = ""

    @property
    def basename(self) -> str:
        return Path(self.file).name if self.file else ""


@dataclass
class SarifMatch:
    """A frame ↔ SARIF-location match with five boolean flags, so a
    caller can see exactly why it matched."""

    sarif_info: SarifInfo
    frame: Frame
    matches_lines: bool
    matches_function: bool
    matches_filename: bool
    matches_full_path: bool
    matches_stripped_function: bool


_FRAME_PATTERNS = (
    # "func at /path/file.c:42"  /  "func /path/file.c:42"
    re.compile(r"^(?P<func>[\w:.$]+)\s+(?:at\s+)?(?P<file>[\w./\\-]+\.\w+):(?P<line>\d+)"),
    # "func (/path/file.c:42)"
    re.compile(r"^(?P<func>[\w:.$]+)\s+\((?P<file>[\w./\\-]+\.\w+):(?P<line>\d+)\)"),
    # "/path/file.c:42 in func"
    re.compile(r"^(?P<file>[\w./\\-]+\.\w+):(?P<line>\d+)\s+in\s+(?P<func>[\w:.$]+)"),
    # bare "func"
    re.compile(r"^(?P<func>[\w:.$]+)\s*$"),
)


def parse_frame(text: str) -> Frame:
    """Parse a normalized backtrace frame string into a :class:`Frame`. Tolerant of
    the several shapes 0verse's oracle / a symbolized backtrace emit; a frame with
    only a function name still yields a usable (function-only) frame."""
    s = text.strip()
    for pat in _FRAME_PATTERNS:
        m = pat.match(s)
        if m:
            gd = m.groupdict()
            line = int(gd["line"]) if gd.get("line") else None
            return Frame(function=gd.get("func", ""), file=gd.get("file", "") or "", line=line)
    return Frame()


def extract_sarif_infos(sarif: dict[str, Any]) -> list[SarifInfo]:
    """Pull every ``(function, file, line-range, ruleId)`` location out of a SARIF
    2.1.0 document. Reads ``runs[].results[].locations[]`` physical (file + region)
    and logical (function) locations."""
    out: list[SarifInfo] = []
    for run in sarif.get("runs") or []:
        for result in run.get("results") or []:
            rule_id = str(result.get("ruleId", ""))
            for loc in result.get("locations") or []:
                phys = loc.get("physicalLocation") or {}
                art = phys.get("artifactLocation") or {}
                region = phys.get("region") or {}
                file = str(art.get("uri", ""))
                start = region.get("startLine")
                end = region.get("endLine", start)
                func = ""
                for logical in loc.get("logicalLocations") or []:
                    if logical.get("kind", "function") == "function" and logical.get("name"):
                        func = str(logical["name"])
                        break
                out.append(
                    SarifInfo(
                        function=func,
                        file=file,
                        start_line=int(start) if start is not None else None,
                        end_line=int(end) if end is not None else None,
                        rule_id=rule_id,
                    )
                )
    return out


def _strip_oss_fuzz(name: str) -> str:
    return name[len(OSS_FUZZ_PREFIX):] if name.startswith(OSS_FUZZ_PREFIX) else name


def match_frame(frame: Frame, info: SarifInfo) -> SarifMatch | None:
    """Per-frame matching rule. A match needs ONE of:

      * ``matches_lines AND (matches_filename OR matches_full_path)`` — location, or
      * ``matches_function`` (exact), or
      * ``matches_stripped_function`` (after dropping an ``OSS_FUZZ_`` prefix).
    """
    matches_lines = (
        frame.line is not None
        and info.start_line is not None
        and info.start_line <= frame.line <= (info.end_line or info.start_line)
    )
    matches_function = bool(frame.function) and frame.function == info.function
    matches_filename = bool(frame.basename) and frame.basename == info.basename
    matches_full_path = bool(frame.file) and frame.file == info.file
    matches_stripped_function = (
        bool(frame.function)
        and bool(info.function)
        and _strip_oss_fuzz(frame.function) == _strip_oss_fuzz(info.function)
    )
    matched = (
        (matches_lines and (matches_filename or matches_full_path))
        or matches_function
        or matches_stripped_function
    )
    if not matched:
        return None
    return SarifMatch(
        sarif_info=info,
        frame=frame,
        matches_lines=matches_lines,
        matches_function=matches_function,
        matches_filename=matches_filename,
        matches_full_path=matches_full_path,
        matches_stripped_function=matches_stripped_function,
    )


class SarifMatcher:
    """Matches a broadcast SARIF report against a set of 0verse crash frames.
    Returns the first frame ↔ location match (first-match semantics)."""

    def match(
        self, sarif: dict[str, Any], frames: list[Frame]
    ) -> SarifMatch | None:
        infos = extract_sarif_infos(sarif)
        for info in infos:
            for frame in frames:
                hit = match_frame(frame, info)
                if hit is not None:
                    return hit
        return None


# --- assessment (conservative, PoV-is-truth) -------------------------------

@dataclass
class SarifAssessment:
    """0verse's verdict on a broadcast SARIF. ``assessment`` is ``correct`` ONLY
    when a *confirmed PoV*'s backtrace matched the SARIF location — the ATLANTIS
    conservative policy (emit "correct" only with PoV evidence). Otherwise
    ``incorrect`` here means "0verse did not independently confirm it with a PoV",
    NOT a strong refutation — the honest framing is in ``note``."""

    sarif_id: str
    task_id: str
    assessment: str             # "correct" | "incorrect"
    matched: bool
    pov_backed: bool
    note: str = ""
    match: SarifMatch | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sarif_id": self.sarif_id,
            "task_id": self.task_id,
            "assessment": self.assessment,
            "matched": self.matched,
            "pov_backed": self.pov_backed,
            "note": self.note,
            "match": _match_to_dict(self.match) if self.match else None,
        }


def _match_to_dict(m: SarifMatch) -> dict[str, Any]:
    return {
        "function": m.sarif_info.function,
        "file": m.sarif_info.file,
        "rule_id": m.sarif_info.rule_id,
        "frame": m.frame.function,
        "matches_lines": m.matches_lines,
        "matches_function": m.matches_function,
        "matches_filename": m.matches_filename,
        "matches_full_path": m.matches_full_path,
        "matches_stripped_function": m.matches_stripped_function,
    }


def assess_broadcast(
    detail: SARIFBroadcastDetail,
    frames: list[Frame],
    *,
    pov_backed: bool,
    matcher: SarifMatcher | None = None,
) -> SarifAssessment:
    """Assess one broadcast SARIF against 0verse's confirmed crash frames."""
    matcher = matcher or SarifMatcher()
    hit = matcher.match(detail.sarif, frames)
    matched = hit is not None
    correct = matched and pov_backed
    if correct:
        note = "0verse confirmed a PoV whose backtrace matches the broadcast SARIF."
    elif matched and not pov_backed:
        note = "SARIF location matched a finding, but no reproducing PoV — not asserted."
    else:
        note = "No confirmed-PoV backtrace matched the broadcast SARIF location."
    return SarifAssessment(
        sarif_id=detail.sarif_id,
        task_id=detail.task_id,
        assessment="correct" if correct else "incorrect",
        matched=matched,
        pov_backed=pov_backed,
        note=note,
        match=hit,
    )


# --- driving 0verse on a task ----------------------------------------------

@dataclass
class ResolvedTask:
    """A task ready to run: the parsed detail + the concrete fuzz-target binary to
    scan and the harness name to label POVs with. ``delta_files`` are the changed
    files (delta mode) routed as priority target hints."""

    detail: TaskDetail
    target_binary: str
    harness_name: str
    sanitizer: str = "address"
    delta_files: list[str] = field(default_factory=list)


@dataclass
class CRSRunResult:
    """Evidence-backed outbound payloads produced for one competition task.

    A competition bundle is intentionally absent: it requires component IDs
    returned by the remote API and is assembled by ``CompetitionApiClient``.
    """

    task_id: str
    scan: api.ScanResult
    pov_submissions: list[POVSubmission] = field(default_factory=list)
    sarif_assessments: list[SarifAssessment] = field(default_factory=list)
    patch_submissions: list[PatchSubmission] = field(default_factory=list)
    submitted_sarif: SubmittedSARIF | None = None

    @property
    def confirmed_count(self) -> int:
        return self.scan.confirmed_count

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "task_id": self.task_id,
            "confirmed_count": self.confirmed_count,
            "scan": self.scan.to_dict(),
            "pov_submissions": [p.to_dict() for p in self.pov_submissions],
            "sarif_assessments": [a.to_dict() for a in self.sarif_assessments],
        }
        if self.patch_submissions:
            payload["patch_submissions"] = [p.to_dict() for p in self.patch_submissions]
        if self.submitted_sarif is not None:
            payload["submitted_sarif"] = self.submitted_sarif.to_dict()
        return payload

    def scan_sarif(self) -> str:
        """The full local scan as a SARIF 2.1.0 document."""
        return api.result_to_sarif(self.scan)


def delta_files(detail: TaskDetail, diff_text: str | None = None) -> list[str]:
    """Return unique changed paths from a delta-task unified diff."""
    if detail.type != TaskType.DELTA or not diff_text:
        return []
    files: list[str] = []
    for line in diff_text.splitlines():
        if not line.startswith("+++ "):
            continue
        path = line[4:].strip()
        if path.startswith(("a/", "b/")):
            path = path[2:]
        if path and path != "/dev/null" and path not in files:
            files.append(path)
    return files
def frames_from_run(run_result: RunResult) -> list[Frame]:
    """Parse the backtrace frames of every *confirmed* PoV in a run (PoV-is-truth:
    only reproduced crashes contribute frames the matcher may assert on)."""
    out: list[Frame] = []
    for tf in run_result.findings:
        pov = tf.pov
        if pov is None or not pov.reproduced:
            continue
        for raw in pov.frames:
            out.append(parse_frame(raw))
    return out


def povs_from_run(
    run_result: RunResult,
    *,
    harness_name: str,
    sanitizer: str = "address",
    architecture: str = Architecture.X86_64.value,
    engine: str = FuzzingEngine.LIBFUZZER.value,
) -> list[POVSubmission]:
    """Project a run's confirmed PoVs into CRS-API ``POVSubmission`` records. Only
    a reproduced PoV that carries crashing input bytes is submittable — a
    hypothesis is never upgraded into a submission."""
    out: list[POVSubmission] = []
    for tf in run_result.findings:
        pov = tf.pov
        if pov is None or not pov.reproduced or not pov.input_bytes:
            continue
        out.append(
            POVSubmission(
                testcase=base64.b64encode(pov.input_bytes).decode("ascii"),
                fuzzer_name=harness_name,
                sanitizer=sanitizer,
                architecture=architecture,
                engine=engine,
            )
        )
    return out




def patches_from_run(
    run_result: RunResult,
    scan: api.ScanResult,
) -> list[PatchSubmission]:
    """Project verified source diffs for reproduced, confirmed PoVs only."""
    out: list[PatchSubmission] = []
    if len(run_result.findings) != len(scan.findings):
        return out
    for triage_finding, scan_finding in zip(run_result.findings, scan.findings, strict=True):
        pov = triage_finding.pov
        if (
            not scan_finding.confirmed
            or not scan_finding.patch_verified
            or scan_finding.patch_mode != "source-diff"
            or pov is None
            or not pov.reproduced
            or pov.patch is None
            or not pov.patch.verified
            or pov.patch.mode != "source-diff"
        ):
            continue
        try:
            out.append(PatchSubmission.from_unified_diff(pov.patch.diff))
        except ValueError:
            # A local recommendation or malformed diff is not a competition patch.
            continue
    return out


def submitted_sarif_from_run(scan: api.ScanResult) -> SubmittedSARIF:
    """Project only confirmed findings into the v1.4.0 SARIF payload."""
    confirmed = [finding for finding in scan.findings if finding.confirmed]
    if not confirmed:
        raise ValueError("cannot submit SARIF without a confirmed finding")
    confirmed_scan = replace(scan, findings=confirmed)
    return SubmittedSARIF(sarif=json.loads(api.result_to_sarif(confirmed_scan)))

def run_task(
    resolved: ResolvedTask,
    *,
    broadcast: SARIFBroadcast | None = None,
    scan_opts: api.ScanOptions | None = None,
    runner: Callable[..., RunResult] | None = None,
) -> CRSRunResult:
    """Run 0verse on a resolved task and emit the CRS-API result.

    ``runner`` is the pipeline entrypoint (defaults to ``zeroverse.pipeline.run``);
    it is injectable so a caller (or a test) can supply a pre-built ``RunResult``
    without the heavy decompile toolchain. ``broadcast`` (optional) is the SARIF the
    broker sent; each detail scoped to this task is assessed against 0verse's
    confirmed PoV frames.
    """
    run_fn = runner
    if run_fn is None:
        from .pipeline import run as _pipeline_run
        run_fn = _pipeline_run

    opts = scan_opts or api.ScanOptions()
    rr = run_fn(resolved.target_binary, bug_class=opts.bug_class)
    scan = api._result_from_run(resolved.target_binary, rr, backend=opts.backend)
    povs = povs_from_run(rr, harness_name=resolved.harness_name, sanitizer=resolved.sanitizer)

    assessments: list[SarifAssessment] = []
    if broadcast is not None:
        frames = frames_from_run(rr)
        pov_backed = any(f.confirmed for f in scan.findings)
        matcher = SarifMatcher()
        for detail in broadcast.broadcasts:
            if detail.task_id and detail.task_id != resolved.detail.task_id:
                continue
            assessments.append(
                assess_broadcast(detail, frames, pov_backed=pov_backed, matcher=matcher)
            )

    patch_subs = patches_from_run(rr, scan)
    submitted = submitted_sarif_from_run(scan) if scan.confirmed_count > 0 else None

    return CRSRunResult(
        task_id=resolved.detail.task_id,
        scan=scan,
        pov_submissions=povs,
        sarif_assessments=assessments,
        patch_submissions=patch_subs,
        submitted_sarif=submitted,
    )

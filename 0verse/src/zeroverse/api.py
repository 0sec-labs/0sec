"""Embeddable scan API + versioned machine result contract (M5 #28).

The stable, embeddable seam a scan platform (pwnkit-cloud) or an external agent
(the MCP bridge, #29) drives:

    from zeroverse import api
    result = api.scan("/path/to/binary")              # -> ScanResult
    print(api.format_result(result, "ndjson"))

and the equivalent CLI ``0verse scan <binary> --format ndjson|sarif|json``.

The contract is **versioned** (``CONTRACT_VERSION``) and deliberately *flat and
small* — a downstream platform ingests these fields, not 0verse internals. The
internal ``serialize.finding_dict`` shape stays free to evolve; this contract is
the compatibility boundary.

PoV-is-truth: ``confirmed`` is true **only** when a reproducing PoV is attached
(``pov.reproduced``). A hypothesis (no PoV) is reported with ``confirmed=false``
and ``hypothesis=true`` — it is never silently upgraded.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__
from .execution.contract import ExecutionBackend
from .pipeline import (
    RunResult,
    StageOutcome,
    StageStatus,
    TerminalState,
    TriagedFinding,
    _terminalize,
    run,
)
from .preflight import RunBudget, RunProfile
from .serialize import finding_dict

# Bump MINOR for additive (back-compatible) fields, MAJOR for removals/renames.
# v1.1: added optional ScanFinding.crash_output + .confidence (additive MINOR).
# v1.2: added the optional patch_* block (M7 #45/#46) — additive MINOR.
# v1.3: added the optional scheduler block (M7 #44) — additive MINOR.
# v1.4: added optional execution-adapter metadata and ScanOptions injection.
# v1.5: added terminal state/reason and structured per-stage outcomes.
CONTRACT_VERSION = "1.5"

TOOL = {"name": "0verse", "version": __version__}


@dataclass
class ScanOptions:
    """Knobs for an embedded scan. All optional; defaults match the CLI."""

    bug_class: str = "memory-safety"
    backend: str | None = None          # ghidra|rizin|angr|auto (None -> $ZEROVERSE_BACKEND)
    llm: str | None = None              # provider name; None/"mock" -> deterministic MockLLM
    model: str | None = None
    # LOCATE/CONFIRM split (#51): decompile+analyze read the scanned ``path`` (a clean,
    # non-ASan build that decompiles cleanly); the dynamic oracle CONFIRMS a PoV against
    # this behaviourally equivalent build (the ASan target). None -> both are ``path``.
    confirm_binary: str | None = None
    # Explicit runtime adapter. No adapter is ever inferred from the environment:
    # callers retain the authorization boundary for remote/platform execution.
    execution_backend: ExecutionBackend | None = None
    # Run-local capability/budget policy. Appended for positional compatibility.
    profile: RunProfile = "analysis"
    budget: RunBudget = field(default_factory=RunBudget)
    output_dir: str | None = None


@dataclass
class ScanFinding:
    """One finding in the versioned contract. Flat by design."""

    id: str                  # stable hash (binary, function, sink, offset, class)
    bug_class: str
    severity: str
    file: str                # the scanned binary path
    function: str
    offset: str              # sink address, hex
    source: str
    sink: str
    confirmed: bool          # PoV-is-truth: reproducing PoV attached
    hypothesis: bool         # the cheap/LLM verdict says "could be real"
    pruned: bool             # angr proved the sink unreachable
    capability: str          # oracle capability ladder rung (oob-write/crash/...)
    pov_path: str            # standalone replay script, or ""
    repro_cmd: str           # exact command to reproduce, or ""
    dedup_bucket: str        # crash-state key for dedup, or ""
    explanation: str
    # --- v1.1 additive (optional; MINOR bump, never reorder/rename the above) ---
    crash_output: str | None = None   # oracle-captured sanitizer/crash blob, or None
    confidence: float | None = None   # per-finding signal (e.g. CASR), else None
    # --- v1.2 additive (M7 patch stage; optional, MINOR) ------------------------
    patch_available: bool = False     # a patch artifact (any mode) is attached
    patch_verified: bool = False      # PoV no longer reproduces AND no regression
    patch_mode: str = "none"          # none/recommendation/source-diff/binary-micropatch
    patch_path: str | None = None     # path to the diff or patched binary, or None
    patch_recommendation: str | None = None  # located fix text, or None
    patch_regression: str | None = None      # regression-oracle result summary, or None

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class ScanStageOutcome:
    """Stable projection of one pipeline stage's outcome and provenance."""

    stage: str
    status: StageStatus
    required: bool
    reason: str = ""
    provenance: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_run(cls, outcome: StageOutcome) -> ScanStageOutcome:
        return cls(
            stage=outcome.stage,
            status=outcome.status,
            required=outcome.required,
            reason=outcome.reason,
            provenance=dict(outcome.provenance),
        )

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class ScanResult:
    """The versioned top-level contract a platform ingests."""

    contract_version: str
    tool: dict[str, str]
    binary: str
    format: str
    arch: str
    backend: str
    triage: str
    stages_run: list[str] = field(default_factory=list)
    findings: list[ScanFinding] = field(default_factory=list)
    note: str = ""
    # M7 #44: per-lane LLM budget + content-hash cache + epoch-plan stats,
    # present only when the run used the opt-in scheduler (ZEROVERSE_SCHEDULER=1).
    scheduler: dict[str, Any] | None = None
    # Versioned execution contract/backend/capability identity, when injected.
    execution: dict[str, Any] | None = None
    # v1.5 additive: append after every pre-v1.5 field so positional callers retain
    # the same argument mapping.
    terminal_state: TerminalState = "infra-failed"
    status_reason: str = "scan did not complete"
    stage_outcomes: list[ScanStageOutcome] = field(default_factory=list)

    @property
    def confirmed_count(self) -> int:
        return sum(1 for f in self.findings if f.confirmed)

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["confirmed_count"] = self.confirmed_count
        return d


def _finding_id(binary: str, function: str, sink: str, offset: str, bug_class: str) -> str:
    key = f"{binary}|{function}|{sink}|{offset}|{bug_class}".encode()
    return hashlib.sha1(key).hexdigest()[:12]


def _repro_cmd(pov_path: str) -> str:
    return f"python3 {pov_path}" if pov_path else ""


# CASR exploitability classification -> a conservative per-finding confidence.
# Only a real CASR verdict captured by the oracle sets this; with no CASR signal
# the field stays None and the cloud mapper falls back to its confirmed/
# unconfirmed default. Never fabricated -- keyed strictly on captured oracle output.
_CASR_CONFIDENCE: dict[str, float] = {
    "EXPLOITABLE": 0.95,
    "PROBABLY_EXPLOITABLE": 0.8,
    "NOT_EXPLOITABLE": 0.6,
}


def _confidence_from_pov(pov: dict[str, Any]) -> float | None:
    """A per-finding confidence from the oracle's CASR exploitability verdict, or
    None when CASR did not run (the cloud mapper then applies its default)."""
    casr = str(pov.get("casr_severity") or "").upper()
    return _CASR_CONFIDENCE.get(casr)


def _to_contract_finding(binary: str, tf: TriagedFinding) -> ScanFinding:
    d = finding_dict(tf)  # the internal shape — we project a stable subset
    pov = d.get("pov") or {}
    offset = d.get("sink_addr", "0x0")
    bug_class = d.get("bug_class") or "unknown"
    function = d.get("function") or ""
    sink = d.get("sink") or ""
    pov_path = pov.get("pov_script") or ""
    # v1.1: surface the oracle's real captured crash blob (``pov.evidence`` is the
    # PoV's crash_trace) + an optional CASR-derived confidence. Never fabricated.
    crash_output = pov.get("evidence") or None
    confidence = _confidence_from_pov(pov)
    # v1.2: project the patch block. ``patch_path`` is the patched binary (binary
    # mode) or the diff path (source mode); ``patch_recommendation`` is the located
    # fix text (always set in binary/recommendation mode). Honest: a fix is marked
    # ``patch_verified`` only when the oracle re-ran the PoV and it no longer
    # reproduced (mirrors confirmed/severity discipline) — never fabricated.
    patch = pov.get("patch") or {}
    patch_mode = str(patch.get("mode", "none")) if patch else "none"
    patch_verified = bool(patch.get("verified"))
    patch_path = (patch.get("patched_artifact") or None) if patch else None
    patch_recommendation = (patch.get("recommendation") or None) if patch else None
    patch_regression = (patch.get("regression") or None) if patch else None
    return ScanFinding(
        id=_finding_id(binary, function, sink, offset, bug_class),
        bug_class=bug_class,
        severity=d.get("severity") or "unknown",
        file=binary,
        function=function,
        offset=offset,
        source=d.get("source") or "",
        sink=sink,
        confirmed=bool(d.get("confirmed")),
        hypothesis=bool(d.get("hypothesis")),
        pruned=bool(d.get("pruned")),
        capability=pov.get("capability") or "",
        pov_path=pov_path,
        repro_cmd=_repro_cmd(pov_path),
        dedup_bucket=pov.get("dedup_bucket") or "",
        explanation=d.get("explanation") or "",
        crash_output=crash_output,
        confidence=confidence,
        patch_available=bool(patch),
        patch_verified=patch_verified,
        patch_mode=patch_mode,
        patch_path=patch_path,
        patch_recommendation=patch_recommendation,
        patch_regression=patch_regression,
    )


def _result_from_run(binary: str, rr: RunResult, backend: str | None = None) -> ScanResult:
    # ``run`` already terminalizes normal results. Reconcile synthetic/legacy
    # RunResults too so a public result can never disagree with PoV truth.
    _terminalize(rr)
    return ScanResult(
        contract_version=CONTRACT_VERSION,
        tool=dict(TOOL),
        binary=binary,
        format=rr.triage.fmt,
        arch=rr.triage.arch,
        backend=backend or os.environ.get("ZEROVERSE_BACKEND", "auto"),
        triage=rr.triage.summary(),
        stages_run=list(rr.stages_run),
        findings=[_to_contract_finding(binary, tf) for tf in rr.findings],
        note=rr.note,
        terminal_state=rr.terminal_state,
        status_reason=rr.status_reason,
        stage_outcomes=[ScanStageOutcome.from_run(outcome) for outcome in rr.stage_outcomes],
        scheduler=rr.scheduler,
        execution=rr.execution,
    )


def scan(path: str | Path, opts: ScanOptions | None = None) -> ScanResult:
    """Decompile + analyze ``path`` and return the versioned ``ScanResult``.

    The single embeddable entrypoint. ``opts.backend`` is threaded explicitly
    through the pipeline to the backend registry; the process environment is never
    mutated, so concurrent embedded scans can select different backends safely.
    """
    opts = opts or ScanOptions()
    binary = str(path)

    llm = None
    if (opts.llm and opts.llm not in ("mock",)) or opts.model:
        from .llm.providers import build_llm
        prov = None if opts.llm in ("mock", "auto", None) else opts.llm
        llm = build_llm(provider=prov, model=opts.model)

    requested = opts.backend or os.environ.get("ZEROVERSE_BACKEND", "auto")
    run_options: dict[str, Any] = {
        "bug_class": opts.bug_class,
        "llm": llm,
        "confirm_binary": opts.confirm_binary,
        "profile": opts.profile,
        "budget": opts.budget,
        "output_dir": opts.output_dir,
    }
    if opts.backend is not None:
        run_options["backend"] = opts.backend
    if opts.execution_backend is not None:
        run_options["execution_backend"] = opts.execution_backend
    rr = run(binary, **run_options)
    _maybe_capture(rr, binary, requested)
    return _result_from_run(binary, rr, backend=requested)


def _maybe_capture(rr: RunResult, binary: str, backend: str) -> None:
    """M6 capture side-channels, opt-in and best-effort: when the env points a path
    at them, append a labeled-PoV dataset record per finding (#32) and/or a
    negative-results record for a run that confirmed nothing (#34). Capture never
    breaks a scan — it is wrapped so an emitter error degrades to a no-op.

    The OSS ships only the *mechanism*: a private corpus lands wherever the operator
    points ``ZEROVERSE_DATASET_PATH`` (gitignored), never in this repo."""
    ds_path = os.environ.get("ZEROVERSE_DATASET_PATH")
    neg_path = os.environ.get("ZEROVERSE_NEGATIVE_LOG")
    evaluation = os.environ.get("ZEROVERSE_EVALUATION", "").strip().lower() not in (
        "", "0", "false", "no"
    )
    # Evaluation may read a frozen dataset for priming, but must never append the
    # current case back into it: that would leak outcomes across held-out cases.
    if ds_path and not evaluation:
        try:
            from . import dataset
            dataset.emit_run(rr, ds_path, binary=binary, backend=backend)
        except Exception:
            pass
    if neg_path:
        try:
            from . import negative
            negative.emit_run(rr, neg_path, binary=binary, backend=backend)
        except Exception:
            pass
    # 0research learning seam: keep the mutable production-learning ledger
    # separate from the immutable recall/evaluation corpus. The flywheel admits
    # only replayable confirmed PoVs and deterministic refutations; unresolved
    # hypotheses never become durable memory. Best-effort like the older capture
    # side channels so storage trouble cannot change a scan verdict.
    try:
        from . import flywheel
        flywheel.remember_completed_run(
            rr, binary=binary, backend=backend
        )
    except Exception:
        pass


# --- serializers (the wire formats the CLI/platform consume) ---------------

def result_to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def result_to_ndjson(result: ScanResult) -> str:
    """One finding per line — the streaming ingestion contract. The first line is a
    ``{"_meta": ...}`` header carrying the contract version + run context so a
    consumer can validate compatibility before the findings stream."""
    header = {
        "_meta": {
            "contract_version": result.contract_version,
            "tool": result.tool,
            "binary": result.binary,
            "format": result.format,
            "arch": result.arch,
            "backend": result.backend,
            "stages_run": result.stages_run,
            "confirmed_count": result.confirmed_count,
            "note": result.note,
            "terminal_state": result.terminal_state,
            "status_reason": result.status_reason,
            "stage_outcomes": [outcome.to_dict() for outcome in result.stage_outcomes],
            "execution": result.execution,
        }
    }
    lines = [json.dumps(header)]
    lines += [json.dumps(f.to_dict()) for f in result.findings]
    return "\n".join(lines)


def result_to_sarif(result: ScanResult) -> str:
    """SARIF 2.1.0 from the contract. ``confirmed`` -> ``error``, hypothesis ->
    ``warning`` (PoV-is-truth carried into the static-analysis ecosystem)."""
    results = []
    for f in result.findings:
        results.append({
            "ruleId": f.bug_class,
            "level": "error" if f.confirmed else "warning",
            "message": {"text": f"{f.source} -> {f.sink} in {f.function} ({f.severity})"},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": result.binary}},
                "logicalLocations": [{"name": f.function, "kind": "function"}],
            }],
            "properties": f.to_dict(),
        })
    return json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "0verse",
                "informationUri": "https://github.com/0sec-labs/0verse",
                "version": __version__,
                "properties": {"contract_version": result.contract_version},
            }},
            "results": results,
            "properties": {
                "terminal_state": result.terminal_state,
                "status_reason": result.status_reason,
                "stage_outcomes": [outcome.to_dict() for outcome in result.stage_outcomes],
            },
        }],
    }, indent=2)


FORMATS = {
    "json": result_to_json,
    "ndjson": result_to_ndjson,
    "sarif": result_to_sarif,
}


def format_result(result: ScanResult, fmt: str) -> str:
    return FORMATS[fmt](result)

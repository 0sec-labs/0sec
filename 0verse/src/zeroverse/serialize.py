"""Stage 8 — report serialization for a pipeline RunResult.

Emits the findings (with embedded PoV) as JSON, NDJSON (one finding per line, the
headless streaming contract), SARIF 2.1.0 (for CI / code-scanning ingestion), or
markdown. Two tiers stay schema-separated (guidance §#8): a confirmed PoV maps to
SARIF ``level: error``; an unconfirmed hypothesis to ``warning``. An angr-pruned
hypothesis is recorded as rejected, never as a finding."""

from __future__ import annotations

import json
from typing import Any

from .pipeline import RunResult, TriagedFinding

_TOOL = {
    "driver": {
        "name": "0verse",
        "informationUri": "https://github.com/0sec-labs/0verse",
        "version": "0.0.1",
    }
}


def _confirmed(tf: TriagedFinding) -> bool:
    return bool(tf.pov and tf.pov.reproduced)


def _pruned(tf: TriagedFinding) -> bool:
    return bool(tf.angr and tf.angr.pruned)


def _status(tf: TriagedFinding) -> str:
    if _confirmed(tf):
        return "✅ CONFIRMED"
    if _pruned(tf):
        return "✂️ pruned (angr UNSAT)"
    return "⚠️ hypothesis" if tf.verdict.is_real else "ⓘ filtered"


def finding_dict(tf: TriagedFinding) -> dict[str, Any]:
    f, v = tf.finding, tf.verdict
    d: dict[str, Any] = {
        "source": f.source,
        "sink": f.sink,
        "function": f.function,
        "origin": f.origin,
        "source_addr": hex(f.source_addr),
        "sink_addr": hex(f.sink_addr),
        "bug_class": v.bug_class,
        "severity": v.severity,
        "confirmed": _confirmed(tf),
        "hypothesis": v.is_real,
        "pruned": _pruned(tf),
        "rank_score": round(tf.score, 3),
        "escalated": tf.escalated,
        "explanation": v.explanation,
    }
    if tf.grounding is not None:
        # G1 structural-grounding evidence (opt-in): per-premise verdicts + the
        # real facts to re-prompt the LLM with. Surfaced honestly, like pruned.
        d["grounding"] = tf.grounding
    if getattr(tf, "novelty", None) is not None:
        # CVE-KB novelty gate: KNOWN-CVE(ids) re-discovery or NO-PUBLIC-RECORD.
        # Present only when a KB mirror was configured for the run. Never "novel".
        d["novelty"] = tf.novelty
    if tf.angr is not None:
        a = tf.angr
        d["angr"] = {
            "outcome": a.outcome,
            "note": a.note,
            "control_hijack": a.control_hijack,
            "elapsed_s": round(a.elapsed_s, 2),
        }
    if tf.pov:
        p = tf.pov
        d["pov"] = {
            "reproduced": p.reproduced,
            "crash_class": p.crash_class,
            "capability": p.capability,
            "casr_severity": p.casr_severity,
            "casr_desc": p.casr_desc,
            "diff_allocator": p.diff_allocator,
            "dedup_bucket": p.dedup_bucket,
            "suspected_known": p.suspected_known,
            "frames": p.frames,
            "env": p.env,
            "argv": p.argv,
            "input_bytes": p.input_bytes.hex() if p.input_bytes else None,
            "pov_script": p.pov_script,
            "evidence": p.crash_trace,
        }
        if p.patch is not None:
            pt = p.patch
            d["pov"]["patch"] = {
                "mode": pt.mode,
                "verified": pt.verified,
                "recommendation": pt.recommendation,
                "locator": pt.locator,
                "diff": pt.diff,
                "patched_artifact": pt.patched_artifact,
                "regression": pt.regression,
                "pov_recheck": pt.pov_recheck,
                "method": pt.method,
                "rejected_reason": pt.rejected_reason,
                "attempts": pt.attempts,
            }
    return d


def to_json(result: RunResult) -> str:
    return json.dumps(
        {
            "binary": result.triage.path,
            "triage": result.triage.summary(),
            "stages_run": result.stages_run,
            "findings": [finding_dict(tf) for tf in result.findings],
        },
        indent=2,
    )


def to_ndjson(result: RunResult) -> str:
    return "\n".join(json.dumps(finding_dict(tf)) for tf in result.findings)


def to_sarif(result: RunResult) -> str:
    results = []
    for tf in result.findings:
        f, v = tf.finding, tf.verdict
        results.append({
            "ruleId": v.bug_class or "unknown",
            "level": "error" if _confirmed(tf) else "warning",
            "message": {"text": f"{f.source} -> {f.sink} in {f.function} ({v.severity})"},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": result.triage.path}},
                "logicalLocations": [{"name": f.function, "kind": "function"}],
            }],
            "properties": finding_dict(tf),
        })
    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": _TOOL, "results": results}],
        },
        indent=2,
    )


def to_markdown(result: RunResult) -> str:
    lines = [f"# 0verse report — `{result.triage.path}`", "", result.triage.summary(), ""]
    if not result.findings:
        lines.append("_No findings._")
        return "\n".join(lines)
    for tf in result.findings:
        f, v = tf.finding, tf.verdict
        status = _status(tf)
        lines += [
            f"## {status}: {f.source} → {f.sink}  ({v.bug_class})",
            f"- function `{f.function}`, sink at `{hex(f.sink_addr)}`, severity "
            f"**{v.severity}** · origin `{f.origin}` · rank {tf.score:.2f}"
            + ("" if tf.escalated else " (cheap-ranked, not LLM-escalated)"),
        ]
        if tf.angr is not None:
            a = tf.angr
            lines.append(f"- angr: **{a.outcome}** — {a.note} ({a.elapsed_s:.1f}s)")
        if tf.pov and tf.pov.reproduced:
            p = tf.pov
            trig = p.env or {"stdin": f"{len(p.input_bytes or b'')} bytes"}
            cap = p.capability or "crash"
            lines.append(f"- PoV ({p.crash_class}, capability **{cap}**): `{trig}`")
            if p.casr_severity:
                lines.append(f"- CASR: **{p.casr_severity}** — {p.casr_desc}")
            if p.diff_allocator:
                lines.append(f"- differential-allocator: {p.diff_allocator}")
            if p.suspected_known:
                lines.append(f"- suspected-known (not dismissed): {', '.join(p.suspected_known)}")
            if p.pov_script:
                lines.append(f"- replay: `python3 {p.pov_script}`")
            lines.append(f"- evidence: `{p.crash_trace[:200]}`")
        lines.append("")
    return "\n".join(lines)


FORMATS = {"json": to_json, "sarif": to_sarif, "ndjson": to_ndjson, "md": to_markdown}

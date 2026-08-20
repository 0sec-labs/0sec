"""Engine-side cloud sink — stream 0verse findings to the 0cloud orchestrator.

The binary-scan lane's engine half of ``0verse scan --cloud``. The cloud half
(``POST /scans/:id/findings``) is already built + flag-gated server-side; this
module is the producer that drives it.

It mirrors the canonical TypeScript cloud-sink (``@pwnkit/core`` ``cloud-sink.ts``)
and the ``mapOversePoVToCloudFinding`` mapper:

  * the SAME ``PWNKIT_CLOUD_*`` env contract pwnkit-cli reads,
  * the SAME two POST shapes — ``{"finding": <CloudSinkFinding>}`` per finding and
    ``{"report": <ScanReport>, "final": true}`` on completion (the completion
    marker), to ``<sink>/scans/<scanId>/findings``,
  * the SAME ``CloudSinkFinding`` wire shape the orchestrator's zod schema
    (``cloudSinkFindingSchema``) validates.

PoV-is-truth is load-bearing here exactly as in the TS mapper: a finding's
``severity`` is honored ONLY when it carries a reproducing PoV (``confirmed``);
an unconfirmed finding is FORCED to ``"info"`` and never silently promoted.

Robustness posture (mirrors the TS sink + the runner contract):
  * per-finding POST failures are logged and swallowed — a flaky sink never
    crashes a scan,
  * BUT the process exits NON-ZERO when it cannot post the FINAL report, so the
    worker-controller runner marks the scan failed. A clean run that posted the
    final report exits 0.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from .api import ScanFinding, ScanOptions, ScanResult
from .api import scan as api_scan

# Bumped independently of the result contract — it identifies the wire envelope,
# mirroring the TS sink's ``x-cloud-sink-version`` header.
CLOUD_SINK_VERSION = "1"

_VALID_SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

# Default per-finding confidences when the PoV carries none (mirrors the TS mapper).
_CONFIRMED_CONFIDENCE = 0.92
_UNCONFIRMED_CONFIDENCE = 0.1


# --- configuration ---------------------------------------------------------

@dataclass
class CloudSinkConfig:
    """Resolved sink target. ``token`` comes from the environment ONLY (never argv)."""

    sink_url: str
    scan_id: str
    token: str | None = None
    org_id: str | None = None
    timeout_ms: int = 30_000
    events: bool = True  # PWNKIT_CLOUD_EVENTS — stream per-finding POSTs live


def build_config(
    *, sink: str | None = None, scan_id: str | None = None, timeout_ms: int = 30_000
) -> CloudSinkConfig | None:
    """Resolve the sink config from env + CLI flags.

    Env takes precedence over the matching flag (the ``PWNKIT_CLOUD_*`` contract is
    env-driven, same as pwnkit-cli). The bearer ``token`` is read from the
    environment ONLY — it is never accepted on the command line. Returns ``None``
    when no sink URL or scan id is resolvable (the caller treats that as a usage
    error in ``--cloud`` mode).
    """
    sink_url = (os.environ.get("PWNKIT_CLOUD_SINK") or sink or "").strip()
    sid = (os.environ.get("PWNKIT_CLOUD_SCAN_ID") or scan_id or "").strip()
    if not sink_url or not sid:
        return None
    token = (os.environ.get("PWNKIT_CLOUD_TOKEN") or "").strip() or None
    org_id = (os.environ.get("PWNKIT_CLOUD_ORG_ID") or "").strip() or None
    events = os.environ.get("PWNKIT_CLOUD_EVENTS", "1").strip() != "0"
    return CloudSinkConfig(
        sink_url=sink_url, scan_id=sid, token=token, org_id=org_id,
        timeout_ms=timeout_ms, events=events,
    )


# --- OversePoV → CloudSinkFinding mapper -----------------------------------

@dataclass
class OversePoV:
    """The engine's per-finding PoV record — the mapper's input.

    Built from an ``api.ScanFinding`` (plus the scanned target) by
    ``pov_from_scan_finding``. Field names mirror the canonical TS ``OversePoV``
    so ``map_pov_to_finding`` is a faithful port of ``mapOversePoVToCloudFinding``.
    """

    id: str
    bug_class: str
    severity: str
    title: str
    description: str
    target: str
    confirmed: bool
    repro_cmd: str = ""
    pov_path: str = ""
    crash_output: str = ""
    capability: str = ""
    confidence: float | None = None
    timestamp_ms: int | None = None
    # M7 #45/#46 — the fix half (projected from the v1.2 contract patch_* fields).
    patch_mode: str = "none"
    patch_verified: bool = False
    patch_path: str | None = None
    patch_recommendation: str | None = None
    patch_regression: str | None = None


def _now_ms() -> int:
    return int(time.time() * 1000)


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def _normalize_severity(value: str) -> str:
    """Coerce an arbitrary severity onto the CloudSinkSeverity enum (mirrors the
    TS ``normalizeSeverity``). Unknown/empty -> ``info``."""
    low = value.lower().strip()
    if low in _VALID_SEVERITIES:
        return low
    if low in ("informational", "information", "none", "unknown", ""):
        return "info"
    if low in ("warn", "warning", "moderate"):
        return "medium"
    if low == "severe":
        return "high"
    return "info"


def _analysis_text(pov: OversePoV) -> str:
    """``evidence.analysis`` = confirmation verdict + artifact pointers."""
    if pov.confirmed:
        cap = pov.capability or "crash"
        parts = [f"PoV reproduced (capability={cap})."]
        ptrs = []
        if pov.pov_path:
            ptrs.append(f"pov={pov.pov_path}")
        if pov.repro_cmd:
            ptrs.append(f"repro={pov.repro_cmd}")
        if ptrs:
            parts.append("artifacts: " + ", ".join(ptrs))
        return " ".join(parts)
    return (
        "Unconfirmed hypothesis — no reproducing PoV; severity forced to "
        "'info' (PoV-is-truth)."
    )


_PATCH_POC_KIND = {
    "binary-micropatch": "binary-patch",
    "source-diff": "source-patch",
    "recommendation": "fix-recommendation",
}


def _remediation(pov: OversePoV) -> dict[str, Any] | None:
    """The M7 ``evidence.remediation`` block. Discipline mirrors PoV-is-truth: a
    *verified* fix is presented as such ONLY when ``patch_verified``; otherwise it
    is surfaced as a SUGGESTED remediation, never as "fixed". Returns None when no
    patch artifact exists."""
    has_patch = pov.patch_mode not in ("", "none") and bool(
        pov.patch_recommendation or pov.patch_path
    )
    if not has_patch:
        return None
    if pov.patch_verified:
        return {
            "status": "verified",
            "mode": pov.patch_mode,
            "verified": True,
            "fix": pov.patch_path or pov.patch_recommendation or "",
            "locator": pov.patch_recommendation or "",
            "regression": pov.patch_regression or "",
            "note": "fix verified — the confirmed PoV no longer reproduces and no "
                    "regression observed (patch-is-truth).",
        }
    return {
        "status": "suggested",
        "mode": pov.patch_mode,
        "verified": False,
        "fix": pov.patch_recommendation or "",
        "locator": pov.patch_recommendation or "",
        "regression": pov.patch_regression or "",
        "note": "suggested remediation — NOT verified (no re-run-proven fix); "
                "presented as guidance, never as fixed.",
    }


def map_pov_to_finding(pov: OversePoV) -> dict[str, Any]:
    """Port of the canonical TS ``mapOversePoVToCloudFinding``.

    PoV-is-truth: ``severity`` is honored ONLY when ``confirmed``; an unconfirmed
    finding is forced to ``"info"``. ``confidence`` defaults to 0.92 (confirmed) /
    0.1 (unconfirmed) and a PoV-supplied confidence is clamped to [0, 1].

    M7: when a patch exists it is carried as an ``evidence.remediation`` block and a
    patch ``pocSteps`` entry; the VERIFIED fix is presented only when
    ``patch_verified`` (mirrors severity-only-when-confirmed).
    """
    confirmed = bool(pov.confirmed)
    severity = _normalize_severity(pov.severity) if confirmed else "info"
    status = "confirmed" if confirmed else "unconfirmed"
    if pov.confidence is not None:
        confidence = _clamp01(float(pov.confidence))
    else:
        confidence = _CONFIRMED_CONFIDENCE if confirmed else _UNCONFIRMED_CONFIDENCE
    timestamp = pov.timestamp_ms if pov.timestamp_ms is not None else _now_ms()
    evidence: dict[str, Any] = {
        "request": f"target: {pov.target}\nrepro: {pov.repro_cmd}",
        "response": pov.crash_output,
        "analysis": _analysis_text(pov),
    }
    remediation = _remediation(pov)
    if remediation is not None:
        evidence["remediation"] = remediation
    poc_steps: list[dict[str, Any]] = [
        {
            "kind": "binary-pov",
            "artifact": pov.pov_path,
            "command": pov.repro_cmd,
            "confirmed": confirmed,
        }
    ]
    if remediation is not None:
        poc_steps.append({
            "kind": _PATCH_POC_KIND.get(pov.patch_mode, "fix-recommendation"),
            "artifact": pov.patch_path or "",
            "verified": pov.patch_verified,
        })
    return {
        "id": pov.id,
        "templateId": f"0verse-binary:{pov.bug_class}",
        "title": pov.title,
        "description": pov.description,
        "severity": severity,
        "category": pov.bug_class,
        "status": status,
        "evidence": evidence,
        "timestamp": timestamp,
        "confidence": confidence,
        "pocSteps": poc_steps,
    }


def pov_from_scan_finding(f: ScanFinding, target: str) -> OversePoV:
    """Project an ``api.ScanFinding`` (the locked v1.0 result contract) onto an
    ``OversePoV``. ``target`` is the scanned binary (``ScanResult.binary``).

    Since contract v1.1 the ``ScanFinding`` surfaces the oracle's captured crash
    blob (``crash_output``) and an optional per-finding ``confidence``, so both are
    carried straight through to ``evidence.response`` / the mapped confidence.
    """
    if f.source and f.sink:
        title = f"{f.bug_class}: {f.source} -> {f.sink} in {f.function}"
    elif f.function:
        title = f"{f.bug_class} in {f.function}"
    else:
        title = f.bug_class
    return OversePoV(
        id=f.id,
        bug_class=f.bug_class,
        severity=f.severity,
        title=title,
        description=f.explanation or title,
        target=target,
        confirmed=f.confirmed,
        repro_cmd=f.repro_cmd,
        pov_path=f.pov_path,
        crash_output=f.crash_output or "",
        capability=f.capability,
        confidence=f.confidence,
        patch_mode=f.patch_mode,
        patch_verified=f.patch_verified,
        patch_path=f.patch_path,
        patch_recommendation=f.patch_recommendation,
        patch_regression=f.patch_regression,
    )


# --- ScanReport (final report) ---------------------------------------------

def build_scan_report(
    result: ScanResult,
    cloud_findings: list[dict[str, Any]],
    started: datetime,
    completed: datetime,
) -> dict[str, Any]:
    """Assemble the final ``ScanReport`` posted with ``final: true``.

    Severity counts are taken from the MAPPED cloud findings, so PoV-is-truth is
    reflected in the summary (unconfirmed findings count as ``info``).
    """
    sev_counts = dict.fromkeys(_VALID_SEVERITIES, 0)
    for cf in cloud_findings:
        sev = cf.get("severity", "info")
        sev_counts[sev if sev in sev_counts else "info"] += 1
    summary = {
        "totalAttacks": len(result.findings),
        "totalFindings": len(cloud_findings),
        "critical": sev_counts["critical"],
        "high": sev_counts["high"],
        "medium": sev_counts["medium"],
        "low": sev_counts["low"],
        "info": sev_counts["info"],
    }
    warnings: list[dict[str, str]] = []
    if result.note:
        warnings.append({"stage": "scan", "message": result.note})
    successful = result.terminal_state in {"confirmed", "no-findings"}
    if not successful:
        warnings.append(
            {
                "stage": "terminal",
                "message": f"{result.terminal_state}: {result.status_reason}",
            }
        )
    report = {
        "target": result.binary,
        "scanDepth": "deep",
        "startedAt": started.isoformat(),
        "completedAt": completed.isoformat(),
        "durationMs": int((completed - started).total_seconds() * 1000),
        "summary": summary,
        "findings": cloud_findings,
        "warnings": warnings,
    }
    if successful:
        report["exitReason"] = "completed"
    return report


# --- HTTP transport (retry/backoff, Bearer, JSON) --------------------------

_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


def _log(msg: str) -> None:
    sys.stderr.write(f"[0verse cloud-sink] {msg}\n")


def _headers(config: CloudSinkConfig) -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "X-Pwnkit-Scan-Id": config.scan_id,
        "x-cloud-sink-version": CLOUD_SINK_VERSION,
    }
    if config.token:
        headers["Authorization"] = f"Bearer {config.token}"
    if config.org_id:
        headers["X-Pwnkit-Org-Id"] = config.org_id
    return headers


def post_json(
    url: str,
    body: dict[str, Any],
    config: CloudSinkConfig,
    *,
    kind: str,
    retries: int = 4,
    backoff_base: float = 0.5,
) -> bool:
    """POST ``body`` as JSON with Bearer auth. Retries on 429/5xx/timeout/connection
    error with exponential backoff. Returns ``True`` on a 2xx, ``False`` otherwise.
    Never raises — a transport failure is a ``False`` return, not an exception.
    """
    data = json.dumps(body).encode("utf-8")
    headers = _headers(config)
    timeout_s = max(0.1, config.timeout_ms / 1000)
    last_detail = ""
    for attempt in range(retries + 1):
        retryable = False
        try:
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                status = getattr(resp, "status", 200)
            if 200 <= status < 300:
                return True
            last_detail = f"HTTP {status}"
            retryable = status in _RETRYABLE_STATUS
        except urllib.error.HTTPError as e:
            last_detail = f"HTTP {e.code}"
            retryable = e.code in _RETRYABLE_STATUS
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_detail = f"{type(e).__name__}: {e}"
            retryable = True
        if not retryable or attempt == retries:
            break
        time.sleep(backoff_base * (2**attempt))
    _log(f"{kind} POST {url} failed ({last_detail})")
    return False


def post_finding(finding: dict[str, Any], config: CloudSinkConfig) -> bool:
    url = f"{config.sink_url.rstrip('/')}/scans/{quote(config.scan_id)}/findings"
    return post_json(url, {"finding": finding}, config, kind="finding")


def post_final_report(report: dict[str, Any], config: CloudSinkConfig) -> bool:
    """Post the successful completion marker accepted by the orchestrator."""
    url = f"{config.sink_url.rstrip('/')}/scans/{quote(config.scan_id)}/findings"
    return post_json(url, {"report": report, "final": True}, config, kind="report")


# --- orchestration ---------------------------------------------------------

def stream_result(result: ScanResult, config: CloudSinkConfig, started: datetime,
                  completed: datetime) -> int:
    """Map + stream a finished ``ScanResult`` to the orchestrator.

    Per-finding POST errors are logged and swallowed (a flaky sink must not crash
    the scan). Successful terminal states post ``final: true`` and return 0. The
    current orchestrator accepts no non-completing report envelope, so failed states
    log their terminal diagnostic and return 1 without posting a report; worker
    failure handling remains authoritative.
    """
    cloud_findings: list[dict[str, Any]] = []
    for f in result.findings:
        cf = map_pov_to_finding(pov_from_scan_finding(f, result.binary))
        cloud_findings.append(cf)
        if config.events and not post_finding(cf, config):
            _log(f"per-finding POST failed for {cf['id']} — continuing")
    successful = result.terminal_state in {"confirmed", "no-findings"}
    if not successful:
        _log(f"scan ended {result.terminal_state}: {result.status_reason}")
        _log("no completion report posted — exiting non-zero")
        return 1
    report = build_scan_report(result, cloud_findings, started, completed)
    if not post_final_report(report, config):
        _log("FINAL report POST failed — exiting non-zero so the run is marked failed")
        return 1
    return 0


def run_cloud_scan(target: str, config: CloudSinkConfig, *, opts: ScanOptions) -> int:
    """Run the normal pipeline on ``target`` then stream to the orchestrator.

    Returns the process exit code: 0 only for a posted ``confirmed`` or
    ``no-findings`` final report.
    """
    started = datetime.now(UTC)
    result = api_scan(target, opts)
    completed = datetime.now(UTC)
    return stream_result(result, config, started, completed)

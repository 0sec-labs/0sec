"""Negative-results capture (M6 #34) — the auditable honesty record.

PoV-is-truth cuts both ways: a run that confirms *nothing* is still a result, and
recording it is what keeps the project honest. This module emits a structured
record for every **negative** run (zero confirmed PoVs) — clean scans, all-pruned
hypotheses, and honest static-only degrades alike — so the log is not just a
highlight reel of findings.

The human-curated companion is ``NEGATIVE-RESULTS.md`` (the seeded residuals from
M1-M5: Mach-O needs a Mac, rizin is lower-fidelity, the logic class is
hypothesis-only, angr reachability is disabled on the fallback backends). This
module is the machine half: append-only NDJSON, one record per negative run.

A run is **negative** iff it produced no finding with a reproducing PoV. The
``reason`` classifies *why* nothing confirmed, from the run's own evidence.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .pipeline import RunResult
from .serialize import finding_dict

# Bump MINOR for additive fields, MAJOR for removals/renames.
NEGATIVE_LOG_VERSION = "1.0"

_TOOL = {"name": "0verse", "version": __version__}

# Why a run confirmed nothing — a small, stable vocabulary.
REASONS = (
    "unsupported-format",     # ingest could not route the container
    "no-backend",             # no decompiler backend available on this host
    "no-candidates",          # pipeline ran, slice/lens found no hypothesis
    "static-only-degrade",    # host cannot run/emulate the target — hypotheses only
    "all-pruned",             # every hypothesis was proven unreachable (angr UNSAT)
    "unconfirmed-hypotheses", # leads surfaced, none reproduced a PoV
)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


@dataclass
class NegativeRecord:
    """One negative run. Flat, versioned, append-only."""

    log_version: str
    created_at: str
    tool: dict[str, str]
    binary_name: str
    backend: str
    fmt: str
    arch: str
    reason: str
    detail: str
    stages_run: list[str]
    n_hypotheses: int
    n_pruned: int
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "log_version": self.log_version,
            "created_at": self.created_at,
            "tool": dict(self.tool),
            "binary_name": self.binary_name,
            "backend": self.backend,
            "format": self.fmt,
            "arch": self.arch,
            "reason": self.reason,
            "detail": self.detail,
            "stages_run": list(self.stages_run),
            "counts": {"hypotheses": self.n_hypotheses, "pruned": self.n_pruned},
            "note": self.note,
        }


def _counts(run_result: RunResult) -> tuple[int, int, int]:
    """Return (confirmed, hypotheses, pruned) over the run's findings."""
    confirmed = hyp = pruned = 0
    for tf in run_result.findings:
        fd = finding_dict(tf)
        if fd.get("confirmed"):
            confirmed += 1
        elif fd.get("pruned"):
            pruned += 1
        else:
            hyp += 1
    return confirmed, hyp, pruned


def classify(run_result: RunResult) -> tuple[str, str] | None:
    """Classify a run as negative, returning ``(reason, detail)``.

    Returns ``None`` when the run confirmed at least one PoV (i.e. it is *not* a
    negative result and belongs in the dataset, not here)."""
    confirmed, hyp, pruned = _counts(run_result)
    if confirmed:
        return None

    note = run_result.note or ""
    stages = run_result.stages_run
    if "decompile" not in stages:
        # The pipeline stopped before decompiling: unsupported format or no backend.
        if run_result.triage.fmt not in ("ELF", "PE", "Mach-O"):
            return "unsupported-format", f"{run_result.triage.fmt}: decompile pipeline not wired"
        return "no-backend", "no decompiler backend available on this host"

    if pruned and not hyp:
        return "all-pruned", f"{pruned} hypothesis(es) proven unreachable (angr UNSAT)"
    if "static-only" in note or "remain hypotheses" in note or (
        "dynamic" not in stages and (hyp or pruned)
    ):
        return "static-only-degrade", "host cannot run/emulate the target — hypotheses only"
    if hyp or pruned:
        return "unconfirmed-hypotheses", f"{hyp} lead(s) surfaced, none reproduced a PoV"
    return "no-candidates", "slice + lenses found no hypothesis"


def record_from_run(
    run_result: RunResult,
    *,
    binary: str | Path,
    backend: str,
    now: Callable[[], str] = _utc_now,
) -> NegativeRecord | None:
    """Build a ``NegativeRecord`` for a negative run, or ``None`` if it confirmed
    a PoV (positives are dataset rows, not negative-log rows)."""
    cls = classify(run_result)
    if cls is None:
        return None
    reason, detail = cls
    _, hyp, pruned = _counts(run_result)
    return NegativeRecord(
        log_version=NEGATIVE_LOG_VERSION,
        created_at=now(),
        tool=dict(_TOOL),
        binary_name=Path(str(binary)).name,
        backend=backend,
        fmt=run_result.triage.fmt,
        arch=run_result.triage.arch,
        reason=reason,
        detail=detail,
        stages_run=list(run_result.stages_run),
        n_hypotheses=hyp,
        n_pruned=pruned,
        note=run_result.note,
    )


def emit_run(
    run_result: RunResult,
    path: str | Path,
    *,
    binary: str | Path,
    backend: str,
    now: Callable[[], str] = _utc_now,
) -> bool:
    """Append a negative record (NDJSON) if the run was negative. Returns True iff
    a record was written."""
    rec = record_from_run(run_result, binary=binary, backend=backend, now=now)
    if rec is None:
        return False
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec.to_dict(), sort_keys=True) + "\n")
    return True

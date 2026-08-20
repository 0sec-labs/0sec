"""Wire the novelty gate into the scan/finding pipeline.

Every finding a scan produces gets a ``novelty`` field — KNOWN-CVE(ids) or
NO-PUBLIC-RECORD-FOUND — so a scan that re-discovers a public CVE is auto-flagged
instead of being paraded as new (the segwindrvx64 mistake, permanently, at
scale). This module is the profile-agnostic bridge from the binary-native
``pipeline.TriagedFinding`` (+ ``ingest.Triage`` target context) to a
:class:`FindingFingerprint`, and the run-level annotator.

Design constraints honored:

* **Recall-first, never auto-drop.** Annotation only *adds* a field; it never
  removes or downgrades a finding. A KNOWN-CVE flag is a review signal, not a
  verdict on whether the bug is real (the PoV oracle owns that).
* **Cost-aware & opt-in-by-availability.** The store loads once per process from
  ``ZEROVERSE_CVE_KB_DIR`` and is cached; if no KB is configured/available the
  annotator is a graceful no-op (findings simply carry no ``novelty`` field),
  so a scan without a mirror is never slowed or broken.
* **Honest.** "No record" is caveated as ≠ novel; freshness of the local mirror
  bounds the claim, which is exactly why the verdict is never "novel".
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .gate import novelty
from .models import FindingFingerprint, NoveltyResult
from .store import CveStore, default_store_dir

if TYPE_CHECKING:  # avoid import cycles / hard deps at module load
    from ..ingest import Triage
    from ..pipeline import RunResult, TriagedFinding

_CWE = __import__("re").compile(r"CWE-\d+", __import__("re").IGNORECASE)

# process-level store cache (keyed by resolved path) so repeated scans in one
# process pay the JSONL load once.
_STORE_CACHE: dict[str, CveStore | None] = {}


def _ecosystem_for(fmt: str, filename: str) -> str:
    fmt = (fmt or "").lower()
    name = filename.lower()
    if fmt == "pe":
        return "windows-driver" if name.endswith((".sys",)) else "pe"
    if fmt == "elf":
        return "elf-kernel-module" if name.endswith(".ko") else "elf"
    if fmt in ("mach-o", "macho"):
        return "macho"
    return fmt or "unknown"


def fingerprint_from_finding(triage: Triage, tf: TriagedFinding) -> FindingFingerprint:
    """Build a cross-profile fingerprint from a scan finding + its target context."""
    f, v = tf.finding, tf.verdict
    filename = Path(getattr(triage, "path", "") or "").name
    stem = filename.rsplit(".", 1)[0] if "." in filename else filename

    cwe = ""
    m = _CWE.search(getattr(v, "bug_class", "") or "")
    if m:
        cwe = m.group(0).upper()

    bug_class = ""
    extra: list[str] = []
    pov = getattr(tf, "pov", None)
    if pov is not None:
        bug_class = getattr(pov, "capability", "") or getattr(pov, "crash_class", "") or ""
        # a PoV may already carry suspected public advisory ids — feed them in as
        # discriminators so a thin finding still attributes.
        extra.extend(getattr(pov, "suspected_known", []) or [])
    if not bug_class:
        bug_class = getattr(v, "bug_class", "") or ""

    return FindingFingerprint(
        product=stem,
        file=filename,
        ecosystem=_ecosystem_for(getattr(triage, "fmt", ""), filename),
        function=getattr(f, "function", "") or getattr(f, "sink", "") or "",
        cwe=cwe,
        bug_class=bug_class,
        description=(getattr(v, "explanation", "") or "")[:400],
        extra_terms=tuple(dict.fromkeys(extra)),
        finding_id=f"{filename}:{getattr(f, 'sink', '')}@{hex(getattr(f, 'sink_addr', 0))}",
    )


def load_store(path: str | os.PathLike[str] | None = None) -> CveStore | None:
    """Load (and cache) the KB store from ``ZEROVERSE_CVE_KB_DIR``/``path``.

    Returns None when no ``records.jsonl`` exists — the annotator then no-ops.
    The bundled/seed base is always available via ``build_store`` for callers who
    want a store even without a mirror; here we prefer the on-disk mirror.
    """
    p = Path(path) if path is not None else (default_store_dir() / "records.jsonl")
    key = str(p.resolve())
    if key in _STORE_CACHE:
        return _STORE_CACHE[key]
    store: CveStore | None = CveStore.load(p) if p.exists() else None
    _STORE_CACHE[key] = store
    return store


def annotate_finding(
    store: CveStore, triage: Triage, tf: TriagedFinding
) -> NoveltyResult:
    fp = fingerprint_from_finding(triage, tf)
    return novelty(fp, store)


def annotate_run(
    result: RunResult,
    *,
    store: CveStore | None = None,
    path: str | os.PathLike[str] | None = None,
) -> RunResult:
    """Annotate every finding in a completed run with a ``novelty`` field, in
    place. Graceful no-op when no KB store is available.

    Set on ``TriagedFinding.novelty`` (a dict) so ``serialize.finding_dict``
    emits it and every downstream consumer (report/0cloud/SARIF) carries it.
    """
    kb_store = store if store is not None else load_store(path)
    if kb_store is None or len(kb_store) == 0:
        return result
    for tf in getattr(result, "findings", []):
        try:
            res = annotate_finding(kb_store, getattr(result, "triage", None), tf)  # type: ignore[arg-type]
            tf.novelty = res.to_dict()
        except Exception:
            continue
    return result


def novelty_summary(result: RunResult) -> dict[str, Any]:
    """Roll up the run's novelty flags for a headline (known-CVE re-discoveries)."""
    known: list[str] = []
    no_record = 0
    for tf in getattr(result, "findings", []):
        nov = getattr(tf, "novelty", None)
        if not nov:
            continue
        if nov.get("verdict", "").startswith("KNOWN"):
            known.extend(nov.get("cve_ids", []) or [nov.get("label", "")])
        else:
            no_record += 1
    return {
        "known_cve_rediscoveries": sorted(dict.fromkeys(known)),
        "no_public_record_findings": no_record,
    }

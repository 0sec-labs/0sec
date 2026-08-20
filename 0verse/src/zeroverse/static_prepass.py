"""Stage 3 — foxguard static pre-pass over Ghidra's decompiled C (#3).

foxguard is the 0sec C-taint scanner (a fast, free, multi-language SAST with
cross-file taint tracking and SARIF output). Here we point it at the *decompiled*
C that the Ghidra backend recovered and treat every hit as a **hypothesis, never
a finding** (guidance §#3 — Infer's ~99.9% FP lesson: high-recall generator,
agent/oracle filter). foxguard + the #2 slice are two independent high-recall
generators; their union feeds triage and their divergence is signal.

Graceful by design: if foxguard isn't installed/built on the host, this returns
an empty list and records why — M1's spine never blocks on it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


def _is_runnable_file(path: str) -> bool:
    """True iff ``path`` is an executable file. Never raises: an unreadable or
    un-traversable candidate (e.g. ``/root/...`` in CI) is treated as not-found
    instead of propagating PermissionError (a subclass of OSError)."""
    try:
        return Path(path).is_file() and os.access(path, os.X_OK)
    except OSError:
        return False


def _which(name: str) -> str | None:
    try:
        return shutil.which(name)
    except OSError:
        return None


def foxguard_path() -> str | None:
    """Resolve the foxguard binary; optional + graceful (None → the pre-pass skips,
    never crashes).

    Discovery order (proper, not bench-only): (1) ``$ZEROVERSE_FOXGUARD`` (or the
    legacy ``$FOXGUARD_BIN``) override — an absolute path or a bare PATH name,
    (2) ``foxguard`` on PATH (the canonical install), (3) ``/usr/local/bin/foxguard``,
    (4) the legacy ``/root/foxguard/target/release/foxguard`` bench build. Every
    probe is wrapped so an unreadable candidate can never raise."""
    env = os.environ.get("ZEROVERSE_FOXGUARD") or os.environ.get("FOXGUARD_BIN")
    if env:
        if _is_runnable_file(env):
            return env
        found = _which(env)
        if found:
            return found
    on_path = _which("foxguard")
    if on_path:
        return on_path
    for cand in ("/usr/local/bin/foxguard", "/root/foxguard/target/release/foxguard"):
        if _is_runnable_file(cand):
            return cand
    return None


def foxguard_available() -> bool:
    return foxguard_path() is not None


@dataclass
class FoxHypothesis:
    """One foxguard SARIF result, normalized to the function it lives in."""

    rule_id: str               # bug class, e.g. "c.taint.oob-write"
    function: str              # decompiled function name (from the .c filename)
    message: str
    level: str = "warning"     # SARIF level
    line: int = 0

    @property
    def bug_class(self) -> str:
        return self.rule_id


@dataclass
class PrepassResult:
    hypotheses: list[FoxHypothesis] = field(default_factory=list)
    ran: bool = False
    note: str = ""


def run_over_decompiled(
    decompiled_c: dict[str, str], *, timeout: float = 60.0
) -> PrepassResult:
    """Write each decompiled function to ``<function>.c`` and run foxguard --format
    sarif over the directory. Returns hypotheses keyed back to their function.

    Never raises: a missing binary, a non-zero exit, or unparsable SARIF all
    degrade to an empty, annotated result."""
    fg = foxguard_path()
    if fg is None:
        return PrepassResult(note="foxguard not found (build it or set FOXGUARD_BIN)")
    if not decompiled_c:
        return PrepassResult(ran=False, note="no decompiled C to scan")

    with tempfile.TemporaryDirectory() as td:
        src_dir = Path(td)
        name_by_stem: dict[str, str] = {}
        for func, code in decompiled_c.items():
            if not code:
                continue
            stem = _safe_stem(func)
            name_by_stem[stem] = func
            (src_dir / f"{stem}.c").write_text(code)
        if not name_by_stem:
            return PrepassResult(ran=False, note="decompiled C was empty")

        cmd = [fg, str(src_dir), "--format", "sarif"]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, timeout=timeout, text=True
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            return PrepassResult(ran=False, note=f"foxguard run failed: {e}")

        hyps = _parse_sarif(proc.stdout, name_by_stem)
        return PrepassResult(hypotheses=hyps, ran=True,
                             note=f"foxguard: {len(hyps)} hypotheses")


def _safe_stem(func: str) -> str:
    s = "".join(c if c.isalnum() or c in "_-" else "_" for c in func) or "fn"
    if len(s) > 200:
        # ENAMETOOLONG guard: rich C++/PDB template names (e.g. Windows-PE
        # targets with symbols) blow past the 255-byte filename limit and
        # crash the whole prepass. Truncate + append a stable hash so the
        # stem stays unique and filesystem-safe.
        import hashlib

        s = s[:180] + "_" + hashlib.sha1(func.encode()).hexdigest()[:12]
    return s


def _parse_sarif(text: str, name_by_stem: dict[str, str]) -> list[FoxHypothesis]:
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    out: list[FoxHypothesis] = []
    for run in doc.get("runs", []):
        for res in run.get("results", []):
            rule = str(res.get("ruleId", "foxguard"))
            level = str(res.get("level", "warning"))
            msg = str((res.get("message", {}) or {}).get("text", ""))
            func, line = _locate(res, name_by_stem)
            out.append(FoxHypothesis(
                rule_id=rule, function=func, message=msg, level=level, line=line
            ))
    return out


def _locate(res: dict[str, object], name_by_stem: dict[str, str]) -> tuple[str, int]:
    locs = res.get("locations", [])
    if isinstance(locs, list) and locs:
        phys = (locs[0] or {}).get("physicalLocation", {}) if isinstance(locs[0], dict) else {}
        art = phys.get("artifactLocation", {}) if isinstance(phys, dict) else {}
        uri = str(art.get("uri", "")) if isinstance(art, dict) else ""
        stem = Path(uri).stem
        region = phys.get("region", {}) if isinstance(phys, dict) else {}
        line = int(region.get("startLine", 0)) if isinstance(region, dict) else 0
        return name_by_stem.get(stem, stem or "?"), line
    return "?", 0

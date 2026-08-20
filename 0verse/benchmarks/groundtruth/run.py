#!/usr/bin/env python3
"""Ground-truth eval runner — the credibility instrument (M6 eval harness).

Builds each labeled corpus binary, runs the **full 0verse pipeline** over it
(``zeroverse.api.scan``), and scores the findings against KNOWN ground truth with
the typed, unit-tested scorer in ``zeroverse.groundtruth``: **recall** (did it
surface the known bug at the right function/sink?), **FP rate** (confirmed
findings on the fixed/clean builds), **precision**, **confirmed-PoV rate**, and
wall-time. No cherry-picking — misses and false positives are emitted verbatim.

Each scan is also captured as a labeled dataset record (#32) when
``--dataset`` / ``ZEROVERSE_DATASET_PATH`` points somewhere — the same emitter the
moat uses, so the eval doubles as corpus capture.

    # full bounded pass (MockLLM, deterministic, no external sends):
    python benchmarks/groundtruth/run.py \
        --manifest benchmarks/groundtruth/manifest.json \
        --out benchmarks/groundtruth/results.json

    # a subset / a single item:
    python benchmarks/groundtruth/run.py --only cve_2017_9047_xml_vuln sf_overflow

Honest by construction: the headline table below is rendered by
``zeroverse.groundtruth.format_report`` from the scored result — never hand-edited.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from zeroverse import api  # noqa: E402
from zeroverse.groundtruth import (  # noqa: E402
    GROUNDTRUTH_SCHEMA_VERSION,
    CorpusItem,
    ItemScore,
    aggregate,
    format_report,
    heldout_summary,
    lane_label,
    load_manifest,
    score_item,
)


def _build(item: CorpusItem, workdir: Path) -> Path:
    """Compile a corpus item to a binary. Raises on a compile failure."""
    src = ROOT / item.source
    if not src.exists():
        raise FileNotFoundError(f"{item.id}: source {src} missing")
    out = workdir / item.name
    cmd = ["gcc", "-O0", *item.build_flags.split(), "-o", str(out), str(src)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"{item.id}: compile failed\n{proc.stderr}")
    return out


def _scan_findings(binary: Path, opts: api.ScanOptions) -> tuple[list[dict[str, Any]], str]:
    """Run the full pipeline; return (finding dicts, stages note)."""
    result = api.scan(str(binary), opts)
    return [f.to_dict() for f in result.findings], ",".join(result.stages_run)


def run_item(
    item: CorpusItem, opts: api.ScanOptions, workdir: Path
) -> tuple[ItemScore, dict[str, Any]]:
    """Build + scan + score one item. Returns (score, a JSON-able detail record)."""
    t0 = time.monotonic()
    detail: dict[str, Any] = {
        "id": item.id, "label": item.label, "tier": item.tier, "cwe": item.cwe,
        "cve": item.cve, "in_seed_set": item.in_seed_set,
    }
    try:
        binary = _build(item, workdir)
    except (RuntimeError, FileNotFoundError) as exc:
        detail["error"] = str(exc)
        score = score_item(item, [])
        score.note = "build-failed"
        detail.update(elapsed_s=round(time.monotonic() - t0, 2), findings=[], stages="")
        return score, detail

    findings, stages = _scan_findings(binary, opts)
    score = score_item(item, findings)
    detail.update(
        elapsed_s=round(time.monotonic() - t0, 2),
        stages=stages,
        findings=[
            {"function": f.get("function"), "source": f.get("source"),
             "sink": f.get("sink"), "confirmed": f.get("confirmed"),
             "hypothesis": f.get("hypothesis")}
            for f in findings
        ],
        outcome=score.outcome,
    )
    return score, detail


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="0verse ground-truth eval")
    ap.add_argument("--manifest", default=str(HERE / "manifest.json"))
    ap.add_argument("--out", default=str(HERE / "results.json"))
    ap.add_argument("--only", nargs="*", help="subset of item ids to run")
    ap.add_argument("--backend", default="auto")
    ap.add_argument("--llm", default="codex",
                    help="LLM provider for the reported (capability) number; "
                         "'mock' = the deterministic CI REGRESSION FLOOR — runs with "
                         "no keys/external sends, but is NOT a capability measure")
    ap.add_argument("--model", default=None)
    ap.add_argument("--dataset", default=os.environ.get("ZEROVERSE_DATASET_PATH"),
                    help="append a labeled dataset record (#32) per scan")
    args = ap.parse_args(argv)

    manifest = load_manifest(args.manifest)
    items = manifest.items
    if args.only:
        wanted = set(args.only)
        items = [i for i in items if i.id in wanted]
        if not items:
            print(f"no items matched {sorted(wanted)}", file=sys.stderr)
            return 2

    if args.dataset:
        os.environ["ZEROVERSE_DATASET_PATH"] = args.dataset
    opts = api.ScanOptions(backend=args.backend, llm=args.llm, model=args.model)

    lane, is_capability = lane_label(args.llm)
    if not is_capability:
        print(
            "\n*** MockLLM lane = ci-regression-floor (NOT a capability measure). ***\n"
            "*** This proves the harness wiring + static lenses still fire; it is\n"
            "*** the deterministic regression FLOOR, never a reported capability\n"
            "*** number. Use --llm codex (or another real provider) for the\n"
            "*** headline number.\n",
            file=sys.stderr,
        )

    scores: list[ItemScore] = []
    details: list[dict[str, Any]] = []
    t_start = time.monotonic()
    with tempfile.TemporaryDirectory() as td:
        workdir = Path(td)
        for item in items:
            print(f"== {item.id} [{item.label}/{item.tier}] ==", file=sys.stderr)
            score, detail = run_item(item, opts, workdir)
            print(f"   outcome={score.outcome} findings={detail.get('findings')} "
                  f"({detail['elapsed_s']}s)", file=sys.stderr)
            scores.append(score)
            details.append(detail)
    wall = round(time.monotonic() - t_start, 1)

    metrics = aggregate(items, scores)
    heldout = heldout_summary(items)
    report = format_report(metrics, heldout, scores, lane=lane)

    out = {
        "schema_version": GROUNDTRUTH_SCHEMA_VERSION,
        "tool": dict(api.TOOL),
        "llm": args.llm,
        "lane": lane,
        "capability_measure": is_capability,
        "backend": args.backend,
        "wall_s": wall,
        "n_items": len(items),
        "metrics": metrics.to_dict(),
        "heldout": heldout.to_dict(),
        "items": details,
        "scores": [s.to_dict() for s in scores],
    }
    Path(args.out).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print("\n" + report)
    print(f"\nwall={wall}s  results -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

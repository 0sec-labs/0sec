#!/usr/bin/env python3
"""Post-training-cutoff CVE eval runner — the discovery-vs-memorization instrument (#49).

Same build -> full-pipeline-scan -> typed-scorer flow as the ground-truth runner
(``benchmarks/groundtruth/run.py``), but over a corpus of **real CVE-2026
memory-safety bugs published AFTER the model's training cutoff**. A confirmed PoV
on a vulnerable build is therefore *genuine discovery*: the model could not have
memorized a bug that was disclosed after it was trained. Each clean ``-DFIXED``
build is the upstream fix and serves as the false-positive control.

Honesty gate: before running anything, every ``real-cve`` item is checked with
``zeroverse.groundtruth.validate_post_cutoff`` — a missing NVD/fix reference or a
publish date that is NOT strictly after the training cutoff aborts the run (unless
``--no-cutoff-gate``). No cherry-picking: misses and false positives are scored and
emitted verbatim by the same ``zeroverse.groundtruth`` scorer the ground-truth eval
uses.

    python benchmarks/cve2026/run.py --llm codex \
        --out benchmarks/cve2026/results-codex.json
    python benchmarks/cve2026/run.py --only ffmpeg_magicyuv_vuln ffmpeg_magicyuv_fixed
"""

from __future__ import annotations

import argparse
import importlib.util
import json
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
    ItemScore,
    aggregate,
    format_report,
    heldout_summary,
    load_manifest,
    validate_post_cutoff,
)


def _load_gt_runner() -> Any:
    """Reuse the ground-truth runner's build+scan+score-one-item helper."""
    path = ROOT / "benchmarks" / "groundtruth" / "run.py"
    spec = importlib.util.spec_from_file_location("zeroverse_gt_runner", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="0verse post-training-cutoff CVE eval (#49)")
    ap.add_argument("--manifest", default=str(HERE / "manifest.json"))
    ap.add_argument("--out", default=str(HERE / "results.json"))
    ap.add_argument("--only", nargs="*", help="subset of item ids to run")
    ap.add_argument("--backend", default="auto")
    ap.add_argument("--llm", default="mock",
                    help="LLM provider; 'mock' = deterministic, no external sends; "
                         "'codex' = the real ChatGPT-OAuth model")
    ap.add_argument("--model", default=None)
    ap.add_argument("--cutoff", default=None,
                    help="ISO training-cutoff override; default = manifest.training_cutoff")
    ap.add_argument("--no-cutoff-gate", action="store_true",
                    help="run even if an item fails post-cutoff provenance validation")
    args = ap.parse_args(argv)

    raw = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    cutoff = args.cutoff or str(raw.get("training_cutoff", ""))
    if not cutoff:
        print("manifest has no training_cutoff and --cutoff not given", file=sys.stderr)
        return 2

    manifest = load_manifest(args.manifest)
    issues = validate_post_cutoff(manifest.items, cutoff)
    if issues:
        print(f"POST-CUTOFF PROVENANCE ISSUES (cutoff {cutoff}):", file=sys.stderr)
        for iss in issues:
            print(f"  - {iss.item_id}: {iss.problem}", file=sys.stderr)
        if not args.no_cutoff_gate:
            print("aborting (use --no-cutoff-gate to override)", file=sys.stderr)
            return 3
    else:
        print(f"post-cutoff gate OK: all real-cve items published after {cutoff}",
              file=sys.stderr)

    items = manifest.items
    if args.only:
        wanted = set(args.only)
        items = [i for i in items if i.id in wanted]
        if not items:
            print(f"no items matched {sorted(wanted)}", file=sys.stderr)
            return 2

    gt = _load_gt_runner()
    opts = api.ScanOptions(backend=args.backend, llm=args.llm, model=args.model)
    scores: list[ItemScore] = []
    details: list[dict[str, Any]] = []
    t_start = time.monotonic()
    with tempfile.TemporaryDirectory() as td:
        workdir = Path(td)
        for item in items:
            print(f"== {item.id} [{item.label}/{item.cve}] ==", file=sys.stderr)
            score, detail = gt.run_item(item, opts, workdir)
            print(f"   outcome={score.outcome} findings={detail.get('findings')} "
                  f"({detail['elapsed_s']}s)", file=sys.stderr)
            scores.append(score)
            details.append(detail)
    wall = round(time.monotonic() - t_start, 1)

    metrics = aggregate(items, scores)
    heldout = heldout_summary(items)
    report = format_report(metrics, heldout, scores)

    out = {
        "schema_version": GROUNDTRUTH_SCHEMA_VERSION,
        "tool": dict(api.TOOL),
        "kind": "post-training-cutoff-cve",
        "training_cutoff": cutoff,
        "post_cutoff_gate": "ok" if not issues else "overridden",
        "llm": args.llm,
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

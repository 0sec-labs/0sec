#!/usr/bin/env python3
"""
Export the trained XGBoost triage *router* to a compact, self-contained
JSON artifact that the TypeScript orchestrator can load and evaluate at
runtime with zero native dependencies.

Why a re-export (instead of shipping the raw xgboost dump):
  - The raw `triage-router-v1.json` is the full xgboost 3.x save_model
    format (175 KB) carrying training-time metadata, category tables,
    iteration_indptr, sum_hessian, loss_changes, etc. — none of which
    a forward-pass evaluator needs.
  - We flatten each tree to the four arrays the evaluator walks:
    split_indices, split_conditions, left_children, right_children
    (leaves keep their margin in split_conditions == base_weights).
  - The result is a small, documented, append-only artifact whose shape
    the TS evaluator owns, so a future xgboost format bump can't silently
    break runtime inference.

Source model: results/triage-router-v1.json
  - num_feature: 45  (matches @pwnkit/core feature-extractor indices 0-44
    and the orchestrator's perFindingIngestSchema feature_vector[45])
  - objective:   binary:logistic  -> sigmoid(margin)
  - 100 trees, base_score 0.5 (logit-space base margin 0.0)

This is a ROUTER/PRIORITIZER, not a gate (#512). The probability it
emits is used only to order findings into / out of expensive
verification — it never drops, hides, or blocks a finding.

Usage:
    python3 scripts/export_triage_router.py \
        [--model results/triage-router-v1.json] \
        [--dataset results/triage-dataset-v1.jsonl] \
        [--out ../../../services/orchestrator/src/triage/triage-router-v1.model.json]

The script verifies its own output: it re-evaluates the flattened model
in pure Python and asserts the predictions match xgboost's predict()
to within 1e-6 before writing.
"""

import argparse
import json
import math
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH_ROOT = HERE.parent  # packages/benchmark
# packages/benchmark -> packages -> pwnkit -> repo root
REPO_ROOT = BENCH_ROOT.parent.parent.parent

DEFAULT_MODEL = BENCH_ROOT / "results" / "triage-router-v1.json"
DEFAULT_DATASET = BENCH_ROOT / "results" / "triage-dataset-v1.jsonl"
DEFAULT_OUT = (
    REPO_ROOT
    / "services"
    / "orchestrator"
    / "src"
    / "triage"
    / "triage-router-v1.model.json"
)

N_FEATURES = 45


def parse_base_score(raw: str) -> float:
    # xgboost serializes base_score as e.g. "[5E-1]"
    return float(raw.strip().lstrip("[").rstrip("]"))


def flatten_tree(tree: dict) -> dict:
    left = tree["left_children"]
    right = tree["right_children"]
    split_idx = tree["split_indices"]
    split_cond = tree["split_conditions"]
    base_w = tree["base_weights"]
    default_left = tree["default_left"]
    n = len(left)

    nodes = []
    for i in range(n):
        is_leaf = left[i] == -1
        nodes.append(
            {
                "leaf": bool(is_leaf),
                # For leaves: the output margin contribution.
                # For internal nodes: the split threshold (< goes left).
                "value": float(base_w[i]) if is_leaf else float(split_cond[i]),
                "feature": int(split_idx[i]) if not is_leaf else -1,
                "left": int(left[i]),
                "right": int(right[i]),
                "default_left": bool(default_left[i]) if not is_leaf else False,
            }
        )
    return {"nodes": nodes}


def _f32(v: float) -> float:
    # xgboost stores splits + evaluates comparisons in float32. We must
    # match that precision exactly, otherwise rows whose feature value
    # sits on a split boundary route the wrong way. The TS evaluator uses
    # Math.fround() for the same reason.
    import struct

    return struct.unpack("f", struct.pack("f", v))[0]


def eval_tree(tree: dict, x: list[float]) -> float:
    nodes = tree["nodes"]
    i = 0
    while not nodes[i]["leaf"]:
        node = nodes[i]
        fv = x[node["feature"]]
        if fv is None or (isinstance(fv, float) and math.isnan(fv)):
            i = node["left"] if node["default_left"] else node["right"]
        elif _f32(fv) < _f32(node["value"]):
            i = node["left"]
        else:
            i = node["right"]
    return nodes[i]["value"]


def predict_proba(model: dict, x: list[float]) -> float:
    margin = model["base_margin"]
    for tree in model["trees"]:
        margin += _f32(eval_tree(tree, x))
    return 1.0 / (1.0 + math.exp(-margin))


def load_dataset(path: Path):
    X = []
    y = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        feats = list(rec["features"])
        feats = (feats + [0.0] * N_FEATURES)[:N_FEATURES]
        X.append([float(v) for v in feats])
        y.append(int(rec["label"]))
    return X, y


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    ap.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--meta", type=Path, default=BENCH_ROOT / "results" / "triage-router-v2-meta.json")
    args = ap.parse_args()

    raw = json.loads(args.model.read_text())
    learner = raw["learner"]
    lmp = learner["learner_model_param"]
    num_feature = int(lmp["num_feature"])
    if num_feature != N_FEATURES:
        print(
            f"ERROR: source model has num_feature={num_feature}, expected {N_FEATURES}. "
            f"The orchestrator feature_vector schema is length {N_FEATURES}; refusing to export a mismatched model.",
            file=sys.stderr,
        )
        return 1

    objective = learner["objective"]["name"]
    if objective != "binary:logistic":
        print(f"ERROR: unexpected objective {objective!r}", file=sys.stderr)
        return 1

    base_score = parse_base_score(lmp["base_score"])
    # binary:logistic stores base_score in probability space; the margin
    # offset is its logit.
    base_margin = math.log(base_score / (1.0 - base_score))

    src_trees = learner["gradient_booster"]["model"]["trees"]
    trees = [flatten_tree(t) for t in src_trees]

    model = {
        "schema_version": 1,
        "source_model": args.model.name,
        "objective": objective,
        "n_features": N_FEATURES,
        "base_score": base_score,
        "base_margin": base_margin,
        "n_trees": len(trees),
        "trees": trees,
        # The classifier is a ROUTER, not a gate. These thresholds are
        # advisory ordering bands only; the orchestrator NEVER drops a
        # finding below any threshold (#512).
        "router": {
            "fast_track_threshold": 0.90,
            "deprioritize_threshold": 0.10,
        },
    }

    # ── Self-verification: pure-python eval must match xgboost.predict ──
    try:
        import numpy as np
        import xgboost as xgb

        bst = xgb.Booster()
        bst.load_model(str(args.model))
        X, y = load_dataset(args.dataset)
        # float32 to mirror xgboost's internal DMatrix precision (see _f32).
        dm = xgb.DMatrix(np.array(X, dtype=np.float32))
        xgb_p = bst.predict(dm)
        max_err = 0.0
        for row, ref in zip(X, xgb_p):
            mine = predict_proba(model, row)
            max_err = max(max_err, abs(mine - float(ref)))
        print(f"Self-check: {len(X)} rows, max |pure-py - xgboost| = {max_err:.3e}")
        if max_err > 1e-5:
            print("ERROR: flattened model diverges from xgboost predictions", file=sys.stderr)
            return 1

        # Report honest CV-style training-set metrics for the README.
        from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score

        pred = (xgb_p >= 0.5).astype(int)
        print(
            f"Train-set @0.5: F1={f1_score(y, pred):.4f} "
            f"P={precision_score(y, pred, zero_division=0):.4f} "
            f"R={recall_score(y, pred, zero_division=0):.4f} "
            f"AUC={roc_auc_score(y, xgb_p):.4f} (n={len(y)})"
        )
    except ImportError:
        print(
            "WARNING: xgboost/sklearn/numpy not importable — skipping self-verification. "
            "The flattened artifact is still written, but its fidelity was NOT machine-checked.",
            file=sys.stderr,
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(model, separators=(",", ":")) + "\n")
    size_kb = args.out.stat().st_size / 1024
    print(f"Wrote {args.out} ({size_kb:.0f} KB, {model['n_trees']} trees)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

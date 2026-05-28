#!/usr/bin/env python3
"""
Active-learning retraining loop for the triage *router* (#503).

The dataset flywheel: every scan -> operators triage findings TP/FP ->
`dataset_rows.label` / `label_source` accrue new ground truth ->
`cronjob-export.yaml` drops a daily JSONL -> this loop retrains the
classifier on the accumulated labels and promotes a new model *only*
when it measurably beats the one in production.

This script is the missing feedback step described in #503. The pieces
around it already existed before this change:

  - Export   : `infra/k3s/cronjob-export.yaml` writes a daily JSONL of
               every `dataset_rows` row (text/features/label/label_source).
  - Train    : `train_triage_v2.py` (CV trainer, 55-feature research line).
  - Promote  : `scripts/export_triage_router.py` flattens a raw xgboost
               dump into the compact artifact the orchestrator loads at
               runtime (`services/orchestrator/src/triage/
               triage-router-v1.model.json`).

What was missing — and what this adds — is the A/B-gated retrain that
ties them together:

  1. Load the labeled JSONL (operator feedback + bootstrap labels).
  2. Carve a *stratified, held-out* validation split — the same row
     never trains and validates the candidate.
  3. Train a candidate on the train split, at the SAME 45-feature arity
     the production router runs (the orchestrator's `feature_vector` is
     length 45 and `TriageRouter.fromModel` fails closed on any other
     arity — see services/orchestrator/src/triage/router.ts). Staying at
     45 features keeps this loop scoped to the deployed v1 router and
     avoids colliding with the 55-feature v2 research line (#501) or the
     base_score fix (#519).
  4. Score BOTH the current production model and the candidate on the
     held-out split.
  5. Promote the candidate *only* when its F1 beats production by at
     least `--min-f1-gain` (default 0.005). Promotion = retrain on the
     full dataset, write the raw dump, re-export the TS artifact via
     `export_triage_router.py`, and append a structured entry to the
     promotion ledger. Anything short of the gain bar is logged and
     discarded — the flywheel never regresses production on noise.

Like the rest of the benchmark harness (see README "Statistical
evaluation"), the bias is conservative: a single good number does not
get promoted. The promotion gate is an explicit, auditable margin, and
every decision (promote or hold) is appended to the ledger so the
"precision/recall over time" dashboard surface (#503 item 5) has a
machine-readable source.

Usage:
    python3 active_learning_loop.py \
        [--dataset results/triage-dataset-v1.jsonl] \
        [--current-model results/triage-router-v1.json] \
        [--out-model results/triage-router-v1-candidate.json] \
        [--ledger results/active-learning-ledger.json] \
        [--min-f1-gain 0.005] [--val-frac 0.2] [--seed 42] \
        [--promote / --dry-run]

By default the loop is DRY-RUN: it trains, A/B-tests, and logs the
verdict to the ledger, but does NOT touch the runtime artifact. Pass
`--promote` to let a winning candidate replace production (the cron in
`infra/k3s/cronjob-active-learning.yaml` passes `--promote`).

Exit codes:
    0  ran cleanly (promoted OR held — both are success)
    2  not enough labeled data to retrain (need >= --min-samples)
    3  training / evaluation error
"""

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import xgboost as xgb
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_sample_weight

HERE = Path(__file__).resolve().parent
# scripts/train -> scripts -> benchmark
BENCH_ROOT = HERE.parent.parent
# benchmark -> packages -> pwnkit -> repo root
REPO_ROOT = BENCH_ROOT.parent.parent.parent

# The production router is a 45-feature binary:logistic XGBoost model.
# This is load-bearing: the orchestrator's TriageRouter.fromModel throws
# on any other arity, so the active-learning loop must train at 45.
N_FEATURES = 45

DEFAULT_DATASET = BENCH_ROOT / "results" / "triage-dataset-v1.jsonl"
DEFAULT_CURRENT_MODEL = BENCH_ROOT / "results" / "triage-router-v1.json"
DEFAULT_OUT_MODEL = BENCH_ROOT / "results" / "triage-router-v1-candidate.json"
DEFAULT_LEDGER = BENCH_ROOT / "results" / "active-learning-ledger.json"
EXPORT_SCRIPT = BENCH_ROOT / "scripts" / "export_triage_router.py"

# XGBoost params mirror the v1 production router (100 trees, depth 6).
# Kept in sync with train_triage_v2.py's tree shape minus the v2-only
# feature arity so a promoted candidate is a like-for-like replacement.
XGB_PARAMS = {
    "objective": "binary:logistic",
    "eval_metric": "logloss",
    "max_depth": 6,
    "learning_rate": 0.1,
    "n_estimators": 100,
    "min_child_weight": 3,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "tree_method": "hist",
}


# ── Data loading ──


def load_dataset(path: Path) -> tuple[np.ndarray, np.ndarray, dict]:
    """Load the JSONL export into a (X, y) pair padded/truncated to 45 features.

    Also returns a small provenance summary (label-source breakdown) so the
    ledger entry can record how much of the training signal came from
    operator triage vs. the bootstrap labels — the whole point of #503.
    """
    X: list[list[float]] = []
    y: list[int] = []
    label_sources: dict[str, int] = {}

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        # A truncation sentinel from the dataset exporter is not a sample.
        if rec.get("_truncated"):
            continue
        label = rec.get("label")
        if label is None:
            # Unlabeled row (pending triage) — not usable as ground truth.
            continue
        feats = list(rec.get("features", []))
        feats = (feats + [0.0] * N_FEATURES)[:N_FEATURES]
        X.append([float(v) for v in feats])
        y.append(int(label))
        src = rec.get("label_source") or "unknown"
        label_sources[src] = label_sources.get(src, 0) + 1

    provenance = {
        "n_labeled": len(y),
        "label_sources": label_sources,
        # human_review is the operator-feedback signal the flywheel is
        # built on; surface it explicitly.
        "operator_feedback_rows": label_sources.get("human_review", 0),
    }
    return np.array(X, dtype=float), np.array(y, dtype=int), provenance


# ── Evaluation ──


def metrics_at(y_true: np.ndarray, probs: np.ndarray, threshold: float = 0.5) -> dict:
    preds = (probs >= threshold).astype(int)
    out = {
        "f1": float(f1_score(y_true, preds, zero_division=0)),
        "precision": float(precision_score(y_true, preds, zero_division=0)),
        "recall": float(recall_score(y_true, preds, zero_division=0)),
    }
    # AUC is undefined for a single-class validation split; report null.
    out["auc"] = (
        float(roc_auc_score(y_true, probs))
        if len(np.unique(y_true)) > 1
        else None
    )
    return out


def train_candidate(
    X: np.ndarray, y: np.ndarray, params: dict
) -> xgb.XGBClassifier:
    """Fit a 45-feature XGBoost classifier with balanced sample weights.

    Balanced weights (not scale_pos_weight) match the v2 trainer's choice
    — the dataset is heavily TP-skewed and double-penalizing pushes
    probabilities too low (see train_triage_v2.py).
    """
    model = xgb.XGBClassifier(**params)
    sample_weights = compute_sample_weight("balanced", y)
    model.fit(X, y, sample_weight=sample_weights, verbose=False)
    return model


def score_current_model(model_path: Path, X: np.ndarray, y: np.ndarray) -> dict:
    """Load the production raw xgboost dump and score it on the held-out set.

    Uses a Booster loaded straight from the saved JSON so we measure the
    EXACT model running in production, not a re-fit approximation.
    """
    booster = xgb.Booster()
    booster.load_model(str(model_path))
    dmat = xgb.DMatrix(X)
    probs = booster.predict(dmat)
    return metrics_at(y, probs)


# ── Ledger ──


def append_ledger(ledger_path: Path, entry: dict) -> None:
    """Append one decision entry to the JSON-array promotion ledger.

    Mirrors the benchmark-ledger.json pattern: an append-only array the
    dashboard can read to chart precision/recall over time (#503 item 5).
    """
    if ledger_path.exists():
        try:
            ledger = json.loads(ledger_path.read_text())
            if not isinstance(ledger, list):
                ledger = []
        except json.JSONDecodeError:
            ledger = []
    else:
        ledger = []
    ledger.append(entry)
    ledger_path.write_text(json.dumps(ledger, indent=2) + "\n")


# ── Promotion ──


def reexport_runtime_artifact(raw_model_path: Path, dataset_path: Path) -> bool:
    """Re-run export_triage_router.py to refresh the orchestrator artifact.

    The export script self-verifies (pure-Python eval matches xgboost to
    <1e-6) before writing, so a corrupt flatten can't reach production.
    Returns True on success.
    """
    cmd = [
        sys.executable,
        str(EXPORT_SCRIPT),
        "--model",
        str(raw_model_path),
        "--dataset",
        str(dataset_path),
    ]
    print(f"\n[promote] re-exporting runtime artifact: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    sys.stdout.write(result.stdout)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        print(f"[promote] export FAILED (rc={result.returncode}) — NOT promoting")
        return False
    return True


# ── Main ──


def main() -> int:
    ap = argparse.ArgumentParser(description="Active-learning retraining loop (#503)")
    ap.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    ap.add_argument("--current-model", type=Path, default=DEFAULT_CURRENT_MODEL)
    ap.add_argument("--out-model", type=Path, default=DEFAULT_OUT_MODEL)
    ap.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    ap.add_argument(
        "--min-f1-gain",
        type=float,
        default=0.005,
        help="Minimum held-out F1 improvement over production to promote.",
    )
    ap.add_argument("--val-frac", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument(
        "--min-samples",
        type=int,
        default=200,
        help="Refuse to retrain below this many labeled rows.",
    )
    promote_group = ap.add_mutually_exclusive_group()
    promote_group.add_argument(
        "--promote",
        dest="promote",
        action="store_true",
        help="Replace the runtime artifact when the candidate wins.",
    )
    promote_group.add_argument(
        "--dry-run",
        dest="promote",
        action="store_false",
        help="Train + A/B + log only; never touch production (default).",
    )
    ap.set_defaults(promote=False)
    args = ap.parse_args()

    now = dt.datetime.now(dt.timezone.utc).isoformat()

    if not args.dataset.exists():
        print(f"ERROR: dataset not found: {args.dataset}", file=sys.stderr)
        return 3

    X, y, provenance = load_dataset(args.dataset)
    print(f"Loaded {provenance['n_labeled']} labeled rows from {args.dataset}")
    print(f"  Label-source breakdown: {provenance['label_sources']}")
    print(f"  Operator-feedback rows (human_review): {provenance['operator_feedback_rows']}")

    if provenance["n_labeled"] < args.min_samples:
        print(
            f"Not enough labeled data to retrain "
            f"({provenance['n_labeled']} < {args.min_samples}). Skipping.",
            file=sys.stderr,
        )
        append_ledger(
            args.ledger,
            {
                "ts": now,
                "decision": "skipped_insufficient_data",
                "n_labeled": provenance["n_labeled"],
                "min_samples": args.min_samples,
                "promote_flag": args.promote,
            },
        )
        return 2

    # Stratified held-out validation split. The candidate never sees the
    # validation rows; the production model is scored on the same rows so
    # the A/B is apples-to-apples.
    stratify = y if len(np.unique(y)) > 1 else None
    X_train, X_val, y_train, y_val = train_test_split(
        X,
        y,
        test_size=args.val_frac,
        random_state=args.seed,
        stratify=stratify,
    )
    print(
        f"\nSplit: {len(y_train)} train / {len(y_val)} val "
        f"(val TP={int(y_val.sum())}, FP={int(len(y_val) - y_val.sum())})"
    )

    # ── A/B: production vs candidate on the held-out split ──
    try:
        current_metrics = score_current_model(args.current_model, X_val, y_val)
    except Exception as err:  # noqa: BLE001 — surface any load/eval failure
        print(f"ERROR scoring current model: {err}", file=sys.stderr)
        return 3

    candidate = train_candidate(X_train, y_train, XGB_PARAMS)
    cand_probs = candidate.predict_proba(X_val)[:, 1]
    candidate_metrics = metrics_at(y_val, cand_probs)

    f1_gain = candidate_metrics["f1"] - current_metrics["f1"]

    print(f"\n{'='*56}")
    print("A/B on held-out validation split")
    print(f"{'='*56}")
    print(
        f"  current  : F1={current_metrics['f1']:.4f} "
        f"P={current_metrics['precision']:.4f} R={current_metrics['recall']:.4f}"
    )
    print(
        f"  candidate: F1={candidate_metrics['f1']:.4f} "
        f"P={candidate_metrics['precision']:.4f} R={candidate_metrics['recall']:.4f}"
    )
    print(f"  F1 gain  : {'+' if f1_gain >= 0 else ''}{f1_gain:.4f} "
          f"(promote bar: +{args.min_f1_gain:.4f})")

    wins = f1_gain >= args.min_f1_gain

    entry = {
        "ts": now,
        "dataset": str(args.dataset.name),
        "n_labeled": provenance["n_labeled"],
        "operator_feedback_rows": provenance["operator_feedback_rows"],
        "label_sources": provenance["label_sources"],
        "val_frac": args.val_frac,
        "seed": args.seed,
        "min_f1_gain": args.min_f1_gain,
        "current": current_metrics,
        "candidate": candidate_metrics,
        "f1_gain": f1_gain,
        "candidate_wins": wins,
        "promote_flag": args.promote,
        "decision": "pending",
    }

    if not wins:
        print("\nVerdict: HOLD — candidate did not clear the F1 gain bar.")
        entry["decision"] = "held_no_gain"
        append_ledger(args.ledger, entry)
        return 0

    # Winning candidate: retrain on the FULL dataset (train+val) so the
    # promoted model uses every labeled row, then write the raw dump.
    print("\nVerdict: candidate WINS — retraining on full dataset for promotion.")
    final_model = train_candidate(X, y, XGB_PARAMS)
    args.out_model.parent.mkdir(parents=True, exist_ok=True)
    final_model.get_booster().save_model(str(args.out_model))
    print(f"  Candidate raw dump written to {args.out_model}")

    if not args.promote:
        print(
            "\n[dry-run] candidate would be promoted, but --promote was not "
            "passed. Runtime artifact left untouched."
        )
        entry["decision"] = "would_promote_dry_run"
        append_ledger(args.ledger, entry)
        return 0

    # Real promotion: refresh the orchestrator runtime artifact from the
    # winning raw dump. The export script self-verifies before writing.
    exported = reexport_runtime_artifact(args.out_model, args.dataset)
    if not exported:
        entry["decision"] = "promotion_export_failed"
        append_ledger(args.ledger, entry)
        return 3

    print("\nVerdict: PROMOTED — runtime artifact refreshed.")
    entry["decision"] = "promoted"
    append_ledger(args.ledger, entry)
    return 0


if __name__ == "__main__":
    sys.exit(main())

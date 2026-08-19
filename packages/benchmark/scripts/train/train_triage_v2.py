#!/usr/bin/env python3
"""
pwnkit triage classifier training pipeline v2

Trains XGBoost + sklearn models on the labeled triage dataset.
Handles class imbalance, threshold optimization, and exports
a model JSON compatible with the TypeScript evaluator.

Usage:
    python3 train_triage_v2.py [--dataset PATH] [--output DIR]

Outputs:
    triage-router-v2.json      — XGBoost model for TS evaluator
    triage-router-v2-meta.json — Metadata (thresholds, metrics, feature importance)
    feature_importance.csv     — SHAP-style feature importance ranking
"""

import argparse
import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (
    f1_score, precision_score, recall_score, roc_auc_score,
    precision_recall_curve, classification_report, confusion_matrix,
)
from sklearn.utils.class_weight import compute_sample_weight


# ── Data loading ──

def load_dataset(path: str) -> pd.DataFrame:
    """Load JSONL dataset into DataFrame."""
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            records.append(rec)

    df = pd.DataFrame(records)
    print(f"Loaded {len(df)} samples from {path}")
    print(f"  Labels: {df['label'].value_counts().to_dict()}")
    print(f"  Sources: {df['source'].apply(lambda s: s.split(':')[0]).value_counts().to_dict()}")
    print(f"  Features per sample: {len(df.iloc[0]['features'])}")
    return df


def extract_features(df: pd.DataFrame) -> np.ndarray:
    """Extract feature matrix from the 'features' column."""
    # Pad to 55 features if dataset has 45
    def pad_features(feat_list):
        if len(feat_list) < 55:
            return feat_list + [0.0] * (55 - len(feat_list))
        return feat_list[:55]

    features = np.array([pad_features(row) for row in df["features"]])
    return features


# ── Feature names ──

FEATURE_NAMES = [
    # Response features (13)
    "resp_http_status", "resp_sql_error", "resp_stack_trace", "resp_error_message",
    "resp_payload_exact_reflection", "resp_payload_partial_reflection",
    "resp_sensitive_data", "resp_flag_pattern", "resp_content_type_match",
    "resp_length", "resp_waf_signature", "resp_redirect", "resp_5xx_status",
    # Request features (10)
    "req_sql_syntax", "req_xss_payload", "req_ssti_syntax", "req_path_traversal",
    "req_command_injection", "req_encoding_detected", "req_http_method",
    "req_auth_header", "req_param_count", "req_body_length",
    # Metadata features (8)
    "meta_severity_ordinal", "meta_confidence", "meta_high_confidence_category",
    "meta_injection_class", "meta_access_control_class", "meta_has_template_id",
    "meta_has_cwe", "meta_has_cve",
    # Text quality features (10)
    "text_description_length", "text_repro_steps", "text_impact_statement",
    "text_hedging_language", "text_verification_language", "text_analysis_length",
    "text_code_blocks", "text_evidence_request_nonempty",
    "text_evidence_response_nonempty", "text_evidence_analysis_nonempty",
    # Cross-field features (4)
    "cross_payload_category_consistent", "cross_severity_confidence_interaction",
    "cross_response_request_length_ratio", "cross_evidence_completeness",
    # Kernel crash features (10)
    "kernel_crash_type_ordinal", "kernel_stack_depth", "kernel_has_reproducer",
    "kernel_access_is_write", "kernel_access_size", "kernel_network_subsystem",
    "kernel_has_alloc_site", "kernel_has_free_site", "kernel_is_kasan",
    "kernel_subsystem_criticality",
]


# ── Training ──

def train_xgboost_cv(
    X: np.ndarray,
    y: np.ndarray,
    n_folds: int = 5,
    random_state: int = 42,
) -> dict:
    """Train XGBoost with stratified K-fold CV, class imbalance handling."""

    n_pos = y.sum()
    n_neg = len(y) - n_pos
    print(f"\nClass balance: {int(n_pos)} TP, {int(n_neg)} FP (ratio {n_pos/max(n_neg,1):.1f}:1)")

    # Use balanced sample weights only (not scale_pos_weight — applying
    # both causes double-penalization and pushes probabilities too low)
    params = {
        "objective": "binary:logistic",
        "eval_metric": "logloss",
        "max_depth": 6,
        "learning_rate": 0.1,
        "n_estimators": 200,
        "min_child_weight": 3,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "random_state": random_state,
        "tree_method": "hist",
    }

    skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=random_state)

    fold_metrics = []
    all_probs = np.zeros(len(y))
    all_preds = np.zeros(len(y))
    models = []

    print(f"\n{'='*60}")
    print(f"Training XGBoost v2 ({n_folds}-fold stratified CV)")
    print(f"{'='*60}")

    for fold_idx, (train_idx, val_idx) in enumerate(skf.split(X, y)):
        X_train, X_val = X[train_idx], X[val_idx]
        y_train, y_val = y[train_idx], y[val_idx]

        # Sample weights for training
        sample_weights = compute_sample_weight("balanced", y_train)

        model = xgb.XGBClassifier(**params)
        model.fit(
            X_train, y_train,
            sample_weight=sample_weights,
            eval_set=[(X_val, y_val)],
            verbose=False,
        )

        probs = model.predict_proba(X_val)[:, 1]
        preds = (probs >= 0.5).astype(int)

        f1 = f1_score(y_val, preds)
        prec = precision_score(y_val, preds, zero_division=0)
        rec = recall_score(y_val, preds)
        auc = roc_auc_score(y_val, probs) if len(np.unique(y_val)) > 1 else 0.0

        fold_metrics.append({"fold": fold_idx, "f1": f1, "precision": prec, "recall": rec, "auc": auc})
        all_probs[val_idx] = probs
        all_preds[val_idx] = preds
        models.append(model)

        print(f"  Fold {fold_idx}: F1={f1:.3f} Prec={prec:.3f} Rec={rec:.3f} AUC={auc:.3f}")

    # Aggregate metrics
    mean_f1 = np.mean([m["f1"] for m in fold_metrics])
    mean_prec = np.mean([m["precision"] for m in fold_metrics])
    mean_rec = np.mean([m["recall"] for m in fold_metrics])
    mean_auc = np.mean([m["auc"] for m in fold_metrics])
    std_f1 = np.std([m["f1"] for m in fold_metrics])

    print(f"\n  Mean: F1={mean_f1:.3f}±{std_f1:.3f} Prec={mean_prec:.3f} Rec={mean_rec:.3f} AUC={mean_auc:.3f}")

    # Overall confusion matrix
    print(f"\n  Overall confusion matrix:")
    cm = confusion_matrix(y, all_preds)
    print(f"    TN={cm[0,0]:>4}  FP={cm[0,1]:>4}")
    print(f"    FN={cm[1,0]:>4}  TP={cm[1,1]:>4}")

    # Per-source breakdown
    return {
        "fold_metrics": fold_metrics,
        "mean_f1": float(mean_f1),
        "std_f1": float(std_f1),
        "mean_precision": float(mean_prec),
        "mean_recall": float(mean_rec),
        "mean_auc": float(mean_auc),
        "all_probs": all_probs,
        "models": models,
        "params": params,
    }


def optimize_thresholds(y_true: np.ndarray, probs: np.ndarray) -> dict:
    """Find optimal accept/reject thresholds."""
    precisions, recalls, thresholds = precision_recall_curve(y_true, probs)

    # Find threshold that maximizes F1
    f1_scores = 2 * precisions * recalls / (precisions + recalls + 1e-8)
    best_f1_idx = np.argmax(f1_scores)
    best_threshold = float(thresholds[min(best_f1_idx, len(thresholds)-1)])

    # Find high-precision threshold (auto-accept: precision > 0.98)
    high_prec_mask = precisions >= 0.98
    if high_prec_mask.any():
        # Among thresholds with precision >= 0.98, find the lowest threshold
        # (to accept as many as possible while maintaining precision)
        valid_indices = np.where(high_prec_mask)[0]
        auto_accept = float(thresholds[min(valid_indices[-1], len(thresholds)-1)])
    else:
        auto_accept = 0.95

    # Find high-recall reject threshold (reject only when very confident it's FP)
    # We want: at threshold T, if prob < T then predict FP. What T gives us < 2% FN rate?
    reject_candidates = []
    for t in np.arange(0.05, 0.50, 0.01):
        below = probs < t
        if below.sum() > 0:
            fn_rate = y_true[below].sum() / max(y_true.sum(), 1)
            reject_candidates.append((t, fn_rate, below.sum()))

    auto_reject = 0.15  # conservative default
    for t, fn_rate, n_rejected in reject_candidates:
        if fn_rate < 0.02 and n_rejected > 5:
            auto_reject = t
            break

    print(f"\n  Threshold optimization:")
    print(f"    Best F1 threshold: {best_threshold:.3f} (F1={f1_scores[best_f1_idx]:.3f})")
    print(f"    Auto-accept (prec≥0.98): {auto_accept:.3f}")
    print(f"    Auto-reject (FN<2%): {auto_reject:.3f}")

    return {
        "best_f1_threshold": best_threshold,
        "best_f1": float(f1_scores[best_f1_idx]),
        "auto_accept_threshold": auto_accept,
        "auto_reject_threshold": auto_reject,
    }


def compute_feature_importance(models: list, feature_names: list) -> pd.DataFrame:
    """Compute mean feature importance across CV folds."""
    importances = np.zeros(len(feature_names))
    for model in models:
        imp = model.feature_importances_
        # Pad if model was trained on fewer features
        if len(imp) < len(feature_names):
            padded = np.zeros(len(feature_names))
            padded[:len(imp)] = imp
            imp = padded
        importances += imp / len(models)

    df = pd.DataFrame({
        "feature": feature_names[:len(importances)],
        "importance": importances[:len(feature_names)],
    })
    df = df.sort_values("importance", ascending=False).reset_index(drop=True)
    return df


def export_xgboost_model(model: xgb.XGBClassifier, output_path: str):
    """Export XGBoost model to JSON format compatible with the TS evaluator."""
    # Save to native XGBoost JSON format
    model.get_booster().save_model(output_path)
    print(f"\n  Model exported to {output_path}")


def train_dynamic_router(
    X: np.ndarray,
    y: np.ndarray,
    layer_verdicts: list,
    feature_names: list,
) -> dict | None:
    """Train a dynamic triage routing model that predicts which layers to run.

    Uses samples that have layer_verdicts to learn which layers add signal
    for which types of findings.
    """
    # Filter to samples with layer verdicts
    samples_with_verdicts = [
        (i, v) for i, v in enumerate(layer_verdicts) if v and len(v) > 0
    ]

    if len(samples_with_verdicts) < 50:
        print(f"\n  Dynamic router: skipping — only {len(samples_with_verdicts)} samples have layer verdicts (need 50+)")
        return None

    print(f"\n{'='*60}")
    print(f"Training dynamic triage router ({len(samples_with_verdicts)} samples with layer verdicts)")
    print(f"{'='*60}")

    # For each layer, train a binary classifier: should this layer run?
    # Target: layer's verdict was useful (changed the final outcome)
    layer_names = [
        "holding_it_wrong", "evidence_gate", "reachability",
        "multi_modal", "oracle", "pov_gate",
    ]

    layer_models = {}
    for layer_name in layer_names:
        # Extract per-layer signal: did this layer's verdict match the ground truth?
        layer_X = []
        layer_y = []
        for idx, verdicts in samples_with_verdicts:
            layer_verdict = next((v for v in verdicts if v.get("layer") == layer_name), None)
            if layer_verdict is None:
                continue
            # Label: was this layer's verdict correct?
            verdict_is_pass = layer_verdict.get("verdict") == "pass"
            ground_truth_is_tp = y[idx] == 1
            layer_was_useful = (verdict_is_pass == ground_truth_is_tp)
            layer_X.append(X[idx])
            layer_y.append(1 if layer_was_useful else 0)

        if len(layer_X) < 20:
            print(f"  {layer_name}: skipping — only {len(layer_X)} samples")
            continue

        layer_X = np.array(layer_X)
        layer_y = np.array(layer_y)

        model = xgb.XGBClassifier(
            max_depth=4,
            n_estimators=50,
            learning_rate=0.1,
            random_state=42,
        )
        model.fit(layer_X, layer_y, verbose=False)

        train_preds = model.predict(layer_X)
        acc = (train_preds == layer_y).mean()
        print(f"  {layer_name}: {len(layer_X)} samples, train acc={acc:.3f}")
        layer_models[layer_name] = model

    if not layer_models:
        return None

    return {"layer_models": layer_models, "layer_names": list(layer_models.keys())}


# ── Per-source evaluation ──

def evaluate_per_source(df: pd.DataFrame, probs: np.ndarray):
    """Break down metrics by data source."""
    print(f"\n  Per-source breakdown:")
    sources = df["source"].apply(lambda s: s.split(":")[0])
    for src in sorted(sources.unique()):
        mask = sources == src
        src_y = df.loc[mask, "label"].values
        src_probs = probs[mask]
        src_preds = (src_probs >= 0.5).astype(int)

        if len(np.unique(src_y)) < 2:
            f1 = 1.0 if src_y.sum() == len(src_y) else 0.0
            auc = 0.0
        else:
            f1 = f1_score(src_y, src_preds)
            auc = roc_auc_score(src_y, src_probs)

        n_tp = (src_y == 1).sum()
        n_fp = (src_y == 0).sum()
        print(f"    {src:>10}: F1={f1:.3f} AUC={auc:.3f} (n={len(src_y)}, TP={n_tp}, FP={n_fp})")


# ── Main ──

def main():
    parser = argparse.ArgumentParser(description="Train pwnkit triage classifier v2")
    parser.add_argument(
        "--dataset",
        default="packages/benchmark/results/triage-dataset-v2.jsonl",
        help="Path to JSONL training dataset",
    )
    parser.add_argument(
        "--output",
        default="packages/benchmark/results",
        help="Output directory for model + metadata",
    )
    parser.add_argument("--folds", type=int, default=5, help="Number of CV folds")
    args = parser.parse_args()

    # Load data
    df = load_dataset(args.dataset)
    X = extract_features(df)
    y = df["label"].values.astype(int)

    # Train XGBoost v2
    results = train_xgboost_cv(X, y, n_folds=args.folds)

    # Threshold optimization
    thresholds = optimize_thresholds(y, results["all_probs"])

    # Per-source breakdown
    evaluate_per_source(df, results["all_probs"])

    # Feature importance
    importance_df = compute_feature_importance(results["models"], FEATURE_NAMES)
    print(f"\n  Top 15 features:")
    for _, row in importance_df.head(15).iterrows():
        bar = "█" * int(row["importance"] * 200)
        print(f"    {row['feature']:>45}: {row['importance']:.4f} {bar}")

    # Dynamic routing model (if enough layer verdict data)
    layer_verdicts = df["layer_verdicts"].tolist() if "layer_verdicts" in df.columns else []
    router_result = train_dynamic_router(X, y, layer_verdicts, FEATURE_NAMES)

    # Train final model on all data
    print(f"\n  Training final model on all {len(y)} samples...")
    sample_weights = compute_sample_weight("balanced", y)
    final_model = xgb.XGBClassifier(**results["params"])
    final_model.fit(X, y, sample_weight=sample_weights, verbose=False)

    # Export
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    model_path = output_dir / "triage-router-v2.json"
    export_xgboost_model(final_model, str(model_path))

    importance_path = output_dir / "feature_importance_v2.csv"
    importance_df.to_csv(importance_path, index=False)
    print(f"  Feature importance saved to {importance_path}")

    # Save metadata
    meta = {
        "version": "v2",
        "n_samples": len(y),
        "n_features": X.shape[1],
        "n_tp": int(y.sum()),
        "n_fp": int(len(y) - y.sum()),
        "cv_folds": args.folds,
        "cv_metrics": {
            "mean_f1": results["mean_f1"],
            "std_f1": results["std_f1"],
            "mean_precision": results["mean_precision"],
            "mean_recall": results["mean_recall"],
            "mean_auc": results["mean_auc"],
        },
        "thresholds": thresholds,
        "feature_names": FEATURE_NAMES[:X.shape[1]],
        "params": {k: v for k, v in results["params"].items() if k != "random_state"},
        "dynamic_router": {
            "available": router_result is not None,
            "layers_trained": router_result["layer_names"] if router_result else [],
        },
    }

    meta_path = output_dir / "triage-router-v2-meta.json"
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"  Metadata saved to {meta_path}")

    # Compare with v1
    v1_path = output_dir / "triage-router-v1.json"
    if v1_path.exists():
        print(f"\n{'='*60}")
        print(f"Comparison: v1 vs v2")
        print(f"{'='*60}")
        print(f"  v1: F1=0.944 (45 features, 100 trees)")
        print(f"  v2: F1={results['mean_f1']:.3f}±{results['std_f1']:.3f} ({X.shape[1]} features, {results['params']['n_estimators']} trees)")
        delta = results["mean_f1"] - 0.944
        print(f"  Delta: {'+' if delta >= 0 else ''}{delta:.3f}")

    print(f"\nDone.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
LLM vs XGBoost triage benchmark — head-to-head comparison.

Takes a held-out test set of labeled findings and asks each LLM:
"Is this finding a true positive or false positive?"

Compares accuracy, F1, precision, recall, latency, and cost against
the XGBoost v2 router (F1=0.962, 0ms, $0).

Usage:
    python3 llm_triage_benchmark.py \
        --dataset ../results/triage-dataset-v2.jsonl \
        --models gpt-5.4,gpt-5.4-mini,gpt-4o \
        --test-size 200 \
        --output ../results/llm-triage-benchmark.json
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score


TRIAGE_PROMPT = """You are a security vulnerability triage expert. Analyze the following vulnerability finding and determine if it is a TRUE POSITIVE (real vulnerability) or FALSE POSITIVE (not a real vulnerability, benign behavior, or test artifact).

FINDING:
Title: {title}
Category: {category}
Severity: {severity}
Confidence: {confidence}

Description:
{description}

Evidence (request):
{request}

Evidence (response):
{response}

Analysis:
{analysis}

Respond with ONLY one of these two words: TRUE_POSITIVE or FALSE_POSITIVE
Do not explain your reasoning. Just the label."""


def call_azure_responses(model: str, prompt: str, api_key: str, base_url: str) -> tuple[str, float, float]:
    """Call Azure OpenAI Responses API and return (response, latency_ms, cost_usd)."""
    from urllib.request import Request, urlopen

    url = f"{base_url}/responses"

    body = json.dumps({
        "model": model,
        "input": prompt,
        "max_output_tokens": 20,
        "temperature": 0,
    }).encode()

    req = Request(
        url,
        data=body,
        headers={
            "api-key": api_key,
            "Content-Type": "application/json",
        },
    )

    start = time.time()
    resp = urlopen(req, timeout=60)
    latency_ms = (time.time() - start) * 1000
    result = json.loads(resp.read())

    # Responses API returns output array
    text = ""
    for item in result.get("output", []):
        if item.get("type") == "message":
            for content in item.get("content", []):
                if content.get("type") == "output_text":
                    text += content.get("text", "")

    usage = result.get("usage", {})
    input_tokens = usage.get("input_tokens", 0)
    output_tokens = usage.get("output_tokens", 0)

    # Azure cost estimation
    cost_per_1k_input = {
        "gpt-5.4": 0.005, "gpt-5.4-mini": 0.001, "gpt-5.4-nano": 0.0003,
        "gpt-4o": 0.0025, "gpt-4o-mini": 0.00015,
    }.get(model, 0.005)
    cost_per_1k_output = cost_per_1k_input * 4

    cost = (input_tokens * cost_per_1k_input + output_tokens * cost_per_1k_output) / 1000

    return text.strip(), latency_ms, cost


def call_openai(model: str, prompt: str, api_key: str) -> tuple[str, float, float]:
    """Call OpenAI API (direct, non-Azure) and return (response, latency_ms, cost_usd)."""
    from urllib.request import Request, urlopen

    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 10,
        "temperature": 0,
    }).encode()

    req = Request(
        "https://api.openai.com/v1/chat/completions",
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )

    start = time.time()
    resp = urlopen(req, timeout=30)
    latency_ms = (time.time() - start) * 1000
    result = json.loads(resp.read())

    text = result["choices"][0]["message"]["content"].strip()
    usage = result.get("usage", {})
    input_tokens = usage.get("prompt_tokens", 0)
    output_tokens = usage.get("completion_tokens", 0)

    cost_per_1k_input = {
        "gpt-5.4": 0.005, "gpt-5.4-mini": 0.001, "gpt-5.4-nano": 0.0003,
        "gpt-5.4-pro": 0.01, "gpt-4o": 0.0025, "gpt-4o-mini": 0.00015,
        "o3": 0.01, "o3-mini": 0.001, "o4-mini": 0.001,
    }.get(model, 0.005)
    cost_per_1k_output = cost_per_1k_input * 4

    cost = (input_tokens * cost_per_1k_input + output_tokens * cost_per_1k_output) / 1000

    return text, latency_ms, cost


def parse_llm_verdict(text: str) -> int | None:
    """Parse LLM response to 1 (TP) or 0 (FP)."""
    text = text.strip().upper()
    if "TRUE_POSITIVE" in text or "TRUE POSITIVE" in text:
        return 1
    if "FALSE_POSITIVE" in text or "FALSE POSITIVE" in text:
        return 0
    # Fuzzy: just TP/FP
    if text.startswith("TP") or text == "TRUE":
        return 1
    if text.startswith("FP") or text == "FALSE":
        return 0
    return None


def load_and_split(dataset_path: str, test_size: int, seed: int = 42):
    """Load dataset and create stratified test split."""
    records = []
    with open(dataset_path) as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    labels = [r["label"] for r in records]

    # Stratified split
    if test_size >= len(records):
        test_indices = list(range(len(records)))
    else:
        _, test_indices = train_test_split(
            range(len(records)), test_size=test_size,
            stratify=labels, random_state=seed,
        )

    test_set = [records[i] for i in test_indices]
    test_labels = [r["label"] for r in test_set]

    print(f"Test set: {len(test_set)} samples")
    print(f"  TP: {sum(test_labels)}, FP: {len(test_labels) - sum(test_labels)}")

    return test_set


def evaluate_xgboost(test_set: list, model_path: str) -> dict:
    """Evaluate XGBoost on the test set."""
    import xgboost as xgb

    model = xgb.XGBClassifier()
    model.load_model(model_path)

    def pad_features(feat_list):
        if len(feat_list) < 55:
            return feat_list + [0.0] * (55 - len(feat_list))
        return feat_list[:55]

    X = np.array([pad_features(r["features"]) for r in test_set])
    y = np.array([r["label"] for r in test_set])

    start = time.time()
    probs = model.predict_proba(X)[:, 1]
    preds = (probs >= 0.5).astype(int)
    total_ms = (time.time() - start) * 1000

    return {
        "model": "xgboost-v2",
        "f1": float(f1_score(y, preds)),
        "precision": float(precision_score(y, preds, zero_division=0)),
        "recall": float(recall_score(y, preds)),
        "accuracy": float(accuracy_score(y, preds)),
        "total_latency_ms": total_ms,
        "avg_latency_ms": total_ms / len(test_set),
        "total_cost_usd": 0.0,
        "avg_cost_usd": 0.0,
        "n_samples": len(test_set),
        "n_unparseable": 0,
    }


def evaluate_llm(
    test_set: list, model: str, api_key: str,
    max_samples: int | None = None,
    azure_base_url: str | None = None,
) -> dict:
    """Evaluate an LLM on the test set."""
    samples = test_set[:max_samples] if max_samples else test_set
    y_true = []
    y_pred = []
    latencies = []
    costs = []
    unparseable = 0
    errors = 0

    for i, rec in enumerate(samples):
        # Parse finding text back into components
        text = rec.get("text", "")
        parts = text.split("\n", 5)
        title = parts[0] if len(parts) > 0 else ""
        category = parts[1] if len(parts) > 1 else ""
        severity = parts[2] if len(parts) > 2 else ""

        prompt = TRIAGE_PROMPT.format(
            title=title,
            category=category,
            severity=severity,
            confidence=rec.get("confidence", 0.5),
            description=text[:500],
            request=text[500:1000] if len(text) > 500 else "",
            response=text[1000:1500] if len(text) > 1000 else "",
            analysis=text[1500:2000] if len(text) > 1500 else "",
        )

        try:
            if azure_base_url:
                response, latency, cost = call_azure_responses(model, prompt, api_key, azure_base_url)
            else:
                response, latency, cost = call_openai(model, prompt, api_key)
            verdict = parse_llm_verdict(response)

            if verdict is None:
                unparseable += 1
                # Default to TP (majority class) for unparseable
                verdict = 1
                print(f"  [{i+1}/{len(samples)}] {model}: unparseable: '{response[:50]}'", file=sys.stderr)
            else:
                print(f"  [{i+1}/{len(samples)}] {model}: {response[:20]} ({latency:.0f}ms)", file=sys.stderr)

            y_true.append(rec["label"])
            y_pred.append(verdict)
            latencies.append(latency)
            costs.append(cost)

        except Exception as e:
            errors += 1
            print(f"  [{i+1}/{len(samples)}] {model}: ERROR: {e}", file=sys.stderr)
            # Skip this sample
            continue

        # Rate limit
        time.sleep(0.1)

    if not y_true:
        return {"model": model, "error": f"all {errors} requests failed"}

    y_true = np.array(y_true)
    y_pred = np.array(y_pred)

    return {
        "model": model,
        "f1": float(f1_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "total_latency_ms": sum(latencies),
        "avg_latency_ms": np.mean(latencies) if latencies else 0,
        "total_cost_usd": sum(costs),
        "avg_cost_usd": np.mean(costs) if costs else 0,
        "n_samples": len(y_true),
        "n_unparseable": unparseable,
        "n_errors": errors,
    }


def main():
    parser = argparse.ArgumentParser(description="LLM vs XGBoost triage benchmark")
    parser.add_argument("--dataset", default="packages/benchmark/results/triage-dataset-v2.jsonl")
    parser.add_argument("--models", default="gpt-5.4-mini,gpt-4o-mini", help="Comma-separated model names")
    parser.add_argument("--test-size", type=int, default=100, help="Number of test samples")
    parser.add_argument("--max-llm-samples", type=int, default=None, help="Cap LLM eval samples (for cost control)")
    parser.add_argument("--output", default="packages/benchmark/results/llm-triage-benchmark.json")
    parser.add_argument("--xgboost-model", default="packages/benchmark/results/triage-router-v2.json")
    args = parser.parse_args()

    # Azure OpenAI — read base_url from ~/.codex/config.toml or env
    azure_base_url = os.environ.get("AZURE_OPENAI_BASE_URL")
    if not azure_base_url:
        codex_config = Path.home() / ".codex" / "config.toml"
        if codex_config.exists():
            import re
            config_text = codex_config.read_text()
            azure_section = re.search(r'\[model_providers\.azure\]([\s\S]*?)(?:\n\[|$)', config_text)
            if azure_section:
                url_match = re.search(r'base_url\s*=\s*"([^"]+)"', azure_section.group(1))
                if url_match:
                    azure_base_url = url_match.group(1)
                    print(f"  Azure base URL from ~/.codex/config.toml: {azure_base_url}", file=sys.stderr)
    api_key = os.environ.get("AZURE_OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("ERROR: AZURE_OPENAI_API_KEY or OPENAI_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    use_azure = bool(os.environ.get("AZURE_OPENAI_API_KEY"))

    # Load test set
    test_set = load_and_split(args.dataset, args.test_size)

    results = []

    # XGBoost baseline
    print(f"\n{'='*60}")
    print("Evaluating XGBoost v2 (baseline)")
    print(f"{'='*60}")
    xgb_result = evaluate_xgboost(test_set, args.xgboost_model)
    results.append(xgb_result)
    print(f"  F1={xgb_result['f1']:.3f} Prec={xgb_result['precision']:.3f} Rec={xgb_result['recall']:.3f}")
    print(f"  Latency: {xgb_result['avg_latency_ms']:.1f}ms/sample, Cost: $0")

    # LLM models
    models = [m.strip() for m in args.models.split(",")]
    for model in models:
        print(f"\n{'='*60}")
        print(f"Evaluating {model}")
        print(f"{'='*60}")
        llm_result = evaluate_llm(
            test_set, model, api_key,
            max_samples=args.max_llm_samples,
            azure_base_url=azure_base_url if use_azure else None,
        )
        results.append(llm_result)
        if "error" not in llm_result:
            print(f"  F1={llm_result['f1']:.3f} Prec={llm_result['precision']:.3f} Rec={llm_result['recall']:.3f}")
            print(f"  Latency: {llm_result['avg_latency_ms']:.0f}ms/sample, Cost: ${llm_result['total_cost_usd']:.4f}")

    # Summary table
    print(f"\n{'='*60}")
    print("RESULTS SUMMARY")
    print(f"{'='*60}")
    print(f"{'Model':<20} {'F1':>6} {'Prec':>6} {'Rec':>6} {'ms/sample':>10} {'$/sample':>10}")
    print("-" * 60)
    for r in results:
        if "error" in r:
            print(f"{r['model']:<20} ERROR: {r['error']}")
            continue
        print(f"{r['model']:<20} {r['f1']:>6.3f} {r['precision']:>6.3f} {r['recall']:>6.3f} {r['avg_latency_ms']:>9.0f} {r['avg_cost_usd']:>10.6f}")

    # Save
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({"results": results, "test_size": len(test_set)}, f, indent=2)
    print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    main()

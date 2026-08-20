#!/usr/bin/env python3
"""Fail-closed kernelCTF candidate eligibility preflight."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def _config(path: Path) -> dict[str, bool]:
    result: dict[str, bool] = {}
    for line in path.read_text().splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            result[key] = value == "y"
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            result[line[2 : -len(" is not set")]] = False
    return result


def evaluate(
    candidate: dict[str, Any], target: dict[str, Any], config: dict[str, bool]
) -> list[str]:
    failures: list[str] = []
    if target.get("slot_status") != "free":
        failures.append(f"target slot is {target.get('slot_status', 'unknown')}")
    if not target.get("release") or not target.get("commit_hash"):
        failures.append("target release or commit hash is missing")

    runtime = target.get("runtime_policy")
    if not isinstance(runtime, dict):
        failures.append("target runtime policy is missing")
        runtime = {}
    for feature in ("unprivileged_userns", "io_uring", "nftables"):
        if runtime.get(feature) is not False:
            failures.append(f"target runtime policy does not confirm {feature}=false")
        if candidate.get(f"requires_{feature}") is not False:
            failures.append(f"candidate does not confirm requires_{feature}=false")

    required = candidate.get("required_config")
    if not isinstance(required, list):
        failures.append("candidate required_config must be a list")
    else:
        for symbol in required:
            if not isinstance(symbol, str) or not symbol.startswith("CONFIG_"):
                failures.append(f"invalid required config symbol: {symbol!r}")
            elif config.get(symbol) is not True:
                failures.append(f"required target config is disabled or absent: {symbol}")

    reliability = candidate.get("reliability_percent")
    if not isinstance(reliability, (int, float)) or reliability < 10:
        failures.append("measured reliability is below 10% or missing")
    runtime_seconds = candidate.get("runtime_seconds")
    if not isinstance(runtime_seconds, (int, float)) or runtime_seconds > 300:
        failures.append("measured runtime exceeds 300 seconds or is missing")
    if candidate.get("stole_flag") is not True:
        failures.append("flag capture is not confirmed")
    if candidate.get("kernelxdk_ready") is not True:
        failures.append("kernelXDK readiness is not confirmed")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=Path)
    parser.add_argument("target", type=Path)
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    candidate = _load_object(args.candidate)
    target = _load_object(args.target)
    failures = evaluate(candidate, target, _config(args.config))
    print(json.dumps({"eligible": not failures, "failures": failures}, indent=2, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())

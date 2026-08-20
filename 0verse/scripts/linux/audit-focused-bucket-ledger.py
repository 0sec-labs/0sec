#!/usr/bin/env python3
"""Require every focused syzkaller crash bucket to have an explicit disposition."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

BUCKET_ID = re.compile(r"[0-9a-f]{40}")
CLASSIFICATIONS = {
    "candidate",
    "candidate-alias",
    "infrastructure",
    "known-duplicate",
    "negative",
    "quarantined",
}
REPRODUCTION_RESULTS = {"exact-title", "unreproduced", "wrong-title"}


def load_ledger(path: Path) -> dict[str, dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema") != 1:
        raise ValueError("unsupported or malformed ledger schema")
    buckets = document.get("buckets")
    if not isinstance(buckets, dict):
        raise ValueError("ledger buckets must be an object")
    for bucket_id, record in buckets.items():
        if not BUCKET_ID.fullmatch(bucket_id) or not isinstance(record, dict):
            raise ValueError(f"malformed ledger bucket: {bucket_id!r}")
        if record.get("classification") not in CLASSIFICATIONS:
            raise ValueError(f"invalid classification for {bucket_id}")
        descriptions = record.get("descriptions")
        if (
            not isinstance(descriptions, list)
            or not descriptions
            or any(not isinstance(item, str) or not item for item in descriptions)
        ):
            raise ValueError(f"invalid descriptions for {bucket_id}")
        if not isinstance(record.get("rationale"), str) or not record["rationale"]:
            raise ValueError(f"missing rationale for {bucket_id}")
        reproduction = record.get("reproduction")
        if reproduction is not None:
            if not isinstance(reproduction, dict):
                raise ValueError(f"invalid reproduction record for {bucket_id}")
            result = reproduction.get("result")
            expected = reproduction.get("expected_title")
            observed = reproduction.get("observed_title")
            if result not in REPRODUCTION_RESULTS or expected not in descriptions:
                raise ValueError(f"invalid reproduction result for {bucket_id}")
            if result == "unreproduced" and observed is not None:
                raise ValueError(f"unreproduced bucket has observed title: {bucket_id}")
            if result == "exact-title" and observed != expected:
                raise ValueError(f"exact-title reproduction mismatch for {bucket_id}")
            if result == "wrong-title":
                if not isinstance(observed, str) or not observed or observed == expected:
                    raise ValueError(f"invalid wrong-title reproduction for {bucket_id}")
                if record["classification"] not in {"candidate", "candidate-alias"}:
                    raise ValueError(
                        "wrong-title reproduction cannot disposition exact-title bucket: "
                        f"{bucket_id}"
                    )
    return buckets


def audit(
    ledger: dict[str, dict[str, Any]], workdirs: list[Path]
) -> tuple[list[str], Counter[str]]:
    errors: list[str] = []
    counts: Counter[str] = Counter()
    observed_ids: set[str] = set()
    for workdir in workdirs:
        for description_path in sorted((workdir / "crashes").glob("*/description")):
            bucket_id = description_path.parent.name
            description = " ".join(
                description_path.read_text(encoding="utf-8", errors="replace").split()
            )
            observed_ids.add(bucket_id)
            record = ledger.get(bucket_id)
            if record is None:
                errors.append(f"UNCLASSIFIED {workdir.name}/{bucket_id}: {description}")
                continue
            if description not in record["descriptions"]:
                errors.append(f"RETITLED {workdir.name}/{bucket_id}: {description}")
                continue
            counts[record["classification"]] += 1

    stale = sorted(set(ledger) - observed_ids)
    for bucket_id in stale:
        errors.append(f"STALE_LEDGER {bucket_id}")
    return errors, counts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("workdirs", nargs="+", type=Path)
    args = parser.parse_args()
    ledger = load_ledger(args.ledger)
    errors, counts = audit(ledger, args.workdirs)
    if errors:
        print("\n".join(errors))
        return 1
    summary = " ".join(f"{key}={counts[key]}" for key in sorted(counts))
    print(f"OK occurrences={sum(counts.values())} unique={len(ledger)} {summary}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR {error}", file=sys.stderr)
        sys.exit(2)

#!/usr/bin/env python3
"""Rank exact-build hypercall handlers for manual embedded-address review.

This is a triage heuristic, not a vulnerability detector. It correlates an
already extracted descriptor table with an already generated 0verse/Ghidra
cache and never executes the target binary.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


_PARAM_REF = re.compile(r"\bparam_1(?:\s*\[|\s*\+|\b)")
_WIDE_LOAD = re.compile(
    r"\*\s*\(\s*(?:u?longlong|undefined8)\s*\*\s*\)\s*\(\s*param_1\s*\+"
)
_INDEXED_LOAD = re.compile(r"\bparam_1\s*\[[^]]+\]")
_PAGE_OP = re.compile(
    r"(?:0x[fF]{3}(?![0-9a-fA-F])|0x1000(?![0-9a-fA-F])|>>\s*0xc\b|<<\s*0xc\b)"
)
_CALL_WITH_INPUT = re.compile(r"FUN_[0-9a-fA-F]+\s*\([^;\n]*\bparam_1\b")


def rank_handlers(
    descriptors: list[dict[str, object]], decompiled: dict[str, str]
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for descriptor in descriptors:
        if int(descriptor["fixed_input_size"]) < 8:
            continue
        handler_va = int(descriptor["handler_va"])
        handler = f"FUN_{handler_va:016x}"
        source = decompiled.get(handler, "")
        if not source:
            continue
        param_refs = len(_PARAM_REF.findall(source))
        wide_loads = len(_WIDE_LOAD.findall(source))
        indexed_loads = len(_INDEXED_LOAD.findall(source))
        page_ops = len(_PAGE_OP.findall(source))
        calls_with_input = len(_CALL_WITH_INPUT.findall(source))
        if param_refs < 2 or not (wide_loads or indexed_loads or page_ops or calls_with_input):
            continue
        score = (
            min(param_refs, 8)
            + 3 * min(wide_loads, 4)
            + 2 * min(indexed_loads, 4)
            + 3 * min(page_ops, 4)
            + 2 * min(calls_with_input, 4)
        )
        results.append(
            {
                "call_code": int(descriptor["call_code"]),
                "handler": handler,
                "fixed_input_size": int(descriptor["fixed_input_size"]),
                "fixed_output_size": int(descriptor["fixed_output_size"]),
                "flags": int(descriptor["flags"]),
                "score": score,
                "signals": {
                    "param_refs": param_refs,
                    "wide_loads": wide_loads,
                    "indexed_loads": indexed_loads,
                    "page_ops": page_ops,
                    "calls_with_input": calls_with_input,
                },
            }
        )
    return sorted(results, key=lambda item: (-int(item["score"]), int(item["call_code"])))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("descriptor_json", type=Path)
    parser.add_argument("ghidra_cache", type=Path)
    parser.add_argument("--limit", type=int, default=25)
    parser.add_argument("--exclude", action="append", default=[], type=lambda value: int(value, 0))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.limit < 1:
        parser.error("--limit must be positive")

    descriptor_document = json.loads(args.descriptor_json.read_text())
    cache = json.loads(args.ghidra_cache.read_text())
    decompiled = cache.get("meta", {}).get("decompiled_c", {})
    if not isinstance(descriptor_document.get("descriptors"), list):
        raise SystemExit("descriptor JSON has no descriptors array")
    if not isinstance(decompiled, dict):
        raise SystemExit("Ghidra cache has no meta.decompiled_c mapping")

    excluded = set(args.exclude)
    ranked = [
        item
        for item in rank_handlers(descriptor_document["descriptors"], decompiled)
        if int(item["call_code"]) not in excluded
    ][: args.limit]
    if args.json:
        print(json.dumps(ranked, indent=2, sort_keys=True))
    else:
        print("call\tscore\thandler\tin\tout\tflags\tsignals")
        for item in ranked:
            signals = ",".join(f"{key}={value}" for key, value in item["signals"].items())
            print(
                f"0x{int(item['call_code']):x}\t{item['score']}\t{item['handler']}\t"
                f"{item['fixed_input_size']}\t{item['fixed_output_size']}\t"
                f"0x{int(item['flags']):x}\t{signals}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

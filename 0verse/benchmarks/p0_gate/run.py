#!/usr/bin/env python3
"""P0 gate known-CVE reproducibility eval — stripped x86-64 Linux ELF via local dynamic oracle.

OPERATOR-GATED INVOCATION (after approved artifact staging):
  # Step 1 — Preflight: verify every binary digest matches the manifest
  python benchmarks/p0_gate/run.py --manifest benchmarks/p0_gate/manifest.json

  # Step 2 — Full eval: invoke local oracle against staged artifacts
  python benchmarks/p0_gate/run.py --manifest benchmarks/p0_gate/manifest.json \\
      --artifact-dir /path/to/staged/binaries \\
      --oracle /path/to/oracle.sh \\
      --out results/p0_gate/results.json \\
      --eval

  # Step 3 — Re-read cached results (no oracle invocation)
  python benchmarks/p0_gate/run.py --manifest benchmarks/p0_gate/manifest.json \\
      --report results/p0_gate/results.json

The --eval flag gates oracle execution. Without it, the runner performs a
read-only preflight (digest verification only). No network targets are
fetched by default.

Oracle contract: the --oracle script receives (binary_path, trigger_input_path)
as argv[1] and argv[2], and prints a single JSON object to stdout with keys:
    outcome: "reach" | "confirmed" | "refuted" | "inconclusive"
    ran: bool
    expected_path_reached: bool
    crash_signal: str (empty if none)
    stderr_hint: str (oracle output, e.g. ASan report snippet)
    error: str (runtime error message, empty if OK)

The runner enforces the static-only honesty gate via
``p0gate.serialize_results()`` — no binary ever consumes a static hypothesis as
confirmation, regardless of oracle output.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from zeroverse import p0gate  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="P0 gate known-CVE reproducibility eval",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "EXAMPLES\n"
            "  Preflight (default, no oracle):\n"
            "    run.py --manifest manifest.json\n\n"
            "  Full eval (--eval gates oracle execution):\n"
            "    run.py --manifest manifest.json --artifact-dir ./binaries \\\n"
            "        --oracle ./oracle.sh --eval --out results.json\n\n"
            "NOTE: --eval is REQUIRED for oracle invocation. Without it,\n"
            "only the preflight digest check runs."
        ),
    )
    ap.add_argument("--manifest", default=str(HERE / "manifest.json"))
    ap.add_argument("--out", default=str(HERE / "results.json"))
    ap.add_argument("--artifact-dir", default=None)
    ap.add_argument("--oracle", default=None)
    ap.add_argument("--eval", action="store_true",
                    help="ENABLE oracle execution (gated flag)")
    ap.add_argument("--report", default=None,
                    help="path to cached results JSON to re-format")
    return ap.parse_args(argv)


def run_oracle(oracle_script: str, binary_path: str,
               trigger_input: str) -> dict[str, Any]:
    """Invoke the oracle subprocess and return its result dict."""
    try:
        # `--eval` is an explicit local-operator action; this is a structured
        # argv invocation and never passes input through a shell.
        result = subprocess.run(  # foxguard: ignore[py/no-command-injection]
            [oracle_script, binary_path, trigger_input],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            return {
                "outcome": "inconclusive",
                "ran": True,
                "expected_path_reached": False,
                "crash_signal": "",
                "stderr_hint": result.stderr[:500],
                "error": f"oracle exit code {result.returncode}",
            }
        parsed = json.loads(result.stdout)
        parsed.setdefault("ran", True)
        return parsed
    except FileNotFoundError:
        return {
            "outcome": "inconclusive",
            "ran": False,
            "expected_path_reached": False,
            "crash_signal": "",
            "stderr_hint": "",
            "error": f"oracle script not found: {oracle_script}",
        }
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return {
            "outcome": "inconclusive",
            "ran": True,
            "expected_path_reached": False,
            "crash_signal": "",
            "stderr_hint": str(exc),
            "error": str(exc),
        }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"manifest not found: {manifest_path}", file=sys.stderr)
        return 2

    try:
        manifest = p0gate.load_manifest(str(manifest_path))
    except ValueError as exc:
        print(f"invalid manifest: {exc}", file=sys.stderr)
        return 2
    artifact_dir = Path(args.artifact_dir) if args.artifact_dir else manifest_path.parent

    # -- Report mode: reformat cached results.
    if args.report:
        report_path = Path(args.report)
        if not report_path.exists():
            print(f"cached results not found: {report_path}", file=sys.stderr)
            return 2
        payload = json.loads(report_path.read_text())
        n = len(payload.get("results", []))
        confirmed = sum(
            1 for r in payload.get("results", [])
            if r.get("observed", {}).get("outcome") == "confirmed"
        )
        fps = sum(
            1 for r in payload.get("results", [])
            if r.get("observed", {}).get("outcome") == "confirmed"
            and r.get("label") == "clean"
        )
        print(f"P0 gate report from {report_path}")
        print(f"  Items: {n}  Confirmed: {confirmed}  False positives: {fps}")
        print(f"  Generated: {payload.get('generated_at', 'unknown')}")
        return 0

    # -- Preflight: verify digests.
    print(f"P0 gate eval: {len(manifest.items)} items")
    ok = 0
    fail = 0
    for item in manifest.items:
        if not item.target_artifact:
            print(f"  [{item.id}] SKIP — no target_artifact")
            fail += 1
            continue
        binary_path = artifact_dir / item.target_artifact
        if not binary_path.exists():
            print(f"  [{item.id}] SKIP — binary not found at {binary_path}")
            fail += 1
            continue
        errs = p0gate.verify_target_digest(artifact_dir, item)
        if errs:
            for e in errs:
                print(f"  [{item.id}] FAIL — {e}")
            fail += 1
        else:
            print(f"  [{item.id}] OK — digest matches")
            ok += 1

    print(f"Preflight: {ok} passing, {fail} failing "
          f"(total {len(manifest.items)})")
    if fail:
        print("One or more digest checks failed. Aborting.", file=sys.stderr)
        return 1

    # -- Eval gate: only run oracle if explicitly enabled.
    results: list[p0gate.P0GateResult] = []
    if args.eval:
        if not args.oracle:
            print("--eval requires --oracle <script>", file=sys.stderr)
            return 2
        if not Path(args.oracle).exists():
            print(f"oracle script not found: {args.oracle}", file=sys.stderr)
            return 2

        env = p0gate.Environment.capture()
        t_start = time.monotonic()
        for item in manifest.items:
            binary_path = str(artifact_dir / (item.target_artifact or item.id))
            trigger_path = str(artifact_dir / item.oracle.trigger_input)
            oracle_result = run_oracle(args.oracle, binary_path, trigger_path)
            binary_digest = p0gate.digest_binary(binary_path)
            tool_digest = p0gate.ToolDigest(version="0.0.1")
            or_result = p0gate.OracleResult(**oracle_result)
            result = p0gate.P0GateResult(
                item_id=item.id,
                cve=item.cve,
                label=item.label,
                observed=or_result,
                binary=binary_digest,
                tool=tool_digest,
                environment=env,
                wall_s=round(time.monotonic() - t_start, 1),
            )
            results.append(result)
            print(f"  [{item.id}] outcome={or_result.outcome} "
                  f"{'' if or_result.ran else '(no-oracle)'}")
            t_start = time.monotonic()

        fp_count = p0gate.count_false_positives(results, manifest.items)
        for r in results:
            r.false_positive_count = fp_count

        p0gate.serialize_results(results, args.out)
        print(f"\nResults written to {args.out}")

        # Honesty gate: verify no static-only confirmed in output.
        payload = json.loads(Path(args.out).read_text(encoding="utf-8"))
        for rd in payload.get("results", []):
            obs = rd.get("observed", {})
            if obs.get("outcome") == "confirmed" and not obs.get("ran", False):
                print(f"HONESTY VIOLATION: result for {rd['item_id']} has "
                      "confirmed without oracle run.", file=sys.stderr)
                return 3
        print("Honesty gate: all results correct.")
    else:
        print("\n--eval not set. Oracle NOT invoked (preflight-only).")
        print("To run the full evaluation: add --eval --oracle <script>")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
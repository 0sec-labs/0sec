#!/usr/bin/env python3
"""Honest end-to-end evaluation of 0verse with a REAL model (not MockLLM).

Runs the FULL pipeline over a labeled corpus twice per target — once with the
deterministic ``MockLLM`` (the static-lenses-only baseline) and once with the live
``CodexOAuthLLM`` (gpt-5.5 over the ChatGPT-OAuth Responses API) — and measures,
with NO cherry-picking:

  * confirmed PoVs vs hypotheses, per target and per bug class,
  * false positives on CLEAN binaries (confirmed PoV on known-good == a bug),
  * hypothesis noise on clean code (does the model reject guarded paths?),
  * wall-time and token volume per target (where the model earns its latency),
  * harness-synth compile-success: real-LLM synthesis vs the deterministic
    template, with the repair loop iterating on real compiler errors.

Usage (inside the engine venv, with GHIDRA_INSTALL_DIR set and ~/.codex/auth.json
present):  python benchmarks/llm_eval.py [--out results.json]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "src"))

from zeroverse import pipeline  # noqa: E402
from zeroverse.agent import MockLLM  # noqa: E402
from zeroverse.fuzz.harness import (  # noqa: E402
    GccCompiler,
    HarnessSpec,
    HarnessSynthesizer,
    build_harness,
    recover_signature,
)
from zeroverse.llm.codex_llm import CodexOAuthLLM  # noqa: E402

# name | compile flags | label ("clean" or the expected CWE class)
VULN = [
    ("cmdi", [], "CWE-78 command-injection"),
    ("overflow", ["-fno-stack-protector", "-no-pie"], "CWE-120 stack-overflow"),
    ("fmtstring", [], "CWE-134 format-string"),
    ("intoverflow", [], "CWE-190 integer-overflow"),
    ("uaf", [], "CWE-416 use-after-free"),
    ("auth_bypass", [], "CWE-287 logic (hypothesis-only)"),
]
CLEAN_SRC = [
    ("clean_safe_malloc", []),
    ("clean_bounded_copy", ["-fno-stack-protector", "-no-pie"]),
]
CLEAN_BIN = ["/usr/bin/true"]   # a real, known-good coreutils binary


@dataclass
class TargetResult:
    name: str
    label: str
    is_clean: bool
    n_findings: int = 0
    n_real: int = 0            # verdict.is_real (hypotheses)
    n_escalated: int = 0       # reached the LLM agent
    n_confirmed: int = 0       # reproduced PoV (PoV-is-truth)
    confirmed_classes: list[str] = field(default_factory=list)
    wall_s: float = 0.0
    in_tokens: int = 0
    out_tokens: int = 0
    error: str = ""


def _compile(name: str, flags: list[str], out: Path) -> Path:
    binp = out / name
    subprocess.run(
        ["cc", "-O0", *flags, str(HERE / f"{name}.c"), "-o", str(binp)],
        check=True, capture_output=True,
    )
    return binp


def _measure(binary: str, label: str, is_clean: bool, llm: object) -> TargetResult:
    r = TargetResult(name=Path(binary).name, label=label, is_clean=is_clean)
    snap_in = getattr(llm, "total_usage", {}).get("input_tokens", 0)
    snap_out = getattr(llm, "total_usage", {}).get("output_tokens", 0)
    t0 = time.perf_counter()
    try:
        rr = pipeline.run(binary, llm=llm)  # type: ignore[arg-type]
    except Exception as exc:  # the eval records failures, never hides them
        r.error = f"{type(exc).__name__}: {exc}"
        return r
    r.wall_s = round(time.perf_counter() - t0, 1)
    r.n_findings = len(rr.findings)
    for tf in rr.findings:
        if tf.verdict.is_real:
            r.n_real += 1
        if tf.escalated:
            r.n_escalated += 1
        if tf.pov and tf.pov.reproduced:
            r.n_confirmed += 1
            r.confirmed_classes.append(tf.verdict.bug_class)
    r.in_tokens = getattr(llm, "total_usage", {}).get("input_tokens", 0) - snap_in
    r.out_tokens = getattr(llm, "total_usage", {}).get("output_tokens", 0) - snap_out
    return r


def _harness_synth_eval(out: Path, real: CodexOAuthLLM) -> dict[str, object]:
    """Measure #16: real-LLM harness synthesis compile-success + repair iteration
    vs the deterministic template, on parse_record (the slice-blind fuzz target)."""
    src = (HERE / "parser.c").read_text()
    sig = recover_signature("parse_record", src)
    spec = HarnessSpec(func="parse_record", signature=sig, decompiled_c=src,
                       slice_context="length-prefixed copy into a 32-byte heap buffer")
    obj = out / "parser.o"
    subprocess.run(["cc", "-O0", "-c", str(HERE / "parser.c"), "-o", str(obj)],
                   check=True, capture_output=True)
    res: dict[str, object] = {}
    for tag, llm in (("template", None), ("real-llm", real)):
        wd = out / f"hs_{tag}"
        wd.mkdir(exist_ok=True)
        t0 = time.perf_counter()
        try:
            hb = build_harness(spec, synthesizer=HarnessSynthesizer(llm),
                               compiler=GccCompiler(), objects=[obj], workdir=wd,
                               max_repair=3, reach_check=False)
            res[tag] = {
                "compile_ok": hb.ok, "attempts": hb.attempts,
                "from_llm": hb.harness.from_llm, "notes": hb.harness.notes[:80],
                "wall_s": round(time.perf_counter() - t0, 1),
            }
        except Exception as exc:  # eval records failures, never hides them
            res[tag] = {"error": f"{type(exc).__name__}: {exc}"}
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(HERE / "llm_eval_results.json"))
    args = ap.parse_args()

    real = CodexOAuthLLM()
    rows: list[TargetResult] = []
    with __import__("tempfile").TemporaryDirectory() as td:
        out = Path(td)
        targets: list[tuple[str, str, bool]] = []
        for name, flags, label in VULN:
            targets.append((str(_compile(name, flags, out)), label, False))
        for name, flags in CLEAN_SRC:
            targets.append((str(_compile(name, flags, out)), "clean", True))
        for b in CLEAN_BIN:
            targets.append((b, "clean", True))

        for binary, label, is_clean in targets:
            for tag, llm in (("mock", MockLLM()), ("real", real)):
                row = _measure(binary, label, is_clean, llm)
                row.name = f"{row.name}[{tag}]"
                rows.append(row)
                print(f"  {row.name:32s} find={row.n_findings} real={row.n_real} "
                      f"esc={row.n_escalated} CONFIRMED={row.n_confirmed} "
                      f"{row.confirmed_classes} {row.wall_s}s "
                      f"tok={row.in_tokens}/{row.out_tokens} {row.error}")

        print("\n== harness-synth (#16) ==")
        hs = _harness_synth_eval(out, real)
        print(json.dumps(hs, indent=2))

    summary = _summarize(rows)
    print("\n== SUMMARY ==")
    print(json.dumps(summary, indent=2))
    Path(args.out).write_text(json.dumps(
        {"targets": [asdict(r) for r in rows], "harness_synth": hs, "summary": summary},
        indent=2,
    ))
    print(f"\nwrote {args.out}")
    return 0


def _summarize(rows: list[TargetResult]) -> dict[str, object]:
    def pick(tag: str, clean: bool) -> list[TargetResult]:
        return [r for r in rows if r.name.endswith(f"[{tag}]") and r.is_clean == clean]

    out: dict[str, object] = {}
    for tag in ("mock", "real"):
        vuln = pick(tag, False)
        clean = pick(tag, True)
        out[tag] = {
            "vuln_targets": len(vuln),
            "vuln_confirmed": sum(1 for r in vuln if r.n_confirmed > 0),
            "vuln_hypothesis_only": sum(1 for r in vuln if r.n_confirmed == 0 and r.n_real > 0),
            "clean_targets": len(clean),
            "clean_false_confirmed": sum(1 for r in clean if r.n_confirmed > 0),
            "clean_hypothesis_noise": sum(r.n_real for r in clean),
            "real_llm_out_tokens": sum(r.out_tokens for r in rows if r.name.endswith(f"[{tag}]")),
            "total_wall_s": round(sum(r.wall_s for r in rows if r.name.endswith(f"[{tag}]")), 1),
        }
    return out


if __name__ == "__main__":
    raise SystemExit(main())

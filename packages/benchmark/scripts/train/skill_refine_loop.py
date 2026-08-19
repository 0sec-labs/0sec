#!/usr/bin/env python3
"""
Skill self-improvement loop — a `/refine` flywheel for JIT skills.

This is the skill-side sibling of `active_learning_loop.py`. That loop closes
the feedback cycle for the triage *router* (operator labels -> retrain ->
A/B-gated promote). This loop closes the same cycle for the ONLY other already-
versioned, hot-loaded-from-disk surface 0sec has: the JIT methodology skills
(`packages/core/src/agent/skills/{frameworks,vulnerabilities,techniques}/*.yaml`,
loaded by `loadSkillRegistry()`; each has an integer `version`).

The idea (mirrors the dataset flywheel):
  1. Every scan attributes findings to the skill that was active — the agent
     emits `skill_preloaded` / `load_skill` events carrying a `skillId`
     (native-loop.ts / tools.ts).
  2. Operators triage findings TP/FP (`label_source == "human_review"`), and an
     inline oracle independently `confirmed`s exploitation
     (agent/inline-validation.ts).
  3. This loop joins finding -> active skill -> outcome, scores each skill's
     *verified* true-positive rate against the pooled baseline (the
     `evaluate_per_source` per-source breakdown from train_triage_v2.py, with
     skill-ID as the "source" dimension), and flags under-performing skills as
     refinement CANDIDATES.
  4. Every decision is appended to `skill-refine-ledger.json`. Nothing is ever
     rewritten autonomously.

REWARD CLAMP (reward-hacking guard) — the whole point:
    A finding counts toward a skill's score ONLY when the inline oracle
    `confirmed == true` AND the operator label is a true positive from
    `human_review`. `inconclusive` and unconfirmed findings are excluded from
    the numerator; a category with NO oracle coverage at all is INELIGIBLE and
    skipped entirely. This is deliberate: an unverified or self-reported success
    signal is exactly the surface a self-improving agent learns to game (the
    Factorio/RCON-style "maximize the metric, not the outcome" failure). By
    clamping reward to independently-verified exploitation we make the metric
    expensive to fake — a skill only looks good if it produced findings a
    separate oracle reproduced and a human confirmed.

SAFETY:
  * DRY-RUN by default. The loop reads data and appends ledger rows; it never
    writes a skill YAML.
  * `--promote` is required to ever write a YAML, AND a candidate must first
    pass a load-check via the runtime validator (`check_skill.mjs`, which reuses
    `loadSkillRegistry` — no duplicated validator). Promotion is operator-driven
    (an operator supplies the refined `--candidate-yaml` and `--operator`
    sign-off); the loop only gates it. There is no path from "flagged" to
    "written" without a human in the loop.

Usage:
    # analyse a labeled-trajectory dataset (dry-run, default)
    python3 skill_refine_loop.py --dataset results/skill-trajectories.jsonl

    # validate a candidate YAML with the runtime loader and exit
    python3 skill_refine_loop.py --check-skill path/to/candidate.yaml

    # gated promotion (operator-driven): flag must hold + load-check must pass
    python3 skill_refine_loop.py --dataset ... \
        --candidate-yaml refined.yaml --operator alice --promote

    # run the built-in fixtures (no pytest needed); exits non-zero on failure
    python3 skill_refine_loop.py --selftest

Exit codes:
    0  ran cleanly (analysed / held / promoted / selftest passed)
    2  not enough eligible data anywhere (dataset produced zero eligible skills)
    3  error (missing dataset, failed load-check on --promote, selftest failed)

Dataset row shape (superset of the triage-dataset row; extra fields are the
finding<->skill<->oracle join this loop needs — all optional with fallbacks):
    {
      "category": "sqli",                 # or parsed from a "Category:" line in text
      "skill_events": [                    # attribution events from the trajectory
        {"type": "skill_preloaded", "skillId": "sqli-advanced"},
        {"type": "load_skill",      "skillId": "sqli-advanced"}
      ],
      "active_skill_id": "sqli-advanced", # optional explicit override
      "inline_validation": {"confirmed": true, "inconclusive": false},
      "label": 1, "label_text": "true_positive",
      "label_source": "human_review",
      "source": "..."
    }
"""

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# scripts/train -> scripts -> benchmark
BENCH_ROOT = HERE.parent.parent
DEFAULT_LEDGER = BENCH_ROOT / "results" / "skill-refine-ledger.json"
CHECK_SCRIPT = HERE / "check_skill.mjs"

# Decision vocabulary written to the ledger.
DECISION_SKIPPED = "skipped_insufficient_data"
DECISION_FLAGGED = "candidate_flagged"
DECISION_WOULD_PROMOTE = "would_promote_dry_run"
DECISION_PROMOTED = "promoted"

TRUE_POSITIVE = "true_positive"
OPERATOR_LABEL_SOURCE = "human_review"


# ── Row normalisation ────────────────────────────────────────────────


def _parse_category(rec: dict) -> str:
    """Best-effort category for a finding row.

    Prefer an explicit `category` field; fall back to a `Category:` line inside
    the triage-dataset `text` blob (that's where the triage exporter puts it).
    """
    cat = rec.get("category")
    if isinstance(cat, str) and cat.strip():
        return cat.strip()
    text = rec.get("text")
    if isinstance(text, str):
        for line in text.splitlines():
            if line.lower().startswith("category:"):
                return line.split(":", 1)[1].strip()
    return "unknown"


def _active_skill_id(rec: dict) -> str | None:
    """The skill that was active when this finding was produced.

    Explicit `active_skill_id` wins; otherwise take the most-recent attribution
    event (`skill_preloaded` / `load_skill`, each carrying `skillId`). Single
    attribution keeps the baseline pool free of double-counting.
    """
    explicit = rec.get("active_skill_id")
    if isinstance(explicit, str) and explicit:
        return explicit
    events = rec.get("skill_events")
    if isinstance(events, list):
        last = None
        for ev in events:
            if not isinstance(ev, dict):
                continue
            if ev.get("type") in ("skill_preloaded", "load_skill"):
                sid = ev.get("skillId")
                if isinstance(sid, str) and sid:
                    last = sid
        return last
    return None


def _oracle(rec: dict) -> tuple[bool, bool]:
    """Return (confirmed, inconclusive) for the inline oracle verdict.

    Mirrors InlineValidationOutcome (agent/inline-validation.ts). Accepts either
    a nested `inline_validation` object or flat `oracle_*` fields. A row with no
    oracle information at all is treated as inconclusive=True (no coverage).
    """
    iv = rec.get("inline_validation")
    if isinstance(iv, dict) and ("confirmed" in iv or "inconclusive" in iv):
        return bool(iv.get("confirmed", False)), bool(iv.get("inconclusive", False))
    if "oracle_confirmed" in rec or "oracle_inconclusive" in rec:
        return bool(rec.get("oracle_confirmed", False)), bool(
            rec.get("oracle_inconclusive", False)
        )
    # No oracle info -> not conclusive.
    return False, True


def _is_operator_label(rec: dict) -> bool:
    return rec.get("label_source") == OPERATOR_LABEL_SOURCE


def _is_true_positive(rec: dict) -> bool:
    if rec.get("label_text") == TRUE_POSITIVE:
        return True
    # Fall back to the numeric label used by the triage dataset (1 == TP).
    return rec.get("label") == 1


def normalise(rec: dict) -> dict:
    """Project a raw row into the fields the reward logic needs."""
    confirmed, inconclusive = _oracle(rec)
    return {
        "category": _parse_category(rec),
        "skill_id": _active_skill_id(rec),
        "confirmed": confirmed,
        "inconclusive": inconclusive,
        "operator_label": _is_operator_label(rec),
        "true_positive": _is_true_positive(rec),
    }


def load_trajectories(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if rec.get("_truncated"):
            continue
        rows.append(normalise(rec))
    return rows


# ── Reward + aggregation (pure, unit-tested) ─────────────────────────


def _has_conclusive_oracle(f: dict) -> bool:
    """A conclusive oracle verdict — confirmed OR clean-fail, never an infra
    error. `inconclusive` means the oracle threw / could not run and is NEVER
    counted as evidence (inline-validation.ts: an inline error is inconclusive,
    never a false positive)."""
    return not f["inconclusive"]


def oracle_covered_categories(findings: list[dict]) -> set[str]:
    """Categories with at least one conclusive oracle verdict.

    A category with NO oracle coverage is INELIGIBLE — we have no verified
    ground truth for it, so scoring a skill on it would reintroduce exactly the
    unverified signal the reward clamp exists to reject.
    """
    return {f["category"] for f in findings if _has_conclusive_oracle(f)}


def is_eligible(f: dict, covered: set[str]) -> bool:
    """A finding counts toward reward accounting only if its category has oracle
    coverage, it has a conclusive oracle verdict, AND it carries an operator
    label. Anything else (inconclusive, non-operator label source, unlabeled)
    is excluded outright."""
    return (
        f["category"] in covered
        and _has_conclusive_oracle(f)
        and f["operator_label"]
    )


def is_confirmed_tp(f: dict) -> bool:
    """The reward numerator: verified-only. Oracle confirmed AND operator TP."""
    return f["confirmed"] and f["true_positive"]


def aggregate(findings: list[dict]) -> dict:
    """Per-skill verified-TP / FP stats plus the pooled baseline.

    Returns:
      {
        "skills": { skill_id: {n_eligible, n_confirmed_tp, n_fp,
                                tp_rate, fp_rate} },
        "baseline": {n_eligible, tp_rate, fp_rate},
        "ineligible_categories": [cat, ...],   # no oracle coverage
      }
    """
    covered = oracle_covered_categories(findings)
    all_categories = {f["category"] for f in findings}
    ineligible_categories = sorted(all_categories - covered)

    skills: dict[str, dict] = {}
    base_elig = base_tp = base_fp = 0

    for f in findings:
        if f["skill_id"] is None:
            continue
        if not is_eligible(f, covered):
            continue
        s = skills.setdefault(
            f["skill_id"],
            {"n_eligible": 0, "n_confirmed_tp": 0, "n_fp": 0},
        )
        s["n_eligible"] += 1
        base_elig += 1
        if is_confirmed_tp(f):
            s["n_confirmed_tp"] += 1
            base_tp += 1
        elif f["true_positive"] is False:
            # Operator marked it a false positive -> the elevated-FP signal.
            s["n_fp"] += 1
            base_fp += 1

    for s in skills.values():
        n = s["n_eligible"] or 1
        s["tp_rate"] = s["n_confirmed_tp"] / n
        s["fp_rate"] = s["n_fp"] / n

    baseline = {
        "n_eligible": base_elig,
        "tp_rate": (base_tp / base_elig) if base_elig else 0.0,
        "fp_rate": (base_fp / base_elig) if base_elig else 0.0,
    }
    return {
        "skills": skills,
        "baseline": baseline,
        "ineligible_categories": ineligible_categories,
    }


def analyze(
    findings: list[dict],
    *,
    min_samples: int,
    min_delta: float,
    now: str,
) -> list[dict]:
    """Produce one ledger-shaped decision entry per skill (and per ineligible
    category). Pure: no I/O, no promotion — the testable core of the loop."""
    agg = aggregate(findings)
    baseline = agg["baseline"]
    entries: list[dict] = []

    # Ineligible categories: no oracle coverage -> skipped.
    for cat in agg["ineligible_categories"]:
        entries.append(
            {
                "ts": now,
                "category": cat,
                "decision": DECISION_SKIPPED,
                "reason": "no_oracle_coverage",
            }
        )

    for skill_id in sorted(agg["skills"]):
        s = agg["skills"][skill_id]
        entry = {
            "ts": now,
            "skill_id": skill_id,
            "metrics": {
                "n_eligible": s["n_eligible"],
                "n_confirmed_tp": s["n_confirmed_tp"],
                "n_fp": s["n_fp"],
                "tp_rate": round(s["tp_rate"], 6),
                "fp_rate": round(s["fp_rate"], 6),
            },
            "baseline": {
                "n_eligible": baseline["n_eligible"],
                "tp_rate": round(baseline["tp_rate"], 6),
                "fp_rate": round(baseline["fp_rate"], 6),
            },
            "tp_rate_delta": round(s["tp_rate"] - baseline["tp_rate"], 6),
            "fp_rate_delta": round(s["fp_rate"] - baseline["fp_rate"], 6),
            "min_samples": min_samples,
            "min_delta": min_delta,
        }

        if s["n_eligible"] < min_samples:
            entry["decision"] = DECISION_SKIPPED
            entry["reason"] = "below_min_samples"
            entries.append(entry)
            continue

        below_baseline_tp = (baseline["tp_rate"] - s["tp_rate"]) >= min_delta
        elevated_fp = (s["fp_rate"] - baseline["fp_rate"]) >= min_delta
        if below_baseline_tp or elevated_fp:
            entry["decision"] = DECISION_FLAGGED
            entry["reason"] = (
                "below_baseline_tp" if below_baseline_tp else "elevated_fp"
            )
            entries.append(entry)
        # Skills at/above baseline are healthy -> no ledger noise for them.

    return entries


# ── Ledger (append-only JSON array — mirrors active_learning_loop) ────


def append_ledger(ledger_path: Path, entries: list[dict]) -> None:
    if ledger_path.exists():
        try:
            ledger = json.loads(ledger_path.read_text())
            if not isinstance(ledger, list):
                ledger = []
        except json.JSONDecodeError:
            ledger = []
    else:
        ledger = []
    ledger.extend(entries)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_path.write_text(json.dumps(ledger, indent=2) + "\n")


# ── Load-check bridge (reuses the runtime validator) ─────────────────


def load_check(candidate_yaml: Path, core_dist: Path | None = None) -> tuple[bool, str]:
    """Validate a candidate YAML via check_skill.mjs (which calls the runtime
    `loadSkillRegistry`). Returns (ok, message)."""
    if not CHECK_SCRIPT.exists():
        return False, f"validator not found: {CHECK_SCRIPT}"
    cmd = ["node", str(CHECK_SCRIPT), str(candidate_yaml)]
    if core_dist is not None:
        cmd += ["--core-dist", str(core_dist)]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        return False, "node not found on PATH — cannot run load-check"
    msg = (res.stdout + res.stderr).strip()
    return res.returncode == 0, msg


# ── Reporting ────────────────────────────────────────────────────────


def print_report(entries: list[dict], baseline: dict) -> None:
    print(f"\n{'='*60}")
    print("Skill refine — verified-only reward report")
    print(f"{'='*60}")
    print(
        f"  baseline: TP-rate={baseline['tp_rate']:.4f} "
        f"FP-rate={baseline['fp_rate']:.4f} "
        f"(n_eligible={baseline['n_eligible']})"
    )
    flagged = [e for e in entries if e["decision"] == DECISION_FLAGGED]
    skipped = [e for e in entries if e["decision"] == DECISION_SKIPPED]
    if flagged:
        print("\n  Refinement candidates (below-baseline / elevated-FP):")
        for e in flagged:
            m = e["metrics"]
            print(
                f"    {e['skill_id']:>24}: TP={m['tp_rate']:.3f} "
                f"FP={m['fp_rate']:.3f} n={m['n_eligible']} "
                f"[{e['reason']}]"
            )
    else:
        print("\n  No refinement candidates — every scored skill met baseline.")
    if skipped:
        print("\n  Skipped (ineligible / insufficient data):")
        for e in skipped:
            who = e.get("skill_id") or f"category:{e.get('category')}"
            print(f"    {who:>24}: {e['reason']}")


# ── Main ─────────────────────────────────────────────────────────────


def run_analysis(args) -> int:
    if not args.dataset or not args.dataset.exists():
        print(f"ERROR: dataset not found: {args.dataset}", file=sys.stderr)
        return 3

    findings = load_trajectories(args.dataset)
    print(f"Loaded {len(findings)} finding rows from {args.dataset}")

    now = dt.datetime.now(dt.timezone.utc).isoformat()
    entries = analyze(
        findings,
        min_samples=args.min_samples,
        min_delta=args.min_delta,
        now=now,
    )
    agg = aggregate(findings)
    print_report(entries, agg["baseline"])

    # Promotion gate: only meaningful when an operator supplied a refined YAML.
    if args.candidate_yaml is not None:
        entries += _gate_promotion(args, entries, now)

    append_ledger(args.ledger, entries)
    print(f"\nAppended {len(entries)} decision(s) to {args.ledger}")

    if agg["baseline"]["n_eligible"] == 0:
        print(
            "WARNING: zero eligible findings — no verified ground truth to "
            "score. (Reward clamp working as intended on unverified data.)",
            file=sys.stderr,
        )
        return 2
    return 0


def _gate_promotion(args, entries: list[dict], now: str) -> list[dict]:
    """Gate an operator-supplied refined YAML. Never autonomous: the skill must
    already be flagged AND the candidate must pass the runtime load-check."""
    cand = args.candidate_yaml
    ok, msg = load_check(cand, args.core_dist)
    # Resolve which skill this refines: explicit flag or the YAML's id line.
    target = args.candidate_skill or _yaml_id(cand)
    flagged_ids = {
        e.get("skill_id") for e in entries if e["decision"] == DECISION_FLAGGED
    }
    base = {
        "ts": now,
        "skill_id": target,
        "candidate_yaml": str(cand),
        "operator": args.operator,
        "load_check_ok": ok,
        "load_check_msg": msg,
    }

    if not ok:
        print(f"\n[promote] load-check FAILED for {cand}: {msg}", file=sys.stderr)
        base["decision"] = DECISION_SKIPPED
        base["reason"] = "load_check_failed"
        return [base]

    if target not in flagged_ids:
        print(
            f"\n[promote] '{target}' is not a flagged candidate — refusing to "
            "promote a skill that is not under-performing."
        )
        base["decision"] = DECISION_SKIPPED
        base["reason"] = "not_flagged"
        return [base]

    if not args.promote:
        print(
            f"\n[dry-run] '{target}' would be promoted (load-check OK, flagged), "
            "but --promote was not passed. No YAML written."
        )
        base["decision"] = DECISION_WOULD_PROMOTE
        return [base]

    if not args.operator:
        print(
            "\n[promote] --promote requires --operator <name> for sign-off. "
            "No YAML written.",
            file=sys.stderr,
        )
        base["decision"] = DECISION_SKIPPED
        base["reason"] = "missing_operator_signoff"
        return [base]

    # Real promotion: write the validated candidate into the destination.
    dest = args.promote_dest
    if dest is None:
        print(
            "\n[promote] --promote-dest <path> is required to choose where the "
            "validated YAML is written. No YAML written.",
            file=sys.stderr,
        )
        base["decision"] = DECISION_SKIPPED
        base["reason"] = "missing_promote_dest"
        return [base]
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(cand.read_text())
    print(f"\n[promote] PROMOTED — validated candidate written to {dest}")
    base["decision"] = DECISION_PROMOTED
    base["promoted_to"] = str(dest)
    return [base]


def _yaml_id(path: Path) -> str | None:
    """Cheap `id:` scrape (avoids a YAML dep just to read one line)."""
    for line in path.read_text().splitlines():
        if line.startswith("id:"):
            return line.split(":", 1)[1].strip().strip("\"'")
    return None


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Skill self-improvement loop (/refine)")
    ap.add_argument("--dataset", type=Path, help="Labeled-trajectory JSONL.")
    ap.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    ap.add_argument(
        "--min-samples",
        type=int,
        default=200,
        help="Floor of eligible findings before a skill can be scored.",
    )
    ap.add_argument(
        "--min-delta",
        type=float,
        default=0.005,
        help="Min rate gap vs baseline to flag a refinement candidate.",
    )
    ap.add_argument(
        "--candidate-yaml",
        type=Path,
        help="Operator-refined skill YAML to gate for promotion.",
    )
    ap.add_argument("--candidate-skill", help="Skill id the candidate refines.")
    ap.add_argument("--operator", help="Operator sign-off name (required to --promote).")
    ap.add_argument(
        "--promote-dest",
        type=Path,
        help="Where a promoted YAML is written (required with --promote).",
    )
    ap.add_argument(
        "--core-dist",
        type=Path,
        help="Path to @0sec/core build (for the load-check). Defaults to sibling.",
    )
    ap.add_argument(
        "--check-skill",
        type=Path,
        help="Validate a single YAML via the runtime loader and exit.",
    )
    promote_group = ap.add_mutually_exclusive_group()
    promote_group.add_argument(
        "--promote", dest="promote", action="store_true",
        help="Allow writing a validated candidate YAML (default: dry-run).",
    )
    promote_group.add_argument(
        "--dry-run", dest="promote", action="store_false",
        help="Analyse + log only; never write a YAML (default).",
    )
    ap.set_defaults(promote=False)
    ap.add_argument(
        "--selftest", action="store_true",
        help="Run built-in fixtures; exit non-zero on failure.",
    )
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if args.selftest:
        return run_selftest()

    if args.check_skill is not None:
        ok, msg = load_check(args.check_skill, args.core_dist)
        print(msg)
        return 0 if ok else 3

    if args.dataset is None:
        print(
            "ERROR: provide --dataset, --check-skill, or --selftest.",
            file=sys.stderr,
        )
        return 3

    return run_analysis(args)


# ── Self-test (fixtures) ─────────────────────────────────────────────


def selftest_rows() -> list[dict]:
    """Synthetic labeled-trajectory rows exercising every reward-clamp branch.

    Also written to fixtures/skill-refine-trajectories.sample.jsonl for the
    pytest suite. Design (min_samples=5, min_delta=0.005 in the selftest):
      * sqli-advanced  — healthy: 8 eligible, 7 confirmed-TP, 1 FP (above base)
      * ssrf-bypass    — under-performer: 8 eligible, 2 confirmed-TP, 6 FP
      * jwt-attacks    — 2 eligible -> below the floor -> skipped
      * exotic category — all inconclusive -> no oracle coverage -> skipped
      * plus inconclusive / non-operator / unlabeled sqli rows that must NOT
        change sqli's counts (exclusion proof).
    """
    rows: list[dict] = []

    def row(cat, skill, confirmed, inconclusive, tp, operator=True, label_src=None):
        src = label_src or (OPERATOR_LABEL_SOURCE if operator else "flag_extraction")
        return {
            "category": cat,
            "skill_events": [{"type": "skill_preloaded", "skillId": skill}],
            "inline_validation": {"confirmed": confirmed, "inconclusive": inconclusive},
            "label": 1 if tp else 0,
            "label_text": TRUE_POSITIVE if tp else "false_positive",
            "label_source": src,
            "source": "selftest",
        }

    # sqli-advanced: 7 confirmed TP + 1 operator FP == 8 eligible
    for _ in range(7):
        rows.append(row("sqli", "sqli-advanced", True, False, True))
    rows.append(row("sqli", "sqli-advanced", False, False, False))
    # exclusion noise on sqli — must NOT be counted:
    rows.append(row("sqli", "sqli-advanced", False, True, True))          # inconclusive
    rows.append(row("sqli", "sqli-advanced", True, False, True, operator=False))  # non-operator
    rows.append(row("sqli", "sqli-advanced", True, False, True, label_src="package_verdict"))  # non-operator

    # ssrf-bypass: 2 confirmed TP + 6 operator FP == 8 eligible (under-performer)
    for _ in range(2):
        rows.append(row("ssrf", "ssrf-bypass", True, False, True))
    for _ in range(6):
        rows.append(row("ssrf", "ssrf-bypass", False, False, False))

    # jwt-attacks: only 2 eligible -> below floor
    for _ in range(2):
        rows.append(row("auth-bypass", "jwt-attacks", True, False, True))

    # exotic category: all inconclusive -> no oracle coverage -> skipped
    for _ in range(4):
        rows.append(row("exotic", "deserialization-chains", False, True, True))

    return rows


def run_selftest() -> int:
    import tempfile

    failures: list[str] = []

    def check(name: str, cond: bool):
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if not cond:
            failures.append(name)

    raw = selftest_rows()
    findings = [normalise(r) for r in raw]
    now = "1970-01-01T00:00:00+00:00"
    entries = analyze(findings, min_samples=5, min_delta=0.005, now=now)
    by_skill = {e.get("skill_id"): e for e in entries if e.get("skill_id")}
    agg = aggregate(findings)

    # 1. reward excludes inconclusive / non-operator / unlabeled rows
    sqli = agg["skills"]["sqli-advanced"]
    check(
        "reward excludes inconclusive/unlabeled (sqli n_eligible==8, tp==7)",
        sqli["n_eligible"] == 8 and sqli["n_confirmed_tp"] == 7 and sqli["n_fp"] == 1,
    )

    # 2. oracle-uncovered category skipped
    exotic_skips = [
        e for e in entries
        if e["decision"] == DECISION_SKIPPED and e.get("category") == "exotic"
        and e.get("reason") == "no_oracle_coverage"
    ]
    check("oracle-uncovered category 'exotic' skipped", len(exotic_skips) == 1)
    check(
        "under-oracle skill not scored (deserialization-chains absent)",
        "deserialization-chains" not in agg["skills"],
    )

    # 3. min-samples floor -> skipped_insufficient_data
    jwt = by_skill.get("jwt-attacks")
    check(
        "jwt-attacks below floor -> skipped_insufficient_data",
        jwt is not None
        and jwt["decision"] == DECISION_SKIPPED
        and jwt.get("reason") == "below_min_samples",
    )

    # 4. under-performer flagged as candidate
    ssrf = by_skill.get("ssrf-bypass")
    check(
        "ssrf-bypass flagged as candidate",
        ssrf is not None and ssrf["decision"] == DECISION_FLAGGED,
    )
    check(
        "healthy sqli-advanced NOT flagged",
        "sqli-advanced" not in by_skill
        or by_skill["sqli-advanced"]["decision"] != DECISION_FLAGGED,
    )

    # 5. dry-run writes NO YAML and DOES append a ledger row
    with tempfile.TemporaryDirectory() as td:
        ledger = Path(td) / "skill-refine-ledger.json"
        append_ledger(ledger, entries)
        wrote_ledger = ledger.exists() and len(json.loads(ledger.read_text())) == len(entries)
        no_yaml = not any(Path(td).glob("**/*.yaml"))
        check("dry-run appended ledger rows", wrote_ledger)
        check("dry-run wrote NO YAML", no_yaml)

    print()
    if failures:
        print(f"SELFTEST FAILED: {len(failures)} check(s) failed: {failures}")
        return 3
    print("SELFTEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

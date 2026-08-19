# Skill self-improvement loop (`/refine`)

A dry-run-first `/refine` flywheel for pwnkit's JIT methodology **skills** — the
skill-side sibling of `active_learning_loop.py` (which does the same for the
triage router). It scores each skill by the **verified** outcomes of the
findings produced while it was active, flags under-performers as refinement
candidates, and appends every decision to an append-only ledger. It **never**
rewrites a skill on its own.

Files:

| File | Role |
| --- | --- |
| `skill_refine_loop.py` | The loop: reward, aggregation, flagging, ledger, promotion gate, `--selftest`. |
| `check_skill.mjs` | Load-check bridge — reuses the runtime `loadSkillRegistry` (no duplicated validator). |
| `test_skill_refine_loop.py` | Pytest suite (mirrors `--selftest`). |
| `fixtures/skill-refine-trajectories.sample.jsonl` | Synthetic labeled-trajectory fixture. |

## Why skills are the refinable surface

JIT skills are the only agent-behaviour surface that is already **versioned**
(integer `version` in `SkillDefinition`) **and hot-loaded from disk** at runtime
(`packages/core/src/agent/skills/{frameworks,vulnerabilities,techniques}/*.yaml`,
loaded by `loadSkillRegistry()` in `skills/index.ts`). That makes them the
cheapest thing to close a feedback loop around: a refined YAML with a bumped
`version` is picked up with no code change, exactly like a promoted router model.

## How it plugs into the existing flywheel

The dataset flywheel already emits everything this loop consumes:

1. **Attribution** — the agent emits `skill_preloaded` / `load_skill` events
   carrying a `skillId` (`native-loop.ts`, `tools.ts`) and `playbook_injected`.
   Each finding is joined to the skill that was active when it was produced.
2. **Ground truth** — operators triage findings TP/FP
   (`label_source == "human_review"` in `dataset_rows`) and an **inline oracle**
   independently `confirmed`s exploitation (`agent/inline-validation.ts`).
3. **This loop** joins finding → active skill → outcome, scores each skill's
   verified-TP / FP rate against the pooled baseline (the `evaluate_per_source`
   per-source breakdown from `train_triage_v2.py`, with **skill-ID as the
   "source" dimension**), and appends decisions to `skill-refine-ledger.json`
   — the same append-only-JSON-array pattern as `active-learning-ledger.json`,
   so the precision/recall dashboard surface can read it.

## The reward clamp (verified-only) — the reward-hacking guard

**A finding counts toward a skill's score ONLY when the inline oracle
`confirmed == true` AND the operator label is a true positive from
`human_review`.** Everything else is excluded:

- `inconclusive` oracle verdicts (an infra error is never evidence) — excluded.
- unconfirmed findings — excluded from the reward numerator.
- non-operator label sources (`flag_extraction`, `package_verdict`) — excluded.
- a category with **no oracle coverage at all** — **ineligible**, skipped
  entirely (`skipped_insufficient_data` / `reason: no_oracle_coverage`).
- fewer than `--min-samples` (default **200**) eligible findings for a skill —
  skipped (`reason: below_min_samples`).

This is deliberate. A self-improving agent optimising an unverified or
self-reported success signal learns to **game the metric instead of achieving
the outcome** — the Factorio/RCON-style failure where the model maximises the
number it is graded on rather than actually solving the task. Clamping reward to
independently-verified exploitation (a separate oracle reproduced it *and* a
human confirmed it) makes the metric expensive to fake: a skill can only look
good by producing findings that survived two independent checks.

## Safety model — no autonomous promotion

- **Dry-run by default.** The loop reads data and appends ledger rows. It never
  writes a skill YAML without `--promote`.
- **`--promote` is gated three ways**, all of which must hold:
  1. the skill is currently **flagged** as an under-performer (you cannot
     promote a refinement to a skill that is meeting baseline),
  2. the operator-supplied `--candidate-yaml` passes a **load-check** through
     the runtime validator (`check_skill.mjs` → `loadSkillRegistry`), and
  3. an operator **sign-off** (`--operator <name>`) and an explicit
     `--promote-dest <path>` are provided.
- Even then, promotion just copies the *already-validated* YAML to the
  destination you name. There is no code path from "flagged" to "written"
  without a human supplying the refined YAML and the sign-off.

## Ledger decision vocabulary

| Decision | Meaning |
| --- | --- |
| `skipped_insufficient_data` | Below the sample floor, or category has no oracle coverage, or a promotion pre-condition failed (`reason` distinguishes). |
| `candidate_flagged` | Skill scored below baseline TP or above baseline FP by `--min-delta` — refine it. |
| `would_promote_dry_run` | A supplied candidate passed the load-check and the skill is flagged, but `--promote` was absent. |
| `promoted` | `--promote` + sign-off + load-check all passed; validated YAML written to `--promote-dest`. |

## Usage

```bash
# analyse a labeled-trajectory dataset (dry-run, default)
python3 skill_refine_loop.py --dataset results/skill-trajectories.jsonl

# validate a single candidate YAML with the runtime loader and exit
python3 skill_refine_loop.py --check-skill path/to/candidate.yaml

# gated promotion (operator-driven)
python3 skill_refine_loop.py --dataset results/skill-trajectories.jsonl \
    --candidate-yaml refined-ssrf-bypass.yaml \
    --candidate-skill ssrf-bypass \
    --operator alice \
    --promote --promote-dest packages/core/src/agent/skills/vulnerabilities/ssrf-bypass.yaml
```

The load-check needs the core build. If `check_skill.mjs` reports the build is
missing, run `pnpm --filter @pwnkit/core build` (or pass `--core-dist <dir>`).

## Tests

No Python test harness ships in this repo, so the fixtures run two ways:

```bash
# dependency-free self-check (primary); exits non-zero on failure
python3 skill_refine_loop.py --selftest

# or, if pytest is available
python3 -m pytest packages/benchmark/scripts/train/test_skill_refine_loop.py -q
```

Both assert: reward excludes inconclusive/unlabeled/non-operator rows; an
oracle-uncovered category is skipped; the `--min-samples` floor yields
`skipped_insufficient_data`; a clearly under-performing skill is flagged; and a
dry-run writes **no YAML** while still appending a ledger row.

## Dataset row shape

A superset of the triage-dataset row. The extra fields are the
finding ↔ skill ↔ oracle join (all optional, with fallbacks):

```json
{
  "category": "sqli",
  "skill_events": [
    {"type": "skill_preloaded", "skillId": "sqli-advanced"},
    {"type": "load_skill",      "skillId": "sqli-advanced"}
  ],
  "active_skill_id": "sqli-advanced",
  "inline_validation": {"confirmed": true, "inconclusive": false},
  "label": 1, "label_text": "true_positive",
  "label_source": "human_review",
  "source": "..."
}
```

`category` falls back to a `Category:` line inside the triage `text` blob;
`active_skill_id` falls back to the most-recent `skill_events` entry;
`inline_validation` falls back to flat `oracle_confirmed` / `oracle_inconclusive`
fields.

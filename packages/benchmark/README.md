# @pwnkit/benchmark

Benchmark runners for pwnkit across multiple security evaluation suites
(XBOW, AutoPenBench, CyBench, HarmBench, NPM advisories).

This document focuses on the **XBOW runner** and how to point it at
arbitrary XBOW-compatible benchmark suites.

For public benchmark publication, do not treat ad hoc `xbow-latest.json`
files or markdown notes as the canonical score surface. The current repo
keeps an explicit benchmark ledger at
`packages/benchmark/results/benchmark-ledger.json` to separate:

- retained artifact-backed results that are machine-recoverable from GitHub
  Actions artifacts, and
- older historical mixed local+CI publication tallies.

## XBOW runner

The XBOW runner (`src/xbow-runner.ts`, exposed as `pnpm xbow`) executes
pwnkit against the [XBOW validation benchmarks][xbow] — 104 Docker CTF
challenges covering SQLi, XSS, SSRF, deserialization, IDOR, auth bypass,
command injection, and other classic web bug classes.

[xbow]: https://github.com/xbow-engineering/validation-benchmarks

### Benchmark source precedence

The runner locates the benchmark suite on disk using the following
precedence (first match wins):

1. `--benchmark-path <dir>` — use an existing local checkout as-is
2. `XBOW_PATH` environment variable — use an existing local checkout as-is
3. `--benchmark-repo <git-url>` — clone into a workspace cache dir
   (`$TMPDIR/pwnkit-xbow-cache/<slug>`) and reuse the clone on subsequent
   runs
4. Default `/tmp/xbow-benchmarks`

`--benchmark-repo` accepts either the GitHub short form (`owner/repo`)
or a full git URL (`https://github.com/owner/repo.git`, SSH specs, etc.).
Use `--benchmark-ref <branch|tag|sha>` to pin a specific ref.

### Examples

Run against upstream XBOW (note: several Docker builds are broken upstream):

```sh
pnpm --filter @pwnkit/benchmark xbow \
  --benchmark-repo xbow-engineering/validation-benchmarks \
  --agentic --limit 10
```

Run against the community patched fork (fixes all 104 Docker builds):

```sh
pnpm --filter @pwnkit/benchmark xbow \
  --benchmark-repo 0ca/xbow-validation-benchmarks-patched \
  --agentic
```

Run against Shannon's "cleaned" fork (strips comments, variable names,
filepaths, and rewrites Dockerfiles — the substrate Shannon used for
their 96.15% result):

```sh
pnpm --filter @pwnkit/benchmark xbow \
  --benchmark-repo KeygraphHQ/xbow-validation-benchmarks \
  --agentic
```

Use a local checkout without cloning:

```sh
pnpm --filter @pwnkit/benchmark xbow \
  --benchmark-path /path/to/my/xbow-fork \
  --agentic --limit 5
```

### CI (GitHub Actions)

The `.github/workflows/xbow-bench.yml` workflow exposes two
`workflow_dispatch` inputs that drive the same behavior:

- `benchmark_repo` — any XBOW-compatible source repo
  (default: `0ca/xbow-validation-benchmarks-patched`)
- `benchmark_ref` — optional branch/tag/sha inside that repo

The clone step in the workflow honors these inputs before any benchmark
runs, so scheduled and dispatched runs can easily target upstream, the
patched fork, or a cleaned fork for apples-to-apples comparisons.

### Other flags

See the header comment in `src/xbow-runner.ts` for the full flag list
(`--agentic`, `--white-box`, `--limit`, `--tag`, `--level`, `--only`,
`--start`, `--retries`, `--models`, `--fresh`, `--save-findings`,
`--runtime`, `--dry-run`, `--json`).

### Statistical evaluation (`--repeat N`)

A single XBOW solve is an anecdote, not a benchmark. On 2026-04-06 a
v1 sweep solved XBEN-061 in 8 turns with a `handoff,no-hiw,no-evidence`
feature combo; we promoted that to a "winning configuration" in a blog
post and on the public roadmap. The same afternoon, a v2 regression
test ran the same combo against the same challenge with a fresh
workspace and failed. The single solve was noise inside an estimated
20–40% per-attempt success rate — not a generalizable signal.

Issue [#81] is the fix: every `(challenge, configuration)` cell gets
run N independent times and the harness reports the per-attempt
success rate with a 95% **Wilson score** confidence interval before
anything gets promoted to a default. Wilson (not Wald / normal
approximation) because N is small and rates can be near 0 or 1, where
Wald produces degenerate intervals like `[0, 0]` or extends outside
`[0, 1]`.

[#81]: https://github.com/0sec-labs/pwnkit/issues/81

#### Flags

```
--repeat N                         number of independent attempts per
                                   challenge (default 1)
--repeat-cost-ceiling-usd <amount> per-cell cost ceiling (default $5.00).
                                   Subsequent runs of a challenge are
                                   skipped once cumulative cost across
                                   attempts exceeds the ceiling; the
                                   result carries costCeilingHit: true.
```

Default reasoning for the cost ceiling: `$5/cell × 8 unsolved challenges
× n=10 = $40 max per sweep.` Affordable for a nightly CI job.

#### Recommended invocation (n=10 evaluation)

Run the n=10 harness over the 8 unsolved XBEN challenges with the
lean-scaffolding feature combo under investigation:

```sh
pnpm --filter @pwnkit/benchmark xbow \
  --agentic \
  --only XBEN-010,XBEN-051,XBEN-061,XBEN-066,XBEN-080,XBEN-084,XBEN-099,XBEN-104 \
  --repeat 10 \
  --repeat-cost-ceiling-usd 5.00 \
  --fresh --json
```

The CI workflow exposes the same via the `repeat` and
`repeat_cost_ceiling_usd` `workflow_dispatch` inputs on
`.github/workflows/xbow-bench.yml`.

### JIT skills A/B

Issue [#410] adds a small wrapper for comparing the default agent against
`PWNKIT_FEATURE_JIT_SKILLS=1` on the same XBOW target selection. The
wrapper runs the baseline cell first, then the JIT-skills cell, and
reports pass/flag deltas plus attack turns, token totals, and estimated cost.

```sh
pnpm --filter @pwnkit/benchmark xbow:jit-skills-ab --limit 10
pnpm --filter @pwnkit/benchmark xbow:jit-skills-ab \
  --only XBEN-010,XBEN-051,XBEN-061 --repeat 3 --json
```

[#410]: https://github.com/0sec-labs/pwnkit/issues/410

#### JSON output schema

**When `--repeat 1` (default):** the `xbow-latest.json` shape is
**unchanged**. Same `results: [...]` array, no new fields, no
top-level `repeatProtocol`. Existing consumers that don't know about
`--repeat` keep working byte-for-byte.

**When `--repeat N > 1`:** a top-level `repeatProtocol` field appears:

```jsonc
{
  "timestamp": "…",
  "repeatProtocol": { "N": 10, "costCeilingUsd": 5.0 },
  "results": [ /* … */ ]
}
```

And each entry in `results[]` **adds** the aggregation fields while
**keeping** the legacy single-run fields populated from the first
attempt, so old consumers still see a recognizable shape:

```jsonc
{
  "id": "XBEN-061",
  "name": "IDOR in user profile",
  "level": 2,
  "tags": ["idor"],

  // Legacy single-shot fields — populated from the FIRST attempt.
  // `passed` / `flagFound` reflect "did any attempt solve it?" so
  // the top-level pass counter still means something in repeat mode.
  "passed": true,
  "flagFound": true,
  "attackTurns": 8,
  "estimatedCostUsd": 0.25,
  "durationMs": 42000,

  // n=10 aggregation fields.
  "attempts": 10,
  "passes": 3,
  "successRate": 0.3,
  "successRateCI95": [0.1078, 0.6032],
  "meanTurns": 10.5,
  "stdDevTurns": 2.4,
  "meanCostUsd": 0.35,
  "stdDevCostUsd": 0.1,
  "perRun": [
    { "runIndex": 0, "passed": true,  "turns": 8,  "cost": 0.25, "durationMs": 42000 },
    { "runIndex": 1, "passed": false, "turns": 12, "cost": 0.42, "durationMs": 68000 }
    // … 8 more
  ],
  "costCeilingHit": false
}
```

If a cell stops early because the `--repeat-cost-ceiling-usd` ceiling
was hit, `costCeilingHit: true` and `attempts < repeatProtocol.N` —
a reader can tell at a glance that the sample is smaller than the
requested N.

The Wilson CI computation and the aggregation logic live in
`src/wilson.ts` and are independently unit-tested in
`src/wilson.test.ts` (15 tests, including the k=0 / k=n boundary
clamps) and `src/xbow-runner.test.ts` (4 tests covering the repeat
harness with an injected fake `runOne`).

## CyberGym fair-config pass@1 (pre-registration = claim-gate integrity)

CyberGym (UC Berkeley RDI — `sunblaze-ucb/cybergym`) is the field's
C/C++ memory-safety benchmark. The committed receipts
(`results/cybergym-v1.jsonl`, `results/cybergym-agent-v1.jsonl`) are
real but **non-random** first-pulled subsets (n=6 / n=18) — defensible
data points, NOT a benchmark-wide pass@1. The path to a citation-grade
number is issue [#1029]: a **pre-registered, stratified** 150–200-task
subset with the task-ID list + RNG seed committed **before** the run.

[#1029]: https://github.com/0sec-labs/0sec/issues/1029

Pre-registration is the integrity contract — the order is fixed:

1. **Commit the subset file before any model run.** The task-id list +
   seed are frozen in git at pre-registration time.
2. Run the engine on that subset, writing a **fresh** receipt
   (`--corpus-path results/cybergym-fair-v1.jsonl`) so the defensible
   number cannot contaminate the existing n=6/n=18 receipts.
3. **Commit the per-task JSONL receipt after the run.**

Editing the subset list after the run breaks the claim-gate (epic #1026).

### `cybergym-stratify` — pre-registered stratified subset generator

`src/cybergym-stratify.ts` (exposed as `pnpm cybergym:stratify`) emits a
stratified subset from the bench-side corpus (the mask_map / HF dataset
metadata, which is NOT in-repo — the corpus is always passed as input):

```sh
pnpm --filter @pwnkit/benchmark cybergym:stratify \
  --corpus /root/cybergym/mask_map.json \
  --target 175 --seed 0xc6f1a5ed \
  --stratify-by project,crashType \
  --out results/cybergym-fair-v1.subset.txt
```

- Stratifies across `project,crashType` per #1029 (configurable via
  `--stratify-by`). Tolerant of corpus shape: `mask_map.json` (bare
  id universe), JSONL of task records, or a JSON array. When a stratum
  field is absent (e.g. a bare mask_map carries no crash types) it
  falls back to uniform deterministic sampling on the remaining fields
  and warns to stderr — still pre-registered + seeded, just not
  stratified. For a true stratified run, feed a corpus with project +
  crash-type metadata (dumpable from the HF dataset on bench).
- Determinism: a mulberry32 PRNG seeded from `--seed` (default
  `0xc6f1a5ed`) decides membership; the same corpus + seed always yields
  the same subset. Allocation across strata is largest-remainder
  proportional, bounded by each stratum's size.
- The output file carries a provenance header (source path + sha256,
  generated-at, target, seed, stratify-by) so the frozen artifact is
  self-describing. `cybergym-runner --subset` already skips `#` comment
  lines, so the header rides along cleanly.

### `cybergym-runner --corpus-path` — write a fresh receipt

`--corpus-path <file>` (or the `CYBERGYM_CORPUS_PATH` env) overrides the
corpus output path so a fair run writes a NEW receipt instead of
appending to the stale `cybergym-v1.jsonl`. Defaults to
`results/cybergym-v1.jsonl` (unchanged for existing callers):

```sh
pnpm --filter @pwnkit/benchmark cybergym \
  --subset results/cybergym-fair-v1.subset.txt \
  --corpus-path results/cybergym-fair-v1.jsonl \
  --harness-dir /root/cybergym --json
```

The full fair-run protocol (firewall, one-container-per-task, relaunch
policy, Wilson-CI reporting) lives in the
[runbook](../../../docs/operations/runbooks/cybergym-harness.md) and
issue [#1029]. The fairness fix itself is already in the engine
(`pwnkit/packages/core/src/stages/craft-scan.ts`, commit 704b84b5) —
not a flag.

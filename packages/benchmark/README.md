# @0sec/benchmark

Benchmark runners for 0sec across multiple security evaluation suites
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

## Windows research evidence ledger

`pnpm --filter @0sec/benchmark windows-research` converts an input JSON or
JSONL file of Windows research attempts into an append-only, hash-bound ledger
and a summary with Wilson intervals:

```sh
pnpm --filter @0sec/benchmark windows-research \
  --input attempts.jsonl \
  --output results/windows-research-v1.jsonl \
  --summary results/windows-research-summary-v1.json
```

The ledger retains every outcome, including no-candidate, not-reproduced,
inconclusive, and safety-rejected attempts. Contract fixtures are reported
separately and are never included in capability metrics. A live reproduced row
is claim-eligible only when it is bound to a passing 0sec import verdict, the
exact receipt hash, distinct retained dump bytes, a pre-run sealed label, and
all execution safety gates. Raw commands, exploit material, secrets, and local
paths are rejected or omitted.

Live collection also requires `0SEC_WINDOWS_LABEL_SEAL_KEY` (at least 32
bytes). The collector verifies the HMAC seal over campaign, case, ground truth,
label hash, and seal timestamp without persisting the key.

### Windows LPE discovery corpus

The Windows LPE benchmark uses a separate, strict corpus manifest so known
regressions cannot be confused with novel bounty findings:

```sh
pnpm --filter @0sec/benchmark windows-lpe-corpus \
  --input fixtures/windows-lpe-corpus-contract-v1.json
```

The v2 manifest keeps development and holdout vulnerability families disjoint,
requires positive and negative controls, pins target and scope digests, and
forbids executable payload fields. Every corpus case is permanently marked
non-novel, non-claimable, non-weaponizing, and ineligible for automatic
disclosure. When a live attempt supplies `corpusManifestPath`, the collector
recomputes the canonical manifest digest and binds the case ID, ground-truth
label, and Windows build before forcing that ledger row out of claim metrics.

Agents must not receive that full evaluator manifest for holdout work. The
`windows-lpe-opaque-projection` boundary generates a fresh agent-facing file
containing only a projection ID, randomized 256-bit handles, and fail-closed
policy. Case IDs, split/family/pair structure, CVEs, builds, artifacts, scope,
provenance, commitments, timestamps, and labels remain in an evaluator-only
resolver. The resolver is bound to both the projection and full inventory.

Dynamic resolution requires an external execution-authority verifier bound to
the projection, resolver, inventory, opaque handle, exact observed Windows
runtime, and worker acceptance. Its nonce is atomically consumed once. The
evaluator also pins the resolver digest independently, so a complete handle
remap cannot authorize itself. The agent mount validator permits exactly one
read-only regular `projection.json` file in a fresh, non-symlinked, read-only
directory and uses bounded, duplicate-key-safe, nofollow reads. The trusted
runner must preserve that mount immutability for the worker lifetime; the
resolver, private resolution result, and labels must never cross into the agent
environment.

The committed fixture is an offline contract check only: it performs no dynamic
execution. Actual target runs require an independently authorized scope and a
human decision before any report leaves the research system.

### MSRC capability promotion gate

`msrc-windows-lpe-capability-promotion` is the evaluator-private boundary
between the frozen MSRC staging lock and a paired-v2 capability corpus. A
tranche lock is intentionally insufficient input: promotion also requires the
two complete MSRC inventories that produced it, both committed private label
documents, and exact per-artifact extraction, package, servicing, scope, and
static-control evidence.

The gate requires every one of at least 20 staged public CVE families to have
exactly four static cases: one vulnerable member, its paired fixed member, one
guarded safe near-miss, and one sink proven unreachable from dispatch. This
produces exactly three evaluator-labeled negatives per family and at least 60
negatives overall. At least five and at least 25% of families must remain in a
family-disjoint sealed holdout. The vulnerable member must bind the
inventory's superseded boundary; all three controls bind its fixed boundary.
Package, extracted component, receipt, build/UBR, KB/catalog, source-document,
scope, and corpus identities are cross-checked rather than inferred from CVE
metadata.

Promotion is static validation only. It requires three confirmations and three
clean controls for any later reproduction campaign, forces every target's
dynamic-execution flag off, and preserves evaluator-private, agent-hidden,
non-novel, non-claimable, non-weaponizing, no-auto-disclosure policy. It does
not download updates, execute drivers, infer that a staged CVE is IOCTL
relevant, authenticate upstream extraction signatures, or establish that any
candidate is vulnerable. Those exact retained bytes and receipts must be
verified before constructing the promotion input.

### Evaluator-private 0verse IOCTL observations

`windows-ioctl-benchmark-observation` is the benchmark-only consumer boundary
for 0verse Windows IOCTL static evidence. The parser requires the evaluator's
actual paired-corpus manifest, opaque agent projection, private resolver, and
an independently provisioned resolver digest. The caller must also supply the
exact 0verse digests and site/candidate counts authenticated by upstream
artifact verifiers; self-declared observation commitments are rejected. It
then binds one opaque handle
to the exact corpus, inventory, projection, resolver, driver, analysis export,
analysis receipt, complete site universe, rank result, signed rank receipt, and
private aggregate evaluation commitments.

The observation retains complete contiguous candidate ranks in 0verse's
deterministic score/content-ID order, requires the site-universe, rank-result,
and evaluation site counts to agree, and derives recall and suppression Wilson
intervals from evaluator-only aggregate counts. Timing and cost are retained as
measurement data, not evidence of vulnerability.

Pass gates are recomputed with integer arithmetic from evaluator-owned
parts-per-million threshold policy supplied through the trusted context. The
observation's gate booleans cannot override that policy. MRR contribution is
derived from the evaluator-private first expected rank. The competitive gate is
instead Recall@k lift: it compares expected sites found at the cutoff with the
trusted best-baseline count using exact integer cross-multiplication (the normal
policy requires at least 2,000,000 ppm, or 2x). The reported MRR contribution
and Recall@k lift use bounded integer parts per million to avoid floating-point
policy decisions.

A zero-hit baseline is not treated as infinite lift. It produces
`baselineWasZero: true`, a null `recallLiftPpm`, and a fail-closed
`baselineRecallLift` gate until the evaluator supplies a nonzero baseline.

This module is a pure validator. It has no runner, command, target path,
callback, research-adapter, or `ResearchFinding` dependency. It cannot execute
a binary or device operation and cannot emit a finding. Every observation is
static-only, evaluator-private, non-runtime-consumable, non-novel,
non-claimable, non-weaponizing, ineligible for automatic disclosure, and gated
on human promotion and reporting.

The observation and its aggregate counts must never be returned to an agent.
The agent-facing projection remains the existing one-file list of randomized
handles; it receives no corpus commitment, resolver identity, target metadata,
site role, label, metric, or directional evaluation result. The evaluation
digest only commits private bytes at the evaluator boundary.

Proof limit: successful parsing establishes internal commitment consistency
for one static benchmark observation against caller-supplied trusted inputs.
The trusted inputs are the already-validated paired corpus/projection/resolver,
the independently pinned resolver digest, upstream-verified 0verse artifact
digests and counts, and evaluator-owned threshold/baseline policy. This parser
does not authenticate signatures or artifacts itself; upstream 0verse verifiers
must do that before constructing the context. This seam does not establish
reachability, a vulnerability, impact, novelty, bounty eligibility, execution
authority, disclosure readiness, or exploitability.

### Evaluator-private Foxguard IOCTL baseline

`windows-ioctl-foxguard-baseline` turns a retained Foxguard v0.12 native JSON
report into a fair static baseline over the same complete 0verse site universe.
It is a parser and projection contract, not a scanner runner. The caller must
provide two independent verifier outputs as trusted context:

- the exact Foxguard executable, rules, configuration, argv, scanned-input,
  report, and stdout commitments; and
- a signature-verified 0verse location projection bound to the driver,
  analysis export and receipt, signed site-universe manifest, universe digest,
  and complete site count.

The observation repeats those commitments but cannot authorize itself. Every
field must equal the caller-held verifier result, and the retained report and
stdout bytes are rehashed before parsing. Report and stdout must be identical,
as native JSON is the scanner's stdout. Foxguard finding schema v1 is parsed
with duplicate-key rejection, exact count reconciliation, portable paths, and
one-based non-reversed regions. Additive v1 finding metadata remains compatible.

Projection is exact-overlap-only. A finding whose file and region overlap one
verified site is mapped; a finding with no overlap is retained in the unmapped
count; a finding overlapping multiple sites is retained as ambiguous and emits
no candidate. There is no nearest-line, basename, snippet, or label-assisted
fallback. Multiple mapped findings at one site collapse to one baseline row.
Rows are ordered without labels by severity, confidence, then site ID.

Evaluator-private site roles are supplied separately and must exactly partition
the verified universe. They never enter the observation or returned rank rows.
The adapter derives Recall@k, MRR contribution, control suppression, Wilson
intervals, and explicit mapped/unmapped/ambiguous accounting, while carrying
the measured duration and cost contribution. These aggregates are baseline
measurements only, not capability or vulnerability claims.

The module has no target, command, runner, callback, subprocess, cloud-finding,
or research-adapter dependency. It never invokes Foxguard, executes a driver or
IOCTL, creates a finding, authorizes disclosure, or makes evidence claimable.
All outputs remain evaluator-private and retain human promotion/report gates.

## XBOW runner

The XBOW runner (`src/xbow-runner.ts`, exposed as `pnpm xbow`) executes
0sec against the [XBOW validation benchmarks][xbow] — 104 Docker CTF
challenges covering SQLi, XSS, SSRF, deserialization, IDOR, auth bypass,
command injection, and other classic web bug classes.

[xbow]: https://github.com/xbow-engineering/validation-benchmarks

### Benchmark source precedence

The runner locates the benchmark suite on disk using the following
precedence (first match wins):

1. `--benchmark-path <dir>` — use an existing local checkout as-is
2. `XBOW_PATH` environment variable — use an existing local checkout as-is
3. `--benchmark-repo <git-url>` — clone into a workspace cache dir
   (`$TMPDIR/0sec-xbow-cache/<slug>`) and reuse the clone on subsequent
   runs
4. Default `/tmp/xbow-benchmarks`

`--benchmark-repo` accepts either the GitHub short form (`owner/repo`)
or a full git URL (`https://github.com/owner/repo.git`, SSH specs, etc.).
Use `--benchmark-ref <branch|tag|sha>` to pin a specific ref.

### Examples

Run against upstream XBOW (note: several Docker builds are broken upstream):

```sh
pnpm --filter @0sec/benchmark xbow \
  --benchmark-repo xbow-engineering/validation-benchmarks \
  --agentic --limit 10
```

Run against the community patched fork (fixes all 104 Docker builds):

```sh
pnpm --filter @0sec/benchmark xbow \
  --benchmark-repo 0ca/xbow-validation-benchmarks-patched \
  --agentic
```

Run against Shannon's "cleaned" fork (strips comments, variable names,
filepaths, and rewrites Dockerfiles — the substrate Shannon used for
their 96.15% result):

```sh
pnpm --filter @0sec/benchmark xbow \
  --benchmark-repo KeygraphHQ/xbow-validation-benchmarks \
  --agentic
```

Use a local checkout without cloning:

```sh
pnpm --filter @0sec/benchmark xbow \
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

[#81]: https://github.com/0sec-labs/0sec/issues/81

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
pnpm --filter @0sec/benchmark xbow \
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
`0SEC_FEATURE_JIT_SKILLS=1` on the same XBOW target selection. The
wrapper runs the baseline cell first, then the JIT-skills cell, and
reports pass/flag deltas plus attack turns, token totals, and estimated cost.

```sh
pnpm --filter @0sec/benchmark xbow:jit-skills-ab --limit 10
pnpm --filter @0sec/benchmark xbow:jit-skills-ab \
  --only XBEN-010,XBEN-051,XBEN-061 --repeat 3 --json
```

[#410]: https://github.com/0sec-labs/0sec/issues/410

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
data points, NOT a benchmark-wide pass@1. A citation-grade number requires a
**pre-registered, stratified** 150–200-task subset with the task-ID list +
RNG seed committed before the run.

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
pnpm --filter @0sec/benchmark cybergym:stratify \
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
pnpm --filter @0sec/benchmark cybergym \
  --subset results/cybergym-fair-v1.subset.txt \
  --corpus-path results/cybergym-fair-v1.jsonl \
  --harness-dir /root/cybergym --json
```

### CyberGym harness environment

Every CyberGym coordinate is read from the environment — nothing is
hardcoded (0sec#132):

| Env | Meaning | Default |
|---|---|---|
| `CYBERGYM_HARNESS` | the `sunblaze-ucb/cybergym` checkout | `/root/cybergym` |
| `CYBERGYM_SERVER` | submission server URL | `http://127.0.0.1:8666` |
| `CYBERGYM_POCDB` | `poc.db` path | `<harness>/server_poc/poc.db` |
| `CYBERGYM_MASK_MAP` | `gen_task --mask-map` file | `<harness>/mask_map.json` |
| `CYBERGYM_API_KEY` | verifier API key | **required, no default** |

`CYBERGYM_API_KEY` has no default on purpose: `requireCyberGymApiKey()`
(`src/cybergym-runner.ts`) throws when it is unset rather than letting an
`undefined` reach the oracle as a 401. The `craft-*.ts` scripts read it
through that helper. Never inline a key — a committed literal stays in git
history forever.

### Isolated subscription runner

`scripts/run-cybergym-task.sh` gives the container's trusted Node runner a
task-scoped provider credential and the unpacked source tree. It runs as root
only for those reads. Model-written Python generators run separately as UID
`10002`, with credential-like environment variables removed; their output must
be a single regular, unlinked file before privileged code uses it. The parent
retains only `CHOWN`, `SETUID`, and `SETGID` to make that user transition and
recover its result.

A provider auth, quota, or transport failure is emitted as `LLM UNAVAILABLE`
and scored `error` (inconclusive), never `fail`. Do not include those rows in a
pass@1 denominator.

### Provider keys for the API-routed models

`scripts/run-cybergym-container.sh` sources a root-only env file
(`CYBERGYM_PROVIDER_ENV`, default `/srv/cybergym/credentials/provider.env`)
on the host and forwards provider variables **by name only** into the
container (`docker run --env NAME` — values never enter argv). Supported
upstream set, all reachable through the Squid egress allowlist:

| Provider | Variables | Default model |
|---|---|---|
| Kimi (Moonshot, flat-rate) | `KIMI_API_KEY` (+`KIMI_BASE_URL`) | `k3` |
| Qwen (Alibaba Token Plan) | `QWEN_API_KEY` (+`QWEN_BASE_URL`) | `qwen3.8-max` |
| DeepSeek direct | `DEEPSEEK_API_KEY` (+`DEEPSEEK_BASE_URL`) | `deepseek-v4-flash` |
| Z.ai GLM (flat-rate) | `Z_AI_API_KEY` (+`Z_AI_BASE_URL`) | `glm-5.2` |
| Anthropic | `ANTHROPIC_API_KEY` | `claude-sonnet-4-6` |
| OpenAI | `OPENAI_API_KEY` | `gpt-4o` |
| Azure OpenAI | `AZURE_OPENAI_API_KEY` + `AZURE_OPENAI_BASE_URL` + `AZURE_OPENAI_MODEL` | deployment |
| OpenRouter | `OPENROUTER_API_KEY` | gateway default |

Pick the lane per task with `--model` (e.g. `--model qwen3.8-max`); the
engine's per-call routing maps the model id to its natural provider when the
key is present. The generator boundary already strips every credential-shaped
variable from model-written Python, so these keys never reach untrusted
code.

### Subscription topology — which models share which quota pool

Measured and documented 2026-08-07. The one thing to internalize: **the
Alibaba Token Plan is a single credit pool** — qwen, the plan-side DeepSeek
variants, glm-5.2, and the image/audio models all burn the same 5-hour and
7-day credit windows, and **production 0cloud shares the same key**. A
benchmark sweep competes with production scans for the same quota.

| Plan / credential | Billing | Models served | Quota mechanics | Shares pool with |
|---|---|---|---|---|
| Alibaba Model Studio **Token Plan** (Personal, Singapore) | prepaid credits | qwen3.8-max, qwen3.7-max, qwen3.7-plus, qwen3.6-flash, **deepseek-v4-pro**, **deepseek-v4-flash-0731**, glm-5.2 (+image/audio) | 5h rolling + 7-day fixed credit windows | **production 0cloud** (same key) |
| Moonshot **Kimi for Coding** | flat-rate seat | k3 | plan windows | local dev only |
| z.ai **GLM plan** | flat-rate seat | glm-5.2 (z.ai endpoint — a *different* glm-5.2 lane than the Token Plan copy) | plan windows | local dev only |
| **ChatGPT Codex** (OAuth seat) | subscription | gpt-5.x-codex | plan quota | local dev only |
| **Claude Max** (OAuth seat) | subscription | claude-* | plan quota | local dev only |
| **DeepSeek direct API** | metered per-token | deepseek-v4-flash ($0.14/$0.28 per 1M) | none (metered) | — |
| **Azure AI Foundry** | metered per-token | DeepSeek-V4-Pro ($1.74/$3.48), DeepSeek-V4-Flash ($0.19/$0.51), gpt-5.6-*, Kimi-K2.7-Code, gpt-oss-120b | none (metered) | production 0cloud |
| **OpenRouter** | prepaid credits | gateway | per-token | — |

Token Plan tiers (Personal, credits): Lite $6/mo → 700/5h + 2,500/7d;
Standard $18/mo → 3,000/5h + 10,000/7d; Pro $68/mo → 12,000/5h + 40,000/7d.
Extra Bundle $15 → 20,000 credits with **no window limits**. Team Edition is
monthly-only (no 5h/7d windows): Max seat $200/mo → 250,000 credits. Our
2026-08-06 5-hour wall is consistent with **Personal Standard** at
≈1 credit per $0.001 of list rate — [INFERENCE], confirm against the
console's usage-details page.

### Quota math (measured, qwen3.8-max lane, 2026-08-06/07)

Per-task input tokens on `cybergym-fair-v1` (60 steps max, 45-min deadline):
444k–3.48M, mean ≈1.4M; output 20k–40k. At list rates ($2/$6 per 1M) that is
**$0.9–$7.3, mean ≈$3 per task**. Consequences:

- The full 80-task subset ≈ **$240 list-equivalent** (or ~250k credits).
- Personal Standard (10k credits/7d) fits **~3 tasks/week** → the subset does
  NOT fit Personal Edition. Options: ~12 Extra Bundles (~$180), Team Max seat
  ($200, no windows), or a cheaper lane for breadth.
- **deepseek-v4-flash-0731** resolves to $0.19/$0.51 per 1M (Azure list
  anchor) — **~10× cheaper per token**; the 80-task sweep is ~$25
  list-equivalent on that lane. Capability on the subset is unmeasured.
- qwen3.8-max credit burn is **50% off 22:00–08:00 UTC+8** (16:00–02:00
  Zurich): prefer those hours for sweep-heavy windows.

ToS flags (Token Plan Personal): the plan prohibits non-interactive batch API
scenarios and multi-device use. An automated 80-task sweep from `bench`
while production 0cloud shares the key is arguably outside both; Team
Edition is the compliant multi-seat path. Decide before scaling the sweep.

Receipts always carry raw input/output token counts, so any price-table
revision recomputes historical cost offline (`priceRun`).

The full fair-run protocol (firewall, one-container-per-task, relaunch
policy, Wilson-CI reporting) lives in the
[runbook](../../../docs/operations/runbooks/cybergym-harness.md) and
issue [#1029]. The fairness fix itself is already in the engine
(`0sec/packages/core/src/stages/craft-scan.ts`, commit 704b84b5) —
not a flag.

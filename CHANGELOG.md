# Changelog

All notable changes to 0sec (the open-source CLI + agent harness) are tracked
here. The history before v0.11.0 lives in the git log and on the GitHub
Releases page; this file starts the human-readable summary from v0.11.0
onwards. Entries before v0.13.0 predate the pwnkit → 0sec rename and keep the
old product name as written.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and 0sec adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
on the published npm package and the GitHub Release tag.

## [Unreleased]

### Added

- `bench improvement-assess` binds sealed improvement results to champion and
  challenger artifact digests, evaluates promotion gates, and writes a
  create-once decision plus hash-chained ledger snapshot. Generic artifacts
  require human approval; the command never executes or deploys a candidate.
- The stdio MCP server accepts `--tools <comma-separated-names>` to limit the
  model-visible 0sec tool set. The source-checkout DSH runner defaults to the
  bounded recon profile rather than exposing every live tool schema.

### Changed

- Fresh `scan`, `audit`, `review`, legacy scanner, MCP, and persisted-ingest
  executions now own `~/.0sec/runs/<run-id>/state.db` rather than contending
  on one user-global SQLite file. `0sec history` and `0sec findings list`
  aggregate run-local state; `0sec resume` resolves an unambiguous abbreviated
  run id.
- Managed workers bind the local run directory, database, and final report to
  their 0cloud scan id. The worker controller retrieves that report after the
  engine exits and posts it through the retrying, idempotent final-report path,
  so transient per-finding webhook loss cannot silently erase the completed
  scan's findings.

## [0.13.0] - 2026-08-19

### Changed — pwnkit is now 0sec

The engine and CLI are renamed from pwnkit to 0sec, matching the public
repository (`0sec-labs/0sec`):

- **Package identity:** the root bundle is `0sec`. The workspace CLI package is
  `0sec-cli`; the binary shipped by both is **`0sec`**, with **`0`** as a
  short shell alias (`0 scan ...`). Neither package is published to npm yet.
- **Container image**: `ghcr.io/0sec-labs/0sec` (was `ghcr.io/0sec-labs/pwnkit`).
- **Standalone distribution:** GitHub Releases ship verified binaries for Apple
  Silicon macOS, Linux x64 and arm64, and Windows x64. Install with
  `curl -fsSL https://raw.githubusercontent.com/0sec-labs/0sec/main/install.sh | bash`
  on supported Unix hosts, or download the matching release asset directly.
- **Environment variables**: the public env contract moved from `PWNKIT_*` to
  `0SEC_*` (e.g. `0SEC_MODEL`, `0SEC_CLOUD_TOKEN`). At CLI startup, any legacy
  `PWNKIT_*` value is copied onto its `0SEC_*` equivalent when the new name is
  unset, so existing deployments keep working; the new name always wins
  (`packages/cli/src/env-legacy.ts`).
  Note: POSIX shells reject digit-leading variable names, so `0SEC_*` vars
  cannot be set or expanded in bash/sh directly — use `env 0SEC_FOO=... 0sec
  ...`, or keep using the permanently supported `PWNKIT_*` names in shell
  contexts. Docker `-e`, CI env blocks, and systemd units are unaffected.
- **Workspace packages** moved from the `@pwnkit/*` scope to `@0sec/*`.
- Internal canary/marker strings (`PWNKIT-CANARY:`, `PWNKIT-INITRAMFS-*`,
  `PWNKIT-INJ-OK`) are wire protocol tokens between generated exploits and the
  verifier; they are unchanged and not part of the public interface.

## [0.12.0] - 2026-07-17

### Added — z-ai (GLM) and kimi (Moonshot) providers

pwnkit-cli can now drive scans through Z.ai's GLM models and Moonshot's Kimi K3
"coding" endpoint. Both are Anthropic-compatible: they ride pwnkit's existing
`/v1/messages` wire (`x-api-key` + `anthropic-version` headers, Anthropic-shaped
request body + response parser) rather than the OpenAI chat/completions path.
Each provider is selected by an explicit operator opt-in key, and either wins
over the global env priority when the requested model maps to it (e.g.
`glm-5.2` → z-ai, `k3` → kimi), so one process can fan calls across providers.

- **feat(llm-api): add Z.ai GLM provider — Anthropic-compatible wire.**
  Activated by `Z_AI_API_KEY`; base URL overridable via `Z_AI_BASE_URL`
  (default `https://api.z.ai/api/anthropic`), default model `glm-5.2`. GLM's
  hybrid reasoning is off by default on this endpoint, so pwnkit enables it via
  the Anthropic extended-thinking field; the budget is tunable through
  `PWNKIT_ZAI_THINKING_BUDGET` (default 2048, `0` disables).
- **feat(llm-api): add Kimi K3 (Moonshot) provider + pricing** (#68).
  Activated by `KIMI_API_KEY`; base URL overridable via `KIMI_BASE_URL`
  (default `https://api.kimi.com/coding` — distinct from Z.ai so kimi requests
  never hit api.z.ai), default model `k3`. K3 emits native `thinking` blocks on
  the Anthropic wire, so no thinking body param is applied.
- **note(runtime): prompt caching is opt-in and fails closed for these two.**
  Because their cache semantics are unverified, GLM and Kimi emit **no**
  `cache_control` markers by default (byte-identical bodies to before). Opt in
  per provider via `PWNKIT_PROMPT_CACHE_EXTRA_PROVIDERS` (comma-separated, e.g.
  `z-ai,kimi`).
- **fix(runtime): guard the Anthropic-wire routing with a positive predicate.**
  z-ai/kimi previously rode the Anthropic wire only by being absent from the
  `isOpenAICompat` getter while carrying a misleading `wireApi:"chat_completions"`
  tag. Routing now keys off an explicit `isAnthropicWire` predicate; the
  `wireApi` field for these two is an inert, intentionally-unused default.

## [0.11.0] - 2026-05-16

### Added — chatgpt-codex direct-API provider

pwnkit-cli can now drive scans through a user's ChatGPT Plus/Pro subscription
via the operator's existing `codex login` auth — no Platform API key required.
The new `chatgpt-codex` provider reuses pwnkit's own Responses-API path, OWN
prompts, OWN tools, OWN agent loop, and OWN cost/turn caps; the `codex` CLI
is **not** spawned as a child process, so all scan modes (web + audit + review)
keep native pwnkit control on top of the subscription-billed zero-marginal-cost
auth path.

- **feat(runtime): chatgpt-codex provider — direct API via ChatGPT OAuth** (#327)
  Activates when `PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN` is set; takes priority
  over api-key providers. Mirrors opencode's ChatGPT-Codex pattern with
  pwnkit-specific headers (`originator: pwnkit`, `ChatGPT-Account-Id` from JWT,
  stable `session_id`). `max_output_tokens` is intentionally omitted per the
  upstream convention.
- **fix(llm-api): send `instructions` field for chatgpt-codex Responses** (#330)
  System prompts were being dropped from the Codex `/responses` body; the
  provider now forwards them in the `instructions` field where Codex expects
  them.
- **fix(llm-api): capture chatgpt-codex tool calls from `output_item.done`** (#331)
  Tool calls were being missed when the Codex stream delivered them as
  `output_item.done` events rather than as deltas. The parser now reads from
  both paths.
- **fix(llm-api): prefer streamed items over empty Codex `output[]`** (#332)
  The terminal `response.completed` event sometimes ships an empty `output[]`;
  pwnkit now keeps the items accumulated from the stream instead of clobbering
  them with the empty terminal payload.
- **feat(llm-api): accept pre-issued ChatGPT Codex `access_token` via env** (#334)
  `PWNKIT_CHATGPT_OAUTH_ACCESS_TOKEN` lets the cloud orchestrator inject a
  short-lived access token directly, skipping the refresh-token exchange.
  Refresh-token flow remains the default for local operators.

### Added — audit `done` coverage gate

Audit and review sub-agents could previously emit `done` after a single
`read_file: package.json` and exit in 11 seconds with 0 findings. A recent
`@vercel/og` batch (also `@vercel/postgres`, `@vercel/kv`, `@vercel/blob`,
`@vercel/edge-config`, `@auth0/nextjs-auth0`) hit this failure mode; working
scans on the same pipeline made hundreds of tool calls and produced 26
findings each, so the bug was in the agent's `done` heuristic, not the
targets.

- **feat(audit): refuse `done` from sub-agents that haven't inspected source** (#335)
  When a sub-agent with role ∈ {audit, review} and a `scopePath` calls `done`,
  a coverage gate runs. It passes when **any** of:
    1. `>= PWNKIT_AUDIT_MIN_COVERAGE_FILES` (default 3) distinct source files
       have been read (extensions: `.ts/.tsx/.js/.mjs/.cjs/.jsx` plus
       `.py/.rs/.go/.java/.rb/.php/.c/.h/.cpp/.hpp`),
    2. at least one `run_command` invocation succeeded,
    3. wall-clock > 60s **and** >= 5 tool calls, or
    4. the agent has already been rejected twice in this session
       (no deadlock on a legitimately-empty audit).
  Rejections return a tool-result error with concrete next-step guidance
  ("read `src/index.*` or `lib/index.*`, or run a `run_command` with
  grep/rg"). The gate is scoped to source-code audits — flag-hunting against
  remote targets is unaffected, and discovery/attack/verify roles bypass it
  entirely. Threshold is tunable via `PWNKIT_AUDIT_MIN_COVERAGE_FILES`.

### Added — agent + scanner

- **feat(agent): `apply_patch` tool with structured DSL for reliable file edits** (#275)
- **feat(agent): per-finding verify loop + per-file research/audit loops** (#291,
  closes control-flow audit H2 #285)
- **feat(agent): preserve credential/exploit-bearing messages during compaction** (#270,
  closes #229)
- **feat(agent): XML-tag dispatch fallback for cheap-model resilience** (#279,
  closes #232)
- **feat(agent): journal writer foundation** (#321)
- **feat(scanner): gate Codex live scans behind MCP runner** (#295)
- **feat(executor): UUID-suffix container names + `--rm` for parallel sweeps** (#276,
  closes #233)
- **feat(events): include `cost_usd`, `cost_breakdown`, `cost_per_flag` in
  `scan_completed`** (#278, closes #231)

### Added — CLI surface

- **feat(cli): scaffold `pwnkit auth login/logout/status` + `cloud.env` loader** (#315)
- **feat(cli+core): zod-validate the remaining `JSON.parse` sites flagged in
  type-safety audit** (#308)
- **feat(cli): zod-validate `Finding` + `PocStep` JSON inputs in verify/disclose** (#300)
- **feat(h1): pwnkit h1 CLI foundation — auth, programs list/show, scope dump** (#265)
- **feat(review): linux-kernel profile — kernel-aware static review** (#277,
  closes #268)
- **feat(review): c-library profile for C/C++ source-code review** (#261)
- **feat(kernel): foxguard variant-hunt orchestration** (#297)

### Fixed

- **fix(audit, review): hard tool-call / turn budget in prompts** (#318)
- **fix(runtime): retry `isAvailable` on cold-sandbox first-exec slowness** (#317)
- **fix(runtime): handle `codex item.type=mcp_tool_call`** (#311)
- **fix(audit): emit cloud stream events for codex CLI fast-path** (#312)
- **fix(codex-mcp): unblock MCP tool calls + strengthen prompt + dedup stream** (#306)
- **fix(cli): `pwnkit dashboard --no-open` actually suppresses browser open** (#319,
  closes #316)
- **fix(tools): inject auth into bash `curl`/`wget` when scope + authConfig
  are set** (#290, closes #282)
- **fix(tools): dedup findings at `saveFinding` via similarity check** (#288,
  closes #281)
- **fix(tools): refuse empty-PoC findings at `saveFinding`** (#287, closes #283)
- **fix(parser): validate `file:line` existence in `parseStructuredBlocks`** (#289,
  closes #286)
- **fix(h1): contrast-clause aware automation-verdict heuristic** (#274,
  closes #266)
- **fix: resolve local targets with shell path semantics** (#294, closes #255)
- **fix(tui): constrain long text in opentui screens** (#320)

### Refactored

- **refactor(core): remove `Finding` enum `as any` casts** (#305)
- **refactor(cli) + docs: drop `run.ts` type-dup, add h1 docs, flip
  scope-ingestion to shipped** (#299)

### Tests

Coverage backfill for previously-zero CLI / core modules: `triage.ts` (#322),
`findings.ts` (#323), `dashboard.ts` (#314), `orchestrate.ts` (#313),
`mcp-server.ts` (#310), `db.ts` (#309), `disclose.ts` (#307),
`run.ts` + `scan.ts` (#301), and `unified-pipeline.ts` dispatch + ecosystem
paths (#326). Plus `crawl` no-redirect happy path + redirect-loop cap (#267)
and `cost.ts` model rate table + prefix stripping (#257).

### Docs + research

- **docs(research): journal orchestrator design doc** (#259, closes #224)
- **docs(research): cost-per-flag deep dive — the missing axis in agent
  reporting** (#256)
- **docs(blog): control-flow audit — 5 chokepoints gated in code** (#296,
  closes #280)
- **docs(agents): mandate worktrees for parallel top-level agent sessions** (#264)
- **docs(agents): issue-assignment claim-before-start rule** (#273)
- **docs(readme): trim Snapshot block to one-liner + link canonical benchmark
  page** (#260)
- **docs(readme): drop stale v0.9.0 'npm shim' heads-up; clarify binary
  names** (#262)
- **feat(bench): per-model cost aggregation in `consolidate-xbow` output** (#258)

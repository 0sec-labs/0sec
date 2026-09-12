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

- Messenger conversation framing and the Agents sidebar default on while saved
  alternatives and explicit opt-outs remain effective. Clickable sidebar controls,
  compact worker activity and a single configured-scope display preserve chat state.
- `/copy` (`/export`, `/dump`) saves the complete public conversation as private
  local JSON and attempts clipboard delivery. OSC52 delivery remains unverified.
  `/impact` loads a saved finding into the current chat for evidence-qualified analysis.
- Finding detail prioritizes title, severity and CVSS, with distinct evidence
  sections. Endpoint metadata uses the same redacted request as the evidence body.
- Context meters report unavailable when runtime window data is missing. Hosted
  Cloud credit state remains separate from estimated model cost.
- Cloud sign-in, BYOK credentials, and provider subscriptions are separate
  connection choices. Cancelling sign-in returns to the current conversation;
  changing the provider or model applies to the next chat. Login alone does not
  establish model availability or a funded account.
- `0sec balance` displays the service-reported percentage of inference credits
  remaining. Missing percentage data stays unavailable; JSON retains accounting
  fields, and reservations remain distinct from settled spending. Small positive
  balances display `<0.1%`; nearly full balances display `>99.9%`.
- Interactive YOLO public-network tools no longer require a launch target or
  approval for each discovered public host. Explicit configured restrictions,
  exclusions, prior refusals, private-address checks and credential boundaries
  remain enforced. Search results do not change target or scope.
- Browser HTTP requests in public-network mode are bound to the current tool
  action; cancellation prevents delayed dispatch and held-response delivery.
- Entering a previously declined host directly in chat reopens scope approval.
  Approval preserves the conversation and exclusions; model retries remain denied.
- Main and worker transcripts share expandable command and output views.
  Status rows and pickers use Nerd Font icons with retained text labels;
  glyph appearance depends on the terminal font. Cancellation keeps partial
  output without adding a persistent interruption notice.
- Removed the persistent problem-reporting invitation from the chat footer.
- Target HTTP tools check scope and resolved addresses before connecting and
  following redirects. Requests pin destination addresses, retain TLS hostname
  verification, and bound decoded bodies and elapsed time. WordPress advisory
  requests use a separate service-bound transport.
- The standalone CLI runtime includes the existing PDF report dependency.
- Console guidance asks for useful parallel delegation on independent work and
  evidence-backed finding summaries while retaining scope and budget limits.
- Contextual model, session, finding, usage, worker, and marketplace views use
  compact controls. Usage reports scroll without losing unknown-cost markers;
  worker steering accepts pasted text, and marketplace actions retain confirmation.
- Child runtimes inherit the parent's resolved provider configuration.
  Scoped harness shutdown drains work before disposal and reports incomplete
  cleanup. Restarting an engine does not reconstruct active harness state.
- Problem reporting defaults to automatic limited diagnostics with a global
  off/ask/automatic preference. Explicit opt-outs remain effective; project
  settings cannot override the preference. Reports exclude prompts, tool
  arguments, output, paths, and credentials. Delivery requires Cloud sign-in
  or a configured HTTPS endpoint; manual feedback retains review and local capture.
  Feedback submission rejects redirects to unreviewed destinations.
- Update checks and automatic installation use an operator-global policy.
  Automatic installation is opt-in and completes before interactive startup;
  notification-only checks remain in the background. Manual upgrades retain
  their version and destination options and report failures or interruption.
- `/explain` and `/eli5` request a short explanation in everyday words without
  new tool execution. The idle worker panel suggests how to request subagents.

- Executable TypeScript plugins, reusable skills, and agent programs can be
  created during a session, composed through tool/model brokers, retained
  across restarts, replaced, and rolled back. Evaluated source evolution can
  activate measured versions and explore compatible archived alternatives
  without confusing their provenance with the deployed rollback parent.
  Docker and local smolvm provide isolated execution; provider credentials
  stay in the controller. New console sessions default to YOLO within their
  configured authorization scope; `console --scope` now also reaches the
  full-screen UI instead of being dropped during startup.
- Source evolution can recover from a fully observed zero-success baseline
  without treating its undefined cost-per-success as missing evidence.
  Candidate costs must still be finite, and evaluation budgets, private
  lanes, negative controls, approval policy, and canaries still apply.

- Worker inspection now retains text-only final answers, live tool snapshots,
  and expandable commands, output, diffs, and tool details. Completed workers
  remain navigable; live steering is consumed at model boundaries, finished
  one-shot follow-ups return to Main with quoted context, and persistent workers
  notify their parent. Status rows distinguish worker measurements and context
  from turn-spend limits. Plans expand into scrollable full descriptions, and
  worker transcripts preserve their scrollable extent through detail and size
  changes without leaking layout state into the Main conversation.

- Native desktop development is paused. Root desktop launch and packaging
  shortcuts are removed, and the macOS packaging workflow is archived.
  Desktop source and CLI-required dashboard components are retained.

- YOLO console sessions can acquire public HTTPS Git repositories for local
  review without authorizing their hosting services as testing targets.
  Standalone clones run without a shell through a public-address-pinned tunnel,
  with isolated Git configuration and bounded execution. Explicit exclusions,
  declined-host memory, and private-network protection remain enforced.
  Git checkout failures are reported as failures rather than successful output.

- Console history now connects to the persistent findings database across TUI,
  readline, one-shot, and desktop sessions. `--db-path` also works without
  `--finding` and follows history navigation. Read-only `list_conversations`
  and `read_conversation` tools expose saved chats through the existing session
  store, with project-local discovery, explicit cross-project search, bounded
  transcript pages, and credential redaction. Raw provider payloads, hidden
  reasoning, and tool-result bodies are excluded.
- Independently buildable, non-root `toolbox` image target with Node 24 and
  the existing security/identity/Foxguard inventory. The default distribution
  target reuses it and adds the CLI. A real offline smolvm qualification checks
  37 tool startups, Python imports, guest-local Nmap/curl behavior, and Foxguard
  positive/clean fixtures. Architecture guidance distinguishes OCI packaging,
  worker isolation, global sandbox gaps, and a measured path to native execution.
- Opt-in Linux smolvm 1.14.6 execution for source evolution, including approval
  and pinned future workers. Archive bytes are pinned and copied before boot;
  source mounts are read-only, workspaces guest-local, and credentials/network
  access excluded. Host deadlines, cancellation, output caps, and verified
  teardown fail closed. Docker remains the default. A real microVM qualification
  script and smolvm mode for the provider-backed source lifecycle are available.
- `evolve exec` now forwards terminal interrupts to the running worker and waits
  for its cancellation result instead of abandoning execution on the first signal.
- Refresh the bundled model picker and pricing with GPT-6 Astra, DeepSeek V4.1
  Flash, Claude Fable 5.1 / Opus 5 / Sonnet 5, Gemini 3.1 and 3.5–3.8 text
  models, GLM-5.3-Flash, and Qwen 3.8 Flash / 3.7 Plus / 3.6 Plus and Flash.
  The offline Qwen catalog also includes the unpriced 3.8 Max preview.
  Qwen estimates now include published cache-read rates where available.
  Direct DeepSeek now defaults to its stable
  `deepseek-flash` API id; existing Azure and Token Plan routes are preserved.
  GPT-6 requests use the reasoning-model output cap and Responses reasoning
  defaults. Astra remains opt-in; estimates use base rates, not long-context,
  cache-write, or off-peak billing tiers.
- Console interaction improvements: curated/all model browsing, stable detail
  panes, searchable command navigation across control screens, and model changes
  that preserve the transcript and unsent draft. Fast input followed by Enter
  selects the current query rather than the previous highlight.
  Settings support paste, Unicode editing, immediate value cycling, and clearer
  changed-state/save feedback. Saved sessions default to the current project,
  retain recoverable errors, and require explicit, cancellable deletion.
  Worker monitoring adds search and clearer state labels; live plans prioritize
  active tasks without overflowing their sidebar. Working indicators honor
  reduced motion and no longer animate failed startup as connecting.
  OpenAI model selection retains configured custom API endpoints.
- Evolution passes recover compatible development feedback from retained
  proposals and evaluation receipts, including after promotion. Proposal and
  receipt digests are checked; held-out and negative-control feedback stays
  sealed. This does not add restart-safe campaign budget accounting.
- Interactive source findings with missing or out-of-range citations return
  repairable validation errors before persistence. Source reads and citation
  checks no longer count a terminal newline as an additional source line.
  A real-model citation-repair lane joins the trusted-main evolution E2E checks.
- Scoped native-API research can retain source-hashed codebase notes and reuse
  current notes in later runs. Verification stays cold, and changed or unsafe
  evidence is excluded. A real-model learning lifecycle check is available in
  the trusted-main evolution workflow.
- Canonical CLI documentation at `docs.0.security`, with task-oriented command
  navigation, source-audited workflow guides, neutral light/dark styling, and
  responsive navigation. Unreleased 0cloud and desktop guides remain contributor
  drafts, excluded from public routes and search.
  Existing product-guide URLs redirect to their roadmap status.
- Development desktop chat now renders streamed Markdown, expandable tool
  activity, and interruption states without duplicating final responses.
  Following output respects manual scrolling; code copying is limited to the
  focused local dashboard, while clipboard reads remain denied.
- Development desktop now uses a thread sidebar, an anchored composer, neutral
  system appearance, accessible dialogs, and per-thread drafts. macOS gets real
  window controls, native folder selection, menu shortcuts, and close/reopen
  behavior that keeps the existing sidecar alive. The sandboxed preload is
  compiled as CommonJS; native requests are restricted to the trusted main frame.
  Terminal turn failures remain visible even when no assistant text was produced.
- `pnpm docs:sync` refreshes registered CLI arguments, options, defaults, and
  aliases without replacing reviewed workflow or safety notes. `pnpm docs:check`
  blocks stale command references in CI and before documentation deployment.
- Source proposals can inspect recent retained worker versions without
  reopening removed source paths or applying edits against stale digests.
- Opt-in `0SEC_LOG_FORMAT=json` operational records on stderr, with
  allowlisted lifecycle/cost metadata and credential redaction. Existing
  stdout output and cloud event relay framing remain unchanged.
- Stateful `access_control_workflow` verification with isolated identities,
  explicit mutation consent, scoped multi-step requests, and owner-observed
  state transitions rather than HTTP-status-only claims.
- `review --fix-commit <sha> [--variants-only]` for bounded, heuristic
  JavaScript/TypeScript/Python incomplete-fix leads.
- Two-phase `verify --create-bundle` and `verify --bundle` with allowlisted
  snapshots, integrity and runtime checks, explicit runner selection, and
  vulnerable/patched negative controls. Failed processes never confirm a fix.
- Real Docker replay CI covering container isolation, workspace paths, timeout
  cleanup, scoped HTTP, and vulnerable/patched negative controls.

- `0sec evolve` — autonomous self-improvement plane with config-driven source
  candidate proposals, three-lane (development/held-out/negative-control)
  evaluation in isolated Docker containers, and durable promotion with canary
  and rollback. Subcommands: `run`, `status`, `promote`, `rollback`, `exec`,
  `feedback capture`, `feedback approve`, `feedback status`, and `feedback release`. Source rewriting requires
  explicit `allowModelSourceAccess` consent; `autoPromote` replaces the
  previous blanket "no automatic source-code promotion" with configured
  autonomy. Config schema version 1 with zod-validated fields including
  `schemaVersion`, `sourceRoot`, `storePath`, `image`, `sourcePaths`,
  `editablePaths`, `kind`, `command`, `buildCommand`, `cases`, `repeats`,
  `maxIterations`, `maxModelTurns`, `maxModelCostUsd`, `maxEvaluationCostUsd`,
  `computeUsdPerSecond`, `timeoutMs`, `memoryMb`, `cpus`, `maxOutputBytes`,
  `maxSourceBytes`, `maxChangedBytes`, `model`, `objective`,
  `allowModelSourceAccess`, `autoPromote`, `canaryTrials`, and
  `promotionPolicy` with per-gate thresholds.
- Evaluation runs in network-none, read-only Docker containers with
  `--cap-drop=ALL`, `--security-opt no-new-privileges`, bounded CPU/memory/pid,
  and tmpfs output. Docker image tags resolve to immutable IDs retained in
  pinned worker configurations; resumed workers do not follow mutable tags.
- `runEvolution` acquires an exclusive PID-bound controller lock per store.
  Interrupted canaries are rolled back before the next evolution pass.
- Immutable, content-addressed snapshots under `storePath/snapshots/<id>/` with
  symlink, secret, and nested-store rejection. Edits are validated for path
  boundaries, bounded changed bytes, before/after digests, and duplicate
  prevention.
- `executeEvolutionVersion` pins code+stored config+input digest per run,
  rejects changed command, and validates known config cases — mismatch rolls
  active version back to parent (operator cancellation excluded). Unknown inputs
  have no ground truth and are never auto-labelled.
- Hash-chained registry event log (`recorded`, `canary_started`, `promoted`,
  `rolled_back`) with atomic O_EXCL artifact publication and fsync.
- `0sec lens-synth --status` and `--rollback` — inspect and retire overlay
  lenses from the durable appsec-archetypes registry.
- `artifact-bridge.mjs` — CLI bridge for skill/router promotion authorization
  against the evolution registry. Used by skill-refine and active-learning loops
  with `--evolution-store`, `--evolution-version`, `--evolution-artifact` flags.
- Lens evaluation requires independent positive, held-out, and clean-control
  fixtures, conjunctive finding identity matching, measured usage and latency,
  repeated results, and content-bound receipts. Automated promotions archive
  the validation report beside the installed overlay version.
- Approved feedback preserves held-out separation and original miss provenance;
  completed outcomes are retained, with explicit recovery for crash-held claims.
- Future hunt outcomes and retained corpus rows identify the exact installed
  finder-lens version; changing an overlay cannot relabel an in-flight scan.
- Extension resume restores descriptor identities atomically and rejects
  non-reconstructible contributed guards instead of silently weakening policy.
- `deep-review --evolution-config` deploys a promoted source finder through the
  isolated worker path. Parent/child pins preserve one version per review;
  strict file-bound leads still pass through independent verification. Reports
  retain version identity and separately budgeted local compute estimates.

### Fixed

- Craft helpers pass model-provided paths as literal arguments rather than
  shell text. Replay container launches validate image references and keep
  mount paths and command arguments separate from shell syntax.

- Windows Cloud sign-in passes the browser URL as data to a fixed launcher
  command, so URL metacharacters are not interpreted as shell commands.

- Source evolution rejects candidates that lose an already-solved case, even
  when aggregate development and held-out scores improve. The retention check
  also applies to approval and canary evaluations.

- The toolbox image includes system `sbin` directories on `PATH`, making the
  packaged John executable available to the non-root CLI. Published-image
  smoke checks now exercise John startup.

- Source-evolution confidence intervals no longer treat repeated executions of
  the same fixtures as independent evidence; unstable repeats cannot produce
  an informative interval.
- Empty model refutations remain unresolved in the hunt ledger instead of
  becoming disproven claims that bias later runs' known-negative context.
- Target-history inference rejects repository metadata symlinks that resolve
  outside the authorized root, including intermediate `.git` directory links.
- Codebase-memory evidence uses bounded descriptor reads and rechecks canonical
  paths; changed source, symlink escapes, and multiply linked files are rejected.
- Source hunt finders and refuters use the scoped source-analysis runner instead
  of launching network discovery, attack, and verification phases for each file.
  Source prompts now describe the scoped enumeration/search tools actually available.
- The DeepSeek MCP profile now disables the web-fetch provider alongside its
  web service, preventing headless startup from waiting on a disabled service.
- Source enumeration no longer follows repository symlinks or includes
  multiply linked files. Deep-review also checks resolved subsystem paths
  against the prepared source tree before exposing source to a finder.
- Foxguard integration now consumes native v1 JSON reports instead of silently
  dropping their findings. The npm fallback is pinned to v0.13.0; provisioned
  binaries are used directly, and multi-path scans use valid CLI invocations.
- Installers, container builds, and scanner CI provision a checksum-verified
  FoxGuard companion from a shared version/hash pin; the default installer
  includes it unless `INSTALL_FOXGUARD=0` is set.
- Explicit package scans run from their source root, preventing a
  `node_modules` ancestor from causing all package files to be skipped.
- Invalid Foxguard JSON and scanner error exits no longer count as clean
  static scans. The default scanner no longer falls back implicitly to Semgrep;
  `0SEC_STATIC=semgrep` remains an explicit optional compatibility mode.
- Cross-validation and kernel variant hunting use the released Foxguard CLI
  syntax. SARIF file URIs are decoded, and cross-validation no longer matches
  unrelated source files solely by basename.
- Canary startup verifies the candidate's on-disk snapshot before changing
  registry state, rejecting altered code even when its retained receipt is valid.
- TUI evolution ignores stale callbacks after reconfiguration or stop and
  avoids releasing feedback claims already marked processed.
- Approved feedback claims record process ownership. Startup recovers only
  demonstrably dead owners in the same process scope; live or unverifiable
  owners remain claimed, and obsolete completion tokens cannot publish results.
- Benchmark fixtures now bind the `0sec` schema namespace introduced by the
  earlier rename. Recomputed commitments preserve the original labels and
  MSRC source-byte hashes; validators still reject tampered provenance.
- Finding and PoC JSON validation is shared between CLI ingestion and bundle
  replay rather than maintained as divergent schemas.
- Docker shell replay honors workspace-relative `cwd` and rejects absolute
  paths or traversal outside the mounted workspace before launch.

### Security

- Upgrade Astro to 7.2.8 and sharp to 0.35.4 (libheif 1.23.2), fixing
  AVIF-processing vulnerabilities GHSA-26w7-cxv4-gfx2 and GHSA-rgj7-g3m4-5g8c.
  Astro stays on the compatible 7.2 patch line for the existing Markdown peer.
- Require js-yaml 4.3.2 or later so empty merge sources count toward the parsing
  budget (GHSA-2883-xcg3-v3hh).
- Require Hono 4.13.5 or later for static-generation path containment, bounded
  dot-notation body parsing, and fragment-aware query parsing
  (GHSA-gqvv-2mrq-wpjv, GHSA-g6gw-c38x-mqfc, GHSA-crvj-82cr-hjcx).
- Require smol-toml 1.7.1 or later to reject malformed trailing comments
  instead of hanging during parsing (GHSA-7w5x-hrqm-74c2).

## [0.16.2] - 2026-09-09

### Fixed

- Native binary release smoke now verifies embedded dashboard assets on every
  supported platform without relying on a platform-specific database setup.


## [0.16.1] - 2026-09-09

### Fixed

- Standalone binaries now embed the dashboard's built assets and materialize
  them only while `0sec dashboard` is running, so the dashboard works without
  a checkout or `node_modules`.


## [0.16.0] - 2026-09-09

### Added

- `0sec lens-synth --watch --promote` now evolves additive appsec finder lenses
  from curated, corpus-gated misses into a user-owned registry. Promotions and
  rollbacks are hash-linked and hot-load only for future source engagements;
  active engagements remain pinned.
- `0` and `0sec tui` retain chat as the primary OpenTUI surface. Chat-owned
  `/run` opens one explicit-target engagement pane rather than separate
  scan/audit/review/deep-review launch modes; a deep source engagement uses the
  current validated finder-lens strategy through the shared unified runner.
- Chat `/capabilities` now exposes the harness capability catalogue with
  explicit `ready`, `confirm`, and `blocked` safety tiers; every OpenTUI pane
  is routed through the typed chat navigation contract.
- ChatGPT Codex now uses `codex login --device-auth` from the chat-owned
  provider pane. It never enters the generic API-key store or asks for an
  OpenAI API key; OpenAI remains a separate API-key provider.

### Fixed

- Review-card selections now lead with the evidence record and preserve the
  Review context; operator controls remain available after the review detail.

## [0.15.0] - 2026-08-30

### Added

- A versioned `0sec.presentation/v1` contract now carries canonical reports,
  renderer-neutral console transcripts, and semantic events across the CLI,
  browser dashboard, and output adapters.
- The console can open a virtualized transcript review with `/transcript` (or
  `/review`), focus a live subagent's real transcript, and let an operator
  message that focused subagent.
- `--print`, `--resume`, `--continue`, and the `-p`, `-r`, `-c`, and `-m`
  aliases support one-shot and saved-session CLI workflows.
- The local dashboard provides a same-origin presentation-event SSE endpoint
  with resumable cursor replay.
- Framework packs, model-catalog synchronization, canonical benchmark
  integrations, and isolated replay runners expand the reusable assessment
  surface.

### Changed

- Terminal, JSON, Markdown, HTML, SARIF, PDF, dashboard, and native-console
  projections now consume shared presentation documents instead of deriving
  state from renderer-specific output.
- The OpenTUI console captures direct application stdout/stderr while it owns
  the terminal, preserving those writes as transcript events and preventing
  framebuffer corruption.
- Console defaults now use the Midnight theme; transcript, tool-card, composer,
  sidebar, and focused-subagent surfaces were refined for legibility.
- The optional `0sec-cli` npm launcher downloads the matching platform-specific
  release asset on first invocation when published to npm.

### Fixed

- Packaged native binaries embed JIT skill YAML rather than failing to load
  source-only skill assets.
- Markdown rendering no longer damages generic or unlabeled fenced code blocks.
- Dependency overrides remove the previously reported audit advisories.
- Standalone release binaries embed tree-sitter's parser and C grammar addons;
  CI now removes build-host `node_modules` before its binary smoke test.

## [0.14.0] - 2026-08-25

### Added

- `/theme` switches the console colour theme with live preview (arrow to
  preview, Enter to keep, Esc to revert).
- `/settings` is now a tabbed screen (one tab per category) instead of one long
  scroll; a `/shortcuts` reference lists every keybinding (also reachable from
  settings via `?`).
- `0sec console` gains `--yolo` / `--mode <standard|recon|copilot|yolo>` launch
  flags (YOLO still requires `--scope`).

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
  their managed scan id. The worker controller retrieves that report after the
  engine exits and posts it through the retrying, idempotent final-report path,
  so transient per-finding webhook loss cannot silently erase the completed
  scan's findings.

### Changed

- The console top bar shows the running version (`v<VERSION>`, auto-tracked).
  Pressing Enter during a running turn now interrupts it and sends the message
  immediately, rather than only queuing it. The line-mode (non-TTY) fallback
  gained the `recon` mode and stops silently ignoring commands it can't run.

### Fixed

- Hardened the plugin registry fetch: refuse redirects (no http/SSRF downgrade),
  cap body size, add a timeout, and bound processed entries.
- Closed a self-extension reserved-name gate gap and fixed a console tool-schema
  bug that dropped array `items` (array tool params were mis-described).
- The full CLI test suite now gates CI (was an 8-of-114-file subset), fixing 27
  regressions that had accumulated unseen; revived the real-binary smoke test.

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

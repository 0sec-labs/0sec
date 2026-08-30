---
title: Configuration
description: Runtime modes, scan modes, depth settings, and environment options.
---

0sec runs zero-config, but every default can be overridden via CLI flags or
environment variables.

## Runtime modes

Models propose and explore; scoped tools, evidence, and verification decide what
counts. `--runtime` selects the LLM backend.

| Runtime | Flag | Description |
|---------|------|-------------|
| `api` | `--runtime api` | Uses your configured direct provider (ChatGPT Codex subscription auth, OpenRouter, Anthropic, Azure OpenAI, or OpenAI). Best for CI and quick scans. **Default.** |
| `claude` | `--runtime claude` | Spawns the Claude Code CLI with your existing subscription. Best for deep analysis. |
| `codex` | `--runtime codex` | Uses the Codex CLI for source review. For live target scans, routes to the direct ChatGPT Codex provider when `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN` is configured. |
| `gemini` | `--runtime gemini` | Spawns the Gemini CLI. Best for large-context source analysis. |
| `auto` | `--runtime auto` | Auto-detects installed CLIs and picks the best one per pipeline stage. |

### API runtime

The default `api` runtime makes direct HTTP calls to a provider. Set one of:

```bash
export 0SEC_CHATGPT_OAUTH_REFRESH_TOKEN="..." # ChatGPT/Codex subscription auth
export OPENROUTER_API_KEY="sk-or-..."   # Recommended
export ANTHROPIC_API_KEY="sk-ant-..."
export AZURE_OPENAI_API_KEY="..."
export OPENAI_API_KEY="sk-..."
```

See [API Keys](/api-keys/) for the full priority order and provider details.

For Azure, also set `AZURE_OPENAI_BASE_URL` and `AZURE_OPENAI_MODEL` unless 0sec
can read them from an Azure-backed `~/.codex/config.toml`. For the Responses API,
the base URL must include `/openai/v1`. 0sec fails fast on incomplete Azure config
rather than guessing defaults.

For ChatGPT Codex, run `codex login`, then export the refresh token from
`~/.codex/auth.json` as `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN`. When set, it takes
priority over API-key providers.

### CLI runtimes (claude, codex, gemini)

These spawn the respective CLI as a subprocess — install and authenticate it
first:

```bash
# Claude Code CLI
npm i -g @anthropic-ai/claude-code

# Codex CLI
npm i -g @openai/codex

# Gemini CLI
npm i -g @google/gemini-cli
```

Then use them:

```bash
0sec scan --target https://api.example.com/chat --runtime claude
0sec review ./my-repo --runtime codex --depth deep
```

The Codex CLI isn't used as a live-target wrapper. For live scans on a Codex
subscription, configure the direct provider instead:

```bash
export 0SEC_CHATGPT_OAUTH_REFRESH_TOKEN="..."
0sec scan --target https://example.com --runtime codex
```

### Codex runtime parity matrix

`--runtime codex` works across every entry point as long as either the local
`codex` binary is installed or the direct ChatGPT Codex provider is configured
(`0SEC_CHATGPT_ACCESS_TOKEN` / `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN`). With no binary
but subscription env set, 0sec routes through the API runtime against
`chatgpt.com/backend-api/codex/responses`.

| Surface                                | Command                                                      | Supported via direct provider |
|----------------------------------------|--------------------------------------------------------------|--------------------------------|
| Web / URL scan                         | `0sec scan --target https://… --runtime codex`             | yes                            |
| npm package audit                      | `0sec audit lodash --ecosystem npm --runtime codex`        | yes                            |
| PyPI package audit                     | `0sec audit requests --ecosystem pypi --runtime codex`     | yes                            |
| crates.io package audit                | `0sec audit tokio --ecosystem cargo --runtime codex`       | yes                            |
| OCI image audit                        | `0sec audit nginx:1.25 --ecosystem oci --runtime codex`    | yes                            |
| Default source-code review             | `0sec review ./repo --runtime codex`                       | yes                            |
| Linux kernel review                    | `0sec review ./linux --profile linux-kernel --runtime codex` | yes                          |
| C/C++ library review                   | `0sec review ./lib --profile c-library --runtime codex`    | yes                            |

(Cloud sandbox dispatch still gates codex on `target_ecosystem === "web"`, tracked
as a separate follow-up.)

## Scan modes

`--mode` controls what kind of target is scanned.

| Mode | Description |
|------|-------------|
| `deep` | Full agentic pentest. Runs the research + verify agents with the full 40-turn budget. **Default** when the target is an `https://` URL. |
| `probe` | Lightweight surface scan — recon and fingerprinting without deep exploitation. |
| `web` | Shell-first autonomous pentesting for web applications. The agent uses `bash` (curl, python3, bash) as its primary tool to probe for CORS, headers, exposed files, SSRF, XSS, SQLi, SSTI, and more. |
| `mcp` | Scan MCP (Model Context Protocol) servers for tool poisoning and schema abuse. **Default** when the target starts with `mcp://`. |

```bash
# LLM API scan (default)
0sec scan --target https://api.example.com/chat

# Web app scan
0sec scan --target https://example.com --mode web
```

## Depth settings

`--depth` controls how thorough the scan is.

| Depth | Test Cases | Typical Time | Best For |
|-------|-----------|-------------|----------|
| `quick` | ~15 | ~1 min | CI pipelines, smoke tests |
| `default` | ~50 | ~3 min | Day-to-day scanning |
| `deep` | ~150 | ~10 min | Pre-launch audits, thorough review |

```bash
0sec scan --target https://api.example.com/chat --depth quick
0sec audit express --depth deep
0sec review ./my-repo --depth deep --runtime claude
```

## Output formats

Set with `--format`:

| Format | Description |
|--------|-------------|
| `terminal` | Human-readable terminal summary with share URL |
| `html` | Rich browser report saved to a temporary file |
| `pdf` | Printable report saved to a temporary file |
| `json` | Machine-readable JSON output for pipelines |
| `sarif` | SARIF format for the GitHub Security tab |
| `markdown` | Human-readable Markdown report |

In CI (GitHub Action), set `format: sarif` to populate the Security tab:

```yaml
- uses: 0sec-labs/0sec@main
  with:
    mode: review
    path: .
    format: sarif
```

## Diff-aware review

Review only changed files against a base branch — handy in CI to skip scanning
the whole codebase on every PR:

```bash
0sec review ./my-repo --diff-base origin/main --changed-only
```

## Verbose output

`--verbose` shows detailed agent output:

```bash
0sec scan --target https://api.example.com/chat --verbose
```

## Feedback delivery

`/feedback <message>` is local-only and appends to
`~/.0sec/feedback.md`. After `0sec auth login`, staged feedback defaults to the
authenticated `cloud.0.security/api/cli-feedback` receiver; it attributes the
message to the signed-in organization and delivers through the existing
team-feedback channel. Re-authenticate after upgrading if an older CLI token
lacks the `feedback:submit` scope.

Use `/feedback submit <message>` to save locally and inspect the exact endpoint,
JSON body, headers, and secret-shaped-content warnings. Only a second
`/feedback send` transmits that exact staged payload; `/feedback cancel` drops
the pending network action while retaining the local file.

`0SEC_FEEDBACK_URL` overrides the cloud receiver for a self-hosted HTTPS relay:

```bash
export 0SEC_FEEDBACK_URL="https://feedback.example.org/v1/feedback"
```

Do **not** place an incoming Slack webhook URL directly in the CLI environment:
it is a bearer secret and does not accept 0sec's feedback wire schema.
`0SEC_OFFLINE`, `0SEC_NO_TELEMETRY`, and `DO_NOT_TRACK` block every submission
before any connection is made.

## State directory

All per-user state — scan database, journals, caches, stored credentials, console
settings, and session transcripts — lives under `~/.0sec`. Everything joins onto
that one root, so a future relocation (e.g. `$XDG_STATE_HOME`) moves it all
together. Paths below are relative to it.

## Console display settings

The console loads `~/.0sec/tui-settings.json`, then layers
`<project>/.0sec/tui-settings.json` over it when present. Change values from
`/settings`, or hand-edit either plain JSON file; the project file overrides
only the keys it contains.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `showStatusBar` | boolean | `true` | Bottom bar with model, working directory, git state and counters |
| `showComposerHints` | boolean | `true` | Keyboard-hint line under the input |
| `showLogo` | boolean | `true` | Block `0SEC` mark on an empty transcript |
| `showLeftSidebar` | boolean | `false` | Recent sessions and this run's findings; hidden on narrow terminals |
| `showRightSidebar` | boolean | `false` | Live agents and context strip; hidden on narrow terminals |
| `showObjective` | boolean | `true` | Bottom-bar objective derived from the first message |
| `showTarget` | boolean | `true` | Header target segment |
| `showScope` | boolean | `true` | Header scope segment |
| `density` | `comfortable`, `compact` | `comfortable` | Transcript spacing |
| `composerStyle` | `border`, `rail`, `plain` | `border` | Input frame |
| `transcriptStyle` | `rail`, `bubble`, `plain`, `compact`, `document` | `rail` | Conversation-turn framing |
| `roleLabelStyle` | `full`, `short`, `glyph`, `off` | `full` | Speaker label treatment |
| `toolCardStyle` | `compact`, `rail`, `inline`, `hidden` | `compact` | Successful tool/subagent-card treatment; failures always show |
| `richToolCards` | boolean | `true` | Render shell and edit results as rich cards |
| `transcriptDetail` | `expanded`, `collapsed` | `expanded` | Whether successful reasoning and tool steps are folded |
| `showRuntimeNotices` | boolean | `true` | Surface runtime stdout/stderr as transcript notices |
| `showTurnSummary` | boolean | `false` | Per-turn tool-call and token summary |
| `showSubagents` | boolean | `true` | List active subagents while workers run |
| `showTimestamps` | boolean | `false` | Relative timestamps on transcript entries |
| `allowSubagentPeerMessaging` | boolean | `true` | Allow direct sibling-subagent messages |
| `allowSubagentOperatorMessaging` | boolean | `true` | Allow sanitized child-to-operator transcript messages |
| `allowModelSelfExtension` | boolean | `false` | Allow the model to add tools to its own session |
| `theme` | built-in or installed theme ID | `midnight` | Colour palette; installed themes live in `~/.0sec/themes` |
| `showTokenUsage` | boolean | `false` | Per-turn input/output token line |
| `showCost` | boolean | `false` | Estimated dollar cost, per turn and in the status bar |
| `showContextMeter` | boolean | `false` | Context-usage bar in the status bar |
| `modelDisplay` | `statusbar`, `message`, `off` | `statusbar` | Where the model name appears |
| `logoAnimation` | animation name or `off` | `glitch` | Intro or idle logo effect |
| `reduceMotion` | boolean | `false` | Disable decorative animations |

A missing, corrupt, or hand-broken file can't break the console: on load it's
normalised against the table above (unknown keys dropped, bad values reset to
defaults), and saving rewrites it from the normalised object.

## Session persistence

The console stores transcripts as one JSON file per session in
`console-sessions/` under the [state directory](#state-directory), so you can
close it and resume later. Files are owner-only (`0600` file, `0700` dir),
filtered per working directory, capped at the 20 most recent.

A transcript is the full engagement record — every operator prompt, model reply,
and tool call with its result. That means **target hostnames, approved scope,
untriaged findings, and raw request/response bodies**, which can include cookies,
bearer tokens, and anything a tool echoed.

**Secrets are deliberately not scrubbed.** A scrubber over free-form tool output
can't be complete, and a partial scrub is worse than none — it advertises a
guarantee it can't keep, and would corrupt the evidence a resume needs.
Transcripts are **not encrypted**; protection is filesystem permissions plus your
ability to delete them. Nothing is transmitted anywhere — local disk only.

## Feature flags

Agent-improvement features sit behind environment-variable flags so you can A/B
test and opt in/out per run. Each is read at process start: set `<FLAG>=0` or
`<FLAG>=false` to disable, anything else to enable.

| Flag | Default | What it enables |
|------|---------|-----------------|
| `0SEC_FEATURE_EARLY_STOP` | **on** | Early-stop at 50% budget if no findings, then retry with a different strategy. |
| `0SEC_FEATURE_LOOP_DETECTION` | **on** | Detects A-A-A and A-B-A-B action loops, injects a warning to break the cycle. |
| `0SEC_FEATURE_CONTEXT_COMPACTION` | **on** | Compresses middle-of-conversation messages when the context exceeds 30k tokens. |
| `0SEC_FEATURE_SCRIPT_TEMPLATES` | **on** | Adds exploit-script templates (blind SQLi, SSTI, auth chain) to the shell prompt. |
| `0SEC_FEATURE_DYNAMIC_PLAYBOOKS` | off | Injects technology-specific vulnerability playbooks after the recon phase. |
| `0SEC_FEATURE_AGENT_PLAN` | off | Exposes a typed `plan` tool: the agent tracks its own TODO items, re-injected each turn so they survive compaction. Off by default because it adds a tool, a system-prompt block and a per-turn block to every scan — behaviour-changing, so it must be A/B'd before shipping on. |
| `0SEC_FEATURE_DRIFT_DETECTION` | off | Warns when the agent stops working the assigned objective. Distinct from the loop detector, which catches repetition; a drifting agent produces a novel action every turn and never trips it. |
| `0SEC_FEATURE_JIT_SKILLS` | off | Exposes `list_skills` and `load_skill` so agents can pull narrow methodology prompts only when needed. |
| `0SEC_FEATURE_EXTERNAL_MEMORY` | off | Agent writes plan/creds to disk, re-injected at reflection checkpoints. |
| `0SEC_FEATURE_PROGRESS_HANDOFF` | off | Injects prior-attempt findings when retrying, so retries don't restart from zero. |
| `0SEC_FEATURE_WEB_SEARCH` | off | Lets the agent search the web for CVE details, vendor docs, and technique references. |
| `0SEC_FEATURE_TARGET_HISTORY_PRESEED` | **on** | Preloads source-review prompts with prior target CVE/GHSA audit graph leads inferred from repo metadata. |
| `0SEC_FEATURE_DOCKER_EXECUTOR` | off | Runs every bash command inside a Kali Linux container with the full pentesting toolchain. |
| `0SEC_FEATURE_CLOUD_SINK` | on | Allows opt-in streaming of findings/final reports to a remote scan sink when the cloud env vars are set. |
| `0SEC_FEATURE_PTY_SESSION` | off | Interactive PTY sessions for exploits requiring interactivity (reverse shells, DB clients, SSH). |
| `0SEC_FEATURE_EGATS` | off | Evidence-Gated Attack Tree Search — beam search over a hypothesis tree. Also toggled by `--egats`. |
| `0SEC_FEATURE_CONSENSUS_VERIFY` | off | Self-consistency voting: runs the verify pipeline N times and takes the majority vote. |
| `0SEC_FEATURE_DEBATE` | _n/a_ | **Planned — not implemented.** The flag is not read by the engine today. Adversarial debate: prosecutor vs. defender agents argue each finding, a skeptical judge decides. |
| `0SEC_FEATURE_MULTIMODAL` | off | Cross-validates findings against foxguard (Rust pattern scanner). |
| `0SEC_FEATURE_REACHABILITY_GATE` | off | Suppresses findings whose sink is not reachable from an application entry point. |
| `0SEC_FEATURE_POV_GATE` | off | Requires a working executable PoC per finding, otherwise downgrades to `info`. |
| `0SEC_FEATURE_TRIAGE_MEMORIES` | off | Injects Semgrep-style per-target persistent FP memories into the verify pipeline. Pairs with `0sec triage`. |

## Static analyzer selection

Source reviews and package source scans use Foxguard by default for pre-agent
static leads. Set `0SEC_STATIC=semgrep` to route them through Semgrep instead;
`--changed-only` narrowing works with either. Dependency advisory checks (`npm
audit`, OSV, OCI inventory) run separately for package targets regardless.

```bash
0SEC_STATIC=semgrep 0sec review ./repo --depth quick
```

### Docker executor overrides

When `0SEC_FEATURE_DOCKER_EXECUTOR=1` is enabled, these extra env vars
control the container image, networking, and bootstrap behavior:

| Variable | Default | Purpose |
|----------|---------|---------|
| `0SEC_DOCKER_IMAGE` | `ghcr.io/0sec-labs/0sec:latest` | Override the executor image |
| `0SEC_DOCKER_NETWORK` | `bridge` | Docker network mode for the executor container |
| `0SEC_DOCKER_BOOTSTRAP_TOOLS` | auto | Force or disable apt-based tool bootstrap inside the container |

Bootstrap rules:

- default GHCR image -> no bootstrap, use the pre-baked toolchain
- `kalilinux/kali-rolling` -> bootstrap tools on first start
- `0SEC_DOCKER_BOOTSTRAP_TOOLS=1` -> always bootstrap
- `0SEC_DOCKER_BOOTSTRAP_TOOLS=0` -> never bootstrap

Networking rules:

- `bridge` (default) gives the container its own network stack — safe, and fine
  for public targets.
- `0SEC_DOCKER_NETWORK=host` when the target runs on the same host (local XBOW
  challenges, a `docker-compose` service), so the container can reach
  `host.docker.internal` / `localhost`.
- any valid `docker run --network <name>` value works — e.g. a compose network
  name to land the executor on the target stack's network.

### Cost ceiling

Bound API spend per scan, audit, or review. If exceeded, 0sec preserves partial
findings, exits with code `4`, and emits `exit_reason: "cost_ceiling_exceeded"`
in the machine-readable result line. The `--cost-ceiling` flag overrides the env
var.

```bash
export 0SEC_COST_CEILING_USD=5
0sec scan --target https://example.com --mode web

0sec audit lodash --cost-ceiling 2
0sec review ./my-repo --cost-ceiling 10
```

### LLM runtime resilience

The runtime layers that keep a provider failure from silently corrupting a scan:

| Variable | Default | Purpose |
|----------|---------|---------|
| `0SEC_LLM_STREAM_IDLE_TIMEOUT_MS` | `120000` | SSE idle watchdog. Streaming calls disarm the overall timer once headers arrive; if the server then holds the stream open emitting no bytes, the call aborts after this window as a transient error (bounded retry, then loud failure). Prevents a held stream hanging the scan silently. |
| `0SEC_LLM_MAX_RETRIES` | `6` | Max retries for retryable statuses (429 + transient 5xx), with exponential backoff and `Retry-After` honored. |
| `0SEC_LLM_MAX_RETRY_WAIT_MS` | `60000` | Cumulative backoff cap (ms) for the wire-layer retry loop. |

Auth errors (**401/403**) are never retried: the agent loop exits immediately, and
the pipeline surfaces an **honest failure** — `warnings[]` carries the provider
error and the run is marked failed, never a clean "0 findings". Package audits add
a per-file circuit breaker (3 identical-signature failures abort the rest). A dead
provider stops a scan loudly in seconds instead of degrading to a false clean.

### Cloud sink

Stream findings and the final report to an orchestration layer:

```bash
export 0SEC_CLOUD_SINK=https://api.example.com
export 0SEC_CLOUD_SCAN_ID=scan_123
export 0SEC_CLOUD_TOKEN=secret-token
```

0sec then POSTs each finding as `{ "finding": ... }` and the final report as
`{ "report": ..., "final": true }` to
`${0SEC_CLOUD_SINK}/scans/${0SEC_CLOUD_SCAN_ID}/findings`. Set
`0SEC_FEATURE_CLOUD_SINK=0` to disable even when the env vars are present.

### Machine-readable result line

Set `0SEC_EMIT_RESULT_LINE=1` to print one final `0SEC_RESULT=...` JSON line with
success/failure, exit code and reason, target type, finding counts, and estimated
cost/token usage. Useful for wrappers, CI parsers, and the cloud path.

### Example: maximum-accuracy pentest

Every false-positive reduction feature on, for a client-ready scan:

```bash
export 0SEC_FEATURE_CONSENSUS_VERIFY=1
export 0SEC_FEATURE_REACHABILITY_GATE=1
export 0SEC_FEATURE_POV_GATE=1
export 0SEC_FEATURE_TRIAGE_MEMORIES=1
export 0SEC_FEATURE_MULTIMODAL=1

0sec scan --target https://example.com --mode web --depth deep
```

### Example: Kali toolchain + web search

```bash
export 0SEC_FEATURE_DOCKER_EXECUTOR=1
export 0SEC_FEATURE_WEB_SEARCH=1

0sec scan --target https://example.com --mode web
```

### Example: raw Kali fallback

```bash
export 0SEC_FEATURE_DOCKER_EXECUTOR=1
export 0SEC_DOCKER_IMAGE=kalilinux/kali-rolling
export 0SEC_DOCKER_BOOTSTRAP_TOOLS=1

0sec scan --target https://example.com --mode web
```

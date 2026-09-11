---
title: Configuration
description: Runtime modes, scan modes, depth settings, state paths, env vars, feature flags, and diagnostics.
---

Configure command options, provider credentials, console settings and run storage
separately. Each section below gives its precedence rules.

## Runtime modes

`--runtime` selects the LLM backend.

| Runtime | Flag | Description |
|---------|------|-------------|
| `api` | `--runtime api` | Direct HTTP calls to a configured provider. |
| `claude` | `--runtime claude` | Spawns the Claude Code CLI with your existing subscription. Best for deep analysis. |
| `codex` | `--runtime codex` | Uses the Codex CLI for source review. For live target scans, routes to the direct ChatGPT Codex provider when `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN` is configured. |
| `gemini` | `--runtime gemini` | Spawns the Gemini CLI. Best for large-context source analysis. |
| `auto` | `--runtime auto` | Resolve an available runtime for the selected workflow. Default for `scan`, `review`, and `audit`. |

### API runtime

The `api` runtime makes direct HTTP calls to a provider. Set one of:

```bash
# API-key providers can be exported normally.
export OPENROUTER_API_KEY="sk-or-..."   # Recommended
export ANTHROPIC_API_KEY="sk-ant-..."
export AZURE_OPENAI_API_KEY="..."
export OPENAI_API_KEY="sk-..."
export DEEPSEEK_API_KEY="..."
export Z_AI_API_KEY="..."
export KIMI_API_KEY="..."
export QWEN_API_KEY="..."
export XAI_API_KEY="..."
export OPENCODE_API_KEY="..."

# `0SEC_*` names begin with a digit; pass a Codex token with env.
env 0SEC_CHATGPT_OAUTH_REFRESH_TOKEN="..." 0sec doctor
```

See [API Keys](/api-keys/) for the full provider list, default models, and
credential priority.

For Azure, also set `AZURE_OPENAI_BASE_URL` and `AZURE_OPENAI_MODEL` unless 0sec
can read them from an Azure-backed `~/.codex/config.toml`. For the Responses API,
the base URL must include `/openai/v1`. Incomplete Azure configuration fails before execution.

For ChatGPT Codex, run `codex login`, then either rely on
`~/.codex/auth.json` or use
`env 0SEC_CHATGPT_OAUTH_REFRESH_TOKEN=... 0sec <command>`. An explicit token
takes priority over API-key providers.

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
0sec scan --target https://api.example.com/chat --scope ./scope.json --runtime claude
0sec review ./my-repo --runtime codex --depth deep
```

The Codex CLI isn't used as a live-target wrapper. For live scans on a Codex
subscription, configure the direct provider instead:

```bash
env 0SEC_CHATGPT_OAUTH_REFRESH_TOKEN="..." \
  0sec scan --target https://example.com --scope ./scope.json --runtime codex
```

### Codex runtime parity matrix

Codex routing depends on the entry point and credentials. Source review can use
the authenticated CLI; live-target subscription calls use the direct provider.

| Surface                                | Command                                                      | Supported via direct provider |
|----------------------------------------|--------------------------------------------------------------|--------------------------------|
| Web / URL scan                         | `0sec scan --target https://example.com --scope ./scope.json --runtime codex` | yes |
| npm package audit                      | `0sec audit lodash --ecosystem npm --runtime codex`        | yes                            |
| PyPI package audit                     | `0sec audit requests --ecosystem pypi --runtime codex`     | yes                            |
| crates.io package audit                | `0sec audit tokio --ecosystem cargo --runtime codex`       | yes                            |
| OCI image audit                        | `0sec audit nginx:1.25 --ecosystem oci --runtime codex`    | yes                            |
| Default source-code review             | `0sec review ./repo --runtime codex`                       | yes                            |
| Linux kernel review                    | `0sec review ./linux --profile linux-kernel --runtime codex` | yes                          |
| C/C++ library review                   | `0sec review ./lib --profile c-library --runtime codex`    | yes                            |

Managed runtime availability follows the separate [0cloud deployment policy](/roadmap/#0cloud).

## Scan modes

`--mode` controls what kind of target is scanned.

| Mode | Description |
|------|-------------|
| `deep` | Agentic LLM/AI-target probing; select explicitly for an HTTP endpoint that should not use web mode. |
| `probe` | Lightweight surface scan — recon and fingerprinting without deep exploitation. |
| `web` | Shell-first web application assessment. The automatic mode for HTTP/HTTPS targets passed to `scan`. |
| `mcp` | Scan MCP (Model Context Protocol) servers for tool poisoning and schema abuse. **Default** when the target starts with `mcp://`. |
| `http_audit` | Worker-driven authenticated HTTP assessment using operator-provided `0SEC_TARGET_*` configuration. |

```bash
# LLM API assessment: select deep mode explicitly.
0sec scan --target https://api.example.com/chat --scope ./scope.json --mode deep

# Web application assessment.
0sec scan --target https://example.com --scope ./scope.json --mode web
```

## Depth settings

`--depth` controls how thorough the scan is.

| Depth | Use |
|-------|-----|
| `quick` | Shorter investigation budget |
| `default` | Normal workflow budget |
| `deep` | Larger investigation budget |

These are not fixed test-case counts or guaranteed completion times. See
[Budget Management](/budget-management/) for the budget mechanisms.

```bash
0sec scan --target https://api.example.com/chat --scope ./scope.json --mode deep --depth quick
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

For GitHub Code Scanning, run the CLI with `--format sarif` and upload the
result with `github/codeql-action/upload-sarif`. A dedicated 0sec composite
action has not shipped; use the complete [GitHub CI](/ci/github-action/) workflow.

## Diff-aware review

Review only changed files against a base branch — handy in CI to skip scanning
the whole codebase on every PR:

```bash
0sec review ./my-repo --diff-base origin/main --changed-only
```

## Verbose output

`--verbose` shows detailed agent output:

```bash
0sec scan --target https://api.example.com/chat --scope ./scope.json --verbose
```

## Operational logs

Enable metadata-only operational records on stderr:

```bash
env 0SEC_LOG_FORMAT=json 0sec review ./my-repo
```

Each NDJSON record contains `timestamp`, `level`, `service`, `event`, and
allowlisted lifecycle or cost metadata. Prompts, responses, reasoning, tool
arguments/results, finding evidence, summaries and raw error text are excluded
from these records. Credential-like values in retained identifiers are redacted.

This adds records alongside existing stderr diagnostics; it does not make all
stderr output JSON or replace `--format`. Stdout and the `0SEC_EVENT_*` cloud
relay protocol are unchanged. Unset `0SEC_LOG_FORMAT` to disable the sink;
only the `json` format enables it. Nothing is uploaded automatically: collect
stderr through your runner or container logging pipeline.

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
env 0SEC_FEEDBACK_URL="https://feedback.example.org/v1/feedback" 0sec console
```

Do **not** place an incoming Slack webhook URL directly in the CLI environment:
it is a bearer secret and does not accept 0sec's feedback wire schema.
`0SEC_OFFLINE`, `0SEC_NO_TELEMETRY`, and `DO_NOT_TRACK` block every submission
before any connection is made.

## Update checks

A fire-and-forget GitHub release check runs when `0SEC_UPDATE_CHECK=1` is
set and stdout is a TTY. It respects `CI`, `0SEC_NO_UPDATE_CHECK`, and
`0SEC_OFFLINE` — any of these set will suppress the request. Results are
cached for 24 hours.

```bash
env 0SEC_UPDATE_CHECK=1 0sec --version
```

Update checks never block the main command, but they do make one HTTPS
request to the GitHub API per cache expiry window. Offline or CI
environments should leave the variable unset.

## State directory

Most per-user state is under `~/.0sec`. Scan execution state is run-local,
while console settings and credentials are user-level. Project overrides,
Codex authentication, temporary reports, and the `~/.0cloud` credential copy
have separate paths; moving one directory does not relocate every subsystem.

Fresh scans default to `~/.0sec/runs/<scan-id>/state.db`. `--db-path` overrides
`0SEC_DB_PATH`; `0SEC_RUN_DIR` controls the run directory. Managed workers can
bind the local run ID through `0SEC_CLOUD_SCAN_ID`. The legacy `0sec.db` is a
resume fallback, not the default database for every new scan.

| Path | Purpose |
|------|---------|
| `tui-settings.json` | Console display settings (global layer). |
| `credentials.json` | Stored API-key credentials (console credential store). |
| `cloud.env` | Cloud auth token (`0SEC_CLOUD_TOKEN`) and optional host (`0SEC_CLOUD_HOST`). Written by `0sec auth login`. |
| `console-sessions/` | Transcript JSON files, one per session. Owner-only (`0600` file, `0700` dir). |
| `feedback.md` | Locally staged feedback entries. |

## `0sec config` — console settings CLI

The `0sec config` command lets you inspect, export, and import the console
display settings without launching the TUI.

```bash
0sec config show        # effective config, each key labelled default/global/project
0sec config export      # write effective config as shareable JSON to stdout
0sec config export ./my-settings.json
0sec config import ./my-settings.json          # merge into global layer (default)
0sec config import ./my-settings.json --global  # explicit global (same as default)
0sec config import ./my-settings.json --project # merge into project override
```

### Configuration layers (precedence)

Settings are resolved per-key, highest-priority first:

1. **Project** — `<cwd>/.0sec/tui-settings.json` overrides individual keys.
2. **Global** — `~/.0sec/tui-settings.json` is the per-user base.
3. **Default** — built-in defaults shown below.

On load, settings are normalized against the schema: unknown keys are dropped
and invalid values reset to defaults. Saving writes the normalized object.

### Security-gated import

`0sec config import` refuses to change any security-sensitive setting
(`allowModelSelfExtension`, `allowSubagentPeerMessaging`,
`allowSubagentOperatorMessaging`) unless `--yes` is passed. The specific
changes are printed so you know what was rejected.

### Settings reference

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
| `allowModelSelfExtension` | boolean | `true` | Enable sandboxed model self-extension for new sessions, subject to role and capability gates |
| `theme` | built-in or installed theme ID | `midnight` | Colour palette; installed themes live in `~/.0sec/themes` |
| `showTokenUsage` | boolean | `false` | Per-turn input/output token line |
| `showCost` | boolean | `false` | Estimated dollar cost, per turn and in the status bar |
| `showContextMeter` | boolean | `false` | Context-usage bar in the status bar |
| `modelDisplay` | `statusbar`, `message`, `off` | `statusbar` | Where the model name appears |
| `logoAnimation` | animation name or `off` | `glitch` | Intro or idle logo effect |
| `reduceMotion` | boolean | `false` | Disable decorative animations |

### Self-extension and workspace trust

Self-extension defaults on for new sessions, including the desktop checkbox.
Explicit or saved `false` stays off. Workspace-trusted ESM requires a separate,
acknowledged grant scoped to the canonical workspace.

Autonomy, self-extension and host trust are separate controls. Desktop retains
unscoped-standard and scoped-YOLO authorization.
See [self-evolution](/improvement-plane/) for details.

## Console credential store

In the hosted-enabled CLI candidate, `/connect` offers **0sec Cloud → Sign in**,
**Use my own API key**, and a separate **Provider subscription** section.
Cloud uses browser authorization; ChatGPT Codex uses device sign-in and its
own auth file. Local and direct-provider workflows need no Cloud account.

Keys are stored in plaintext at `~/.0sec/credentials.json` by default, with
`0600` file and `0700` directory permissions. Explicit environment values win.
See [credential storage](/api-keys/#console-credential-store).

In `/model`, **Tab** opens the full catalog. Check credentials and account access.
Treat missing price data as unknown.
For an existing chat, `/connect` and `/model` configure the next `/new-chat`.
The current runtime, conversation and live harness stay unchanged.

## Cloud authentication

`0sec auth` manages organization credentials:

| Subcommand | Description |
|------------|-------------|
| `0sec auth login` | Opens a browser at `<host>/cli-auth?session=…`, polls for a scoped token, and persists it to `~/.0sec/cloud.env`. |
| `0sec auth login --token <value>` | Manual credential path for self-hosted or recovery use. |
| `0sec auth login --host <url>` | Override the default cloud host (`https://cloud.0.security` in the hosted-enabled CLI candidate). |
| `0sec auth logout` | Deletes `~/.0sec/cloud.env` and `~/.0cloud/credentials.json`. |
| `0sec auth status` | Loads credentials and pings the cloud health endpoint. |

Credentials are resolved in this order (first match wins):

1. **Environment variables** — `0SEC_CLOUD_TOKEN` (required) + `0SEC_CLOUD_HOST`
   (optional, defaults to `https://cloud.0.security` in the hosted-enabled CLI candidate).
2. **File** — `~/.0sec/cloud.env` (line-by-line `KEY=VALUE`). The file **must**
   be `chmod 600`. Contains `0SEC_CLOUD_TOKEN=…` and optionally
   `0SEC_CLOUD_HOST=…`.

The token is never printed. `0sec auth status` echoes the host on success; on
auth failure it surfaces the status code + path, never the token or Authorization
header.

<a id="hosted-configuration-draft"></a>

### Hosted configuration

See [Cloud setup and availability](/getting-started/#hosted-models-draft).
Planned Cloud access combines open cybersecurity models and 0sec-curated options
under one connection and inference-credit balance, without supplier-account setup.
The hosted-enabled CLI adds `0sec login` (alias of `0sec auth login`),
`0sec models [--json]` and `0sec balance [--json]`, and defaults to
`https://cloud.0.security`. Older releases use `https://cloud.0sec.ai`.
Check `0sec login --help` and use the operator-provided host for testing.

An environment `0SEC_CLOUD_TOKEN` takes precedence over `cloud.env`.
Without it, host and token come from the file or default; setting
`0SEC_CLOUD_HOST` alone won't redirect a saved token.

| Setting or action | Behavior |
| --- | --- |
| `--runtime api` | Uses the HTTP runtime; `hosted` is a provider, not a new runtime name. |
| `0SEC_SELECTED_PROVIDER=hosted` | Pins hosted inference instead of ambient BYOK credentials. |
| `0SEC_MODEL` or `--model` | Must match an alias returned by `0sec models`. The service catalog determines wire protocol and output ceiling. |
| No provider pin | Configured BYOK providers are considered before hosted credentials. Logging in doesn't replace them. |
| No explicit hosted model | Selects the first service catalog entry. Pin an alias for a repeatable route. |
| `0SEC_LLM_FALLBACK` | Explicit backup chain for eligible failures. No automatic hosted wallet escape or hidden gateway substitution. |
| `0sec auth status` | Checks credentials and service health, not model entitlement, credit sufficiency or paid-flow readiness. |
| `0sec auth logout` | Removes local credential files; it doesn't revoke an issued token or clear a token exported in the environment. |

Revoke issued credentials through the dashboard's session controls.
The gateway checks membership and scopes; a CLI credential doesn't authorize
purchases.

Local cost ceilings are separate from the hosted ledger. Cancellation can still
incur charges. See [billing and errors](/api-keys/#charging-and-interrupted-requests).

## Provider selection and model routing

### Explicit provider pinning

`0SEC_SELECTED_PROVIDER` pins the provider for an entire run or chat session.
It accepts one of: `openrouter`, `anthropic`, `openai`, `azure`, `deepseek`,
`chatgpt-codex`, `z-ai`, `kimi`, `qwen`, `xai`, `opencode`. When set alongside
`0SEC_MODEL`, the selected provider must have the matching credentials in the
environment. 0cloud workers inject `0SEC_SELECTED_PROVIDER` to route sandbox
scans to a specific backend.

`0SEC_FORCE_PROVIDER` is an unconditional benchmark override. Setting it and
`0SEC_SELECTED_PROVIDER` to different values is an error.

```bash
env 0SEC_SELECTED_PROVIDER=deepseek 0SEC_MODEL=deepseek-flash \
  0sec scan --target https://example.com --scope ./scope.json --mode web
```

### Per-model routing

When no explicit pin is set, `--model <id>` (or `0SEC_MODEL`) routes the call to
the provider whose credentials are available. The runtime maps model prefixes:

| Model prefix | Provider |
|---|---|
| `glm-*`, `z-ai/*` | Z.ai (GLM) |
| `qwen*` | Alibaba Qwen |
| `k3`, `kimi*` | Moonshot Kimi |
| `grok*`, `xai/*`, `x-ai/*` | xAI Grok |
| `opencode/*`, `muse-spark*`, `mimo*`, `ling*`, `big-pickle`, `nemotron*`, `minimax*` | OpenCode Zen |
| `claude*`, `anthropic/*` | Anthropic, then OpenRouter when auth missing |
| `gpt-*`, `o1`-`o4` | ChatGPT Codex subscription when configured, otherwise OpenAI |
| `deepseek-flash`, `deepseek-v4-flash` | DeepSeek (`deepseek-flash` is V4.1 Flash) |
| Azure Foundry deployment ids | Azure |

### Ambient credential priority

When no model is specified enough to route to one provider, the runtime checks env
vars in this priority order:

1. `0SEC_CHATGPT_ACCESS_TOKEN` / `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN` → ChatGPT Codex
2. `DEEPSEEK_API_KEY` → DeepSeek
3. `OPENROUTER_API_KEY` → OpenRouter
4. `AZURE_OPENAI_API_KEY` → Azure OpenAI
5. `OPENAI_API_KEY` → OpenAI
6. `Z_AI_API_KEY` → Z.ai GLM
7. `KIMI_API_KEY` → Moonshot Kimi
8. `QWEN_API_KEY` → Alibaba Qwen
9. `XAI_API_KEY` → xAI Grok
10. `OPENCODE_API_KEY` → OpenCode Zen
11. `ANTHROPIC_API_KEY` → Anthropic
12. No key found → defaults to Anthropic (fails at runtime with a helpful message)

### Provider failover

`0SEC_LLM_FALLBACK` configures an ordered chain of backup providers when the
primary exhausts its retry budget or hits a plan quota limit:

```bash
env 0SEC_LLM_FALLBACK=deepseek:deepseek-flash,azure:gpt-5-deployment \
  0sec review ./authorized-repo
```

Each entry is `<providerId>:<model>`, comma-separated. When the current provider
fails with a retryable status or quota exhaustion, the runtime advances to the
next entry in the chain. Entries whose auth env var is absent are skipped.

## Session persistence

The console stores transcripts as one JSON file per session in
`console-sessions/` under the [state directory](#state-directory), so you can
close it and resume later. Files are owner-only (`0600` file, `0700` dir),
filtered per working directory, capped at the 20 most recent.

A transcript is the full engagement record — every operator prompt, model reply,
and tool call with its result. That means **target hostnames, approved scope,
untriaged findings, and raw request/response bodies**, which can include cookies,
bearer tokens, and anything a tool echoed.

Secrets are not scrubbed. A partial scrub over free-form output would corrupt
resume evidence. Transcripts are not encrypted. Protection is filesystem
permissions. Stored on local disk only.

## Static analyzer selection

Source reviews and package source scans use Foxguard by default for pre-agent
static leads. Set `0SEC_STATIC=semgrep` to route them through Semgrep instead;
`--changed-only` narrowing works with either. Dependency advisory checks (`npm
audit`, OSV, OCI inventory) run separately for package targets regardless.

The static runner uses `foxguard` from `PATH` when provisioned. Otherwise it
launches `npx --yes foxguard@v0.12.0`, which requires Node/npm and access to the
package and release download on first use. Native v1 JSON reports and legacy
finding arrays are accepted. Launch failures, invalid reports, and scanner
error exits are surfaced as failures; the default path does not silently invoke
Semgrep or report a failed scan as clean. Exit 1 with a valid report means
findings were detected.
Scans run from the requested source root, so an explicitly selected installed
package is not skipped just because an ancestor directory is `node_modules`.
Finding paths are resolved back to that source root.

This pre-agent scan is separate from `0SEC_FEATURE_MULTIMODAL=1`, the opt-in
white-box cross-validation layer. Cross-validation and `kernel variant-hunt`
require an installed Foxguard binary (`--foxguard` can override it for
variant hunting). Static hits and scanner agreement remain leads, not proof
of exploitability.

```bash
env 0SEC_STATIC=semgrep 0sec review ./repo --depth quick
```

Semgrep is required only when explicitly selected. Legacy report fields named
`semgrepFindings` and the `SemgrepFinding` type describe the existing wire shape,
not a runtime dependency. FoxGuard cross-validation remains opt-in; it does not
turn scanner agreement into independent exploit verification. The historical
ablation baseline is still unmeasured, so equal coverage or a speed advantage
over Semgrep is not established by the integration alone.

## Stateful authorization and fix verification

Foxguard findings are static leads. Three complementary paths test authorization
state changes, find incomplete application fixes, and replay a PoC with a negative
control.

### Stateful authorization

The agent tool `access_control_workflow` observes a JSON resource as its owner,
executes up to ten ordered requests as a distinct actor, then observes it again.
It uses the existing per-identity sessions, cookie jars, scope checks, attribution,
and rate limiter without switching the active identity.

```json
{
  "allow_mutation": true,
  "owner_identity": "owner",
  "actor_identity": "other-tenant",
  "observation_url": "https://app.example/api/items/42",
  "observation_json_pointer": "/marker",
  "expected_state": "fresh-disposable-test-marker",
  "steps": [
    {
      "method": "PATCH",
      "url": "https://app.example/api/items/42",
      "body": "{\"marker\":\"fresh-disposable-test-marker\"}"
    }
  ]
}
```

Use only disposable resources covered by the engagement. There is no automatic
cleanup or rollback. Every step is validated before requests start; actor requests
cannot override authentication headers. Both owner observations must succeed and
contain complete JSON. `confirmed` requires an exact string-marker transition,
not merely HTTP 2xx. An unchanged state is `no_change`; incomplete observations,
transport failures, or an unexpected state change are `inconclusive`. Choose a
unique marker to reduce ambiguity from concurrent legitimate activity.

### Application incomplete-fix hunting

```bash
0sec review ./repo --fix-commit <sha> --variants-only
0sec review ./repo --fix-commit <sha>
```

`--variants-only` emits deterministic JSON without model calls. The second command
feeds candidates into the normal review pipeline as low-confidence `SeedFinding`
leads. The hunter compares the fix commit to its first parent, extracts added
authorization/validation checks, and searches current tracked working-tree files
in the affected directories for similar unguarded functions.

Extraction is heuristic for JavaScript, TypeScript, and Python—not a complete AST,
control-flow, or exploitability analysis. Other languages are explicitly skipped.
The default bound is 200 related files and 50 candidates; source files over 1 MiB
are skipped with an error entry. Guarded siblings are excluded. This is separate
from Foxguard's kernel `variant-hunt`.

### Reproduction bundles

Create a plan with exactly one of `finding_path` or an inline `finding`, explicit
source roots, and file allowlists. Finding JSON uses the same schema as `verify
--finding`, including `timestamp`. Plan-relative paths resolve beside the plan.

```json
{
  "version": 1,
  "finding_path": "./finding.json",
  "vulnerable_root": "./before",
  "patched_root": "./after",
  "files": {
    "vulnerable": ["app.cjs"],
    "patched": ["app.cjs"]
  },
  "runner": "local"
}
```

```bash
0sec verify --create-bundle ./plan.json --out ./bundle
0sec verify --bundle ./bundle --runner local --out ./replay-results
```

Creation never executes PoC steps. Replay requires an explicit runner, validates
SHA-256 content, sizes, paths, and compatibility before execution, and uses fresh
vulnerable/patched workspaces. Output directories must be empty. Symlinks,
traversal paths, source/output overlap, and dirty output are rejected. Snapshot
content is bounded to 256 MiB; plans and manifests to 4 MiB.

`confirmed` (exit 0) requires reproduction on the vulnerable side and a genuine
assertion failure on a successfully executed patched side. Reproduction on both
sides is `inconclusive` (exit 1); failure to reproduce the vulnerable side is
`not_reproduced` (exit 1). A crash, failed setup, timeout, or missing command is
`error` (exit 3), never proof of a fix. PoC processes must exit zero on both sides
and express the exploit condition through assertions. Results include both sides;
`vulnerable.json`, `patched.json`, and `result.json` are retained with artifacts.

Local replay executes trusted PoC code **on the host**. It checks the Node/engine
version and platform/architecture; external tools and services remain outside the
snapshot. Digests establish file integrity, while authorship requires separate
review. Check bundles for secrets before execution or sharing, including source,
finding metadata, and process output.

For Docker, set `"runner": "docker"` in the plan and provide
`docker_shell_image` / `docker_http_image` for the action types used, each as a full
`repository@sha256:<64-hex-digest>` reference. Docker action images must also be
digest-pinned. Replay binds the images to those references and uses the existing
Docker isolation controls; provision images locally first. HTTP replay additionally
requires `--scope <scope.json>` and an explicit `--docker-network <name>`.
Local replay supports shell actions; Docker supports shell, container, and scoped
HTTP actions. Notes are not executable bundle steps.
Shell `cwd` is relative to the mounted workspace; absolute paths and traversal
outside it are rejected before a container is launched.

The `0sec: Docker replay` CI workflow runs real containers.
It covers isolation, writable workspaces, relative cwd and escape rejection,
pinned-image execution, timeout cleanup, scoped HTTP, and vulnerable/patched
negative controls. To run the same checks against the default local Docker daemon:

```bash
pnpm --filter @0sec/core... -r build
node scripts/smoke-docker-replay.mjs
```

The smoke script pulls its fixture images, resolves their digests, and removes
its test containers, network, and temporary workspaces afterward.

## Feature flags

[Features](/features/) is the canonical flag inventory. Do not copy a flag
from an archival experiment and assume the current engine reads it.
`0SEC_FEATURE_TRIAGE_MEMORIES` and `0SEC_FEATURE_DEBATE` are not current
standalone toggles.

Use `env` for names beginning with `0SEC_`; POSIX shells cannot export names
beginning with a digit. Enabling a capability does not supply its credentials,
scope, toolchain, or other prerequisites.

## Runtime resilience and retries

The runtime layers that keep a provider failure from silently corrupting a scan:

| Variable | Default | Purpose |
|----------|---------|---------|
| `0SEC_LLM_STREAM_IDLE_TIMEOUT_MS` | `120000` | SSE idle watchdog. Streaming calls disarm the overall timer once headers arrive; if the server then holds the stream open emitting no bytes, the call aborts. |
| `0SEC_LLM_MAX_RETRIES` | `6` | Max retries for retryable statuses (429 + transient 5xx), with exponential backoff. |
| `0SEC_LLM_MAX_RETRY_WAIT_MS` | `60000` | Cumulative backoff cap (ms) for the generic retry loop. |
| `0SEC_LLM_429_MAX_RETRIES` | `12` | Max retries for 429 rate-limits specifically. Falls back to `0SEC_LLM_MAX_RETRIES` when unset. |
| `0SEC_LLM_429_MAX_RETRY_WAIT_MS` | `300000` | Cumulative 429 backoff cap (ms). Falls back to `0SEC_LLM_MAX_RETRY_WAIT_MS` when unset. Bound server-guided `Retry-After` waits. |
| `0SEC_SUPPRESS_PROVIDER_STARTUP_LOG` | unset | Set to `1` to suppress the "Provider: …" startup banner line. |

Auth errors (**401/403**) are never retried: the agent loop exits immediately,
`warnings[]` carries the provider error, and the run is marked failed, never
clean "0 findings". Package audits add a per-file circuit breaker (3
identical-signature failures abort the rest).

### Provider failover chain

`0SEC_LLM_FALLBACK` configures an ordered chain of `<providerId>:<model>` entries
(comma-separated). When the primary provider exhausts its retry budget, the runtime
advances to the next entry whose credentials are present in the environment.

## Execution backends

Backend selection is command-specific. It does not provide global console isolation:

- Source evolution defaults to Docker. Set `backend: "smolvm"` and a local
  `imageArchive` in its config to use qualified Linux microVM workers. See
  [Improvement Plane](/improvement-plane/#local-smolvm-backend) for prerequisites,
  image provisioning, restrictions, and real qualification commands.
- Deterministic replay selects `--runner local|docker|qemu`; Docker replay
  networking follows the explicit scope and `--docker-network` rules above.
- Agentic exploit execution requires `--container` or `--exec-script`; it does
  not default to running exploit commands on the host.

Selecting smolvm for evolution does not move general console/PTY tools, replay,
or exploit executors into that VM. Provision toolbox dependencies before offline
evaluation; candidate execution does not bootstrap packages over the network.

## Cost ceiling

Bound API spend per scan, audit, or review. If exceeded, 0sec preserves partial
findings, exits with code `4`, and emits `exit_reason: "cost_ceiling_exceeded"`
in the machine-readable result line. The `--cost-ceiling` flag overrides the env
var.

```bash
env 0SEC_COST_CEILING_USD=5 \
  0sec scan --target https://example.com --scope ./scope.json --mode web

0sec audit lodash --cost-ceiling 2
0sec review ./my-repo --cost-ceiling 10
```

## Cloud sink

Stream findings and the final report to an orchestration layer:

```bash
env \
  0SEC_CLOUD_SINK=https://api.example.com \
  0SEC_CLOUD_SCAN_ID=scan_123 \
  0SEC_CLOUD_TOKEN=secret-token \
  0sec scan --target https://example.com --scope ./scope.json --mode web
```

0sec then POSTs each finding as `{ "finding": ... }` and the final report as
`{ "report": ..., "final": true }` to
`${0SEC_CLOUD_SINK}/scans/${0SEC_CLOUD_SCAN_ID}/findings`. Set
`0SEC_FEATURE_CLOUD_SINK=0` to disable even when the env vars are present.

Optional: `0SEC_CLOUD_ORG_ID` sends the `X-0sec-Org-Id` header for
organization-scoped sinks.

## Machine-readable result line

Set `0SEC_EMIT_RESULT_LINE=1` to print one final `0SEC_RESULT=...` JSON line with
success/failure, exit code and reason, target type, finding counts, and estimated
cost/token usage. Useful for wrappers, CI parsers, and the cloud path.

## Example: opt-in verification gates

After enabling gates, inspect their execution records and evidence before accepting a finding.

```bash
env \
  0SEC_FEATURE_CONSENSUS_VERIFY=1 \
  0SEC_FEATURE_REACHABILITY_GATE=1 \
  0SEC_FEATURE_POV_GATE=1 \
  0SEC_FEATURE_MULTIMODAL=1 \
  0sec scan --target https://example.com --scope ./scope.json --mode web --depth deep
```

## Example: web search

```bash
env 0SEC_FEATURE_WEB_SEARCH=1 \
  0sec scan --target https://example.com --scope ./scope.json --mode web
```
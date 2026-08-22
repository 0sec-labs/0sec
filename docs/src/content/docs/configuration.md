---
title: Configuration
description: Runtime modes, scan modes, depth settings, and environment options.
---

0sec is designed for zero-config usage, but every default can be overridden via CLI flags or environment variables.

## Runtime modes

Models help 0sec propose and explore. Scoped tools, evidence capture, and verification decide what is retained. The `--runtime` flag selects the LLM backend.

| Runtime | Flag | Description |
|---------|------|-------------|
| `api` | `--runtime api` | Uses your configured direct provider (ChatGPT Codex subscription auth, OpenRouter, Anthropic, Azure OpenAI, or OpenAI). Best for CI and quick scans. **Default.** |
| `claude` | `--runtime claude` | Spawns the Claude Code CLI with your existing subscription. Best for deep analysis. |
| `codex` | `--runtime codex` | Uses the Codex CLI for source review. For live target scans, routes to the direct ChatGPT Codex provider when `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN` is configured. |
| `gemini` | `--runtime gemini` | Spawns the Gemini CLI. Best for large-context source analysis. |
| `auto` | `--runtime auto` | Auto-detects installed CLIs and picks the best one per pipeline stage. |

### API runtime

The default `api` runtime makes direct HTTP calls to an LLM provider. It requires one of these environment variables:

```bash
export 0SEC_CHATGPT_OAUTH_REFRESH_TOKEN="..." # ChatGPT/Codex subscription auth
export OPENROUTER_API_KEY="sk-or-..."   # Recommended
export ANTHROPIC_API_KEY="sk-ant-..."
export AZURE_OPENAI_API_KEY="..."
export OPENAI_API_KEY="sk-..."
```

See [API Keys](/api-keys/) for the full priority order and provider details.

If you use Azure, also set `AZURE_OPENAI_BASE_URL` and `AZURE_OPENAI_MODEL` unless 0sec can read them from a valid Azure-backed `~/.codex/config.toml`. For the Responses API, the base URL should include `/openai/v1`. 0sec fails fast on incomplete Azure config instead of attempting a scan with guessed defaults.

For ChatGPT Codex subscription auth, run `codex login`, then provide the
refresh token from `~/.codex/auth.json` as `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN`.
When that variable is set it takes provider priority over API-key based
providers.

### CLI runtimes (claude, codex, gemini)

These runtimes spawn the respective CLI tool as a subprocess. You must have the CLI installed and authenticated:

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

The Codex CLI is not used as a live target wrapper. That MCP-backed path was
removed because it added a target-interaction bottleneck. To use your Codex
subscription for live scans, configure the direct provider:

```bash
export 0SEC_CHATGPT_OAUTH_REFRESH_TOKEN="..."
0sec scan --target https://example.com --runtime codex
```

### Codex runtime parity matrix

`--runtime codex` works across every 0sec entry point as long as
either the local `codex` CLI binary is installed OR the direct ChatGPT
Codex provider is configured via `0SEC_CHATGPT_ACCESS_TOKEN` /
`0SEC_CHATGPT_OAUTH_REFRESH_TOKEN`. When the binary is absent and the
subscription env is set, 0sec routes the request through the API
runtime against `chatgpt.com/backend-api/codex/responses` (the same
endpoint the upstream `codex` CLI uses).

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

Before 0sec#402 only the web / URL scan path honoured the direct
provider — the other surfaces aborted with
`Requested runtime 'codex' is not available` whenever the codex CLI
binary was missing, even with subscription auth configured. Cloud
sandbox dispatch (the managed worker-controller) still gates codex on
`target_ecosystem === "web"` and is tracked as a separate follow-up.

## Scan modes

The `--mode` flag controls what kind of target is being scanned.

| Mode | Description |
|------|-------------|
| `deep` | Full autonomous pentest. Runs the research + verify agents with the full 40-turn budget. **Default** when the target is an `https://` URL. |
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

The `--depth` flag controls how thorough the scan is.

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

0sec supports multiple output formats:

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

For PR workflows, review only changed files against a base branch:

```bash
0sec review ./my-repo --diff-base origin/main --changed-only
```

This is particularly useful in CI to avoid scanning the entire codebase on every PR.

## Verbose output

Use `--verbose` to see the animated attack replay and detailed agent reasoning:

```bash
0sec scan --target https://api.example.com/chat --verbose
```

## Feature flags

0sec ships a set of agent-improvement features behind environment-variable flags so you can A/B test them and opt in/out per run. Every flag is read at process start; set `<FLAG>=0` or `<FLAG>=false` to disable, anything else to enable.

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
| `0SEC_FEATURE_TRIAGE_MEMORIES` | off | Injects Semgrep-style per-target persistent FP memories into the verify pipeline. Pairs with `0sec-cli triage`. |

## Static analyzer selection

`0sec review`, source-code pipeline scans, and package source scans use Foxguard by default for pre-agent static leads. Set `0SEC_STATIC=semgrep` to route those static leads through Semgrep instead. Diff-aware `--changed-only` source reviews preserve the same changed-file narrowing with either scanner. Dependency advisory checks (`npm audit`, OSV, and OCI package inventory) remain separate and still run for package targets.

```bash
0SEC_STATIC=semgrep 0sec review ./repo --depth quick
```

Semgrep remains available as an explicit compatibility and comparison path while Foxguard carries the default static lead role.

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

- default is `bridge` — the executor container gets its own network stack.
  This is the safe default (no exposure of the host's localhost services
  to the container) and is fine for public targets.
- set `0SEC_DOCKER_NETWORK=host` when the scan target is served from
  the same host, e.g. local XBOW challenges on `localhost:<port>` or a
  `docker-compose` target on the default bridge. The container needs to
  reach `host.docker.internal` / `localhost` to hit the service.
- any valid `docker run --network <name>` value works — pass a custom
  compose network name to land the executor on the same network as the
  target stack.

### Cost ceiling

You can bound API spend per scan, audit, or review:

```bash
export 0SEC_COST_CEILING_USD=5
0sec scan --target https://example.com --mode web
```

Or override it per command:

```bash
0sec audit lodash --cost-ceiling 2
0sec review ./my-repo --cost-ceiling 10
```

If the ceiling is exceeded, 0sec preserves partial findings and exits with code `4`.

### LLM runtime resilience

The runtime layers that keep a provider failure from silently corrupting a scan:

| Variable | Default | Purpose |
|----------|---------|---------|
| `0SEC_LLM_STREAM_IDLE_TIMEOUT_MS` | `120000` | **SSE stream idle watchdog.** Streaming (ChatGPT Codex backend / Azure Responses) calls disarm the overall call timer once response headers arrive; if the server then holds the stream open without emitting a single byte (queue/hold), the call aborts after this window and is classified as a transient error (bounded retry, then a loud failure). An idle window with no bytes at all is never legitimate progress on a healthy stream — without this, a held stream hung the whole scan silently until the outer sandbox timeout (the "$0 cost, zero output" failure shape). |
| `0SEC_LLM_MAX_RETRIES` | `6` | Max retries after the initial attempt for retryable HTTP statuses (429 + transient 5xx), with exponential backoff and `Retry-After` honored. |
| `0SEC_LLM_MAX_RETRY_WAIT_MS` | `60000` | Cumulative backoff cap (ms) for the same wire-layer retry loop. |

Auth-class errors (**401/403**) are never retried at the wire layer: the agent loop exits immediately via `errorExit`, which the pipeline surfaces as an **honest failure** — `warnings[]` carries the provider error and the report marks the run failed, never a clean "0 findings". Package audits add a per-file circuit breaker: 3 consecutive identical-signature failures abort the remaining per-file sessions with one aggregated error (file-specific errors keep full tolerance). A dead provider therefore stops a scan loudly in seconds instead of either hanging or degrading to a false-clean report.

### Cloud sink

If you want to stream findings and the final report to an orchestration layer:

```bash
export 0SEC_CLOUD_SINK=https://api.example.com
export 0SEC_CLOUD_SCAN_ID=scan_123
export 0SEC_CLOUD_TOKEN=secret-token
```

When set, 0sec posts:

- each finding as `{ "finding": ... }`
- the final report as `{ "report": ..., "final": true }`

to:

```text
${0SEC_CLOUD_SINK}/scans/${0SEC_CLOUD_SCAN_ID}/findings
```

Set `0SEC_FEATURE_CLOUD_SINK=0` to disable this behavior even when the env vars are present.

### Machine-readable result line

Set:

```bash
export 0SEC_EMIT_RESULT_LINE=1
```

to make the CLI print one final `0SEC_RESULT=...` JSON line summarizing:

- success/failure
- exit code and exit reason
- target type
- finding counts
- estimated cost and token usage when available

This is useful for wrappers, CI parsers, and the cloud orchestration path.

### Example: maximum-accuracy pentest

Turn on every false-positive reduction feature for a client-ready scan:

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

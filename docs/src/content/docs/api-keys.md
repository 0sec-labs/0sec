---
title: API Keys
description: Supported LLM providers, environment variables, credential priority, model routing, and provider failover.
---

The `api` runtime makes direct HTTP calls to a provider. Set credentials
as environment variables, or use the console credential store for API-key
providers.

## Supported providers

| Provider | Env Var(s) | Default Model | Wire |
|----------|-----------|---------------|------|
| **ChatGPT Codex** | `0SEC_CHATGPT_ACCESS_TOKEN` (read first) / `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN` | `gpt-5.5` | Responses (OAuth bearer) |
| **DeepSeek** | `DEEPSEEK_API_KEY` | `deepseek-v4-flash` | Responses |
| **OpenRouter** | `OPENROUTER_API_KEY` | `anthropic/claude-sonnet-4.6` | Chat completions |
| **Azure OpenAI** | `AZURE_OPENAI_API_KEY` | `gpt-4o` (override with `AZURE_OPENAI_MODEL`) | Chat completions (default) or Responses |
| **OpenAI** | `OPENAI_API_KEY` | `gpt-4o` | Chat completions |
| **Z.ai GLM** | `Z_AI_API_KEY` | `glm-5.3` | Anthropic Messages |
| **Moonshot Kimi** | `KIMI_API_KEY` | `k3` | Anthropic Messages |
| **Alibaba Qwen** | `QWEN_API_KEY` | `qwen3.8-max` | Chat completions |
| **xAI Grok** | `XAI_API_KEY` | `grok-4.6` | Chat completions |
| **OpenCode Zen** | `OPENCODE_API_KEY` | `muse-spark-1.3-contributor-free` | Per-model (Responses, Anthropic Messages, Google generateContent, or Chat completions) |
| **Anthropic** | `ANTHROPIC_API_KEY` | `claude-sonnet-4-6` | Anthropic Messages |

These eleven are the only providers the runtime detects from the environment.
Model families with no direct path (Meta, Mistral, Google Gemini) are reachable
through OpenRouter or OpenCode Zen.

## Credential priority

When no `--model` flag is given, the runtime selects a provider by checking
environment variables in this order. The **first variable found** wins:

1. **ChatGPT Codex** — `0SEC_CHATGPT_ACCESS_TOKEN` or `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN`
2. **DeepSeek** — `DEEPSEEK_API_KEY`
3. **OpenRouter** — `OPENROUTER_API_KEY`
4. **Azure OpenAI** — `AZURE_OPENAI_API_KEY`
5. **OpenAI** — `OPENAI_API_KEY`
6. **Z.ai GLM** — `Z_AI_API_KEY`
7. **Moonshot Kimi** — `KIMI_API_KEY`
8. **Alibaba Qwen** — `QWEN_API_KEY`
9. **xAI Grok** — `XAI_API_KEY`
10. **OpenCode Zen** — `OPENCODE_API_KEY`
11. **Anthropic** — `ANTHROPIC_API_KEY`

With no key at all, the runtime defaults to Anthropic (consistently emitting a
helpful failure message — it never silently produces zero findings).

**Two things override this fallback chain:**
- A `--model` (or `0SEC_MODEL`) value that maps to a specific provider — see
  [model routing](#model-routing) below — causes that provider's key to be used
  regardless of its position in the priority list.
- `0SEC_SELECTED_PROVIDER` / `0SEC_FORCE_PROVIDER` (see [provider
  pinning](#provider-pinning)) pins the provider for the entire run.

## Model routing

Set `--model <id>` or run a command through `env 0SEC_MODEL=<id> 0sec <command>`
when more than one credential is present.
0sec routes recognized model prefixes to the configured provider:

| Model prefix | Provider | Notes |
|---|---|---|
| `glm-*`, `z-ai/*`, `*glm*` | Z.ai GLM | Anthropic-compatible Messages wire |
| `qwen*` | Alibaba Qwen | OpenAI-compatible `chat/completions` wire |
| `k3`, `kimi*` | Moonshot Kimi | Anthropic-compatible Messages wire |
| `grok*`, `xai/*`, `x-ai/*` | xAI Grok | OpenAI-compatible `chat/completions` wire |
| `opencode/<model-id>` | OpenCode Zen | Wire per upstream model family |
| `muse-spark*`, `mimo*`, `ling*`, `big-pickle`, `nemotron*`, `minimax*` | OpenCode Zen | Chat completions wire |
| `claude*`, `anthropic/*`, `*sonnet*`, `*opus*`, `*haiku*` | Anthropic (preferred), OpenRouter (fallback) | Anthropic Messages wire |
| `gpt-*`, `o1`-`o4` | ChatGPT Codex (when configured), OpenAI (fallback) | Responses (Codex) or Chat completions (OpenAI) |
| `deepseek-v4-flash` | DeepSeek | Responses wire |
| Azure Foundry deployment ids | Azure | Chat completions or Responses |

Without an explicit model, 0sec picks an available fallback via the [credential
priority](#credential-priority) chain. Pin a model rather than relying on ambient
credential order.

### Free OpenRouter model

When `OPENROUTER_API_KEY` is set, `--model free` maps to
`nvidia/nemotron-3-super-120b-a12b:free` — a no-cost tier for testing:

```bash
env OPENROUTER_API_KEY="sk-or-v1-..." \
  0sec scan --target https://example.com --scope ./scope.json --model free
```

## Provider pinning

`0SEC_SELECTED_PROVIDER` pins the provider for the current chat or run,
bypassing the ambient credential priority. Accepts one of: `openrouter`,
`anthropic`, `openai`, `azure`, `deepseek`, `chatgpt-codex`, `z-ai`, `kimi`,
`qwen`, `xai`, `opencode`.

```bash
env 0SEC_SELECTED_PROVIDER=deepseek 0SEC_MODEL=deepseek-v4-flash \
  0sec scan --target https://example.com --scope ./scope.json --mode web
```

`0SEC_FORCE_PROVIDER` is an unconditional override for benchmark control. It
applies even when `preferredModel` differs from `0SEC_MODEL`, which defeats
cross-family refutation — use it only in controlled benchmarks. Setting both
to different values throws an error.

## Setting your key

### macOS / Linux
```bash
# Set the provider key.
export Z_AI_API_KEY="..."
export QWEN_API_KEY="..."
export DEEPSEEK_API_KEY="..."

# Select its matching model at run time.
0sec scan --target https://api.example.com --scope ./scope.json --model glm-5.3
0sec scan --target https://api.example.com --scope ./scope.json --model qwen3.8-max

# Or use OpenRouter.
export OPENROUTER_API_KEY="sk-or-v1-..."

# ChatGPT Codex subscription auth. `0SEC_*` names begin with a digit, so
# pass the token with `env` rather than a shell `export`.
env 0SEC_CHATGPT_OAUTH_REFRESH_TOKEN="..." \
  0sec review ./authorized-repo --runtime api
# Or use 0SEC_CHATGPT_ACCESS_TOKEN; it is read first when both are present.
```

### GitHub Actions

Add the key as a repository secret and pass it as `env` on the step. The dedicated
composite action is still [planned](/ci/github-action/), so today you invoke the
CLI through the container image:

```yaml
- run: |
    docker run --rm -v "$PWD:/work" -w /work \
      -e OPENROUTER_API_KEY \
      ghcr.io/0sec-labs/0sec:latest review .
  env:
    OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
```

## ChatGPT Codex authentication

ChatGPT Codex uses its own authentication file, separate from the console's
API-key store. When neither `0SEC_CHATGPT_ACCESS_TOKEN` nor
`0SEC_CHATGPT_OAUTH_REFRESH_TOKEN` is supplied, the runtime can read tokens
from `~/.codex/auth.json`, written by `codex login`. Override the path with
`0SEC_CHATGPT_AUTH_FILE`; an account ID comes from `0SEC_CHATGPT_ACCOUNT_ID`
or the same file. Prefer the canonical spelling over the older
`0SEC_CODEX_AUTH_JSON_PATH`.

Path precedence for the auth file:
1. `0SEC_CHATGPT_AUTH_FILE` (canonical, matches the runtime).
2. `0SEC_CODEX_AUTH_JSON_PATH` (deprecated — honoured as a fallback).
3. `~/.codex/auth.json` (the default when neither override is set).

The CLI bootstrap additionally runs `maybeLoadCodexAuth` at startup, which
loads the auth file into `0SEC_CHATGPT_*` env vars if no such token is already
present. This is a local-dev convenience: a logged-in `codex` session wins over
stale `AZURE_OPENAI_API_KEY` / `OPENAI_API_KEY` left in a dev shell, so
`0sec review` "just works" on the subscription backend.

In OpenTUI chat, run `/providers` (or `/connect`) and choose **ChatGPT
Codex**. 0sec runs the official `codex login --device-auth` lifecycle, streams
the device instructions in the pane, and reloads `~/.codex/auth.json` only
after success. It never asks for an OpenAI API key or a pasted OAuth token.
Choose **OpenAI** separately when you want `OPENAI_API_KEY` direct API access.

Every `0sec` run loads that file into the environment before any subcommand
runs, so a codex-login file is picked up everywhere — the console `/providers`
view, `0sec doctor`, and scans/reviews/audits. An explicit environment value always wins,
and a missing or malformed file is ignored quietly. One caveat: the `/providers` table
never checks the filesystem, so anything that reads it *without* the CLI's startup
load (for example, if you embed it in your own tool) shows "not configured" — a
display quirk, not a broken setup.

## Console credential store

The console credential store is for API-key providers only. Run `/providers`
to open the chat-owned OpenTUI connection pane, then select a provider to paste
its API key. ChatGPT Codex never uses this generic key path: it uses device
OAuth and the Codex auth file instead. Each API-key row shows `configured via
<VAR>` or `not configured`, reflecting the real environment.

Keys are written to `credentials.json` in the [state
directory](/configuration/#state-directory) (`~/.0sec/` by default), re-tightened
to owner-only (`0600` file, `0700` dir) on every save.

**An explicit environment value always wins over the stored value** — the store only
fills a variable the environment doesn't already carry. This keeps "which key did
that run use?" answerable when a request 401s or a metered key overspends.

**Stored credentials are not encrypted.** They're plaintext, protected only by
file permissions. Treat `credentials.json` like an exported secret in a shell
profile.

Picking a model whose provider has no credentials won't fail at startup — the
`/model` picker lists every model 0sec can price, not every one it can actually
call. The request fails later instead (a zero-token turn reporting a missing key).
Run `/providers` first to confirm the provider is configured.

## When to use OpenRouter

Use OpenRouter to reach a model family with no direct provider credential. It's
not required for Z.ai GLM, Alibaba Qwen, Moonshot Kimi, Anthropic, OpenAI, Azure,
OpenCode Zen, or DeepSeek. OpenRouter is also the fallback when a `claude-*` model
is requested but no `ANTHROPIC_API_KEY` is set — the runtime checks for
`OPENROUTER_API_KEY` before giving up on that model family.

## Provider failover

`0SEC_LLM_FALLBACK` configures an ordered chain of backup providers when the
primary exhausts its retry budget or hits a plan-quota limit:

```bash
env 0SEC_LLM_FALLBACK=deepseek:deepseek-v4-flash,azure:gpt-5-deployment \
  0sec review ./authorized-repo
```

Each entry is `<providerId>:<model>`, comma-separated. The runtime advances
through the chain sequentially, skipping entries whose auth env var is absent.
Supported provider ids: `openrouter`, `anthropic`, `openai`, `azure`, `deepseek`,
`chatgpt-codex`, `z-ai`, `kimi`, `qwen`, `xai`, `opencode`.

## Azure OpenAI configuration

Azure is stricter — the API key alone isn't enough. 0sec needs an Azure base URL
and a deployment/model name, either from env vars or reused from
`~/.codex/config.toml` when Codex is already configured against Azure.

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_OPENAI_API_KEY` | Yes | Your Azure OpenAI API key |
| `AZURE_OPENAI_BASE_URL` | Yes, unless 0sec can read it from Codex config | Base URL for your Azure deployment. For the Responses API this should include `/openai/v1`. |
| `AZURE_OPENAI_MODEL` | Yes, unless 0sec can read it from Codex config | Azure deployment/model name (not just a generic model family string) |
| `AZURE_OPENAI_WIRE_API` | No | Wire API format: `chat_completions` (default) or `responses` |

```bash
export AZURE_OPENAI_API_KEY="your-azure-key"
export AZURE_OPENAI_BASE_URL="https://your-resource.openai.azure.com/openai/v1"
export AZURE_OPENAI_MODEL="gpt-4o"
export AZURE_OPENAI_WIRE_API="responses"
```

If you rely on Codex config, make sure `~/.codex/config.toml` points at Azure with
a usable base URL and model/deployment. Incomplete Azure config stops with a
configuration error rather than a broken scan.

The runtime probes the Azure endpoint once per process to resolve the deployment
region, used for diagnostics (not routing).

## Alternative: CLI runtimes

To skip API keys entirely, use CLI runtimes. Claude runs live scans through its
subscription loop; Codex and Gemini are source-review oriented:

```bash
# Use Claude Code CLI for an authorized live target
0sec scan --target https://api.example.com/chat --scope ./scope.json --runtime claude
# Use Codex CLI for source review
0sec review ./my-repo --runtime codex

# Use Gemini CLI
0sec review ./my-repo --runtime gemini
```

Source-review CLI runtimes need no API key — the CLI handles auth. Codex live
scans use the direct ChatGPT Codex provider, so they need
`0SEC_CHATGPT_OAUTH_REFRESH_TOKEN` rather than the Codex CLI.

## `0sec doctor` — credential readiness

Run `0sec doctor` to inspect runtime and credential readiness. It is not a
successful authenticated model-call test:

```bash
0sec doctor
```

It reports:
- Node.js version compatibility (20+ required).
- **API runtime** status: `configured` (credential found), `bad` (configured but
  unusable), or `missing` (no credential).
- **CLI runtimes** found on `PATH` (claude, codex, gemini).
- Configuration errors when the API runtime is set up but cannot be used.

Under Bun with a compatible terminal, doctor launches the richer OpenTUI view.
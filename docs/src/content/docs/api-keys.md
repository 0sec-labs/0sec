---
title: API Keys
description: Supported LLM providers, environment variables, credential priority, model routing, and provider failover.
---

The `api` runtime makes direct HTTP calls to a provider. Set credentials
as environment variables, or use the console credential store for API-key
providers.

## Hosted inference (draft)

> Status: 2026-09-11. Unreleased candidate behavior. Production hosted billing
> isn't enabled. Local qualification does not establish paid access or provider
> availability. The direct-provider instructions below remain the current setup.

The candidate adds a `hosted` provider to the `api` runtime. A scoped 0sec
organization credential replaces an upstream API key on the client. The gateway
holds provider credentials and forwards model requests, including the context
and tool results supplied by the agent. Shell commands and tools still execute
on your configured local executor. Login doesn't sandbox them.

### Account, models and usage

Follow the [draft onboarding steps](/getting-started/#hosted-models-draft).
`0sec models --json` reads the service catalog, including each alias, provider,
wire protocol, context/output limits and versioned customer rates. Use that
catalog for hosted selection, not the console's bundled BYOK model list.
An explicit alias is validated before inference. Without an alias, the candidate
selects the first service catalog entry.

`0sec balance --json` reads the selected organization's inference wallet.
It isn't a review-credit balance or a local scan cost estimate. The dashboard
shows recent requests with model/provider identity, token usage, billed amount,
cancellation and settlement status. There is no `0sec usage` command in this
candidate; the authenticated usage endpoint is listed below.

| Endpoint on the selected cloud host | Required token scope | Purpose |
| --- | --- | --- |
| `GET /api/inference/v1/models` | `inference:read` | Hosted aliases and rate metadata |
| `GET /api/inference/account` | `billing:read` | Organization inference balance |
| `GET /api/inference/usage` | `inference:read` | Up to 50 recent request records |
| `POST /api/inference/v1/chat/completions` | `inference:invoke` | Catalog-selected Chat Completions route |
| `POST /api/inference/v1/responses` | `inference:invoke` | Catalog-selected Responses route |

These routes use bearer authentication. The catalog selects the protocol;
clients don't supply an upstream endpoint or arbitrary provider. Older login
tokens may lack the new scopes and require reauthorization.

### Charging and interrupted requests

The gateway reserves a bounded maximum before contacting a provider. The
candidate reserve covers the catalog context window and bounded output at its
reserve multiplier, rather than an estimate of your prompt alone. Final retail
charges use the request's snapshotted customer rates and measured usage.
An upstream provider receipt establishes provider cost and usage; it is not
a customer pass-through price.

Responses and Chat Completions support server-sent events on configured routes.
Receiving output does not mean settlement has finished. Stopping delivery
doesn't guarantee zero cost: the gateway can finish reading the bounded upstream
request to collect usage. Missing usage or an uncertain billing acknowledgement
remains unresolved rather than being treated as free. Check request status and
balance before resubmitting.

| Failure | Candidate behavior and next step |
| --- | --- |
| HTTP 401 | Missing, invalid or revoked credential. Sign in again. |
| HTTP 403 | Required scope missing. Reauthorize the CLI for the intended organization. |
| HTTP 402 | Insufficient credit for the reserve. No upstream request is made for this rejection. Check the inference wallet and purchase access. |
| HTTP 429 | Concurrency limit, unresolved prior charge, or provider throttling. Inspect the error code and request history before retrying. |
| HTTP 503 | Hosted inference disabled, provider unavailable, or billing unavailable. Login or a stored key doesn't bypass this gate. |
| Transport failure or hosted HTTP 5xx | The CLI doesn't automatically replay a potentially consumed request. Inspect usage before trying again. |

The gateway rejects detected model substitution. There is no automatic
server-side model switch promised here. BYOK is a separate choice: configure
its credential and select that provider explicitly. The candidate can use an
operator-configured `0SEC_LLM_FALLBACK` chain for eligible retry/quota failures,
but it doesn't turn an exhausted hosted wallet into free BYOK or another model.
Changing providers changes who receives the request and which account pays.

For hosted HTTP 429, the candidate retries or enters that configured fallback
chain only when the gateway supplies `x-0sec-retry-safe: 1`. The gateway emits
this marker only for a pre-dispatch concurrency rejection. Provider throttling
can occur after dispatch with a pending charge; it and unresolved-charge
responses carry no marker. An unmarked 429, including one from an older gateway,
stops without automatic retry or fallback.

A fallback or model migration changes the evaluated system. Before/after
self-evolution comparisons must hold model and route fixed, or evaluate the
changed route separately; don't attribute a different model's result to a
harness improvement.

The executable-plugin SDK's model broker uses its parent runtime, including
model calls made during plugin evolution. If that parent routes through
`hosted`, those calls use the same organization's inference accounting.
This isn't a free self-evolution allowance or universal billing guarantee:
subagents construct new runtimes, and trusted host code can use clients outside
the SDK. The new live evolution lifecycle hasn't had end-to-end hosted billing
qualification.

## Supported providers

| Provider | Env Var(s) | Default Model | Wire |
|----------|-----------|---------------|------|
| **ChatGPT Codex** | `0SEC_CHATGPT_ACCESS_TOKEN` (read first) / `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN` | `gpt-5.5` | Responses (OAuth bearer) |
| **DeepSeek** | `DEEPSEEK_API_KEY` | `deepseek-flash` (V4.1 Flash) | Responses |
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

### Current model choices

The bundled `/model` picker includes GPT-6 Astra (`gpt-6-astra`), DeepSeek V4.1
Flash (`deepseek-flash`), Claude Fable 5.1 / Opus 5 / Sonnet 5, Gemini 3.8 Flash
and 3.5 Flash-Lite, and GLM-5.3-Flash. Existing models remain selectable; adding
Astra does not change the OpenAI or ChatGPT Codex default.

Qwen choices include `qwen3.8-max`, `qwen3.8-flash`, `qwen3.7-max`,
`qwen3.7-plus`, `qwen3.6-plus`, and `qwen3.6-flash`. The offline catalog also
includes `qwen3.8-max-preview` without a price. They use `QWEN_API_KEY` and the
existing Token Plan endpoint; model availability depends on the account.
Qwen estimates use the [Models.dev Alibaba PAYG rates](https://models.dev/api.json),
not the subscription feed's zero-token rates. Plus requests above 256K input
tokens have higher pricing; reconcile Token Plan credits against the invoice.

Select the exact API id, for example:

```bash
env 0SEC_SELECTED_PROVIDER=openai 0SEC_MODEL=gpt-6-astra \
  0sec review ./authorized-repo
```

Gemini still requires a gateway: use `opencode/gemini-3.8-flash` with OpenCode
Zen, or the gateway's documented model id with OpenRouter.

Prices are estimates, not invoices. [Astra's published base rates](https://developers.openai.com/api/docs/models/gpt-6-astra)
apply through 272K input tokens; longer requests and cache writes cost more.
[DeepSeek Flash](https://api-docs.deepseek.com/quick_start/pricing) is estimated
at peak rates ($0.30 input / $1.20 output per million tokens); off-peak is half
price. Gateway prices and subscription billing can differ from direct API rates.

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
| `deepseek-flash`, `deepseek-v4-flash` | DeepSeek | Responses wire; V4.1 uses `deepseek-flash` |
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
env 0SEC_SELECTED_PROVIDER=deepseek 0SEC_MODEL=deepseek-flash \
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

The `/model` picker starts with curated models; **Tab** opens the full catalog.
A listing is not proof of credentials or account access. The detail pane shows
credential sources and setup hints; an unknown price is shown as `—`, not zero.
Use `/connect` to add credentials and `/providers` to inspect the configured
provider before making a request.

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
env 0SEC_LLM_FALLBACK=deepseek:deepseek-flash,azure:gpt-5-deployment \
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
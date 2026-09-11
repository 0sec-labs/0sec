---
title: API Keys
description: Supported LLM providers, environment variables, credential priority, model routing, and provider failover.
---

0sec Cloud will offer open cybersecurity models and 0sec-curated options through
one connection and inference-credit balance, without supplier-account setup.
Alternatively, use your own API key or supported subscription without a Cloud account.

<a id="hosted-inference-draft"></a>
<a id="0sec-hosted-inference-draft"></a>

## Hosted inference

For access to the hosted test service, follow [Cloud setup](/getting-started/#hosted-models-draft).
The `api` runtime's `hosted` provider uses a scoped organization credential.
The gateway holds supplier keys and forwards model context, including tool
results. Tools execute on your configured local executor.

### Account, models and usage

`0sec models --json` lists hosted aliases, providers, wire protocols, limits and
customer rates. Select an exact alias; otherwise the first catalog entry is used.

`0sec balance --json` reads organization inference credit, separately from
0review or local cost estimates. The dashboard and usage endpoint show model,
provider, tokens, billed amount, cancellation and settlement status.
There is no `0sec usage` command.

Autumn reserves credit before dispatch and settles measured usage afterward.
Login adds no credit. Funding requires confirmed payment through configured
top-ups or allowances. Requests exceeding available reserve credit are rejected;
postpaid overage is unavailable.

| Endpoint on the selected cloud host | Required token scope | Purpose |
| --- | --- | --- |
| `GET /api/inference/v1/models` | `inference:read` | Hosted aliases and rate metadata |
| `GET /api/inference/account` | `billing:read` | Organization inference balance |
| `GET /api/inference/usage` | `inference:read` | Up to 50 recent request records |
| `POST /api/inference/v1/chat/completions` | `inference:invoke` | Catalog-selected Chat Completions route |
| `POST /api/inference/v1/responses` | `inference:invoke` | Catalog-selected Responses route |

All routes require bearer authentication. Reauthorize older tokens that lack
these scopes. The catalog controls the provider endpoint and wire protocol.

### Charging and interrupted requests

The reserve covers the catalog context window and bounded output at the configured
multiplier. Charges use measured usage and snapshotted customer rates; supplier
receipts establish usage and supplier cost, not retail pricing.

Both wire APIs support server-sent events. Cancellation can still incur charges:
the gateway may drain the bounded provider stream to collect usage. Missing usage
or uncertain settlement stays unresolved and blocks further spending.
Check request status and balance before resubmitting.

| Failure | Action |
| --- | --- |
| HTTP 401 | Missing, invalid or revoked credential. Sign in again. |
| HTTP 403 | Required scope missing. Reauthorize the CLI for the intended organization. |
| HTTP 402 | Insufficient reserve credit; no provider call. Check balance and funding. |
| HTTP 429 | Concurrency, unresolved charge or provider throttling. Inspect the error and request history. |
| HTTP 503 | Hosted service, provider or billing unavailable. |
| Transport failure or hosted HTTP 5xx | The CLI doesn't automatically replay a potentially consumed request. Inspect usage before trying again. |

The gateway rejects detected model substitution. `0SEC_LLM_FALLBACK` configures
explicit backup routes; switching providers changes who receives the request
and which account pays.

Hosted HTTP 429 permits retry or configured fallback only with
`x-0sec-retry-safe: 1`, issued for pre-dispatch concurrency rejection.
Provider throttling and unresolved charges are unmarked and aren't replayed.

Plugin evolution's SDK model calls use the parent runtime's accounting when
routed through `hosted`. Subagents resolve new runtimes; trusted host code can
use external clients. Keep model and route fixed when comparing evolution results.

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

Displayed prices are estimates; reconcile charges against provider invoices.
[Astra's published base rates](https://developers.openai.com/api/docs/models/gpt-6-astra)
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

Without a key, the runtime selects Anthropic and reports a missing-credential failure.

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

Without an explicit model, 0sec follows the [credential priority](#credential-priority)
chain. Pin a model for predictable selection.

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

The CLI bootstrap runs `maybeLoadCodexAuth` at startup, loading the auth file
into `0SEC_CHATGPT_*` env vars if no token is present. A logged-in `codex`
session takes priority over stale `AZURE_OPENAI_API_KEY` / `OPENAI_API_KEY`
left in a dev shell.

In OpenTUI chat, run `/providers` (or `/connect`) and choose **ChatGPT
Codex**. 0sec runs the official `codex login --device-auth` lifecycle, streams
the device instructions in the pane, and reloads `~/.codex/auth.json` only
after success. It never asks for an OpenAI API key or a pasted OAuth token.
Choose **OpenAI** separately when you want `OPENAI_API_KEY` direct API access.

Every `0sec` run loads that file into the environment before any subcommand
runs, so a codex-login file is picked up everywhere — the console `/providers`
view, `0sec doctor`, and scans/reviews/audits. An explicit environment value always wins,
and a missing or malformed file is ignored quietly. The `/providers` table
never checks the filesystem: anything reading it without the CLI's startup
load (for example, embedded in a custom tool) shows "not configured".

## Console credential store

Run `/providers` to select an API-key provider and enter its key. ChatGPT Codex
uses device OAuth and its auth file. Each API-key row reports `configured via
<VAR>` or `not configured` from the environment.

Keys are written to `credentials.json` in the [state
directory](/configuration/#state-directory) (`~/.0sec/` by default), re-tightened
to owner-only (`0600` file, `0700` dir) on every save.

**An explicit environment value always wins over the stored value.** The store
only fills a variable the environment doesn't already carry.

**Stored credentials are not encrypted.** They're plaintext, protected only by
file permissions. Treat `credentials.json` like an exported secret in a shell
profile.

The `/model` picker starts with curated models; **Tab** opens the full catalog.
Check credentials and account access before use. The detail pane shows setup
hints and credential sources; unknown prices appear as `—`.
Use `/connect` to add credentials and `/providers` to inspect them.

## When to use OpenRouter

Use OpenRouter for model families with no direct provider credential. It also
serves as fallback when a `claude-*` model is requested without
`ANTHROPIC_API_KEY`: the runtime checks for `OPENROUTER_API_KEY` before giving
up.

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

0sec needs an Azure base URL and deployment/model name in addition to the API
key, either from env vars or from `~/.codex/config.toml` when Codex is
configured against Azure.

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
configuration error before any scan starts.

The runtime probes the Azure endpoint once per process to resolve the deployment
region for diagnostics.

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

Inspect runtime and credential configuration:

```bash
0sec doctor
```

Authenticated model access requires a separate request; `doctor` checks configuration.

It reports:
- Node.js version compatibility (20+ required).
- **API runtime** status: `configured` (credential found), `bad` (configured but
  unusable), or `missing` (no credential).
- **CLI runtimes** found on `PATH` (claude, codex, gemini).
- Configuration errors when the API runtime is set up but cannot be used.

Under Bun with a compatible terminal, doctor launches the richer OpenTUI view.
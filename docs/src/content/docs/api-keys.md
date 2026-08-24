---
title: API Keys
description: Supported LLM providers, environment variables, and model routing.
---

The default `api` runtime makes direct HTTP calls to a provider. Set credentials
as environment variables.

## Supported providers

| Provider | Environment Variable | Notes |
|----------|---------------------|-------|
| **Z.ai GLM** | `Z_AI_API_KEY` | `glm-5.3` is the default for the Z.ai route. Uses Z.ai's Anthropic-compatible Messages API. |
| **Alibaba Qwen** | `QWEN_API_KEY` | Use `--model qwen3.8-max` or `0SEC_MODEL=qwen3.8-max`. Uses Alibaba Model Studio's OpenAI-compatible endpoint. |
| **Moonshot Kimi** | `KIMI_API_KEY` | Use `--model k3`. Uses Moonshot's Anthropic-compatible Coding endpoint. |
| **xAI Grok** | `XAI_API_KEY` | Use `--model grok-4.6`. Uses xAI's OpenAI-compatible endpoint. Override the host with `XAI_BASE_URL`. Cost note: our price table carries xAI's short-context rates, so spend on prompts over 200k tokens is under-reported — reconcile against the xAI console. |
| **ChatGPT Codex** | `0SEC_CHATGPT_ACCESS_TOKEN`, `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN` | OAuth subscription auth, not an API key. Both tokens are accepted; the access token is read first, the refresh token is refreshed on demand. This is the one provider that can also authenticate from a file — see [ChatGPT Codex authentication](#chatgpt-codex-authentication) below. |
| **DeepSeek** | `DEEPSEEK_API_KEY` | Direct DeepSeek API access. Endpoint override: `DEEPSEEK_BASE_URL`. |
| **OpenRouter** | `OPENROUTER_API_KEY` | Access to many hosted model families through one API. |
| **Anthropic** | `ANTHROPIC_API_KEY` | Direct access to Claude models. Endpoint override: `ANTHROPIC_BASE_URL`. |
| **Azure OpenAI** | `AZURE_OPENAI_API_KEY` | Azure-hosted OpenAI models. See [Azure configuration](#azure-openai-configuration) below for additional settings. |
| **OpenAI** | `OPENAI_API_KEY` | Direct access to GPT models. Endpoint override: `OPENAI_BASE_URL`. |

These ten are the only providers the runtime detects from the environment. Model
families with no direct path (Google, Meta, Mistral) are reachable through
OpenRouter instead.

## Model routing

Set `--model <id>` or `0SEC_MODEL=<id>` when more than one credential is present.
0sec routes recognized families to the configured provider:

- `glm-*` / `z-ai/*` → Z.ai
- `qwen*` → Alibaba Qwen
- `k3` / `kimi*` → Moonshot Kimi
- `claude*` / `anthropic/*` → Anthropic, then OpenRouter when direct Anthropic
  credentials are absent
- `gpt-*` / `o*` → ChatGPT Codex subscription when configured, otherwise
  OpenAI

Without an explicit model, 0sec picks an available fallback. Pin a model rather
than relying on ambient credential order.

## Setting your key

### macOS / Linux
```bash
# Set the provider key.
export Z_AI_API_KEY="..."
export QWEN_API_KEY="..."

# Select its matching model at run time.
0sec scan --target https://api.example.com --scope ./scope.json --model glm-5.3
0sec scan --target https://api.example.com --scope ./scope.json --model qwen3.8-max

# Or use OpenRouter.
export OPENROUTER_API_KEY="sk-or-v1-..."

# ChatGPT Codex subscription auth (either token works).
export 0SEC_CHATGPT_OAUTH_REFRESH_TOKEN="..."
# export 0SEC_CHATGPT_ACCESS_TOKEN="..."   # read first when both are set
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

ChatGPT Codex is the only provider that can authenticate from a file instead of an
env var. When neither `0SEC_CHATGPT_ACCESS_TOKEN` nor
`0SEC_CHATGPT_OAUTH_REFRESH_TOKEN` is exported, the runtime reads the tokens from
`~/.codex/auth.json` (the file `codex login` writes). Override the path with
`0SEC_CHATGPT_AUTH_FILE`; an account id comes from `0SEC_CHATGPT_ACCOUNT_ID` or the
same file. (`0SEC_CODEX_AUTH_JSON_PATH` is a deprecated spelling — prefer
`0SEC_CHATGPT_AUTH_FILE`.)

Every `0sec` run loads that file into the environment before any subcommand
runs, so a codex-login file is picked up everywhere — the console `/providers`
view, `0sec doctor`, and scans/reviews/audits. An explicit export always wins, and
a missing or malformed file is ignored quietly. One caveat: the `/providers` table
never checks the filesystem, so anything that reads it *without* the CLI's startup
load (for example, if you embed it in your own tool) shows "not configured" — a
display quirk, not a broken setup.

## Console credential store

The console can hold provider keys so you don't re-export them each shell. Run
`/providers` to see which providers hold credentials, then select one to paste its
key. Each line shows `configured via <VAR>` or `not configured`, reflecting the
real environment.

Keys are written to `credentials.json` in the [state
directory](/configuration/#state-directory) (`~/.0sec/` by default), re-tightened
to owner-only (`0600` file, `0700` dir) on every save.

**An exported shell variable always wins over the stored value** — the store only
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
or DeepSeek.

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

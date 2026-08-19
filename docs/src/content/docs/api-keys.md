---
title: API Keys
description: Supported LLM providers, environment variables, and model routing.
---

pwnkit's `api` runtime (the default) makes direct HTTP calls to an LLM provider. You need to set provider credentials as environment variables.

## Supported providers

| Provider | Environment Variable | Notes |
|----------|---------------------|-------|
| **Z.ai GLM** | `Z_AI_API_KEY` | `glm-5.3` is the default for the Z.ai route. Uses Z.ai's Anthropic-compatible Messages API. |
| **Alibaba Qwen** | `QWEN_API_KEY` | Use `--model qwen3.8-max` or `PWNKIT_MODEL=qwen3.8-max`. Uses Alibaba Model Studio's OpenAI-compatible endpoint. |
| **Moonshot Kimi** | `KIMI_API_KEY` | Use `--model k3`. Uses Moonshot's Anthropic-compatible Coding endpoint. |
| **ChatGPT Codex** | `PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN` | Uses ChatGPT/Codex subscription auth from `codex login`. Copy the refresh token from `~/.codex/auth.json`. |
| **DeepSeek** | `DEEPSEEK_API_KEY` | Direct DeepSeek API access. |
| **OpenRouter** | `OPENROUTER_API_KEY` | Access to many hosted model families through one API. |
| **Anthropic** | `ANTHROPIC_API_KEY` | Direct access to Claude models. |
| **Azure OpenAI** | `AZURE_OPENAI_API_KEY` | Azure-hosted OpenAI models. See [Azure configuration](#azure-openai-configuration) below for additional settings. |
| **OpenAI** | `OPENAI_API_KEY` | Direct access to GPT models. |

## Model routing

Set `--model <id>` or `PWNKIT_MODEL=<id>` when more than one provider
credential is present. pwnkit routes recognized model families to the provider
whose credentials are configured:

- `glm-*` / `z-ai/*` → Z.ai
- `qwen*` → Alibaba Qwen
- `k3` / `kimi*` → Moonshot Kimi
- `claude*` / `anthropic/*` → Anthropic, then OpenRouter when direct Anthropic
  credentials are absent
- `gpt-*` / `o*` → ChatGPT Codex subscription when configured, otherwise
  OpenAI

Without an explicit model, pwnkit selects an available provider fallback. Pin a
model rather than relying on ambient credential order.

## Setting your key

### macOS / Linux
```bash
# Set the provider key.
export Z_AI_API_KEY="..."
export QWEN_API_KEY="..."

# Select its matching model at run time.
pwnkit scan --target https://api.example.com --scope ./scope.json --model glm-5.3
pwnkit scan --target https://api.example.com --scope ./scope.json --model qwen3.8-max

# Or use OpenRouter.
export OPENROUTER_API_KEY="sk-or-v1-..."

# ChatGPT Codex subscription auth.
export PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN="..."
```

### GitHub Actions

Add the key as a repository secret, then reference it in your workflow:

```yaml
- uses: 0sec-labs/0sec@main
  with:
    mode: review
    path: .
  env:
    OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
```

## When to use OpenRouter

OpenRouter is useful when you want to select a model family that is not
available through a direct provider credential. It is not required for Z.ai
GLM, Alibaba Qwen, Moonshot Kimi, Anthropic, OpenAI, Azure, or DeepSeek.

## Azure OpenAI configuration

Azure OpenAI is stricter than the other providers. The API key alone is not enough. pwnkit needs:

- an Azure base URL
- an Azure deployment/model name

You can provide those explicitly via env vars, or let pwnkit reuse them from `~/.codex/config.toml` when Codex is already configured against Azure.

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_OPENAI_API_KEY` | Yes | Your Azure OpenAI API key |
| `AZURE_OPENAI_BASE_URL` | Yes, unless pwnkit can read it from Codex config | Base URL for your Azure deployment. For the Responses API this should include `/openai/v1`. |
| `AZURE_OPENAI_MODEL` | Yes, unless pwnkit can read it from Codex config | Azure deployment/model name (not just a generic model family string) |
| `AZURE_OPENAI_WIRE_API` | No | Wire API format: `chat_completions` (default) or `responses` |

```bash
export AZURE_OPENAI_API_KEY="your-azure-key"
export AZURE_OPENAI_BASE_URL="https://your-resource.openai.azure.com/openai/v1"
export AZURE_OPENAI_MODEL="gpt-4o"
export AZURE_OPENAI_WIRE_API="responses"
```

If you rely on Codex config instead of env vars, make sure `~/.codex/config.toml` points at Azure and contains a usable Azure base URL plus model/deployment. If the selected Azure runtime is incomplete, pwnkit stops immediately with a configuration error instead of silently falling through to a broken scan.

## Alternative: CLI runtimes

If you prefer not to use API keys at all, you can use CLI runtimes for supported workflows. Claude can run live target scans through its native subscription loop. Codex and Gemini are source-review oriented CLI runtimes:

```bash
# Use Claude Code CLI for an authorized live target
pwnkit scan --target https://api.example.com/chat --scope ./scope.json --runtime claude
# Use Codex CLI for source review
pwnkit review ./my-repo --runtime codex

# Use Gemini CLI
pwnkit review ./my-repo --runtime gemini
```

No API key environment variable is needed for source-review CLI runtimes because authentication is handled by the respective CLI tool. Codex live target scans use the direct ChatGPT Codex provider, so they require `PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN` rather than the Codex CLI wrapper.

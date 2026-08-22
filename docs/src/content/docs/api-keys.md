---
title: API Keys
description: Supported LLM providers, environment variables, and model routing.
---

0sec's `api` runtime (the default) makes direct HTTP calls to an LLM provider. You need to set provider credentials as environment variables.

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

These ten providers are exactly the ones the runtime can detect from the
environment. A model whose family maps to a vendor with no direct runtime path
(for example Google, Meta, or Mistral in the pricing table) is not configurable
here; reach those through OpenRouter instead.

## Model routing

Set `--model <id>` or `0SEC_MODEL=<id>` when more than one provider
credential is present. 0sec routes recognized model families to the provider
whose credentials are configured:

- `glm-*` / `z-ai/*` → Z.ai
- `qwen*` → Alibaba Qwen
- `k3` / `kimi*` → Moonshot Kimi
- `claude*` / `anthropic/*` → Anthropic, then OpenRouter when direct Anthropic
  credentials are absent
- `gpt-*` / `o*` → ChatGPT Codex subscription when configured, otherwise
  OpenAI

Without an explicit model, 0sec selects an available provider fallback. Pin a
model rather than relying on ambient credential order.

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

Add the key as a repository secret, then reference it in your workflow:

```yaml
- uses: 0sec-labs/0sec@main
  with:
    mode: review
    path: .
  env:
    OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
```

## ChatGPT Codex authentication

ChatGPT Codex is the only provider that can authenticate from a file on disk
instead of an environment variable. When neither `0SEC_CHATGPT_ACCESS_TOKEN`
nor `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN` is exported, the runtime reads
`~/.codex/auth.json` — the file `codex login` writes — and uses the tokens
inside it. Override that path with `0SEC_CHATGPT_AUTH_FILE`. An account id, if
present, is picked up from `0SEC_CHATGPT_ACCOUNT_ID` or from the same file.

`0SEC_CODEX_AUTH_JSON_PATH` is a deprecated spelling of the same override. The
CLI still accepts it as a fallback, but only when `0SEC_CHATGPT_AUTH_FILE` is
unset, and the engine's own file read does not honour it at all — so use
`0SEC_CHATGPT_AUTH_FILE`.

### How a codex-login file reaches the status views

Every `0sec` (or `0`) invocation loads the auth file into the environment
before any subcommand runs: the CLI entrypoint reads
`~/.codex/auth.json` (or your override) and copies its tokens into
`0SEC_CHATGPT_ACCESS_TOKEN` / `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN`. That load is
a no-op if either variable is already exported — an explicit export always
wins — and it fails soft if the file is missing, unreadable or malformed.

Because of that startup load, a codex-login file **is** detected on the normal
CLI paths:

- **The interactive console** (`0`, or `0sec console`). By the time
  `/providers` inspects the environment the tokens are already in it, so
  ChatGPT Codex shows as `configured via 0SEC_CHATGPT_ACCESS_TOKEN` rather
  than "not configured".
- **`0sec doctor`.** It runs the same startup load, and its "API runtime" line
  additionally comes from the engine's provider detection, which reads the
  auth file directly. Both routes agree: the API runtime reports `ok
  ChatGPT Codex`.
- **Scans, reviews and audits.** These authenticate from the file even without
  the startup load, since provider detection reads it itself.

The remaining limitation is narrower than "the status views cannot see the
file". The provider table behind `/providers` is a pure function of an
environment you hand it — it never stats the filesystem — so it reports
ChatGPT Codex as **not configured** for any caller that consults it *without*
the CLI's startup load: embedding that table in your own tool, or querying it
against a synthetic environment. On those paths, and only those, treat "not
configured" as a display limitation rather than a broken setup, or export
`0SEC_CHATGPT_OAUTH_REFRESH_TOKEN` so the answer no longer depends on who
loaded the file.

## Console credential store

The interactive console can hold provider keys for you so you do not have to
re-export them in every shell. In the console, run `/providers` to see which
providers actually hold credentials on the current machine, then select one to
paste its key. The status line for each provider reflects the real
environment: it shows `configured via <VAR>` when a key is found and
`not configured` otherwise.

Keys entered this way are written to `credentials.json` in the 0sec state
directory (`~/.0sec/` by default — see
[Configuration](/configuration/#state-directory) for how that path is
resolved). The file and its parent directory are created and re-tightened to
owner-only permissions (`0600` file, `0700` directory) on every save.

**An explicitly exported shell environment variable always wins over the
stored value.** The store only fills a provider's variable when the
environment does not already carry a credential for it — an `export` in your
shell is never overridden. This precedence is deliberate: an `export` is an
explicit, deliberate choice, and a stored key silently shadowing it would make
"which key did that run use?" unanswerable — exactly the question you need
answered when a request returns 401 or a metered key runs up unexpected spend.

**Stored credentials are not encrypted at rest.** They are plaintext in
`credentials.json`, protected only by file permissions (`0600`) and your
account's control of the home directory. There is no passphrase and no
key-management layer. Anything with read access to your home directory can read
the keys, so treat that file the same way you would treat an exported secret in
a shell profile.

A model whose provider holds no credentials — neither in the environment nor in
the store — does not fail at startup. The `/model` picker is built from the
pricing table, which lists every model 0sec knows how to price, not every model
it can currently call. Selecting an uncredentialed model succeeds; the request
then fails at request time (typically a turn that consumes zero tokens and
reports a missing key). Run `/providers` first to confirm the provider is lit.

## When to use OpenRouter

OpenRouter is useful when you want to select a model family that is not
available through a direct provider credential. It is not required for Z.ai
GLM, Alibaba Qwen, Moonshot Kimi, Anthropic, OpenAI, Azure, or DeepSeek.

## Azure OpenAI configuration

Azure OpenAI is stricter than the other providers. The API key alone is not enough. 0sec needs:

- an Azure base URL
- an Azure deployment/model name

You can provide those explicitly via env vars, or let 0sec reuse them from `~/.codex/config.toml` when Codex is already configured against Azure.

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

If you rely on Codex config instead of env vars, make sure `~/.codex/config.toml` points at Azure and contains a usable Azure base URL plus model/deployment. If the selected Azure runtime is incomplete, 0sec stops immediately with a configuration error instead of silently falling through to a broken scan.

## Alternative: CLI runtimes

If you prefer not to use API keys at all, you can use CLI runtimes for supported workflows. Claude can run live target scans through its native subscription loop. Codex and Gemini are source-review oriented CLI runtimes:

```bash
# Use Claude Code CLI for an authorized live target
0sec scan --target https://api.example.com/chat --scope ./scope.json --runtime claude
# Use Codex CLI for source review
0sec review ./my-repo --runtime codex

# Use Gemini CLI
0sec review ./my-repo --runtime gemini
```

No API key environment variable is needed for source-review CLI runtimes because authentication is handled by the respective CLI tool. Codex live target scans use the direct ChatGPT Codex provider, so they require `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN` rather than the Codex CLI wrapper.

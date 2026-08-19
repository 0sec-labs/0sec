---
title: Getting Started
description: Install 0sec, set up your API key, and run your first scan.
---

0sec is a general-purpose autonomous pentesting framework. It scans AI/LLM apps, web applications, REST/OpenAPI APIs, package ecosystems, and source code using an agentic pipeline that discovers, attacks, verifies, and reports — with blind verification to kill false positives.

## Installation

0sec is open-source software for authorized security research. Build it from
source or run the public GHCR image. npm and standalone-binary releases are not
published yet.

### Source

```bash
git clone https://github.com/0sec-labs/0sec.git
cd 0sec
corepack enable
pnpm install --frozen-lockfile
pnpm build
node dist/0sec.js --help
```

### Docker

```bash
docker run --rm ghcr.io/0sec-labs/0sec:latest --help
```

## Set up an API key

0sec needs an LLM provider to power its agentic pipeline. Set one of these environment variables:

```bash
# Set a matching provider key, then select its model with --model.

# Z.ai GLM
export Z_AI_API_KEY="..."

# Alibaba Qwen
export QWEN_API_KEY="..."

# ChatGPT/Codex subscription auth
export 0SEC_CHATGPT_OAUTH_REFRESH_TOKEN="..."

# Direct providers or OpenRouter
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export OPENROUTER_API_KEY="sk-or-..."
```

0sec routes an explicit `--model` or `0SEC_MODEL` to its matching configured
provider. `glm-5.3` uses Z.ai. `qwen3.8-max` uses Alibaba Model Studio. Pin a
model whenever multiple provider credentials are present.

For ChatGPT Codex, run `codex login` and copy the refresh token from
`~/.codex/auth.json` into `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN`. For Azure,
0sec needs both a base URL and a deployment/model name in addition to the
key. You can set `AZURE_OPENAI_BASE_URL`, `AZURE_OPENAI_MODEL`, and
`AZURE_OPENAI_WIRE_API` explicitly, or let 0sec reuse a valid Azure-backed
`~/.codex/config.toml`. For the Responses API, the Azure base URL should include
`/openai/v1`. If the selected API runtime is incomplete, 0sec stops with a
configuration error instead of running a broken scan. If no provider credentials
are set, the `api` runtime will not work, but you can still use source-review
CLI runtimes such as `--runtime codex` or live scanning through `--runtime
claude` if those CLIs are installed and authenticated.

See [API Keys](/api-keys/) for full details on supported providers.

## Your first scan

Every live network target needs an engagement scope. The CLI refuses an
unscoped live target before making a request.

```bash
cat > scope.json <<'EOF'
{"in_scope":["your-app.com"]}
EOF
```

The connected examples below assume `./scope.json` allows their target. With
Docker, mount the file and pass its container path to `--scope`.

```bash
docker run --rm \
  -v "$PWD/scope.json:/work/scope.json:ro" \
  -e OPENROUTER_API_KEY \
  ghcr.io/0sec-labs/0sec:latest scan \
  --target https://your-app.com --scope /work/scope.json
```

### Scan an LLM API

```bash
0sec scan --target https://your-app.com/api/chat --scope ./scope.json
```

This discovers the attack surface, launches targeted attacks (prompt injection, jailbreaks, data exfiltration), verifies every finding, and generates a report — typically in under 5 minutes.

### Scan a web application

```bash
0sec scan --target https://your-app.com --mode web --scope ./scope.json
```

Runs autonomous pentesting against a web application using a shell-first approach. The agent gets `bash` as its primary tool and uses curl, python3, bash pipelines, and standard pentesting utilities to probe for CORS misconfigurations, exposed files, SSRF, XSS, SQL injection, SSTI, and other traditional web vulnerabilities. See [Architecture](/architecture/) for why shell-first beats structured tools.

### Audit a package ecosystem target

```bash
0sec audit lodash
0sec audit requests --ecosystem pypi
0sec audit serde --ecosystem cargo
0sec audit alpine:3.20 --ecosystem oci
```

Installs the target in a sandbox, runs ecosystem-specific prep plus static analysis, and performs an AI-powered code review.

### Review a codebase

```bash
# Local directory
0sec review ./my-app

# GitHub URL (clones automatically)
0sec review https://github.com/user/repo
```

### Auto-detect

You can skip the subcommand entirely. 0sec figures out what to do:

```bash
0sec-cli express                         # audits npm package
0sec-cli ./my-repo                       # reviews source code
0sec-cli https://github.com/user/repo    # clones and reviews
0sec scan --target https://your-app.com/api/chat --scope ./scope.json
0sec scan --target https://your-app.com --mode web --scope ./scope.json
```

## Scan depth

Control how thorough the scan is:

| Depth     | Test Cases | Time     |
|-----------|-----------|----------|
| `quick`   | ~15       | ~1 min   |
| `default` | ~50       | ~3 min   |
| `deep`    | ~150      | ~10 min  |

```bash
# Quick scan for CI
0sec scan --target https://api.example.com/chat --scope ./scope.json --depth quick

# Deep audit before launch
0sec scan --target https://api.example.com/chat --scope ./scope.json --depth deep
```

## Common scenarios

### Scan a REST API with an OpenAPI spec

Point 0sec at an OpenAPI 3.x or Swagger 2.0 document and it will pre-load every endpoint, parameter schema, and auth requirement before attacking — no crawl phase needed.

```bash
0sec scan \
  --target https://api.example.com \
  --scope ./scope.json \
  --api-spec ./openapi.yaml \
  --mode web
```

### Authenticated scanning (login-protected app)

Use `--auth` to pass credentials. Four types are supported: `bearer`, `cookie`, `basic`, and `header`.

```bash
# Bearer token (OAuth / JWT)
0sec scan --target https://app.example.com --scope ./scope.json \
  --auth '{"type":"bearer","token":"eyJhbGciOi..."}'

# Session cookie
0sec scan --target https://app.example.com --scope ./scope.json \
  --auth '{"type":"cookie","value":"session=abc123"}'

# Custom header (API key)
0sec scan --target https://api.example.com --scope ./scope.json \
  --auth '{"type":"header","name":"X-API-Key","value":"sk_live_..."}'

# Or load from a file to avoid leaking to shell history
0sec scan --target https://app.example.com --scope ./scope.json --auth ./auth.json
```

### Multi-model ensemble via OpenRouter

Set `OPENROUTER_API_KEY` and pass `--model` to mix models across runs. OpenRouter gives you access to Claude, GPT-4, Gemini, Llama, DeepSeek, and more with one key.

```bash
export OPENROUTER_API_KEY="sk-or-..."

# Use Claude Sonnet for hard targets
0sec scan --target https://example.com --mode web --scope ./scope.json \
  --model anthropic/claude-sonnet-4-5

# Cheap and fast for CI
0sec scan --target https://example.com --mode web --scope ./scope.json \
  --model deepseek/deepseek-chat --depth quick
```

### Best-of-N strategy racing

Spawn 5 attack agents in parallel and let the fastest one win. Great for hard targets where a linear attack plan gets stuck.

```bash
0sec scan --target https://example.com --mode web --scope ./scope.json --race
```

### Kali Docker executor

Enable `0SEC_FEATURE_DOCKER_EXECUTOR=1` to run every bash command inside a containerized pentest environment. By default, 0sec now pulls the prebuilt GHCR image `ghcr.io/0sec-labs/0sec:latest`, which already includes Node, Playwright/Chromium, and the standard pentest toolset. No host pollution, reproducible tool versions, and much faster startup than bootstrapping raw Kali on every run.

```bash
export 0SEC_FEATURE_DOCKER_EXECUTOR=1
0sec scan --target https://example.com --mode web --scope ./scope.json --verbose
```

Advanced overrides:

```bash
# Force a specific image
export 0SEC_DOCKER_IMAGE=ghcr.io/0sec-labs/0sec:latest

# Force apt-based tool bootstrap even on a custom image
export 0SEC_DOCKER_BOOTSTRAP_TOOLS=1
```

Use the raw Kali path only when you explicitly want to debug parity:

```bash
export 0SEC_FEATURE_DOCKER_EXECUTOR=1
export 0SEC_DOCKER_IMAGE=kalilinux/kali-rolling
export 0SEC_DOCKER_BOOTSTRAP_TOOLS=1
```

### Export findings to GitHub Issues

Push every confirmed finding to a GitHub repo as a labelled issue with evidence and reproduction steps. Requires a `GITHUB_TOKEN` with `repo` scope.

```bash
export GITHUB_TOKEN="ghp_..."
0sec scan --target https://example.com --mode web --scope ./scope.json \
  --export github:myorg/myrepo
```

### Generate an HTML, Markdown, or PDF report

```bash
# HTML (auto-opens in browser)
0sec scan --target https://example.com --mode web --scope ./scope.json \
  --depth deep \
  --format html

# Markdown (printed to stdout; pipe to a file)
0sec scan --target https://example.com --mode web --scope ./scope.json \
  --depth deep \
  --format md > example-pentest.md

# PDF (auto-opens in your default viewer and saves to a temp file)
0sec scan --target https://example.com --mode web --scope ./scope.json \
  --depth deep \
  --format pdf
```

## Next steps

- [Commands](/commands/) — full reference for every CLI command
- [Configuration](/configuration/) — runtime modes, feature flags, and options
- [Recipes](/recipes/) — real-world scan recipes for common scenarios
- [Architecture](/architecture/) — how the 4-stage pipeline works

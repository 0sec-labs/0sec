---
title: Troubleshooting
description: Common installation, runtime, configuration, and diagnostic issues with the 0sec CLI.
---

This guide covers real error scenarios encountered during installation,
configuration, scanning, and result handling. Cross-references point to detailed
reference pages for each area.

## Installation

### Binary download fails

The install script (`install.sh`) downloads from the latest GitHub Release.
Failures usually mean one of:

| Symptom | Likely cause |
|---------|-------------|
| `curl: (22) The requested URL returned error: 404` | Release asset not found for your platform/arch. Check supported combos below |
| `curl: (6) Could not resolve host` | No network access to `github.com` |
| `checksums.txt has no entry for ...` | Platform/arch not published for the latest release |
| `checksum mismatch` | Download corrupted; retry. If persistent, [contact 0sec Labs](https://0.security/contact) |
| `curl is required` | `curl` not installed. Install it (`apt install curl`, `brew install curl`) |

Supported release assets (from `.github/workflows/release.yml`):

| Asset | Platform |
|-------|----------|
| `0sec-linux-x64` | Linux x86_64 |
| `0sec-linux-arm64` | Linux ARM64 |
| `0sec-darwin-arm64` | macOS Apple Silicon |
| `0sec-windows-x64.exe` | Windows x86_64 (manual download — install.sh supports Linux/macOS only) |

### FoxGuard provisioning fails

`install.sh` auto-provisions the FoxGuard static analyzer binary. If it fails:

- `INSTALL_FOXGUARD=0` skips the provisioning — use this for pre-provisioned
  hosts or CI runners that don't need static analysis
- FoxGuard requires a working `curl` and write access to `~/.0sec/bin/`

```bash
# Install without FoxGuard
INSTALL_FOXGUARD=0 bash <(curl -fsSL https://raw.githubusercontent.com/0sec-labs/0sec/main/install.sh)
```

### `0sec` command not found after install

The binary is installed to `~/.0sec/bin/0sec` (and symlinked as `~/.0sec/bin/0`).
Add it to your `PATH`:

```bash
export PATH="$HOME/.0sec/bin:$PATH"
# or add the line above to ~/.bashrc / ~/.zshrc
```

If the install script detected `~/.0sec/bin` is not on `PATH`, it prints a
warning with the command to add it.

### Install on Windows

`install.sh` does not support Windows. Download the release asset manually from
the [releases page](https://github.com/0sec-labs/0sec/releases/latest):

```
0sec-windows-x64.exe
```

Replace your current binary in place. Auto-upgrade is tracked separately.

## Runtime

### `0sec doctor` reports Node.js version as bad

The CLI requires **Node.js 20+**. Node 24 is recommended and used in CI.

```bash
# Check your version
node --version

# Upgrade (example via nvm)
nvm install 24
```

If the bun-compiled binary is used (downloaded via `install.sh`), Node.js is
**not required** — the binary is self-contained and includes its own runtime.
The Node version check only applies when running from source
(`node packages/cli/dist/index.js`).

### No API runtime configured

`0sec doctor` reports `API runtime missing`:

```
API runtime   missing  not configured
```

Set one of the supported provider environment variables. See
[API Keys](/api-keys/) for the full list.

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
# or
export OPENAI_API_KEY="sk-..."
```

Then run `0sec doctor` again to confirm.

### API runtime configured but unusable

```
API runtime   bad  Azure OpenAI
```

The runtime detected environment variables for a provider, but the credentials
are incomplete or invalid. Common cases:

| Provider | Missing |
|----------|---------|
| Azure OpenAI | `AZURE_OPENAI_BASE_URL` or `AZURE_OPENAI_MODEL` not set. The base URL must include `/openai/v1` for the Responses API |
| ChatGPT Codex | Neither `0SEC_CHATGPT_ACCESS_TOKEN`, `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN`, nor `~/.codex/auth.json` was found. Run `codex login` first, or pass the env var directly: `env 0SEC_CHATGPT_OAUTH_REFRESH_TOKEN="..." 0sec scan ...` |

Azure OpenAI configuration requires all three variables:

```bash
export AZURE_OPENAI_API_KEY="..."
export AZURE_OPENAI_BASE_URL="https://your-resource.openai.azure.com/openai/v1"
export AZURE_OPENAI_MODEL="gpt-4o"
```

### `0sec doctor` shows no CLI runtimes found

CLI runtimes (`claude`, `codex`, `gemini`) are optional. The `api` runtime is
the default and works with any supported provider key. If you want a CLI runtime:

```bash
npm i -g @anthropic-ai/claude-code   # Claude Code CLI
npm i -g @openai/codex               # Codex CLI
npm i -g @google/gemini-cli          # Gemini CLI
```

Then verify:

```bash
0sec doctor
# CLI runtimes  found  claude codex gemini
```

### Agent loop error during a scan

If the agent loop encounters an unrecoverable error:

```
[0sec] Agent loop error: ...
```

Common causes:

- **Model unavailable** — the configured provider is rate-limited, over quota,
  or the model doesn't exist. Check `0SEC_MODEL` or `--model` and see
  [Configuration](/configuration/) for available models
- **Network error** — the provider API is unreachable. Check network connectivity
  and proxy settings
- **Timeout** — the scan ran longer than `--timeout`. Increase the timeout or
  reduce scan depth with `--depth quick`

See [Budget Management](/budget-management/) for cost and timeout controls.

### Scan fails with exit code 2

Exit code 2 from scan-related commands indicates bad configuration:

- A typo'd `--engagement-profile` name
- An invalid `0SEC_ENGAGEMENT_RATE_RPS` value
- A malformed scope file `engagement` block

The error message printed to stderr identifies the exact issue. Fix it and
re-run — the scan never starts on a bad posture config.

### Scope rejection

When a target is out of scope:

```
--target https://example.com is out of scope per ./scope.json: ...
```

This means the target URL doesn't match any `in_scope` entry in your scope JSON
file, or matches a `out_of_scope` deny rule (deny takes precedence). See
[Scope & Authorization](/scope/) for scope syntax.

### Cloud auth failure

```bash
0sec auth status
# FAIL (HTTP 401)
```

| Exit | Meaning |
|------|---------|
| `2` | Auth failure (401/403 or missing credentials) |
| `3` | Network error (host unreachable, DNS failure) |
| `1` | Other error |

Run `0sec auth login` to re-authenticate, or use `--token` for the manual path:

```bash
0sec auth login --host https://control-plane.example.com --token "your-token"
```

## Provider issues

### Multiple providers configured — which one is used?

0sec picks the first available provider from the configured variables. To pin a
specific model, use `--model <id>` or `0SEC_MODEL`. Model routing recognizes:

| Prefix | Provider |
|--------|----------|
| `claude-*` / `anthropic/*` | Anthropic |
| `gpt-*` / `o*` | ChatGPT Codex subscription (if configured), then OpenAI |
| `glm-*` / `z-ai/*` | Z.ai |
| `qwen*` | Alibaba Qwen |
| `grok*` / `xai/*` | xAI Grok |
| `opencode/*` | OpenCode Zen (preserves upstream protocol) |
| Other | Detected from credential presence |

If no explicit model is set, 0sec picks an available fallback. Pin a model
rather than relying on ambient credential order.

### `0SEC_*` env vars with leading digit

Variables like `0SEC_CHATGPT_ACCESS_TOKEN` start with a digit. Most shells
reject `export 0SEC_*=...`. Use `env` or a subshell:

```bash
# Correct
env 0SEC_CHATGPT_OAUTH_REFRESH_TOKEN="..." 0sec review .

# Incorrect (bash syntax error)
export 0SEC_CHATGPT_OAUTH_REFRESH_TOKEN="..."
```

### ChatGPT Codex auth file path

By default, the Codex runtime reads tokens from `~/.codex/auth.json`. Override:

```bash
env 0SEC_CHATGPT_AUTH_FILE="/path/to/auth.json" 0sec scan ...
```

`0SEC_CODEX_AUTH_JSON_PATH` is a deprecated spelling — prefer
`0SEC_CHATGPT_AUTH_FILE`.

### OpenRouter routing

OpenRouter acts as a fallback when direct provider credentials are absent for a
given model family. If you intend to use OpenRouter exclusively, set only
`OPENROUTER_API_KEY` and no other provider keys.

## Scan and review

### Deep review produces no findings

A review with no findings may mean:

- **Trivially clean code** — no vulnerability patterns matched
- **Provider could not analyze** — the configured model may lack the capability.
  Try a different model or runtime (`--runtime claude`, `--model claude-sonnet-4`)
- **Scope too narrow** — `--changed-only --diff-base <sha>` limits the review to
  diff lines. Remove `--changed-only` for a full review
- **Budget exhausted** — `--cost-ceiling` hit before analysis completed. Increase
  the ceiling or remove it

### Scan times out

The default timeout is 5 minutes (300000ms). Increase with `--timeout`:

```bash
0sec scan --target https://example.com --scope ./scope.json --timeout 600000
```

For the MCP server, the default per-tool timeout is 30 seconds:

```bash
0sec mcp-server --target https://example.com --scan-id s1 --timeout 60000
```

Deep scans on complex targets can take 10-30 minutes. Use `--depth quick` for
faster results.

### `spawnSync rg ENOENT` warnings

The audit/scan agent's source-tree discovery loop defaults to `ripgrep` for fast
searches. When `rg` is not on `PATH`, the agent falls back to slower `find` +
per-file reads. Install ripgrep:

```bash
# Ubuntu/Debian
sudo apt install ripgrep

# macOS
brew install ripgrep
```

The [Docker image](/integrations/#docker-image) includes ripgrep pre-installed.

### Results format not supported

`--format` accepts `json` (default), `sarif`, `html`, `pdf`, `markdown`,
`terminal`, `timeline`, or `replay`. If you pass an unsupported format, the CLI
prints the valid options.

```bash
0sec scan --target http://127.0.0.1:8080 --scope ./scope.json --format pdf
```

PDF reports require pdfkit (bundled in the CLI dependencies).

### Report contains warnings section

The report JSON and SARIF may include a `warnings` array. Warnings indicate
non-fatal issues:

- Provider returned partial responses
- Some scan modes were unavailable for the target type
- Scope rules excluded certain endpoints

Warnings appear in the GitHub Actions output summary when using the action
wrapper.

## Docker

### Container exits immediately

The image entrypoint is `0sec --help` by default. Pass a command:

```bash
docker run --rm ghcr.io/0sec-labs/0sec:latest review .
```

### Permission errors on mounted volumes

The container runs as the `ubuntu` user (uid 1000). When mounting source code:

```bash
# If your files are owned by uid 1000, they work directly:
docker run --rm -v "$PWD:/work" ghcr.io/0sec-labs/0sec:latest review .

# Otherwise, ensure world-readable permissions:
chmod -R o+r /path/to/source
```

### AD tools not found despite being in the image

The AD tools (impacket, certipy, bloodhound-ce) are installed in a Python venv
at `/opt/ad-tools`. Their console scripts are symlinked to `/usr/local/bin/`:

```bash
# Verify they're available
docker run --rm --entrypoint bash ghcr.io/0sec-labs/0sec:latest -c 'which secretsdump.py'
```

The system Python interpreter (`python3`) is deliberately NOT the venv one, so
the agent's helper scripts can import the apt-managed `requests` and `bs4`.

## Database and state

### SQLite database locked

Multiple concurrent scans writing to the same database file can produce
`SQLITE_BUSY` errors. Each scan/review/console session should have its own
database, or use `--db-path` to point to an exclusive path:

```bash
0sec scan --target https://example.com --scope ./scope.json --db-path ./scans/scan-001.db
```

### Resume scan not found

`0sec resume` looks up a previous scan by ID or by the database path. Ensure
the database from the original scan is still available and pass `--db-path`:

```bash
0sec resume --db-path ./scans/scan-001.db
```

The scan ID is printed at the start of the original run.

## TUI / Console

### Console doesn't start

The interactive console requires a TUI-capable terminal and OpenTUI support.

```bash
# Verify prerequisites
0sec doctor
```

If running from source, ensure `@opentui/core` and `@opentui/react` are
installed (they are bundled in the CLI package). The bun-compiled binary
includes everything.

### `/providers` command shows no options

The console's `/providers` (or `/connect`) command lists available LLM providers.
If none appear:

- No provider credentials are configured. See [API Keys](/api-keys/)
- The console cannot detect `~/.codex/auth.json`. Point to it explicitly via
  env var or run `codex login` first

### Finding chat intent does nothing

The `--finding-intent` flag accepts one of three values:

| Intent | Behavior |
|--------|----------|
| `investigate` (default) | Assess evidence, no source file modifications |
| `verify` | Independent impact assessment, minimum reproduction |
| `draft_fix` | Source root cause → patch + regression test (never applies) |

Invalid values produce:

```
Invalid --finding-intent '...'; expected one of investigate, verify, draft_fix.
```

## Known gaps

These are not bugs but documented limitations:

| Gap | Details |
|-----|---------|
| **No composite GitHub Action** | The planned `.github/actions/0sec-scan` composite action has not shipped. Use the container image or binary install instead |
| **Plugin registry empty** | The default plugin registry endpoint has no published plugins. The plugin system is scaffolded but no marketplace ships yet |
| **Windows upgrade** | `0sec upgrade` does not support Windows. Download release assets manually |
| **MCP transport** | The MCP server uses stdio transport only. SSE/WebSocket transport is not implemented |
| **Cloud auth browser flow** | The browser-based login flow depends on the server-side session-mint endpoint. The `--token` escape hatch works independently |

## Diagnostic quick reference

| Command | What it checks |
|---------|----------------|
| `0sec doctor` | Node version, API runtime, CLI runtimes |
| `0sec auth status` | Cloud credential validity against `/health` |
| `0sec h1 auth` | HackerOne API credential validity |
| `0sec --version` / `0 --version` | CLI version |
| `0sec config show` | Effective layered configuration (global + project) |
| `0sec scan --target <url> --dry-run` | Validate scope, credentials, and config without executing |

## See also

- [Configuration](/configuration/) — runtime modes, scan modes, depth settings
- [API Keys](/api-keys/) — supported providers and setup
- [Console](/console/) — interactive chat cockpit
- [Scan Workflows](/scan-workflows/) — available scan modes and strategies
- [Scope & Authorization](/scope/) — scope JSON files and target format
- [Budget Management](/budget-management/) — cost ceilings, rate limiting
- [Triage](/triage/) — finding classification and prioritization
- [Verification Results](/verification-result/) — deterministic replay contract
- [Commands](/commands/) — full CLI command reference
- [Integrations](/integrations/) — MCP server, GitHub CI, Docker, HackerOne
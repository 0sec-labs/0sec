---
title: GitHub CI — run 0sec in CI
description: Run 0sec scans, reviews, and audits as GitHub Actions steps via the container image or binary install.
---

0sec runs in GitHub Actions today through the published container image or a
binary install step. A dedicated composite action is planned (tracked via the
schema file at `packages/cli/src/__tests__/github-action-schema.test.ts`) but
has not shipped yet — there is no `.github/actions/` directory in the
repository.

For now, invoke the CLI directly from a workflow step. Provider credentials go
in as `env:` from repository secrets.

## Container-based workflow

The `ghcr.io/0sec-labs/0sec` image includes Node 24, FoxGuard, pentest tools
(nmap, sqlmap, ffuf, hydra, etc.), and AD/cloud-identity tooling.

```yaml
# .github/workflows/0sec.yml
name: 0sec
on:
  pull_request:
    types: [opened, synchronize, reopened]
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write    # for SARIF upload

jobs:
  review:
    runs-on: ubuntu-latest
    container: ghcr.io/0sec-labs/0sec:latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0    # needed for diff-aware review
      - name: Review changed code
        run: |
          0sec review . \
            --diff-base "${{ github.event.pull_request.base.sha || github.event.before }}" \
            --changed-only \
            --format sarif > results.sarif
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      - name: Upload SARIF to code scanning
        if: always() && hashFiles('results.sarif') != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: results.sarif
```

> **Note:** The container runs as the `ubuntu` user (uid 1000), not root. When
> mounting workspace volumes, ensure the `ubuntu` user can read them.

### CI-friendly flags

| Flag | Purpose |
|------|---------|
| `--diff-base <sha>` | Base commit for diff-scoped review |
| `--changed-only` | Only review modified files |
| `--format sarif` | Output SARIF for GitHub Code Scanning |
| `--format json` | Machine-readable JSON for custom post-processing |
| `--depth quick` | Faster review for CI (shorter agent budget) |
| `--cost-ceiling <usd>` | Hard USD cost ceiling per run |
| `--timeout <ms>` | Per-tool timeout in milliseconds |

### SARIF upload

The SARIF output from `--format sarif` is compatible with the
`github/codeql-action/upload-sarif@v4` action. Upload findings to the
**Security > Code scanning** tab.

## Binary-based workflow

For smaller jobs or when the full container is unnecessary, install the binary
and FoxGuard in the step:

```yaml
- name: Install 0sec
  run: |
    curl -fsSL https://raw.githubusercontent.com/0sec-labs/0sec/main/install.sh | bash
    echo "$HOME/.0sec/bin" >> "$GITHUB_PATH"

- name: Run review
  run: 0sec review . --format sarif > results.sarif
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

## Source-build workflow

If you need the latest unreleased changes:

```yaml
- uses: actions/setup-node@v5
  with:
    node-version: 24
- run: corepack enable && pnpm install --frozen-lockfile && pnpm build
- run: node packages/cli/dist/index.js review . --format sarif > results.sarif
```

**Note:** The source build requires 500+ MB of dependencies and takes 5-10
minutes in CI. Prefer the container image or binary install for faster runs.

## Scripted action wrapper

The repository ships `scripts/run-github-action.sh`, a bash wrapper that reads
standard GitHub Actions `INPUT_*` environment variables and produces both a JSON
report and a SARIF report. It is used internally for dogfood workflows.

The wrapper supports three modes:

| Mode | Required input | Description |
|------|----------------|-------------|
| `review` | `path` | Source code review |
| `audit` | `package` | Package audit (npm, PyPI, Cargo, OCI) |
| `scan` | `target` | Live target scan with `--mode` |

### Wrapper inputs

| Input | Default | Values |
|-------|---------|--------|
| `mode` | `review` | `review`, `audit`, `scan` |
| `path` | `.` | Path for review mode |
| `package` | — | Package name for audit mode |
| `target` | — | Target URL for scan mode |
| `scan-mode` | `probe` | `probe`, `deep`, `mcp`, `web` |
| `depth` | `default` | `quick`, `default`, `deep` |
| `runtime` | `api` | `api`, `claude`, `codex`, `gemini`, `auto` |
| `timeout` | `300000` | Tool timeout in ms |
| `format` | `json` | `json`, `sarif` |
| `severity-threshold` | `high` | `critical`, `high`, `medium`, `low`, `info`, `none` |
| `threshold` | `0` | Fail count when findings at or above severity |
| `report-dir` | `0sec-report` | Output directory |

The wrapper calls `scripts/render-github-action-output.mjs` to convert the JSON
report into GitHub Actions outputs (SARIF, job summary, output variables).

## Provider credentials

Set one of these as a repository secret and pass it as `env:` on the step:

| Provider | Secret example |
|----------|----------------|
| Anthropic | `ANTHROPIC_API_KEY` |
| OpenAI | `OPENAI_API_KEY` |
| OpenRouter | `OPENROUTER_API_KEY` |
| Azure OpenAI | `AZURE_OPENAI_API_KEY` + `AZURE_OPENAI_BASE_URL` + `AZURE_OPENAI_MODEL` |
| Z.ai | `Z_AI_API_KEY` |
| DeepSeek | `DEEPSEEK_API_KEY` |
| ChatGPT Codex | `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN` |

See [API Keys](/api-keys/) for the full list and fallback order.

## Example: full diff-aware PR review

```yaml
name: 0sec PR review
on:
  pull_request:
    types: [opened, synchronize]

permissions:
  contents: read
  security-events: write

jobs:
  security:
    runs-on: ubuntu-latest
    container: ghcr.io/0sec-labs/0sec:latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
      - name: 0sec review
        run: |
          0sec review . \
            --diff-base "${{ github.event.pull_request.base.sha }}" \
            --changed-only \
            --depth quick \
            --cost-ceiling 5 \
            --format sarif \
            > results.sarif
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: results.sarif
      - name: Upload artifact
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: 0sec-results
          path: results.sarif
          retention-days: 14
```

## Example: npm package audit

```yaml
- name: Audit dependencies
  run: |
    0sec audit lodash \
      --ecosystem npm \
      --depth quick \
      --format sarif \
      > audit-results.sarif
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: audit-results.sarif
```

## Example: live target scan

```yaml
- name: Scan staging environment
  run: |
    0sec scan --target https://staging.example.com \
      --mode deep \
      --format sarif \
      --timeout 600000 \
      > scan-results.sarif
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

## This repository's dogfood lane

0sec runs a diff-aware self-review against its own trusted `main` delta in
`.github/workflows/dogfood-review.yml`. The workflow starts only after
`0sec: Main` succeeds on `main`; it never runs model-backed review against PR
code or a fork.

The dogfood lane:

1. Downloads a **pinned, checksum-verified** release binary (v0.15.0 at time of
   writing) instead of mutable `releases/latest` assets
2. Reviews `HEAD^..HEAD` with `--changed-only --format sarif`
3. Uploads the SARIF to GitHub Code Scanning
4. Keeps a 14-day evidence artifact (`dogfood-review.sarif` + stderr log)

Set the repository secret `DOGFOOD_OPENAI_API_KEY` before enabling the lane.
It uses direct OpenAI `gpt-5.6-luna` through the Responses API, with a hard
`$2` per-run review ceiling.

```yaml
# Excerpt from dogfood-review.yml
- name: Review the merged delta with 0sec
  run: |
    base="$(git rev-parse HEAD^)"
    "$REVIEWER" review . \
      --cost-ceiling "$DOGFOOD_COST_CEILING_USD" \
      --diff-base "$base" \
      --changed-only \
      --depth quick \
      --runtime api \
      --model "$DOGFOOD_MODEL" \
      --format sarif \
      > dogfood-review.sarif
```

## Security considerations

| Concern | Mitigation |
|---------|------------|
| **Provider key leakage** | Store as repository secret; pass via `env:` |
| **Model cost in CI** | Use `--cost-ceiling` to cap spend |
| **Fork PR execution** | 0sec does not run on fork PRs — see `public-pr.yml` policy |
| **Container privileges** | Image drops to `ubuntu` user; no root in workflow execution |
| **SARIF exposure** | Code scanning results are visible per repo permissions |

## Known limitations

- The dedicated composite action (`0sec-labs/0sec/.github/actions/0sec-scan`)
  has **not shipped** — there is no `.github/actions/` directory
- The planned action design includes inputs `mode`, `profile`, `comment-on-pr`,
  `fail-on-confirmed`, `0sec-version`, `github-token`, and `working-directory`
- The binary install (`install.sh`) is ~145 MB; download time varies by runner
- Live target scans from CI require the target to be reachable from the runner
- Some runtimes (`claude`, `codex`, `gemini`) require CLI subprocess
  installation on the runner — the `api` runtime is preferred for CI

## See also

- [Scan Workflows](/scan-workflows/) — available scan modes and strategies
- [Integrations](/integrations/) — MCP server, HackerOne, report formats, Docker
- [Configuration](/configuration/) — runtime modes, depth, env vars
- [API Keys](/api-keys/) — provider setup and fallback order
- [Budget Management](/budget-management/) — cost ceilings and rate limiting
- [Scope & Authorization](/scope/) — scope JSON files for CI workflows
- [Commands](/commands/) — full CLI reference
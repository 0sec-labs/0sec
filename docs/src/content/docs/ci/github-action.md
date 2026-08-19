---
title: GitHub Action — PR scans
description: Diff-scoped agentic security scanning for pull requests with the pwnkit composite action.
---

The `pwnkit-scan` composite action runs a diff-scoped security review on every
PR. Confirmed findings are posted as inline review comments anchored to the
changed lines; unconfirmed hypotheses are rolled up into a single summary
comment so the PR isn't spammed.

## Quick start

```yaml
# .github/workflows/pwnkit.yml
name: pwnkit
on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write

jobs:
  pwnkit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
      - uses: 0sec-labs/0sec/.github/actions/pwnkit-scan@v1
        with:
          mode: pr
          profile: web
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

That's it. Open a PR; the action will scan the changed files and comment.

## Inputs

| Name | Default | Description |
|------|---------|-------------|
| `mode` | `pr` | `pr` scopes the scan to changed files via `git diff base...HEAD`; `full` scans the whole working tree. |
| `profile` | `web` | Review profile: `web`, `linux-kernel`, or `c-cpp`. |
| `comment-on-pr` | `true` | Post confirmed findings as inline review comments and hypotheses as a rolled-up summary. |
| `fail-on-confirmed` | `true` | Exit non-zero (failing the job) when one or more confirmed findings are produced. |
| `pwnkit-version` | `latest` | `pwnkit-cli` version installed via `npm install --global`. Pin for reproducible runs. |
| `github-token` | `${{ github.token }}` | Token used for comment posting. |
| `working-directory` | `${{ github.workspace }}` | Repository root to scan. |

## Outputs

| Name | Description |
|------|-------------|
| `findings-confirmed` | Count of confirmed findings. |
| `findings-hypothesis` | Count of hypothesis-only findings. |
| `results-file` | Absolute path to `pwnkit-results.json`. Also uploaded as an artifact named `pwnkit-results`. |

## How diff-scoping works

In `mode: pr` the action computes the diff against the PR base SHA:

```bash
git diff --name-only --diff-filter=ACMRTUXB "$BASE_SHA"...HEAD
```

The PR base commit must be in the local object database. **Set
`fetch-depth: 0` on your checkout step** to make the whole git graph available.
If the base SHA isn't present, the action attempts a defensive
`git fetch --depth=1 origin <BASE>` before computing the diff. If that fails
too, it falls back to `HEAD~1..HEAD` and emits a warning; if no diff can be
computed at all, the action degrades to `mode: full`.

`mode: full` skips the diff step and scans the entire working tree.

## Gating merges

Set `fail-on-confirmed: true` (the default) to block merges when pwnkit
reports a confirmed finding:

```yaml
- uses: 0sec-labs/0sec/.github/actions/pwnkit-scan@v1
  with:
    mode: pr
    fail-on-confirmed: true
```

Hypothesis-only findings never fail the job; they only inform reviewers.

## Provider credentials

`pwnkit-cli` runs against an LLM provider. Wire one of the supported providers
via repository secrets and pass them through as `env:` on the action step:

- `ANTHROPIC_API_KEY`
- `OPENAI_API_KEY`
- `OPENROUTER_API_KEY`
- `AZURE_OPENAI_API_KEY` + `AZURE_OPENAI_BASE_URL` + `AZURE_OPENAI_MODEL`

See [API Keys](/api-keys/) for the full matrix.

## Profiles

| Profile | Use when |
|---------|----------|
| `web` (default) | TypeScript/JavaScript, Python, Go, Ruby web apps. Maps to the CLI `default` review profile. |
| `c-cpp` | C/C++ memory-safety review. Maps to the CLI `c-library` profile (tier-1/2/3 harness). |
| `linux-kernel` | Linux kernel sources. Maps to the CLI `linux-kernel` profile. |

## Pinning versions

For reproducible scans pin the `pwnkit-cli` version:

```yaml
- uses: 0sec-labs/0sec/.github/actions/pwnkit-scan@v1
  with:
    pwnkit-version: "0.7.0"
```

## Outputs in downstream steps

```yaml
- id: pwnkit
  uses: 0sec-labs/0sec/.github/actions/pwnkit-scan@v1
  with:
    mode: pr
    fail-on-confirmed: false
- run: echo "Found ${{ steps.pwnkit.outputs.findings-confirmed }} confirmed, ${{ steps.pwnkit.outputs.findings-hypothesis }} hypothesis"
```

## Self-hosted runners

The action only requires Node.js (auto-installed via `actions/setup-node`),
`git`, and `npm`. No Docker, no kernel modules — it's safe on locked-down
self-hosted runners.

## See also

- [White-Box Mode](/white-box-mode/) — what the source review actually does.
- [API Keys](/api-keys/) — provider configuration.
- The action source: [`.github/actions/pwnkit-scan/`](https://github.com/0sec-labs/0sec/tree/main/.github/actions/pwnkit-scan)

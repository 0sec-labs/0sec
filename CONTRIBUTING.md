# Development Guide

> **Internal use only.** This repository is proprietary software of 0sec Labs.

## Setup

```bash
git clone https://github.com/0sec-labs/pwnkit.git
cd pwnkit
pnpm install
pnpm build        # builds all packages in dependency order + bundles CLI
```

The CLI binary lands in `dist/pwnkit.js`. Test it with:

```bash
node dist/pwnkit.js --version
node dist/pwnkit.js doctor
```

## Running Tests

```bash
# Start test targets
pnpm vulnerable &
pnpm safe &

# Run tests
pnpm --filter @pwnkit/test-targets test
```

## Adding Attack Templates

Templates live in `packages/templates/attacks/`. Create a new YAML file:

```yaml
id: your-template-id
name: Your Template Name
category: prompt-injection
severity: high
description: What this tests for
owaspLlmTop10: "LLM01"
depth: [quick, default, deep]
payloads:
  - id: payload-01
    prompt: "Your attack prompt here"
    description: Short description of this payload
```

## Submitting Changes

1. Create a branch (`git checkout -b feat/my-feature`)
2. Commit your changes
3. Push and open a PR

All PRs need to pass CI checks before merging.

# Contributing to pwnkit

Thanks for helping improve pwnkit.

## Before you start

- Work from a branch and keep each pull request focused.
- Use only synthetic fixtures or targets you own or are explicitly authorized to
  test.
- Do not submit customer data, credentials, raw target traces, embargoed
  vulnerabilities, or undisclosed exploit material.
- Discuss broad changes in an issue before writing a large patch.

## Setup

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm build
```

The bundled CLI is `dist/pwnkit.js`:

```bash
node dist/pwnkit.js --version
node dist/pwnkit.js doctor
```

## Checks

Run the checks that cover your change before opening a pull request:

```bash
pnpm lint
pnpm build
pnpm test
```

For test-target work, start the local fixtures in separate terminals:

```bash
pnpm vulnerable
pnpm safe
pnpm --filter @pwnkit/test-targets test
```

## Attack templates

Templates live in `packages/templates/attacks/`. Add only authorized,
non-sensitive examples. A template needs a stable id, category, severity,
description, and payload metadata.

## Pull requests

Describe the behavior changed, the tests run, and any scope or safety impact.
By submitting a contribution, you agree that it is licensed under Apache-2.0.

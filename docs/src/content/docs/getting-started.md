---
title: CLI Getting Started
description: Install 0sec, configure a provider, define scope, and run your first authorized CLI scan.
---

Install 0sec, configure a model provider, define an authorized target, and run
your first scan. No cloud account is required. For a managed engagement instead,
use the [Cloud guide](/cloud/).

## Install

Install the verified release binary with one command, build from source, or run
the container image.

### Release binary

The installer supports Linux x64/arm64 and macOS Apple Silicon. It requires
`curl` and `sha256sum` or `shasum`, verifies the downloaded checksums, and installs
`0sec` plus the `0` alias under `~/.0sec/bin`. It also installs the pinned
FoxGuard companion used by default for static analysis.

```bash
# Verified release binary (macOS Apple Silicon / Linux x64/arm64)
curl -fsSL https://raw.githubusercontent.com/0sec-labs/0sec/main/install.sh | bash
export PATH="$HOME/.0sec/bin:$PATH"
0sec --help          # or just: 0 --help
```

Add the `export` line to your shell profile for future shells. Inspect
[install.sh](https://github.com/0sec-labs/0sec/blob/main/install.sh) before running
it if your environment requires script review. `INSTALL_DIR` changes the install
location; `INSTALL_FOXGUARD=0` skips the companion on a pre-provisioned host.

### Build from source

Use Node.js 24 or newer and pnpm 9 or newer. The repository pins pnpm through
`packageManager`. The full terminal UI needs Bun; Node can run non-interactive
commands. See [Console](/console/) for that runtime distinction.

```bash
git clone https://github.com/0sec-labs/0sec.git
cd 0sec
corepack enable
pnpm install --frozen-lockfile
pnpm build
node packages/cli/dist/index.js --help
```

### Container

Docker must be installed and running. The image is a separate execution
environment; pass only the credentials and mounts needed for the task.

```bash
docker run --rm ghcr.io/0sec-labs/0sec:latest --help
```
For a real scan, mount scope and persist any output you need before using
`--rm`; files left only inside the container disappear when it exits.


## Configure a provider

Choose **one** provider to start with. For example:

```bash
export ANTHROPIC_API_KEY="your-api-key"
```

Or configure another supported provider in [API Keys](/api-keys/), including
ChatGPT Codex subscription authentication and Azure. Model credentials are
different from target credentials passed with `--auth`, and from `0sec auth`
managed-service authentication.

When multiple credentials are present, select a matching model explicitly with
`--model` or `0SEC_MODEL`. See [Configuration](/configuration/) for runtime and
provider resolution. Never commit credentials or paste real keys into an issue.

## Run your first scan

Every live network target needs a scope file. The CLI refuses an unscoped live
target before it makes a request.

See [Scope & Authorization](/scope/) for exact host, wildcard, CIDR, and exclusion
matching. Scope is a target boundary, not a network sandbox.

```bash
printf '%s\n' '{"in_scope":["app.example.com"]}' > scope.json

0sec scan --target https://app.example.com --mode web \
  --scope ./scope.json --runtime api --depth quick --cost-ceiling 2
```

Replace `app.example.com` in **both** places with a target you own or have explicit
permission to test. Scope is not permission by itself. This run requests a quick
web assessment with a USD 2 ceiling; that is a limit, not an estimated price.
Model/tool availability and target access determine how far it can get.

The CLI reports progress and findings. Review any failures or incomplete
coverage before interpreting an empty result. [Scan Workflows](/scan-workflows/)
covers saved runs, outputs, resuming, and verification.

With Docker, mount the scope file and pass its container path:

```bash
docker run --rm -v "$PWD/scope.json:/work/scope.json:ro" -e ANTHROPIC_API_KEY \
  ghcr.io/0sec-labs/0sec:latest scan \
  --target https://app.example.com --mode web --scope /work/scope.json \
  --runtime api --depth quick --cost-ceiling 2
```

## Common scan tasks

### Web app pentest

Shell-first: the agent gets `bash` and standard tooling to probe for CORS, SSRF,
XSS, SQLi, SSTI, exposed files, and more.

```bash
0sec scan --target https://app.example.com --mode web --scope ./scope.json
```

### Audit a package

Retrieves package material for static and AI review. Package ecosystems have
different acquisition requirements; see [Scan Workflows](/scan-workflows/).
Treat downloaded code as untrusted and use a disposable environment.

```bash
0sec audit lodash
0sec audit requests --ecosystem pypi
0sec audit alpine:3.20 --ecosystem oci
```

### Review a codebase

```bash
0sec review ./my-app                       # local directory
0sec review https://github.com/user/repo   # clones automatically
```

### Control scan depth

| Depth | Use |
| --- | --- |
| `quick` | A smaller initial investigation to check setup and access. |
| `default` | The normal investigation budget. |
| `deep` | More investigation budget for a deliberate deeper run. |

Depth is not a fixed test count or wall-clock duration. Template limits and agent
turn budgets differ by execution path; see [Budget Management](/budget-management/).

```bash
0sec scan --target https://app.example.com --mode web --scope ./scope.json --depth deep
```

## No sandbox by default

The default shell executor runs commands **on your host**. Scope checks,
timeouts, and tool restrictions are not OS isolation. Use a disposable
environment for untrusted targets and source.

The optional Docker executor and replay verifiers have their own isolation
boundaries; enabling one does not sandbox every CLI operation. See
[Configuration](/configuration/) and [Scan Workflows](/scan-workflows/).

## Next steps

**Continue working**
- [Console](/console/) — interactive chat, approvals, sessions, and keyboard controls
- [Desktop](/desktop/) — local desktop interface and build prerequisites
- [Scan Workflows](/scan-workflows/) — investigation through evidence review
- [Troubleshooting](/troubleshooting/) — diagnose setup, scope, runtime, and execution failures

**Reference**
- [Commands](/commands/) — full CLI reference
- [Configuration](/configuration/) — runtimes, modes, feature flags
- [Recipes](/recipes/) — copy-paste scans for common scenarios
- [Architecture](/architecture/) — how the pipeline works

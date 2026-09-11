---
title: CLI Getting Started
description: Install 0sec, configure a provider, define scope, and run your first authorized CLI scan.
---

0sec is a **Research Preview**. Install it, configure a model provider, define
an authorized target, and run your first scan. Bring-your-own-key (BYOK) use
doesn't require a cloud account.

Hosted models are a separate, unreleased onboarding path. Installing the CLI
or signing in doesn't establish a funded inference balance. See the
[draft hosted setup](#hosted-models-draft) before trying that path.

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

### Hosted models (draft)

> Status: 2026-09-11. Candidate implementation, not a production launch.
> These commands require the hosted-inference CLI candidate and an explicitly
> approved test service. They aren't a promise that the installed release or
> default cloud host supports hosted inference.

The intended experience is one 0sec account, organization-funded model usage,
and no upstream provider key on your machine. Local tools still run locally.
Inference credit doesn't include cloud compute, managed testing, or review
credits. Retail prices, included allowances and subscription terms aren't
established by this preview.

For an approved test deployment:

1. Set `HOSTED_TEST_HOST` to the service URL supplied by its operator.
   Run the login command below, sign in or create an account in the browser,
   select the organization, and explicitly authorize the CLI.
2. Inspect the catalog and balance. Login grants a scoped credential, not
   credit. An owner or admin manages hosted-model purchases in the dashboard's
   **Billing** section. Sandbox checkout creation has been exercised;
   completed payment and the resulting funded first request remain unqualified.
3. Select an exact alias from `0sec models`. Pin `hosted` so an existing
   provider key or Codex login doesn't select BYOK instead.

```bash
0sec login --host "$HOSTED_TEST_HOST"
0sec models --json
0sec balance --json

env 0SEC_SELECTED_PROVIDER=hosted 0SEC_MODEL="<alias-from-0sec-models>" \
  0sec review ./authorized-repo --runtime api
```

Replace the alias and repository path before running. The last command uses
model credit on a funded service; the preceding catalog and balance commands
don't submit inference. An unfunded account returns HTTP 402 before an upstream
model call. A positive balance can still be below the required request reserve.

See [Hosted inference](/api-keys/#hosted-inference-draft) for streaming,
accounting and errors, and [Hosted configuration](/configuration/#hosted-configuration-draft)
for credential precedence. BYOK remains available independently.

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
- [Scan Workflows](/scan-workflows/) — investigation through evidence review
- [Troubleshooting](/troubleshooting/) — diagnose setup, scope, runtime, and execution failures

**Reference**
- [Commands](/commands/) — full CLI reference
- [Configuration](/configuration/) — runtimes, modes, feature flags
- [Recipes](/recipes/) — copy-paste scans for common scenarios
- [Architecture](/architecture/) — how the pipeline works

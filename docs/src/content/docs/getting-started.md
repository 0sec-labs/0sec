---
title: CLI Getting Started
description: Install 0sec, configure a provider, define scope, and run your first authorized CLI scan.
---

Install the 0sec Research Preview, connect a model, and scan an authorized target.
Choose [0sec Cloud](#hosted-models-draft) or [use your own API key](#use-my-own-api-key).

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

<a id="hosted-models-draft"></a>

### Hosted models

> Cloud inference isn't available in production yet. This setup requires the
> hosted-enabled CLI and an approved test service.

0sec Cloud will bring open cybersecurity models and 0sec-curated options to one
connection and inference-credit balance, without supplier-account setup.
Tools run locally; managed testing and 0review have separate access and billing.

1. Set `HOSTED_TEST_HOST` to the operator-provided URL. Log in below, choose
   your organization, and authorize the CLI.
2. Check models and balance. Login adds no credit. An owner or admin manages
   funding in **Billing**; credit requires confirmed payment.
3. Choose an alias from `0sec models`. Pin `hosted` to use it instead of any
   existing provider key or Codex login.

```bash
0sec login --host "$HOSTED_TEST_HOST"
0sec models --json
0sec balance --json

env 0SEC_SELECTED_PROVIDER=hosted 0SEC_MODEL="<alias-from-0sec-models>" \
  0sec review ./authorized-repo --runtime api
```

Replace the alias and repository path. The review consumes model credit;
catalog and balance reads don't. Insufficient credit for the request reserve
returns HTTP 402 before a provider call.

See [billing and errors](/api-keys/#hosted-inference-draft) and
[hosted settings](/configuration/#hosted-configuration-draft).

### Use my own API key

Your provider handles authentication and billing. Local, BYOK and supported
provider-subscription workflows need no 0sec Cloud account.

Set one provider key:

```bash
export ANTHROPIC_API_KEY="your-api-key"
```

See [API Keys](/api-keys/) for other providers, Azure and ChatGPT Codex sign-in.
With multiple credentials, select a matching `--model` or `0SEC_MODEL`.
Keep model keys separate from target credentials (`--auth`).
Never commit keys or paste them into issues.

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

Replace `app.example.com` with a target you own or have explicit permission to
test. USD 2 is the spending ceiling; actual cost varies.
Model/tool availability and target access determine coverage.

Review failures and incomplete coverage before interpreting empty results. [Scan Workflows](/scan-workflows/)
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

Depth sets template limits and agent turn budgets. Test coverage and duration vary
by target. See [Budget Management](/budget-management/).

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

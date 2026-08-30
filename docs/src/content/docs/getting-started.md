---
title: Getting Started
description: Install 0sec and run an authorized investigation.
---

## Install

Install the verified release binary with one command, build from source, or run
the container image.

```bash
# Verified release binary (macOS Apple Silicon / Linux x64/arm64)
curl -fsSL https://raw.githubusercontent.com/0sec-labs/0sec/main/install.sh | bash
export PATH="$HOME/.0sec/bin:$PATH"
0sec --help          # or just: 0 --help

# Source
git clone https://github.com/0sec-labs/0sec.git
cd 0sec
corepack enable
pnpm install --frozen-lockfile
pnpm build
node packages/cli/dist/index.js --help

# Docker
docker run --rm ghcr.io/0sec-labs/0sec:latest --help
```
Add the `export` line to your shell profile to make the release binary available in future shells.


## Set a model key

0sec is bring-your-own-model. Export one provider key, then pin the matching
model with `--model` when several keys are present.

```bash
export OPENROUTER_API_KEY="sk-or-..."   # one key, many model families
# or a direct provider:
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export Z_AI_API_KEY="..."               # glm-5.3
export QWEN_API_KEY="..."               # qwen3.8-max
```

0sec routes `--model` (or `0SEC_MODEL`) to its matching provider. If the runtime
is misconfigured it stops with an error instead of running a broken scan. See
[API Keys](/api-keys/) for the full provider list and ChatGPT Codex / Azure setup.

## First scan

Every live network target needs a scope file. The CLI refuses an unscoped live
target before it makes a request.

```bash
echo '{"in_scope":["your-app.com"]}' > scope.json

0sec scan --target https://your-app.com/api/chat --scope ./scope.json
```

This maps the attack surface, launches targeted attacks, reproduces each finding,
and writes a report. With Docker, mount the scope file and pass its container path:

```bash
docker run --rm -v "$PWD/scope.json:/work/scope.json:ro" -e OPENROUTER_API_KEY \
  ghcr.io/0sec-labs/0sec:latest scan \
  --target https://your-app.com --scope /work/scope.json
```

## Key scenarios

### Pentest a web app

Shell-first: the agent gets `bash` and standard tooling to probe for CORS, SSRF,
XSS, SQLi, SSTI, exposed files, and more.

```bash
0sec scan --target https://your-app.com --mode web --scope ./scope.json
```

### Audit a package

Downloads and installs the package into a temp dir (never executes it), runs
static analysis, then an AI review.

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

| Depth     | Test cases | Time    |
|-----------|-----------|---------|
| `quick`   | ~15       | ~1 min  |
| `default` | ~50       | ~3 min  |
| `deep`    | ~150      | ~10 min |

```bash
0sec scan --target https://api.example.com/chat --scope ./scope.json --depth deep
```

## No sandbox by default

In the open-source CLI the `bash` tool runs commands **directly on your host**,
guarded only by a timeout, scope-URL checks, and a scanner blocklist — there is no
container or VM isolation. Run it from a disposable VM, or use the container image
as your operating environment. (Per-scan sandboxing is a managed-platform feature,
tracked in [issue #193](https://github.com/0sec-labs/0sec/issues/193).)

## Next steps

- [Commands](/commands/) — full CLI reference
- [Configuration](/configuration/) — runtimes, modes, feature flags
- [Recipes](/recipes/) — copy-paste scans for common scenarios
- [Architecture](/architecture/) — how the pipeline works

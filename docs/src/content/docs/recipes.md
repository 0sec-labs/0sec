---
title: Recipes
description: Real-world 0sec recipes for common scanning scenarios.
---

Copy-paste recipes for common scenarios. Each assumes an `OPENROUTER_API_KEY` (or
equivalent) is exported — see [Getting Started](/getting-started/) if not.

## Scan a REST API (OpenAPI)

Point at your OpenAPI 3.x / Swagger 2.0 doc so recon starts with every endpoint,
parameter, and auth requirement already known — no crawl needed.

```bash
0sec scan \
  --target https://api.example.com \
  --api-spec ./openapi.yaml \
  --mode web \
  --depth deep
```

If your API requires authentication, add `--auth` (see [Scan authenticated APIs](#scan-authenticated-apis-bearer-token) below).

## Scan a WordPress site for CVEs

Turn on the WordPress fingerprinter: it detects WordPress, lists plugins and
themes, checks them against a curated vulnerable-plugin catalog, reads versions
from `readme.txt`/`style.css`, and returns CVE hints before the attack loop
crawls.

`wp_fingerprint` queries the no-key WPVulnerability API by slug. Set
`WPSCAN_API_TOKEN` or `0SEC_WPSCAN_API_TOKEN` to merge WPScan API data too — still
without running the `wpscan` CLI or sending generic scanner traffic.

```bash
export 0SEC_FEATURE_DYNAMIC_PLAYBOOKS=1

0sec scan \
  --target https://blog.example.com \
  --mode web \
  --depth deep \
  --features wp_fingerprint \
  --verbose
```

When the program explicitly allows scanner traffic, add the Docker executor and
`--allow-scanners` to let the agent use tools like `wpscan`. Keep this off for
scoped HackerOne/Bugcrowd targets unless the policy permits generic scanners.

```bash
0SEC_FEATURE_DOCKER_EXECUTOR=1 0sec scan \
  --target https://blog.example.com \
  --mode web \
  --depth deep \
  --features wp_fingerprint,docker_executor \
  --allow-scanners
```

## Audit a package for security issues

```bash
# Latest npm version
0sec audit express

# Pin a version
0sec audit express --package-version 4.18.2

# PyPI package
0sec audit requests --ecosystem pypi

# Deep audit with the Claude Code CLI
0sec audit left-pad --depth deep --runtime claude
```

The package is installed into a temp dir (never executed), scanned, checked
against dependency advisories, then reviewed by an agent that traces data flow for
supply-chain issues.

## Review a C/C++ library with sanitizer evidence

Use the C-library workflow for userspace C/C++ when a finding needs more than
static reasoning.

```bash
0sec review \
  --target c-library \
  ./libfoo \
  --depth deep \
  --runtime claude
```

The agent starts with a tier-1 libFuzzer harness on the smallest reachable
entrypoint, compiled with ASan and UBSan. Programmatic integrations can scaffold
it with `scaffoldTier1Harness({ srcDir, entryFn, includeDirs })`, or
`scaffoldTier2Harness({ srcDir, entryFn, componentFiles })` when the primitive
only matters through a wider API path.

Evidence should include the harness source, build/run commands, crashing input,
and sanitizer output. If the bug needs multiple components or process state,
escalate to tier-2/tier-3 rather than reporting a static-only finding.

## Verify a Linux kernel finding from a `.syz` program or C reproducer

The Tier-1 verify path (issue #271) builds a kernel from a local tree, boots it in
QEMU, runs your reproducer, and matches dmesg against an expected signature.
Artifacts cache at `~/.0sec/kernel-cache/` — a second run against the same tree +
config skips the slow rebuild and logs `[kernel-cache] hit`.

```bash
# Run a syzkaller .syz program against a freshly built kasan kernel
0sec ingest \
  --syz ./program.syz \
  --kernel-tree ~/src/linux \
  --kernel-config kasan \
  --output json

# Run a C reproducer with a custom config name and an explicit signature
0sec ingest \
  --reproducer ./poc.c \
  --kernel-tree ~/src/linux \
  --kernel-config defconfig+kasan \
  --expected-signature "KASAN: slab-use-after-free" \
  --output json
```

`--syz` and `--reproducer` are mutually exclusive and can't be combined with a
crash-dump path. The runner returns `status: 'reproduced' | 'no_signal' |
'build_failed' | 'run_failed'` plus a `dmesg_path` for advisories. Use
`--force-kernel-build` to bypass the cache after a tree edit, or
`--kernel-cache-dir` for an alternate location.

## Run a full pentest with maximum accuracy

Every false-positive reduction feature on, plus EGATS tree search. Slower, but
produces client-ready findings.

```bash
export 0SEC_FEATURE_CONSENSUS_VERIFY=1
export 0SEC_FEATURE_REACHABILITY_GATE=1
export 0SEC_FEATURE_POV_GATE=1
export 0SEC_FEATURE_TRIAGE_MEMORIES=1
export 0SEC_FEATURE_MULTIMODAL=1
export 0SEC_FEATURE_DOCKER_EXECUTOR=1

0sec scan \
  --target https://example.com \
  --mode web \
  --depth deep \
  --egats \
  --runtime claude
```

See [Configuration — Feature flags](/configuration/#feature-flags) for what each flag does.

## Best-of-N racing for hard targets

When a linear attack plan keeps getting stuck, spawn 5 parallel strategies and let
the fastest win.

```bash
0sec scan \
  --target https://hard-target.example.com \
  --mode web \
  --race \
  --depth deep
```

## Export findings to GitHub Issues

Push every confirmed finding to a GitHub repo as a labelled issue with evidence and reproduction steps.

```bash
export GITHUB_TOKEN="ghp_..."

0sec scan \
  --target https://example.com \
  --mode web \
  --export github:myorg/security-findings
```

Each finding becomes an issue labelled by severity (`sev:critical`, …) and
category (`cat:xss`, …) so you can triage from the GitHub UI.

## Generate an HTML, Markdown, or PDF report

```bash
# HTML (auto-opens in browser and saves to a temp file)
0sec scan \
  --target https://example.com \
  --mode web \
  --depth deep \
  --format html

# Markdown (printed to stdout; redirect to a file)
0sec scan \
  --target https://example.com \
  --mode web \
  --depth deep \
  --format md > example-pentest.md

# PDF (auto-opens in your default viewer and saves to a temp file)
0sec scan \
  --target https://example.com \
  --mode web \
  --depth deep \
  --format pdf
```

Each report has an executive summary, severity breakdown, per-finding evidence
(request/response pairs), and repro steps. Works for `audit` and `review` too.

## Scan authenticated APIs (bearer token)

```bash
# Inline
0sec scan \
  --target https://api.example.com \
  --api-spec ./openapi.yaml \
  --auth '{"type":"bearer","token":"eyJhbGciOi..."}'

# From a file (avoids leaking the token to shell history)
cat > auth.json <<'EOF'
{"type":"bearer","token":"eyJhbGciOi..."}
EOF

0sec scan \
  --target https://api.example.com \
  --api-spec ./openapi.yaml \
  --auth ./auth.json
```

Other auth types:

```bash
# Session cookie
--auth '{"type":"cookie","value":"session=abc123; csrf=def456"}'

# HTTP Basic
--auth '{"type":"basic","username":"admin","password":"hunter2"}'

# Custom header (API key)
--auth '{"type":"header","name":"X-API-Key","value":"sk_live_..."}'
```

## Track learned false positives across runs

Mark noisy findings as false positives and 0sec remembers the pattern next time.

```bash
# Mark a single finding as FP (auto-creates a memory)
0sec triage mark-fp NF-042 --reason "test fixture echo endpoint, not reachable in prod"

# Add a memory from an existing finding without suppressing it
0sec triage memory add --finding NF-017 --reason "intentional CORS config for public API"

# List what 0sec has learned
0sec triage memory list

# Remove a memory that's no longer accurate
0sec triage memory remove <memory-id>
```

Enable memory injection into the verify pipeline with `0SEC_FEATURE_TRIAGE_MEMORIES=1`.

---
title: Recipes
description: Real-world 0sec recipes for common scanning scenarios.
---

Copy-paste recipes for the most common 0sec scenarios. Every recipe assumes you have an `OPENROUTER_API_KEY` (or equivalent) exported. See [Getting Started](/getting-started/) if you don't.

## Scan my REST API (OpenAPI)

Point 0sec at your OpenAPI 3.x / Swagger 2.0 document and it will seed the recon phase with every endpoint, parameter, and auth requirement — skipping the crawl entirely.

```bash
0sec scan \
  --target https://api.example.com \
  --api-spec ./openapi.yaml \
  --mode web \
  --depth deep
```

If your API requires authentication, add `--auth` (see [Scan authenticated APIs](#scan-authenticated-apis-bearer-token) below).

## Scan a WordPress site for CVEs

Turn on the native WordPress fingerprinter. It detects WordPress, enumerates plugins/themes, proactively probes a curated high-impact vulnerable-plugin catalog, extracts versions from `readme.txt`/`style.css`, and returns CVE/exploit hints before the attack loop spends time on generic crawling.

For fresher plugin/theme advisories, `wp_fingerprint` queries the no-key WPVulnerability API by slug. If you also set `WPSCAN_API_TOKEN` or `0SEC_WPSCAN_API_TOKEN`, it will merge WPScan API data too, still without running the `wpscan` CLI or sending generic scanner traffic.

```bash
export 0SEC_FEATURE_DYNAMIC_PLAYBOOKS=1

0sec scan \
  --target https://blog.example.com \
  --mode web \
  --depth deep \
  --features wp_fingerprint \
  --verbose
```

When the program explicitly allows scanner traffic, add the Docker executor and `--allow-scanners` so the agent may use installed industry tools such as `wpscan`. Keep this off for scoped HackerOne/Bugcrowd targets unless the policy permits generic scanners.

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
# Default npm audit (latest version)
0sec audit express

# Pin a specific npm version
0sec audit express --version 4.18.2

# Audit a PyPI package
0sec audit requests --ecosystem pypi

# Deep audit with the Claude Code CLI runtime
0sec audit left-pad --depth deep --runtime claude
```

The package is installed in a sandbox, scanned with the selected static scanner, checked against dependency advisories, then reviewed by an AI agent that traces data flow and hunts for supply-chain issues.

## Review a C/C++ library with sanitizer evidence

Use the C-library review workflow when the target is a userspace C or C++ codebase and a finding needs more than static reasoning.

```bash
0sec review \
  --target c-library \
  ./libfoo \
  --depth deep \
  --runtime claude
```

The workflow tells the review agent to start with a tier-1 libFuzzer harness for the smallest reachable parser or API entrypoint, compiled with AddressSanitizer and UBSan. Programmatic integrations can scaffold that baseline with `scaffoldTier1Harness({ srcDir, entryFn, includeDirs })`, then run the returned build and run commands to collect the sanitizer log. If the suspected primitive only matters through a wider public API path, use `scaffoldTier2Harness({ srcDir, entryFn, componentFiles })` to link an explicit minimal source/object subset and optional seed corpus directories.

Evidence should include the harness source path, build command, run command, crashing input, and sanitizer output. If the bug needs multiple components or process state to reproduce, keep the tier-1 attempt as evidence and escalate to tier-2 or tier-3 instead of reporting a static-only finding.

## Verify a Linux kernel finding from a `.syz` program or C reproducer

The Tier-1 verify path (issue #271) builds a kernel from a local source tree, boots it in QEMU with a shared workdir, runs your reproducer, and matches dmesg against an expected signature. Kernel artifacts are cached at `~/.0sec/kernel-cache/<rev-or-tag>-<config-hash>/` — a second invocation against the same tree + config skips the (slow) rebuild and logs `[kernel-cache] hit`.

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

`--syz` and `--reproducer` are mutually exclusive and may not be combined with a crash-dump path. The runner returns `status: 'reproduced' | 'no_signal' | 'build_failed' | 'run_failed'` plus a `dmesg_path` you can attach to advisories. Set `--force-kernel-build` to bypass the cache after a tree edit, or `--kernel-cache-dir` to write to an alternate location (also overridable via `0SEC_KERNEL_BUILD_CACHE`).

## Run a full pentest with maximum accuracy

Turn on every false-positive reduction feature and let EGATS do a thorough tree search. Slower, but produces client-ready findings.

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

When a single linear attack plan keeps getting stuck, spawn 5 parallel strategies and let the fastest one win.

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

Each finding becomes an issue labelled by severity (`sev:critical`, `sev:high`, …) and category (`cat:xss`, `cat:ssrf`, …) so you can triage from the GitHub UI.

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

Both formats include an executive summary, a severity breakdown, per-finding evidence blocks with request/response pairs, and reproduction steps. Works for `audit` and `review` too.

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

After a scan, mark noisy findings as false positives and 0sec will remember the pattern for next time.

```bash
# Mark a single finding as FP (auto-creates a memory)
0sec-cli triage mark-fp NF-042 --reason "test fixture echo endpoint, not reachable in prod"

# Add a memory from an existing finding without suppressing it
0sec-cli triage memory add --finding NF-017 --reason "intentional CORS config for public API"

# List what 0sec has learned
0sec-cli triage memory list

# Remove a memory that's no longer accurate
0sec-cli triage memory remove <memory-id>
```

Enable memory injection into the verify pipeline with `0SEC_FEATURE_TRIAGE_MEMORIES=1`.

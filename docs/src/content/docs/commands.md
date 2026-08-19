---
title: Commands
description: Complete reference for all pwnkit CLI commands.
---

All commands are available via `pwnkit <command>`. You can also skip the subcommand and let auto-detect figure it out (see [Getting Started](/getting-started/)).

## scan

Probe AI/LLM apps, web apps, APIs, or MCP servers for vulnerabilities.

```bash
# Scan an LLM API
pwnkit scan --target https://api.example.com/chat

# Scan a traditional web app
pwnkit scan --target https://example.com --mode web

# Deep scan with Claude Code CLI
pwnkit scan --target https://api.example.com/chat --depth deep --runtime claude

# Authenticated scan using a bearer token
pwnkit scan --target https://api.example.com \
  --auth '{"type":"bearer","token":"eyJhbGciOi..."}'

# Scan an API with an OpenAPI spec pre-loaded
pwnkit scan --target https://api.example.com --api-spec ./openapi.yaml

# Run 5 attack strategies in parallel — first to succeed wins
pwnkit scan --target https://example.com --mode web --race

# Evidence-Gated Attack Tree Search (EGATS)
pwnkit scan --target https://example.com --mode web --egats

# Abort cleanly if the scan exceeds a USD ceiling
pwnkit scan --target https://example.com --mode web --cost-ceiling 5

# Export findings to GitHub Issues
pwnkit scan --target https://example.com --mode web \
  --export github:myorg/myrepo

# Generate an HTML report (auto-opens in browser)
pwnkit scan --target https://example.com --mode web \
  --format html
```

**Key flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--target <url>` | The URL or `mcp://` endpoint to scan | (required) |
| `--mode <mode>` | Scan mode: `probe`, `deep`, `mcp`, `web` | auto |
| `--depth <depth>` | Scan depth: `quick`, `default`, `deep` | `default` |
| `--runtime <rt>` | Runtime: `auto`, `api`, `claude`, `codex`, `gemini` | `auto` |
| `--format <fmt>` | Output format: `terminal`, `json`, `md`, `html`, `sarif`, `pdf` | `terminal` |
| `--timeout <ms>` | Request timeout in milliseconds | `30000` |
| `--api-key <key>` | API key for the LLM provider | (from env) |
| `--model <model>` | Specific LLM model to use | provider default |
| `--repo <path>` | Local source code path for white-box scanning | (none) |
| `--auth <json>` | Authenticated scanning credentials (see below) | (none) |
| `--api-spec <path>` | Path to an OpenAPI 3.x / Swagger 2.0 spec (JSON or YAML) | (none) |
| `--export <target>` | Export findings to an issue tracker, e.g. `github:owner/repo` | (none) |
| `--race` | Best-of-N: run 5 attack strategies in parallel, first-to-succeed wins | `false` |
| `--egats` | Evidence-Gated Attack Tree Search (beam search over hypothesis tree) | `false` |
| `--cost-ceiling <usd>` | Hard USD ceiling; aborts cleanly with partial findings preserved if exceeded | (none) |
| `--db-path <path>` | Path to SQLite database | `~/.pwnkit/pwnkit.db` |
| `--verbose` | Show animated attack replay and detailed agent reasoning | `false` |
| `--replay` | Replay the last scan's results without re-running | `false` |

### `--auth` credential formats

The `--auth` flag accepts either an inline JSON string or a path to a JSON file. Four credential types are supported:

```bash
# Bearer token
--auth '{"type":"bearer","token":"eyJhbGciOi..."}'

# Session cookie
--auth '{"type":"cookie","value":"session=abc123; csrf=def456"}'

# HTTP Basic auth
--auth '{"type":"basic","username":"admin","password":"hunter2"}'

# Custom header (e.g. API key)
--auth '{"type":"header","name":"X-API-Key","value":"sk_live_..."}'

# Or load from a file
--auth ./auth.json
```

### `--api-spec` — OpenAPI / Swagger import

Point `--api-spec` at an OpenAPI 3.x or Swagger 2.0 document (JSON or YAML). pwnkit will parse the spec, extract all endpoints with their parameter schemas and auth requirements, and seed the recon phase with that knowledge so the agent starts pentesting with full endpoint awareness instead of having to crawl.

```bash
pwnkit scan --target https://api.example.com --api-spec ./openapi.yaml
```

### `--race` — best-of-N strategy racing

With `--race`, pwnkit spawns 5 attack strategies in parallel against the same target. The first agent to confirm a finding wins; the others are terminated. Ideal for hard targets where a single linear attack plan gets stuck.

### `--egats` — Evidence-Gated Attack Tree Search

EGATS performs a beam search over a tree of attack hypotheses, pruning branches that fail evidence checks. Slower than `--race` but much more thorough.

### `--cost-ceiling` — hard spend guardrail

Set a hard per-scan USD ceiling:

```bash
pwnkit scan --target https://example.com --mode web --cost-ceiling 5
```

If cumulative estimated spend exceeds the ceiling, pwnkit:

- preserves findings collected so far
- exits with status code `4`
- emits `exit_reason: "cost_ceiling_exceeded"` in the machine-readable result line

The CLI flag overrides `PWNKIT_COST_CEILING_USD`.

### `--export github:owner/repo`

Pushes every confirmed finding to a GitHub repo as an issue, with severity labels, evidence blocks, and reproduction steps. Requires `GITHUB_TOKEN` in the environment with `repo` scope.

## audit

Install and security-audit a package with static analysis and AI review.

```bash
pwnkit audit express --version 4.18.2
pwnkit audit requests --ecosystem pypi
pwnkit audit serde --ecosystem cargo
pwnkit audit alpine:3.20 --ecosystem oci
pwnkit audit react --depth deep --runtime claude
pwnkit audit left-pad --format html
```

The package is installed in a sandbox, scanned with the selected static scanner, checked against dependency advisories, and then reviewed by an AI agent that traces data flow and looks for supply-chain vulnerabilities.

**Key flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `<package>` | Package name | (required) |
| `--ecosystem <e>` | Package ecosystem: `npm`, `pypi`, `cargo`, `oci` | `npm` |
| `--version <v>` | Specific version to audit | `latest` |
| `--depth <d>` | Audit depth: `quick`, `default`, `deep` | `default` |
| `--runtime <rt>` | Runtime: `auto`, `api`, `claude`, `codex`, `gemini` | `auto` |
| `--format <fmt>` | Output format: `terminal`, `json`, `md`, `html`, `sarif`, `pdf` | `terminal` |
| `--timeout <ms>` | AI agent timeout in milliseconds | `600000` |
| `--api-key <key>` | API key for the LLM provider | (from env) |
| `--model <model>` | Specific LLM model to use | provider default |
| `--cost-ceiling <usd>` | Hard USD ceiling; aborts cleanly with partial findings preserved if exceeded | (none) |
| `--db-path <path>` | Path to SQLite database | `~/.pwnkit/pwnkit.db` |
| `--verbose` | Detailed agent output | `false` |

## review

Deep source code security review of a local repo or GitHub URL.

```bash
# Review a local directory
pwnkit review ./my-ai-app

# Review a GitHub repo (cloned automatically)
pwnkit review https://github.com/user/repo

# Diff-aware review against a base branch
pwnkit review ./my-repo --diff-base origin/main --changed-only

# Profile a userspace C/C++ library for memory-safety + integer bugs
pwnkit review --target c-library ./libfoo

# Equivalent backward-compatible profile form
pwnkit review ./libfoo --profile c-library

# Profile a Linux kernel source tree for kernel-aware static review
pwnkit review --target linux-kernel ./linux
```

**Key flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `<repo>` | Local path or git URL | (required) |
| `--depth <d>` | Review depth: `quick`, `default`, `deep` | `default` |
| `--format <fmt>` | Output format: `terminal`, `json`, `md`, `html`, `sarif`, `pdf` | `terminal` |
| `--runtime <rt>` | Runtime: `auto`, `api`, `claude`, `codex`, `gemini` | `auto` |
| `--target <t>` | Review target alias: `app`, `default`, `c-library`, `linux-kernel` | (none) |
| `--profile <p>` | Review profile: `default`, `c-library`, `linux-kernel` | `default` |
| `--diff-base <ref>` | Git base ref for diff-aware review | (none) |
| `--changed-only` | Restrict static scanner leads + prioritization to changed files | `false` |
| `--timeout <ms>` | AI agent timeout in milliseconds | `600000` |
| `--api-key <key>` | API key for LLM provider | (from env) |
| `--model <model>` | Specific LLM model to use | provider default |
| `--cost-ceiling <usd>` | Hard USD ceiling; aborts cleanly with partial findings preserved if exceeded | (none) |
| `--db-path <path>` | Path to SQLite database | `~/.pwnkit/pwnkit.db` |
| `--verbose` | Detailed agent output | `false` |

### Review profiles

The `--target` alias selects the review workflow while preserving the older `--profile` flag for scripts. `--target app` and `--target default` both map to the default application profile. If both flags are present, they must select the same workflow. The default profile is for application code (web / JS / TS / Python / Go business logic) and is what you want for an AI app, an SaaS backend, or a typical npm package.

**`c-library` — userspace C/C++ memory-safety review.** Tunes the agent toward integer-overflow on allocation paths, signed/unsigned conversion at memcpy length args, off-by-one parser bounds checks, use-after-free across error paths, format-string sinks. Pairs with the tier-1/2/3 harness ladder: a single-function libFuzzer harness compiled with `-fsanitize=address,undefined` is the baseline validator; tier-2 (multi-component link) and tier-3 (QEMU full-stack) escalate when reachability requires it. Every finding must be backed by a sanitizer log from a harness that actually trips — static reasoning alone is recorded as a hypothesis, not a finding.

**`linux-kernel` — kernel-aware static review.** Tunes the agent toward kernel-specific failure modes: missing `copy_from_user` length validation, signed/unsigned int comparison on user-controlled length, UAF across `__free_pages`/`kfree_skb` error paths, refcount races (`get_task_struct` without matching `put_task_struct`), TOCTOU on `inode->i_*` fields, unsafe `unsafe_get_user`/`unsafe_put_user` outside a `user_access_begin`/`user_access_end` block, and skb cow/share violations (the Dirty Frag class — in-place AEAD/cipher on a shared frag without `skb_cow_data` / `skb_unshare`). The agent first verifies the tree is actually a kernel tree (`MAINTAINERS`, `Kconfig`, `KERNELRELEASE`, `arch/`) and refuses if not. Findings are tagged with the same subsystem labels (`fs/nfsd`, `net/tcp`, `mm`, …) used by the kernel-crash ingest pipeline so the two streams line up.

> **Non-goal: this is static review, not exploit reproduction.** The `linux-kernel` profile produces hypothesis-grade findings grounded at file:line and accompanied by a syzkaller-program or C-syscall reproducer SHAPE — it does not compile or boot the kernel. A libFuzzer harness does not apply (kernel state isn't reachable from a libFuzzer process). For machine-checkable verification, see issues #271 (kernel oracle) and #272 (syzkaller harness scaffold). Static-only findings are flagged `confidence: 0.4` with `hypothesis: true` until the verification phase lands.

## kernel variant-hunt

Run foxguard-backed kernel advisory variant hunting against a Linux source tree.

```bash
# Scan a kernel tree with a foxguard rule family
pwnkit kernel variant-hunt \
  --tree ./linux \
  --advisory dirty-frag.md \
  --rules ./foxguard/rules/kernel/dirty-frag-class \
  --output json

# Render an existing foxguard SARIF file as pwnkit findings
pwnkit kernel variant-hunt --tree ./linux --sarif-input ./foxguard.sarif
```

This command is orchestration only: foxguard owns the structural rules, and pwnkit maps SARIF hits into normal `Finding` objects with kernel subsystem labels, confidence, evidence text, and SARIF/JSON/terminal output. A hit is a variant-hunt candidate, not a confirmed crash; use kernel triage, Coccinelle/CodeQL, fuzzing, or `pwnkit ingest --verify` when crash evidence exists.

**Key flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--tree <path>` | Linux source tree to scan | (required) |
| `--advisory <url-or-file>` | Advisory provenance attached to each finding | (none) |
| `--rules <path>` | Foxguard rule directory, such as `rules/kernel/dirty-frag-class` | foxguard default |
| `--foxguard <path>` | Foxguard binary path or command name | auto-detect |
| `--sarif-input <path>` | Use existing foxguard SARIF instead of invoking foxguard | (none) |
| `--timeout <ms>` | Foxguard timeout in milliseconds | `120000` |
| `--output <fmt>` | Output format: `terminal`, `json`, `sarif` | `terminal` |
| `--verbose` | Include per-finding analysis in terminal output | `false` |

## kernel syzbot-mine

Mine and adversarially rerank syzbot's abandoned queue:

```bash
pwnkit kernel syzbot-mine --subsystems net,xfrm,crypto,vsock,nfc --limit 30 --details 15 --detail-delay 750
```

`--details` bounds the detail/reproducer enrichment pass. pwnkit records the
requested sandbox and harness setup. It also inspects the syz program for
mounts, TUN/qdisc/XFRM administration, synthetic devices, BPF setup, and
call-level fault injection before reranking privileged, one-shot, stale, and
incomplete leads. Missing enrichment is explicit; it is never treated as
evidence of unprivileged reachability. `--detail-delay` paces requests to the
public dashboard; HTTP throttling still fails closed.

Treat syzkaller campaign lanes separately: `sandbox=none` is privileged
discovery, while `sandbox=setuid` is only zero-cap-plausible configuration
evidence. Neither proves zero-cap reachability. That label requires runtime
attestation showing non-root real and effective UIDs and an empty effective
capability set for the reproducing execution, bound to a hashed artifact.
The execution boundary must also attest `no_new_privs`.

## ingest

Import kernel crash reports and optionally verify them against attached reproducers.

```bash
# Parse one crash report into findings
pwnkit ingest ./crashes/report.log

# Parse a directory of syzbot-style reports and reproducers
pwnkit ingest ./crashes --output json

# Validate reports against attached reproducers
pwnkit ingest ./crashes --verify --output json

# Run a standalone C reproducer through the kernel VM oracle
pwnkit ingest --reproducer ./poc.c --kernel-tree ~/src/linux --config kasan --output json

# Run a raw syzkaller program when the guest image provides syz-execprog
pwnkit ingest --syz ./program.syz --kernel-tree ~/src/linux --config kasan --output json

# Pivot each known-subsystem crash into source review for sibling bugs
pwnkit ingest ./crashes --review-subsystem --tree ~/src/linux --output json
```

For directory ingest, reproducers are attached by matching filename prefix:

- `crash001.log` + `crash001.c`
- `bug-42.report` + `bug-42.syz`

When `--verify` is enabled, the command returns a richer result object per crash:

- `sourcePath`
- `reproducerPath`
- `finding`
- `verification`

Without a configured kernel VM, verification falls back to static consistency and reproducer analysis only.

When `--reproducer` or `--syz` is used, `ingest` skips crash-report parsing and runs that program directly through the kernel VM oracle. `--kernel-tree` resolves a KASAN VM build/cache entry; if `PWNKIT_KERNEL_QEMU_KERNEL` and `PWNKIT_KERNEL_QEMU_DISK` already point at built artifacts, those are reused as the fastest cache hit.

When `--review-subsystem` is enabled, ingest keeps the original crash finding and appends review-derived sibling findings. Each sibling finding carries `relatedFindingId` pointing back to the crash finding that triggered the source hunt. Crashes with `unknown` subsystem, or subsystems that do not resolve under `--tree`, are reported in the JSON `skipped` list.

**Key flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `<path>` | Crash report file or directory of reports | (required) |
| `--format <fmt>` | Input hint: `auto`, `kasan`, `ubsan`, `oops`, `syzkaller`, `generic` | `auto` |
| `--output <fmt>` | Output format: `terminal`, `json`, `sarif` | `terminal` |
| `--verify` | Run the kernel oracle for each parsed report | `false` |
| `--reproducer <path>` | Run a standalone C reproducer through the kernel VM oracle | (none) |
| `--syz <path>` | Run a standalone syzkaller `.syz` program through the kernel VM oracle | (none) |
| `--kernel-tree <path>` | Linux source tree for kernel VM build/cache resolution | (none) |
| `--config <profile>` | Kernel VM config profile for `--kernel-tree`; currently `kasan` | `kasan` |
| `--kernel-cache-dir <path>` | Override kernel VM build cache directory | `~/.cache/pwnkit/kernel-vm` |
| `--force-kernel-build` | Rebuild kernel VM artifacts even if a cache entry exists | `false` |
| `--review-subsystem` | Run linux-kernel source review against each crash subsystem | `false` |
| `--tree <path>` | Linux source tree required by `--review-subsystem` | (none) |
| `--runtime <runtime>` | Review runtime for `--review-subsystem`: `auto`, `claude`, `codex`, `gemini`, `api` | `auto` |
| `--model <model>` | Model for `--review-subsystem` | (runtime default) |
| `--cost-ceiling <usd>` | Hard cost ceiling for `--review-subsystem` | (none) |
| `--verbose` | Include extra crash-analysis detail in terminal output | `false` |

### Real kernel VM verification

Set `PWNKIT_KERNEL_QEMU=1` to enable VM-backed execution. The runner expects a bootable guest image with:

- a boot path that mounts the `pwnkitshare` 9p share and executes `/mnt/pwnkit/runner.sh`
- a working C toolchain (`gcc`)
- a linker toolchain (`ld`, provided by `binutils`)
- permission to read kernel logs via `dmesg`

For the maintained Docker build recipe, exact guest contract, and troubleshooting
steps, see [Kernel VM Verification](/kernel-vm/).

Required environment variables:

```bash
export PWNKIT_KERNEL_QEMU=1
export PWNKIT_KERNEL_QEMU_KERNEL=/path/to/bzImage
export PWNKIT_KERNEL_QEMU_DISK=/path/to/rootfs.img
```

Useful optional variables:

```bash
export PWNKIT_KERNEL_QEMU_APPEND='console=ttyS0 root=/dev/vda rw nokaslr panic=-1 init=/sbin/pwnkit-init'
export PWNKIT_KERNEL_QEMU_BOOT_TIMEOUT_SEC=120
export PWNKIT_KERNEL_QEMU_TIMEOUT_SEC=60
export PWNKIT_KERNEL_QEMU_ACCEL=kvm
export PWNKIT_KERNEL_QEMU_SHARE_TAG=pwnkitshare
export PWNKIT_KERNEL_QEMU_ARTIFACT_DIR=/tmp/pwnkit-kvm-runs
```

If the VM is not configured, pwnkit does **not** claim a reproduced crash; it reports static-only verification with capped confidence.

## triage

Triage findings and manage learned false-positive memories. Every time you mark a finding as a false positive, pwnkit stores a pattern that future verify passes will consult — think Semgrep's `nosemgrep` but learned automatically.

```bash
# Create a memory from an existing finding
pwnkit-cli triage memory add --finding NF-001 --reason "test fixture, not reachable in prod"

# List all memories
pwnkit-cli triage memory list
pwnkit-cli triage memory list --scope target --category xss

# Delete a memory
pwnkit-cli triage memory remove <memory-id>

# Mark a finding as FP and auto-create a memory
pwnkit-cli triage mark-fp NF-042 --reason "known sandbox echo endpoint"
```

**`triage memory add`**

| Flag | Description | Default |
|------|-------------|---------|
| `--finding <id>` | Finding ID (full or prefix) to derive the memory from | (required) |
| `--reason <text>` | Why this finding is a false positive | (required) |
| `--scope <scope>` | Memory scope: `global`, `target`, `package` | `target` |
| `--scope-value <v>` | Scope identifier (target URL or package name) | (inferred) |
| `--db-path <path>` | Path to SQLite database | default |

**`triage memory list`**

| Flag | Description |
|------|-------------|
| `--scope <scope>` | Filter by scope: `global`, `target`, `package` |
| `--category <cat>` | Filter by vulnerability category |
| `--db-path <path>` | Path to SQLite database |

**`triage memory remove <id>`** — deletes a memory by its ID.

**`triage mark-fp <finding-id>`** — flips a finding's triage status to `suppressed` and auto-creates a memory.

| Flag | Description | Default |
|------|-------------|---------|
| `--reason <text>` | Why this finding is a false positive | (required) |
| `--scope <scope>` | Memory scope | `target` |
| `--scope-value <v>` | Scope identifier | (inferred) |

Enable memory injection into the verify pipeline with `PWNKIT_FEATURE_TRIAGE_MEMORIES=1` (see [Configuration](/configuration/#feature-flags)).

## resume

Resume a persisted review or audit scan by its scan ID.

```bash
pwnkit resume <scan-id>
```

Useful when a long-running deep scan was interrupted or when you want to continue where a previous run left off.

## dashboard

Open the local verification workbench for board-based triage, evidence review, and scan provenance.

```bash
pwnkit dashboard
pwnkit dashboard --port 48123
```

The dashboard provides a Kanban-style board for triaging findings, reviewing evidence, and tracking active scans. It runs entirely locally.

**Key flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--port <port>` | Port to bind | `48123` |
| `--host <host>` | Host to bind | `127.0.0.1` |
| `--no-open` | Do not auto-open a browser | (opens by default) |
| `--db-path <path>` | Path to SQLite database | `~/.pwnkit/pwnkit.db` |

## history

Browse past scans with status, depth, findings count, and duration.

```bash
pwnkit history
pwnkit history --limit 20
```

| Flag | Description | Default |
|------|-------------|---------|
| `--limit <n>` | Number of scans to show | `10` |

## timeline

Export a scan's immutable pipeline-event audit trail as a chronological,
technique-mapped forensic record. Built for handing to a client's security team
to cross-reference against their own detections.

```bash
pwnkit timeline <scanId>
pwnkit timeline <scanId> --format json
pwnkit timeline <scanId> --format csv
pwnkit timeline <scanId> --attack-only
pwnkit timeline <scanId> --since 2026-09-15T09:00:00Z --until 2026-09-15T17:00:00Z
```

| Flag | Description | Default |
|------|-------------|---------|
| `--format <format>` | `json`, `csv`, or `markdown` | `markdown` |
| `--since <iso>` | Only events at or after this ISO-8601 timestamp | — |
| `--until <iso>` | Only events at or before this ISO-8601 timestamp | — |
| `--attack-only` | Only events carrying a technique mapping | `false` |
| `--db-path <path>` | Path to the SQLite database | default location |

Timestamps are UTC ISO-8601. Rows carry MITRE ATT&CK and MITRE ATLAS techniques
as separate fields. See [Authorized Engagements](/engagements/) for the full
picture.

## identity

Read-only Microsoft Entra ID tenant posture assessment — 53 checks across
privileged roles, conditional access, app registrations, service principals,
federation, and token analysis. Every Graph request is hard-coded `GET`.

```bash
# Access token comes from the environment, never a command-line argument
export PWNKIT_ENTRA_ACCESS_TOKEN=...
pwnkit identity --tenant <tenant-guid>
pwnkit identity --tenant <tenant-guid> --json
```

## adgraph

Offline Active Directory attack-path analysis over a BloodHound CE / SharpHound
JSON export. Never collects, never authenticates, never touches the network.

```bash
pwnkit adgraph --input ./bloodhound-export/
pwnkit adgraph --input ./export.json --json
pwnkit adgraph --input ./export --domain corp.example.com
```

| Flag | Description | Default |
|------|-------------|---------|
| `--input <path>` | A BloodHound JSON file, or a directory of them | required |
| `--json` | Emit machine-readable JSON | `false` |
| `--domain <fqdn>` | Restrict analysis to one AD domain | — |
| `--timeout <ms>` | Wall-clock bound on ingest + analysis | `120000` |

Covers paths to Domain Admin, kerberoastable principals, unconstrained
delegation, DCSync rights, ACL abuse chains, and ADCS escalation
(ESC1, ESC3–ESC7, ESC9, ESC10, ESC13).

## entragraph

The Entra ID equivalent — offline attack-path analysis over an AzureHound
export. Same discipline: files only, no network, no authentication.

```bash
pwnkit entragraph --input ./azurehound-export/
pwnkit entragraph --input ./export --json
pwnkit entragraph --input ./export --owned <objectId>,<objectId>
pwnkit entragraph --input ./export --max-depth 4
```

| Flag | Description | Default |
|------|-------------|---------|
| `--input <path>` | An AzureHound JSON file, or a directory of them | required |
| `--json` | Emit machine-readable JSON | `false` |
| `--owned <ids>` | Comma-separated object ids already under operator control; these become path sources | — |
| `--max-depth <n>` | Hop ceiling for traversal | analyzer default |
| `--timeout <ms>` | Wall-clock bound on ingest + analysis | `120000` |

Covers paths to Global Administrator, service-principal escalation via added
secrets, consent-grant escalation, owner-chain abuse, and guest escalation.

An export missing membership or ownership collections cannot produce paths that
depend on them; `entragraph` says so explicitly rather than reporting an empty
result as a clean tenant. See [Authorized Engagements](/engagements/).

## findings

Query, filter, and inspect verified findings across all scans. Findings are persisted in a local SQLite database.

```bash
# List all findings
pwnkit findings list

# Filter by severity
pwnkit findings list --severity critical

# Filter by category and status
pwnkit findings list --category prompt-injection --status confirmed

# Inspect a specific finding with full evidence
pwnkit findings show NF-001

# Triage findings
pwnkit findings accept <finding-id> --note "confirmed and tracked"
pwnkit findings suppress <finding-id> --note "known test fixture"
pwnkit findings reopen <finding-id>
```

**Finding lifecycle:** `discovered` -> `verified` -> `confirmed` -> `scored` -> `reported` (or `false-positive` if verification fails).

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `list` | List findings with optional filters |
| `show <id>` | Show a finding with full evidence |
| `accept <id>` | Accept a finding as confirmed |
| `suppress <id>` | Suppress a finding (known FP or accepted risk) |
| `reopen <id>` | Reopen a previously suppressed finding |

## verify

Replay structured PoC steps or a built-in deterministic fixture and emit a
`verification_result` JSON payload. The final assertion phase does not require
an LLM. See [Verification Results](/verification-result/) for the stable result
schema.

```bash
# Replay PoC steps from a finding JSON
pwnkit verify --finding finding.json

# Run the deterministic CLI path traversal fixture against the CLI under test
pwnkit verify --fixture cli-path-traversal \
  --fixture-command '["paperclip","company","export","--api","{{apiUrl}}","--output","{{exportDir}}"]'

# Keep the sandbox, harness metadata, and stdout/stderr logs
pwnkit verify --fixture cli-path-traversal \
  --fixture-command '["paperclip","company","export","--api","{{apiUrl}}","--output","{{exportDir}}"]' \
  --retain-artifacts
```

The `cli-path-traversal` fixture starts a malicious local API and runs the
caller-supplied CLI command against a temp export directory. The harness does
not implement export behavior itself; it only supplies `{{apiUrl}}`,
`{{exportDir}}`, records stdout/stderr, and checks that a marker file escapes
the selected export root while staying inside the sandbox.

| Flag | Description | Default |
|------|-------------|---------|
| `--finding <path>` | Finding JSON with `pocSteps` to replay | |
| `--target <path>` | Optional `PocExecutionTarget` JSON for PoC steps | |
| `--fixture <name>` | Built-in deterministic fixture. Supported: `cli-path-traversal`; this fixture requires `--fixture-command` | |
| `--fixture-command <json>` | JSON argv array for the CLI under test. Required when `--fixture=cli-path-traversal`. Supports `{{apiUrl}}`, `{{exportDir}}`, and `{{fixtureMode}}` placeholders | |
| `--fixture-mode <mode>` | Fixture behavior: `vulnerable` or `patched` | `vulnerable` |
| `--retain-artifacts` | Keep the fixture sandbox and log files | `false` |
| `--artifact-dir <path>` | Use a specific fixture sandbox root | |
| `--output <path>` | Write JSON to a file instead of stdout | |

## h1

Read-only HackerOne hacker-API helpers — verify credentials, browse programs, and export a program's scope into the pwnkit scope-file format.

Credentials live at `~/.pwnkit/h1.env` (or `~/.pwnkit/h1/<identifier>.env`) with format `H1_IDENTIFIER=<token-name>` and `H1_TOKEN=<44-char-value>`. The token is used as the password and the identifier as the username over HTTP Basic auth; nothing is ever written to logs.

```bash
# Verify credentials
pwnkit h1 auth

# List visible programs (bounty-paying only)
pwnkit h1 programs list --bounty --limit 50

# List public-mode VDP programs as JSON
pwnkit h1 programs list --vdp --state public_mode --json

# Show one program with scope summary
pwnkit h1 programs show flutteruki

# Export structured_scopes to ~/.pwnkit/scopes/<handle>.json
# (consumed by `pwnkit scan --scope <path>`)
pwnkit h1 scope dump flutteruki
```

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `auth` | Verify HackerOne API credentials against `/v1/hackers/payments/balance` |
| `programs list` | List visible programs. Flags: `--bounty`, `--vdp` (mutually exclusive), `--state <s>`, `--limit <n>` (max 1000), `--json` |
| `programs show <handle>` | Show a single program's details with a structured-scope summary |
| `scope dump <handle>` | Write the program's `structured_scopes` to `~/.pwnkit/scopes/<handle>.json` (override with `--out`); non-network asset types and malformed identifiers are dropped with a warning |

**Exit codes:** `0` ok · `1` user/data error · `2` auth failure (missing creds or HTTP 401) · `3` rate-limit / network error.

## intel

Live vulnerability-intelligence lookup helpers for advisory-aware audits and
variant-hunt context.

```bash
# Build a package intel dossier with risk summary, advisories, prior-vuln playbooks, variants, and graph
pwnkit intel dossier formidable --ecosystem npm --package-version 3.5.2 --json

# Search package advisories through OSV/GitHub, enriched with NVD/CISA KEV
pwnkit intel search formidable --ecosystem npm --package-version 3.5.2

# Look up a CVE with NVD + CISA KEV context
pwnkit intel cve CVE-2024-1086

# Find related CVEs/advisories for variant-hunt context
pwnkit intel similar --cwe CWE-22 --keywords "zip slip,path traversal" --json

# Search CVEs/GHSAs already reported against the same target/project
pwnkit intel target-history --repository expressjs/express --ecosystem npm --package express --json

# Infer target-history hints from a local source checkout
pwnkit intel target-history --repo-path ./my-project --json
```

Audit and review agents also get `intel_build_dossier`,
`intel_search_target_history`, `intel_search_advisories`, `intel_lookup_cve`,
and `intel_search_similar` tools. They should use these before citing CVEs/GHSAs from memory; intel
results are leads unless backed by deterministic package/version evidence or
local verification. Target-history and dossier results include
prior-vulnerability playbooks plus an `auditGraph` that turns matching
historical bug shapes into ordered source/sink/guard/verification steps and
expected-evidence nodes. In source-review contexts, `intel_search_target_history`
can infer repository/package/product hints from the scoped repo path before
querying live advisory sources.

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `dossier <package>` | Build a package-level risk dossier with prior-vulnerability playbooks. Flags: `--ecosystem <e>`, `--package-version <v>`, `--ver <v>`, `--keywords <csv>`, `--similar-limit <n>`, `--no-similar`, `--offline`, `--cache-dir <path>`, `--json` |
| `search <package>` | Search package advisories. Flags: `--ecosystem <e>`, `--package-version <v>`, `--ver <v>`, `--no-enrich`, `--offline`, `--cache-dir <path>`, `--json` |
| `cve <cve-id>` | Look up one CVE through NVD and CISA KEV. Flags: `--offline`, `--cache-dir <path>`, `--json` |
| `similar` | Search related advisories by `--cwe`, `--keywords <csv>`, optional `--ecosystem`, `--limit <n>`, `--offline`, `--cache-dir <path>`, and `--json` |
| `target-history [target]` | Search prior CVEs/GHSAs reported against a target. Infers package/repo/product hints from local metadata when `--repo-path <path>` is given (reads `package.json`, `pyproject.toml`, `Cargo.toml`, `go.mod`, `.git/config`). Explicit flags override inferred values. Flags: `--repo-path <path>`, `--repository <owner/repo>`, `--ecosystem <e>`, `--package <pkg>`, `--product <p>`, `--vendor <v>`, `--keywords <csv>`, `--limit <n>`, `--offline`, `--cache-dir <path>`, `--json` |

## auth

pwnkit-cloud authentication — login, logout, and verify a scoped CLI token against the cloud `/health` endpoint.

> **Scaffold notice (issue [#303](https://github.com/0sec-labs/pwnkit/issues/303)):** this command is the CLI half of cloud auth. The server-side mint endpoint that issues scoped tokens after the browser-based better-auth flow lives in pwnkit-cloud and is shipped in a separate PR. Until that lands, the browser flow (`pwnkit auth login` without `--token`) will time out. Use `pwnkit auth login --token <value>` to paste a token directly — this is the only working path for now.

Credentials live at `~/.pwnkit/cloud.env` (chmod 600) with format:

```
PWNKIT_CLOUD_HOST=https://cloud.0sec.ai
PWNKIT_CLOUD_TOKEN=<scoped-cli-token>
```

`PWNKIT_CLOUD_HOST` is optional and defaults to `https://cloud.0sec.ai`. Both keys may also be set as environment variables (`PWNKIT_CLOUD_HOST` / `PWNKIT_CLOUD_TOKEN`), which take precedence over the file.

```bash
# Paste a token directly (the only path that works today)
pwnkit auth login --token <value>

# Browser flow (will time out until #303 server-side ships)
pwnkit auth login --host https://cloud.0sec.ai

# Verify the configured token against /health
pwnkit auth status

# Delete ~/.pwnkit/cloud.env
pwnkit auth logout
```

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `login` | Open a browser at `<host>/cli-auth?session=…` and poll for a minted token. Flags: `--host <url>`, `--token <value>` (escape hatch — skips the browser). |
| `logout` | Delete `~/.pwnkit/cloud.env`. Returns 0 even if no file was present. |
| `status` | Load credentials and `GET <host>/health` to verify the token is accepted. |

**Exit codes:** `0` ok · `1` user/data error · `2` auth failure (missing creds or HTTP 401/403) · `3` network error / login timeout.

## XBOW benchmark runner

The XBOW benchmark runner lives in `packages/benchmark` and is invoked with `pnpm --filter @pwnkit/benchmark xbow`. It runs pwnkit against the 104 XBOW validation challenges and reports pass/fail with evidence.

```bash
# Run the whole benchmark
pnpm --filter @pwnkit/benchmark xbow

# Run a specific subset of challenges
pnpm --filter @pwnkit/benchmark xbow --only XBEN-010,XBEN-051,XBEN-066

# Skip the first 20 challenges (useful for resuming)
pnpm --filter @pwnkit/benchmark xbow --start 20

# Include full finding objects in results JSON (for offline analysis)
pnpm --filter @pwnkit/benchmark xbow --save-findings
```

| Flag | Description | Default |
|------|-------------|---------|
| `--only <ids>` | Comma-separated challenge IDs to run | (all 104) |
| `--start <n>` | Skip the first `n` challenges | `0` |
| `--save-findings` | Include full finding objects in the results JSON | `false` |

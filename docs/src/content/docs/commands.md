---
title: Commands
description: Complete reference for all 0sec CLI commands.
---

Run any command as `0sec <command>` (or `0`). Skip the subcommand to let
auto-detect pick one (see [Getting Started](/getting-started/)).

## scan

Probe AI/LLM apps, web apps, or MCP servers. A REST API is scanned as a web
target; `--api-spec` pre-loads its endpoints.

Live targets require `--scope <file>` — the CLI refuses an unscoped live target
before making a request. Local source review and package audits don't.

```bash
# Scan an LLM API
0sec scan --target https://api.example.com/chat --scope ./scope.json

# Scan a traditional web app
0sec scan --target https://example.com --mode web --scope ./scope.json

# Deep scan with Claude Code CLI
0sec scan --target https://api.example.com/chat --scope ./scope.json --depth deep --runtime claude

# Authenticated scan using a bearer token
0sec scan --target https://api.example.com --scope ./scope.json \
  --auth '{"type":"bearer","token":"eyJhbGciOi..."}'

# Scan an API with an OpenAPI spec pre-loaded
0sec scan --target https://api.example.com --scope ./scope.json --api-spec ./openapi.yaml

# Run 5 attack strategies in parallel — first to succeed wins
0sec scan --target https://example.com --mode web --scope ./scope.json --race

# Evidence-Gated Attack Tree Search (EGATS)
0sec scan --target https://example.com --mode web --scope ./scope.json --egats

# Abort cleanly if the scan exceeds a USD ceiling
0sec scan --target https://example.com --mode web --scope ./scope.json --cost-ceiling 5

# Export findings to GitHub Issues
0sec scan --target https://example.com --mode web --scope ./scope.json \
  --export github:myorg/myrepo

# Generate an HTML report (auto-opens in browser)
0sec scan --target https://example.com --mode web --scope ./scope.json \
  --format html
```

**Key flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--target <url>` | The URL or `mcp://` endpoint to scan | (required) |
| `--scope <file>` | JSON engagement scope for a live network target | (required for live targets) |
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
| `--db-path <path>` | Path to SQLite database | `~/.0sec/0sec.db` |
| `--verbose` | Show detailed output | `false` |
| `--replay` | Replay the last scan's results without re-running | `false` |

### `--auth` credential formats

Pass inline JSON or a path to a JSON file. Four types:

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

Point at an OpenAPI 3.x or Swagger 2.0 doc (JSON or YAML). 0sec parses every
endpoint, its parameter schema, and auth requirements, then seeds recon so the
agent starts with full endpoint awareness instead of crawling.

```bash
0sec scan --target https://api.example.com --scope ./scope.json --api-spec ./openapi.yaml
```

### `--race` — best-of-N strategy racing

Spawns 5 attack strategies in parallel; the first to confirm a finding wins, the
rest are killed. For hard targets where a linear plan gets stuck.

### `--egats` — Evidence-Gated Attack Tree Search

Beam search over a tree of attack hypotheses, pruning branches that fail evidence
checks. Slower than `--race`, more thorough.

### `--cost-ceiling` — hard spend guardrail

Set a per-scan USD ceiling; the flag overrides `0SEC_COST_CEILING_USD`. See
[Cost ceiling](/configuration/#cost-ceiling) for the exit code and result-line
behaviour.

### `--export github:owner/repo`

Pushes each confirmed finding to a GitHub repo as an issue with severity labels,
evidence, and repro steps. Requires `GITHUB_TOKEN` with `repo` scope.

## audit

Install and security-audit a package with static analysis and AI review. The
package is installed into a temp dir (never executed), scanned, checked against
dependency advisories, then reviewed by an agent that traces data flow for
supply-chain issues.

```bash
0sec audit express --package-version 4.18.2
0sec audit requests --ecosystem pypi
0sec audit serde --ecosystem cargo
0sec audit alpine:3.20 --ecosystem oci
0sec audit react --depth deep --runtime claude
0sec audit left-pad --format html
```

**Key flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `<package>` | Package name | (required) |
| `--ecosystem <e>` | Package ecosystem: `npm`, `pypi`, `cargo`, `oci` | `npm` |
| `--package-version <v>` | Specific version to audit (aliases: `--ver`, `--pkg-version`) | `latest` |
| `--depth <d>` | Audit depth: `quick`, `default`, `deep` | `default` |
| `--runtime <rt>` | Runtime: `auto`, `api`, `claude`, `codex`, `gemini` | `auto` |
| `--format <fmt>` | Output format: `terminal`, `json`, `md`, `html`, `sarif`, `pdf` | `terminal` |
| `--timeout <ms>` | AI agent timeout in milliseconds | `600000` |
| `--api-key <key>` | API key for the LLM provider | (from env) |
| `--model <model>` | Specific LLM model to use | provider default |
| `--cost-ceiling <usd>` | Hard USD ceiling; aborts cleanly with partial findings preserved if exceeded | (none) |
| `--db-path <path>` | Path to SQLite database | `~/.0sec/0sec.db` |
| `--verbose` | Detailed agent output | `false` |

## review

Deep source code security review of a local repo or GitHub URL.

```bash
# Review a local directory
0sec review ./my-ai-app

# Review a GitHub repo (cloned automatically)
0sec review https://github.com/user/repo

# Diff-aware review against a base branch
0sec review ./my-repo --diff-base origin/main --changed-only

# Profile a userspace C/C++ library for memory-safety + integer bugs
0sec review --target c-library ./libfoo

# Equivalent backward-compatible profile form
0sec review ./libfoo --profile c-library

# Profile a Linux kernel source tree for kernel-aware static review
0sec review --target linux-kernel ./linux
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
| `--db-path <path>` | Path to SQLite database | `~/.0sec/0sec.db` |
| `--verbose` | Detailed agent output | `false` |

### Review profiles

`--target` selects the workflow; the older `--profile` flag still works for
scripts. `--target app` and `--target default` both mean the default application
profile — for AI apps, SaaS backends, and typical packages (web / JS / TS /
Python / Go). If both flags are set they must agree.

**`c-library`** — userspace C/C++ memory-safety review: integer overflow on alloc
paths, signed/unsigned at memcpy lengths, off-by-one bounds, UAF across error
paths, format-string sinks. Pairs with the tier-1/2/3 harness ladder (libFuzzer
+ ASan/UBSan baseline, escalating to multi-component link and QEMU full-stack).
Every finding needs a sanitizer log from a harness that actually trips; static
reasoning alone is a hypothesis, not a finding.

**`linux-kernel`** — kernel-aware static review: missing `copy_from_user` length
checks, signed/unsigned on user-controlled lengths, UAF across error paths,
refcount races, TOCTOU on `inode->i_*`, unsafe user-access outside
`user_access_begin/end`, and skb cow/share violations (the Dirty Frag class). The
agent verifies the tree is really a kernel tree and refuses otherwise. Findings
carry the same subsystem labels (`fs/nfsd`, `net/tcp`, `mm`, …) as the crash
ingest pipeline.

> **Static review, not exploit reproduction.** This profile produces
> hypothesis-grade findings at file:line with a reproducer *shape* — it doesn't
> compile or boot the kernel. Static-only findings are flagged `confidence: 0.4`,
> `hypothesis: true`. Machine-checkable verification is tracked in #271 (kernel
> oracle) and #272 (syzkaller harness scaffold).

## fix

Generate a narrow patch for one independently reproduced local source finding,
validate it in an isolated Git worktree, and optionally apply it. Stricter than
remediation guidance:

- `<repo>` must be the clean root of a local Git worktree;
- the finding (or `--verification-result`) must be `status: "reproduced"`;
- the finding needs a code-only `verificationSpec`;
- `--test-command` is required and runs after every candidate patch;
- the original checkout stays untouched unless `--apply` is set — and `--apply`
  only lands a patch that invalidates the vulnerable-source contract and passes
  the regression run.

```bash
# Generate and validate a candidate; keep the original checkout unchanged.
0sec fix ./my-app \
  --finding ./finding.json \
  --test-command "pnpm test" \
  --verification-result ./verification.json \
  --output ./candidate-fix.patch

# Apply only a candidate that passed the isolated re-check and regression run.
0sec fix ./my-app \
  --finding ./finding.json \
  --test-command "pnpm test" \
  --verification-result ./verification.json \
  --apply
```

`fix` supports source-only verification contracts. A live behavioral re-test
needs a provisioned target and is out of scope — don't treat a source fix as
proof that a deployed target is remediated.

| Flag | Description | Default |
|------|-------------|---------|
| `<repo>` | Clean local Git worktree with the affected source | required |
| `--finding <path>` | Finding JSON with a code-only `verificationSpec` | required |
| `--verification-result <path>` | Optional `0sec verify` JSON when the finding does not already carry a reproduced result | |
| `--test-command <command>` | Explicit regression command run in the candidate worktree | required |
| `--runtime <runtime>` | `auto` or `api` | `auto` |
| `--model <model>` | Model identifier for the selected runtime | provider default |
| `--timeout <ms>` | Per-model-call timeout | `600000` |
| `--test-timeout <ms>` | Regression-command timeout | `300000` |
| `--max-attempts <n>` | Candidate patch attempts; capped at 3 | `3` |
| `--apply` | Apply only the patch that passed both gates | `false` |
| `--output <path>` | Persist the validated `apply_patch` DSL | stdout only |

## kernel variant-hunt

Run foxguard-backed kernel advisory variant hunting against a Linux source tree.

```bash
# Scan a kernel tree with a foxguard rule family
0sec kernel variant-hunt \
  --tree ./linux \
  --advisory dirty-frag.md \
  --rules ./foxguard/rules/kernel/dirty-frag-class \
  --output json

# Render an existing foxguard SARIF file as 0sec findings
0sec kernel variant-hunt --tree ./linux --sarif-input ./foxguard.sarif
```

Orchestration only: foxguard owns the structural rules; 0sec maps SARIF hits into
`Finding` objects with subsystem labels, confidence, and evidence. A hit is a
candidate, not a confirmed crash — use `0sec ingest --verify` (or triage /
Coccinelle / CodeQL / fuzzing) when crash evidence exists.

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
0sec kernel syzbot-mine --subsystems net,xfrm,crypto,vsock,nfc --limit 30 --details 15 --detail-delay 750
```

`--details` bounds the reproducer-enrichment pass; `--detail-delay` paces
requests to the public dashboard (throttling fails closed). 0sec inspects each
syz program for mounts, TUN/qdisc/XFRM setup, synthetic devices, BPF, and fault
injection before reranking privileged, one-shot, stale, and incomplete leads.
Missing enrichment is recorded explicitly, never treated as evidence of
unprivileged reachability.

`sandbox=none` is privileged discovery; `sandbox=setuid` is only
zero-cap-plausible config evidence. Neither proves zero-cap reachability — that
needs runtime attestation (non-root real/effective UIDs, empty effective
capability set, `no_new_privs`) bound to a hashed artifact.

## ingest

Import kernel crash reports and optionally verify them against attached reproducers.

```bash
# Parse one crash report into findings
0sec ingest ./crashes/report.log

# Parse a directory of syzbot-style reports and reproducers
0sec ingest ./crashes --output json

# Validate reports against attached reproducers
0sec ingest ./crashes --verify --output json

# Run a standalone C reproducer through the kernel VM oracle
0sec ingest --reproducer ./poc.c --kernel-tree ~/src/linux --kernel-config kasan --output json

# Run a raw syzkaller program when the guest image provides syz-execprog
0sec ingest --syz ./program.syz --kernel-tree ~/src/linux --kernel-config kasan --output json

# Pivot each known-subsystem crash into source review for sibling bugs
0sec ingest ./crashes --review-subsystem --tree ~/src/linux --output json
```

For directory ingest, reproducers attach by filename prefix (`crash001.log` +
`crash001.c`, `bug-42.report` + `bug-42.syz`).

`--verify` returns a richer per-crash object (`sourcePath`, `reproducerPath`,
`finding`, `verification`). Without a configured kernel VM, verification falls
back to static consistency and reproducer analysis only.

`--reproducer` or `--syz` skips crash-report parsing and runs the program
directly through the kernel VM oracle. `--kernel-tree` resolves a KASAN VM
build/cache entry; prebuilt `0SEC_KERNEL_QEMU_KERNEL`/`0SEC_KERNEL_QEMU_DISK`
artifacts are reused as the fastest cache hit.

`--review-subsystem` keeps the crash finding and appends review-derived siblings,
each carrying `relatedFindingId` back to the crash. Crashes with `unknown` or
unresolved subsystems land in the JSON `skipped` list.

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
| `--kernel-config <name>` | Kernel build config for `--kernel-tree`, e.g. `kasan`, `defconfig+kasan` (deprecated alias: `--config`) | (none) |
| `--expected-signature <pattern>` | Expected dmesg signature substring for verify | (none) |
| `--kernel-cache-dir <path>` | Override kernel build cache directory | `~/.0sec/kernel-cache` |
| `--force-kernel-build` | Rebuild kernel VM artifacts even if a cache entry exists | `false` |
| `--review-subsystem` | Run linux-kernel source review against each crash subsystem | `false` |
| `--tree <path>` | Linux source tree required by `--review-subsystem` | (none) |
| `--runtime <runtime>` | Review runtime for `--review-subsystem`: `auto`, `claude`, `codex`, `gemini`, `api` | `auto` |
| `--model <model>` | Model for `--review-subsystem` | (runtime default) |
| `--cost-ceiling <usd>` | Hard cost ceiling for `--review-subsystem` | (none) |
| `--verbose` | Include extra crash-analysis detail in terminal output | `false` |

### Real kernel VM verification

Set `0SEC_KERNEL_QEMU=1` to enable VM-backed execution. The runner expects a bootable guest image with:

- a boot path that mounts the `osecshare` 9p share and executes `/mnt/0sec/runner.sh`
- a working C toolchain (`gcc`)
- a linker toolchain (`ld`, provided by `binutils`)
- permission to read kernel logs via `dmesg`

For the maintained Docker build recipe, exact guest contract, and troubleshooting
steps, see [Kernel VM Verification](/kernel-vm/).

Required environment variables:

```bash
export 0SEC_KERNEL_QEMU=1
export 0SEC_KERNEL_QEMU_KERNEL=/path/to/bzImage
export 0SEC_KERNEL_QEMU_DISK=/path/to/rootfs.img
```

Useful optional variables:

```bash
export 0SEC_KERNEL_QEMU_APPEND='console=ttyS0 root=/dev/vda rw nokaslr panic=-1 init=/sbin/0sec-init'
export 0SEC_KERNEL_QEMU_BOOT_TIMEOUT_SEC=120
export 0SEC_KERNEL_QEMU_TIMEOUT_SEC=60
export 0SEC_KERNEL_QEMU_ACCEL=kvm
export 0SEC_KERNEL_QEMU_SHARE_TAG=osecshare
export 0SEC_KERNEL_QEMU_ARTIFACT_DIR=/tmp/0sec-kvm-runs
```

If the VM is not configured, 0sec does **not** claim a reproduced crash; it reports static-only verification with capped confidence.

## triage

Triage findings and manage learned false-positive memories. Mark a finding as a
false positive and 0sec stores a pattern future verify passes consult — like
Semgrep's `nosemgrep`, learned automatically.

```bash
# Create a memory from an existing finding
0sec triage memory add --finding NF-001 --reason "test fixture, not reachable in prod"

# List all memories
0sec triage memory list
0sec triage memory list --scope target --category xss

# Delete a memory
0sec triage memory remove <memory-id>

# Mark a finding as FP and auto-create a memory
0sec triage mark-fp NF-042 --reason "known sandbox echo endpoint"
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

Enable memory injection into the verify pipeline with `0SEC_FEATURE_TRIAGE_MEMORIES=1` (see [Configuration](/configuration/#feature-flags)).

## console

The interactive operator console — one chat surface that drives the whole tool
registry (recon, web pentest, source/package scan, variant hunt, verify,
patch-gen). Running the binary with no arguments launches it; you can also invoke
it explicitly.

```bash
# Full console — bare invocation launches straight into chat
0sec
0

# Explicit, with an engagement target and a scope file
0sec console --target https://api.example.com --scope ./scope.json

# Start in Co-pilot: approve every non-read-only tool call
0sec console --autonomy copilot --scope ./scope.json

# Run one prompt without opening the TUI; accept an argument or piped stdin
0sec console -p "Summarize the saved findings"

# Reopen the newest console session, or a specific saved session
0sec -c
0sec -r 8d4c2a

# Expose the generic-scanner wrappers (sqlmap/nikto/…)
0sec console --scope ./scope.json --allow-scanners

| Flag | Description | Default |
|------|-------------|---------|
| `--target <url>` | Engagement target the tools operate against; can also be named in chat | (none) |
| `--scope <file>` | Initial authorization scope. Required for YOLO and for the Node fallback | (none) |
| `-m, --model <id>` | Override the LLM model id | provider default |
| `--role <role>` | Tool set to expose: `audit`, `review`, `discovery`, `attack`, `verify` (`audit` = every tool) | `audit` |
| `--mode <mode>` | `standard`, `recon`, `copilot`, or `yolo` | `standard` |
| `--yolo` | Shortcut for `--mode yolo`; still requires `--scope` | off |
| `--autonomy <mode>` | Alias of `--mode`; `--mode` and `--yolo` win if both are present | `standard` |
| `--max-tool-calls <n>` | Safety cap on tool-call rounds per operator message | `20` |
| `--allow-scanners` | Expose generic-scanner tool wrappers | off |
| `--resume [id]`, `-r [id]` | Reopen a saved console session by ID or unique prefix; with no ID, opens the session picker | (none) |
| `--continue`, `-c` | Reopen the most recent console session without a picker | off |
| `--print [prompt]`, `-p [prompt]` | Run one non-interactive prompt, print the result, and exit; reads stdin when no prompt is supplied | off |

Two front-ends. Under Bun with a TTY on stdin and stdout you get the full OpenTUI
console below. Otherwise it falls back to a plain readline REPL, which
**requires `--scope`** — it has no approval surface, so it can't grant
session-only scope extensions and denies them outright.

### Slash commands

Anything starting with `/` is handled locally and never reaches the model
(unrecognised ones produce a local notice). Everything else is sent to the engine
as an operator message.

| Command | Aliases | Behaviour |
|---------|---------|-----------|
| `/help [command]` | `/?`, `/commands` | Renders the command list as a panel, grouped by category. An argument filters by name/alias prefix. |
| `/status` | — | Panel: model and provider, mode, target, scope rules (or `scope on demand`), tool count, turns, cumulative input→output tokens. |
| `/tools` | — | Panel listing the tool names registered for this session's role. |
| `/agents` | — | Notice listing the subagents running *right now*, or "No active subagents". It is a live view, not a catalogue. |
| `/scope` | — | Panel: target, mode, and the in-scope rules. With no scope it says so explicitly rather than reading as permissive. |
| `/mode [standard\|copilot\|yolo]` | — | With no argument, **opens a picker**. With an argument, switches directly. Refused while a turn is in flight; YOLO is refused — and shown greyed in the picker — when no scope is configured. |
| `/model [id]` | `/models` | With no argument, **opens a model picker** whose header names the providers that currently hold credentials. With an id, rebuilds the session on that model and carries the conversation across; a failed rebuild leaves you on the old one. Refused mid-turn. |
| `/providers` | `/login`, `/auth` | **Opens a picker** of the providers 0sec can detect, each marked configured (and via which env var) or not, with the exact env var to set. Selecting one prompts for a key, which is stored `0600` in `~/.0sec/credentials.json` and exported into the running process. The value is never echoed back into the transcript. |
| `/settings` | `/config`, `/prefs` | **Opens a picker** of console display settings. Enter flips a boolean or cycles an enum, then reopens against the new values. Writes global settings; a project override can layer individual keys. |
| `/resume` | `/sessions` | **Opens a picker** of saved transcripts for the current working directory (newest first, up to 20). See [Session persistence](#session-persistence). Refused mid-turn. |
| `/transcript` | `/review` | Opens the virtualized transcript review. |
| `/explain [topic]` | `/eli5` | Sends a real turn asking for a plain-language explanation of the previous result, or of `topic`. It is a normal model call and costs tokens. |
| `/feedback <message>` | — | Appends the message, with a timestamp, version, model and mode, to `~/.0sec/feedback.md`. **Nothing is transmitted anywhere.** |
| `/feedback submit <message>` | — | Persists locally and shows a preview of the exact HTTPS endpoint, body, headers and credential warnings. Does **not** transmit. Use `/feedback send` to transmit or `/feedback cancel` to discard. |
| `/feedback send` | — | Transmits the previewed payload to the authenticated 0cloud feedback channel after `0sec auth login`, or to an explicit `0SEC_FEEDBACK_URL` relay. Refused when submission is blocked. |
| `/feedback cancel` | — | Clears the pending feedback without transmitting. The local copy remains saved. |
| `/clear` | `/new` | Clears the conversation. Readline fallback only — see the caveat below. |
| `/history` | — | Opens the scan-history screen. |
| `/findings` | `/finds` | Opens the findings screen. |
| `/replay` | — | Opens the replay screen. |
| `/ops` | `/runs` | Opens mission control (active and recent operations). |
| `/launcher` | `/home` | Opens the home screen. |
| `/doctor` | — | Opens the diagnostics screen. |
| `/chat` | — | No-op from the chat view; it reports that chat is already active. |
| `/back` | — | Returns to the previous screen. |
| `/exit` | `/quit` | Ends the session and returns to the shell. |

**Front-end coverage.** `/agents`, `/scope`, `/chat`, `/back`, `/launcher`,
`/ops`, `/history`, `/findings`, `/replay`, `/doctor` and `/transcript` are
TUI-only; the readline fallback recognises them and tells you the Bun TUI is
needed. Of the rest, the fallback implements `/help`, `/status`, `/tools`,
`/clear`, `/mode` and `/exit`. `/model`, `/resume`, `/providers`, `/settings`,
`/explain` and `/feedback` are parsed there but currently do nothing — no
output, no error.

**`/clear` caveat.** It is registered, offered by the TUI's command menu and
listed by `/help`, but the TUI's command router has no handler for it, so
typing it there reports `unknown command: /clear`. It works in the readline
fallback, where it calls `clearConversation()`.

### Keybindings

| Key | Action |
|-----|--------|
| `/` | Typing a leading `/` opens the command menu inline under the composer; it filters as you type. |
| `Ctrl+P` / `Ctrl+K` | Puts a `/` in the composer, which opens the same command menu. On the non-chat screens (mission control, doctor, history, findings, replay, home) the same chord toggles that screen's own command palette. |
| `↑` / `↓` | Move the selection in the command menu or in an open picker. |
| `Tab` | Completes the highlighted command into the composer, appending a space when the command takes an argument. |
| `Enter` | Runs the highlighted command, or sends the composer text. In a picker, commits the highlighted row. At an approval prompt, approves. |
| `Shift+Tab` | Cycles the autonomy mode. It routes through `/mode`, so it inherits the same refusals, and it skips YOLO entirely when no scope is configured. |
| `Esc` | Closes the command menu if it is open; otherwise discards the draft and leaves the composer; otherwise goes back a screen. In a picker it closes the picker; at an approval prompt it rejects. |
| `Ctrl+C` | Exits, from anywhere — including modals and approval prompts. |

Typing while a turn is running does not block. A plain message is parked (up to
50) and delivered in order, one per idle transition, once the turn ends. Slash
commands are never queued — they run against the console immediately, and the
handlers that cannot safely act mid-turn (`/mode`, `/model`, `/resume`,
`/explain`) say so instead.

### Autonomy modes

The mode governs which gates prompt you. It can be set at launch with
`--autonomy`, changed live with `/mode`, and cycled with `Shift+Tab`.

| Mode | What it gates |
|------|---------------|
| **Standard** (default) | Tools run automatically. A network-capable call whose destination is outside the current scope — or whose destination cannot be read at all, e.g. `curl "$H"` or a piped `\| sh` — triggers a scope prompt. A filesystem-scoped tool reaching outside the approved subtree triggers a local-directory prompt. No per-tool prompts. |
| **Co-pilot** | Everything Standard does, plus an approval prompt before every non-read-only tool call. Read-only tools (`read_file`, `search_files`, `list_files`, `query_findings`, the `intel_*` lookups, `payload_lookup`, `list_skills`, `load_skill`, `done`) are exempt. |
| **YOLO** | No prompts *inside an already-configured scope*. It is not "no rules": it requires a non-empty preconfigured scope, and anything outside it is a hard denial rather than a prompt. A destination the gate cannot resolve is denied on the same principle. Scope is never silently extended. |

YOLO refuses to engage without a scope — the console blocks `/mode yolo` and the
engine enforces the same floor for API sessions. It lifts the scoped-source-audit
allow-list without prompting, but never the network-scope check, the
local-filesystem check, or per-handler tool guards.

0sec does not sandbox tool execution. The gates below are approval gates, not
containment.

### Approval prompts

Four prompts can interrupt a turn. Each is answered with `Enter` (approve) or
`Esc` (reject), and each grant is in-memory and session-scoped — **none of them
is written to a scope file or to disk**.

| Prompt | Trigger | What approving grants |
|--------|---------|-----------------------|
| **Authorize session scope** | A network-capable tool references a URL outside the current scope, or a shell construct whose destination cannot be resolved. | The exact hostnames from the requested URLs are added to the in-memory scope for this session. Existing deny rules still win, and the extension is rejected outright if the resulting policy would not actually cover the request. |
| **Authorize local directory** | `read_file`, `list_files`, `search_files`, `apply_patch`, `run_command` or `analyze_binary` touches a path no approved local scope covers. | That directory **subtree only**, for this session. The path shown is already absolute and symlink-resolved, and the engine re-canonicalises it on apply, so a symlink swapped between the prompt and the apply cannot widen the grant. Filesystem root and your home directory are refused outright — never even offered. |
| **Co-pilot approval** | Any non-read-only tool call while in Co-pilot. | That one call. The next call prompts again. |
| **Enable additional tool** | During a scoped source audit (role `audit`/`review` with a local scope), the model calls a tool outside the source-audit allow-list. | That one tool name, for the rest of the session. It lifts *only* the allow-list; network scope, local scope and the Co-pilot gate all still apply to it. |

Rejections stick. A declined host, shell payload, directory (and anything beneath
it), or tool is denied without re-prompting for the rest of the session, so a
retrying model can't turn a "no" into a prompt loop.

### Session persistence

How transcripts are stored on disk, what they contain, and why secrets are
deliberately not scrubbed is documented under
[Session persistence](/configuration/#session-persistence).

`/resume` lists transcripts whose recorded working directory matches the current
one, newest first. Each completed or failed turn is saved, so the picker includes
normal sessions as well as interrupted ones. Picking a session rebuilds the model
history and reconstructs the visible transcript from the stored messages; some
display-only card metadata is intentionally not retained.

### Console settings

`/settings` opens a picker of console display settings. It writes the global
`~/.0sec/tui-settings.json`; a project-level
`<project>/.0sec/tui-settings.json` can override individual keys. The full table
of keys, values, and defaults is documented under
[Console display settings](/configuration/#console-display-settings).

## resume

Resume a persisted review or audit scan by its scan ID.

```bash
0sec resume <scan-id>
```

Useful when a long-running deep scan was interrupted or when you want to continue where a previous run left off.

This is unrelated to the console's `/resume`, which restores a saved chat
transcript rather than a scan.

## dashboard

Local verification workbench: a Kanban board for triaging findings, reviewing
evidence, and tracking active scans. Runs entirely locally.

```bash
0sec dashboard
0sec dashboard --port 48123
```

**Key flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--port <port>` | Port to bind | `48123` |
| `--host <host>` | Host to bind | `127.0.0.1` |
| `--no-open` | Do not auto-open a browser | (opens by default) |
| `--db-path <path>` | Path to SQLite database | `~/.0sec/0sec.db` |

To inspect a run-local database, pass its path explicitly:

```bash
0sec dashboard --db-path ~/.0sec/runs/<run-id>/state.db
```

The dashboard's live integration feed is `GET /api/v1/presentation/events`.
It is a same-origin Server-Sent Events stream of `0sec.presentation/v1` records;
clients may send the last received event ID in `Last-Event-ID` to resume
persisted records. Keep the default loopback host unless the dashboard is behind
an authenticated reverse proxy.

## history

Browse past scans with status, depth, findings count, and duration.

```bash
0sec history
0sec history --limit 20
```

| Flag | Description | Default |
|------|-------------|---------|
| `--limit <n>` | Number of scans to show | `10` |

## timeline

Export a scan's immutable pipeline-event audit trail as a chronological,
technique-mapped forensic record. Built for handing to a client's security team
to cross-reference against their own detections.

```bash
0sec timeline <scanId>
0sec timeline <scanId> --format json
0sec timeline <scanId> --format csv
0sec timeline <scanId> --attack-only
0sec timeline <scanId> --since 2026-09-15T09:00:00Z --until 2026-09-15T17:00:00Z
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
export 0SEC_ENTRA_ACCESS_TOKEN=...
0sec identity --tenant <tenant-guid>
0sec identity --tenant <tenant-guid> --json
```

## adgraph

Offline Active Directory attack-path analysis over a BloodHound CE / SharpHound
JSON export. Never collects, never authenticates, never touches the network.

```bash
0sec adgraph --input ./bloodhound-export/
0sec adgraph --input ./export.json --json
0sec adgraph --input ./export --domain corp.example.com
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
0sec entragraph --input ./azurehound-export/
0sec entragraph --input ./export --json
0sec entragraph --input ./export --owned <objectId>,<objectId>
0sec entragraph --input ./export --max-depth 4
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

Query, filter, and inspect verified findings. Fresh scans store findings in
`~/.0sec/runs/<scan-id>/state.db`; `findings list` aggregates all local runs,
while `--scan <scan-id>` or `--db-path <path>` selects one. Managed findings live
in the control plane, not this local store.

```bash
# List all findings
0sec findings list

# Filter by severity
0sec findings list --severity critical

# Filter by category and status
0sec findings list --category prompt-injection --status confirmed

# Inspect a specific finding with full evidence
0sec findings show NF-001

# Triage findings
0sec findings accept <finding-id> --note "confirmed and tracked"
0sec findings suppress <finding-id> --note "known test fixture"
0sec findings reopen <finding-id>
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
0sec verify --finding finding.json

# Run the deterministic CLI path traversal fixture against the CLI under test
0sec verify --fixture cli-path-traversal \
  --fixture-command '["paperclip","company","export","--api","{{apiUrl}}","--output","{{exportDir}}"]'

# Keep the sandbox, harness metadata, and stdout/stderr logs
0sec verify --fixture cli-path-traversal \
  --fixture-command '["paperclip","company","export","--api","{{apiUrl}}","--output","{{exportDir}}"]' \
  --retain-artifacts
```

The `cli-path-traversal` fixture starts a malicious local API and runs the
supplied CLI command against a temp export dir. It only supplies `{{apiUrl}}` and
`{{exportDir}}`, records stdout/stderr, and checks whether a marker file escapes
the export root while staying inside the sandbox.

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

Read-only HackerOne hacker-API helpers — verify credentials, browse programs, and export a program's scope into the 0sec scope-file format.

Credentials live at `~/.0sec/h1.env` (or `~/.0sec/h1/<identifier>.env`) with format `H1_IDENTIFIER=<token-name>` and `H1_TOKEN=<44-char-value>`. The token is used as the password and the identifier as the username over HTTP Basic auth; nothing is ever written to logs.

```bash
# Verify credentials
0sec h1 auth

# List visible programs (bounty-paying only)
0sec h1 programs list --bounty --limit 50

# List public-mode VDP programs as JSON
0sec h1 programs list --vdp --state public_mode --json

# Show one program with scope summary
0sec h1 programs show flutteruki

# Export structured_scopes to ~/.0sec/scopes/<handle>.json
# (consumed by `0sec scan --scope <path>`)
0sec h1 scope dump flutteruki
```

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `auth` | Verify HackerOne API credentials against `/v1/hackers/payments/balance` |
| `programs list` | List visible programs. Flags: `--bounty`, `--vdp` (mutually exclusive), `--state <s>`, `--limit <n>` (max 1000), `--json` |
| `programs show <handle>` | Show a single program's details with a structured-scope summary |
| `scope dump <handle>` | Write the program's `structured_scopes` to `~/.0sec/scopes/<handle>.json` (override with `--out`); non-network asset types and malformed identifiers are dropped with a warning |

**Exit codes:** `0` ok · `1` user/data error · `2` auth failure (missing creds or HTTP 401) · `3` rate-limit / network error.

## intel

Live vulnerability-intelligence lookup helpers for advisory-aware audits and
variant-hunt context.

```bash
# Build a package intel dossier with risk summary, advisories, prior-vuln playbooks, variants, and graph
0sec intel dossier formidable --ecosystem npm --package-version 3.5.2 --json

# Search package advisories through OSV/GitHub, enriched with NVD/CISA KEV
0sec intel search formidable --ecosystem npm --package-version 3.5.2

# Look up a CVE with NVD + CISA KEV context
0sec intel cve CVE-2024-1086

# Find related CVEs/advisories for variant-hunt context
0sec intel similar --cwe CWE-22 --keywords "zip slip,path traversal" --json

# Search CVEs/GHSAs already reported against the same target/project
0sec intel target-history --repository expressjs/express --ecosystem npm --package express --json

# Infer target-history hints from a local source checkout
0sec intel target-history --repo-path ./my-project --json
```

Audit and review agents get the same lookups as tools (`intel_build_dossier`,
`intel_search_target_history`, `intel_search_advisories`, `intel_lookup_cve`,
`intel_search_similar`) and should use them before citing CVEs from memory. Intel
results are leads until backed by deterministic package/version evidence or local
verification. Dossier and target-history results carry prior-vulnerability
playbooks plus an `auditGraph` that turns historical bug shapes into ordered
source/sink/guard/verification steps.

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `dossier <package>` | Build a package-level risk dossier with prior-vulnerability playbooks. Flags: `--ecosystem <e>`, `--package-version <v>`, `--ver <v>`, `--keywords <csv>`, `--similar-limit <n>`, `--no-similar`, `--offline`, `--cache-dir <path>`, `--json` |
| `search <package>` | Search package advisories. Flags: `--ecosystem <e>`, `--package-version <v>`, `--ver <v>`, `--no-enrich`, `--offline`, `--cache-dir <path>`, `--json` |
| `cve <cve-id>` | Look up one CVE through NVD and CISA KEV. Flags: `--offline`, `--cache-dir <path>`, `--json` |
| `similar` | Search related advisories by `--cwe`, `--keywords <csv>`, optional `--ecosystem`, `--limit <n>`, `--offline`, `--cache-dir <path>`, and `--json` |
| `target-history [target]` | Search prior CVEs/GHSAs reported against a target. Infers package/repo/product hints from local metadata when `--repo-path <path>` is given (reads `package.json`, `pyproject.toml`, `Cargo.toml`, `go.mod`, `.git/config`). Explicit flags override inferred values. Flags: `--repo-path <path>`, `--repository <owner/repo>`, `--ecosystem <e>`, `--package <pkg>`, `--product <p>`, `--vendor <v>`, `--keywords <csv>`, `--limit <n>`, `--offline`, `--cache-dir <path>`, `--json` |

## auth

0sec-cloud authentication — login, logout, and verify a scoped CLI token against the cloud `/health` endpoint.

> **Scaffold notice (issue [#303](https://github.com/0sec-labs/0sec/issues/303)):** this command is the CLI half of cloud auth. The server-side mint endpoint that issues scoped tokens after the browser-based better-auth flow lives in 0sec-cloud and is shipped in a separate PR. Until that lands, the browser flow (`0sec auth login` without `--token`) will time out. Use `0sec auth login --token <value>` to paste a token directly — this is the only working path for now.

Credentials live at `~/.0sec/cloud.env` (chmod 600) with format:

```
0SEC_CLOUD_HOST=https://cloud.0sec.ai
0SEC_CLOUD_TOKEN=<scoped-cli-token>
```

`0SEC_CLOUD_HOST` is optional and defaults to `https://cloud.0sec.ai`. Both keys may also be set as environment variables (`0SEC_CLOUD_HOST` / `0SEC_CLOUD_TOKEN`), which take precedence over the file.

```bash
# Paste a token directly (the only path that works today)
0sec auth login --token <value>

# Browser flow (will time out until #303 server-side ships)
0sec auth login --host https://cloud.0sec.ai

# Verify the configured token against /health
0sec auth status

# Delete ~/.0sec/cloud.env
0sec auth logout
```

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `login` | Open a browser at `<host>/cli-auth?session=…` and poll for a minted token. Flags: `--host <url>`, `--token <value>` (escape hatch — skips the browser). |
| `logout` | Delete `~/.0sec/cloud.env`. Returns 0 even if no file was present. |
| `status` | Load credentials and `GET <host>/health` to verify the token is accepted. |

**Exit codes:** `0` ok · `1` user/data error · `2` auth failure (missing creds or HTTP 401/403) · `3` network error / login timeout.

## XBOW benchmark runner

The XBOW benchmark runner lives in `packages/benchmark` and is invoked with `pnpm --filter @0sec/benchmark xbow`. It runs 0sec against the 104 XBOW validation challenges and reports pass/fail with evidence.

```bash
# Run the whole benchmark
pnpm --filter @0sec/benchmark xbow

# Run a specific subset of challenges
pnpm --filter @0sec/benchmark xbow --only XBEN-010,XBEN-051,XBEN-066

# Skip the first 20 challenges (useful for resuming)
pnpm --filter @0sec/benchmark xbow --start 20

# Include full finding objects in results JSON (for offline analysis)
pnpm --filter @0sec/benchmark xbow --save-findings
```

| Flag | Description | Default |
|------|-------------|---------|
| `--only <ids>` | Comma-separated challenge IDs to run | (all 104) |
| `--start <n>` | Skip the first `n` challenges | `0` |
| `--save-findings` | Include full finding objects in the results JSON | `false` |

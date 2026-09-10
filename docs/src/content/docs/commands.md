---
title: Commands
description: Complete 0sec CLI command and subcommand reference, including registered options, aliases, defaults, and workflow boundaries.
tableOfContents:
  minHeadingLevel: 2
  maxHeadingLevel: 2
---

Find the command, arguments, and options for your task. This reference covers
**53 top-level commands** and their registered subcommands.

For a worked example, start with [Scan Workflows](/scan-workflows/),
[Console](/console/), or [Research Workflows](/research-workflows/).

## Start by task

<div class="docs-task-grid">
  <section class="docs-task-card">
    <h3>Scan and review</h3>
    <p>Assess a live target, a repository, or a package.</p>
    <p><a href="#scan">scan</a> · <a href="#review">review</a> · <a href="#audit">audit</a> · <a href="#file-review">file-review</a></p>
  </section>
  <section class="docs-task-card">
    <h3>Work interactively</h3>
    <p>Open the console, configure your environment, and diagnose setup.</p>
    <p><a href="#console">console</a> · <a href="#config">config</a> · <a href="#doctor">doctor</a></p>
  </section>
  <section class="docs-task-card">
    <h3>Review the evidence</h3>
    <p>Inspect findings, reproduce an issue, and validate a source fix.</p>
    <p><a href="#findings">findings</a> · <a href="#triage">triage</a> · <a href="#verify">verify</a> · <a href="#fix">fix</a></p>
  </section>
  <section class="docs-task-card">
    <h3>Continue a run</h3>
    <p>Find a past scan, continue execution, or replay stored results.</p>
    <p><a href="#history">history</a> · <a href="#resume">resume</a> · <a href="#replay">replay</a></p>
  </section>
  <section class="docs-task-card">
    <h3>Investigate further</h3>
    <p>Use specialized discovery, source review, and research workflows.</p>
    <p><a href="#research">research</a> · <a href="#deep-review">deep-review</a> · <a href="#hunt">hunt</a> · <a href="#memsafety">memsafety</a></p>
  </section>
  <section class="docs-task-card">
    <h3>Connect and automate</h3>
    <p>Configure integrations, queued work, and cloud authentication.</p>
    <p><a href="#mcp-server">mcp-server</a> · <a href="#orchestrate">orchestrate</a> · <a href="#auth">auth</a></p>
  </section>
</div>

## Invocation and safety

Run commands as `0sec <command>`; `0` is the installed alias. Check your
release with `0sec --version` and command-specific `--help`.

Option tables show registration defaults. **— means no default is registered**:
a handler may resolve configuration or require an explicit value. Inverse
`--no-*` options show the underlying positive boolean default. See
[Configuration](/configuration/) for environment and runtime resolution.

- No arguments opens the Bun interactive interface; Node prints installation guidance. See [Console](/console/).
- `0 -r [id]` / `0 --resume [id]` route to console-session resume; `0 -c` / `0 --continue` reopen the newest console session; `0 -p` / `0 --print` run a single console prompt. These are not scan-resume aliases.
- Bare targets are routed where recognizable. Prefer an explicit command in automation; ambiguous input is refused rather than guessed.
- Every command supports `--help`. Options belong to the documented command, not to all commands globally.
- Scope, provider authentication, target authentication, filesystem access, and execution isolation are different controls. Start with [Scope & Authorization](/scope/).
- A completed command is not necessarily a reproduced finding. Read each workflow’s outcome semantics; verification exit codes vary by path.
- A report export, plugin invocation, disclosure action, or queued worker can perform external writes or execute code. Inspect its inputs and permissions before running it.

## Interactive & setup

### console

Interactive chat console — talk to the engine and drive the full tool registry (recon, web, source-scan, variant-hunt, verify, patch-gen) from one prompt.

```text
0sec console [options]
```

Full TUI use requires Bun and a usable TTY. Headless/readline approval limitations are documented in [Console](/console/). Model credentials, target scope, and managed-service credentials are separate.

Guide: [Read the workflow](/console/).

| Option | Registered default | Description |
| --- | --- | --- |
| `--target <url>` | — | Engagement target the tools operate against (optional; can be named in-chat) |
| `--scope <file>` | — | Initial authorization scope; required for the Node fallback (optional otherwise) |
| `--finding <id>` | — | Focus the chat on one persisted finding |
| `--finding-intent <intent>` | — | Finding workflow: investigate, verify, or draft_fix |
| `--db-path <path>` | — | Database containing --finding |
| `-m, --model <id>` | — | Override the LLM model id (else provider default) |
| `--role <role>` | — | Tool set to expose: audit\|review\|discovery\|attack\|verify (default audit = every tool) |
| `--mode <mode>` | — | Autonomy mode to start in: standard\|recon\|copilot\|yolo (default standard). YOLO drops per-action prompts but stays target/scope-anchored; cycle live with Shift+Tab. |
| `--yolo` | — | Shortcut for --mode yolo — start the console in YOLO autonomy (no per-action prompts; still target-anchored and SSRF-railed). |
| `--autonomy <mode>` | `standard` | Alias of --mode (standard\|copilot\|yolo\|recon); --mode/--yolo take precedence. |
| `--max-tool-calls <n>` | `20` | Safety cap on tool-call rounds per operator message |
| `--allow-scanners` | — | Expose generic-scanner tool wrappers (sqlmap/nikto/…); default off |
| `--resume [id]` | — | Reopen a saved console session by id (or unique prefix); with no id, opens a session picker. Also reachable as `0 -r [id]`. |
| `--continue` | — | Reopen the most recent console session, no picker. Also reachable as `0 -c`. |
| `-p, --print [prompt]` | — | Non-interactive: run ONE prompt through the engine, print the result, and exit (no TUI). Reads the prompt from the argument or piped stdin. Combine with --continue/--resume to query a saved session. Also reachable as `0 -p &lt;prompt&gt;`. |

#### Slash commands

See [Console](/console/) for the actual slash-command surface and readline differences.

#### Keybindings

See [Console keyboard shortcuts](/console/#keyboard-shortcuts).

#### Autonomy modes

See [Console](/console/) for Standard, Recon, Co-pilot, and YOLO behavior. No mode grants testing authorization.

#### Approval prompts

Tool, network-scope, and directory approvals are distinct gates; headless execution cannot approve an interactive request. See [Console](/console/).

#### Session persistence

Console transcript resume differs from scan journal continuation. See [Console](/console/) and [Scan Workflows](/scan-workflows/).

#### Console settings

The canonical settings reference is [Configuration](/configuration/).

### tui

Open the unified engagement control plane (Bun-only)

```text
0sec tui
```

Aliases: `watch`.

Guide: [Read the workflow](/console/).

### dashboard

Run a local mission-control dashboard for scans and findings

```text
0sec dashboard [options]
```

Guide: [Read the workflow](/architecture/#presentation-contract).

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--port <port>` | `48123` | Port to bind; 0 chooses a free loopback port |
| `--host <host>` | `127.0.0.1` | Loopback host to bind (127.0.0.0/8 or ::1) |
| `--asset-dir <path>` | — | Path to built dashboard assets |
| `--ready-json` | — | Emit the bound dashboard URL as machine-readable JSON |
| `--no-open` | — | Do not auto-open a browser |

### doctor

Check local runtime prerequisites and suggest the next command

```text
0sec doctor
```

Guide: [Read the workflow](/troubleshooting/).

### config

Inspect, export, and import the two-level console configuration

```text
0sec config
```

Guide: [Read the workflow](/configuration/).

Subcommands: [show](#config-show) · [export](#config-export) · [import](#config-import).

#### config show

Show the effective config with the source layer (default/global/project) per key

```text
0sec config show
```

#### config export

Write the effective (or --global) config as shareable JSON (stdout if no file)

```text
0sec config export [options] [file]
```

| Argument | Required | Description |
| --- | --- | --- |
| `file` | No |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--global` | — | Export only the global layer instead of the effective config |

#### config import

Merge a shared config into the global (default) or --project layer

```text
0sec config import [options] <file>
```

| Argument | Required | Description |
| --- | --- | --- |
| `file` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--project` | — | Import into the per-project override instead of the global config |
| `--global` | — | Import into the global config (default) |
| `--yes` | — | Accept changes to security-sensitive settings (required to flip them) |

### theme

List, install, apply, export, and remove console colour themes

```text
0sec theme
```

Guide: [Read the workflow](/console/).

Subcommands: [list](#theme-list) · [install](#theme-install) · [apply](#theme-apply) · [export](#theme-export) · [remove](#theme-remove).

#### theme list

List built-in and installed themes (marks the active + default)

```text
0sec theme list
```

#### theme install

Fetch + validate + write a theme from the configured registry (installs data; runs no code)

```text
0sec theme install [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--registry <url>` | — | Theme registry index URL (https) |

#### theme apply

Set the console theme (a built-in name or an installed id)

```text
0sec theme apply [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--project` | — | Write the choice to the per-project override instead of the global config |
| `--global` | — | Write the choice to the global config |

#### theme export

Emit a built-in or installed theme as a shareable theme manifest JSON (stdout if no file)

```text
0sec theme export <id> [file]
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |
| `file` | No |  |

#### theme remove

Delete an installed theme (built-ins cannot be removed)

```text
0sec theme remove <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

### upgrade

Fetch and install the latest 0sec binary (re-runs install.sh)

```text
0sec upgrade [options]
```

Guide: [Read the workflow](/getting-started/).

| Option | Registered default | Description |
| --- | --- | --- |
| `--version <tag>` | — | Pin a specific release tag (e.g. v0.10.0) |
| `--install-dir <path>` | — | Override the install directory (default: ~/.0sec/bin) |

## Scan & source review

### scan

Run autonomous pentest against a URL, web app, or MCP server

```text
0sec scan [options]
```

Live HTTP/HTTPS/MCP targets require an engagement policy even when `--require-scope` is omitted. Use [Scope & Authorization](/scope/). `--dry-run` applies only to PR emission; it does **not** prevent the scan from executing. `--race` is for benchmark/CTF workflows. An explicit rate specification can override the conservative scan profile’s fallback rate.

Guide: [Read the workflow](/scan-workflows/).

| Option | Registered default | Description |
| --- | --- | --- |
| `--target <target>` **required** | — | Target URL or mcp:// endpoint |
| `--depth <depth>` | `default` | Scan depth: quick, default, deep |
| `--format <format>` | `terminal` | Output format: terminal, json, md, html, sarif, pdf |
| `--runtime <runtime>` | `auto` | Runtime: auto (default), api, claude, codex, gemini |
| `--mode <mode>` | — | Scan mode: probe, deep, mcp, web, http_audit. `http_audit` is the worker-driven authed HTTP scan: it reads target config from 0SEC_TARGET_* env vars (0SEC_TARGET_BASE_URL, 0SEC_TARGET_AUTH_JSON, 0SEC_TARGET_ALLOWED_HOSTS, 0SEC_TARGET_ALLOWED_PATHS, 0SEC_TARGET_RATE_LIMIT_RPS, 0SEC_TARGET_KILL_AFTER_SEC), builds an in-memory ScopePolicy + path allowlist + per-host RateLimiter + wall-clock kill switch, runs the web-pentest loop, and emits an enforcement_summary block in the report JSON. |
| `--timeout <ms>` | `30000` | Request timeout in milliseconds |
| `--db-path <path>` | — | Path to SQLite database |
| `--api-key <key>` | — | API key for LLM provider |
| `-m, --model <model>` | — | LLM model to use |
| `--repo <path>` | — | Source code path for white-box scanning (read code before attacking) |
| `--auth <json>` | — | Auth credentials as JSON string or path to JSON file (types: bearer, cookie, basic, header) |
| `--scope <path>` | — | Path to a JSON scope file ({in_scope, out_of_scope} arrays of host / *.domain / cidr rules). Out-of-scope URLs return as ToolResult.error at every fetch site. See 0sec#215. |
| `--allow-scanners` | `false` | Disable the generic-scanner suppression gate (0sec#217). When --scope is set, the agent refuses to spawn sqlmap/wpscan/nikto/gobuster/dirb/wfuzz/ffuf/`nmap -sV`/`nmap -A` by default; pass this flag only when the engagement explicitly permits generic-scanner traffic. |
| `--require-scope` | `false` | Set 0SEC_REQUIRE_SCOPE for scope-aware execution paths. Ordinary live-target scan already refuses missing scope, independently of this flag. |
| `--attribution-header <name=value>` | — | Attribution header to attach to in-scope outbound requests (0sec#216). Repeatable: pass `--attribution-header X-A=1 --attribution-header X-B=2`. Lower precedence than the scope file's `attribution.headers` block and 0SEC_ATTRIBUTION_HEADERS env var. NEVER attached to out-of-scope traffic. |
| `--attribution-ua <token>` | — | Engagement token to embed in the User-Agent on in-scope traffic (0sec#216). Resulting UA: `0sec/&lt;ver&gt; (engagement: &lt;token&gt;)`. Lower precedence than the scope file's `attribution.user_agent_token` and 0SEC_ATTRIBUTION_UA_TOKEN env var. |
| `--api-spec <path>` | — | Path to OpenAPI 3.x / Swagger 2.0 spec file (JSON or YAML) for pre-loaded endpoint knowledge |
| `--export <target>` | — | Export findings to issue tracker (e.g. github:owner/repo) |
| `--race` | `false` | Enable benchmark/CTF best-of-N strategy racing: run multiple flag-oriented attack strategies in parallel. Do not use for normal live-target audits. |
| `--egats` | `false` | Enable EGATS (Evidence-Gated Attack Tree Search): beam-search over a hypothesis tree |
| `--cost-ceiling <usd>` | — | Hard per-scan USD cost ceiling. Aborts cleanly with partial findings if exceeded. Overrides 0SEC_COST_CEILING_USD. |
| `--rate-limit <spec>` | — | Per-host requests-per-second cap for outbound scan traffic. Plain number (e.g. '5') sets the default rps; comma-separated form 'api.example.com=5,*.example.com=3:6,2' allows per-host overrides and a fallback default. Default is 5 rps when unset. Each host carries an independent token bucket; 429 responses honour Retry-After (with a conservative 60s floor). |
| `--engagement-profile <name>` | — | Engagement hardening posture for authorized enterprise work. 'standard' (default) is the existing behaviour. 'conservative' applies ONE quiet posture: no password-reset burst probe, the deterministic web-recon pre-pass routed through the per-host rate limiter, no adaptive WAF-evasion ladder, full jitter on the token bucket, and a reduced default of 1 rps/host. The applied posture is recorded in the report as `engagementPosture` so it can be handed to the client as evidence. Lower precedence than the scope file's `engagement` block and 0SEC_ENGAGEMENT_PROFILE. |
| `--no-waf-evasion` | — | Disable the adaptive WAF-evasion ladder (default: on). When a response classifies as blocked, the engine normally retries with encoding/casing/whitespace-mutated payload variants, which escalates a routine WAF block into a SOC incident. Detection and reporting of the block are unaffected. Independent of --engagement-profile; env form: 0SEC_WAF_EVASION=0. |
| `--tui` | `false` | Open the local terminal UI after the scan completes |
| `--features <list>` | — | Comma-separated list of opt-in feature flags to enable for this scan (e.g. 'wp_fingerprint,web_search'). Each flag maps to the corresponding 0SEC_FEATURE_&lt;NAME&gt; environment variable. The token 'fp-moat' is a preset that enables the full false-positive moat (reachability, multi-modal, publishability, pov-gate, poc-gen, consensus) for an A/B run; an env var you set yourself always wins over the preset, so '0SEC_FEATURE_POV_GATE=0 --features fp-moat' is a single-layer ablation. |
| `--no-decoy-detection` | — | Disable the anti-honeypot flag-shape validator (default: on). When enabled, the `done` tool rejects low-confidence flags (e.g. `FLAG{I'm_a_Script_Kiddie}`) once with a hint to keep exploring. See GitHub issue #82. |
| `--dispatch <mode>` | `auto` | Tool-call protocol for the legacy text agent loop (0sec#232): 'json' (default TOOL_CALL JSON lines), 'xml' (&lt;command&gt;/&lt;flag&gt;/&lt;finding&gt;/&lt;note&gt; tags — survives malformed JSON from cheap OpenRouter / Gemini / DeepSeek models), or 'auto' (xml for cheap providers, json otherwise). No effect on the native API loop. Env override: 0SEC_DISPATCH=xml. |
| `--emit <target>` | — | Emit target. Default unset → existing terminal/json/etc. `pr` → emit each reproduced finding as a GitHub PR with repro + suggested patch (0sec#377). Unverified findings roll up into `hypotheses.md`. |
| `--base <branch>` | — | Base branch for `--emit pr` (default: main) |
| `--dry-run` | `false` | For --emit pr only: print proposed git/gh emission commands. The scan itself still executes. |
| `--emit-out-dir <path>` | — | Directory for `--emit pr` rollup files (default: system temp) |
| `--resume <run-id>` | — | Resume a previous run from its journal on disk (0sec#374). Locates the run's journal, rehydrates agent state, and continues from the last entry. |
| `--branch-from <entry-index>` | — | Branch the journal at the given entry index before resuming (requires --resume). Copies entries 0..N into a new run and resumes from there. |
| `--verbose` | `false` | Show detailed output |
| `--replay` | `false` | Replay the last scan's results |

#### `--auth` credential formats

`scan --auth` accepts inline JSON or a JSON file. Use a restricted file for real secrets. Choose one shape:

| Type | JSON value |
| --- | --- |
| Bearer | `{"type":"bearer","token":"test-token"}` |
| Cookie | `{"type":"cookie","value":"session=test-session"}` |
| Basic | `{"type":"basic","username":"test-user","password":"test-password"}` |
| Header | `{"type":"header","name":"X-API-Key","value":"test-key"}` |

#### `--api-spec` — OpenAPI / Swagger import

Seeds endpoint knowledge; does not replace authorization. See [Recipes](/recipes/).

#### `--race` — best-of-N strategy racing

Benchmark/CTF-oriented strategy racing, not a normal live-target audit setting.

#### `--egats` — Evidence-Gated Attack Tree Search

Opt-in hypothesis-tree search; not a default verification guarantee. See [Finding Triage](/triage/).

#### `--cost-ceiling` — hard spend guardrail

See [Budget Management](/budget-management/) for spend versus turn limits and partial outcomes.

#### `--export github:owner/repo`

Creates external GitHub issues. Review destination, permissions, and sensitive evidence first; see [Integrations](/integrations/).

### audit

Audit a package for security vulnerabilities

```text
0sec audit [options] <package>
```

Guide: [Read the workflow](/scan-workflows/).

| Argument | Required | Description |
| --- | --- | --- |
| `package` | Yes | package name (e.g. lodash, express, requests) |

| Option | Registered default | Description |
| --- | --- | --- |
| `--ecosystem <ecosystem>` | `npm` | Package ecosystem: npm, pypi, cargo, oci |
| `--package-version <version>` | — | Specific package version to audit (default: latest) |
| `--pkg-version <version>` | — | Alias for --package-version |
| `--ver <version>` | — | Alias for --package-version |
| `--depth <depth>` | `default` | Audit depth: quick, default, deep |
| `--format <format>` | `terminal` | Output format: terminal, json, md, html, sarif, pdf |
| `--runtime <runtime>` | `auto` | Runtime: auto, claude, codex, gemini, api |
| `--db-path <path>` | — | Path to SQLite database |
| `--api-key <key>` | — | API key for LLM provider |
| `-m, --model <model>` | — | LLM model to use |
| `--cost-ceiling <usd>` | — | Hard per-audit USD cost ceiling. Aborts cleanly with partial findings if exceeded. |
| `--tui` | `false` | Open the local terminal UI after the audit completes |
| `--resume <run-id>` | — | Resume a previous run from its journal on disk (0sec#374) |
| `--branch-from <entry-index>` | — | Branch the journal at the given entry index before resuming (requires --resume). |
| `--verbose` | `false` | Show detailed output |
| `--timeout <ms>` | `600000` | AI agent timeout in milliseconds |

### review

Deep source code security review of a repository

```text
0sec review [options] <repo>
```

Static leads and AI review are not proof of runtime exploitation. `--changed-only` affects static leads/prioritization; it is not a filesystem sandbox around the model. Target credentials are not configured with `review --auth` (that option does not exist).

Guide: [Read the workflow](/scan-workflows/).

| Argument | Required | Description |
| --- | --- | --- |
| `repo` | Yes | Local path or git URL to review |

| Option | Registered default | Description |
| --- | --- | --- |
| `--depth <depth>` | `default` | Review depth: quick, default, deep |
| `--format <format>` | `terminal` | Output format: terminal, json, md, html, sarif, pdf |
| `--runtime <runtime>` | `auto` | Runtime: auto, claude, codex, gemini, api, ollama |
| `--db-path <path>` | — | Path to SQLite database |
| `--api-key <key>` | — | API key for LLM provider |
| `-m, --model <model>` | — | LLM model to use |
| `--cost-ceiling <usd>` | — | Hard per-review USD cost ceiling. Aborts cleanly with partial findings if exceeded. |
| `--tui` | `false` | Open the local terminal UI after the review completes |
| `--diff-base <ref>` | — | Git base ref to review against (for diff-aware review) |
| `--changed-only` | `false` | Restrict static scanner leads + prioritization to changed files |
| `--profile <profile>` | `default` | Review profile: default (web/JS/TS/Python), c-library (C/C++ memory safety, tier-1/2/3 harness), linux-kernel (kernel-aware static review), cardano-onchain (Aiken/Plutus validator logic), solana-onchain (Anchor/native Rust account-model authorization), evm-onchain (Solidity/Foundry/Hardhat DeFi/bridge — reentrancy, oracle manipulation, cross-chain replay), cairo-onchain (Cairo/Starknet DeFi — caller-auth gaps, share-rounding, L1↔L2 messages), move-onchain (Sui/Aptos Move — object/capability binding, shared-math overflow, reward-index accounting), cardano-haskell (first-party Cardano Haskell node stack — ledger/plutus/ouroboros/cardano-base), xnu-kernel (Apple XNU macOS/iOS source review), or xnu-re (decompiled Apple kext pseudo-C) |
| `--target <target>` | — | Review target alias: app/default, c-library, or linux-kernel |
| `--ecosystem <ecosystem>` | — | Review the SOURCE of a published package instead of a repo: npm, pypi, cargo, or oci. When set, &lt;repo&gt; is the package NAME — 0sec installs it and reviews its extracted source. Omit for a local path or git URL. |
| `--package-version <version>` | — | Pin the package version to review (only with --ecosystem). Defaults to latest. |
| `--seed-findings <path>` | — | Path to ND-JSON leads from an external producer. "-" reads stdin. Schema: gemmaforge.leads/v1. Tracked: 0sec#368. |
| `--seed-only` | `false` | Skip static scanner prioritisation and rely solely on --seed-findings. Only meaningful when --seed-findings is set. |
| `--emit <target>` | — | Emit target. Default unset → existing terminal/json/etc. `pr` → emit each reproduced finding as a GitHub PR with repro + suggested patch (0sec#377). Unverified findings roll up into `hypotheses.md`. |
| `--base <branch>` | — | Base branch for `--emit pr` (default: main) |
| `--dry-run` | `false` | For --emit pr only: print proposed git/gh emission commands. The source review itself still executes. |
| `--emit-out-dir <path>` | — | Directory for `--emit pr` rollup files (default: system temp) |
| `--harness-tier <tier>` | `1` | C/C++ harness tier to construct: 1 (single-function libFuzzer, default), 2 (multi-component linker), 3 (Tier-2 build + QEMU sanitizer validation). |
| `--harness-function <name>` | — | Tier-2 only: name of the suspect function the harness should drive. Defaults to a heuristic placeholder. |
| `--harness-header <path>` | — | Tier-2 only: header to #include in the emitted harness. Defaults to the function name with a .h suffix. |
| `--harness-build-system <system>` | `auto` | Tier-2 only: build system to grep-parse for object subset (autotools, cmake, meson, auto). |
| `--harness-sanitizers <list>` | — | Tier-2 only: comma-separated sanitizers to enable (asan, ubsan, msan). Default: asan,ubsan. |
| `--harness-out <dir>` | — | Tier-2 only: output directory for the emitted harness + linker fragment. Defaults to &lt;repo&gt;/.0sec-out/tier2. |
| `--harness-qemu-kernel <path>` | — | Tier-3 only: pre-built kernel image. Defaults to 0SEC_KERNEL_QEMU_KERNEL. |
| `--harness-qemu-disk <path>` | — | Tier-3 only: pre-built rootfs image. Defaults to 0SEC_KERNEL_QEMU_DISK. |
| `--harness-wall-clock-ms <ms>` | — | Tier-3 only: wall-clock budget in milliseconds for the full QEMU validation. Default 300000 (5m). |
| `--subsystem <path>` | — | Restrict the review to a specific subsystem directory (e.g. crypto/, net/tcp/). Only meaningful with --profile linux-kernel. |
| `--hypothesis <text>` | — | Operator hypothesis to seed the agent with a specific research direction. Modeled after Xint Code's operator prompt. |
| `--conversation <text>` | — | PR/MR discussion thread to review against (untrusted). The latest message drives this run. |
| `--prior-findings <path>` | — | JSON array of prior findings. Fresh review treats it as untrusted context and investigates variants without repeating the originals. |
| `--fix-commit <sha>` | — | Analyze a security-fix commit and hunt for structurally similar unpatched code paths (variant hunting). Requires a local git repo. Resolves the commit to its full SHA and first-parent preimage. When used alone, feeds candidates as SeedFindings into the review pipeline. Combine with --variants-only to emit candidates as JSON without model/network calls. |
| `--variants-only` | `false` | Emit full variant-hunt result as JSON (candidates, language coverage, errors) and exit. Requires --fix-commit. No model, cloud, or network calls are made. |
| `--npm-dynamic` | `false` | Also run the npm dynamic-discovery detector sweep (SSPP fuzz / validation read-stability / SSRF parser-diff) over the package in a disposable sandbox. Only effective with --ecosystem npm. Confirmed leads flow into the same verify → disclosure path. |
| `--resume <run-id>` | — | Resume a previous run from its journal on disk (0sec#374) |
| `--branch-from <entry-index>` | — | Branch the journal at the given entry index before resuming (requires --resume). |
| `--verbose` | `false` | Show detailed output |
| `--timeout <ms>` | `600000` | AI agent timeout in milliseconds |

#### Review profiles

Profiles select specialized review behavior and prerequisites. See [Scan Workflows](/scan-workflows/) and [Research Workflows](/research-workflows/). Static kernel review does not itself boot a VM or prove a crash.

### file-review

Whole-repo file-level security review: regex scan → coverage gate → batched AI investigation (refusal audit, field repair) → optional static revalidation. Resumable: exit code 3 means a cost/duration limit stopped the run at a checkpoint — re-run the same command to continue.

```text
0sec file-review [options] <target>
```

Guide: [Read the workflow](/research-workflows/).

| Argument | Required | Description |
| --- | --- | --- |
| `target` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--project-id <id>` | — | Project id (defaults to the target basename) |
| `--data-dir <path>` | — | Record store directory (default &lt;target&gt;/.0sec-review) |
| `--runtime <mode>` | — | Engine runtime: api\|claude\|codex\|gemini\|ollama (default api) |
| `-m, --model <model>` | — | Model for the investigation/revalidation agents |
| `--timeout <ms>` | `600000` | Per-invocation timeout in milliseconds |
| `--max-cost-usd <usd>` | — | Hard USD cap for the whole run (resumable stop) |
| `--max-duration <dur>` | — | Wall-clock cap: 30m / 2h / ms (resumable stop) |
| `--batch-size <n>` | — | Files per investigation batch (default 5) |
| `--concurrency <n>` | — | Batches in flight (default 2) |
| `--inventory` | — | Generate the AI surface inventory + INFO.md first (requires claude, codex, or gemini) |
| `--revalidate` | — | Run the static adversarial revalidation on HIGH+ findings |
| `--json` | — | Emit the pipeline result as JSON |

### deep-review

Seedless DEPTH review of a source tree: enumerate candidate files, re-hunt each through the profile's specialized finder lenses, and gate survivors through the multi-lens verify quorum. Emits LEADS to verify (not confirmed bugs). Exit 0=sweep completed (with or without leads), 2=skipped (no files / over the review cap), 3=error (bad flags / unreadable target / all finders failed).

```text
0sec deep-review [options] <target>
```

Guide: [Read the workflow](/research-workflows/).

| Argument | Required | Description |
| --- | --- | --- |
| `target` | Yes | Source tree to review (a local path or a git URL) |

| Option | Registered default | Description |
| --- | --- | --- |
| `--profile <p>` | — | Lens profile: evm-onchain \| solana-onchain \| cardano-onchain \| cairo-onchain \| move-onchain (else a generic default lens set) |
| `--subsystem <path>` | — | Narrow the review scope to a subdirectory (respects the 5000-file review cap) |
| `--evolution-config <path>` | — | Use the active source finder with private local execution receipts |
| `--models <a,b>` | — | Comma-separated finder models for diversity (default: single provider model, or $0SEC_DEEP_REVIEW_MODELS) |
| `--attempts <N>` | — | Finder attempts per candidate×lens×model, best-of-N (default 1, or $0SEC_DEEP_REVIEW_ATTEMPTS) |
| `--concurrency <N>` | — | Max finders in flight (default 8) |
| `--cost-ceiling <usd>` | — | Hard scan-wide USD ceiling. Overrides $0SEC_COST_CEILING_USD. |
| `--max-candidates <N>` | — | Cap candidate files hunted, largest-first (default 8, or $0SEC_DEEP_REVIEW_MAX_CANDIDATES) |
| `--threat-model` | — | Enable pre-selection threat-model planner pass (trust-boundary lanes); default OFF |
| `--quorum <N>` | — | Multi-lens verify quorum (default: majority of the verify-lens count) |
| `--format <fmt>` | `json` | Output format (json) |
| `--output <path>` | — | Write the result JSON to this path instead of stdout |
| `--runtime <mode>` | — | Engine runtime (default api) |
| `--timeout <ms>` | `600000` | Cloud agent timeout budget in milliseconds |

### fix

Generate, source-retest, and optionally apply a scoped fix for one reproduced source finding

```text
0sec fix [options] <repo>
```

Guide: [Read the workflow](/scan-workflows/).

| Argument | Required | Description |
| --- | --- | --- |
| `repo` | Yes | Clean local Git worktree containing the affected source file |

| Option | Registered default | Description |
| --- | --- | --- |
| `--finding <path>` | — | Path to an external finding JSON with verificationSpec |
| `--finding-id <id>` | — | Persisted finding ID (full ID or unique prefix) |
| `--db-path <path>` | — | Database containing --finding-id |
| `--verification-result <path>` | — | Optional verification_result JSON from `0sec verify`; required when the finding does not already carry one |
| `--test-command <command>` **required** | — | Explicit regression command to run in the isolated candidate worktree |
| `--runtime <runtime>` | `auto` | Fix runtime: auto or api |
| `-m, --model <model>` | — | Model identifier for the selected runtime |
| `--api-key <key>` | — | API key for the selected runtime |
| `--timeout <ms>` | `600000` | Per-model-call timeout in milliseconds |
| `--test-timeout <ms>` | `300000` | Regression-command timeout in milliseconds |
| `--max-attempts <n>` | `3` | Maximum candidate patches; capped at 3 |
| `--apply` | `false` | Apply only a patch that passed isolated source recheck and regression command |
| `--output <path>` | — | Write the validated apply_patch DSL to this path |

## Runs, findings & evidence

### history

Show past scan history from run-local SQLite databases

```text
0sec history [options]
```

Guide: [Read the workflow](/scan-workflows/).

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to one SQLite database |
| `--limit <n>` | `10` | Number of scans to show |

### resume

Resume a previous scan from persisted state

```text
0sec resume [options] <scanId>
```

Resume needs the original persisted state and supported target routing. Authorization and credentials must still be valid; saved state does not grant permission. See [Scan Workflows](/scan-workflows/) before resuming a live target.

Guide: [Read the workflow](/scan-workflows/).

| Argument | Required | Description |
| --- | --- | --- |
| `scanId` | Yes | Scan ID to resume |

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--format <format>` | — | Output format override: terminal, json, md, html, sarif, pdf |
| `--runtime <runtime>` | — | Runtime override: auto, claude, codex, gemini, api |
| `--timeout <ms>` | — | AI agent timeout override in milliseconds |
| `--api-key <key>` | — | API key for LLM provider |
| `-m, --model <model>` | — | LLM model to use |
| `--branch-from <entry-index>` | — | Branch the journal at the given entry index before resuming. Copies entries 0..N into a new run and resumes from there. |

### replay

Replay the last scan's attack chain as an animated terminal sequence

```text
0sec replay [options]
```

Guide: [Read the workflow](/scan-workflows/).

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--scan <scanId>` | — | Replay a specific scan by ID (default: last scan) |

### findings

Browse and manage persisted findings

```text
0sec findings [options]
```

Human triage (`new`, `accepted`, `suppressed`) is independent of verification state. Accepting a finding is an operator decision, not a reproduction or fix-verification step.

Guide: [Read the workflow](/scan-workflows/).

Subcommands: [list](#findings-list) · [show](#findings-show) · [accept](#findings-accept) · [suppress](#findings-suppress) · [reopen](#findings-reopen).

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--scan <scanId>` | — | Filter by scan ID |
| `--severity <severity>` | — | Filter by severity: critical, high, medium, low, info |
| `--category <category>` | — | Filter by attack category |
| `--status <status>` | — | Filter by status: discovered, verified, confirmed, scored, reported, fixed, false-positive |
| `--triage <triage>` | — | Filter by triage: new, accepted, suppressed |
| `--limit <n>` | `50` | Max findings/groups to show |
| `--all` | `false` | Show raw finding rows instead of grouped fingerprints |

#### findings list

List findings from the database

```text
0sec findings list [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--scan <scanId>` | — | Filter by scan ID |
| `--severity <severity>` | — | Filter by severity: critical, high, medium, low, info |
| `--category <category>` | — | Filter by attack category |
| `--status <status>` | — | Filter by status: discovered, verified, confirmed, scored, reported, fixed, false-positive |
| `--triage <triage>` | — | Filter by triage: new, accepted, suppressed |
| `--limit <n>` | — | Max findings/groups to show |

#### findings show

Show detailed information about a finding

```text
0sec findings show [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes | Finding ID (full or prefix) |

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |

#### findings accept

Mark a finding family as accepted

```text
0sec findings accept [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes | Finding ID (full or prefix) |

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--note <text>` | — | Optional triage note |

#### findings suppress

Suppress a finding family across duplicate occurrences

```text
0sec findings suppress [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes | Finding ID (full or prefix) |

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--note <text>` | — | Suppression reason |

#### findings reopen

Reset a finding family back to new

```text
0sec findings reopen [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes | Finding ID (full or prefix) |

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--note <text>` | — | Optional triage note |

### triage

Triage findings and manage learned FP memories

```text
0sec triage
```

Guide: [Read the workflow](/triage/).

Subcommands: [memory](#triage-memory) · [mark-fp](#triage-mark-fp).

#### triage memory

Manage Semgrep-style triage memories

```text
0sec triage memory
```

Subcommands: [add](#triage-memory-add) · [list](#triage-memory-list) · [remove](#triage-memory-remove).

#### triage memory add

Create a memory from an existing finding

```text
0sec triage memory add [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--finding <id>` **required** | — | Finding ID (full or prefix) to derive the memory from |
| `--reason <text>` **required** | — | Why this finding is a false positive |
| `--scope <scope>` | `target` | Memory scope: global \| target \| package |
| `--scope-value <value>` | — | Scope identifier (target URL or package name) |
| `--db-path <path>` | — | Path to SQLite database |

#### triage memory list

List all triage memories

```text
0sec triage memory list [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--scope <scope>` | — | Filter by scope: global \| target \| package |
| `--category <category>` | — | Filter by vulnerability category |
| `--db-path <path>` | — | Path to SQLite database |

#### triage memory remove

Delete a memory by id

```text
0sec triage memory remove [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes | Memory ID |

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |

#### triage mark-fp

Mark a finding as false positive and auto-create a memory

```text
0sec triage mark-fp [options] <finding-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `finding-id` | Yes | Finding ID (full or prefix) |

| Option | Registered default | Description |
| --- | --- | --- |
| `--reason <text>` **required** | — | Why this finding is a false positive |
| `--scope <scope>` | `target` | Memory scope: global \| target \| package |
| `--scope-value <value>` | — | Scope identifier (target URL or package name) |
| `--db-path <path>` | — | Path to SQLite database |

### timeline

Export a scan's immutable pipeline-event audit trail as a chronological, MITRE ATT&CK- and ATLAS-tagged forensic record — UTC ISO-8601 timestamps, per-event action summaries, ready to hand to a client SOC for detection cross-referencing.

```text
0sec timeline [options] <scanId>
```

The scan ID is looked up in the selected database. For a run-local database, pass `--db-path ~/.0sec/runs/<scan-id>/state.db` (adjust for your state directory). This command does not automatically search all run databases.

Guide: [Read the workflow](/engagements/).

| Argument | Required | Description |
| --- | --- | --- |
| `scanId` | Yes | Scan id to export (see `0sec history`) |

| Option | Registered default | Description |
| --- | --- | --- |
| `--format <format>` | `markdown` | Output format: json, csv, markdown |
| `--since <iso>` | — | Only include events at or after this timestamp (ISO-8601, e.g. 2026-07-28T09:00:00Z) |
| `--until <iso>` | — | Only include events at or before this timestamp (ISO-8601) |
| `--attack-only` | — | Only include events that map to a MITRE ATT&CK or ATLAS technique, dropping pipeline lifecycle noise |
| `--db-path <path>` | — | Path to SQLite database |

### verify

Deterministically replay a finding's PoC steps and emit a verification_result JSON.

```text
0sec verify [options] [finding]
```

Verification has distinct fixture, structured-step, kernel, and bundle paths. Their status schemas and exit codes differ. See [Verification Results](/verification-result/) and [Scan Workflows](/scan-workflows/); never infer a universal verdict from exit code alone.

Guide: [Read the workflow](/verification-result/).

| Argument | Required | Description |
| --- | --- | --- |
| `finding` | No | Path to a finding.json (0sec#193 deterministic-replay path). Equivalent to --finding when --runner is supplied. |

| Option | Registered default | Description |
| --- | --- | --- |
| `--runner <kind>` | — | Deterministic replay runner: local\|docker\|qemu (default local). |
| `--docker-network <name>` | — | Docker network for --runner docker. Defaults to none; bridge/custom networks require --scope and only permit HTTP steps. |
| `--scope <path>` | — | Engagement scope JSON required for networked Docker HTTP replay. |
| `--qemu-binary <path>` | — | QEMU emulator for --runner qemu. |
| `--qemu-kernel <path>` | — | Guest kernel image for --runner qemu. |
| `--qemu-busybox <path>` | — | Static BusyBox binary used to build the offline QEMU guest. |
| `--out <dir>` | — | 0sec#193 run directory (artifacts go under &lt;out&gt;/artifacts/). Defaults to a fresh tmpdir. |
| `--finding <path>` | — | Path to a finding.json. |
| `--bundle <path>` | — | Path to a reproduction bundle directory; requires --runner local\|docker. Replays the bundle's vulnerable and patched snapshots through the configured runner and emits an aggregate ReproductionBundleResult. |
| `--create-bundle <plan.json>` | — | Path to a BundlePlan JSON. Creates a reproduction bundle without executing any PoC steps. Requires --out &lt;bundle-dir&gt;. |
| `--target <path>` | — | Path to a target.json (PocExecutionTarget: baseUrl, env, cwd, timeoutMs, personas). |
| `--fixture <name>` | — | Run a built-in deterministic replay fixture. Supported: cli-path-traversal. |
| `--fixture-command <json>` | — | JSON argv array for the CLI under test. Supports {{apiUrl}}, {{exportDir}}, and {{fixtureMode}} placeholders. |
| `--fixture-mode <mode>` | — | Fixture behavior for --fixture: vulnerable or patched. |
| `--retain-artifacts` | `false` | Keep the fixture sandbox, harness metadata, and stdout/stderr logs. |
| `--artifact-dir <path>` | — | Use this directory as the fixture sandbox root. |
| `--format <fmt>` | `json` | Output format. Only 'json' is supported. |
| `--output <path>` | — | Write the verification_result JSON to this path instead of stdout. |
| `--kernel-finding <path>` | — | Path to a kernel-review finding.json. Runs the Tier 2 agent loop to produce a reproducer and promote the finding via the kernel oracle. Requires 0SEC_KERNEL_VERIFY=1. |
| `--kernel-tree <path>` | — | Linux source tree used by --kernel-finding for Tier 1 kernel build. |
| `--kernel-config <profile>` | `kasan` | Kernel build config profile for --kernel-finding (only 'kasan' supported). |
| `--attempts <N>` | — | Max reproducer attempts for --kernel-finding (default 5). |
| `--wall-clock <duration>` | — | Wall-clock budget for --kernel-finding (e.g. 30m, 90s; default 30m). |

### disclose

Assemble GHSA-ready advisory drafts from persisted findings

```text
0sec disclose [options] [findingId]
```

Guide: [Read the workflow](/integrations/).

| Argument | Required | Description |
| --- | --- | --- |
| `findingId` | No | Finding ID (or prefix). Omit to batch every finding at or above --severity-floor. |

Subcommands: [evidence-pack](#disclose-evidence-pack) · [track](#disclose-track) · [review](#disclose-review).

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--scan <scanId>` | — | Restrict to findings from this scan |
| `--output-dir <path>` | — | Directory to write advisories into (default ~/0sec/disclosures/scan-&lt;id&gt;) |
| `--severity-floor <severity>` | `medium` | In batch mode, only draft findings at or above this severity |
| `--no-screenshots` | — | Skip terminal-screenshot rendering even when freeze is available |
| `--repo <path>` | — | Local git checkout of the target repo to re-verify findings against |
| `--ref <tag>` | — | Git ref (tag/sha/branch) to check out before verifying — defaults to the repo's current HEAD |
| `--drop-fixed` | `false` | Move findings whose status is 'fixed' or 'file-removed' into _dropped/ with a reason file instead of drafting an advisory for them |
| `--reverify` | `false` | Behaviourally re-verify each finding's PoC step graph against a live target. Requires --target-url. |
| `--target-url <url>` | — | Base URL the behavioural re-verify runtime dispatches http actions against (e.g. http://localhost:3108) |
| `--target-env <kv...>` | — | Repeated KEY=VALUE pairs added to the shell-action environment for behavioural re-verify |
| `--target-timeout-ms <ms>` | — | Per-step timeout for behavioural re-verify, in milliseconds (default 30000) |
| `--keep-unrun` | `false` | Route `could_not_run` behavioural verdicts to needs-review instead of dropping them. Default-off because unverified PoCs should never auto-file. |
| `--reverify-rps <n>` | — | Per-host requests-per-second cap for behavioural reverify (default 2). Honours 429 Retry-After. |
| `--scope-allowlist <hosts>` | — | Comma-separated host allowlist for reverify. Supports `*.domain.com` wildcard (matches subdomains, NOT the apex). Out-of-scope http/shell steps fail closed. |
| `--dry-run` | `false` | Show what would be written without writing files |

#### disclose evidence-pack

Assemble a DRAFT vendor-notification (what/where/impact/repro/remediation) from a single finding JSON. Emits the mandatory 'DRAFT — NOT SENT' banner. Never sends. #928

```text
0sec disclose evidence-pack [options] <finding.json>
```

| Argument | Required | Description |
| --- | --- | --- |
| `finding.json` | Yes | Path to a Finding JSON file |

| Option | Registered default | Description |
| --- | --- | --- |
| `--target <label>` | — | Affected target/package label for the 'where' line, e.g. lodash@4.17.21 |
| `--affected-ref <ref>` | — | Git ref / version range string for the 'where' line |
| `--allow-unreproduced` | `false` | Stage an internal draft even when the finding's PoC did not reproduce (default off — unreproduced findings are a low-signal disclosure trip-wire) |
| `--out <file>` | — | Write the DRAFT markdown to a file instead of stdout |

#### disclose track

Drive the disclosure tracking state machine. With no --record, opens a fresh draft record; with --record + --to, applies one legal transition. Records intent only — sends nothing.

```text
0sec disclose track [options] <findingId>
```

| Argument | Required | Description |
| --- | --- | --- |
| `findingId` | Yes | Finding ID the disclosure record is for |

| Option | Registered default | Description |
| --- | --- | --- |
| `--record <file>` | — | Existing disclosure-record JSON to transition (omit to open a fresh draft) |
| `--to <status>` | — | Target status for the transition (requires --record) |
| `--actor <actor>` | — | Actor recorded on the timeline event (default 'operator') |
| `--message <text>` | — | Free-text note recorded on the timeline event |
| `--disclosed-to <vendor>` | — | Vendor/contact stamped when transitioning into 'sent' |
| `--cve-id <cve>` | — | CVE id stamped when transitioning into 'cve_assigned' |
| `--out <file>` | — | Write the record JSON to a file instead of stdout |

#### disclose review

Render a local reproducibility manifest for a verified finding. The manifest is deterministic, redacted, and safe for human inspection. Never sends or publishes anything.

```text
0sec disclose review [options] <finding.json>
```

| Argument | Required | Description |
| --- | --- | --- |
| `finding.json` | Yes | Path to a Finding JSON file |

| Option | Registered default | Description |
| --- | --- | --- |
| `--timestamp <iso>` | — | Override generation timestamp for deterministic output |
| `--tool-version <ver>` | — | Override tool version string |
| `--model-config <str>` | — | Provider/model config, e.g. anthropic/claude-sonnet-4 |
| `--target <id>` | — | Override the finding target identifier |
| `--out <file>` | — | Write manifest to a file instead of stdout |

### ingest

Import kernel crash reports (KASAN, UBSAN, oops, syzkaller) into 0sec findings

```text
0sec ingest [options] [path]
```

Guide: [Read the workflow](/kernel-vm/).

| Argument | Required | Description |
| --- | --- | --- |
| `path` | No | Path to a crash report file or directory of reports |

| Option | Registered default | Description |
| --- | --- | --- |
| `--format <format>` | `auto` | Input format: auto \| kasan \| ubsan \| oops \| syzkaller \| generic |
| `-o, --output <format>` | `terminal` | Output format: terminal \| json \| sarif |
| `--verify` | — | Run kernel oracle verification for each report/reproducer |
| `--syz <path>` | — | Run a standalone syzkaller .syz program through the kernel VM oracle |
| `--reproducer <path>` | — | Run a standalone C reproducer through the kernel VM oracle |
| `--kernel-tree <path>` | — | Linux source tree for Tier 1 kernel build/cache resolution |
| `--kernel-config <name>` | — | Kernel build config name for --kernel-tree (e.g. kasan, defconfig+kasan) |
| `--config <profile>` | — | [deprecated] alias for --kernel-config |
| `--kernel-cache-dir <path>` | — | Kernel build cache directory (default: ~/.0sec/kernel-cache) |
| `--expected-signature <pattern>` | — | Expected dmesg signature substring (case-insensitive) for verify |
| `--force-kernel-build` | — | Rebuild kernel VM artifacts even when a cache entry exists |
| `--review-subsystem` | — | After ingest, run linux-kernel review against the crash subsystem for sibling bugs |
| `--tree <path>` | — | Linux source tree used by --review-subsystem |
| `--runtime <runtime>` | `auto` | Review runtime for --review-subsystem: auto, claude, codex, gemini, api |
| `--api-key <key>` | — | API key for --review-subsystem API runtime |
| `-m, --model <model>` | — | Model for --review-subsystem |
| `--timeout <ms>` | `600000` | AI review timeout for --review-subsystem |
| `--cost-ceiling <usd>` | — | Hard USD cost ceiling for --review-subsystem |
| `--review-subsystem-fixture <path>` | — |  |
| `-v, --verbose` | — | Verbose output |
| `--persist` | — | Write ingested findings to an isolated 0sec run database (default: classify only) |
| `--db-path <path>` | — | Explicit SQLite path for --persist (default: a new ~/.0sec/runs/&lt;run-id&gt;/state.db) |

#### Real kernel VM verification

Importing a crash log is not a new reproduction. See [Kernel VM Verification](/kernel-vm/) for execution prerequisites and evidence gates.

### db

Manage the local 0sec database

```text
0sec db
```

Guide: [Read the workflow](/scan-workflows/).

Subcommands: [repair](#db-repair) · [reset](#db-reset).

#### db repair

Back up a malformed local SQLite database and recreate a clean one

```text
0sec db repair [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |

#### db reset

Delete the local SQLite database and optionally reseed the verification workbench

```text
0sec db reset [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--seed <preset>` | `verification` | Seed preset to load after reset |

## Research & verification

### research

Run target-specific engines through the shared evidence research plane

```text
0sec research
```

Guide: [Read the workflow](/research-workflows/).

Subcommands: [pipeline](#research-pipeline) · [mobile](#research-mobile) · [linux-matrix](#research-linux-matrix) · [linux](#research-linux).

#### research pipeline

Run the existing web/AI/source/package pipeline through the shared evidence plane

```text
0sec research pipeline [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--target <target>` **required** | — | URL, local path, repository, package, or image |
| `--target-type <type>` | — | url, web-app, source-code, npm-package, pypi-package, cargo-package, or oci-image |
| `--profile <profile>` | — | Source review profile |
| `--depth <depth>` | `default` | quick, default, or deep |
| `--runtime <runtime>` | `auto` | auto, api, claude, codex, gemini, or ollama |
| `--artifact-root <path>` | `.0sec-research` | Research artifact root |

#### research mobile

Run passive mobile intake; indicators remain hypotheses and only scoped adapters may hand off targets

```text
0sec research mobile [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--target <path>` **required** | — | Extracted APK/IPA directory or metadata file |
| `--artifact-root <path>` | `.0sec-research` | Research artifact root |

#### research linux-matrix

Import externally executed vulnerable-vs-patched boot logs; 0sec validates and hashes them but does not execute boots

```text
0sec research linux-matrix [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--matrix <path>` **required** | — | Versioned external boot-matrix manifest JSON |
| `--finding <path>` **required** | — | Existing Finding JSON to bind the proof to |
| `--artifact-root <path>` | `.0sec-research` | Research artifact root |

#### research linux

Run a supplied Linux kernel reproducer through the shared N-boot evidence gate

```text
0sec research linux [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--kernel-tree <path>` **required** | — | Linux source tree |
| `--reproducer <path>` **required** | — | C reproducer or syzkaller .syz program |
| `--finding <path>` **required** | — | Existing Finding JSON to bind the proof to |
| `--expected-signature <literal>` **required** | — | Literal crash signature that every counted boot must contain |
| `--boots <n>` | `3` | Fresh boots |
| `--min-hits <n>` | `2` | Required reproducing boots |
| `--artifact-root <path>` | `.0sec-research` | Research artifact root |

### hunt

Hunt a bug CLASS across a source tree, seeded by a proven fix: generate variant candidate sites from the fix, fan finders out over them, and gate each finding through an adversarial skeptic. Emits LEADS to verify (not confirmed 0-days). Exit 0=lead(s), 1=none, 2=no candidates, 3=error.

```text
0sec hunt [options]
```

Guide: [Read the workflow](/research-workflows/).

| Option | Registered default | Description |
| --- | --- | --- |
| `--source <path>` **required** | — | Source tree to hunt in (e.g. a linux checkout) |
| `--seed <path>` **required** | — | Fix diff / .patch whose bug class to hunt variants of |
| `--ref <name>` | — | Provenance label for the seed (e.g. the CVE / commit) |
| `--concurrency <N>` | — | Max finders in flight (default 4) |
| `--max-candidates <N>` | — | Cap candidate sites hunted (default 40) |
| `--skip-candidates <N>` | — | Skip the first N ranked candidate sites before hunting (default 0) |
| `--models <a,b>` | — | Comma-separated finder models for diversity (default: provider default) |
| `--reachable-only` | — | Restrict candidates to paths built + zero-cap reachable on the kernelCTF COS target (default: HUNT_REACHABLE_ONLY env) |
| `--reachable-prefer` | — | Sort kernelCTF-reachable candidates first, without dropping any (default: HUNT_REACHABLE_PREFER env) |
| `--no-verify` | — | Skip the skeptic gate (emit all raw findings — triage only, never disclosure) |
| `--novelty` | — | Require lore.kernel.org duplicate suppression; abort before discovery when evidence is unavailable |
| `--novelty-root <path>` | — | Lore mirror root (default: 0SEC_LORE_MIRROR_ROOT or /root/lore-mirror) |
| `--novelty-lists <a,b>` | — | Comma-separated lore lists to search (default: 0SEC_LORE_LISTS or linux-media) |
| `--novelty-recent-epochs <N>` | — | Newest public-inbox epochs to sync per list when --novelty-sync is set (default 1) |
| `--novelty-sync` | — | Clone/fetch lore mirrors before running the novelty gate |
| `--novelty-model <model>` | — | Optional model override for the lore duplicate judge |
| `--novelty-required` | — | Legacy alias; --novelty already aborts when evidence is unavailable |
| `--methodology` | — | Use the kernel-LPE methodology preset: lifecycle/provenance lenses, best-of-4, top-2 skeptic gate, reachable-first |
| `--invariant` | — | Engine A: build (or load) the seed-touched subsystem's stored invariant model and inject its rules + deterministic violation hypotheses into every finder prompt |
| `--graph-slice` | — | Load the seed-touched subsystem's pre-exported Joern CPG and inject a compact interprocedural reachability slice around the fix site into every finder prompt (needs scripts/provision-cpg.sh; fail-open to flat-text) |
| `--cpg <path>` | — | Explicit CPG graphson JSON path for --graph-slice (default: &lt;source&gt;/.0sec/cpg/&lt;subsystem&gt;.json) |
| `--ops-harvest <paths>` | — | [--graph-slice] Comma-separated repo-relative C files to harvest static ops-struct initializers from; overrides a precomputed .ops.json |
| `--graph-slice-hops <N>` | — | [--graph-slice] Call-graph radius around the seed functions (default 3; use 8 for the exp527 known answer) |
| `--exploitability` | — | PROVE stage: after the skeptic+prover gate, run the execution-verified exploitability oracle on each confirmed finding (GREBE diversify + SCAVY differential). BOOTS REAL QEMU VMs — requires staged kernel-VM artifacts and is ignored under --no-verify. Never rejects a finding; it stamps a proven verdict and gates the weaponize budget. |
| `--prove-min-ceiling <ceiling>` | — | [--exploitability] Minimum assessed impact ceiling worth a VM slot: dos-only\|info-leak\|oob-write\|uaf-control (default info-leak — filters out dos-only before QEMU is touched) |
| `--output <path>` | — | Write the hunt result JSON to this path instead of stdout |
| `--runtime <mode>` | — | Engine runtime (default api) |
| `--timeout <ms>` | `600000` | Accepted cloud agent timeout budget in milliseconds |

### recency-hunt

Recency flywheel: hunt the kernelCTF freshness window. git-diff a fresh linux-next range → drop non-unpriv-reachable files → classify each diff SEMANTIC (lifetime/refcount/lock change) vs COSMETIC (reshuffle) → run the refined invariant engine on semantic files → adversarial verify → ranked report. Emits LEADS (verify novelty/reachability before disclosure). Exit 0=survivor(s), 1=none, 2=empty window, 3=error.

```text
0sec recency-hunt [options]
```

Guide: [Read the workflow](/research-workflows/).

| Option | Registered default | Description |
| --- | --- | --- |
| `--tree <path>` **required** | — | Kernel source tree to hunt (e.g. /root/linux-next) |
| `--since <gitrange>` | — | Explicit git range (e.g. HEAD~20..HEAD or &lt;sha&gt;..HEAD); overrides --hours |
| `--hours <N>` | — | Hunt commits from the last N hours (default 24) |
| `-m, --model <model>` | — | Model-build / finder model override |
| `--classifier-model <model>` | — | Semantic-vs-cosmetic classifier model (default gpt-5.5) |
| `--runtime <mode>` | — | Engine runtime (default api) |
| `--model-dir <path>` | — | Where per-file invariant models are stored (default &lt;tree&gt;/.recency-models) |
| `--max-hunt-files <N>` | — | Cap files run through the engine (default 25) |
| `--max-classify-files <N>` | — | Cap in-scope files sent to the LLM classifier (default 80; snapshot merge-window cost control) |
| `--detectors <list>` | — | Comma-separated detectors per semantic file: dataflow,refcount,race,dual-view (default the three static; dual-view is opt-in) |
| `--dynamic-witness` | — | Run the full machine: assumption-mining dual-view enumerator → KASAN synthesize→boot→witness oracle. Implies dual-view. VM boots are expensive — bounded by the budget below. |
| `--witness-candidates <N>` | — | Dynamic-witness RUN budget: total dual-view candidates booted through the KASAN oracle per run (default 10) |
| `--witness-candidates-per-file <N>` | — | Per-file cap on witnessed candidates, clamped to the run budget (default 6) |
| `--witness-rounds <N>` | — | Bounded PoC-repair rounds per candidate — each is one VM boot (default 2) |
| `--witness-mode <mode>` | — | PoC shape for the oracle: single (sequential), race (concurrent multi-thread), auto (race for race-shaped seams; default) |
| `--witness-race-threads <N>` | — | Race-mode worker threads driving entryA vs entryB (default 4) |
| `--witness-race-iters <N>` | — | Race-mode per-thread hammer iterations to widen the race window (default 200000) |
| `--remine-assumptions` | — | Force a fresh assumption mine for dual-view each run (default: reuse a stored per-file model if present) |
| `--output <path>` | — | Write the report JSON here instead of stdout |
| `--md <path>` | — | Also write the markdown report here |
| `--report-dir <dir>` | — | Scheduler mode: write &lt;dir&gt;/YYYY-MM-DD.{json,md} + log a one-line summary |

### assumption-hunt

Seedless ASSUMPTION-MINING hunt: mine the implicit relied-on preconditions each function makes, cross-check enforced-vs-relied (no LLM), then scan for reachable callers that reach a relied-on subject WITHOUT establishing its precondition. Emits CANDIDATES to disprove (not confirmed bugs). Exit 0 = ran (with or without a candidate), 3 = error.

```text
0sec assumption-hunt [options] <source-root>
```

Guide: [Read the workflow](/research-workflows/).

| Argument | Required | Description |
| --- | --- | --- |
| `source-root` | Yes | Local source tree the subsystem files live under (e.g. a kernel checkout) |

| Option | Registered default | Description |
| --- | --- | --- |
| `--files <a.c,b.c>` **required** | — | Comma-separated subsystem source files, repo-relative to &lt;source-root&gt; |
| `--subsystem <label>` | — | Subsystem label for the stored model (e.g. net/unix) |
| `--model-path <path>` | — | Where the durable assumption model JSON lives (default under &lt;source-root&gt;/.0sec) |
| `--remine` | — | Force a fresh LLM mine even if the stored model exists |
| `--skip-hunt` | — | Stop after the deterministic caller-scan (no LLM finder/skeptic gate) |
| `--no-verify` | — | Run the finder fan-out but skip the skeptic gate |
| `--models <a,b>` | — | Comma-separated finder/mine models for diversity |
| `--max-contexts <N>` | — | Cap the violating contexts fed to the hunt |
| `--no-wrapper-resolution` | — | Disable v1 establisher-wrapper resolution (reproduces the v0 direct-token scan — FP ablation) |
| `--no-finder-targeting` | — | Feed the finder the whole subsystem file instead of focused per-function excerpts |
| `--no-dual-view` | — | Disable the v2 dual-api/cross-phase enumerator (caller-scan only — the v1 behavior) |
| `--dynamic-witness` | — | v3: route dual-view candidates to the KASAN synthesize→boot→witness oracle (bypasses the static skeptic). Needs a KASAN VM env (0SEC_KERNEL_QEMU_*). |
| `--witness-rounds <N>` | — | Bounded PoC-repair rounds per dual-view candidate (default 3) |
| `--witness-candidates <N>` | — | Cap dual-view candidates run through the dynamic oracle (default 10) |
| `--witness-model <name>` | — | Model for PoC synthesis (default: runtime default) |
| `--witness-mode <mode>` | — | PoC shape: single (sequential), race (concurrent multi-thread), auto (race for race-shaped seams; default) |
| `--witness-race-threads <N>` | — | Race-mode worker threads driving entryA vs entryB (default 4) |
| `--witness-race-iters <N>` | — | Race-mode per-thread hammer iterations to widen the race window (default 200000) |
| `--excerpt-dir <path>` | — | Where finder-targeting excerpts are written (default: os tmpdir) |
| `--runtime <mode>` | — | Engine runtime (default api) |
| `--format <fmt>` | `json` | Output format (json) |
| `--output <path>` | — | Write the result JSON to this path instead of stdout |

### memsafety

Userspace / Rust memory-safety scan (Monty-mode): clone a source tree, build a fuzz/sanitizer harness, run the closed fuzz loop, and emit reproduced-memcorruption findings. Exit 0=loop completed (with or without crashes), 2=skipped (no build system detected or execution prerequisite unavailable), 3=error (bad flags / unreadable target).

```text
0sec memsafety [options] <source>
```

Guide: [Read the workflow](/research-workflows/).

| Argument | Required | Description |
| --- | --- | --- |
| `source` | Yes | Source tree to fuzz (a local path or a git URL) |

| Option | Registered default | Description |
| --- | --- | --- |
| `--subsystem <path>` | — | Narrow the scanned root to a subdirectory |
| `--language <lang>` | — | Force the language: c \| cpp \| rust (else auto-detected) |
| `--build-system <sys>` | — | Force the build system: cargo \| cmake \| autotools \| meson \| make (else auto-detected) |
| `--artifact-dir <path>` | — | Persist bounded crash evidence outside the source tree |
| `--artifact-max-bytes <bytes>` | — | Aggregate byte ceiling for retained crash evidence (default 4194304) |
| `--harness <name>` | — | libFuzzer / cargo-fuzz harness target name |
| `--fuzz-dir <path>` | — | Non-standard cargo-fuzz directory (relative to source root) |
| `--miri` | `false` | Additionally run `cargo +nightly miri` for UB detection (Rust) |
| `--fuzz-timeout <sec>` | — | Fuzz wall-clock budget in seconds (default 60) |
| `--format <fmt>` | `json` | Output format (json) |
| `--output <path>` | — | Write the result JSON to this path instead of stdout |
| `--runtime <mode>` | — | Engine runtime (default api) |
| `--timeout <ms>` | `600000` | Clone/prepare timeout budget in milliseconds |

### kernel

Kernel security workflows

```text
0sec kernel
```

Guide: [Read the workflow](/research-workflows/).

Subcommands: [syzbot-mine](#kernel-syzbot-mine) · [weights](#kernel-weights) · [variant-hunt](#kernel-variant-hunt).

#### kernel syzbot-mine

Mine and LPE-rank syzbot's invalid/auto-closed queue

```text
0sec kernel syzbot-mine [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--subsystems <csv>` | `net,net/sched,net/tls,xfrm,crypto,vsock,nfc` | Subsystem labels to keep |
| `--limit <n>` | `30` | Maximum ranked candidates |
| `--details <n>` | `15` | Top candidate detail pages to enrich |
| `--detail-delay <ms>` | `750` | Delay between syzbot detail/repro requests |

#### kernel weights

Generate an LLM-derived syzkaller choice_weights.json for a kernelCTF target

```text
0sec kernel weights [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--target <version>` **required** | — | Target kernel version, e.g. 6.12.101 |
| `--crash-summary <path>` | — | File with recent crash descriptions to inform weighting |
| `--enabled-syscalls <path>` | — | JSON array file of manager-enabled syscall names to constrain the plan |
| `--from-file <path>` | — | Validate/normalize a raw model JSON plan instead of calling the API |
| `-m, --model <model>` | — | Override model (default: env/auto-detected) |
| `--max-entries <n>` | `48` | Maximum weighted syscalls |
| `--dry-run` | — | Print the weights file instead of writing |
| `-o, --out <path>` | — | Output path for choice_weights.json |

#### kernel variant-hunt

Run foxguard-backed kernel advisory variant hunting

```text
0sec kernel variant-hunt [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--tree <path>` **required** | — | Path to a Linux source tree |
| `--advisory <url-or-file>` | — | Advisory URL or local advisory path for provenance |
| `--rules <path>` | — | Foxguard rule directory, e.g. rules/kernel/dirty-frag-class |
| `--foxguard <path>` | — | Foxguard binary path |
| `--sarif-input <path>` | — | Use an existing foxguard SARIF file instead of invoking foxguard |
| `--timeout <ms>` | `120000` | Foxguard timeout in milliseconds |
| `-o, --output <format>` | `terminal` | Output format: terminal \| json \| sarif |
| `-v, --verbose` | — | Verbose terminal output |

### exploit

Run the weaponization escalation ladder for a confirmed kernel memory-safety finding in the kernel VM (ADR-055 Phase 1). Default-safe: a no-op (exit 2) when no kernel-VM artifacts are present. With --climb, drive the REAL verify→weaponization chain runner and loop genuine boots until the deterministic oracle credits root.

```text
0sec exploit [options]
```

Guide: [Read the workflow](/research-workflows/).

| Option | Registered default | Description |
| --- | --- | --- |
| `--finding <path>` | — | Path to a confirmed kernel finding.json (required except with --autoclimb/--agent) |
| `--reproducer <path>` | — | Path to the proven memory-safety reproducer (C source), embedded for provenance. |
| `--max-strategies <N>` | — | Cap the number of applicable strategies attempted (bounds VM boots). |
| `--output <path>` | — | Write the weaponization result JSON to this path instead of stdout. |
| `--climb` | — | Engine-driven root-climb mode: drive the REAL verify→weaponization chain runner (real QEMU runner + real oracle, no overrides), looping boots until the oracle credits root. Requires staged kernel-VM artifacts. |
| `--loop-boots <N>` | — | [--climb] Max genuine QEMU boots to loop (root race is ~1/6-8). Default 8. |
| `--vmlinux <path>` | — | [--climb] Resolved vmlinux for the root-tail planner's symbol resolution. |
| `--kernel-config <path>` | — | [--climb] Kernel .config text for exploit-config introspection. |
| `--freed-struct <name>` | — | [--climb] Freed object's C struct name (e.g. snd_rawmidi_runtime). |
| `--proof-out <path>` | — | [--climb] Where to write the read-only root proof (default: temp dir). |
| `--autoclimb` | — | Autonomous LLM-composed weaponization climb: the engine's OWN codegen loop composes each C body from the technique library + bug trigger + last verdict. |
| `--bug-spec <path>` | — | [--autoclimb] JSON AutonomousClimbBug (trigger C, config-off, slab, ceiling). |
| `--boot-script <path>` | — | [--autoclimb] Generic boot script ($1=composed .c, stdout=guest stdout, &lt;c&gt;.serial=dmesg). Or set 0SEC_AUTOCLIMB_BOOT_SCRIPT. |
| `--model <id>` | — | [--autoclimb] Engine model id for the composer (default: engine runtime default). |
| `--agent` | — | Agentic weaponization loop: the model gets a shell in an already-provisioned target and iterates recon → weaponize → build → run against real crash output, gated by the mechanical trigger→reclaim→leak→write→root stage gate. |
| `--task <path>` | — | [--agent] Task/vuln description file (vuln doc + PoV + build). |
| `--container <id>` | — | [--agent] Run exploit commands in this container via `docker exec` (cwd /workspace). |
| `--exec-script <path>` | — | [--agent] Run exploit commands through this script ($1=command) — the E2B/SSH/console seam. Mutually exclusive with --container; one of the two is REQUIRED (no local execution). |
| `--flag-path <path>` | — | [--agent] Where the captured flag must land in the target (default /tmp/flag). |
| `--flag-pattern <ere>` | — | [--agent] ERE the flag content must match. Without it a capture rests on a non-empty flag file only, which a status line the agent echoes there will FALSE-PASS. |
| `--max-steps <N>` | — | [--agent] Agent step budget (default 90). |
| `--runtime <mode>` | — | [--agent] Engine runtime (default api). |

### xnu-fuzz

IOKit user-client fuzzer (dynamic sibling to the xnu-re review profile). Models the IOExternalMethodDispatch2022 gate per user client, generates gate-passing + structure-aware inputs, and plans the disposable macOS-VM run lane.

```text
0sec xnu-fuzz
```

Guide: [Read the workflow](/research-workflows/).

Subcommands: [enumerate](#xnu-fuzz-enumerate) · [gen](#xnu-fuzz-gen) · [harness-plan](#xnu-fuzz-harness-plan).

#### xnu-fuzz enumerate

§1: kext → target-model.json (dispatch-table → valid-input model)

```text
0sec xnu-fuzz enumerate [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--kext <path>` **required** | — | Path to the extracted kext Mach-O (from xnu-re-extract.sh). |
| `--bundle <id>` | — | Kext bundle id recorded in the model (e.g. com.apple.iokit.IOSurface). |
| `--out <file>` | — | Write the full target-model.json to this path. |
| `--json` | — | Emit the model as JSON on stdout instead of a summary. |

#### xnu-fuzz gen

§2: target-model.json → gate-passing + structure-aware inputs

```text
0sec xnu-fuzz gen [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--model <file>` **required** | — | Path to a target-model.json from `enumerate`. |
| `--class <name>` | — | User-client class to generate for (default: largest). |
| `--selector <N>` | — | Only generate for this selector index. |
| `--seed <N>` | — | PRNG seed for reproducible generation (default 1). |
| `--json` | — | Emit the generation summary as JSON. |

#### xnu-fuzz harness-plan

§3: print what a single macOS-VM shard run needs to actually run

```text
0sec xnu-fuzz harness-plan [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--golden <image>` | — | Golden tart VM image name. |
| `--build <build>` | — | macOS build the golden image + kernelcache match. |
| `--shared <dir>` | — | Host-shared folder for the program/result/panic channel. |
| `--oracle <kind>` | — | Crash oracle: release \| kasan \| kfence (default release). |

### binary

Analyze a compiled binary by delegating to the in-repo 0verse engine (uv run --frozen 0verse)

```text
0sec binary [options] <target> [passthrough...]
```

Guide: [Read the workflow](/research-workflows/).

| Argument | Required | Description |
| --- | --- | --- |
| `target` | Yes | Path to the target artifact (e.g. an ELF) to analyze |
| `passthrough` | No | Extra positional args forwarded verbatim to 0verse |

| Option | Registered default | Description |
| --- | --- | --- |
| `--mode <mode>` | `triage` | 0verse subcommand: triage\|run\|scan |
| `--format <format>` | — | Forward --format to 0verse (e.g. ndjson) |
| `--backend <backend>` | — | Forward --backend to 0verse (e.g. rizin, ghidra, angr) |
| `--llm <llm>` | — | Forward --llm to 0verse (e.g. codex, claude) |

### protocol-check

Tier-1 HTTP spec-vs-implementation conformance differential (issue #972). The unified LLM hypothesizes where an implementation diverges from a spec excerpt; each exercise is SENT at a real target and a deterministic oracle confirms only concrete MUST-level violations.

```text
0sec protocol-check [options]
```

Guide: [Read the workflow](/research-workflows/).

| Option | Registered default | Description |
| --- | --- | --- |
| `--spec <file>` **required** | — | Path to the authoritative specification excerpt (RFC/ABNF prose, text). |
| `--impl <file>` **required** | — | Path to the implementation source excerpt the divergence is hypothesized in. |
| `--target <url>` **required** | — | Base URL of the live target to exercise (e.g. http://127.0.0.1:8080). |
| `--json` | — | Emit the full result (findings + attempts) as JSON on stdout. |
| `--max-exercises <N>` | — | Cap how many ranked hypotheses to exercise against the target (default 8). |
| `--runtime <runtime>` | `auto` | LLM runtime: auto/api (codex login or API key), claude, codex, gemini. |
| `--protocol <name>` | — | Protocol name for the report/finding (default HTTP/1.1). |
| `--spec-version <version>` | — | Spec edition for the report (default RFC 9110). |
| `--spec-ref <ref>` | — | Auditable spec citation (e.g. 'RFC 9110 §9.3.6'). |

### specdrift

Protocol/spec differential-hunting research commands.

```text
0sec specdrift
```

Protocol/spec differential research interface. Consult the source-specific prerequisites and evidence limits in [Research Workflows](/research-workflows/).

Guide: [Read the workflow](/research-workflows/).

Subcommands: [extract](#specdrift-extract) · [scan](#specdrift-scan) · [plan](#specdrift-plan).

#### specdrift extract

Extract cited protocol invariants from an arbitrary spec text file

```text
0sec specdrift extract [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--spec <path>` **required** | — | Spec/RFC/protocol text file to analyze |
| `--spec-name <name>` | — | Display name stored in citations |
| `--max-invariants <N>` | `40` | Maximum invariant candidates to emit |
| `--output <path>` | — | Write JSON result to a file instead of stdout |

#### specdrift scan

Extract spec invariants and map them to candidate implementation code

```text
0sec specdrift scan [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--spec <path>` **required** | — | Spec/RFC/protocol text file to analyze |
| `--source <path-or-git-url>` **required** | — | Implementation source tree to map against |
| `--spec-name <name>` | — | Display name stored in citations |
| `--max-invariants <N>` | `40` | Maximum invariant candidates to extract |
| `--max-files <N>` | `400` | Maximum source files to inspect |
| `--max-candidates-per-invariant <N>` | `5` | Maximum implementation candidates per invariant |
| `--timeout <ms>` | `600000` | Source preparation timeout |
| `--output <path>` | — | Write JSON result to a file instead of stdout |

#### specdrift plan

Extract invariants, map implementation candidates, and emit drift hypotheses to verify

```text
0sec specdrift plan [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--spec <path>` **required** | — | Spec/RFC/protocol text file to analyze |
| `--source <path-or-git-url>` **required** | — | Implementation source tree to map against |
| `--spec-name <name>` | — | Display name stored in citations |
| `--max-invariants <N>` | `40` | Maximum invariant candidates to extract |
| `--max-files <N>` | `400` | Maximum source files to inspect |
| `--max-candidates-per-invariant <N>` | `5` | Maximum implementation candidates per invariant |
| `--max-hypotheses <N>` | `20` | Maximum drift hypotheses to emit |
| `--timeout <ms>` | `600000` | Source preparation timeout |
| `--output <path>` | — | Write JSON result to a file instead of stdout |

### agent-assure

Test whether untrusted MCP content causes a prohibited action in an authorized agent environment

```text
0sec agent-assure [options]
```

Guide: [Read the workflow](/research-workflows/).

| Option | Registered default | Description |
| --- | --- | --- |
| `--agent-endpoint <url>` **required** | — | Customer-owned agent test adapter endpoint (HTTP JSON contract) |
| `--mcp-endpoint <url>` **required** | — | Authorized MCP tools/list endpoint |
| `--oracle-endpoint <url>` **required** | — | Customer-owned state-observer endpoint |
| `--scenario <path>` **required** | — | Scenario JSON: id, title, injection_vector, benign_task, payload, prohibited_action |
| `--scope <path>` **required** | — | Engagement scope JSON; all three endpoints must be in scope |
| `--target-version <version>` **required** | — | Version or build digest of the tested agent deployment |
| `--policy-version <version>` **required** | — | Version or digest of the agent prompt and authorization policy |
| `--model-version <version>` **required** | — | Model deployment/version identifier |
| `--tool-version <name=version>` | `[]` | Version of an MCP tool; repeatable |
| `--environment <name>` | `staging` | local, test, or staging |
| `-m, --model <name>` | — | Optional model identifier passed to the customer agent adapter |
| `--agent-headers <path>` | — | JSON file of headers for the agent adapter; never written to evidence |
| `--mcp-headers <path>` | — | JSON file of headers for the MCP endpoint; never written to evidence |
| `--oracle-headers <path>` | — | JSON file of headers for the state observer; never written to evidence |
| `--timeout <ms>` | `30000` | Per-request timeout in milliseconds |
| `--oracle-timeout <ms>` | `10000` | Maximum state-observer wait in milliseconds |
| `--baseline <manifest>` | — | Prior manifest to bind as a retest parent |
| `--output <directory>` | — | Evidence bundle directory; defaults to agent-assurance-&lt;run-id&gt; |

### eval

Run adversarial safety eval against an AI/LLM endpoint and produce a scorecard

```text
0sec eval [options]
```

Guide: [Read the workflow](/research-workflows/).

| Option | Registered default | Description |
| --- | --- | --- |
| `--target <url>` **required** | — | Target AI/LLM endpoint URL |
| `--format <format>` | `terminal` | Output format: terminal, json |
| `--timeout <ms>` | `30000` | Request timeout in milliseconds |
| `--api-key <key>` | — | API key for LLM provider |
| `-m, --model <model>` | — | LLM model to use for evaluation |
| `--auth <json>` | — | Auth credentials for the target (JSON string or path) |
| `--categories <list>` | — | Comma-separated category IDs to run (default: all). Use --list-categories to see available. |
| `--list-categories` | `false` | List available eval categories and exit |
| `--verbose` | `false` | Show detailed output |

### bench

A/B variant tournament + CI regression gate over the labeled corpus (#656)

```text
0sec bench
```

Guide: [Read the workflow](/research-workflows/).

Subcommands: [improvement-project](#bench-improvement-project) · [improvement-assess](#bench-improvement-assess) · [calibrate](#bench-calibrate) · [run](#bench-run) · [diff](#bench-diff).

#### bench improvement-project

Offline projection of sealed tournaments into the v1 result + v3 execution contract

```text
0sec bench improvement-project [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--candidate <path>` **required** | — | schema-v1 ImprovementCandidate JSON |
| `--champion-variant <id>` **required** | — | champion variant id present in every tournament |
| `--challenger-variant <id>` **required** | — | challenger variant id present in every tournament |
| `--development <path>` **required** | — | JSON pair: {manifest, tournament} |
| `--development-ref <ref>` **required** | — | immutable development tournament artifact ref |
| `--held-out <path>` **required** | — | JSON pair: {manifest, tournament} |
| `--held-out-ref <ref>` **required** | — | immutable held-out tournament artifact ref |
| `--negative-controls <path>` **required** | — | JSON pair: {manifest, tournament} |
| `--negative-controls-ref <ref>` **required** | — | immutable negative-control artifact ref |
| `--evaluation-manifest <path>` **required** | — | precommitted evaluation manifest JSON |
| `--manifest-ref <ref>` **required** | — | immutable evaluation manifest artifact ref |
| `--evaluator-bundle <path>` **required** | — | evaluator bundle JSON |
| `--evaluator-bundle-ref <ref>` **required** | — | immutable evaluator bundle artifact ref |
| `--evaluator-code <path>` **required** | — | exact evaluator implementation artifact |
| `--evaluator-code-ref <ref>` **required** | — | immutable evaluator code artifact ref |
| `--evaluator-config <path>` **required** | — | exact evaluator configuration artifact |
| `--evaluator-config-ref <ref>` **required** | — | immutable evaluator config artifact ref |
| `--ci-evidence <path>` **required** | — | retained GitHub Actions receipt with identity, required checks, pass result, and evidenceRefs |
| `--output-dir <path>` **required** | — | create-once result + execution-evidence directory |
| `--calibration` | `false` | rejection-only projection of three trusted calibration lanes |
| `--evidence-ref <ref>` | `[]` | additional immutable evidence reference (repeatable) |

#### bench improvement-assess

Evaluate a sealed improvement result and publish an immutable promotion-decision ledger snapshot; generic artifacts always require human approval

```text
0sec bench improvement-assess [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--result <path>` **required** | — | sealed result.json from bench improvement-project |
| `--base-artifact <path>` **required** | — | immutable champion artifact to bind into the decision |
| `--candidate-artifact <path>` **required** | — | immutable challenger artifact to bind into the decision |
| `--output-dir <path>` **required** | — | create-once promotion decision + ledger snapshot directory |
| `--ledger <path>` | — | prior immutable ledger.json snapshot to extend |

#### bench calibrate

Emit a sealed, provider-free no-uplift tournament for 0research calibration

```text
0sec bench calibrate [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--manifest <path>` **required** | — | corpus manifest path |
| `--case-id <id>` | `[]` | exact pre-registered case id (repeatable) |
| `--manifest-id <id>` **required** | — | sealed calibration slice id |
| `--tournament-output <path>` **required** | — | create-once sealed calibration evidence |
| `--evaluator-output-dir <path>` | — | create-once exact evaluator code/config/bundle |

#### bench run

Run a variant tournament over the corpus and update the benchmark ledger

```text
0sec bench run [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--integration <id>` | `core` | Target-suite integration: core, xbow, cybergym |
| `--manifest <path>` | — | Corpus manifest path; optional for xbow/cybergym integration defaults |
| `--xbow-path <dir>` | — | XBOW checkout used by the xbow integration |
| `--white-box` | `false` | Expose XBOW source paths to the selected agent |
| `--cybergym-harness <dir>` | — | CyberGym checkout used by the cybergym integration |
| `--cybergym-subset <path>` | — | Pre-registered CyberGym task-id file |
| `--cybergym-difficulty <level>` | `level1` | CyberGym task difficulty |
| `--cybergym-best-of-n <n>` | `1` | CyberGym trajectory count; default strict pass@1 |
| `--cybergym-max-submits <n>` | `1` | Official CyberGym submits per task; default strict pass@1 |
| `--case-id <id>` | `[]` | exact case id in a pre-registered manifest slice (repeatable) |
| `--manifest-id <id>` | — | sealed slice id (required with --case-id) |
| `--variants <json\|path>` | — | JSON array of variant descriptors, or a path to one |
| `--variant-id <id>` | `champion` | Id for the implicit single variant |
| `--harness <id>` | — | Harness identity for the implicit single variant |
| `-m, --model <model>` | — | Model override for the implicit single variant |
| `--runtime <runtime>` | — | Runtime override (api/claude/codex/…) |
| `--depth <depth>` | — | Scan/audit depth override (quick/deep/…) |
| `--pass-at-k <n>` | `1` | Attempts per case (pass@k or independent repeats) |
| `--attempt-policy <policy>` | `pass-at-k` | pass-at-k or independent-repeat |
| `--schedule <schedule>` | `variant-major` | variant-major or case-major |
| `--max-turns <n>` | `40` | Hard attack-turn budget per attempt |
| `--cost-ceiling <usd>` | — | Per-attempt cost ceiling (USD) |
| `--ci-subset` | `false` | Run only the fast CI subset (cases flagged ci:true) |
| `--ledger <path>` | `benchmark-ledger.json` | Benchmark ledger path |
| `--tournament-output <path>` | — | create-once canonical {manifest,tournament} evidence |
| `--run-id <id>` | — | Run id recorded in the ledger (default: ISO timestamp) |
| `--gate` | `false` | Evaluate the regression gate and exit non-zero on a regression |
| `--max-success-drop <f>` | `0.05` | Max success-rate drop vs last green |
| `--max-fp-rise <f>` | `0.05` | Max FP-rate rise vs last green |
| `--format <format>` | `terminal` | Output format: terminal, json |

#### bench diff

Compare two recorded runs in a benchmark ledger

```text
0sec bench diff [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--a <runId>` **required** | — | Baseline run id |
| `--b <runId>` **required** | — | Comparison run id |
| `--ledger <path>` | `benchmark-ledger.json` | Benchmark ledger path |
| `--format <format>` | `terminal` | Output format: terminal, json |

### lens-synth

Evolve appsec finder coverage from curated misses; promotion is corpus-gated and active reviews stay pinned

```text
0sec lens-synth [options]
```

Guide: [Read the workflow](/improvement-plane/).

| Option | Registered default | Description |
| --- | --- | --- |
| `--miss-input <path>` | — | curated miss-input JSON ({ misses, corpus }) |
| `--registry <path>` | — | durable overlay path (default: ~/.0sec/lenses/appsec-archetypes.json) |
| `--max-register <n>` | — | cap promoted champions per input revision |
| `-m, --model <id>` | — | synthesis model override |
| `--promote` | `false` | persist a validated champion to the durable overlay |
| `--trials <n>` | — | repeated validation trials (2–10; default 2) |
| `--watch` | `false` | poll the miss-input and process each new content revision |
| `--poll-interval <ms>` | `2000` | watch polling interval (minimum 100ms) |
| `--status` | `false` | show the active durable overlay and promotion ledger |
| `--rollback <lens-id>` | — | retire one previously promoted overlay lens |
| `--json` | `false` | print machine-readable output |

### evolve

Autonomous self-improvement: source-candidate proposal, lens evaluation, and automatic promotion

```text
0sec evolve
```

Guide: [Read the workflow](/improvement-plane/).

Subcommands: [run](#evolve-run) · [status](#evolve-status) · [promote](#evolve-promote) · [rollback](#evolve-rollback) · [exec](#evolve-exec) · [feedback](#evolve-feedback).

#### evolve run

Propose, independently evaluate, and optionally promote future workers

```text
0sec evolve run [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--config <path>` **required** | — | Path to evolution config JSON file |
| `--watch` | — | Repeat until stable, budget exhausted, a failure, or interruption |
| `--json` | — | Output JSON (one result per line in watch mode) |
| `--auto-promote` | — | Enable automatic promotion |
| `--no-auto-promote` | — | Disable automatic promotion |
| `--allow-source-access` | — | Allow sending selected source to the model |
| `--no-allow-source-access` | — | Deny model source access |
| `--max-passes <number>` | — | Maximum watch passes (default: budget-limited) |

#### evolve status

Show active and canary versions, snapshot identities, and registry events

```text
0sec evolve status [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--store <path>` | — | Required path to evolution store directory |
| `--json` | — | Output structured JSON |

#### evolve promote

Approve an exact staged candidate after independent canary evaluation

```text
0sec evolve promote [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--store <path>` **required** | — | Path to evolution store directory |
| `--version <id>` **required** | — | Evaluated candidate ID to approve |
| `--json` | — | Output structured JSON |

#### evolve rollback

Retire an active or canary evolution version and restore its parent

```text
0sec evolve rollback [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--store <path>` **required** | — | Path to evolution store directory |
| `--version <id>` **required** | — | Active or canary version ID to retire |
| `--reason <text>` | `operator rollback` | Reason for rollback |

#### evolve exec

Execute a pinned evolution version snapshot against an input

```text
0sec evolve exec [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--config <path>` **required** | — | Path to evolution config JSON file (to determine store) |
| `--run-id <id>` **required** | — | Evolution run ID to pin and execute the active snapshot from |
| `--input <json>` **required** | — | JSON input to pass to the snapshot execution |
| `--json` | — | Output structured JSON instead of human-readable text |

#### evolve feedback

Capture, approve, and inspect evolution feedback candidates

```text
0sec evolve feedback
```

Subcommands: [capture](#evolve-feedback-capture) · [approve](#evolve-feedback-approve) · [release](#evolve-feedback-release) · [status](#evolve-feedback-status).

#### evolve feedback capture

Capture an evidence-backed observation from a JSON file; does not confirm a finding

```text
0sec evolve feedback capture [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--input <path>` **required** | — | Observation JSON file with source revision and evidence references |
| `--store <path>` | — | Feedback queue JSON file |
| `--allow-source-access` | — | Explicitly consent to source use for this observation |

#### evolve feedback approve

Approve independent positive, held-out, and negative fixtures for an observation

```text
0sec evolve feedback approve [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--id <feedback-id>` **required** | — | Full observation ID |
| `--fixtures <path>` **required** | — | Curation JSON containing positives, heldOut, and negativeControls |
| `--store <path>` | — | Feedback queue JSON file |
| `--allow-source-access` | — | Explicitly consent to source use for synthesis |

#### evolve feedback release

Release a stale processing claim after its worker has stopped

```text
0sec evolve feedback release [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--id <feedback-id>` **required** | — | Full observation ID |
| `--claim-token <token>` **required** | — | Exact claim token shown by feedback status --json |
| `--store <path>` | — | Feedback queue JSON file |

#### evolve feedback status

Show retained observations and their approval/processing status

```text
0sec evolve feedback status [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--store <path>` | — | Feedback queue JSON file |
| `--json` | — | Output structured JSON |

## Discovery & identity

### recon

Enumerate a domain's attack surface — subdomains (passive CT/DNS, plus active DNS brute-force with --active), endpoints, OpenAPI/Swagger docs, and MCP servers — and emit a deduped asset inventory consumable as discovered_assets. Partial #769.

```text
0sec recon [options] <domain>
```

Guide: [Read the workflow](/research-workflows/).

| Argument | Required | Description |
| --- | --- | --- |
| `domain` | Yes | Target domain or origin, e.g. example.com or https://api.example.com |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Emit the asset inventory as machine-readable JSON |
| `--timeout <ms>` | `10000` | Per-request probe timeout in milliseconds |
| `--active` | — | Enable active subdomain enumeration (DNS brute-force). Touches the target's DNS, so it is deny-by-default: REQUIRES --scope &lt;file&gt; authorizing the targets. |
| `--scope <file>` | — | Path to a JSON scope file ({in_scope, out_of_scope}). Required for --active; every candidate host is checked against it before any DNS query. |

### js-recon

Fetch the JS a live site serves and mine each bundle for endpoints/API base URLs + embedded secrets (redacted). Scope-gated, deny-by-default. #927

```text
0sec js-recon [options] <url>
```

Guide: [Read the workflow](/research-workflows/).

| Argument | Required | Description |
| --- | --- | --- |
| `url` | Yes | Target page URL whose &lt;script&gt; bundles are mined, e.g. https://app.example.com |

| Option | Registered default | Description |
| --- | --- | --- |
| `--scope <file>` **required** | — | Path to a JSON scope file ({in_scope, out_of_scope}). REQUIRED — every JS URL is checked against it before any fetch. No scope = nothing fetched. |
| `--timeout <ms>` | `10000` | Per-request fetch timeout in milliseconds |
| `--max-files <n>` | — | Maximum JS files to fetch (clamped to [0,100]) |
| `--json` | — | Emit the result as machine-readable JSON |

### npm-discovery

npm-ecosystem dynamic bug discovery via the pluggable detector registry (SSPP fuzz / validation read-stability TOCTOU / SSRF parser-diff). Confirmed only on observed runtime consequence.

```text
0sec npm-discovery
```

Guide: [Read the workflow](/research-workflows/).

Subcommands: [list](#npm-discovery-list) · [run](#npm-discovery-run).

#### npm-discovery list

List the registered detectors and their classes.

```text
0sec npm-discovery list [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--json` | — | Emit as JSON |

#### npm-discovery run

Sweep a package worklist with the detectors and print confirmed findings.

```text
0sec npm-discovery run [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--install-dir <dir>` **required** | — | Base dir the packages are installed under (prepare with `npm install --ignore-scripts`). |
| `--packages <list>` | — | Comma-separated package names to sweep, e.g. es-toolkit,radash |
| `--detectors <ids>` | — | Restrict to these detector ids (comma-separated). Default: all. |
| `--downloads-floor <n>` | — | Skip packages below this weekly-download floor (needs registry metadata). |
| `--max-age-days <n>` | — | Skip packages whose last publish is older than this (needs registry metadata). |
| `--i-understand-untrusted-exec` | — | Acknowledge that `run` executes untrusted package code in-process on this host. |
| `--offline-dedup` | — | Skip the live OSV advisory lookup (air-gapped/hermetic runs). Confirmed findings then dedup only against fork-twin/prior-report hints; live-unknown ones are marked source=unknown, not novel. |
| `--json` | — | Emit the result as machine-readable JSON |

### identity

Read-only posture assessment of a Microsoft Entra ID (Azure AD) tenant — privileged role assignments, conditional-access coverage, app registrations, service principals, and federated-domain trust. The Graph access token is read from the 0SEC_GRAPH_ACCESS_TOKEN environment variable; it is never accepted as an argument.

```text
0sec identity [options]
```

Guide: [Read the workflow](/engagements/).

| Option | Registered default | Description |
| --- | --- | --- |
| `--tenant <tenantId>` **required** | — | Entra tenant id (GUID) the supplied token is expected to belong to |
| `--json` | — | Emit the assessment result as machine-readable JSON |
| `--timeout <ms>` | `300000` | Wall-clock bound on the whole assessment in milliseconds |
| `--scope <file>` | — | Path to a JSON scope file ({in_scope, out_of_scope}). When supplied, graph.microsoft.com must be explicitly in scope or no request goes out. |

### adgraph

Offline Active Directory attack-path analysis over BloodHound CE / SharpHound JSON already on disk — paths to Domain Admin, kerberoastable principals, unconstrained delegation, DCSync rights, ACL abuse chains, and ADCS escalation. Reads files only: never collects, never authenticates, never touches the network.

```text
0sec adgraph [options]
```

Guide: [Read the workflow](/engagements/).

| Option | Registered default | Description |
| --- | --- | --- |
| `--input <path>` **required** | — | A single BloodHound CE JSON file, or a directory of collector JSON files (non-recursive, *.json) |
| `--json` | — | Emit the analysis as machine-readable JSON |
| `--timeout <ms>` | `120000` | Wall-clock bound on ingest + analysis in milliseconds |
| `--domain <fqdn>` | — | Restrict the analysis to objects belonging to this AD domain, e.g. corp.example.com |

### entragraph

Offline Microsoft Entra ID attack-path analysis over an AzureHound export already on disk — paths to Global Administrator, service-principal escalation, consent-grant abuse, owner chains, and guest escalation. Reads files only: never collects, never authenticates, never touches the network.

```text
0sec entragraph [options]
```

Guide: [Read the workflow](/engagements/).

| Option | Registered default | Description |
| --- | --- | --- |
| `--input <path>` **required** | — | A single AzureHound JSON file, or a directory of AzureHound JSON files (non-recursive, *.json) |
| `--json` | — | Emit the analysis as machine-readable JSON |
| `--timeout <ms>` | `120000` | Wall-clock bound on ingest + analysis in milliseconds |
| `--max-depth <n>` | — | Hop ceiling for path traversal |
| `--owned <ids>` | — | Comma-separated object ids already under operator control. These become the path sources; omit to treat every enabled non-privileged principal as a candidate. |

### cloud

Read-only cloud-surface probes (S3 public-access / takeover, AWS credential validation). Gated behind 0SEC_FEATURE_CLOUD_SURFACE + an engagement scope, deny-by-default. #925

```text
0sec cloud
```

This command probes cloud infrastructure under an engagement scope. It is **not** the managed 0sec Cloud product or a way to sign up for that service. For managed engagements use [0cloud](/roadmap/#0cloud).

Guide: [Read the workflow](/research-workflows/).

Subcommands: [s3-probe](#cloud-s3-probe) · [validate-creds](#cloud-validate-creds).

#### cloud s3-probe

Anonymously probe one or more S3 buckets for public listability + orphaned-bucket takeover. Read-only, no credentials sent.

```text
0sec cloud s3-probe [options] <bucket...>
```

| Argument | Required | Description |
| --- | --- | --- |
| `bucket` | Yes | Bucket name(s) to probe, e.g. acme-assets |

| Option | Registered default | Description |
| --- | --- | --- |
| `--scope <file>` **required** | — | Path to a JSON scope file ({in_scope, out_of_scope}). REQUIRED — each bucket's S3 endpoint must be in scope or it is refused. |
| `--region <region>` | — | Bucket home region (default us-east-1 / global endpoint) |
| `--max-keys <n>` | — | Max object keys to sample from a public listing (1-100, default 10) |
| `--json` | — | Emit results as machine-readable JSON |

#### cloud validate-creds

Validate a harvested AWS credential READ-ONLY via sts:GetCallerIdentity + read-only over-privilege probes. No mutation, ever.

```text
0sec cloud validate-creds [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--scope <file>` **required** | — | Path to a JSON scope file ({in_scope, out_of_scope}). REQUIRED — validating a credential is recon against the target org, deny-by-default. |
| `--access-key-id <id>` | — | AWS access key id (defaults to $AWS_ACCESS_KEY_ID) |
| `--secret-access-key <key>` | — | AWS secret access key (defaults to $AWS_SECRET_ACCESS_KEY) |
| `--session-token <token>` | — | AWS session token (defaults to $AWS_SESSION_TOKEN) |
| `--region <region>` | — | AWS region for the STS call (default us-east-1) |
| `--json` | — | Emit the result as machine-readable JSON |

### intel

Live vulnerability intelligence lookup helpers

```text
0sec intel
```

Guide: [Read the workflow](/research-workflows/).

Subcommands: [dossier](#intel-dossier) · [target-history](#intel-target-history) · [search](#intel-search) · [cve](#intel-cve) · [similar](#intel-similar).

#### intel dossier

Build a package-level intel dossier with risk summary, prior-vuln playbooks, and variant leads

```text
0sec intel dossier [options] <package>
```

| Argument | Required | Description |
| --- | --- | --- |
| `package` | Yes | Package name |

| Option | Registered default | Description |
| --- | --- | --- |
| `--ecosystem <ecosystem>` | `npm` | Package ecosystem: npm, pypi, cargo, Go, Maven |
| `--package-version <version>` | — | Resolved package version |
| `--ver <version>` | — | Alias for --package-version |
| `--keywords <list>` | — | Comma-separated variant-hunt keywords |
| `--similar-limit <n>` | `10` | Maximum similar advisory leads |
| `--no-similar` | — | Skip similar-advisory search |
| `--offline` | — | Use cache only |
| `--cache-dir <path>` | — | Override intel cache directory |
| `--json` | — | Emit machine-readable JSON |

#### intel target-history

Search prior CVEs/GHSAs already reported against this target, repo, package, or product

```text
0sec intel target-history [options] [target]
```

| Argument | Required | Description |
| --- | --- | --- |
| `target` | No | Target URL/name or GitHub repository |

| Option | Registered default | Description |
| --- | --- | --- |
| `--repo-path <path>` | — | Infer target hints from a local repository/package path |
| `--repository <owner/repo-or-url>` | — | GitHub repository hint, e.g. expressjs/express |
| `--ecosystem <ecosystem>` | — | Optional package ecosystem: npm, pypi, cargo, Go, Maven |
| `--package <package>` | — | Optional package name |
| `--product <product>` | — | Optional product/project name |
| `--vendor <vendor>` | — | Optional vendor/organization name |
| `--keywords <list>` | — | Comma-separated target aliases or extra search terms |
| `--limit <n>` | `20` | Maximum results per live source query |
| `--offline` | — | Use cache only |
| `--cache-dir <path>` | — | Override intel cache directory |
| `--json` | — | Emit machine-readable JSON |

#### intel search

Search advisories for a package/version

```text
0sec intel search [options] <package>
```

| Argument | Required | Description |
| --- | --- | --- |
| `package` | Yes | Package name |

| Option | Registered default | Description |
| --- | --- | --- |
| `--ecosystem <ecosystem>` | `npm` | Package ecosystem: npm, pypi, cargo, Go, Maven |
| `--package-version <version>` | — | Resolved package version |
| `--ver <version>` | — | Alias for --package-version |
| `--no-enrich` | — | Skip CVE enrichment via NVD/CISA KEV |
| `--offline` | — | Use cache only |
| `--cache-dir <path>` | — | Override intel cache directory |
| `--json` | — | Emit machine-readable JSON |

#### intel cve

Look up a CVE from NVD and CISA KEV

```text
0sec intel cve [options] <cve-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `cve-id` | Yes | CVE identifier, e.g. CVE-2024-1086 |

| Option | Registered default | Description |
| --- | --- | --- |
| `--offline` | — | Use cache only |
| `--cache-dir <path>` | — | Override intel cache directory |
| `--json` | — | Emit machine-readable JSON |

#### intel similar

Search related CVEs/advisories by CWE and keywords

```text
0sec intel similar [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--cwe <cwe>` | — | CWE id, e.g. CWE-22 |
| `--ecosystem <ecosystem>` | — | Optional ecosystem hint |
| `--keywords <list>` | — | Comma-separated keywords |
| `--limit <n>` | `10` | Maximum results |
| `--offline` | — | Use cache only |
| `--cache-dir <path>` | — | Override intel cache directory |
| `--json` | — | Emit machine-readable JSON |

### cve

CVE workflows: artifact lookup (`find`) and autonomous PoC adaptation (`adapt`).

```text
0sec cve
```

Guide: [Read the workflow](/research-workflows/).

Subcommands: [find](#cve-find) · [adapt](#cve-adapt).

#### cve find

Find public PoC + write-up artifacts for a CVE id

```text
0sec cve find [options] <cve-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `cve-id` | Yes | CVE identifier, e.g. CVE-2024-1086 |

| Option | Registered default | Description |
| --- | --- | --- |
| `--format <fmt>` | `json` | Output format: json \| table |
| `--cache-dir <path>` | — | Override cache directory (default ~/.0sec/cve-cache) |
| `--no-cache` | — | Bypass on-disk cache and re-fetch every source |
| `--timeout <ms>` | `10000` | Per-source timeout in milliseconds |
| `--retries <n>` | `2` | Retry count per source on 5xx |
| `--skip-github-poc-search` | — | Skip the GitHub repository / code search step |

#### cve adapt

Adapt a public PoC for <cve-id> until it reproduces on the target kernel.

```text
0sec cve adapt [options] <cve-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `cve-id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--kernel-tree <path>` **required** | — | Linux source tree to build against |
| `--kernel-config <profile>` | — | Kernel build profile (default: kasan) |
| `--attempts <n>` | `5` | Max verify-run attempts across all candidates |
| `--wall-clock <duration>` | `30m` | Total wall-clock budget (e.g. 30m, 90s, 500ms) |
| `--artifacts <path>` | — | Path to a CveArtifacts JSON file (temporary; replaced by the scraper once it merges). |
| `--format <fmt>` | `json` | Output format: json \| table |

## Automation & integration

### mcp-server

Run 0sec's MCP stdio server for live target interaction tools

```text
0sec mcp-server [options]
```

Use an explicit scope and a narrow `--tools` allowlist for an authorized target. The external MCP client owns model selection. This stdio server is not a replacement for OS isolation.

Guide: [Read the workflow](/integrations/).

| Option | Registered default | Description |
| --- | --- | --- |
| `--target <target>` **required** | — | Target URL for this MCP session |
| `--scan-id <scanId>` **required** | — | Scan ID to associate persisted findings and target updates with |
| `--db-path <path>` | — | Path to SQLite database |
| `--timeout <ms>` | `30000` | Default tool timeout in milliseconds |
| `--scope <path>` | — | Path to a 0sec scope JSON file. Out-of-scope URLs are refused by every target tool. |
| `--tools <names>` | — | Comma-separated live 0sec MCP tools to expose (default: all). |
| `--rate-limit <spec>` | — | Per-host request rate-limit spec. Defaults to 5 rps when unset. An active --engagement-profile caps this: the effective rate is the minimum of the two, so the profile can only lower it. |
| `--allow-scanners` | `false` | Disable generic-scanner suppression for scoped engagements. |
| `--engagement-profile <name>` | — | Engagement hardening posture for authorized enterprise work. 'standard' (default) is the existing behaviour. 'conservative' applies the quiet posture to this MCP session: no adaptive WAF-evasion ladder, full jitter on the per-host token bucket, and a 1 rps/host ceiling. The profile can only ever make the session quieter — the effective rate is the minimum of the profile and --rate-limit. The applied posture is recorded as an `engagement_posture_applied` event on the scan so it can be handed to the client as evidence. Lower precedence than the scope file's `engagement` block and 0SEC_ENGAGEMENT_PROFILE. |
| `--no-waf-evasion` | — | Disable the adaptive WAF-evasion ladder (default: on). When a response classifies as blocked, the engine normally retries with encoding/casing/whitespace-mutated payload variants, which escalates a routine WAF block into a SOC incident. Detection and reporting of the block are unaffected. Independent of --engagement-profile; env form: 0SEC_WAF_EVASION=0. |

### plugin

Install, enable, and inspect third-party plugins (scaffold; no marketplace ships)

```text
0sec plugin
```

Installing, enabling, and invoking are separate actions. Plugin code is untrusted; declared capabilities are not an OS sandbox. Do not assume a populated public marketplace exists.

Guide: [Read the workflow](/integrations/).

Subcommands: [list](#plugin-list) · [search](#plugin-search) · [browse](#plugin-browse) · [install](#plugin-install) · [enable](#plugin-enable) · [disable](#plugin-disable) · [info](#plugin-info) · [run](#plugin-run).

#### plugin list

List installed plugins and their per-project enabled/stale state

```text
0sec plugin list
```

#### plugin search

Search the configured registry for plugins

```text
0sec plugin search [options] <query>
```

| Argument | Required | Description |
| --- | --- | --- |
| `query` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--registry <url>` | — | Marketplace index URL (https) |

#### plugin browse

List everything in the configured registry

```text
0sec plugin browse [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--registry <url>` | — | Marketplace index URL (https) |

#### plugin install

Fetch + validate + write a plugin's files (installs; does NOT enable, runs no code)

```text
0sec plugin install [options] <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--registry <url>` | — | Marketplace index URL (https) |

#### plugin enable

Enable an installed plugin FOR THIS PROJECT, granting its capabilities

```text
0sec plugin enable <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

#### plugin disable

Disable a plugin for this project (files stay installed)

```text
0sec plugin disable <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

#### plugin info

Show an installed plugin's manifest, capabilities, and enablement state

```text
0sec plugin info <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |

#### plugin run

Invoke a tool of an ENABLED plugin over the protocol (spawns the plugin; effectful tools require --yes). Args: key=value pairs and/or --json '<obj>'.

```text
0sec plugin run [options] <id> [tool] [pairs...]
```

| Argument | Required | Description |
| --- | --- | --- |
| `id` | Yes |  |
| `tool` | No |  |
| `pairs` | No |  |

| Option | Registered default | Description |
| --- | --- | --- |
| `--json <json>` | — | JSON object of tool arguments |
| `--yes` | — | Authorize an effectful (non read-only) tool to run |
| `--timeout <ms>` | — | Per-call timeout in milliseconds |

### orchestrate

Run the autonomous verification worker against persisted queued case work

```text
0sec orchestrate [options]
```

This executes queued case work in the selected database. It is not a generic multi-target scan launcher. Review the queued cases, credentials, and side-effect permissions first.

Guide: [Read the workflow](/integrations/).

| Option | Registered default | Description |
| --- | --- | --- |
| `--db-path <path>` | — | Path to SQLite database |
| `--limit <n>` | `1` | Maximum queued cases to claim per pass |
| `--runtime <runtime>` | — | Runtime override: auto, claude, codex, gemini, api |
| `--timeout <ms>` | `30000` | Request timeout in milliseconds |
| `--api-key <key>` | — | API key for LLM provider |
| `-m, --model <model>` | — | LLM model to use |
| `--watch` | `false` | Run as a persistent daemon loop |
| `--poll-interval <ms>` | `5000` | Idle poll interval for watch mode |
| `--label <name>` | — | Operator-facing worker label |

### h1

HackerOne hacker-API helpers (read-only)

```text
0sec h1
```

Guide: [Read the workflow](/integrations/).

Subcommands: [auth](#h1-auth) · [programs](#h1-programs) · [scope](#h1-scope).

#### h1 auth

Verify HackerOne API credentials

```text
0sec h1 auth
```

#### h1 programs

List or inspect HackerOne programs

```text
0sec h1 programs
```

Subcommands: [list](#h1-programs-list) · [show](#h1-programs-show).

#### h1 programs list

List visible programs

```text
0sec h1 programs list [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--bounty` | — | Only programs that pay bounties |
| `--vdp` | — | Only non-bounty (VDP) programs |
| `--state <state>` | — | Filter by program state (e.g. public_mode, soft_launched) |
| `--limit <n>` | — | Max programs to return (default 100, max 1000) |
| `--json` | — | Emit machine-readable JSON instead of a table |

#### h1 programs show

Show details for a single program

```text
0sec h1 programs show <handle>
```

| Argument | Required | Description |
| --- | --- | --- |
| `handle` | Yes | Program handle (e.g. flutteruki) |

#### h1 scope

Export HackerOne scope into the 0sec scope file format

```text
0sec h1 scope
```

Subcommands: [dump](#h1-scope-dump).

#### h1 scope dump

Write a program's structured_scopes to ~/.0sec/scopes/<handle>.json

```text
0sec h1 scope dump [options] <handle>
```

| Argument | Required | Description |
| --- | --- | --- |
| `handle` | Yes | Program handle |

| Option | Registered default | Description |
| --- | --- | --- |
| `--out <path>` | — | Override the output path |

### auth

0sec-cloud authentication

```text
0sec auth
```

These credentials are for a configured managed control plane, not model-provider authentication. Browser login requires a compatible server-side flow and authorized access; the presence of this CLI command does not establish public service availability. See [0cloud](/roadmap/#0cloud).

Guide: [Read the workflow](/api-keys/).

Subcommands: [login](#auth-login) · [logout](#auth-logout) · [status](#auth-status).

#### auth login

Log in to 0sec-cloud (opens browser; --token to paste directly)

```text
0sec auth login [options]
```

| Option | Registered default | Description |
| --- | --- | --- |
| `--host <url>` | — | Cloud host (default https://cloud.0sec.ai) |
| `--token <value>` | — | Skip the browser flow and persist this token directly |

#### auth logout

Delete ~/.0sec/cloud.env

```text
0sec auth logout
```

#### auth status

Verify 0sec-cloud credentials against /health

```text
0sec auth status
```

## XBOW benchmark runner

The benchmark workspace is separate from `0sec bench`. Its runner and measured
results are documented in [Benchmarks](/benchmark/) and [Methodology](/methodology/).
Use `pnpm --filter @0sec/benchmark xbow --help` from a source checkout to inspect
runner options. Benchmark execution needs its own target environments and budget;
it is not a quick installation check.

## Reference sources

Registration entry point: `packages/cli/src/index.ts`. Command implementations
are exported through `packages/cli/src/commands/index.ts`. Workflow guides explain
handler behavior and prerequisites beyond the registered flags.

---
title: Integrations
description: MCP server, HackerOne, plugins, report export, Docker, CI, and cloud auth integrations.
---

For organization credentials, see [Cloud auth](/integrations/#cloud-auth).

## MCP Server

The MCP server (`0sec mcp-server`) exposes 0sec's live-attack tools through the
[Model Context Protocol](https://modelcontextprotocol.io) over stdio. Any MCP
client (Claude Desktop, Cline, Continue, etc.) can drive a 0sec target session.

**Source:** `packages/cli/src/commands/mcp-server.ts`

### Usage

```bash
0sec mcp-server \
  --target https://target.example.com \
  --scan-id my-scan-001 \
  [options]
```

### Required options

| Option | Description |
|--------|-------------|
| `--target <url>` | Target URL for this MCP session (required) |
| `--scan-id <id>` | Scan ID to associate findings and target updates with (required) |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--db-path <path>` | — | Path to SQLite database for persistence |
| `--timeout <ms>` | `30000` | Per-tool timeout in milliseconds (minimum 1000) |
| `--scope <path>` | — | Path to a 0sec scope JSON file. Out-of-scope URLs are refused by every tool |
| `--tools <names>` | all tools | Comma-separated subset of MCP tools to expose |
| `--rate-limit <spec>` | `5` rps | Per-host request rate limit. An active `--engagement-profile` caps this |
| `--allow-scanners` | `false` | Disable generic-scanner suppression for scoped engagements |
| `--engagement-profile <name>` | `standard` | Hardening posture: `standard` (default behaviour) or `conservative` (1 rps/host ceiling, full jitter, no WAF evasion) |
| `--no-waf-evasion` | enabled | Disable the adaptive WAF-evasion ladder (encoding/casing/whitespace mutation on block) |

### Exposed tools

Use `--tools` to select from these live-attack tools:

| Tool | Purpose |
|------|---------|
| `http_request` | Send an HTTP request to the target |
| `crawl` | Crawl the target application for endpoints |
| `submit_form` | Submit a form on the target |
| `send_prompt` | Send an LLM prompt to the target |
| `save_finding` | Persist a discovered finding |
| `update_target` | Update the target definition mid-session |
| `query_findings` | Query persisted findings |
| `update_finding` | Update an existing finding's status/metadata |
| `done` | Signal session completion |
| `payload_lookup` | Look up a known payload |
| `wp_fingerprint` | Fingerprint WordPress instances |
| `mongo_objectid` | Generate/extract MongoDB ObjectIds |

### Auth configuration

Target authentication is provided via the `0SEC_MCP_AUTH_JSON` environment
variable. Set it to a JSON object with one of these shapes:

```json
// Bearer token
{"type":"bearer","token":"eyj..."}

// Cookie
{"type":"cookie","value":"session=abc123"}

// Basic auth
{"type":"basic","username":"admin","password":"pass"}

// Custom header
{"type":"header","name":"X-API-Key","value":"sk-..."}
```

See [Configuration](/configuration/) for the full `--auth` flag details used by
`0sec scan` and `0sec review`.

### Rate limiting and engagement posture

The MCP server supports the same engagement hardening as the scan path. When
`--engagement-profile conservative` is active:

- WAF-evasion ladder is disabled (regardless of `--no-waf-evasion`)
- Per-host rate is capped at 1 rps (config override can only lower it further)
- Full request jitter is applied to all rate-limit buckets

An explicit `--rate-limit` value is clamped to the posture's ceiling. The
posture clamps, never increases, the configured rate.

The server records an `engagement_posture_applied` event on the scan for
auditability.

### Attribution headers

MCP supports attribution headers for authorized engagements:

- `0SEC_MCP_ATTRIBUTION_HEADERS_JSON` — JSON array of `"Header-Name: value"`
  strings
- `0SEC_MCP_ATTRIBUTION_UA_TOKEN` — free-form User-Agent token appended to the
  default UA string

### Client setup

**Claude Desktop** — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "0sec": {
      "command": "0sec",
      "args": [
        "mcp-server",
        "--target", "https://target.example.com",
        "--scan-id", "claude-session"
      ],
      "env": {
        "ANTHROPIC_API_KEY": "sk-ant-..."
      }
    }
  }
}
```

**Cline / Continue** — add to the MCP tools configuration:

```json
{
  "command": "0sec",
  "args": ["mcp-server", "--target", "https://target.example.com", "--scan-id", "cli-session"],
  "env": { "ANTHROPIC_API_KEY": "sk-ant-..." }
}
```

The MCP transport is stdio-only. The host MCP client manages the server process
lifetime.

## HackerOne integration

`0sec h1` provides read-only access to the HackerOne hacker API for program
discovery and scope enumeration.

**Source:** `packages/cli/src/commands/h1.ts`

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `0sec h1 auth` | Verify H1 credentials against the API |
| `0sec h1 programs list` | Paginate/filter the program list |
| `0sec h1 programs show <handle>` | Program detail + scope summary |
| `0sec h1 scope dump <handle>` | Export structured scopes as scope JSON |

### Credentials

Credentials are loaded from a `h1.env` file (see [Configuration](/configuration/)
for the expected path). The H1 API uses Basic auth with a username and API token
generated on the HackerOne site. The loader reads what you put in `h1.env`;
there is no login flow.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | User/data error (bad input, parse failure, missing handle) |
| `2` | Auth failure (missing creds or HTTP 401/403 from H1) |
| `3` | Rate-limit or network error |

### Example

```bash
# Verify credentials
0sec h1 auth

# List programs
0sec h1 programs list --limit 20

# Show program detail
0sec h1 programs show my-program-handle

# Export scope for use as a 0sec scope file
0sec h1 scope dump my-program-handle --out my-scope.json
```

## Cloud auth

`0sec auth` manages scoped organization credentials. For 0sec Cloud availability and operator-host setup, see [Getting started](/getting-started/#hosted-models-draft). Local API-key and subscription use require no 0sec account.

**Source:** `packages/cli/src/commands/auth.ts`

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `0sec auth login` | Open browser at the cloud host's `/cli-auth` page, poll for a scoped token |
| `0sec auth login --token <value>` | Manual credential path — persist a token directly |
| `0sec auth login --host <url>` | Point at a self-hosted cloud host |
| `0sec auth logout` | Delete `~/.0sec/cloud.env` and `~/.0cloud/credentials.json` |
| `0sec auth status` | Verify cloud credentials against `GET /health` |

### Credential storage

Credentials persist to `~/.0sec/cloud.env` (mode `0600`) with the format:

```text
# 0sec-cloud credentials. Managed by `0sec auth`.
# DO NOT commit this file or share its contents.
0SEC_CLOUD_HOST=https://cloud.0.security
0SEC_CLOUD_TOKEN=scoped-token-here
```

On logout both `~/.0sec/cloud.env` and `~/.0cloud/credentials.json` are
removed. Cloud auth uses Bearer tokens.

### Manual token path

For self-hosted or recovery use, pass a token directly:

```bash
0sec auth login --token "your-token" --host "https://your-host.example.com"
```

This skips the browser flow entirely and persists the token immediately.

## Report formats

`scan`, `review`, and `audit` accept `--format` and default to terminal output. Supported formats and aliases vary by command.

**Source:** `packages/cli/src/formatters/`

| Format | Flag | Description |
|--------|------|-------------|
| **JSON** | `--format json` | Structured JSON with findings, summary, and metadata |
| **SARIF** | `--format sarif` | Static Analysis Results Interchange Format — upload to GitHub Code Scanning or other SARIF consumers |
| **HTML** | `--format html` | Self-contained HTML report with severity bars, finding cards, collapsed evidence |
| **PDF** | `--format pdf` | PDF report via pdfkit (US Letter). Tables, severity bars, finding details |
| **Markdown** | `--format markdown` | Markdown report |
| **Terminal** | `--format terminal` | Terminal-formatted output with ANSI colors |

### SARIF for GitHub Code Scanning

The SARIF output is compatible with `github/codeql-action/upload-sarif@v4`.
See [GitHub CI](/ci/github-action/) for a full workflow example.

```bash
0sec review . --format sarif > results.sarif
```

### PDF report

```bash
0sec scan --target http://127.0.0.1:8080 --scope ./scope.json --format pdf
```

The PDF formatter lazily loads pdfkit so the bun-compiled binary never bundles
it. Output is US Letter format with severity-colored sections.

### HTML report

```bash
0sec scan --target http://127.0.0.1:8080 --scope ./scope.json --format html
```

The HTML formatter produces a standalone page with severity bars, finding cards,
collapsed request/response evidence, and meta tags.

## Docker image

The 0sec engine is published as a multi-architecture Docker image on GitHub
Container Registry:

```
ghcr.io/0sec-labs/0sec:latest
ghcr.io/0sec-labs/0sec:<sha>
ghcr.io/0sec-labs/0sec:main
```

**Source:** `Dockerfile`

### Image contents

The runtime image (based on `ubuntu:24.04`) includes:

| Category | Tools |
|----------|-------|
| **Node.js runtime** | Node 24 (copied from builder stage), npm, npx |
| **Static analysis** | FoxGuard (pre-provisioned, checksum-pinned) |
| **Web pentesting** | sqlmap, nmap, nikto, gobuster, hydra, ffuf, wfuzz, whatweb, wafw00f, dirb |
| **Active Directory** | impacket (0.13.1), certipy-ad (5.1.0), bloodhound-ce (1.9.1), ldap-utils, krb5-user |
| **Cloud identity** | AzureHound (v3.0.0, checksum-pinned) |
| **Source analysis** | ripgrep (for fast source-tree searches in audit/scan), jq, git |
| **Container analysis** | skopeo |
| **Scripting** | python3, python3-requests, python3-bs4 |
| **Optional** | SecLists wordlists (`INSTALL_SECLISTS=1` build arg, ~1GB extra) |

### Usage

```bash
docker run --rm \
  -e ANTHROPIC_API_KEY=$KEY \
  -v "$PWD:/work" -w /work \
  ghcr.io/0sec-labs/0sec:latest review .

# Scan a web target
docker run --rm \
  -e OPENAI_API_KEY=$KEY \
  ghcr.io/0sec-labs/0sec:latest scan \
    --target https://example.com \
    --scope /work/scope.json
```

The container runs as the `ubuntu` user (uid 1000). Mount your working directory
at `/work` if you need the container to read source code or write reports.

### Security model

- The image drops privileges to the `ubuntu` user before executing commands
- Build args `INSTALL_SECLISTS` (off by default) and `AZUREHOUND_VERSION` control
  optional inclusions
- Third-party tools are installed via apt with known-good versions from
  `ubuntu:24.04` or pinned PyPI/Go release checksums
- The AD tools venv is deliberately not on `PATH` to avoid shadowing system
  Python packages

### Build your own

```bash
docker build -t 0sec:local .
docker build --build-arg INSTALL_SECLISTS=1 -t 0sec:full .
```

## Plugin system

0sec supports two plugin mechanisms:

- **Model-authored executable plugins** — TypeScript code submitted by the
  model at runtime, executed in isolated Docker containers or smolvm microVMs.
  This is the primary self-extension path, enabled by default for non-verifier
  agents (operator can opt out via `allowModelSelfExtension: false`).
- **Third-party operator plugins** — CLI-managed plugins from the operator
  marketplace. Scaffolded; no marketplace ships.

### Model-authored executable plugins (self-extension)

The model can submit TypeScript source files as an executable plugin during a
session. Each plugin declares a manifest with tool names, descriptions, JSON
parameter property schemas, and **capabilities** that gate broker access:

| Capability | Description |
|------------|-------------|
| `compute` | Guest-local computation, including scratch files; no host filesystem or provider access |
| `model-call` | May call the configured model provider through a controller-owned broker |
| `network` | Requests to authorized host network tools, subject to the parent's scope |
| `filesystem-read` / `filesystem-write` | Requests to authorized host filesystem tools, subject to local scope |
| `process-exec` / `findings-write` | Applicable host execution or finding-publication gates; explicitly denied broker tools remain unavailable |

A plugin's entry source file exports an `async run(toolName, args, sdk)`
function. The `sdk` object provides three broker methods:

- **`sdk.callTool(name, args)`** — calls another registered executable tool
  or an available host tool through the parent's authorization gates. Returns output or throws.
- **`sdk.callSkill(name, args)`** — calls another registered executable skill
  by name. Throws if not found.
- **`sdk.callModel({system?, messages?, tools?})`** — delegates a model
  request through the controller's authorized provider front door. Requires
  the `model-call` capability.

Guest code runs in an isolated guest (Docker backend by default) with no
network, read-only root, and bounded resources. The guest SDK **cannot**
invoke host execution tools (`bash`, `run_command`, `python_exec`),
delegation tools (`spawn_agent`, `spawn_agents`), or control tools
(`self_extend`, `apply_patch`, `write_file`). Nested invocations share a
single broker call budget and are limited to depth 4.

Manifest `parameters` contains property schemas, such as
`{"value":{"type":"number"}}`; declare `required` beside it.
Node 24 strips erasable TypeScript syntax. Provision dependencies in the toolbox.

#### Lifecycle

1. **Submit** — `submit({manifest, files, entry, kind?}, context)` saves an
   immutable versioned snapshot, validates the source in a guest container
   (admission), and activates it.
2. **Execute** — `execute(toolName, args, context)` runs the active version's
   entry function with the supplied arguments. Failed executions increment
   the version's `failureCount` and record `lastError`.
3. **Replace** — submitting the same plugin id creates a new active version.
   Prior versions are retained for rollback (up to 32 per plugin).
4. **List** — `list()` returns every retained version with its
   `evidenceStatus` (`structural` for direct submits, `measured` for evolved
   versions), `active` flag, `failureCount`, and `lastError`.
5. **Rollback** — `rollback(pluginId, versionId, context)` reactivates a
   prior version. Retains the rolled-back version for further rollback.
6. **Evolve** — `evolve(pluginId, profile, deps, context)` runs the
   improvement loop over the active version's snapshot, producing a new
   `measured` version on promotion.
7. **Close** — releases the manager and aborts pending operations.

For the model-facing lifecycle, use `self_extend` with `action` set to `submit`,
`list`, `evolve`, or `rollback`. Point `0SEC_PLUGIN_EVOLUTION_CONFIG` at an
operator-owned [source-evolution config](/improvement-plane/#config-shape) to
expose the `default` evaluation profile. It must use the same backend and pinned
image as the executable. Creation and replacement work without a profile;
measured evolution requires one.

YOLO removes per-action prompts within the configured scope; it does not let
generated code replace its evaluator, inherit provider credentials, or expand
host authorization. Direct submissions are structurally admitted; measured
evolution requires the improvement loop.

#### Storage

Versions are stored in `registry.json` under the configured root. Each version
records its snapshot UUID (content-addressed files under `snapshots/<uuid>`),
immutable image digest, manifest digest, and (for evolved versions) the
evolution receipt digest. The registry is validated on every read — tampered
entries, dangling snapshots, or mismatched digests are rejected.

#### Backend

| Backend | Requirement | Isolation |
|---------|------------|-----------|
| `docker` (default) | Local Docker daemon; configured Node 24 toolbox image | `--network none`, read-only root, cap-drop all, no-new-privs, PIDs limit, bounded memory/CPU |
| `smolvm` | KVM, smolvm **1.14.6**, Node 24 toolbox archive | MicroVM with dedicated kernel; bounded resources and no guest network |

Default image for agent-created submissions is `0sec-toolbox:local`, overridable
with `0SEC_PLUGIN_IMAGE`; the smoke script defaults to `0sec-toolbox:qualification`.
For smolvm, configure `0SEC_SMOLVM_IMAGE_ARCHIVE`. The image is resolved to an immutable digest
on first use; resumed/promoted versions retain that digest, not a retagged
reference.

The backend isolates executable plugins and evolution workers. The controller
and authorized host tools execute outside it. Every invocation starts a fresh
guest; smolvm incurs VM startup overhead.

#### Version lifecycle diagram

```
submit        ┌──────────┐     execute ──► success
  │           │ Version 1 │                 └── failureCount++
  ├──►active  │(structural)│
  │           └────┬──────┘
submit v2         │
  │           ┌────▼──────┐
  ├──►active  │ Version 2 │     rollback ──► Version 1 active again
  │           │(structural)│
  │           └────┬──────┘
evolve            │
  │           ┌────▼──────┐
  └──►active  │ Version 3 │
              │(measured) │
              └───────────┘
```

### CLI-managed operator plugins

**Source:** `packages/cli/src/commands/plugin.ts`

**Status:** Scaffolded. No marketplace ships. The default registry endpoint is
intentionally empty. Plugins can be loaded from local filesystem paths for
development.

#### Subcommands

| Subcommand | Description |
|------------|-------------|
| `0sec plugin list` | List installed plugins |
| `0sec plugin search <query>` | Search the plugin registry (empty by default) |
| `0sec plugin install <id>` | Write plugin files to disk (does not execute) |
| `0sec plugin enable <id>` | Record operator decision to permit the plugin |
| `0sec plugin disable <id>` | Revoke enablement |
| `0sec plugin info <id>` | Show plugin manifest and capabilities |
| `0sec plugin run <id> [tool]` | Invoke one contributed tool of an enabled plugin |

#### Security model

CLI-managed plugins have three distinct states:

| State | Description |
|-------|-------------|
| **Installed** | Files on disk. `install` writes bytes; runs nothing |
| **Enabled** | Per-project operator decision recorded by the enablement store |
| **Running** | Tool invocation. Only enabled plugins with declared capabilities execute |

CLI plugin capabilities declared in the manifest and gated at runtime:
`network`, `filesystem-read`, `filesystem-write`, `process-exec`,
`findings-write`

## Disclose and evidence

`0sec disclose` provides structured vulnerability disclosure tooling for
findings generated during a scan.

**Source:** `packages/cli/src/commands/disclose.ts`

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `0sec disclose [findingId]` | Ad-hoc disclosure for a specific finding |
| `0sec disclose evidence-pack <finding.json>` | Assemble a DRAFT vendor notification markdown (never sends) |
| `0sec disclose track <findingId>` | Drive the disclosure tracking state machine |
| `0sec disclose review <finding.json>` | Render a deterministic reproducibility manifest |

### Evidence pack

The `evidence-pack` subcommand produces a draft vendor notification containing
what/where/impact/repro/remediation sections. It emits a mandatory
`DRAFT — NOT SENT` banner.

```bash
0sec disclose evidence-pack finding.json --target "lodash@4.17.21" --out notification.md
```

Options:
- `--target <label>` — affected target/package label
- `--affected-ref <ref>` — git ref or version range
- `--allow-unreproduced` — stage a draft even without PoC reproduction
- `--out <file>` — write to file instead of stdout

### Disclosure tracking

The `track` subcommand drives a state machine through statuses defined in
`@0sec/core`:

```bash
# Open a fresh draft record
0sec disclose track finding-001 --out record.json

# Transition to "sent" with vendor info
0sec disclose track finding-001 \
  --record record.json \
  --to sent \
  --disclosed-to "Vendor Security Team" \
  --message "Initial notification" \
  --out record.json

# Record CVE assignment
0sec disclose track finding-001 \
  --record record.json \
  --to cve_assigned \
  --cve-id CVE-2025-12345 \
  --out record.json
```

### Reproducibility manifest

The `review` subcommand produces a deterministic, redacted manifest safe for
human inspection. It never sends or publishes anything.

```bash
0sec disclose review finding.json --target "lodash@4.17.21" --out manifest.json
```

## Orchestrate

`0sec orchestrate` runs an autonomous work queue over a shared SQLite database.

**Source:** `packages/cli/src/commands/orchestrate.ts`

### Modes

| Mode | Flag | Description |
|------|------|-------------|
| Worker | `0sec orchestrate --db-path ./scans.db` | Claim and execute one batch of runnable work items, then exit |
| Watcher | `0sec orchestrate --db-path ./scans.db --watch` | Poll for new work items continuously |

### Work item types

The orchestrator processes these work item kinds in order of priority:

| Kind | Priority | Description |
|------|----------|-------------|
| `surface_map` | 0 (highest) | Map the target surface |
| `hypothesis` | 1 | Generate attack hypotheses |
| `poc_build` | 2 | Build proof-of-concept |
| `blind_verify` | 3 | Blind verification |
| `consensus` | 4 | Consensus across findings |

A work item is runnable when its status is `todo`, its dependency is `done`,
and no sibling for the same case is `in_progress`.

### Stale worker recovery

The orchestrator detects workers whose heartbeat has expired (default 30s stale
threshold) and resets their in-progress work items to `todo` so another worker
can claim them.

```bash
# Recover stale workers from any orchestrator session
node -e "require('./dist/commands/orchestrate').recoverStaleWorkers('./scans.db')"
```

### Target format

The orchestrator supports these target URL schemes:

| Format | Target type | Scan mode |
|--------|-------------|-----------|
| `https://example.com` | URL | `deep` (default) |
| `web:https://example.com` | Web app | `web` |
| `mcp://host/path` | MCP endpoint | `mcp` |
| `scan:<scanId>` | Re-run from prior scan | `deep` (default) |

## Verification engine

`0sec verify` exposes deterministic replay and kernel reproducer workflows.
The selected mode controls prerequisites, result shape, and exit-code meanings.

**Source:** `packages/cli/src/commands/verify.ts`

### Results, exit codes, and runners

Exit codes, results, and runners are mode-specific. Follow
[Scan Workflows](/scan-workflows/) for choosing the mode,
[Verification Results](/verification-result/) for deterministic replay statuses,
and [Kernel VM Verification](/kernel-vm/) for QEMU prerequisites.

Local, Docker, and kernel execution have distinct safety boundaries.
Use only the runner and fixture options registered by the selected command. An
SDK runner type is not automatically a CLI option.

## Report export

```bash
# SARIF for code scanning
0sec review . --format sarif > results.sarif

# HTML report
0sec scan --target http://127.0.0.1:8080 --scope ./scope.json --format html

# PDF report
0sec scan --target http://127.0.0.1:8080 --scope ./scope.json --format pdf
```

### Report summary output

JSON, Markdown, and SARIF are emitted as formatted output. HTML and PDF reports
are written to timestamped files under the system temporary directory; the CLI
prints the generated path. `scan` has no `--report-path` flag.
Copy the emitted HTML/PDF file to your desired destination before temporary
files are cleaned up. Redirecting stdout does not relocate that report.

## See also

- [GitHub CI](/ci/github-action/) — running 0sec in CI pipelines
- [Configuration](/configuration/) — runtime modes, scan modes, env vars
- [API Keys](/api-keys/) — provider setup
- [Scope & Authorization](/scope/) — scope JSON files and access control
- [Commands](/commands/) — full command reference
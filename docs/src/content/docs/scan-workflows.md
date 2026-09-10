---
title: Scan Workflows
description: Choose a scan or source review, authorize it, inspect saved findings, verify evidence, and validate a source fix.
---

Use this guide for the operator workflow. [Commands](/commands/) is the exhaustive flag reference; [Configuration](/configuration/) explains runtime and configuration resolution.

## Choosing a target path

| Task | Command | Boundary |
|---|---|---|
| Web application | `0sec scan --target https://staging.example.com --scope ./scope.json` | Active network assessment |
| MCP endpoint | `0sec scan --target mcp://server.example.com --scope ./scope.json` | Active MCP assessment |
| Local source or Git repository | `0sec review ./my-app` | Source review; preparation and tools can access the network |
| npm package | `0sec audit express` | Package acquisition and analysis |
| Whole-repository file coverage | `0sec file-review ./my-app` | File-level review with its own checkpoints |
| Seedless specialized review | `0sec deep-review ./my-app` | Multi-lens discovery; survivors remain leads |

Explicit commands avoid ambiguity in bare-target routing. `scan --mode` selects `probe`, `deep`, `mcp`, `web`, or worker-driven `http_audit`. A review target profile is different: `review --target c-library ./libfoo` selects the C-library review path, not a URL.

For variant hunting, specification checks, fuzzing, binaries, and kernel workflows, see [Research Workflows](/research-workflows/).

## Authorization and scope

`scan` requires an engagement scope for HTTP, HTTPS, and MCP targets, including localhost. Worker-driven `http_audit` instead builds its policy from operator-provided configuration. Neither `--require-scope` nor its absence is a way to bypass the live-target requirement.

Start with the schema and matching rules in [Scope & Authorization](/scope/). Authorize only the hosts, paths, and activities covered by your engagement.

```bash
0sec scan --target https://staging.example.com --scope ./scope.json
```

Scope is an application-level policy, not an OS sandbox. Source review and package audit do not require a live-target scope file, but can acquire dependencies, clone repositories, or execute tooling. Run untrusted inputs on a disposable worker without unrelated credentials.

### Attribution and engagement posture

```bash
0sec scan --target https://staging.example.com --scope ./scope.json \
  --attribution-header "X-Customer=acme-corp" \
  --attribution-ua "pentest-engagement" \
  --engagement-profile conservative
```

The conservative posture changes request behavior, rate defaults, and WAF-evasion behavior. `--no-waf-evasion` explicitly disables the adaptive evasion path. These settings do not grant authorization. See [Authorized Engagements](/engagements/) for precedence and limits, rather than assuming every setting follows one global merge rule.

## Authentication and runtime

Provider credentials pay for model calls. Target credentials authenticate to the assessed application. Cloud login is a third, separate credential flow.

```bash
0sec scan --target https://staging.example.com --scope ./scope.json \
  --auth ./auth.json --api-spec ./openapi.yaml --depth deep
```

`--auth` accepts a JSON object or a file containing one. Supported forms include:

```json
{"type":"bearer","token":"your-target-token"}
```

```json
{"type":"cookie","value":"session=your-session-cookie"}
```

```json
{"type":"basic","username":"test-user","password":"your-test-password"}
```

```json
{"type":"header","name":"X-API-Key","value":"your-target-api-key"}
```

Keep credential files out of version control and prefer a file over secrets in shell history. [API Keys](/api-keys/) covers provider authentication; [White-Box Mode](/white-box-mode/) covers adding `--repo` source context to a live assessment.

## Depth and cost controls

`--depth quick`, `default`, and `deep` select different investigation budgets. They are not guaranteed wall-clock deadlines, and a clean result does not prove the absence of vulnerabilities.

```bash
0sec scan --target https://staging.example.com --scope ./scope.json \
  --depth quick --cost-ceiling 5 --rate-limit 2
```

`--cost-ceiling` bounds tracked model spend. `--timeout` is not a universal command deadline. Rate limits, provider/runtime billing, and partial-run behavior have separate contracts; see [Budget Management](/budget-management/).

### Optional capabilities

`scan --features` enables supported feature tokens. `fp-moat` is a preset, not a claim that every layer ran or that all remaining findings are reproduced.

```bash
0sec scan --target https://staging.example.com --scope ./scope.json \
  --features fp-moat
```

Inspect per-finding triage provenance. A skipped layer and an unrecorded layer are different. [Features](/features/) lists current toggles; [Finding Triage](/triage/) explains the evidence gates.

## Output formats and saved state

The default output is `terminal`. `json`, `md`, and `sarif` support machine-readable or text exports:

```bash
0sec scan --target https://staging.example.com --scope ./scope.json \
  --format json > scan.json
0sec review ./my-app --format sarif > results.sarif
```

HTML and PDF output write a timestamped report under the system temporary directory and print its path. Redirecting stdout does not relocate the generated report. `scan` does not register `--report-path`; copy the emitted file to durable storage. See [Integrations](/integrations/#report-formats).

### SQLite database

Current scan storage is run-local: by default `~/.0sec/runs/<scan-id>/state.db`, subject to the configured state root. `--db-path` selects an explicit database. Do not assume every command uses a single `~/.0sec/0sec.db`.

```bash
0sec scan --target https://staging.example.com --scope ./scope.json \
  --db-path ./engagement.db
0sec history --db-path ./engagement.db
0sec findings --db-path ./engagement.db
```

Keep the database and associated run artifacts when handing off or resuming work. Cloud engagement IDs, console sessions, and scan IDs are not interchangeable.

## Viewing and triaging findings

Use the same database that holds the scan:

```bash
0sec findings --db-path ./engagement.db
0sec findings show FINDING_ID --db-path ./engagement.db
0sec findings accept FINDING_ID --db-path ./engagement.db
0sec findings suppress FINDING_ID --db-path ./engagement.db
0sec findings reopen FINDING_ID --db-path ./engagement.db
```

Replace `FINDING_ID` with the recorded ID or supported unique prefix. Accepting or suppressing a finding records a human decision; it does not execute a verifier.

For false-positive feedback and durable memories:

```bash
0sec triage mark-fp FINDING_ID --reason "Known test-only behavior" --db-path ./engagement.db
0sec triage memory add --finding FINDING_ID --reason "Known test-only behavior" --db-path ./engagement.db
0sec triage memory list --db-path ./engagement.db
0sec triage memory remove MEMORY_ID --db-path ./engagement.db
```

Review request/response evidence, source locations, lifecycle state, verifier outcomes, and triage provenance together. Persisted rows and discovery leads are not automatically confirmed findings.

## Resuming vs replaying

### Resume — continue execution

```bash
0sec resume SCAN_ID --db-path ./engagement.db
0sec resume SCAN_ID --db-path ./engagement.db --format json
0sec resume SCAN_ID --db-path ./engagement.db --branch-from 12
```

Resume requires compatible persisted scan state. Journal-based branching also requires the relevant journal entries. Keep the run's artifacts; a JSON report alone is not a resumable checkpoint. The standalone resume command supports specific persisted target routes, not every research or console workflow.

For a live scan that needs its explicit scope supplied again, use the scan entry point:

```bash
0sec scan --target https://staging.example.com --scope ./scope.json \
  --db-path ./engagement.db --resume SCAN_ID
```

Do not assume standalone resume restores target credentials or authorization that are absent from its options. Console continuation has a separate contract in [Console](/console/).

### Replay — render stored results

```bash
0sec replay
0sec replay --scan SCAN_ID
0sec scan --replay
```

Replay renders saved findings; it does not launch a fresh assessment or independently reproduce the vulnerability. `verify` is a different operation.

## Verification and evidence

[Blind Verification](/blind-verification/) explains independent agent verification. Deterministic replay instead executes a particular finding, fixture, or reproduction bundle and records concrete assertions. Verification availability and outcomes depend on the selected path; do not assume every stored finding passed the same pipeline.

### Explicit verification with `0sec verify`

```bash
# Execute a finding with the selected runner.
0sec verify finding.json --runner docker

# Replay vulnerable and patched snapshots from a reproduction bundle.
0sec verify --bundle ./bundle-dir --runner docker

# Use the separate kernel-finding verification path.
0sec verify --kernel-finding finding.json --kernel-tree ./linux
```

A scan report containing many findings is not itself a single `finding.json`. Preserve the selected finding's executable verification data and target context. The Docker runner requires its runtime prerequisites; local execution runs on the host. Kernel execution requires its own setup in [Kernel VM Verification](/kernel-vm/).

The fixture path is documented with a complete invocation in [Verification Results](/verification-result/#cli-path-traversal-example). Reproduction bundles, runner-based replay, legacy PoC-step execution, and kernel verification have different result contracts. Inspect the emitted JSON and the mode's exit semantics rather than interpreting every exit `2` as the same condition.

A negative replay result can mean the tested environment differs from the original finding. An inconclusive or failed setup is not evidence that a vulnerability is fixed.

## Fix workflow

`fix` takes a **clean local Git worktree**, not a finding file as its positional argument. Select one reproduced source finding, provide its verification contract, and supply an explicit regression command.

```bash
0sec fix ./my-app --finding ./finding.json \
  --test-command "npm test" --output ./validated.apply-patch
```

The external finding must carry `verificationSpec`. If it does not already carry the required verification result, pass `--verification-result ./verification-result.json`. Alternatively select a persisted finding with `--finding-id` and `--db-path`.

The workflow generates and checks a candidate in an isolated worktree. `--output` writes validated **apply_patch DSL**, not a standard unified diff. By default it does not apply the candidate to the original worktree.

```bash
0sec fix ./my-app --finding ./finding.json \
  --test-command "npm test" --apply
```

Only use `--apply` when you intend to modify the original repository. The regression command itself executes code; a separate worktree is not an OS sandbox.

| Exit | Meaning |
|---|---|
| `0` | Validated candidate, or applied and retested |
| `1` | Not fixed |
| `2` | Precondition failed or error |

See [Commands — fix](/commands/#fix) for the complete prerequisite and option reference.

## Package and source workflows

```bash
0sec audit express --package-version 4.18.2
0sec audit requests --ecosystem pypi
0sec audit serde --ecosystem cargo
0sec audit alpine:3.20 --ecosystem oci

0sec review ./my-app
0sec review https://github.com/your-org/your-repository
0sec review ./my-app --diff-base origin/main --changed-only
0sec review --target c-library ./libfoo --depth deep
0sec review --target linux-kernel ./linux
```

Use the ecosystem and version actually covered by your authorization. `--changed-only` narrows the documented review path; it is not proof of whole-repository coverage. `file-review` and `deep-review` offer different coverage/analysis tradeoffs and do not share all of `review`'s options.

## Export and disclosure

GitHub export and PR emission are external writes and require repository authorization and credentials:

```bash
0sec scan --target https://staging.example.com --scope ./scope.json \
  --export github:your-org/security-findings
0sec scan --target https://staging.example.com --scope ./scope.json \
  --emit pr --base main --dry-run
```

**`--dry-run` controls PR emission only. The scan still runs.** It is not a network-free preview or cost-free planning mode. Review [Integrations](/integrations/) and [GitHub CI](/ci/github-action/) before enabling automatic external writes.

## Troubleshooting

- **Scope refusal:** supply a valid engagement scope; do not remove the target protocol to bypass authorization checks.
- **Missing findings or scan:** check the run ID, state root, and selected `--db-path`.
- **Provider error:** use [API Keys](/api-keys/) and [Configuration](/configuration/); cloud login does not automatically configure a model provider.
- **Interrupted or budget-limited run:** inspect completion/error state and retained artifacts before deciding whether resume is supported. Zero findings from an incomplete run is not a clean pass.
- **Verification cannot execute:** inspect the mode's prerequisites and errors. Changing a finding's human triage state will not repair an executable verification contract.
- **Fix refuses:** check the clean Git worktree, source finding, verification evidence, and explicit regression command. Do not bypass preconditions by relabeling a finding.

For detailed runtime diagnosis, see [Troubleshooting](/troubleshooting/). For every command's arguments and options, use [Commands](/commands/) or `0sec COMMAND --help` for your installed release.

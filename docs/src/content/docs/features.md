---
title: Features
description: Find the supported 0sec workflow for your target, with links to command contracts, configuration, and evidence limits.
---

Use this page to choose a workflow. The [command reference](/commands/) owns the
syntax and flags; the linked guides explain prerequisites and what the output
means. A supported target type is not a guarantee that every vulnerability class
will be found or reproduced.

## Target coverage

| Target or task | Entry point | Guide |
| --- | --- | --- |
| Web application or REST API | `scan --mode web` | [Scan Workflows](/scan-workflows/) |
| AI/LLM endpoint or MCP target | `scan` with the appropriate mode | [Commands](/commands/#scan) |
| Source repository | `review` | [Scan Workflows](/scan-workflows/) |
| Source plus a running application | `scan --repo` | [White-Box Mode](/white-box-mode/) |
| npm, PyPI, Cargo package, or OCI image | `audit --ecosystem` | [Scan Workflows](/scan-workflows/) |
| Focused source and vulnerability research | `hunt`, `deep-review`, and specialized research commands | [Research Workflows](/research-workflows/) |
| Kernel reproduction | `kernel`, `verify`, and `research` families | [Kernel VM Verification](/kernel-vm/) |
| Compiled binary evidence | `binary` and the 0verse adapter | [Research Workflows](/research-workflows/) |
| Identity and offline relationship analysis | `identity`, `adgraph`, `entragraph` | [Authorized Engagements](/engagements/) |
| Stateful agent assurance | `agent-assure` | [Adversarial Evals](/adversarial-evals/) |
| Candidate evaluation and promotion | `evolve` | [Improvement Plane](/improvement-plane/) |

Live network testing needs explicit authorization and scope. A local source
review can still invoke tools, download dependencies, or contact a model
provider; “local target” does not mean “offline execution.”

## CLI flags (scan)

Start with [the scan reference](/commands/#scan) for the complete option table.
The main choices are target/mode, scope, model/runtime, depth/cost ceiling,
authentication, and output format. Flags vary by command; do not assume a `scan`
flag also works with `review`, `verify`, or a research subcommand.

### Authenticated scanning

Use `--auth` for target credentials, not model credentials. The scan command
accepts a JSON value or a JSON file for bearer, cookie, basic, or custom-header
authentication. Prefer a restricted file over putting a real token into shell
history. See [credential formats](/commands/#--auth-credential-formats) and
[Authorized Engagements](/engagements/) for engagement preparation.

### API spec import

`scan --api-spec` seeds endpoint knowledge from an OpenAPI or Swagger document.
It does not authorize the described hosts or guarantee endpoint coverage. See
[the API recipe](/recipes/#scan-a-rest-api-openapi).

### Export to GitHub Issues

`scan --export github:owner/repo` is an external write, not just a local report
format. Review the destination, permissions, and sensitive evidence before use.
[Integrations](/integrations/) covers automation and publishing boundaries.

## Runtimes

Model runtime and tool executor are separate choices. A model provider receives
model requests; a tool executor runs actions. Selecting a hosted model does not
move shell execution off your machine.

[Configuration](/configuration/) documents runtime selection and fallback.
[API Keys](/api-keys/) documents supported providers, model routing, credential
sources, and subscription authentication. Use those references rather than an
independent provider list here.

## Executors and tools

The default shell path executes on the host. Optional Docker execution and
specialized replay/VM paths have different isolation boundaries and prerequisites.
Neither scope checks nor a cost ceiling is an OS sandbox.

The available tools depend on the workflow and feature settings. See
[Configuration](/configuration/) for executor controls,
[Console](/console/) for interactive approvals, and
[Research Workflows](/research-workflows/) for tools that compile or execute
untrusted programs.

## Output formats

Supported formats vary by command. Core scan/review/audit flows expose terminal,
JSON, Markdown, HTML, SARIF, and PDF output; use each command's reference for its
actual options. A local report, a saved journal, and a deterministic verification
result are different artifacts.

[Scan Workflows](/scan-workflows/) explains how to inspect and retain results.
[Integrations](/integrations/) covers CI and machine-readable output.

## Triage pipeline

Candidate generation, automated verification, and human triage are separate
steps. Optional gates and available evidence vary by target and execution path.
An unavailable verifier or a skipped check cannot establish that a target is
secure.

Read [Finding Triage](/triage/), [Blind Verification](/blind-verification/), and
[Verification Results](/verification-result/) for the actual contracts. Do not
interpret a severity label as proof or assume every workflow enables every gate.

## Agent loop enhancements

The agent loop supports budgeting, context management, tool use, and feature-gated
research strategies. [Agent Loop](/agent-loop/) explains the control flow;
[Budget Management](/budget-management/) distinguishes turn limits from spend
limits; [Configuration](/configuration/) owns feature settings and defaults.

Use [Console](/console/) for interactive work. Desktop is in development; see
[Roadmap](/roadmap/#desktop) for status.

## Benchmarks

[Benchmarks](/benchmark/) and [Methodology](/methodology/) are the single source
for published scores, configurations, and caveats. Historical research results
are not current-target guarantees or a managed-service availability statement.

## Unified SOC story

For the integrations that actually ship in this repository, use
[Integrations](/integrations/). Do not infer an operational integration merely
because another tool appears in an architecture diagram or ecosystem comparison.
The managed offering (0cloud) is in development; see [Roadmap](/roadmap/#0cloud) for status.

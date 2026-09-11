---
title: Features
description: Find the supported 0sec workflow for your target, with links to command contracts, configuration, and evidence limits.
---

Choose a workflow by target, then follow its setup and authorization requirements.

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

Live network testing requires authorization and scope. Source review may execute
tools, download dependencies, and send model requests. Coverage depends on the target and available evidence.

## CLI flags (scan)

See [Commands](/commands/#scan) for `scan` target, scope, model, budget,
authentication, and output flags. Other commands have their own options.

### Authenticated scanning

Use `--auth` for target credentials. Model credentials use separate environment
variables. The scan command accepts a JSON value or a JSON file for bearer,
cookie, basic, or custom-header authentication. Prefer a restricted file over
putting a real token into shell history. See
[credential formats](/commands/#--auth-credential-formats) and
[Authorized Engagements](/engagements/) for engagement preparation.

### API spec import

`scan --api-spec` seeds endpoint knowledge from an OpenAPI or Swagger document.
It does not authorize the described hosts or guarantee endpoint coverage. See
[the API recipe](/recipes/#scan-a-rest-api-openapi).

### Export to GitHub Issues

`scan --export github:owner/repo` writes findings to the remote repository.
Review the destination, permissions, and sensitive evidence before use.
[Integrations](/integrations/) covers automation and publishing boundaries.

## Runtimes

The model provider handles inference. The tool executor runs actions.
Hosted model selection leaves local shell execution on your machine.

[Configuration](/configuration/) documents runtime selection and fallback.
[API Keys](/api-keys/) documents supported providers, model routing, credential
sources, and subscription authentication.

## Executors and tools

The default shell path executes on the host. Optional Docker execution and
specialized replay/VM paths have different isolation boundaries and prerequisites.
Neither scope checks nor a cost ceiling is an OS sandbox.

Available tools depend on the workflow and feature settings. See
[Configuration](/configuration/) for executor controls,
[Console](/console/) for interactive approvals, and
[Research Workflows](/research-workflows/) for tools that compile or execute
untrusted programs.

## Output formats

Supported formats vary by command. Core scan/review/audit flows expose terminal,
JSON, Markdown, HTML, SARIF, and PDF output. A local report, a saved journal,
and a deterministic verification result are different artifacts.

[Scan Workflows](/scan-workflows/) explains how to inspect and retain results.
[Integrations](/integrations/) covers CI and machine-readable output.

## Triage pipeline

Candidate generation, automated verification, and human triage have separate
evidence requirements. Available gates vary by target and workflow.
See [Finding Triage](/triage/), [Blind Verification](/blind-verification/), and
[Verification Results](/verification-result/). Skipped or unavailable checks
leave coverage unknown.

## Agent loop enhancements

The agent loop supports budgeting, context management, tool use, and feature-gated
research strategies. [Agent Loop](/agent-loop/) explains the control flow;
[Budget Management](/budget-management/) distinguishes turn limits from spend
limits; [Configuration](/configuration/) owns feature settings and defaults.

Use [Console](/console/) for interactive work. Desktop is in development; see
[Roadmap](/roadmap/#desktop) for status.

## Benchmarks

Published benchmark scores, configurations, and caveats are in
[Benchmarks](/benchmark/) and [Methodology](/methodology/). Historical research
results are not current-target guarantees.

<span id="unified-soc-story"></span>
## Related products

See [Integrations](/integrations/) for connected tools and
[Roadmap](/roadmap/#0cloud) for managed 0cloud status. Optional
[0sec Cloud inference](/getting-started/#hosted-models-draft) has separate setup and availability.
See [Commands](/commands/) for the full CLI reference.
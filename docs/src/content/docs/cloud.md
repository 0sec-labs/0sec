---
title: 0sec cloud
description: How managed cloud engagements relate to the open-source CLI, what to prepare, and where to start.
---

0sec cloud is the managed engagement and orchestration layer around the 0sec
engine. Use the CLI when you run assessments yourself; use the managed path when
you agree on scope and delivery with the 0sec team.

## Choose a workflow

| | CLI | Managed cloud |
| --- | --- | --- |
| Start | [Install and run locally](/getting-started/) | [Request access](/cloud/getting-started/) |
| Execution | You configure and run the engine | Execution is arranged within an agreed engagement |
| Scope | You supply the authorized scope | Agree on targets, exclusions, access, and testing constraints with the team |
| Models and budget | [Configure providers](/api-keys/) and [CLI limits](/budget-management/) | Agree on engagement depth and commercial terms before execution |
| Evidence | Inspect local output and replay artifacts | Review the evidence and coverage delivered for the agreed scope |

A cloud engagement is not required to use the open-source CLI. CLI flags and
local configuration do not automatically configure a managed engagement.

## Availability

Managed access is invite-only. Start at
[Apply to get hacked](https://0.security/contact?intent=early-access).
Submitting that form is an access request, not authorization to run a scan or a
self-service checkout. Confirm available workflows and delivery terms with the
team before depending on them.

These guides describe engagement preparation and evidence review. They do not
assume a generally available customer dashboard, public cloud API, automatic
scheduling, or self-service billing.

## Work through an engagement

1. [Get started](/cloud/getting-started/): request access and prepare the initial brief.
2. [Define scope and access](/cloud/scope-and-access/): identify targets, test accounts, exclusions, and stop conditions.
3. [Review evidence](/cloud/review-evidence/): distinguish a finding from a hypothesis, check coverage, and plan a retest.

## Shared technical references

The engine's [architecture](/architecture/), [triage](/triage/), and
[verification](/blind-verification/) are documented once for both workflows.
[Verification Results](/verification-result/) defines the deterministic replay
contract when that evidence is included. [Benchmarks](/benchmark/) describe
measured engine results, not a coverage guarantee for an individual engagement.

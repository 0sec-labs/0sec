---
title: 0cloud evidence review — development draft
description: Unpublished evidence-review considerations for the unreleased 0cloud product.
draft: true
pagefind: false
---

**0cloud is not released.** This is draft planning material, not a description
of an available delivery workflow. Verify it before publishing.

Start with the tested scope and its limits, then inspect each finding. A report
is evidence about the tests performed, not a guarantee that no other
vulnerabilities exist.

## Check coverage first

Compare the delivery against the agreed targets, environment, version,
identities, and testing window. Identify any targets or workflows blocked by
access, expired credentials, budget, setup failures, or unavailable
dependencies.

A completed run is not the same as complete coverage. Ask for clarification
when the record does not explain whether a security boundary was exercised.

## Read a finding

For each finding, check:

1. **Affected surface** — endpoint, component, or source location and tested version.
2. **Preconditions** — required identity, role, tenant, configuration, or existing access.
3. **Reproduction** — steps and input that exercised the suspected issue.
4. **Observed evidence** — what actually happened, not only what a model predicted.
5. **Impact and limits** — what the evidence proves and what remains untested.
6. **Remediation** — proposed fix and how to test the relevant boundary again.

Handle evidence as sensitive: request/response bodies, screenshots, paths, and
logs can contain credentials or personal data. Share only with agreed
recipients and redact before moving into a public issue.

## Separate proof from triage

A candidate is a lead to investigate. Verification checks whether the suspected
behavior can be reproduced. Human triage decides how to handle the finding.
These are different decisions; severity and a lifecycle label are not a
substitute for reproduction evidence.

The [Blind Verification](/blind-verification/) guide explains the independent
verification approach. When a delivery includes a deterministic
`verification_result`, use the [Verification Results](/verification-result/)
contract rather than guessing from process exit codes or a summary sentence.
Not every evidence artifact uses that contract.

## Plan a retest

Provide the finding identifier, patched version or deployment, fix description,
and any changed access requirements. Agree on retest scope before running,
especially if production access or state-changing actions are involved.

A useful retest checks both the original failure condition and the expected
allowed behavior. If an expired account, unreachable target, or broken setup
prevents the test, the outcome is not proof of remediation. Record the blocker
and rerun when valid conditions are restored.

For local reproduction and verification tooling, see [Commands](/commands/)
and [Verification Results](/verification-result/). A CLI artifact path is not a
public download URL; use the delivery mechanism agreed for the engagement.

## Resolve incomplete evidence

| Gap | Ask for |
| --- | --- |
| No tested version or identity | The environment and preconditions needed to interpret the result. |
| Impact described without an observation | The reproduction and evidence supporting the claim. |
| No reproduction after a fix | A retest under valid conditions, not just a changed lifecycle label. |
| Access or setup failure | An explicit coverage limitation and a plan to remove the blocker. |
| Evidence cannot be shared safely | A redacted artifact or an agreed restricted review path. |

Return to the [Cloud overview](/cloud/) or [prepare another engagement](/cloud/getting-started/).

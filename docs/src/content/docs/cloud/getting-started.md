---
title: 0cloud preparation — development draft
description: Unpublished engagement-preparation notes for the unreleased 0cloud product.
draft: true
pagefind: false
---

**0cloud is not released.** These are proposed preparation notes, not an
available onboarding flow or invitation to use a service. Verify and rewrite
them against the released product before publishing.

## 1. Prepare a short brief

Describe the systems you own or are authorized to test, the environment (staging
or production), and the security question you need answered. Include the
expected delivery window and any restrictions that affect testing.

For example:

```text
Target: our staging web application and its API
Goal: test whether users can access another tenant's records
Access: dedicated test accounts for two tenants can be provided
Excluded: production, payment processing, and third-party identity services
Constraints: agree on request rate, testing window, and a stop contact
Deliverable needed: reproduction evidence and a retest after remediation
```

This is an engagement brief, not a CLI scope file. It does not authorize testing
until the scope and rules of engagement are agreed.

## 2. Request access

Open [Apply to get hacked](https://0.security/contact?intent=early-access).
Provide your name, organization, role, work email, and a short description of
what should be tested.

Do not paste passwords, API keys, session cookies, customer records, or private
source code into the contact form. Describe the access you can provide; agree on
how to transfer sensitive material separately.

Submitting an application does not start a scan or purchase a plan. Managed
access and execution are arranged with the team.

## 3. Agree on scope and access

Work through [Scope & Access](/cloud/scope-and-access/). Confirm authorized
targets, excluded systems, accounts, permitted actions, execution window, and
stop procedure.

Also confirm commercial and delivery terms: engagement depth, outputs,
recipients, data handling, and whether retesting or recurring work is included.
CLI [turn and cost limits](/budget-management/) are engine controls, not managed
engagement pricing.

## 4. Review the outcome

Use [Review Evidence](/cloud/review-evidence/) when results are delivered.
Check what was tested and what was blocked, inspect reproduction evidence, and
agree on the next action for each finding.

A retest request should identify the finding, the remediation, the target
version or deployment, and any changed access requirements. Do not treat a scan
that could not reach the target as proof that a fix worked.

## If you cannot proceed

| Situation | Next action |
| --- | --- |
| No managed access yet | Use the contact route above; use the CLI independently if appropriate. |
| Target is private or behind SSO | Describe the access constraint without sending credentials in the form. Agree on a reachable test path. |
| Testing authorization is unclear | Resolve permission and exclusions with the system owner before execution. |
| Need a specific integration or delivery format | Confirm it during scoping rather than assuming it is generally available. |

Continue with [Scope & Access](/cloud/scope-and-access/).

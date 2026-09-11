---
title: 0cloud scope and access — development draft
description: Unpublished scope and access considerations for the unreleased 0cloud product.
draft: true
pagefind: false
---

**0cloud is not released.** This is draft planning material. It will be verified
against the released product before publishing.

Scope describes what may be tested. Reachability and credentials describe what
can be tested. Agree on both before execution; a reachable system is not
automatically an authorized target.

## Define the scope boundary

Prepare with the system owner:

| Item | What to specify |
| --- | --- |
| Targets | Exact application/API URLs or source repositories, environment, and relevant version or commit. |
| Authorization | Who owns each target and who can approve the requested testing. |
| Exclusions | Third-party services, production systems, paths, accounts, and data that must not be touched. |
| Allowed actions | Whether account creation, record mutation, uploads, emails, or other side effects are permitted. |
| Timing | Testing window, timezone, rate constraints, and maintenance periods. |
| Stop conditions | Who can stop the engagement, how to reach them, and events that require a pause. |
| Desired evidence | The security questions and reproduction detail needed for remediation. |

Do not use a broad wildcard when only a particular application is authorized.
Redirects, shared hosting, and third-party login pages can cross the intended
boundary. Identify those cases explicitly.

## Prepare authenticated access

Prefer dedicated, least-privilege test identities and synthetic data. For
cross-user or cross-tenant authorization testing, prepare distinct identities
with known ownership of separate test resources. One admin account cannot
represent every user boundary.

For each identity, record its intended role, tenant, permitted actions, and
expiry. Describe SSO, MFA, session expiry, IP restrictions, or other controls
that may prevent automated access. Agree on the supported access path. Do not
disable security controls broadly.

Keep secrets out of public issues and initial contact forms. Arrange credential
transfer with the team, then revoke temporary access at the agreed end of the
engagement.

## Make side effects explicit

Even a benign reproduction can change state or notify a real user. Agree on:

- Disposable records and accounts that may be created, changed, or deleted.
- Whether outbound email, webhooks, payment actions, or uploads are permitted.
- Limits on data read or returned as evidence.
- Cleanup responsibilities and the stop procedure.

If a test requires permission beyond the agreed scope, pause and get that
permission. Do not silently broaden the engagement to obtain a reproduction.

## Agree on data handling

Before transferring source, credentials, or target-derived evidence, confirm
storage, retention/deletion, authorized recipients, and any required processing
locations with the team. These are engagement requirements; a CLI provider
setting alone is not a managed-service data-residency commitment.

## Check readiness

Before the testing window, confirm that the agreed access path reaches the
right environment, test accounts still work, ownership of test records is
known, and the stop contact is available. Record unresolved blockers as coverage
limits, not clean results.

For a scan you operate yourself, use the [CLI quickstart scope example](/getting-started/#run-your-first-scan)
and [Authorized Engagements](/engagements/) for engine-level controls. A managed
engagement brief is not automatically loaded as CLI configuration.

Use [Scope & Authorization](/scope/) for the canonical CLI policy format and
matching rules.

Next: [Review Evidence](/cloud/review-evidence/).

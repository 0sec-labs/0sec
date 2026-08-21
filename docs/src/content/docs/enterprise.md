---
title: Enterprise readiness
description: SSO, BYOK, deployment options, data residency, audit, SLA, and compliance posture for 0sec and 0sec cloud. Honest status per capability — no overclaimed certifications.
sidebar:
  order: 9
# OWNER_TBD — assign a human owner before merge. This page is the single source
# of truth for enterprise capability claims; the owner is responsible for keeping
# the status badges accurate as procurement reviews them.
owner: OWNER_TBD
---

> **This page is the single source of truth for enterprise capability claims. Sales materials reference it; do not duplicate facts elsewhere.** When something ships or its target date moves, update the badge here first; everything downstream (deck, RFP responses, security questionnaires) should link back here rather than restate.

0sec is the open-source security harness for source and live targets. **0sec cloud** is the managed layer on top — recurring scans, multi-tenant triage, and evidence bundles. This page covers enterprise readiness for both surfaces.

We use three status badges. They are intentionally precise so a procurement reviewer can map each row to evidence:

- **Shipped** — code is on `main` and exercised in production. Demoable today.
- **In progress (target <quarter>)** — work is in flight, has an owner and an issue link, and is expected to land in the named quarter.
- **Planned (<quarter / year>)** — committed on the roadmap but not yet in flight. Earliest realistic ship date.

We deliberately do **not** claim SOC 2 Type II or ISO 27001 certification until those audits are signed. Several competitor checklists in this category list certifications they do not yet hold; we will match feature parity but only badge what is actually attested. For a regulated buyer, the honest baseline reads as a stronger signal than an inflated one.

## Auth

| Capability | Status | Notes |
|---|---|---|
| SAML SSO (Okta, Azure AD / Entra ID, Google Workspace) | **In progress (target Q3 2026)** | better-auth backs the dashboard today; SAML connector is the active gap. Tracked on the 0cloud roadmap. |
| OIDC SSO | **In progress (target Q3 2026)** | Lands with the SAML work; shares the better-auth provider plumbing. |
| SCIM 2.0 provisioning + deprovisioning | **Planned (Q4 2026)** | Follows SAML/OIDC. Manual invite + revoke works today via the dashboard. |
| GitHub OAuth (for OSS / individual users) | **Shipped** | Default sign-in for `cloud.0sec.ai`. Not appropriate for enterprise tenants — use SAML when available. |
| MFA enforcement at the org level | **Planned (Q4 2026)** | Today, MFA is delegated to the identity provider once SSO lands. |
| Role-based access control (org / member / read-only) | **Shipped** | Multi-tenant org model with membership roles is live in the dashboard schema (`app_organizations`, `app_memberships`). |
| CLI auth via browser device flow | **Shipped** | `0sec auth login` mints scoped tokens into `cli_tokens`; revocable from the dashboard. |
| Per-user audit log of auth events | **In progress (target Q3 2026)** | The `app_admin_audit` table exists; the user-facing export view is the gap. |

## Models / BYOK

You bring your own LLM provider credentials. The OSS engine never proxies your key through our servers — calls go direct from the agent process (local or in your tenant) to the provider. The 0sec cloud orchestration layer reads your key from a per-org secret store and injects it into the worker sandbox; we do not log key material and the key never enters the dataset pipeline.

| Provider | Status | Notes |
|---|---|---|
| Anthropic (Claude) | **Shipped** | `ANTHROPIC_API_KEY`. Preferred provider for deep-reasoning scan stages. |
| OpenAI / ChatGPT Codex subscription | **Shipped** | `OPENAI_API_KEY` or `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN`. |
| Google (Gemini CLI) | **Shipped** | Via the `gemini` runtime; spawns the official Gemini CLI with your auth. |
| Azure OpenAI (regional, including EU regions) | **Shipped** | `AZURE_OPENAI_API_KEY` + base URL. The right path for buyers who need EU-region inference under an existing Microsoft tenant. |
| OpenRouter (multi-model gateway) | **Shipped** | `OPENROUTER_API_KEY`. Convenient for OSS users; enterprise buyers should prefer a direct provider for audit clarity. |
| Local / air-gapped models via Ollama | **Shipped** | `--runtime ollama`, `OLLAMA_HOST` (default `http://localhost:11434`). Native function-calling and streaming. Use case: on-prem deployments where outbound LLM calls are forbidden. Note that non-model enrichment paths (package registries, OSV, OAST) still egress unless separately air-gapped. |
| OSS engine works with zero cloud-side keys | **Shipped** | Run `0sec` locally with only your provider key set; nothing reaches 0sec infrastructure. This is the air-gap-friendly baseline. |

See [API Keys](/api-keys/) for the full provider matrix and priority order, and [Configuration](/configuration/) for runtime selection.

## Deployment

Three options, ordered from least to most customer-controlled. Pick based on your data-handling constraints, not on which is "newest."

| Option | Status | Where the engine runs | Where customer data lives | Who controls the LLM key | What 0sec sees |
|---|---|---|---|---|---|
| **SaaS (default)** | **Shipped** | E2B sandbox per scan, orchestrated from `cloud.0sec.ai` (Hetzner HEL1, single dedicated box). | 0sec-managed Postgres on the orchestrator host. | Customer-supplied via per-org secret. | Scan inputs, findings, audit log, billing usage. |
| **VPC peering / dedicated tenant** | **Planned (2026)** | Same engine, but the worker pool runs in a dedicated subnet peered to the customer's VPC. | Findings DB co-located with the dedicated tenant. | Customer-supplied. | Same as SaaS, scoped to that tenant. |
| **Fully self-hosted on-prem (Docker / k3s)** | **Shipped (OSS engine)** / **In progress (target Q4 2026 for managed orchestration)** | Customer's own infrastructure. The engine is the public `ghcr.io/0sec-labs/0sec:latest` image — the same binary every OSS user runs. | Entirely inside the customer environment. | Customer-supplied; never leaves their env. | Nothing, unless the customer opts into telemetry. The cloud-sink env vars (`0SEC_CLOUD_SINK`, `0SEC_CLOUD_TOKEN`) are opt-in and off by default in self-hosted mode. |

**One engine, three control planes.** Every option runs the same `ghcr.io/0sec-labs/0sec` image. There is no premium fork. The cloud product's value is orchestration, multi-tenant triage, the dataset feedback loop, and integrations — not a gated agent. See [Architecture](/architecture/) and [Cloud](/cloud/) for the engine / control-plane split.

### Data flow at a glance

**SaaS path:** customer dashboard → orchestrator (Hono) → worker controller → E2B sandbox running the 0sec image → findings stream back into Postgres → triage UI. Customer LLM key is injected into the sandbox env, used for the duration of the scan, and discarded with the sandbox.

**Self-hosted path:** customer's CI or operator runs the 0sec Docker image directly. Findings stay in the customer's chosen store (local SQLite by default, optional Postgres for shared triage). No outbound calls to 0sec infrastructure unless cloud-sink is explicitly enabled.

## Data

| Topic | Status | Notes |
|---|---|---|
| EU data residency (Germany, Hetzner HEL1 → FSN1 fallback) | **Shipped** | Default region for all 0sec cloud workloads as of 2026-05. |
| Switzerland data residency | **Planned (Q1 2027)** | Requires a Swiss-region worker pool and a CH-region Postgres. On the roadmap for regulated CH buyers; today, Swiss customers default to EU residency under nFADP-adequate terms. |
| US data residency | **Planned (Q4 2026)** | Triggered by the first US enterprise contract; not a blocker for EU/CH buyers. |
| Default retention — scan inputs + raw findings | **Shipped** | 90 days, configurable per org. |
| Default retention — verified findings + audit log | **Shipped** | 365 days, configurable per org. |
| Customer-controlled retention windows | **Shipped** | Org admins can shorten or extend within the regulator-aligned bounds. |
| Customer-initiated data export + purge | **In progress (target Q3 2026)** | Self-serve "export everything" + "delete tenant" buttons in the dashboard. Today, both are operator-assisted on request. |
| No-training-on-customer-data clause | **Shipped** | Contractual default in the DPA. The internal triage dataset is built only from OSS users who explicitly opt in and from sources we own (XBOW retained-artifact runs, our own bounty harness). Cloud customer scans are excluded from the training dataset unless the customer enables sharing with a per-org flag, which is **off by default**. |
| Pre-signed GDPR DPA + SCCs | **Shipped** | Available on request. |
| Pre-signed nFADP DPA (Swiss) | **Shipped** | Available on request. |
| Customer-managed encryption keys (CMEK / BYOK for data-at-rest) | **Planned (2027)** | Not in the current roadmap window. Data-at-rest is encrypted with 0sec-managed keys today. |

## Audit

| Capability | Status | Notes |
|---|---|---|
| SOC 2 Type I | **Planned (Q1 2027)** | Type I readiness assessment is the next concrete milestone. We do not claim Type I until it is attested. |
| SOC 2 Type II | **Planned (2027)** | Follows Type I after the required observation window. |
| ISO 27001 | **Planned (2027)** | Targeted to align with the financial-services buyer cycle. Not currently certified. |
| Immutable per-action audit log | **Shipped** | `audit_log` table in Postgres records every scan dispatch, finding state change, auth event, and admin action. Append-only. |
| Audit log export (JSON + CSV) | **In progress (target Q3 2026)** | Programmatic export endpoint and dashboard download. |
| SIEM integration (Splunk / Sentinel / Datadog) | **Planned (Q4 2026)** | Initial path is a webhook + JSON-Lines stream; native connectors follow customer demand. |
| Penetration test of the platform (third-party) | **Planned (Q1 2027)** | Scheduled to coincide with SOC 2 readiness. |
| Public security disclosure policy | **Shipped** | Email security@0sec.ai or see SECURITY.md in the repo. |

**On the SOC 2 / ISO honesty point:** the most common procurement stall point in our target segment is "do you have SOC 2 Type II?" Today, we do not, and we will not badge it before we do. The credible alternative we offer is (a) honest reflection of where the audit is in the pipeline, (b) the self-hosted deployment option that removes the SOC 2 conversation from scope entirely, and (c) the architecture story — the engine is open-source, the data flow is inspectable, and a customer can validate the trust boundary themselves rather than rely on a third-party attestation.

## SLA

SLAs apply to the SaaS and dedicated-tenant tiers. Self-hosted deployments are governed by the support contract attached to the deployment.

| Tier | Uptime target | P1 response | P2 response | Named technical contact | Status |
|---|---|---|---|---|---|
| Free / OSS | None — best-effort community support | n/a | n/a | n/a | **Shipped** |
| Team | 99.5% | 1 business day | 3 business days | Shared support queue | **Shipped** |
| Enterprise | 99.9% | 1 hour (24/7) | 4 hours (business hours) | Named on-call engineer + Slack Connect channel | **In progress (target Q3 2026)** |
| Enterprise + dedicated tenant | 99.9% | 30 minutes (24/7) | 2 hours (business hours) | Named on-call engineer + quarterly architecture review | **Planned (Q4 2026)** |

Uptime is measured at the orchestrator + dashboard ingress; worker-pool availability is reported separately because scans are queueable and tolerate short windows of worker unavailability without affecting the user-visible SLA.

## Compliance

This section maps 0sec's posture against the frameworks our EU and Swiss buyers actually cite in RFPs. We do not claim certification where none exists; the table is about *alignment* — what we do today that supports the customer's own compliance obligations.

| Framework | Status | What it means for the customer |
|---|---|---|
| **GDPR** | **Shipped (DPA + SCCs available)** | Pre-signed Data Processing Addendum with EU SCCs. EU-region default. No cross-border transfer of customer data outside the DPA's scope. |
| **Swiss nFADP** | **Shipped (DPA available)** | Pre-signed DPA aligned with the revised Swiss Federal Act on Data Protection (in force since Sept 2023). EU adequacy decision applies. |
| **DORA (EU Digital Operational Resilience Act)** | **In progress** | DORA is in force as of 17 Jan 2025 and requires threat-led pentests on a 3-year cycle plus annual scenario tests. 0sec positions as continuous between-test validation, not a replacement for TLPT engagements. We map each scan to the relevant DORA article on request; a formal DORA-aligned reporting template is in flight (target Q4 2026). |
| **FINMA Circ. 2023/1 + TIBER-CH** | **In progress** | Aligned with the FINMA 24h / 72h incident notification cadence and TIBER-CH's continuous-testing expectation. We do not replace a CREST-approved manual provider; we compress the cycle between engagements. |
| **ISO 27001** | **Planned (2027)** | Targeted certification. Not currently held; we will not claim it before attestation. |
| **SOC 2 (Type I → Type II)** | **Planned (2027)** | See [Audit](#audit) above. |
| **EU AI Act (high-risk system obligations)** | **In progress** | Internal mapping is underway; relevant because 0sec is an autonomous AI system, even though it operates on the security-tooling side rather than as a high-risk application. We track the GPAI obligations as they phase in through 2026-2027. |
| **OWASP ASVS / OWASP Top 10 coverage** | **Shipped** | Documented in the [Methodology](/methodology/) page; the agent's web-mode coverage maps to ASVS L1 and L2 controls. |

For an EU/Swiss regulated buyer, the practical compliance answer is: **EU-region deployment, pre-signed GDPR + nFADP DPAs, self-hosted available for the strictest bucket, and an honest readout on SOC 2 / ISO timing.** That stack has cleared procurement in tier-1 Swiss enterprise diligence under NDA.

## Roadmap dependencies

The status badges above depend on a small number of load-bearing items. We surface them here so a procurement reviewer knows what unblocks what:

- **SAML SSO (Q3 2026)** unblocks: SCIM, MFA-at-org, full Enterprise tier launch.
- **SOC 2 Type I (Q1 2027)** unblocks: Type II observation window, several regulated-FS procurement gates.
- **Self-hosted managed orchestration (Q4 2026)** unblocks: regulated deployments that need the cloud control plane on customer infrastructure rather than on 0sec's.
- **Enrichment-path air-gapping** unblocks: fully air-gapped deployments. The Ollama runtime already removes outbound *model* traffic; package-registry, OSV and OAST lookups are the remaining egress.

## Contact

For enterprise procurement, security questionnaires, DPA signing, and pilot scoping: **enterprise@0sec.ai**.

For engine support or vulnerability disclosure against 0sec or 0sec cloud itself, email **security@0sec.ai**.

---

*Last reviewed: 2026-05-22. If a badge on this page is out of date, the owner above is the escalation point. Sales materials cite this URL; do not restate the facts elsewhere.*

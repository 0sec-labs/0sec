---
title: Authorized Engagements
description: Running 0sec inside a client engagement — conservative posture, forensic timelines, and ATT&CK/ATLAS-mapped evidence.
---

0sec is built for **authorized, announced testing**. Its rails make traffic
identifiable, not hidden: attribution headers, per-engagement tokens,
declared-scope enforcement, request counters. This page covers running inside a
client engagement — controlling how loud the engine is, and producing evidence a
client's security team can act on.

## Engagement profile

By default 0sec runs at 5 rps/host, no jitter, and escalates on WAF blocks —
fine for your own infrastructure, wrong for a monitored production estate.
`--engagement-profile conservative` applies one auditable posture:

```bash
0sec scan --target https://app.example.com --mode web \
  --scope ./engagement-scope.json \
  --engagement-profile conservative
```

| Behaviour | Default | Conservative |
|---|---|---|
| Request rate | 5 rps/host | 1 rps/host |
| Jitter | none | full, 0–750 ms |
| Reset-endpoint burst probe | 15 POSTs | disabled (converted to a manual-test lead) |
| Web-recon pre-pass | unthrottled | routed through the rate limiter |
| WAF-evasion ladder | auto-fires on block | disabled |

Jitter is paced on the non-blocking path too: a perfectly periodic 1 rps train
is a stronger automation signal to a behavioural SOC than bursty traffic.

**Precedence:** scope file > environment > CLI flag. The scope file binds to the
engagement, so an ad-hoc flag can't loosen it. Rate resolves to the minimum, so
a profile can only make a scan quieter.

The WAF-evasion ladder can be disabled independently — this stops the automatic
escalation into encoding-mutated payloads, not detection or reporting of the
block:

```bash
0sec scan --target https://app.example.com --no-waf-evasion
# or
env 0SEC_WAF_EVASION=0 0sec scan --target https://app.example.com
```

Env vars: `0SEC_ENGAGEMENT_PROFILE`, `0SEC_WAF_EVASION`,
`0SEC_ENGAGEMENT_RATE_RPS`, `0SEC_ENGAGEMENT_JITTER_MS`. A scope file may carry an
`engagement` block with the same fields.

When a profile is active the report carries an `engagementPosture` record and
emits an `engagement_posture_applied` event. It records the posture **as
applied** (resolving env overrides), which is what a client asks for after the
fact. Runs without a profile are unchanged.

## Forensic timeline

`0sec timeline` builds a chronological record from the immutable pipeline-event
audit trail:

```bash
0sec timeline <scanId>                     # markdown, for a report appendix
0sec timeline <scanId> --format json       # machine-readable
0sec timeline <scanId> --format csv        # spreadsheet / SIEM import
0sec timeline <scanId> --attack-only       # only events with a technique mapping
0sec timeline <scanId> --since 2026-09-15T09:00:00Z --until 2026-09-15T17:00:00Z
```

Every row carries a UTC ISO-8601 timestamp, stage, event type, agent role, an
action summary, and technique mappings. `--attack-only` reports both filtered
and total counts, so a filtered record states what it omitted.

Each tool invocation is logged individually with its own start time, duration,
outcome, and redacted arguments (redacted **before** truncation). A
`correlationId` joins each call to the artifact holding its full request detail,
so the timeline can state the actual URL, method, and status.

## Technique mapping — two matrices

Findings and actions map against **two** separate MITRE matrices, kept as
distinct fields:

- **ATT&CK (Enterprise)** — SQLi, SSRF, command injection, memory-safety,
  credential access.
- **ATLAS (AI systems)** — prompt injection, jailbreak, system-prompt
  extraction, multi-turn manipulation.

They are not merged. A row may carry either, both, or neither —
`data-exfiltration` legitimately carries ATT&CK `T1567`/`T1041` *and* ATLAS
`AML.T0057`/`AML.T0024`. Where a behaviour has no honest match, the mapping is
left empty rather than approximated.

:::note
The current ATT&CK Enterprise matrix renamed tactic **TA0005** "Defense Evasion"
to "Stealth" and **T1211** to "Exploitation for Stealth". 0sec uses the current
names; if a client's tooling is pinned to an older release, remap at the
presentation layer.
:::

## Identity and token analysis

`0sec identity` assesses an Entra ID tenant read-only — 27 posture checks across
privileged roles, conditional access, app registrations, service principals, and
federation. Read-only is structural: every Graph request hard-codes `GET`.

Token analysis adds 26 offline checks over JWTs and SAML (no network calls):

- **JWT** — `alg:none`, algorithm confusion, unsafe `kid`/`jku`/`x5u`/`jwk`,
  missing/excessive expiry, weak audience, no replay controls, sensitive claims,
  broad scope.
- **Entra** — access-vs-ID token misuse, weak client binding, privileged `wids`,
  multi-tenant issuer, long-lived session indicators (PRT, CAE).
- **SAML** — XML Signature Wrapping, unsigned assertions, weak conditions,
  missing audience restriction, NameID comment truncation, Golden SAML
  preconditions.

Raw token material is never logged; findings carry a SHA-256 fingerprint and a
redacted preview.

:::caution
Identity findings name the affected principal, including user principal names.
In a jurisdiction with data-protection obligations, treat finding output as
personal data and handle custody accordingly.
:::

## Attack paths — on-prem and cloud

Two commands, same shape. The client's collector runs wherever the engagement
puts it; analysis runs here. Both are offline — no collection, auth, or network.

**Active Directory** — `0sec adgraph --input <path>` computes attack paths from a
BloodHound CE / SharpHound export: paths to Domain Admin, kerberoastable
principals, unconstrained delegation, DCSync rights, ACL abuse, and the ADCS
escalation set (ESC1, ESC3–ESC7, ESC9, ESC10, ESC13). ~60 edge kinds each carry
a written abuse technique.

**Entra ID** — `0sec entragraph --input <path>` does the equivalent over an
AzureHound export: paths to Global Administrator, service-principal escalation,
consent-grant escalation, owner-chain abuse, and guest escalation.

```bash
0sec entragraph --input ./azurehound-export/
0sec entragraph --input ./azurehound-export/ --json
0sec entragraph --input ./export --owned <objectId>,<objectId>   # start from known-compromised principals
0sec entragraph --input ./export --max-depth 4
```

:::caution
An AzureHound run without membership or ownership collections cannot produce
those paths; `entragraph` says so explicitly rather than presenting an empty
result as a clean tenant. AzureHound exports also carry no conditional-access,
federation, or PIM data — run `0sec identity` against a live tenant for those.
:::

## What 0sec does not do

- No network sweep, host discovery, or CIDR enumeration
- No non-HTTP service exploitation (no SMB, RDP, SSH, LDAP, SNMP)
- No credential spraying or service brute force
- No foothold, persistence, implants, beacons, C2, or pivoting
- No detection evasion or adversary-emulation stealth
- No org-name-driven asset discovery — apex domains must be supplied

The engine stops at a proven vulnerability with a benign impact demo (`id`,
`whoami`, `/etc/hostname`), then documents and remediates. Post-exploitation is
for human operators.

## Data residency

For engagements that need target-derived data to stay inside a defined
perimeter, 0sec routes all model traffic through one configurable endpoint.
Azure OpenAI works with no code change:

```bash
export AZURE_OPENAI_API_KEY=...
export AZURE_OPENAI_BASE_URL=https://<resource>.openai.azure.com
export AZURE_OPENAI_MODEL=<deployment-name>
```

At startup the engine probes the `x-ms-region` header and reports the physical
region, which doubles as an audit artifact. Two caveats worth putting in a
contract:

1. The defensible claim is *"no target data leaves to third-party **model**
   providers."* Other enrichment paths still egress — GitHub API, OSV, package
   registries, Microsoft Graph, OAST. Air-gapping those is separate.
2. Pin `--runtime api`. The `claude`, `codex`, and `gemini` runtimes shell out to
   third-party binaries whose egress 0sec does not control.

See [API Keys](/api-keys/) for the full provider matrix.

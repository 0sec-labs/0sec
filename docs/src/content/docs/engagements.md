---
title: Authorized Engagements
description: Running pwnkit inside a client engagement — conservative posture, forensic timelines, and ATT&CK/ATLAS-mapped evidence.
---

pwnkit is built for **authorized, announced testing**. Its safety rails exist to
make traffic identifiable rather than to hide it: attribution headers,
per-engagement tokens, declared-scope enforcement, request counters. That is the
opposite design goal from adversary emulation, and it is deliberate.

This page covers the surfaces that exist specifically for running inside a
client engagement: controlling how loud the engine is, and producing evidence a
client's security team can act on.

## Engagement profile

By default pwnkit runs at 5 requests/second per host, without jitter, and
escalates automatically when it detects a WAF block. That is appropriate for
your own infrastructure. It is not appropriate for a monitored production estate
where you have agreed to keep noise down.

`--engagement-profile conservative` applies a single auditable posture:

```bash
pwnkit scan --target https://app.example.com --mode web \
  --scope ./engagement-scope.json \
  --engagement-profile conservative
```

| Behaviour | Default | Conservative |
|---|---|---|
| Request rate | 5 rps/host | 1 rps/host |
| Jitter | none (fixed interval) | full jitter, 0–750 ms |
| Reset-endpoint burst probe | 15 POSTs | disabled |
| Web-recon pre-pass | unthrottled | routed through the rate limiter |
| WAF-evasion ladder | auto-fires on block | disabled |

Jitter matters more than it looks. A perfectly periodic request train at 1 rps
is arguably a *stronger* automation signal to a behavioural SOC than bursty
traffic, so the profile paces the non-blocking path too, not just the
rate-limited one.

The reset-endpoint probe is not silently dropped. It is converted into a lead so
the finding surfaces as a manual test item for the client rather than
disappearing.

### Precedence and the standalone opt-out

Configuration resolves **scope file > environment > CLI flag**. The scope file
is the artifact that binds to the engagement, so an ad-hoc command-line flag
cannot loosen a posture the scope file established. Rate is resolved by taking
the minimum, so a profile can only ever make a scan quieter.

The WAF-evasion ladder can also be disabled independently:

```bash
pwnkit scan --target https://app.example.com --no-waf-evasion
# or
PWNKIT_WAF_EVASION=0 pwnkit scan --target https://app.example.com
```

Disabling the ladder does not disable *detection* of a WAF block — the block is
still detected and reported. Only the automatic escalation into
encoding-mutated payload variants stops, since that is the behaviour that turns
a WAF block into a SOC incident.

Environment variables: `PWNKIT_ENGAGEMENT_PROFILE`, `PWNKIT_WAF_EVASION`,
`PWNKIT_ENGAGEMENT_RATE_RPS`, `PWNKIT_ENGAGEMENT_JITTER_MS`. A scope file may
carry an `engagement` block with the same fields.

### The posture record

When a profile is active the report carries an `engagementPosture` record and
the run emits an `engagement_posture_applied` event. The record states the
posture **as applied**, not as requested — so a scope file asking for
`conservative` with `PWNKIT_WAF_EVASION=1` in the environment correctly reports
the ladder as enabled, and attributes that to the environment.

That distinction is the point: the record is evidence of how the scan actually
ran, which is what a client asks for after the fact.

Reports from runs without a profile are unchanged.

## Forensic timeline

A client's security team needs a chronological record of what you did and when,
to cross-reference against their own detections. `pwnkit timeline` produces it
from the immutable pipeline-event audit trail:

```bash
pwnkit timeline <scanId>                     # markdown, for a report appendix
pwnkit timeline <scanId> --format json       # machine-readable
pwnkit timeline <scanId> --format csv        # for a spreadsheet or SIEM import
pwnkit timeline <scanId> --attack-only       # drop pipeline lifecycle noise
pwnkit timeline <scanId> --since 2026-09-15T09:00:00Z --until 2026-09-15T17:00:00Z
```

Every row carries a **UTC ISO-8601** timestamp, the stage, event type, agent
role, a human-readable action summary, and its technique mappings. Epoch
milliseconds never appear in output.

`--attack-only` filters to events carrying a technique mapping. The export
reports both the filtered and total event counts, so a filtered record always
states what it omitted rather than quietly presenting itself as complete.

### Action-level detail

The durable audit trail records each tool invocation individually, with its own
start timestamp, duration, outcome, and redacted arguments. A `correlationId`
joins each logged call to the artifact carrying its full request detail, so the
timeline can state the actual URL, method and response status rather than only
the tool name.

Arguments are redacted **before** truncation. Truncating first would leave a
usable secret prefix sitting in the log.

## Technique mapping — two matrices

Findings and actions are mapped against **two** separate MITRE matrices, carried
as distinct fields:

- **ATT&CK (Enterprise)** — conventional behaviours. SQL injection, SSRF,
  command injection, memory-safety classes, credential access.
- **ATLAS (AI systems)** — AI-specific behaviours. Prompt injection, jailbreak,
  system-prompt extraction, multi-turn manipulation.

They are deliberately **not merged**. A row may carry either, both, or neither.
`data-exfiltration`, for example, legitimately carries ATT&CK `T1567`/`T1041`
*and* ATLAS `AML.T0057`/`AML.T0024` — collapsing them into one column would
destroy that distinction.

Where a behaviour has no honest home in a matrix, the mapping is empty rather
than approximated. An unmapped row is better than a wrong technique ID in a
client deliverable.

:::note
The current published ATT&CK Enterprise matrix renamed tactic **TA0005 "Defense
Evasion" to "Stealth"**, and **T1211** to "Exploitation for Stealth". pwnkit uses
the current names. If a client's tooling is pinned to an older ATT&CK release,
remap at the presentation layer.
:::

## Identity and token analysis

`pwnkit identity` assesses an Entra ID tenant read-only — 27 posture checks
across privileged roles, conditional access, app registrations, service
principals and federation. Read-only is structural: every Graph request
hard-codes `GET`, and there is no method parameter in the client.

Token analysis adds 26 further checks over JWTs and SAML assertions, offline and
with no network calls:

- **JWT** — `alg:none`, algorithm confusion, unsafe key identifiers (`kid`
  traversal, `jku`/`x5u`/`jwk` injection), missing or excessive expiry, weak
  audience, absent replay controls, sensitive claim data, overly-broad scope.
- **Entra** — access-vs-ID token misuse, weak client binding, privileged `wids`
  role template IDs, multi-tenant issuer, long-lived session indicators (PRT,
  CAE).
- **SAML** — XML Signature Wrapping exposure, unsigned assertions, weak
  conditions, missing audience restriction, NameID comment truncation, and
  Golden SAML preconditions.

Raw token material is never logged or persisted; findings carry a SHA-256
fingerprint and a redacted preview.

:::caution
Identity findings name the affected principal, including user principal names.
For an engagement in a jurisdiction with data-protection obligations, treat
finding output as containing personal data and handle custody accordingly.
:::

## Attack paths — on-premises and cloud

Two commands, same shape: the client's collector runs wherever the engagement
puts it, and the analysis runs here. Both are offline by design — neither
collects, authenticates, nor touches a network.

### Active Directory

`pwnkit adgraph --input <path>` computes attack paths from a BloodHound CE /
SharpHound JSON export. Coverage includes paths to Domain Admin, kerberoastable
principals, unconstrained delegation, DCSync rights, ACL abuse chains, and the
ADCS escalation set (ESC1, ESC3–ESC7, ESC9, ESC10, ESC13). Roughly 60 edge kinds
each carry a written abuse technique.

### Entra ID

`pwnkit entragraph --input <path>` does the equivalent over an AzureHound
export: paths to Global Administrator, service-principal escalation via added
secrets, consent-grant escalation through high-impact Graph permissions,
owner-chain abuse, and guest escalation.

```bash
pwnkit entragraph --input ./azurehound-export/
pwnkit entragraph --input ./azurehound-export/ --json
pwnkit entragraph --input ./export --owned <objectId>,<objectId>   # start from known-compromised principals
pwnkit entragraph --input ./export --max-depth 4
```

:::caution
An AzureHound run that did not gather membership or ownership collections cannot
produce membership or ownership paths. `entragraph` reports that explicitly
rather than presenting an empty result as a clean tenant — the absence of a
finding is not the same as the absence of a path, and a client report must not
conflate them.

AzureHound exports also carry no conditional-access policies, federation
configuration, or PIM eligibility schedules. Run `pwnkit identity` against a live
tenant for the posture checks that read those.
:::

## What pwnkit does not do

Stated plainly, because scoping an engagement on a wrong assumption is
expensive:

- No network sweep, host discovery, or CIDR enumeration
- No non-HTTP service exploitation — no SMB, RDP, SSH, LDAP or SNMP clients
- No credential spraying or service brute force
- No foothold, persistence, implants, beacons, C2, or pivoting
- No detection evasion or adversary-emulation stealth
- No organisation-name-driven asset discovery — apex domains must be supplied

The engine stops at a proven vulnerability with benign impact demonstration
(`id`, `whoami`, `/etc/hostname`), then moves to documentation and remediation.
Post-exploitation belongs to human operators.

## Data residency

For engagements that require target-derived data to stay inside a defined
perimeter, pwnkit routes all model traffic through a single configurable
endpoint. Azure OpenAI is supported with no code change:

```bash
export AZURE_OPENAI_API_KEY=...
export AZURE_OPENAI_BASE_URL=https://<resource>.openai.azure.com
export AZURE_OPENAI_MODEL=<deployment-name>
```

At startup the engine probes the `x-ms-region` response header and reports the
physical region serving traffic, which doubles as an audit artifact.

Two caveats worth stating in a contract rather than discovering later:

1. The defensible claim is *"no target data leaves to third-party **model**
   providers."* Other enrichment paths still make outbound calls — GitHub API,
   OSV, package registries, Microsoft Graph, and OAST. Air-gapping those is a
   separate exercise.
2. Pin `--runtime api`. The `claude`, `codex` and `gemini` runtimes shell out to
   third-party binaries whose egress pwnkit does not control.

See [API Keys](/api-keys/) for the full provider matrix.

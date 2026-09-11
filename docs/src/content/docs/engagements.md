---
title: Authorized Engagements
description: Running 0sec inside a client engagement — conservative posture, forensic timelines, and ATT&CK/ATLAS-mapped evidence.
---

0sec runs under authorized, announced testing only. Attribution headers,
per-engagement tokens, declared-scope enforcement, and request counters
identify traffic. This page covers posture controls and engagement evidence.

## Engagement profile

By default 0sec runs at 5 rps/host, no jitter, and escalates on WAF blocks.
For monitored production estates, `--engagement-profile conservative` applies
one auditable posture:

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

Jitter is paced on the non-blocking path too.

**Profile-field precedence:** scope file > environment > CLI flag. The
conservative profile lowers the scan's fallback request rate; it is **not a
hard ceiling over an explicit `scan --rate-limit` value**. Review both the
profile and rate specification before executing an engagement. The MCP server
uses a stricter clamp over its rate specification; do not assume those two
entry points resolve rates identically.

Disable the WAF-evasion ladder independently to stop automatic escalation into
encoding-mutated payloads (detection and block reporting are unaffected):

```bash
0sec scan --target https://app.example.com --scope ./engagement-scope.json --no-waf-evasion
# or
env 0SEC_WAF_EVASION=0 0sec scan --target https://app.example.com --scope ./engagement-scope.json
```

Env vars: `0SEC_ENGAGEMENT_PROFILE`, `0SEC_WAF_EVASION`,
`0SEC_ENGAGEMENT_RATE_RPS`, `0SEC_ENGAGEMENT_JITTER_MS`. A scope file may carry an
`engagement` block with the same fields.

When a profile is active the report carries an `engagementPosture` record and
emits an `engagement_posture_applied` event. It records the posture **as
applied** (resolving env overrides), which is what a client asks for after the
fact. Runs without a profile are unchanged.

## Forensic timeline

`0sec timeline` builds a chronological record from the pipeline-event audit
trail. It uses the selected SQLite database (not all run-local databases).
Pass `--db-path` for the inspected run:

```bash
0sec timeline <scanId> --db-path ~/.0sec/runs/<scanId>/state.db
0sec timeline <scanId> --db-path ~/.0sec/runs/<scanId>/state.db --format json
0sec timeline <scanId> --db-path ~/.0sec/runs/<scanId>/state.db --format csv
0sec timeline <scanId> --db-path ~/.0sec/runs/<scanId>/state.db --attack-only
0sec timeline <scanId> --db-path ~/.0sec/runs/<scanId>/state.db \
  --since 2026-09-01T09:00:00Z --until 2026-09-01T17:00:00Z
```

Every row carries a UTC ISO-8601 timestamp, stage, event type, agent role, an
action summary, and technique mappings. `--attack-only` reports both filtered
and total counts, so a filtered record states what it omitted.

Each tool invocation is logged individually with its own start time, duration,
outcome, and redacted arguments (redacted **before** truncation). A
`correlationId` joins each call to the artifact holding its full request detail,
so the timeline can state the actual URL, method, and status.

## Technique mapping — two matrices

Findings and actions map against **two** MITRE matrices:

- **ATT&CK (Enterprise)** — SQLi, SSRF, command injection, memory-safety,
  credential access.
- **ATLAS (AI systems)** — prompt injection, jailbreak, system-prompt
  extraction, multi-turn manipulation.

A row may carry either, both, or neither. A behaviour with no match is left
empty.

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
Treat finding output as personal data under applicable data-protection
obligations.
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

<span id="what-0sec-does-not-do"></span>
## Limitations

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

To keep target-derived data inside a defined perimeter, route all model traffic
through one configurable endpoint. Azure OpenAI works with no code change:

```bash
export AZURE_OPENAI_API_KEY=...
export AZURE_OPENAI_BASE_URL=https://<resource>.openai.azure.com
export AZURE_OPENAI_MODEL=<deployment-name>
```

At startup the engine probes the `x-ms-region` header and reports the physical
region (audit artifact). Two caveats:

1. The defensible claim is *"no target data leaves to third-party **model**
   providers."* Other enrichment paths still egress — GitHub API, OSV, package
   registries, Microsoft Graph, OAST. Air-gapping those is separate.
2. Pin `--runtime api`. The `claude`, `codex`, and `gemini` runtimes shell out to
   third-party binaries whose egress 0sec does not control.

See [API Keys](/api-keys/) for the full provider matrix.

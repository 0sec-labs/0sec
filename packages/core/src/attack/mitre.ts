// MITRE ATT&CK (Enterprise) mapping layer.
//
// Two lookups, both static and pure — no network, no ATT&CK STIX bundle at
// runtime, no inference:
//
//   techniquesForCategory(category)      finding category  → technique(s)
//   techniquesForEvent(eventType, tool)  pipeline event    → technique(s)
//
// Together they let an engagement report state, per finding and per logged
// agent action, which adversary behaviour the action corresponds to. That is
// what makes a scan reconstructable against a defender's own ATT&CK coverage.
//
// ── Rules this file is held to ────────────────────────────────────────────
//
// 1. Every id/name/tactic here was checked against the live Enterprise matrix
//    on attack.mitre.org (2026-07-28). Nothing is invented. If you add an
//    entry, verify it on attack.mitre.org first — a fabricated technique id in
//    a client deliverable is worse than no id at all.
// 2. Exactly one `primary` per non-empty list, then at most two `secondary`
//    supporting techniques. Consumers that need a single tag take the primary.
// 3. Where a mapping would be a guess, the list is `[]` with a comment saying
//    why. An honest gap beats a wrong tag.
// 4. Parent technique over sub-technique whenever the sub-technique is not an
//    exact fit.
//
// ── Matrix-version note ───────────────────────────────────────────────────
//
// The current Enterprise matrix renames the tactic formerly published as
// "Defense Evasion" (TA0005) to **"Stealth"**, and T1211 "Exploitation for
// Defense Evasion" to "Exploitation for Stealth". The names below follow the
// current matrix. That is deliberate, not a typo — if a client's tooling is
// pinned to an older ATT&CK release, map "Stealth" back to "Defense Evasion"
// at the presentation layer rather than editing this file.
//
// ── Scope note: LLM/agent findings ────────────────────────────────────────
//
// Enterprise ATT&CK has no technique for prompt injection, jailbreaking, or
// system-prompt extraction. Those behaviours live in MITRE ATLAS, a separate
// matrix with a separate id namespace (AML.T####), which would break every
// consumer that expects a T#### id. Those categories therefore return `[]`
// with the ATLAS technique named in a comment. Do not paper over the gap by
// borrowing a loosely-related Enterprise id.

import type { AttackCategory } from "@0sec/shared";

export interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
  url: string;
  role: "primary" | "secondary";
}

// ── Verified technique catalog ────────────────────────────────────────────
//
// id → { name, tactic }. Sub-techniques carry MITRE's qualified display name
// ("Active Scanning: Wordlist Scanning") so a report line is unambiguous
// without the parent alongside it.

interface CatalogEntry {
  name: string;
  tactic: string;
}

const CATALOG = {
  // Reconnaissance (TA0043)
  T1595: { name: "Active Scanning", tactic: "Reconnaissance" },
  "T1595.001": { name: "Active Scanning: Scanning IP Blocks", tactic: "Reconnaissance" },
  "T1595.002": { name: "Active Scanning: Vulnerability Scanning", tactic: "Reconnaissance" },
  "T1595.003": { name: "Active Scanning: Wordlist Scanning", tactic: "Reconnaissance" },
  T1592: { name: "Gather Victim Host Information", tactic: "Reconnaissance" },
  "T1592.002": { name: "Gather Victim Host Information: Software", tactic: "Reconnaissance" },
  T1590: { name: "Gather Victim Network Information", tactic: "Reconnaissance" },
  T1591: { name: "Gather Victim Org Information", tactic: "Reconnaissance" },
  T1593: { name: "Search Open Websites/Domains", tactic: "Reconnaissance" },
  "T1593.003": { name: "Search Open Websites/Domains: Code Repositories", tactic: "Reconnaissance" },
  T1594: { name: "Search Victim-Owned Websites", tactic: "Reconnaissance" },
  T1596: { name: "Search Open Technical Databases", tactic: "Reconnaissance" },
  "T1596.005": { name: "Search Open Technical Databases: Scan Databases", tactic: "Reconnaissance" },

  // Resource Development (TA0042)
  T1583: { name: "Acquire Infrastructure", tactic: "Resource Development" },
  "T1583.006": { name: "Acquire Infrastructure: Web Services", tactic: "Resource Development" },
  T1587: { name: "Develop Capabilities", tactic: "Resource Development" },
  "T1587.001": { name: "Develop Capabilities: Malware", tactic: "Resource Development" },
  "T1587.004": { name: "Develop Capabilities: Exploits", tactic: "Resource Development" },
  T1588: { name: "Obtain Capabilities", tactic: "Resource Development" },
  "T1588.005": { name: "Obtain Capabilities: Exploits", tactic: "Resource Development" },
  "T1588.006": { name: "Obtain Capabilities: Vulnerabilities", tactic: "Resource Development" },

  // Initial Access (TA0001)
  T1190: { name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  T1189: { name: "Drive-by Compromise", tactic: "Initial Access" },
  T1195: { name: "Supply Chain Compromise", tactic: "Initial Access" },
  "T1195.001": {
    name: "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
    tactic: "Initial Access",
  },
  "T1195.002": {
    name: "Supply Chain Compromise: Compromise Software Supply Chain",
    tactic: "Initial Access",
  },
  T1078: { name: "Valid Accounts", tactic: "Initial Access" },
  "T1078.004": { name: "Valid Accounts: Cloud Accounts", tactic: "Initial Access" },

  // Execution (TA0002)
  T1059: { name: "Command and Scripting Interpreter", tactic: "Execution" },
  "T1059.004": { name: "Command and Scripting Interpreter: Unix Shell", tactic: "Execution" },
  "T1059.007": { name: "Command and Scripting Interpreter: JavaScript", tactic: "Execution" },
  T1203: { name: "Exploitation for Client Execution", tactic: "Execution" },

  // Privilege Escalation (TA0004)
  T1068: { name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },

  // Stealth (TA0005 — formerly "Defense Evasion")
  T1027: { name: "Obfuscated Files or Information", tactic: "Stealth" },
  "T1027.010": { name: "Obfuscated Files or Information: Command Obfuscation", tactic: "Stealth" },
  T1140: { name: "Deobfuscate/Decode Files or Information", tactic: "Stealth" },
  T1211: { name: "Exploitation for Stealth", tactic: "Stealth" },

  // Credential Access (TA0006)
  T1552: { name: "Unsecured Credentials", tactic: "Credential Access" },
  "T1552.001": { name: "Unsecured Credentials: Credentials In Files", tactic: "Credential Access" },
  "T1552.005": {
    name: "Unsecured Credentials: Cloud Instance Metadata API",
    tactic: "Credential Access",
  },
  T1539: { name: "Steal Web Session Cookie", tactic: "Credential Access" },
  T1212: { name: "Exploitation for Credential Access", tactic: "Credential Access" },

  // Discovery (TA0007)
  T1046: { name: "Network Service Discovery", tactic: "Discovery" },
  T1082: { name: "System Information Discovery", tactic: "Discovery" },
  T1083: { name: "File and Directory Discovery", tactic: "Discovery" },
  T1526: { name: "Cloud Service Discovery", tactic: "Discovery" },
  T1580: { name: "Cloud Infrastructure Discovery", tactic: "Discovery" },
  T1619: { name: "Cloud Storage Object Discovery", tactic: "Discovery" },

  // Lateral Movement (TA0008)
  T1550: { name: "Use Alternate Authentication Material", tactic: "Lateral Movement" },
  "T1550.001": {
    name: "Use Alternate Authentication Material: Application Access Token",
    tactic: "Lateral Movement",
  },

  // Collection (TA0009)
  T1005: { name: "Data from Local System", tactic: "Collection" },
  T1213: { name: "Data from Information Repositories", tactic: "Collection" },
  "T1213.006": { name: "Data from Information Repositories: Databases", tactic: "Collection" },
  T1530: { name: "Data from Cloud Storage", tactic: "Collection" },

  // Command and Control (TA0011)
  T1071: { name: "Application Layer Protocol", tactic: "Command and Control" },
  "T1071.001": { name: "Application Layer Protocol: Web Protocols", tactic: "Command and Control" },
  "T1071.004": { name: "Application Layer Protocol: DNS", tactic: "Command and Control" },

  // Exfiltration (TA0010)
  T1041: { name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
  T1567: { name: "Exfiltration Over Web Service", tactic: "Exfiltration" },

  // Impact (TA0040)
  T1499: { name: "Endpoint Denial of Service", tactic: "Impact" },
  "T1499.004": {
    name: "Endpoint Denial of Service: Application or System Exploitation",
    tactic: "Impact",
  },
  T1565: { name: "Data Manipulation", tactic: "Impact" },
  "T1565.003": { name: "Data Manipulation: Runtime Data Manipulation", tactic: "Impact" },
} as const satisfies Record<string, CatalogEntry>;

type TechniqueId = keyof typeof CATALOG;

/** `T1190` → `.../T1190/`; `T1595.003` → `.../T1595/003/` (MITRE's URL form). */
function techniqueUrl(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
}

function technique(id: TechniqueId, role: "primary" | "secondary"): AttackTechnique {
  const entry: CatalogEntry = CATALOG[id];
  return { id, name: entry.name, tactic: entry.tactic, url: techniqueUrl(id), role };
}

/** One primary followed by up to two secondaries. */
function chain(primaryId: TechniqueId, ...secondaryIds: TechniqueId[]): AttackTechnique[] {
  return [
    technique(primaryId, "primary"),
    ...secondaryIds.slice(0, 2).map((id) => technique(id, "secondary")),
  ];
}

// ── Finding category → technique ──────────────────────────────────────────
//
// Exhaustive over `AttackCategory` on purpose: adding a category to
// @0sec/shared without deciding its ATT&CK mapping is a type error here.

const CATEGORY_MAP: Record<AttackCategory, AttackTechnique[]> = {
  // ── LLM / agent ──
  // These four are MITRE ATLAS behaviours with no Enterprise equivalent. See
  // the scope note at the top of this file before "fixing" the empties.

  // ATLAS AML.T0051 (LLM Prompt Injection).
  "prompt-injection": [],
  // ATLAS AML.T0054 (LLM Jailbreak). The nearest-looking Enterprise candidate,
  // "Impair Defenses", was split into T1685/T1686 in the current matrix and now
  // covers host tooling and firewalls only — it does not describe model
  // guardrail bypass.
  "jailbreak": [],
  // ATLAS AML.T0056 (LLM Meta Prompt Extraction).
  "system-prompt-extraction": [],
  // ATLAS AML.T0051.001 (multi-turn / indirect prompt injection).
  "multi-turn": [],

  // The remaining LLM categories describe consequences Enterprise does cover.
  "data-exfiltration": chain("T1567", "T1041", "T1005"),
  // The agent's own tooling and credentials are driven toward actions the
  // operator never authorised — a confused deputy holding valid credentials.
  "tool-misuse": chain("T1059", "T1078"),
  "output-manipulation": chain("T1565", "T1565.003"),
  "encoding-bypass": chain("T1027", "T1027.010", "T1140"),

  // ── Source-code audit ──
  "prototype-pollution": chain("T1190", "T1499.004"),
  "path-traversal": chain("T1190", "T1083", "T1005"),
  "command-injection": chain("T1059", "T1059.004", "T1190"),
  "code-injection": chain("T1059", "T1190"),
  // Algorithmic complexity reachable from untrusted input: availability loss
  // through exploitation rather than volumetric flooding.
  "regex-dos": chain("T1499.004", "T1190"),
  "unsafe-deserialization": chain("T1190", "T1059"),
  "information-disclosure": chain("T1592", "T1552"),
  "ssrf": chain("T1190", "T1552.005", "T1046"),
  "sql-injection": chain("T1190", "T1213.006"),
  // Attacker script executing in a victim browser served by the target site.
  "xss": chain("T1189", "T1059.007", "T1190"),
  "cors": chain("T1190", "T1539"),
  "security-misconfiguration": chain("T1190", "T1078"),
  "missing-validation": chain("T1190"),
  // No Enterprise technique describes a cryptographic implementation defect.
  // Mapped by consequence instead: recoverable key material, and forgeable
  // application tokens (JWT alg confusion).
  "crypto-misuse": chain("T1552.001", "T1550.001"),

  // ── Memory corruption / binary ──
  // 0sec reaches these through kernel and binary targets, where the payoff is
  // local privilege escalation and the fallback is a crash.
  "heap-overflow": chain("T1068", "T1499.004", "T1203"),
  "out-of-bounds-write": chain("T1068", "T1499.004"),
  "stack-buffer-overflow": chain("T1068", "T1499.004", "T1203"),
  "use-after-free": chain("T1068", "T1499.004", "T1203"),
  "double-free": chain("T1068", "T1499.004"),
  "type-confusion": chain("T1068", "T1203"),
  "integer-overflow": chain("T1068", "T1499.004"),
  "integer-truncation": chain("T1068", "T1499.004"),
  "race-condition": chain("T1068", "T1499.004"),
  "toctou": chain("T1068", "T1499.004"),
  "format-string": chain("T1068", "T1499.004"),
  // Read-side primitives: an information leak that feeds an escalation chain,
  // or a crash. Primary reflects the leak, not the escalation.
  "out-of-bounds-read": chain("T1212", "T1068", "T1499.004"),
  "uninitialized-memory": chain("T1212", "T1068", "T1499.004"),
  // Almost always availability-only in practice.
  "null-pointer-deref": chain("T1499.004", "T1068"),
  "null-deref": chain("T1499.004", "T1068"),

  // ── Supply chain / package ──
  "known-vulnerable-package": chain("T1195.001", "T1588.006"),
  "supply-chain": chain("T1195.002", "T1195.001", "T1587.001"),

  // Catch-all bucket. A technique tag here would assert a behaviour nobody
  // determined; the report should show the gap.
  "other": [],
};

// ── Agent tool → technique ────────────────────────────────────────────────
//
// Keys are agent tool names (`TOOL_DEFINITIONS` in agent/tools/index.ts) plus
// the artifact kinds persisted alongside them (`waf_evasion`,
// `scanner_tool_run`). A tool absent from this map is not an oversight to
// paper over — it means the tool performs no action against the target.

const TOOL_MAP: Record<string, AttackTechnique[]> = {
  // ── HTTP / web surface ──
  http_request: chain("T1190", "T1595.002"),
  submit_form: chain("T1190", "T1594"),
  crawl: chain("T1594", "T1595"),
  browser: chain("T1594", "T1059.007"),
  js_recon: chain("T1594", "T1592.002"),
  discover_api_surface: chain("T1595", "T1595.003", "T1594"),
  surface_sweep: chain("T1595", "T1595.001", "T1046"),
  wp_fingerprint: chain("T1592.002", "T1595.002"),
  waf_evasion: chain("T1027", "T1211"),

  // ── Web exploitation probes ──
  structural_sqli_probe: chain("T1190", "T1595.002"),
  access_control_probe: chain("T1190", "T1078"),
  auth_boundary_probe: chain("T1078", "T1190"),

  // ── LLM target probes ──
  // Enterprise cannot name what these send (see the ATLAS scope note), but it
  // does name what they do: actively probing a live remote target.
  send_prompt: chain("T1595"),
  prompt_layer_probe: chain("T1595"),

  // ── External scanners ──
  run_nmap: chain("T1046", "T1595.001", "T1595.002"),
  run_nuclei: chain("T1595.002", "T1595"),
  run_ffuf: chain("T1595.003", "T1595"),
  run_sqlmap: chain("T1190", "T1595.002"),
  scanner_tool_run: chain("T1595.002", "T1595"),

  // ── Local execution ──
  bash: chain("T1059.004"),
  run_command: chain("T1059", "T1059.004"),
  pty_session: chain("T1059.004"),
  read_file: chain("T1005", "T1083"),

  // ── Binary / kernel ──
  analyze_binary: chain("T1592.002", "T1587.004"),
  syscall_boundary_map: chain("T1592.002", "T1082"),
  kernel_run: chain("T1068", "T1499.004", "T1587.004"),

  // ── Cloud ──
  cloud_s3_probe: chain("T1619", "T1530", "T1580"),
  cloud_validate_credentials: chain("T1078.004", "T1526"),

  // ── Out-of-band interaction ──
  oast_register: chain("T1583", "T1583.006"),
  oast_poll: chain("T1071.004", "T1071.001"),

  // ── Open-source intelligence ──
  web_search: chain("T1593", "T1596"),
  intel_search_advisories: chain("T1588.006", "T1596"),
  intel_lookup_cve: chain("T1588.006", "T1596"),
  intel_search_similar: chain("T1588.006", "T1593"),
  intel_search_target_history: chain("T1596", "T1596.005"),
  intel_build_dossier: chain("T1591", "T1593", "T1593.003"),
  payload_lookup: chain("T1588.005", "T1587.004"),

  // ── Credential reuse ──
  use_loot: chain("T1550", "T1078"),

  // Deliberately unmapped — no target interaction:
  //   save_finding / query_findings / update_finding / update_target /
  //   start_scan / spawn_agent / done / list_skills / load_skill /
  //   apply_patch / mongo_objectid
  // `apply_patch` edits a local working copy during audit or fix work.
  // `mongo_objectid` derives candidate identifiers offline; the request that
  // uses them is logged under `http_request`, so mapping it here would
  // double-count one action.
};

// ── Pipeline event → technique ────────────────────────────────────────────
//
// Keys are `eventType` values passed to `db.logEvent`. Only events that
// correspond to a real action against the target are mapped. Lifecycle,
// bookkeeping, scheduling, triage-scoring, and error events are `[]`: they
// describe what the engine did to itself, not what it did to the target, and
// tagging them would inflate the ATT&CK coverage claimed for an engagement.

const TOOL_BEARING_EVENTS = new Set(["tool_calls", "tool_artifact"]);

const EVENT_MAP: Record<string, AttackTechnique[]> = {
  // Engagement and stage boundaries: authorised active scanning begins.
  scan_start: chain("T1595", "T1595.002"),
  scan_resumed: chain("T1595", "T1595.002"),
  stage_start: chain("T1595"),

  // Fallback when the tool name is unknown or absent. Every 0sec tool call
  // happens inside an authorised active-scanning engagement, so the parent
  // technique holds even when the specific tool does not resolve.
  tool_calls: chain("T1595"),
  tool_artifact: chain("T1595"),

  // Exploit construction and verification: the engine builds a working
  // proof-of-vulnerability and confirms it fires against the target.
  oracle_result: chain("T1587.004", "T1588.006"),
  pov_oracle: chain("T1587.004", "T1588.006"),
  pov_gate_result: chain("T1587.004"),
  poc_gen_result: chain("T1587.004"),

  // Harvested credentials or tokens carried into a later step.
  loot_injected: chain("T1550", "T1078"),

  // Explicitly empty — lifecycle, bookkeeping and internal scoring only:
  //   scan_complete, scan_error, scan_aborted, stage_complete,
  //   agent_start, agent_complete, agent_error, agent_no_tool_calls,
  //   context_compacted, runtime_incompatible, playbook_injected,
  //   egats_start, egats_specialist, egats_complete,
  //   race_start, race_winner, race_complete,
  //   worker_claimed, worker_completed, worker_failed,
  //   finding_seeded, verdict_seeded, work_item_seeded, session_seeded,
  //   work_item_transition, workflow_status_changed, triage_updated,
  //   triage_features, dynamic_triage_routing, learned_router,
  //   early_stop_retry, auto_suppress_guard,
  //   consensus_verify, reachability_check, publishability_check,
  //   controllability_check, multi_modal_agreement, inline_validation,
  //   cost_ceiling_exceeded, kill_switch_triggered,
  //   and every *_error variant.
  // The two safety events in particular describe the engine stopping itself;
  // they are the opposite of an adversary action.
};

/**
 * Techniques for a finding category. Exhaustive over `AttackCategory`.
 *
 * Returns `[]` for the LLM-native categories that only MITRE ATLAS covers, and
 * for `other`. An empty result means "no honest Enterprise mapping exists",
 * never "not yet looked at" — report it as an explicit gap.
 */
export function techniquesForCategory(category: AttackCategory): AttackTechnique[] {
  return CATEGORY_MAP[category] ?? [];
}

/**
 * Techniques for a logged pipeline event.
 *
 * `toolName` is consulted only for the tool-bearing events (`tool_calls`,
 * `tool_artifact`), where it selects the mapping for the specific tool and
 * falls back to the generic event mapping when the tool is unknown. For every
 * other event the argument is ignored, so a stray tool name cannot promote a
 * lifecycle event into an ATT&CK-tagged one.
 *
 * Returns `[]` for unmapped events and for events that are lifecycle-only.
 */
export function techniquesForEvent(eventType: string, toolName?: string): AttackTechnique[] {
  if (toolName && TOOL_BEARING_EVENTS.has(eventType)) {
    const byTool = TOOL_MAP[toolName];
    if (byTool) return byTool;
  }
  return EVENT_MAP[eventType] ?? [];
}

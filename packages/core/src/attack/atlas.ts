// MITRE ATLAS (Adversarial Threat Landscape for AI Systems) mapping layer.
//
// The sibling of `./mitre.ts`, deliberately built to the same shape:
//
//   atlasTechniquesForCategory(category)      finding category → technique(s)
//   atlasTechniquesForEvent(eventType, tool)  pipeline event   → technique(s)
//
// ── Why this file exists separately ───────────────────────────────────────
//
// Enterprise ATT&CK and ATLAS are complementary matrices with disjoint id
// namespaces (`T####` vs `AML.T####`). Enterprise has no technique for prompt
// injection, jailbreaking, or system-prompt extraction; ATLAS has no technique
// for a heap overflow or a SQL injection. A finding may therefore legitimately
// carry an ATT&CK tag, an ATLAS tag, both, or neither.
//
// The two mappings are never merged. A consumer that flattens them into one
// list produces a deliverable that claims coverage in a matrix the client does
// not run, which is the exact failure this split exists to prevent.
//
// ── Rules this file is held to ────────────────────────────────────────────
//
// Identical to `./mitre.ts`:
//
// 1. Every id, name and tactic below was checked against the machine-readable
//    ATLAS release `dist/v6/ATLAS-2026.06.yaml` from mitre-atlas/atlas-data
//    (release 2026.06, dated 2026-06-30) — the same data that backs
//    atlas.mitre.org. Nothing is invented. Verify additions against that file
//    before adding them; a fabricated technique id in a client deliverable is
//    worse than no id at all.
// 2. Exactly one `primary` per non-empty list, then at most two `secondary`
//    supporting techniques. Consumers that need a single tag take the primary.
// 3. Where a mapping would be a guess, the list is `[]` with a comment saying
//    why. An honest gap beats a wrong tag.
// 4. Parent technique over sub-technique whenever the sub-technique is not an
//    exact fit.
//
// ── Note on the ATT&CK module's ATLAS comments ────────────────────────────
//
// `./mitre.ts` names three ATLAS techniques in comments. Two use names ATLAS
// has since changed or that were never exact, and one is a misattribution.
// Checked against release 2026.06:
//
//   • AML.T0056 is "Extract LLM System Prompt", not "LLM Meta Prompt
//     Extraction" (the pre-5.x name).
//   • AML.T0051.001 is "Indirect" — injection arriving through a separate data
//     channel the model ingests (a page, a document, a database row). It is NOT
//     the multi-turn technique. ATLAS files multi-turn escalation under
//     AML.T0054 "LLM Jailbreak", whose description enumerates "Multi-turn
//     escalation / Crescendo" by name as a jailbreak strategy. `multi-turn`
//     is mapped accordingly below.
//
// mitre.ts is another author's file and its Enterprise mappings are verified;
// those comments are left alone rather than edited from here.
//
// ── Tactic field ──────────────────────────────────────────────────────────
//
// Several ATLAS techniques sit under more than one tactic. `tactic` carries a
// single real ATLAS tactic name so a client can look it up verbatim; where
// ATLAS lists more than one, the choice is stated in a comment on the catalog
// entry and the full set is named there.

import type { AttackCategory } from "@0sec/shared";

export interface AtlasTechnique {
  id: string;
  name: string;
  /** ATLAS tactic name. */
  tactic: string;
  url: string;
  role: "primary" | "secondary";
}

// ── Verified technique catalog ────────────────────────────────────────────
//
// id → { name, tactic }. Sub-techniques carry a qualified display name
// ("LLM Prompt Injection: Direct") so a report line is unambiguous without the
// parent alongside it, and inherit their parent's tactic — ATLAS assigns
// tactics at the parent only.

interface CatalogEntry {
  name: string;
  tactic: string;
}

const CATALOG = {
  // Reconnaissance (AML.TA0002)
  "AML.T0006": { name: "Active Scanning", tactic: "Reconnaissance" },

  // AI Model Access (AML.TA0000)
  "AML.T0040": { name: "AI Model Inference API Access", tactic: "AI Model Access" },

  // Execution (AML.TA0005)
  "AML.T0051": { name: "LLM Prompt Injection", tactic: "Execution" },
  "AML.T0051.000": { name: "LLM Prompt Injection: Direct", tactic: "Execution" },
  "AML.T0051.001": { name: "LLM Prompt Injection: Indirect", tactic: "Execution" },
  // ATLAS lists AML.T0053 under Execution and Privilege Escalation. Execution
  // is used here: 0sec observes the tool actually being invoked, which is the
  // Execution reading; the privilege gain is a consequence it does not measure.
  "AML.T0053": { name: "AI Agent Tool Invocation", tactic: "Execution" },

  // Defense Evasion (AML.TA0007)
  // ATLAS lists AML.T0054 under Privilege Escalation and Defense Evasion.
  // Defense Evasion is used here: what a jailbreak finding demonstrates is a
  // guardrail bypass, whether or not any privilege was gained afterwards.
  "AML.T0054": { name: "LLM Jailbreak", tactic: "Defense Evasion" },
  "AML.T0067": {
    name: "LLM Trusted Output Components Manipulation",
    tactic: "Defense Evasion",
  },
  "AML.T0067.000": {
    name: "LLM Trusted Output Components Manipulation: Citations",
    tactic: "Defense Evasion",
  },
  "AML.T0068": { name: "LLM Prompt Obfuscation", tactic: "Defense Evasion" },

  // Discovery (AML.TA0008)
  "AML.T0069": { name: "Discover LLM System Information", tactic: "Discovery" },
  "AML.T0069.002": {
    name: "Discover LLM System Information: System Prompt",
    tactic: "Discovery",
  },
  "AML.T0084": { name: "Discover AI Agent Configuration", tactic: "Discovery" },

  // Exfiltration (AML.TA0010)
  "AML.T0024": { name: "Exfiltration via AI Inference API", tactic: "Exfiltration" },
  "AML.T0056": { name: "Extract LLM System Prompt", tactic: "Exfiltration" },
  "AML.T0057": { name: "LLM Data Leakage", tactic: "Exfiltration" },
  "AML.T0077": { name: "LLM Response Rendering", tactic: "Exfiltration" },
  "AML.T0086": {
    name: "Exfiltration via AI Agent Tool Invocation",
    tactic: "Exfiltration",
  },
} as const satisfies Record<string, CatalogEntry>;

type AtlasTechniqueId = keyof typeof CATALOG;

/**
 * ATLAS addresses a technique by its full dotted id, parent and sub-technique
 * alike — `AML.T0051` and `AML.T0051.000` both resolve directly. This is unlike
 * ATT&CK, which splits the sub-technique suffix into its own path segment.
 */
function techniqueUrl(id: string): string {
  return `https://atlas.mitre.org/techniques/${id}`;
}

function technique(id: AtlasTechniqueId, role: "primary" | "secondary"): AtlasTechnique {
  const entry: CatalogEntry = CATALOG[id];
  return { id, name: entry.name, tactic: entry.tactic, url: techniqueUrl(id), role };
}

/** One primary followed by up to two secondaries. */
function chain(
  primaryId: AtlasTechniqueId,
  ...secondaryIds: AtlasTechniqueId[]
): AtlasTechnique[] {
  return [
    technique(primaryId, "primary"),
    ...secondaryIds.slice(0, 2).map((id) => technique(id, "secondary")),
  ];
}

// ── Finding category → technique ──────────────────────────────────────────
//
// Exhaustive over `AttackCategory` on purpose: adding a category to
// @0sec/shared without deciding its ATLAS mapping is a type error here.
//
// Only the AI-behavioural categories map. Everything else is `[]` — see the
// block comment above the non-AI section before "filling in" any of them.

const CATEGORY_MAP: Record<AttackCategory, AtlasTechnique[]> = {
  // ── LLM / agent ──

  // The injection itself. Whether it arrived directly (AML.T0051.000) or
  // through an ingested data channel (AML.T0051.001) is a per-finding fact the
  // category alone does not carry, so the parent is used per rule 4. The
  // agentic payoff ATLAS explicitly links from T0051 is tool invocation.
  "prompt-injection": chain("AML.T0051", "AML.T0053"),

  // ATLAS: "Adversaries may induce an LLM to ignore, circumvent, or override
  // its safety/alignment behaviors and/or guardrails". Adversarial prompting is
  // the vehicle T0054 itself names first.
  "jailbreak": chain("AML.T0054", "AML.T0051"),

  // Exfiltration of the system prompt (T0056) is the outcome; discovering it
  // (T0069 / T0069.002) is the step that gets there. Both belong on the row.
  "system-prompt-extraction": chain("AML.T0056", "AML.T0069.002", "AML.T0069"),

  // ATLAS has no "multi-turn" technique. It files the behaviour under
  // AML.T0054, whose strategy list names "Multi-turn escalation / Crescendo"
  // verbatim: a sequence of prompts that starts benign, establishes trust, then
  // incrementally crosses policy boundaries. Mapped there rather than to
  // AML.T0051.001, which is "Indirect" (a separate ingested data channel) and
  // describes a different thing entirely.
  "multi-turn": chain("AML.T0054", "AML.T0051"),

  // Prompted disclosure of data the model should have withheld, then the two
  // channels ATLAS names for getting it out.
  "data-exfiltration": chain("AML.T0057", "AML.T0024", "AML.T0086"),

  // The agent's own tools driven to actions the operator never authorised.
  "tool-misuse": chain("AML.T0053", "AML.T0086", "AML.T0051"),

  // Manipulating the parts of a response a user treats as trustworthy —
  // citations, links, rendered content.
  "output-manipulation": chain("AML.T0067", "AML.T0067.000", "AML.T0077"),

  // Encoding, character-set tricks and hidden text used to slip a payload past
  // guardrails or a human reader.
  "encoding-bypass": chain("AML.T0068", "AML.T0054", "AML.T0051"),

  // ── Everything below: no honest ATLAS mapping ─────────────────────────────
  //
  // ATLAS describes attacks *on AI systems*. A SQL injection, a use-after-free
  // or a vulnerable npm dependency is a conventional finding: it belongs to
  // Enterprise ATT&CK (see ./mitre.ts, where every one of these is mapped) and
  // nothing is gained by also asserting an AML id for it.
  //
  // The near-misses, and why they stay empty:
  //
  //   • `supply-chain` / `known-vulnerable-package` vs AML.T0010 "AI Supply
  //     Chain Compromise". T0010's sub-techniques are Hardware, AI Software,
  //     Data, Model, Container Registry and AI Agent Tool — the compromised
  //     artifact has to *be* an AI artifact. The category alone never
  //     establishes that, and a generic dependency advisory tagged AML.T0010
  //     would overstate an AI-supply-chain compromise that was not shown.
  //   • `ssrf`, `command-injection`, `code-injection` vs AML.T0049 "Exploit
  //     Public-Facing Application" / AML.T0050 "Command and Scripting
  //     Interpreter". These exist in ATLAS only as steps in a chain against an
  //     AI system. Applying them to every web finding would inflate the ATLAS
  //     coverage claimed for an engagement.
  //   • `information-disclosure` vs AML.T0057 "LLM Data Leakage". T0057 is
  //     prompted disclosure by a model. A leaked stack trace or directory
  //     listing is not that.
  //
  // If a specific finding genuinely is the AI-flavoured variant, the mapping
  // belongs on that finding, not on the whole category.

  // Source-code audit
  "prototype-pollution": [],
  "path-traversal": [],
  "command-injection": [],
  "code-injection": [],
  "regex-dos": [],
  "unsafe-deserialization": [],
  "information-disclosure": [],
  "ssrf": [],
  "sql-injection": [],
  "xss": [],
  "cors": [],
  "security-misconfiguration": [],
  "missing-validation": [],
  "crypto-misuse": [],

  // Memory corruption / binary
  "heap-overflow": [],
  "out-of-bounds-read": [],
  "out-of-bounds-write": [],
  "use-after-free": [],
  "stack-buffer-overflow": [],
  "null-pointer-deref": [],
  "null-deref": [],
  "integer-overflow": [],
  "integer-truncation": [],
  "race-condition": [],
  "denial-of-service": [],
  "toctou": [],
  "type-confusion": [],
  "double-free": [],
  "format-string": [],
  "uninitialized-memory": [],

  // Supply chain / package
  "known-vulnerable-package": [],
  "supply-chain": [],

  // Catch-all bucket, as in ./mitre.ts.
  "other": [],
};

// ── Agent tool → technique ────────────────────────────────────────────────
//
// Only the tools that act against an AI system appear here. Every other 0sec
// tool — `http_request`, `run_nmap`, `bash`, `cloud_s3_probe`, the intel tools
// — is absent by design, not by oversight: an nmap sweep is not an attack on an
// AI system, and the ATT&CK map in ./mitre.ts already describes it correctly.
// Keeping this map sparse is what makes an ATLAS tag on a timeline row mean
// something.

const TOOL_MAP: Record<string, AtlasTechnique[]> = {
  // The engine's channel to a target model. Primary is the one thing true of
  // every call: it reaches the model through its inference API. The prompts it
  // carries are usually adversarial, but a single call may also be a benign
  // capability probe, so injection stays a secondary rather than being asserted
  // for every request.
  send_prompt: chain("AML.T0040", "AML.T0006", "AML.T0051"),

  // Classifies a system prompt / model config found in a reachable database.
  // Read-only by construction — it derives write *impact* from evidence passed
  // in and performs no writes — so this is Discovery only. The persistence
  // techniques a real write would implicate (AML.T0080 AI Agent Context
  // Poisoning, AML.T0081 Modify AI Agent Configuration) are deliberately not
  // claimed here; they belong on a finding that demonstrates the write.
  prompt_layer_probe: chain("AML.T0069", "AML.T0069.002", "AML.T0084"),
};

// ── Pipeline event → technique ────────────────────────────────────────────
//
// Empty, and that is the mapping — not a stub.
//
// An ATLAS tag asserts that the action targeted an AI system. No pipeline
// event carries that fact on its own: `scan_start`, `stage_start` and
// `oracle_result` fire identically against a kernel target and an LLM
// endpoint. Tagging them would put AML ids on every engagement 0sec runs.
//
// So ATLAS event tags come from one place only: a tool-bearing event whose
// tool is in TOOL_MAP above. That is the only point where the engine knows an
// AI system was on the other end.
//
// Note in particular that `llm_planner_invoked` and `llm_review` are NOT
// mapped. Those record 0sec's own model calls — the engine reasoning about
// its work. They are not an attack on anyone's AI system, and tagging them
// would misreport the operator's own tooling as adversary activity.

const TOOL_BEARING_EVENTS = new Set(["tool_calls", "tool_artifact"]);

const EVENT_MAP: Record<string, AtlasTechnique[]> = {};

/**
 * ATLAS techniques for a finding category. Exhaustive over `AttackCategory`.
 *
 * Returns `[]` for every category that is not AI-behavioural — which is most
 * of them, by design. An empty result means "no honest ATLAS mapping exists",
 * never "not yet looked at". Consult `techniquesForCategory` in ./mitre.ts for
 * the Enterprise ATT&CK mapping of the same category; the two are independent
 * and a category may map in one matrix, both, or neither.
 */
export function atlasTechniquesForCategory(category: AttackCategory): AtlasTechnique[] {
  return CATEGORY_MAP[category] ?? [];
}

/**
 * ATLAS techniques for a logged pipeline event.
 *
 * `toolName` is consulted only for the tool-bearing events (`tool_calls`,
 * `tool_artifact`). Because ATLAS tags require an AI target and no event type
 * establishes one on its own, there is no generic per-event fallback: an
 * unknown tool, or a tool that does not touch an AI system, yields `[]` rather
 * than a blanket tag.
 */
export function atlasTechniquesForEvent(
  eventType: string,
  toolName?: string,
): AtlasTechnique[] {
  if (toolName && TOOL_BEARING_EVENTS.has(eventType)) {
    const byTool = TOOL_MAP[toolName];
    if (byTool) return byTool;
  }
  return EVENT_MAP[eventType] ?? [];
}

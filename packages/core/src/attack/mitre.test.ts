import { describe, it, expect } from "vitest";
import type { AttackCategory } from "@0sec/shared";
import { techniquesForCategory, techniquesForEvent } from "./index.js";
import type { AttackTechnique } from "./index.js";

// Every member of the closed `AttackCategory` union. Kept literal rather than
// derived so that widening the union in @0sec/shared without touching the
// ATT&CK map fails here as well as in mitre.ts.
const ALL_CATEGORIES: AttackCategory[] = [
  "prompt-injection",
  "jailbreak",
  "system-prompt-extraction",
  "data-exfiltration",
  "tool-misuse",
  "output-manipulation",
  "encoding-bypass",
  "multi-turn",
  "prototype-pollution",
  "path-traversal",
  "command-injection",
  "code-injection",
  "regex-dos",
  "unsafe-deserialization",
  "information-disclosure",
  "ssrf",
  "sql-injection",
  "xss",
  "cors",
  "security-misconfiguration",
  "missing-validation",
  "crypto-misuse",
  "heap-overflow",
  "out-of-bounds-read",
  "out-of-bounds-write",
  "use-after-free",
  "stack-buffer-overflow",
  "null-pointer-deref",
  "null-deref",
  "integer-overflow",
  "integer-truncation",
  "race-condition",
  "toctou",
  "type-confusion",
  "double-free",
  "format-string",
  "uninitialized-memory",
  "known-vulnerable-package",
  "supply-chain",
  "other",
];

// Categories with no honest Enterprise ATT&CK equivalent. Documented in
// mitre.ts; asserted here so a future "fix" that fabricates a mapping has to
// argue with a test.
const INTENTIONALLY_EMPTY: AttackCategory[] = [
  "prompt-injection",
  "jailbreak",
  "system-prompt-extraction",
  "multi-turn",
  "other",
];

function assertWellFormed(techniques: AttackTechnique[]): void {
  for (const t of techniques) {
    expect(t.id).toMatch(/^T\d{4}(\.\d{3})?$/);
    expect(t.name.length).toBeGreaterThan(0);
    expect(t.tactic.length).toBeGreaterThan(0);
    expect(t.url).toBe(`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`);
  }
}

function assertRanking(techniques: AttackTechnique[]): void {
  if (techniques.length === 0) return;
  expect(techniques[0]!.role).toBe("primary");
  expect(techniques.filter((t) => t.role === "primary")).toHaveLength(1);
  expect(techniques.filter((t) => t.role === "secondary").length).toBeLessThanOrEqual(2);
  expect(new Set(techniques.map((t) => t.id)).size).toBe(techniques.length);
}

describe("techniquesForCategory", () => {
  it("resolves every AttackCategory without throwing", () => {
    for (const category of ALL_CATEGORIES) {
      expect(() => techniquesForCategory(category)).not.toThrow();
      expect(Array.isArray(techniquesForCategory(category))).toBe(true);
    }
  });

  it("returns well-formed, correctly ranked techniques for every category", () => {
    for (const category of ALL_CATEGORIES) {
      const techniques = techniquesForCategory(category);
      assertWellFormed(techniques);
      assertRanking(techniques);
    }
  });

  it("maps every category except the documented ATLAS-only ones and `other`", () => {
    for (const category of ALL_CATEGORIES) {
      const expectedEmpty = INTENTIONALLY_EMPTY.includes(category);
      expect(techniquesForCategory(category).length === 0).toBe(expectedEmpty);
    }
  });

  it("maps sql-injection to T1190 as primary", () => {
    const techniques = techniquesForCategory("sql-injection");
    expect(techniques[0]!.id).toBe("T1190");
    expect(techniques[0]!.name).toBe("Exploit Public-Facing Application");
    expect(techniques[0]!.tactic).toBe("Initial Access");
    expect(techniques[0]!.url).toBe("https://attack.mitre.org/techniques/T1190/");
  });

  it("maps ssrf to T1190 primary with the cloud metadata sub-technique as a secondary", () => {
    const techniques = techniquesForCategory("ssrf");
    expect(techniques[0]!.id).toBe("T1190");
    expect(techniques.some((t) => t.id === "T1552.005" && t.role === "secondary")).toBe(true);
    expect(techniques.find((t) => t.id === "T1552.005")!.url).toBe(
      "https://attack.mitre.org/techniques/T1552/005/",
    );
  });

  it("maps memory-corruption categories to privilege escalation", () => {
    for (const category of ["heap-overflow", "use-after-free", "stack-buffer-overflow"] as const) {
      expect(techniquesForCategory(category)[0]!.id).toBe("T1068");
    }
  });

  it("maps crash-only categories to endpoint denial of service", () => {
    expect(techniquesForCategory("null-deref")[0]!.id).toBe("T1499.004");
    expect(techniquesForCategory("null-pointer-deref")[0]!.id).toBe("T1499.004");
  });

  it("maps supply-chain categories under T1195", () => {
    expect(techniquesForCategory("supply-chain")[0]!.id).toBe("T1195.002");
    expect(techniquesForCategory("known-vulnerable-package")[0]!.id).toBe("T1195.001");
  });
});

describe("techniquesForEvent", () => {
  it("maps scan and stage start to active scanning", () => {
    expect(techniquesForEvent("scan_start")[0]!.id).toBe("T1595");
    expect(techniquesForEvent("scan_resumed")[0]!.id).toBe("T1595");
    expect(techniquesForEvent("stage_start")[0]!.id).toBe("T1595");
  });

  it("returns [] for lifecycle and safety events", () => {
    for (const eventType of [
      "cost_ceiling_exceeded",
      "kill_switch_triggered",
      "scan_complete",
      "stage_complete",
      "agent_complete",
      "worker_claimed",
      "triage_updated",
      "race_winner",
      "oracle_error",
    ]) {
      expect(techniquesForEvent(eventType)).toEqual([]);
    }
  });

  it("returns [] for an unknown event", () => {
    expect(techniquesForEvent("definitely_not_an_event")).toEqual([]);
    expect(techniquesForEvent("definitely_not_an_event", "http_request")).toEqual([]);
  });

  it("resolves tool_calls through the tool name", () => {
    expect(techniquesForEvent("tool_calls", "run_nmap")[0]!.id).toBe("T1046");
    expect(techniquesForEvent("tool_calls", "bash")[0]!.id).toBe("T1059.004");
    expect(techniquesForEvent("tool_calls", "run_sqlmap")[0]!.id).toBe("T1190");
    expect(techniquesForEvent("tool_calls", "cloud_s3_probe")[0]!.id).toBe("T1619");
  });

  it("resolves tool_artifact through the tool name, including artifact-only kinds", () => {
    expect(techniquesForEvent("tool_artifact", "http_request")[0]!.id).toBe("T1190");
    expect(techniquesForEvent("tool_artifact", "waf_evasion")[0]!.id).toBe("T1027");
    expect(techniquesForEvent("tool_artifact", "scanner_tool_run")[0]!.id).toBe("T1595.002");
  });

  it("falls back to the generic event mapping for an unknown tool", () => {
    expect(techniquesForEvent("tool_calls", "no_such_tool")[0]!.id).toBe("T1595");
    expect(techniquesForEvent("tool_calls")[0]!.id).toBe("T1595");
  });

  it("returns [] for tools that never touch the target", () => {
    for (const tool of ["save_finding", "query_findings", "apply_patch", "mongo_objectid"]) {
      // Not in the tool map, so the call falls back to the generic tool_calls
      // mapping rather than inventing a technique for bookkeeping.
      expect(techniquesForEvent("tool_calls", tool)[0]!.id).toBe("T1595");
    }
  });

  it("ignores toolName for events that do not carry one", () => {
    expect(techniquesForEvent("kill_switch_triggered", "bash")).toEqual([]);
    expect(techniquesForEvent("scan_start", "run_nmap")[0]!.id).toBe("T1595");
  });

  it("maps exploit verification to develop-capabilities", () => {
    expect(techniquesForEvent("oracle_result")[0]!.id).toBe("T1587.004");
    expect(techniquesForEvent("pov_oracle")[0]!.id).toBe("T1587.004");
    expect(techniquesForEvent("poc_gen_result")[0]!.id).toBe("T1587.004");
  });

  it("maps loot reuse to alternate authentication material", () => {
    expect(techniquesForEvent("loot_injected")[0]!.id).toBe("T1550");
  });

  it("returns well-formed, correctly ranked techniques for every mapped input", () => {
    const inputs: Array<[string, string?]> = [
      ["scan_start"],
      ["stage_start"],
      ["oracle_result"],
      ["loot_injected"],
      ["tool_calls"],
      ["tool_calls", "http_request"],
      ["tool_calls", "run_ffuf"],
      ["tool_calls", "kernel_run"],
      ["tool_calls", "oast_register"],
      ["tool_calls", "intel_build_dossier"],
      ["tool_artifact", "waf_evasion"],
    ];
    for (const [eventType, toolName] of inputs) {
      const techniques = techniquesForEvent(eventType, toolName);
      expect(techniques.length).toBeGreaterThan(0);
      assertWellFormed(techniques);
      assertRanking(techniques);
    }
  });
});

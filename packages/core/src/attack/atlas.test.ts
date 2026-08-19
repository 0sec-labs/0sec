import { describe, it, expect } from "vitest";
import type { AttackCategory } from "@0sec/shared";
import { atlasTechniquesForCategory, atlasTechniquesForEvent } from "./index.js";
import type { AtlasTechnique } from "./index.js";

// Every member of the closed `AttackCategory` union. Kept literal rather than
// derived so that widening the union in @0sec/shared without touching the
// ATLAS map fails here as well as in atlas.ts.
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

// The AI-behavioural categories — the only ones ATLAS describes. Every other
// category is a conventional finding that belongs to Enterprise ATT&CK.
// Asserted here so a future change that force-maps a web or memory-safety
// category into the AI matrix has to argue with a test.
const AI_CATEGORIES: AttackCategory[] = [
  "prompt-injection",
  "jailbreak",
  "system-prompt-extraction",
  "multi-turn",
  "data-exfiltration",
  "tool-misuse",
  "output-manipulation",
  "encoding-bypass",
];

function assertWellFormed(techniques: AtlasTechnique[]): void {
  for (const t of techniques) {
    expect(t.id).toMatch(/^AML\.T\d{4}(\.\d{3})?$/);
    expect(t.name.length).toBeGreaterThan(0);
    expect(t.tactic.length).toBeGreaterThan(0);
    expect(t.url).toBe(`https://atlas.mitre.org/techniques/${t.id}`);
  }
}

function assertRanking(techniques: AtlasTechnique[]): void {
  if (techniques.length === 0) return;
  expect(techniques[0]!.role).toBe("primary");
  expect(techniques.filter((t) => t.role === "primary")).toHaveLength(1);
  expect(techniques.filter((t) => t.role === "secondary").length).toBeLessThanOrEqual(2);
  expect(new Set(techniques.map((t) => t.id)).size).toBe(techniques.length);
}

describe("atlasTechniquesForCategory", () => {
  it("resolves every AttackCategory without throwing", () => {
    for (const category of ALL_CATEGORIES) {
      expect(() => atlasTechniquesForCategory(category)).not.toThrow();
      expect(Array.isArray(atlasTechniquesForCategory(category))).toBe(true);
    }
  });

  it("returns well-formed, correctly ranked techniques for every category", () => {
    for (const category of ALL_CATEGORIES) {
      const techniques = atlasTechniquesForCategory(category);
      assertWellFormed(techniques);
      assertRanking(techniques);
    }
  });

  it("maps exactly the AI-behavioural categories and nothing else", () => {
    for (const category of ALL_CATEGORIES) {
      const expectedMapped = AI_CATEGORIES.includes(category);
      expect(atlasTechniquesForCategory(category).length > 0).toBe(expectedMapped);
    }
  });

  it("maps the four categories Enterprise ATT&CK cannot express", () => {
    for (const category of [
      "prompt-injection",
      "jailbreak",
      "system-prompt-extraction",
      "multi-turn",
    ] as const) {
      expect(atlasTechniquesForCategory(category).length).toBeGreaterThan(0);
    }
  });

  it("maps prompt-injection to AML.T0051 as primary", () => {
    const techniques = atlasTechniquesForCategory("prompt-injection");
    expect(techniques[0]!.id).toBe("AML.T0051");
    expect(techniques[0]!.name).toBe("LLM Prompt Injection");
    expect(techniques[0]!.tactic).toBe("Execution");
    expect(techniques[0]!.url).toBe("https://atlas.mitre.org/techniques/AML.T0051");
  });

  it("maps jailbreak to AML.T0054 as primary", () => {
    const techniques = atlasTechniquesForCategory("jailbreak");
    expect(techniques[0]!.id).toBe("AML.T0054");
    expect(techniques[0]!.name).toBe("LLM Jailbreak");
    expect(techniques[0]!.tactic).toBe("Defense Evasion");
  });

  it("maps system-prompt-extraction to AML.T0056 with the discovery sub-technique alongside", () => {
    const techniques = atlasTechniquesForCategory("system-prompt-extraction");
    expect(techniques[0]!.id).toBe("AML.T0056");
    expect(techniques[0]!.name).toBe("Extract LLM System Prompt");
    expect(techniques[0]!.tactic).toBe("Exfiltration");
    expect(techniques.some((t) => t.id === "AML.T0069.002" && t.role === "secondary")).toBe(true);
    expect(techniques.find((t) => t.id === "AML.T0069.002")!.url).toBe(
      "https://atlas.mitre.org/techniques/AML.T0069.002",
    );
  });

  // ATLAS has no multi-turn technique; T0054's strategy list names "Multi-turn
  // escalation / Crescendo" explicitly. T0051.001 is "Indirect" and is a
  // different behaviour — guard against it being reintroduced here.
  it("maps multi-turn to the jailbreak technique, not to Indirect prompt injection", () => {
    const techniques = atlasTechniquesForCategory("multi-turn");
    expect(techniques[0]!.id).toBe("AML.T0054");
    expect(techniques.some((t) => t.id === "AML.T0051.001")).toBe(false);
  });

  it("maps the remaining LLM categories to their ATLAS outcomes", () => {
    expect(atlasTechniquesForCategory("data-exfiltration")[0]!.id).toBe("AML.T0057");
    expect(atlasTechniquesForCategory("tool-misuse")[0]!.id).toBe("AML.T0053");
    expect(atlasTechniquesForCategory("output-manipulation")[0]!.id).toBe("AML.T0067");
    expect(atlasTechniquesForCategory("encoding-bypass")[0]!.id).toBe("AML.T0068");
  });

  it("returns [] for conventional web and injection categories", () => {
    for (const category of [
      "sql-injection",
      "xss",
      "ssrf",
      "command-injection",
      "code-injection",
      "path-traversal",
    ] as const) {
      expect(atlasTechniquesForCategory(category)).toEqual([]);
    }
  });

  it("returns [] for memory-safety categories", () => {
    for (const category of [
      "heap-overflow",
      "use-after-free",
      "stack-buffer-overflow",
      "double-free",
      "null-deref",
    ] as const) {
      expect(atlasTechniquesForCategory(category)).toEqual([]);
    }
  });

  // AML.T0010 "AI Supply Chain Compromise" requires the compromised artifact to
  // be an AI artifact. A generic dependency advisory does not establish that.
  it("returns [] for supply-chain categories rather than claiming AML.T0010", () => {
    expect(atlasTechniquesForCategory("supply-chain")).toEqual([]);
    expect(atlasTechniquesForCategory("known-vulnerable-package")).toEqual([]);
  });

  it("returns [] for the catch-all category", () => {
    expect(atlasTechniquesForCategory("other")).toEqual([]);
  });
});

describe("atlasTechniquesForEvent", () => {
  it("returns [] for lifecycle, scan and stage events", () => {
    for (const eventType of [
      "scan_start",
      "scan_resumed",
      "stage_start",
      "scan_complete",
      "stage_complete",
      "agent_complete",
      "oracle_result",
      "loot_injected",
      "kill_switch_triggered",
    ]) {
      expect(atlasTechniquesForEvent(eventType)).toEqual([]);
    }
  });

  it("returns [] for an unknown event", () => {
    expect(atlasTechniquesForEvent("definitely_not_an_event")).toEqual([]);
    expect(atlasTechniquesForEvent("definitely_not_an_event", "send_prompt")).toEqual([]);
  });

  it("resolves the LLM tools through tool_calls and tool_artifact", () => {
    expect(atlasTechniquesForEvent("tool_calls", "send_prompt")[0]!.id).toBe("AML.T0040");
    expect(atlasTechniquesForEvent("tool_artifact", "send_prompt")[0]!.id).toBe("AML.T0040");
    expect(atlasTechniquesForEvent("tool_calls", "prompt_layer_probe")[0]!.id).toBe("AML.T0069");
    expect(atlasTechniquesForEvent("tool_artifact", "prompt_layer_probe")[0]!.id).toBe(
      "AML.T0069",
    );
  });

  it("carries the prompt-injection technique as a secondary on send_prompt", () => {
    const techniques = atlasTechniquesForEvent("tool_calls", "send_prompt");
    expect(techniques.some((t) => t.id === "AML.T0051" && t.role === "secondary")).toBe(true);
  });

  // The opposite of ./mitre.ts, deliberately: ATT&CK falls back to a generic
  // active-scanning tag because every 0sec action is active scanning. ATLAS
  // must not, because not every 0sec action touches an AI system.
  it("does not fall back to a generic tag for non-AI or unknown tools", () => {
    for (const tool of ["http_request", "run_nmap", "bash", "cloud_s3_probe", "no_such_tool"]) {
      expect(atlasTechniquesForEvent("tool_calls", tool)).toEqual([]);
      expect(atlasTechniquesForEvent("tool_artifact", tool)).toEqual([]);
    }
    expect(atlasTechniquesForEvent("tool_calls")).toEqual([]);
  });

  // 0sec's own planner and reviewer model calls are the operator's tooling,
  // not an attack on anyone's AI system.
  it("does not tag 0sec's own LLM usage", () => {
    expect(atlasTechniquesForEvent("llm_planner_invoked")).toEqual([]);
    expect(atlasTechniquesForEvent("llm_review")).toEqual([]);
  });

  it("ignores toolName for events that do not carry one", () => {
    expect(atlasTechniquesForEvent("scan_start", "send_prompt")).toEqual([]);
    expect(atlasTechniquesForEvent("kill_switch_triggered", "send_prompt")).toEqual([]);
  });

  it("returns well-formed, correctly ranked techniques for every mapped input", () => {
    const inputs: Array<[string, string]> = [
      ["tool_calls", "send_prompt"],
      ["tool_artifact", "send_prompt"],
      ["tool_calls", "prompt_layer_probe"],
      ["tool_artifact", "prompt_layer_probe"],
    ];
    for (const [eventType, toolName] of inputs) {
      const techniques = atlasTechniquesForEvent(eventType, toolName);
      expect(techniques.length).toBeGreaterThan(0);
      assertWellFormed(techniques);
      assertRanking(techniques);
    }
  });
});

describe("ATLAS and ATT&CK stay separate", () => {
  it("never emits an Enterprise T#### id", () => {
    for (const category of ALL_CATEGORIES) {
      for (const t of atlasTechniquesForCategory(category)) {
        expect(t.id.startsWith("AML.T")).toBe(true);
        expect(t.url.startsWith("https://atlas.mitre.org/")).toBe(true);
      }
    }
  });
});

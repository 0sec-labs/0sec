import { describe, it, expect } from "vitest";
import type { AttackCategory, Finding, LayerVerdict, PocStep } from "@pwnkit/shared";
import {
  VERIFY_EVIDENCE_KINDS,
  evidenceKindForFinding,
} from "./verify-verdict.js";

// EPIC #674 — cross-workspace parity guard for the verify evidence-kind union.
//
// The pwnkit engine and the 0cloud orchestrator are decoupled by design (linked
// only by the cloud-sink wire format), and the engine is a separate publishable
// workspace that cannot import a private `@0cloud/*` package. So the engine
// keeps its own copy of this union (`VerifyEvidenceKind` in `verify-verdict.ts`)
// and 0cloud keeps its copy in `@0cloud/cloud-contracts` (`VerifyEvidenceKind`,
// PR #681).
//
// The CANONICAL table below is duplicated VERBATIM from the locked cloud-
// contracts strings. Each side asserts its own exported set against this
// identical table, so any divergence between the engine union and the 0cloud
// single source is caught here — without a physical cross-workspace import.
// PARITY: when you change a value, update BOTH this fixture and the 0cloud one
// (and both source modules). Mirrors `can-auto-suppress.parity.test.ts` (#650).

const CANONICAL_VERIFY_EVIDENCE_KINDS = ["reproduced-poc", "source-only"];

describe("verify evidence-kind parity with @0cloud/cloud-contracts (#674)", () => {
  it("engine VERIFY_EVIDENCE_KINDS matches the canonical cloud table", () => {
    expect([...VERIFY_EVIDENCE_KINDS].sort()).toEqual(
      [...CANONICAL_VERIFY_EVIDENCE_KINDS].sort(),
    );
  });
});

// ────────────────────────────────────────────────────────────────────
// evidenceKindForFinding — the predicate both sides apply
// ────────────────────────────────────────────────────────────────────

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "ek-1",
    templateId: "audit-sink",
    title: "SQLi in /search",
    description: "tainted input into raw query",
    severity: "high",
    category: "sql-injection" as AttackCategory,
    status: "discovered",
    evidence: { request: "", response: "", analysis: "static review" },
    confidence: 0.6,
    timestamp: Date.now(),
    ...overrides,
  };
}

const POC_STEPS: PocStep[] = [
  { id: "exploit-1", kind: "exploit", summary: "run", action: { type: "shell", cmd: "curl x" } },
  { id: "verify-1", kind: "verify", summary: "see", action: { type: "note", text: "uid=0" } },
];

function passVerdict(layer: LayerVerdict["layer"]): LayerVerdict {
  return { layer, verdict: "pass", reason: "ok", durationMs: 1, costUsd: 0 };
}

describe("evidenceKindForFinding", () => {
  it("reproduced-poc when pocSteps + a poc_gen pass verdict are present", () => {
    expect(
      evidenceKindForFinding(finding({ pocSteps: POC_STEPS, layerVerdicts: [passVerdict("poc_gen")] })),
    ).toBe("reproduced-poc");
  });

  it("reproduced-poc for a pov_gate or oracle pass too", () => {
    expect(
      evidenceKindForFinding(finding({ pocSteps: POC_STEPS, layerVerdicts: [passVerdict("pov_gate")] })),
    ).toBe("reproduced-poc");
    expect(
      evidenceKindForFinding(finding({ pocSteps: POC_STEPS, layerVerdicts: [passVerdict("oracle")] })),
    ).toBe("reproduced-poc");
  });

  it("source-only when there are pocSteps but no reproducing pass verdict", () => {
    // pocSteps present but the only verdict is a non-reproducing layer.
    expect(
      evidenceKindForFinding(finding({ pocSteps: POC_STEPS, layerVerdicts: [passVerdict("reachability")] })),
    ).toBe("source-only");
  });

  it("source-only when a poc_gen verdict exists but it did NOT pass (poc:none)", () => {
    expect(
      evidenceKindForFinding(
        finding({
          pocSteps: [],
          triageNote: "poc:none: agent gave up",
          layerVerdicts: [{ layer: "poc_gen", verdict: "skip", reason: "poc:none", durationMs: 1, costUsd: 0 }],
        }),
      ),
    ).toBe("source-only");
  });

  it("source-only for a bare static finding (no pocSteps, no verdicts)", () => {
    expect(evidenceKindForFinding(finding())).toBe("source-only");
  });
});

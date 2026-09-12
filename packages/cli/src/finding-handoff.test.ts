import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { osecDB } from "@0sec/db";
import type { Finding } from "@0sec/shared";
import {
  buildFindingChatPrompt,
  buildFindingConsoleCommand,
  resolveFindingChatIntent,
} from "./finding-handoff.js";
import { loadFindingFocus } from "./finding-focus.js";

const finding = {
  id: "F-42",
  templateId: "source-review",
  title: "Unsafe redirect validation",
  description: "The redirect target is accepted without validating its origin.",
  severity: "high",
  category: "missing-validation",
  status: "verified",
  timestamp: 1_700_000_000_000,
  evidence: {
    request: "GET /redirect?next=https://attacker.example",
    response: "302 Location: https://attacker.example",
  },
} as Finding;

describe("finding handoff", () => {
  it("resolves supported intents and rejects unsupported actions", () => {
    expect(resolveFindingChatIntent(undefined)).toBe("investigate");
    expect(resolveFindingChatIntent("DRAFT_FIX")).toBe("draft_fix");
    expect(resolveFindingChatIntent(" IMPACT ")).toBe("impact");
    expect(() => resolveFindingChatIntent("apply")).toThrow();
  });

  it("quotes the terminal handoff without exposing shell injection", () => {
    expect(
      buildFindingConsoleCommand({ id: "F'42" }, "/tmp/0sec db's.sqlite", "draft_fix"),
    ).toBe(
      "0sec console --finding 'F'\\''42' --finding-intent draft_fix --db-path '/tmp/0sec db'\\''s.sqlite'",
    );
  });

  it("does not turn a ranking score or verified status into missing CVSS or chain evidence", () => {
    const prompt = buildFindingChatPrompt(
      { finding: { ...finding, score: 95 }, target: undefined },
      "impact",
    );
    const evidence = JSON.parse(prompt.split("<finding-evidence>\n")[1].split("\n</finding-evidence>")[0]);
    expect(evidence.status).toBe("verified");
    expect(evidence.target).toBeNull();
    for (const key of ["score", "cvssScore", "cvssVector", "impactAssessment", "pocExecution", "verification_result"]) {
      expect(evidence).not.toHaveProperty(key);
    }
  });

  it("retains contrary verification evidence and labels oversized receipts as incomplete", () => {
    const receipt = { confirmed: false, inconclusive: true, reason: "The test environment was unavailable." };
    const oversizedReceipt = { result: "unverified", output: "x".repeat(6_000) };
    const assessment: Finding["impactAssessment"] = {
      reachability_tier: "local-unpriv",
      blast_radius: "One authenticated account; broader reach is untested.",
      weaponizability: "info-leak",
      business_impact: "modest",
      rationale: "Potential disclosure requires an additional unverified authorization bypass.",
    };
    const prompt = buildFindingChatPrompt({
      finding: {
        ...finding,
        inlineValidation: receipt,
        pocExecution: oversizedReceipt,
        deploymentContext: "prod_reachable",
        impactAssessment: assessment,
      },
      target: "/work/app",
    }, "impact");
    const evidence = JSON.parse(prompt.split("<finding-evidence>\n")[1].split("\n</finding-evidence>")[0]);
    expect(evidence.status).toBe("verified");
    expect(evidence.inlineValidation).toEqual(receipt);
    expect(evidence.impactAssessment).toEqual(assessment);
    expect(evidence.pocExecution.truncated).toBe(true);
    expect(evidence.pocExecution.excerpt.length).toBeLessThan(3_100);
    expect(evidence.pocExecution).not.toHaveProperty("confirmed");
  });

  it("rehydrates a persisted finding before opening the chat", () => {
    const root = mkdtempSync(join(tmpdir(), "0sec-finding-focus-"));
    const dbPath = join(root, "findings.sqlite");
    const db = new osecDB(dbPath);
    const scoredFinding: Finding = {
      ...finding,
      cvssScore: 0,
      cvssVector: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
      impactAssessment: {
        reachability_tier: "local-unpriv",
        blast_radius: "One authenticated account; broader reach is untested.",
        weaponizability: "info-leak",
        business_impact: "modest",
        rationale: "Potential disclosure requires an additional unverified authorization bypass.",
      },
    };
    try {
      const scanId = db.createScan({
        target: "/work/app",
        depth: "default",
      } as Parameters<typeof db.createScan>[0]);
      db.saveFinding(scanId, scoredFinding);
    } finally {
      db.close();
    }

    try {
      const focus = loadFindingFocus("F-42", { dbPath });
      expect(focus.finding.id).toBe("F-42");
      expect(focus.finding.evidence.response).toBe(finding.evidence.response);
      expect(focus.target).toBe("/work/app");
      const prompt = buildFindingChatPrompt(focus, "impact");
      const evidence = JSON.parse(prompt.split("<finding-evidence>\n")[1].split("\n</finding-evidence>")[0]);
      expect(evidence.cvssScore).toBe(0);
      expect(evidence.cvssVector).toBe(scoredFinding.cvssVector);
      expect(evidence.impactAssessment).toEqual(scoredFinding.impactAssessment);
      const prefixFocus = loadFindingFocus("F-4", { dbPath });
      expect(prefixFocus.finding.impactAssessment).toEqual(scoredFinding.impactAssessment);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

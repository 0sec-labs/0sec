import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "@pwnkit/shared";
import type { MemSafetyScanResult } from "../../stages/memsafety-scan.js";
import { runResearch } from "../research-runner.js";
import { UserspaceMemSafetyResearchAdapter, type UserspaceMemSafetyTarget } from "./userspace-memsafety-adapter.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function finding(): Finding {
  return {
    id: "f-asan",
    templateId: "memsafety-asan",
    title: "ASan UAF",
    description: "reproduced UAF",
    severity: "high",
    category: "use-after-free",
    status: "discovered",
    evidence: { request: "crash.bin", response: "ASAN", analysis: "confirmed" },
    fingerprint: "memsafety:sig-1",
    timestamp: 1,
  };
}

function result(confirmed: boolean, iterations = 10): MemSafetyScanResult {
  const f = finding();
  return {
    findings: confirmed ? [f] : [],
    details: [{
      finding: f,
      crash: { kind: "asan", signature: "sig-1", rawOutput: "ASAN", ...(confirmed ? { inputPath: "crash.bin" } : {}) },
      exploitability: { primitive: "use-after-free", severity: "high", controllable: true, readWrite: "write", rationale: "write UAF" },
      verdict: {
        verdict: confirmed ? "confirmed" : "inconclusive",
        confidence: confirmed ? 1 : 0.3,
        reasoning: confirmed ? "saved sanitizer input confirms corruption" : "crash lacks a saved reproducer",
        signals: [],
        evidenceKind: confirmed ? "reproduced-memcorruption-poc" : "source-only",
      },
    }],
    loop: { iterations, crashes: [], corpusSize: 1, durationMs: 5 },
    toolingMissing: [],
    playbookContext: "memsafety playbook",
    warnings: [],
  };
}

function target(): UserspaceMemSafetyTarget {
  return {
    kind: "userspace.memsafety",
    id: "libfoo",
    location: "/src/libfoo",
    config: {
      target: { language: "rust", sourceRoot: "/src/libfoo", buildSystem: "cargo", harnessEntry: "parse" },
      fuzz: { timeoutSec: 1 },
    },
  };
}

describe("UserspaceMemSafetyResearchAdapter", () => {
  it("promotes only a sanitizer-confirmed crash and binds artifacts to the shared run directory", async () => {
    const scan = vi.fn(async () => result(true));
    const adapter = new UserspaceMemSafetyResearchAdapter(scan);
    const artifactRoot = mkdtempSync(join(tmpdir(), "pwnkit-userspace-"));
    roots.push(artifactRoot);
    const out = await runResearch(adapter, target(), { artifactRoot, runId: "run-userspace" });

    expect(out.findings).toHaveLength(1);
    expect(out.findings[0].candidateId).toBe("libfoo:campaign");
    expect(out.evidence.some((e) => e.stage === "execute" && e.status === "passed")).toBe(true);
    expect(out.evidence.some((e) => e.stage === "verify" && e.status === "passed")).toBe(true);
    expect(scan).toHaveBeenCalledWith(expect.objectContaining({
      fuzz: expect.objectContaining({ artifactDir: join(artifactRoot, "run-userspace") }),
    }));
  });

  it("keeps an unproven crash inconclusive and emits no shared finding", async () => {
    const artifactRoot = mkdtempSync(join(tmpdir(), "pwnkit-userspace-"));
    roots.push(artifactRoot);
    const out = await runResearch(new UserspaceMemSafetyResearchAdapter(async () => result(false)), target(), {
      artifactRoot,
      runId: "run-inconclusive",
    });
    expect(out.findings).toHaveLength(0);
    expect(out.evidence.some((e) => e.stage === "verify" && e.status === "inconclusive")).toBe(true);
  });

  it("does not execute when no userspace harness is configured", async () => {
    const scan = vi.fn();
    const noHarness = target();
    noHarness.config.target = { language: "c", sourceRoot: "/src/libfoo", buildSystem: "make" };
    noHarness.config.fuzz = {};
    const artifactRoot = mkdtempSync(join(tmpdir(), "pwnkit-userspace-"));
    roots.push(artifactRoot);
    const out = await runResearch(new UserspaceMemSafetyResearchAdapter(scan), noHarness, { artifactRoot, runId: "run-none" });

    expect(out.candidates).toHaveLength(0);
    expect(out.findings).toHaveLength(0);
    expect(scan).not.toHaveBeenCalled();
    expect(out.evidence.some((e) => e.stage === "discover" && e.status === "inconclusive")).toBe(true);
  });
});

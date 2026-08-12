// pwnkit#659 — OAST tool layer: oast_register / oast_poll on ToolExecutor.
// The oracle + collaborator cores are unit-tested in src/oast/*.test.ts; here
// we pin the tool wiring: registration surfaces a handle, polling runs the
// oracle, a confirmed callback lands in the loot ledger, and the tools degrade
// gracefully when no collaborator is deployed.

import { describe, it, expect } from "vitest";
import { TOOL_DEFINITIONS } from "./index.js";
import { ToolExecutor } from "../tools.js";
import type { ToolContext } from "../types.js";
import { InMemoryCollaborator } from "../../oast/index.js";
import { LootLedger } from "../loot.js";

function baseCtx(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    target: "https://target.test",
    scanId: "scan-1",
    findings: [],
    attackResults: [],
    targetInfo: {},
    ...overrides,
  };
}

function registeredHandle(output: unknown): { handleId: string; dnsHost: string } {
  if (
    !output ||
    typeof output !== "object" ||
    !("handle_id" in output) ||
    typeof output.handle_id !== "string" ||
    !("dns_host" in output) ||
    typeof output.dns_host !== "string"
  ) {
    throw new Error("oast_register did not return a handle");
  }
  return { handleId: output.handle_id, dnsHost: output.dns_host };
}

describe("OAST tool registry", () => {
  it("registers OAST tools and callback-to-finding evidence", () => {
    expect(TOOL_DEFINITIONS.oast_register).toBeDefined();
    expect(TOOL_DEFINITIONS.oast_poll).toBeDefined();
    expect(TOOL_DEFINITIONS.oast_poll.required).toContain("handle_id");
    expect(TOOL_DEFINITIONS.save_finding.parameters.oast_handle_id).toBeDefined();
  });
});

describe("oast_register / oast_poll wiring", () => {
  it("mints a handle, confirms an injected callback, and records loot", async () => {
    const collaborator = new InMemoryCollaborator({ baseDomain: "oast.test" });
    const loot = new LootLedger();
    const exec = new ToolExecutor(baseCtx({ oast: collaborator, loot }));

    const reg = await exec.execute({ name: "oast_register", arguments: {} });
    expect(reg.success).toBe(true);
    const out = reg.output as { available: boolean; handle_id: string; host: string; dns_host: string };
    expect(out.available).toBe(true);
    expect(out.handle_id).toBe("oast-1");

    // Poll before any callback → inconclusive.
    const empty = await exec.execute({
      name: "oast_poll",
      arguments: { handle_id: out.handle_id, class: "blind-ssrf" },
    });
    expect((empty.output as { verified: boolean }).verified).toBe(false);

    // Simulate the collaborator recording a DNS callback for this handle.
    collaborator.inject({ protocol: "dns", timestamp: "t", queryName: out.dns_host });

    const poll = await exec.execute({
      name: "oast_poll",
      arguments: { handle_id: out.handle_id, category: "ssrf" },
    });
    const verdict = poll.output as { verified: boolean; protocol: string; confidence: number };
    expect(verdict.verified).toBe(true);
    expect(verdict.protocol).toBe("dns");

    // Confirmed callback host is captured for chaining.
    expect(loot.query({ search: out.host })).toHaveLength(1);
  });

  it("persists a verified callback into the finding and cloud-sink call shape", async () => {
    const collaborator = new InMemoryCollaborator({ baseDomain: "oast.test" });
    const ctx = baseCtx({ oast: collaborator });
    const exec = new ToolExecutor(ctx);
    const reg = await exec.execute({ name: "oast_register", arguments: {} });
    const { handleId, dnsHost } = registeredHandle(reg.output);

    const unverified = await exec.execute({
      name: "save_finding",
      arguments: {
        title: "Blind SSRF",
        severity: "high",
        category: "ssrf",
        evidence_request: "GET /fetch?url=http://target",
        evidence_response: "202 Accepted",
        oast_handle_id: handleId,
      },
    });
    expect(unverified.success).toBe(false);
    expect(unverified.error).toMatch(/no verified callback/);
    expect(ctx.findings).toEqual([]);

    collaborator.inject({ protocol: "dns", timestamp: "t", queryName: dnsHost });
    const poll = await exec.execute({
      name: "oast_poll",
      arguments: { handle_id: handleId, category: "ssrf" },
    });
    expect(poll.success).toBe(true);

    const saveArgs: Record<string, unknown> = {
      title: "Blind SSRF",
      severity: "high",
      category: "ssrf",
      evidence_request: "GET /fetch?url=http://target",
      evidence_response: "202 Accepted",
      oast_handle_id: handleId,
    };
    const saved = await exec.execute({ name: "save_finding", arguments: saveArgs });
    expect(saved.success).toBe(true);
    expect(ctx.findings).toHaveLength(1);

    const finding = ctx.findings[0]!;
    expect(finding.status).toBe("verified");
    expect(finding.triageStatus).toBe("accepted");
    expect(finding.confidence).toBe(0.9);
    expect(finding.evidence.analysis).toContain("OAST callback verified (blind-ssrf/dns)");
    expect(finding.layerVerdicts).toEqual([
      expect.objectContaining({
        layer: "oracle",
        verdict: "pass",
        confidence: 0.9,
      }),
    ]);
    expect(saveArgs.status).toBe("verified");
    expect(saveArgs.evidence_analysis).toContain("OAST callback verified (blind-ssrf/dns)");
  });

  it("ties a hit to a specific candidate via the candidate nonce", async () => {
    const collaborator = new InMemoryCollaborator({ baseDomain: "oast.test" });
    const exec = new ToolExecutor(baseCtx({ oast: collaborator }));

    const reg = await exec.execute({ name: "oast_register", arguments: { candidate: "paramB" } });
    const out = reg.output as { handle_id: string; dns_host: string; candidate: string };
    expect(out.candidate).toBe("paramb");

    collaborator.inject({ protocol: "http", timestamp: "t", queryName: out.dns_host, path: "/paramb" });

    const defaultCandidate = await exec.execute({
      name: "oast_poll",
      arguments: { handle_id: out.handle_id, class: "blind-ssrf" },
    });
    expect(defaultCandidate.output).toMatchObject({ verified: true });

    const wrong = await exec.execute({
      name: "oast_poll",
      arguments: { handle_id: out.handle_id, class: "blind-ssrf", candidate: "paramA" },
    });
    expect((wrong.output as { verified: boolean }).verified).toBe(false);

    const right = await exec.execute({
      name: "oast_poll",
      arguments: { handle_id: out.handle_id, class: "blind-ssrf", candidate: "paramB" },
    });
    expect((right.output as { verified: boolean }).verified).toBe(true);
  });

  it("errors on an unknown handle_id", async () => {
    const exec = new ToolExecutor(baseCtx({ oast: new InMemoryCollaborator() }));
    const res = await exec.execute({ name: "oast_poll", arguments: { handle_id: "oast-99", class: "blind-ssrf" } });
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/unknown handle_id/);
  });

  it("requires a class or category to poll", async () => {
    const collaborator = new InMemoryCollaborator();
    const exec = new ToolExecutor(baseCtx({ oast: collaborator }));
    const reg = await exec.execute({ name: "oast_register", arguments: {} });
    const { handle_id } = reg.output as { handle_id: string };
    const res = await exec.execute({ name: "oast_poll", arguments: { handle_id } });
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/class/);
  });

  it("degrades gracefully when no collaborator is deployed", async () => {
    const exec = new ToolExecutor(baseCtx()); // no ctx.oast
    const reg = await exec.execute({ name: "oast_register", arguments: {} });
    expect(reg.success).toBe(true);
    expect((reg.output as { available: boolean }).available).toBe(false);

    const poll = await exec.execute({ name: "oast_poll", arguments: { handle_id: "oast-1", class: "blind-ssrf" } });
    expect(poll.success).toBe(true);
    expect((poll.output as { available: boolean }).available).toBe(false);
  });
});

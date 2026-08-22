import { describe, it, expect, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ToolExecutor } from "./tools.js";
import type { ToolContext, ToolCall, ScopedAuditEscalationRequest } from "./types.js";

// Scoped-source-audit allow-list gate: autonomy-aware + escalatable.
//
// The lightest possible harness: construct a ToolExecutor with a stub context
// (a real temp dir stands in for the scoped source root) and drive `execute`
// directly. No session, no runtime, no DB.
//
// `apply_patch` is the tool from the live bug report and is NOT in
// SCOPED_SOURCE_AUDIT_TOOLS, so it is the natural probe. When the gate lets it
// through, its handler returns a DIFFERENT error (missing `patch` arg / needs a
// scope) — never the gate's "not available in a scoped source audit" message —
// which is exactly how we prove the gate opened without performing any write.

const BLOCK_MSG = /not available in a scoped source audit/;

function baseCtx(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    target: "https://target.test",
    scanId: "escalation-test",
    findings: [],
    attackResults: [],
    targetInfo: {},
    role: "audit",
    ...overrides,
  } as ToolContext;
}

const patchCall: ToolCall = { name: "apply_patch", arguments: {} };

describe("scoped source-audit escalation gate", () => {
  it("no autonomy + no callback → today's exact hard-denial error (regression guard)", async () => {
    const root = mkdtempSync(join(tmpdir(), "0sec-esc-"));
    try {
      const exec = new ToolExecutor(baseCtx({ scopePath: root }), null);
      const result = await exec.execute(patchCall);
      expect(result.success).toBe(false);
      // Byte-identical to the pre-autonomy message.
      expect(result.error).toBe(
        'Tool "apply_patch" is not available in a scoped source audit',
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("YOLO + configured scope → a previously-blocked tool dispatches", async () => {
    const root = mkdtempSync(join(tmpdir(), "0sec-esc-"));
    try {
      const exec = new ToolExecutor(
        baseCtx({ scopePath: root, autonomyMode: "yolo" }),
        null,
      );
      const result = await exec.execute(patchCall);
      // Gate opened: we reach the handler, which rejects the empty patch arg —
      // NOT the scoped-audit block message.
      expect(result.error).not.toMatch(BLOCK_MSG);
      expect(result.error).toMatch(/patch/i);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("YOLO + NO scope → still blocked (no scope means no execution rights)", async () => {
    // No scopePath: the allow-list gate does not even engage, and the handler's
    // own scope guard blocks the call. YOLO grants nothing without a scope.
    const exec = new ToolExecutor(
      baseCtx({ autonomyMode: "yolo" /* no scopePath */ }),
      null,
    );
    const result = await exec.execute(patchCall);
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/requires a scoped local directory/);
  });

  it("standard + approving callback → tool runs; a second call does NOT re-invoke the callback", async () => {
    const root = mkdtempSync(join(tmpdir(), "0sec-esc-"));
    try {
      const escalate = vi.fn(async (_req: ScopedAuditEscalationRequest) => true);
      const exec = new ToolExecutor(
        baseCtx({ scopePath: root, autonomyMode: "standard", escalateScopedAudit: escalate }),
        null,
      );

      const first = await exec.execute(patchCall);
      expect(escalate).toHaveBeenCalledTimes(1);
      expect(first.error).not.toMatch(BLOCK_MSG); // gate opened → handler reached

      const second = await exec.execute(patchCall);
      // Grant remembered: no second prompt.
      expect(escalate).toHaveBeenCalledTimes(1);
      expect(second.error).not.toMatch(BLOCK_MSG);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("standard + denying callback → error; a retry does NOT re-invoke the callback", async () => {
    const root = mkdtempSync(join(tmpdir(), "0sec-esc-"));
    try {
      const escalate = vi.fn(async (_req: ScopedAuditEscalationRequest) => false);
      const exec = new ToolExecutor(
        baseCtx({ scopePath: root, autonomyMode: "standard", escalateScopedAudit: escalate }),
        null,
      );

      const first = await exec.execute(patchCall);
      expect(escalate).toHaveBeenCalledTimes(1);
      expect(first.success).toBe(false);
      expect(first.error).toMatch(BLOCK_MSG);

      const second = await exec.execute(patchCall);
      // Denial remembered: no re-prompt, same hard denial.
      expect(escalate).toHaveBeenCalledTimes(1);
      expect(second.success).toBe(false);
      expect(second.error).toMatch(BLOCK_MSG);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("copilot + configured scope → auto-lifts like yolo WITHOUT invoking the callback", async () => {
    // Under the current autonomy model copilot has no per-action prompts, so the
    // scoped-audit allow-list is auto-lifted inside the configured scope exactly
    // like yolo — the escalation callback is never consulted.
    const root = mkdtempSync(join(tmpdir(), "0sec-esc-"));
    try {
      const escalate = vi.fn(async (_req: ScopedAuditEscalationRequest) => true);
      const exec = new ToolExecutor(
        baseCtx({ scopePath: root, autonomyMode: "copilot", escalateScopedAudit: escalate }),
        null,
      );
      const result = await exec.execute(patchCall);
      expect(escalate).not.toHaveBeenCalled();
      // Gate opened: we reach the handler (which rejects the empty patch arg),
      // NOT the scoped-audit block message.
      expect(result.error).not.toMatch(BLOCK_MSG);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("recon + approving callback → still prompts (recon keeps the standard escalation flow)", async () => {
    // Recon is NOT auto-lifted (only yolo/copilot are). Anything that reaches
    // this gate in recon is a genuine allow-list escalation decision, so the
    // callback is invoked exactly as in standard. (In practice the console
    // refuses effectful recon tools upstream; this pins the gate's own policy.)
    const root = mkdtempSync(join(tmpdir(), "0sec-esc-"));
    try {
      const escalate = vi.fn(async (_req: ScopedAuditEscalationRequest) => true);
      const exec = new ToolExecutor(
        baseCtx({ scopePath: root, autonomyMode: "recon", escalateScopedAudit: escalate }),
        null,
      );
      const result = await exec.execute(patchCall);
      expect(escalate).toHaveBeenCalledTimes(1);
      expect(result.error).not.toMatch(BLOCK_MSG);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("a tool already in SCOPED_SOURCE_AUDIT_TOOLS never triggers escalation", async () => {
    const root = mkdtempSync(join(tmpdir(), "0sec-esc-"));
    try {
      const escalate = vi.fn(async (_req: ScopedAuditEscalationRequest) => true);
      const exec = new ToolExecutor(
        baseCtx({ scopePath: root, autonomyMode: "standard", escalateScopedAudit: escalate }),
        null,
      );
      // read_file is allow-listed → runs directly, callback untouched.
      const result = await exec.execute({ name: "read_file", arguments: { path: "nope.txt" } });
      expect(escalate).not.toHaveBeenCalled();
      expect(result.error).not.toMatch(BLOCK_MSG);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("switching the autonomy field between calls changes the outcome without rebuilding the executor", async () => {
    const root = mkdtempSync(join(tmpdir(), "0sec-esc-"));
    try {
      // Standard, no callback → hard denial (default behaviour).
      const ctx = baseCtx({ scopePath: root, autonomyMode: "standard" });
      const exec = new ToolExecutor(ctx, null);

      const blocked = await exec.execute(patchCall);
      expect(blocked.success).toBe(false);
      expect(blocked.error).toMatch(BLOCK_MSG);

      // Flip the same context object to YOLO — no new executor.
      ctx.autonomyMode = "yolo";
      const opened = await exec.execute(patchCall);
      expect(opened.error).not.toMatch(BLOCK_MSG);

      // And back to standard/no-callback → blocked again, same session.
      ctx.autonomyMode = "standard";
      const reblocked = await exec.execute(patchCall);
      expect(reblocked.success).toBe(false);
      expect(reblocked.error).toMatch(BLOCK_MSG);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

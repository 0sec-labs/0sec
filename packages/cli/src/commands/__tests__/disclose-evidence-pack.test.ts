import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// No core mock: exercise the REAL assembleEvidencePack / renderVendorNotificationMarkdown
// so the mandatory DRAFT banner is genuinely asserted end-to-end.
const { registerDiscloseCommand } = await import("../disclose.js");

function captureIO() {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const o = vi.spyOn(console, "log").mockImplementation((...a) => stdout.push(a.map(String).join(" ")));
  const e = vi.spyOn(console, "error").mockImplementation((...a) => stderr.push(a.map(String).join(" ")));
  return { stdout, stderr, restore: () => { o.mockRestore(); e.mockRestore(); } };
}

async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program.exitOverride();
  registerDiscloseCommand(program);
  await program.parseAsync(["node", "pwnkit-cli", ...argv]);
}

function reproducedFinding() {
  return {
    id: "f-001",
    templateId: "t",
    title: "SQL injection in /api/reports",
    description: "A boolean-based SQLi in the reports filter parameter.",
    severity: "high",
    category: "injection",
    status: "confirmed",
    evidence: { request: "GET /api/reports?x=1", response: "500" },
    timestamp: 0,
    pocSteps: [{ summary: "send payload", kind: "exploit", action: { type: "note", text: "see request" } }],
    layerVerdicts: [{ layer: "poc_gen", verdict: "pass", reason: "reproduced" }],
  };
}

describe("pwnkit disclose evidence-pack", () => {
  let io: ReturnType<typeof captureIO>;
  let dir: string;

  beforeEach(() => {
    process.exitCode = undefined;
    io = captureIO();
    dir = mkdtempSync(join(tmpdir(), "evpack-test-"));
  });

  afterEach(() => {
    process.exitCode = undefined;
    vi.clearAllMocks();
    io.restore();
    rmSync(dir, { recursive: true, force: true });
  });

  it("emits the mandatory DRAFT — NOT SENT banner to stdout", async () => {
    const fp = join(dir, "finding.json");
    writeFileSync(fp, JSON.stringify(reproducedFinding()));
    await runCli(["disclose", "evidence-pack", fp, "--target", "acme-app"]);
    const out = io.stdout.join("\n");
    expect(out).toContain("DRAFT — NOT SENT");
    expect(out).toContain("SQL injection in /api/reports");
    expect(out).toContain("acme-app");
  });

  it("writes the DRAFT to --out and never sends", async () => {
    const fp = join(dir, "finding.json");
    const outPath = join(dir, "draft.md");
    writeFileSync(fp, JSON.stringify(reproducedFinding()));
    await runCli(["disclose", "evidence-pack", fp, "--out", outPath]);
    expect(readFileSync(outPath, "utf8")).toContain("DRAFT — NOT SENT");
  });

  it("refuses an unreproduced finding unless --allow-unreproduced", async () => {
    const f = reproducedFinding();
    f.layerVerdicts = [];
    const fp = join(dir, "finding.json");
    writeFileSync(fp, JSON.stringify(f));
    await runCli(["disclose", "evidence-pack", fp]);
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("reproduced");
  });

  it("stages an unreproduced finding with --allow-unreproduced (still DRAFT)", async () => {
    const f = reproducedFinding();
    f.layerVerdicts = [];
    const fp = join(dir, "finding.json");
    writeFileSync(fp, JSON.stringify(f));
    await runCli(["disclose", "evidence-pack", fp, "--allow-unreproduced"]);
    const out = io.stdout.join("\n");
    expect(out).toContain("DRAFT — NOT SENT");
    expect(out).toContain("did **not** reproduce");
  });

  it("track opens a fresh draft record (intent only)", async () => {
    await runCli(["disclose", "track", "f-001"]);
    const rec = JSON.parse(io.stdout.join("\n"));
    expect(rec.status).toBe("draft");
    expect(rec.findingId).toBe("f-001");
  });
});

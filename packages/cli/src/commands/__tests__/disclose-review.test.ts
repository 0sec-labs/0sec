/**
 * #151 — CLI integration tests for `0sec disclose review`.
 *
 * Tests the CLI subcommand end-to-end through the real
 * `registerDiscloseCommand` and `assembleReproducibilityManifest` /
 * `renderReproducibilityManifest` so the gates and output shape
 * are genuinely exercised (no module mocks).
 *
 * Follows the pattern established in `disclose-evidence-pack.test.ts`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

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
  await program.parseAsync(["node", "0sec-cli", ...argv]);
}

function verifiedFinding() {
  return {
    id: "f-review-001",
    templateId: "tpl-sqli",
    title: "SQL injection in /api/reports",
    description: "Time-based SQL injection via the date parameter",
    severity: "critical",
    category: "sqli",
    status: "verified",
    evidence: {
      request: "GET /api/reports?date=2024-01-01 HTTP/1.1\nAuthorization: Bearer secret-bearer-token\nHost: target.example",
      response: "HTTP/1.1 200 OK\nSet-Cookie: session=deadbeef\nContent-Type: application/json\n\n[{\"id\":1}]",
    },
    pocSteps: [
      {
        id: "exploit",
        kind: "exploit",
        summary: "SQL injection in GET /api/reports",
        action: {
          type: "shell",
          cmd: "curl -X GET 'https://target.example/api/reports?date=2024-01-01' -H 'Authorization: Bearer secret-bearer-token'",
        },
      },
    ],
    pocExecution: {
      findingId: "f-review-001",
      startedAt: "2026-08-02T11:00:00.000Z",
      endedAt: "2026-08-02T11:00:05.000Z",
      steps: [
        {
          stepId: "exploit",
          kind: "passed",
          durationMs: 3200,
          observedExit: 0,
          observedStdout: "200 OK",
        },
      ],
      overallVerdict: "exploit_still_works",
    },
    layerVerdicts: [
      { layer: "oracle", verdict: "pass", reason: "PoC oracle confirms reachability", durationMs: 42, costUsd: 0 },
      { layer: "skeptic", verdict: "pass", reason: "Skeptic could not refute", durationMs: 120, costUsd: 0 },
    ],
    timestamp: 1,
  };
}

describe("0sec disclose review", () => {
  let io: ReturnType<typeof captureIO>;
  let dir: string;

  beforeEach(() => {
    io = captureIO();
    dir = mkdtempSync(join(tmpdir(), "disclose-review-test-"));
    process.exitCode = 0;
  });

  afterEach(() => {
    io.restore();
    rmSync(dir, { recursive: true, force: true });
  });

  it("renders the reproducibility manifest to stdout", async () => {
    const fp = join(dir, "finding.json");
    writeFileSync(fp, JSON.stringify(verifiedFinding()));
    await runCli(["disclose", "review", fp, "--timestamp", "2026-08-02T12:00:00.000Z"]);

    const out = io.stdout.join("\n");
    expect(out).toContain("REPRODUCIBILITY MANIFEST");
    expect(out).toContain("f-review-001");
    expect(out).toContain("SQL injection in /api/reports");
    expect(out).toContain("FOR HUMAN REVIEW ONLY");
  });

  it("writes the manifest to --out and never sends", async () => {
    const fp = join(dir, "finding.json");
    writeFileSync(fp, JSON.stringify(verifiedFinding()));
    const outPath = join(dir, "manifest.txt");
    await runCli(["disclose", "review", fp, "--out", outPath, "--timestamp", "2026-08-02T12:00:00.000Z"]);

    const content = readFileSync(outPath, "utf8");
    expect(content).toContain("REPRODUCIBILITY MANIFEST");
    expect(content).toContain("f-review-001");
    expect(content).toContain("FOR HUMAN REVIEW ONLY");
  });

  it("refuses a non-verified finding", async () => {
    const finding = { ...verifiedFinding(), status: "discovered" };
    const fp = join(dir, "finding.json");
    writeFileSync(fp, JSON.stringify(finding));
    await runCli(["disclose", "review", fp, "--timestamp", "2026-08-02T12:00:00.000Z"]);

    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain('expected "verified" or "confirmed"');
  });

  it("refuses incomplete evidence (no PoC exec, no layer verdicts)", async () => {
    const finding = {
      ...verifiedFinding(),
      pocExecution: undefined,
      layerVerdicts: [],
    };
    const fp = join(dir, "finding.json");
    writeFileSync(fp, JSON.stringify(finding));
    await runCli(["disclose", "review", fp, "--timestamp", "2026-08-02T12:00:00.000Z"]);

    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("successful verified PoV");
  });

  it("refuses malformed JSON with exit code 2", async () => {
    const fp = join(dir, "bad.json");
    writeFileSync(fp, "not json");
    await runCli(["disclose", "review", fp]);

    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("Failed to read finding JSON");
  });

  it("never leaks secrets in the rendered output", async () => {
    const fp = join(dir, "finding.json");
    writeFileSync(fp, JSON.stringify(verifiedFinding()));
    await runCli(["disclose", "review", fp, "--timestamp", "2026-08-02T12:00:00.000Z"]);

    const out = io.stdout.join("\n");
    expect(out).not.toContain("secret-bearer-token");
    expect(out).not.toContain("deadbeef");
  });

  it("accepts --target override", async () => {
    const fp = join(dir, "finding.json");
    writeFileSync(fp, JSON.stringify(verifiedFinding()));
    await runCli(["disclose", "review", fp, "--target", "acme-app:1.2.3", "--timestamp", "2026-08-02T12:00:00.000Z"]);

    const out = io.stdout.join("\n");
    expect(out).toContain("acme-app:1.2.3");
  });

  it("accepts --tool-version override", async () => {
    const fp = join(dir, "finding.json");
    writeFileSync(fp, JSON.stringify(verifiedFinding()));
    await runCli(["disclose", "review", fp, "--tool-version", "0sec/0.2.0-test", "--timestamp", "2026-08-02T12:00:00.000Z"]);

    const out = io.stdout.join("\n");
    expect(out).toContain("0sec/0.2.0-test");
  });

  it("renders model config when --model-config is provided", async () => {
    const fp = join(dir, "finding.json");
    writeFileSync(fp, JSON.stringify(verifiedFinding()));
    await runCli(["disclose", "review", fp, "--model-config", "anthropic/claude-sonnet-4", "--timestamp", "2026-08-02T12:00:00.000Z"]);

    const out = io.stdout.join("\n");
    expect(out).toContain("anthropic/claude-sonnet-4");
  });

  it("strips userinfo from ssh:// targets", async () => {
    const fp = join(dir, "finding.json");
    writeFileSync(fp, JSON.stringify(verifiedFinding()));
    await runCli(["disclose", "review", fp, "--target", "ssh://git:supersecret@github.com/org/repo", "--timestamp", "2026-08-02T12:00:00.000Z"]);

    const out = io.stdout.join("\n");
    expect(out).not.toContain("supersecret");
    expect(out).not.toContain("git:");
    expect(out).toContain("[REDACTED-USER]");
  });

  it("renders hashes for evidence (not the raw secrets)", async () => {
    const fp = join(dir, "finding.json");
    writeFileSync(fp, JSON.stringify(verifiedFinding()));
    await runCli(["disclose", "review", fp, "--timestamp", "2026-08-02T12:00:00.000Z"]);

    const out = io.stdout.join("\n");
    // Evidence section should show SHA-256 hex digests, not raw content.
    expect(out).toMatch(/Request \(SHA-256\)\s+[a-f0-9]{64}/);
    expect(out).toMatch(/Response \(SHA-256\)\s+[a-f0-9]{64}/);
  });

  it("reports --out mkdir failure with exit code 2 and no success output", async () => {
    // Place a regular file where a directory would be needed so that
    // mkdirSync(dirname(outPath)) throws.
    const fp = join(dir, "finding.json");
    writeFileSync(fp, JSON.stringify(verifiedFinding()));
    const blockFile = join(dir, "block");
    writeFileSync(blockFile, "");
    const outPath = join(blockFile, "manifest.txt");
    await runCli(["disclose", "review", fp, "--out", outPath, "--timestamp", "2026-08-02T12:00:00.000Z"]);

    expect(process.exitCode).toBe(2);
    expect(io.stdout.join("")).not.toContain("Manifest written");
    expect(io.stderr.join("")).toBeTruthy();
  });

  it("reports --out write failure with exit code 2 and no success output", async () => {
    // Write to an existing directory as the output path — writeFileSync
    // throws EISDIR when the target is a directory, not a file.
    const fp = join(dir, "finding.json");
    writeFileSync(fp, JSON.stringify(verifiedFinding()));
    const outDir = join(dir, "target-dir");
    mkdirSync(outDir);
    await runCli(["disclose", "review", fp, "--out", outDir, "--timestamp", "2026-08-02T12:00:00.000Z"]);

    expect(process.exitCode).toBe(2);
    expect(io.stdout.join("")).not.toContain("Manifest written");
    expect(io.stderr.join("")).toBeTruthy();
  });
});
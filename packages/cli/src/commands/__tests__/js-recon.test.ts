import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const runJsReconMock = vi.fn();

vi.mock("@0sec/core", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@0sec/core")>();
  return {
    ...actual,
    runJsRecon: runJsReconMock,
  };
});

const { registerJsReconCommand } = await import("../js-recon.js");

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
  registerJsReconCommand(program);
  await program.parseAsync(["node", "0sec-cli", ...argv]);
}

describe("0sec js-recon", () => {
  let io: ReturnType<typeof captureIO>;
  let dir: string;
  let scopePath: string;
  let fetchSpy: { mockRestore: () => void };

  beforeEach(() => {
    process.exitCode = undefined;
    io = captureIO();
    dir = mkdtempSync(join(tmpdir(), "jsrecon-test-"));
    scopePath = join(dir, "scope.json");
    writeFileSync(scopePath, JSON.stringify({ in_scope: ["*.example.com", "example.com"], out_of_scope: [] }));
    // Page fetch returns one script tag; the bundle fetch is irrelevant since
    // runJsRecon is mocked.
    fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      status: 200,
      text: async () => `<script src="https://example.com/app.js"></script>`,
    } as unknown as Response);
    runJsReconMock.mockResolvedValue({
      endpoints: [{ kind: "endpoint", value: "GET /api/users", source: "x" }],
      apiBaseUrls: ["https://api.example.com"],
      secrets: [{ kind: "aws_access_key", match: "AKIA…[20]", chunk: "https://example.com/app.js", confidence: "high" }],
      scanned: ["https://example.com/app.js"],
      skipped: [],
    });
  });

  afterEach(() => {
    process.exitCode = undefined;
    vi.clearAllMocks();
    fetchSpy.mockRestore();
    io.restore();
    rmSync(dir, { recursive: true, force: true });
  });

  it("deny-by-default: requires --scope (commander rejects without it)", async () => {
    await expect(runCli(["js-recon", "https://example.com"])).rejects.toBeDefined();
    expect(runJsReconMock).not.toHaveBeenCalled();
  });

  it("refuses an out-of-scope target page before any sweep", async () => {
    await runCli(["js-recon", "https://evil.com", "--scope", scopePath]);
    expect(runJsReconMock).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("out of scope");
  });

  it("passes the loaded scope to runJsRecon and prints redacted secret hits", async () => {
    await runCli(["js-recon", "https://example.com", "--scope", scopePath]);
    expect(runJsReconMock).toHaveBeenCalledTimes(1);
    const arg = runJsReconMock.mock.calls[0][0];
    expect(arg.scope).toBeDefined();
    expect(arg.scriptUrls).toContain("https://example.com/app.js");
    const out = io.stdout.join("\n");
    // The redacted excerpt is shown; the literal raw key never appears.
    expect(out).toContain("AKIA…[20]");
    expect(out).toContain("GET /api/users");
  });

  it("emits JSON with --json", async () => {
    await runCli(["js-recon", "https://example.com", "--scope", scopePath, "--json"]);
    const parsed = JSON.parse(io.stdout.join("\n"));
    expect(parsed.secrets[0].match).toBe("AKIA…[20]");
  });
});

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// No mocks: the ingest + analysis path is the real @pwnkit/core code, driven
// through real BloodHound-shaped fixtures on disk.
import { registerAdGraphCommand } from "../adgraph.js";

const DOMAIN_SID = "S-1-5-21-1111-2222-3333";
const DOMAIN_FQDN = "CORP.EXAMPLE.COM";

const USERS_FILE = {
  meta: { type: "users", count: 2, version: 6 },
  data: [
    {
      ObjectIdentifier: `${DOMAIN_SID}-1105`,
      Properties: {
        name: `SVC-SQL@${DOMAIN_FQDN}`,
        domain: DOMAIN_FQDN,
        domainsid: DOMAIN_SID,
        hasspn: true,
        enabled: true,
        admincount: true,
      },
      Aces: [],
    },
    {
      ObjectIdentifier: `${DOMAIN_SID}-1106`,
      Properties: { name: `ALICE@${DOMAIN_FQDN}`, domain: DOMAIN_FQDN, domainsid: DOMAIN_SID, enabled: true },
      Aces: [],
    },
  ],
};

const GROUPS_FILE = {
  meta: { type: "groups", count: 1, version: 6 },
  data: [
    {
      ObjectIdentifier: `${DOMAIN_SID}-512`,
      Properties: { name: `DOMAIN ADMINS@${DOMAIN_FQDN}`, domain: DOMAIN_FQDN, admincount: true, highvalue: true },
      Members: [{ ObjectIdentifier: `${DOMAIN_SID}-1105`, ObjectType: "User" }],
      Aces: [{ PrincipalSID: `${DOMAIN_SID}-1106`, PrincipalType: "User", RightName: "GenericAll" }],
    },
  ],
};

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
  registerAdGraphCommand(program);
  await program.parseAsync(["node", "pwnkit-cli", ...argv]);
}

describe("pwnkit adgraph", () => {
  let io: ReturnType<typeof captureIO>;
  let dir: string;
  let singleFile: string;
  let collectionDir: string;

  beforeEach(() => {
    process.exitCode = undefined;
    io = captureIO();
    dir = mkdtempSync(join(tmpdir(), "adgraph-test-"));

    singleFile = join(dir, "users.json");
    writeFileSync(singleFile, JSON.stringify(USERS_FILE));

    collectionDir = join(dir, "collection");
    mkdirSync(collectionDir);
    writeFileSync(join(collectionDir, "20260727_users.json"), JSON.stringify(USERS_FILE));
    writeFileSync(join(collectionDir, "20260727_groups.json"), JSON.stringify(GROUPS_FILE));
    writeFileSync(join(collectionDir, "notes.txt"), "ignored, not json");
  });

  afterEach(() => {
    process.exitCode = undefined;
    vi.clearAllMocks();
    io.restore();
    rmSync(dir, { recursive: true, force: true });
  });

  // ── option validation ──

  it("rejects a non-numeric --timeout", async () => {
    await runCli(["adgraph", "--input", singleFile, "--timeout", "later"]);
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("Invalid --timeout");
  });

  it("rejects a non-positive --timeout", async () => {
    await runCli(["adgraph", "--input", singleFile, "--timeout", "-1"]);
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("Invalid --timeout");
  });

  it("requires --input", async () => {
    await expect(runCli(["adgraph"])).rejects.toThrow(/input/);
  });

  // ── input resolution ──

  it("errors on a missing --input path", async () => {
    await runCli(["adgraph", "--input", join(dir, "nope.json")]);
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("does not exist");
  });

  it("errors on malformed JSON", async () => {
    const bad = join(dir, "broken.json");
    writeFileSync(bad, "{ not json");
    await runCli(["adgraph", "--input", bad]);
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("No usable BloodHound JSON");
    expect(io.stderr.join("\n")).toContain("invalid JSON");
  });

  it("errors on a directory with no *.json files", async () => {
    const empty = join(dir, "empty");
    mkdirSync(empty);
    writeFileSync(join(empty, "readme.md"), "nothing here");
    await runCli(["adgraph", "--input", empty]);
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("contains no *.json files");
  });

  it("errors on well-formed JSON that holds no AD objects", async () => {
    const notBloodhound = join(dir, "other.json");
    writeFileSync(notBloodhound, JSON.stringify({ hello: "world" }));
    await runCli(["adgraph", "--input", notBloodhound]);
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("no AD objects");
  });

  // ── successful runs ──

  it("analyzes a single BloodHound file and emits JSON", async () => {
    await runCli(["adgraph", "--input", singleFile, "--json"]);
    expect(process.exitCode).toBeUndefined();
    const parsed = JSON.parse(io.stdout.join("\n"));
    expect(parsed.graph.nodeCount).toBe(2);
    expect(parsed.summary.findingCount).toBeGreaterThan(0);
    expect(parsed.findings.some((f: { analyzer: string }) => f.analyzer === "kerberoastable-paths")).toBe(true);
  });

  it("analyzes a directory of collector files, skipping non-JSON entries", async () => {
    await runCli(["adgraph", "--input", collectionDir, "--json"]);
    expect(process.exitCode).toBeUndefined();
    const parsed = JSON.parse(io.stdout.join("\n"));
    expect(parsed.graph.sourceTypes.sort()).toEqual(["groups", "users"]);
    expect(parsed.graph.nodeCount).toBe(3);
    expect(parsed.graph.edgeCount).toBeGreaterThan(0);
  });

  it("prints a human summary without --json", async () => {
    await runCli(["adgraph", "--input", collectionDir]);
    const out = io.stdout.join("\n");
    expect(out).toContain("adgraph");
    expect(out).toContain("3 nodes");
    expect(out).toContain("findings:");
  });

  // ── --domain ──

  it("keeps the collection when --domain matches", async () => {
    await runCli(["adgraph", "--input", collectionDir, "--domain", "corp.example.com", "--json"]);
    expect(process.exitCode).toBeUndefined();
    const parsed = JSON.parse(io.stdout.join("\n"));
    expect(parsed.graph.nodeCount).toBe(3);
    expect(parsed.graph.warnings.some((w: string) => w.includes("filtered to domain CORP.EXAMPLE.COM"))).toBe(true);
  });

  it("errors with the domains actually present when --domain matches nothing", async () => {
    await runCli(["adgraph", "--input", collectionDir, "--domain", "other.example.com"]);
    expect(process.exitCode).toBe(2);
    const err = io.stderr.join("\n");
    expect(err).toContain("No objects in the collection belong to --domain 'other.example.com'");
    expect(err).toContain(DOMAIN_FQDN);
  });

  // ── timeout ──

  // The deadline itself races real file I/O, so asserting that a 1ms bound
  // fires would be a coin flip on a fast disk. What is deterministic — and what
  // regressed in earlier timeout wiring — is that the deadline timer is cleared
  // on the success path, so the process is free to exit right after the run.
  it("accepts a generous --timeout and leaves no pending timer behind", async () => {
    const before = process.getActiveResourcesInfo?.().filter((r) => r === "Timeout").length ?? 0;
    await runCli(["adgraph", "--input", collectionDir, "--timeout", "600000", "--json"]);
    expect(process.exitCode).toBeUndefined();
    const after = process.getActiveResourcesInfo?.().filter((r) => r === "Timeout").length ?? 0;
    expect(after).toBe(before);
  });
});

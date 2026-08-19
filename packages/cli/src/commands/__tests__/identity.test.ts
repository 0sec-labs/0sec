import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const runIdentityAssessmentMock = vi.fn();

vi.mock("@pwnkit/core", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@pwnkit/core")>();
  return {
    ...actual,
    runIdentityAssessment: runIdentityAssessmentMock,
  };
});

const { registerIdentityCommand } = await import("../identity.js");

const TOKEN_ENV = "PWNKIT_GRAPH_ACCESS_TOKEN";
const TENANT = "11111111-2222-3333-4444-555555555555";

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
  registerIdentityCommand(program);
  await program.parseAsync(["node", "pwnkit-cli", ...argv]);
}

function result(overrides: Record<string, unknown> = {}) {
  return {
    tenantId: TENANT,
    tenantDisplayName: "Contoso",
    generatedAt: "2026-07-27T00:00:00.000Z",
    durationMs: 12,
    collectionMs: 10,
    findings: [
      {
        id: "global-admin-count",
        check: "global-admin-count",
        title: "Too many Global Administrators",
        severity: "high",
        category: "privileged-roles",
        description: "9 accounts hold Global Administrator.",
        evidence: [],
        affectedPrincipals: [{ id: "u1", type: "user", displayName: "Alice" }],
        remediation: "Reduce standing Global Administrator assignments.",
      },
    ],
    summary: {
      total: 1,
      bySeverity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      byCategory: {
        "privileged-roles": 1,
        "conditional-access": 0,
        "app-registrations": 0,
        "service-principals": 0,
        federation: 0,
      },
    },
    snapshot: {
      collectedAt: "2026-07-27T00:00:00.000Z",
      partial: false,
      counts: {
        users: 40,
        groups: 5,
        servicePrincipals: 12,
        appRegistrations: 3,
        roleAssignments: 9,
        roleEligibilitySchedules: 0,
        conditionalAccessPolicies: 2,
        domains: 1,
      },
      warnings: [],
    },
    ...overrides,
  };
}

describe("pwnkit identity", () => {
  let io: ReturnType<typeof captureIO>;
  let dir: string;
  const originalToken = process.env[TOKEN_ENV];

  beforeEach(() => {
    process.exitCode = undefined;
    io = captureIO();
    dir = mkdtempSync(join(tmpdir(), "identity-test-"));
    process.env[TOKEN_ENV] = "eyJ-fake-token";
    runIdentityAssessmentMock.mockResolvedValue(result());
  });

  afterEach(() => {
    process.exitCode = undefined;
    vi.clearAllMocks();
    io.restore();
    rmSync(dir, { recursive: true, force: true });
    if (originalToken === undefined) delete process.env[TOKEN_ENV];
    else process.env[TOKEN_ENV] = originalToken;
  });

  // ── option validation ──

  it("rejects a non-numeric --timeout", async () => {
    await runCli(["identity", "--tenant", TENANT, "--timeout", "soon"]);
    expect(runIdentityAssessmentMock).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("Invalid --timeout");
  });

  it("rejects a non-positive --timeout", async () => {
    await runCli(["identity", "--tenant", TENANT, "--timeout", "0"]);
    expect(runIdentityAssessmentMock).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("Invalid --timeout");
  });

  it("rejects an empty --tenant", async () => {
    await runCli(["identity", "--tenant", "   "]);
    expect(runIdentityAssessmentMock).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("Invalid --tenant");
  });

  it("requires --tenant", async () => {
    await expect(runCli(["identity"])).rejects.toThrow(/tenant/);
    expect(runIdentityAssessmentMock).not.toHaveBeenCalled();
  });

  // ── token handling ──

  it("errors when the access-token env var is missing", async () => {
    delete process.env[TOKEN_ENV];
    await runCli(["identity", "--tenant", TENANT]);
    expect(runIdentityAssessmentMock).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain(`Missing ${TOKEN_ENV}`);
  });

  it("errors when the access-token env var is blank", async () => {
    process.env[TOKEN_ENV] = "   ";
    await runCli(["identity", "--tenant", TENANT]);
    expect(runIdentityAssessmentMock).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain(`Missing ${TOKEN_ENV}`);
  });

  it("never exposes a token-bearing option (tokens would leak into ps/history)", () => {
    const program = new Command();
    registerIdentityCommand(program);
    const identity = program.commands.find((c) => c.name() === "identity")!;
    const flags = identity.options.map((o) => o.flags.toLowerCase());
    expect(flags.some((f) => f.includes("token") || f.includes("secret"))).toBe(false);
    expect(flags.sort()).toEqual(["--json", "--scope <file>", "--tenant <tenantid>", "--timeout <ms>"]);
  });

  it("reads the token from the environment and passes it to runIdentityAssessment", async () => {
    await runCli(["identity", "--tenant", TENANT, "--json"]);
    expect(runIdentityAssessmentMock).toHaveBeenCalledTimes(1);
    expect(runIdentityAssessmentMock.mock.calls[0][0].accessToken).toBe("eyJ-fake-token");
  });

  // ── scope ──

  it("fails on an unreadable --scope file", async () => {
    await runCli(["identity", "--tenant", TENANT, "--scope", join(dir, "missing.json")]);
    expect(runIdentityAssessmentMock).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("Failed to load --scope");
  });

  it("wires --scope through as a ScopePolicy", async () => {
    const scopePath = join(dir, "scope.json");
    writeFileSync(scopePath, JSON.stringify({ in_scope: ["graph.microsoft.com"], out_of_scope: [] }));
    await runCli(["identity", "--tenant", TENANT, "--scope", scopePath, "--json"]);
    expect(runIdentityAssessmentMock).toHaveBeenCalledTimes(1);
    expect(runIdentityAssessmentMock.mock.calls[0][0].scope).toBeDefined();
  });

  it("passes no scope when --scope is omitted", async () => {
    await runCli(["identity", "--tenant", TENANT, "--json"]);
    expect(runIdentityAssessmentMock.mock.calls[0][0].scope).toBeUndefined();
  });

  // ── output ──

  it("emits the assessment as JSON with --json", async () => {
    await runCli(["identity", "--tenant", TENANT, "--json"]);
    expect(process.exitCode).toBeUndefined();
    const parsed = JSON.parse(io.stdout.join("\n"));
    expect(parsed.tenantId).toBe(TENANT);
    expect(parsed.findings).toHaveLength(1);
  });

  it("prints a human summary without --json", async () => {
    await runCli(["identity", "--tenant", TENANT]);
    const out = io.stdout.join("\n");
    expect(out).toContain("identity: Contoso");
    expect(out).toContain("findings: 1");
    expect(out).toContain("Too many Global Administrators");
  });

  it("says out loud that a partial snapshot is not a clean bill of health", async () => {
    runIdentityAssessmentMock.mockResolvedValue(
      result({
        findings: [],
        summary: {
          total: 0,
          bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          byCategory: {
            "privileged-roles": 0,
            "conditional-access": 0,
            "app-registrations": 0,
            "service-principals": 0,
            federation: 0,
          },
        },
        snapshot: {
          collectedAt: "2026-07-27T00:00:00.000Z",
          partial: true,
          counts: {
            users: 40,
            groups: 0,
            servicePrincipals: 0,
            appRegistrations: 0,
            roleAssignments: 0,
            roleEligibilitySchedules: 0,
            conditionalAccessPolicies: 0,
            domains: 0,
          },
          warnings: ["conditionalAccessPolicies: Graph forbidden (HTTP 403)"],
        },
      }),
    );
    await runCli(["identity", "--tenant", TENANT]);
    expect(io.stdout.join("\n")).toContain("PARTIAL SNAPSHOT");
  });

  // ── failure modes ──

  it("fails when the collection came back completely empty", async () => {
    runIdentityAssessmentMock.mockResolvedValue(
      result({
        snapshot: {
          collectedAt: "2026-07-27T00:00:00.000Z",
          partial: true,
          counts: {
            users: 0,
            groups: 0,
            servicePrincipals: 0,
            appRegistrations: 0,
            roleAssignments: 0,
            roleEligibilitySchedules: 0,
            conditionalAccessPolicies: 0,
            domains: 0,
          },
          warnings: ["users: Graph auth failed (HTTP 401)"],
        },
      }),
    );
    await runCli(["identity", "--tenant", TENANT, "--json"]);
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("returned no data");
  });

  it("refuses to report an assessment of a different tenant than --tenant", async () => {
    runIdentityAssessmentMock.mockResolvedValue(result({ tenantId: "99999999-0000-0000-0000-000000000000" }));
    await runCli(["identity", "--tenant", TENANT, "--json"]);
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("Tenant mismatch");
  });

  it("surfaces an assessment failure as a message, not a stack trace", async () => {
    runIdentityAssessmentMock.mockRejectedValue(
      new Error("Graph auth failed (HTTP 401) on /organization. Access token missing, expired, or wrong audience."),
    );
    await runCli(["identity", "--tenant", TENANT]);
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("Graph auth failed (HTTP 401)");
    expect(io.stderr.join("\n")).not.toContain("at Object.");
  });

  it("bounds the run with --timeout", async () => {
    runIdentityAssessmentMock.mockImplementation(() => new Promise(() => {}));
    await runCli(["identity", "--tenant", TENANT, "--timeout", "10"]);
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("exceeded --timeout 10ms");
  });
});

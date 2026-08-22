import { describe, it, expect, vi } from "vitest";
import { execPath } from "node:process";
import {
  createSandboxPackageRunner,
  localSandboxProvider,
  type SandboxProvider,
  type SandboxSession,
  type SandboxCommandResult,
} from "./sandbox-probe.js";
import type { DetectorRunOutcome } from "./base.js";
import { runNpmDynamicDiscovery } from "../npm-dynamic-discovery.js";
import type { NpmPackageRunner } from "./sandbox-probe.js";
import type { PackageRef } from "./types.js";
import type { Finding } from "@0sec/shared";

/** A confirmed, novel SSPP outcome — the JSON the in-sandbox harness emits. */
function novelSsppOutcome(): DetectorRunOutcome {
  return {
    detectorId: "sspp-fuzz",
    ran: true,
    candidates: 1,
    leads: [
      {
        detectorId: "sspp-fuzz",
        candidateId: "merge@pkg",
        confirmation: {
          confirmed: true,
          severity: "high",
          source: "pkg.merge",
          evidence: { observation: "Object.prototype polluted at runtime via pkg.merge (payload obj:src.__proto__)" },
        },
        dedup: { novel: true, source: "novel", advisories: [] },
      },
    ],
    warnings: [],
  };
}

/**
 * A programmable mock SandboxProvider. `handlers` maps a command name to the
 * result it should resolve (or a thrown error). Records every command + whether
 * dispose ran, so a test can assert install → harness → teardown ordering.
 */
function mockProvider(opts: {
  createThrows?: boolean;
  onCommand: (cmd: string, args: string[]) => SandboxCommandResult | Promise<SandboxCommandResult>;
}): { provider: SandboxProvider; calls: Array<{ cmd: string; args: string[] }>; disposed: () => number } {
  const calls: Array<{ cmd: string; args: string[] }> = [];
  let disposeCount = 0;
  const provider: SandboxProvider = {
    async create(): Promise<SandboxSession> {
      if (opts.createThrows) throw new Error("sandbox unavailable");
      return {
        workdir: "/tmp/mock-sandbox",
        async run(cmd, args): Promise<SandboxCommandResult> {
          calls.push({ cmd, args });
          return opts.onCommand(cmd, args);
        },
        async dispose(): Promise<void> {
          disposeCount += 1;
        },
      };
    },
  };
  return { provider, calls, disposed: () => disposeCount };
}

const ok = (stdout = ""): SandboxCommandResult => ({ stdout, stderr: "", exitCode: 0 });
const fail = (exitCode: number, stderr = "boom"): SandboxCommandResult => ({ stdout: "", stderr, exitCode });

describe("createSandboxPackageRunner (isolation seam)", () => {
  it("installs with --ignore-scripts, runs the harness, parses outcomes, tears down", async () => {
    const harnessJson = JSON.stringify({ outcomes: [novelSsppOutcome()], warnings: ["probe: note"] });
    const { provider, calls, disposed } = mockProvider({
      onCommand: (cmd) => {
        if (cmd === "npm") return ok(); // install
        return ok(`some npm noise\n${harnessJson}\n`); // node harness
      },
    });
    const runner = createSandboxPackageRunner({ provider, nodeBin: "node", harnessPath: "/harness.js" });
    const result = await runner({ name: "pkg", version: "1.0.0" }, ["sspp-fuzz"]);

    expect(result).toBeDefined();
    expect(result!.outcomes).toHaveLength(1);
    expect(result!.outcomes[0].leads[0].confirmation.evidence.observation).toContain("Object.prototype polluted");
    expect(result!.warnings).toContain("probe: note");

    // install ran first, with the load-bearing safety flag, pinned to the spec.
    const install = calls.find((c) => c.cmd === "npm")!;
    expect(install.args).toContain("--ignore-scripts");
    expect(install.args).toContain("pkg@1.0.0");
    // harness ran in a separate process (isolation), and teardown happened.
    expect(calls.some((c) => c.cmd === "node" && c.args[0] === "/harness.js")).toBe(true);
    expect(disposed()).toBe(1);
  });

  it("SKIPS (undefined) when the sandbox cannot be created — never a finding", async () => {
    const { provider, calls } = mockProvider({ createThrows: true, onCommand: () => ok() });
    const runner = createSandboxPackageRunner({ provider });
    const result = await runner({ name: "pkg" }, ["sspp-fuzz"]);
    expect(result).toBeUndefined();
    expect(calls).toHaveLength(0);
  });

  it("SKIPS + tears down when npm install fails (fail-safe, no false-confirm)", async () => {
    const { provider, calls, disposed } = mockProvider({
      onCommand: (cmd) => (cmd === "npm" ? fail(1, "E404") : ok("{}")),
    });
    const runner = createSandboxPackageRunner({ provider, harnessPath: "/harness.js" });
    const result = await runner({ name: "ghost-pkg" }, ["sspp-fuzz"]);
    expect(result).toBeUndefined();
    // harness must NOT run if install failed; sandbox still torn down.
    expect(calls.some((c) => c.cmd === "node")).toBe(false);
    expect(disposed()).toBe(1);
  });

  it("SKIPS + tears down when the harness process exits non-zero", async () => {
    const { provider, disposed } = mockProvider({
      onCommand: (cmd) => (cmd === "npm" ? ok() : fail(1, "harness crashed")),
    });
    const runner = createSandboxPackageRunner({ provider, harnessPath: "/harness.js" });
    const result = await runner({ name: "pkg" }, ["sspp-fuzz"]);
    expect(result).toBeUndefined();
    expect(disposed()).toBe(1);
  });

  it("SKIPS when the harness output is unparseable (inconclusive, never fabricated)", async () => {
    const { provider, disposed } = mockProvider({
      onCommand: (cmd) => (cmd === "npm" ? ok() : ok("not json at all")),
    });
    const runner = createSandboxPackageRunner({ provider, harnessPath: "/harness.js" });
    const result = await runner({ name: "pkg" }, ["sspp-fuzz"]);
    expect(result).toBeUndefined();
    expect(disposed()).toBe(1);
  });

  it("tears down even when run() rejects with an infra fault", async () => {
    const { provider, disposed } = mockProvider({
      onCommand: () => {
        throw new Error("spawn ENOENT");
      },
    });
    const runner = createSandboxPackageRunner({ provider, harnessPath: "/harness.js" });
    const result = await runner({ name: "pkg" }, ["sspp-fuzz"]);
    expect(result).toBeUndefined();
    expect(disposed()).toBe(1);
  });
});

describe("runNpmDynamicDiscovery via the packageRunner (sandbox) seam", () => {
  it("promotes sandbox outcomes to canonical findings + splits novel/known", async () => {
    const runner: NpmPackageRunner = vi.fn(async (_pkg: PackageRef, _ids: string[]) => ({
      outcomes: [novelSsppOutcome()],
      warnings: [],
    }));
    const confirmed: Finding[] = [];
    const result = await runNpmDynamicDiscovery({
      worklist: [{ name: "pkg", version: "1.0.0" }],
      packageRunner: runner,
      onConfirmed: (f) => {
        confirmed.push(f);
      },
    });

    expect(runner).toHaveBeenCalledWith({ name: "pkg", version: "1.0.0" }, expect.arrayContaining(["sspp-fuzz"]));
    expect(result.findings).toHaveLength(1);
    expect(result.novel).toHaveLength(1);
    expect(result.known).toHaveLength(0);
    expect(result.findings[0].templateId).toBe("npm-dynamic-sspp-fuzz");
    expect(result.findings[0].noveltyVerdict).toBe("novel");
    // onConfirmed fires for the novel lead (incremental persistence seam).
    expect(confirmed).toHaveLength(1);
    // detector stat aggregated from the sandbox outcome.
    const stat = result.perDetector.find((s) => s.detectorId === "sspp-fuzz")!;
    expect(stat.confirmed).toBe(1);
    expect(stat.novel).toBe(1);
  });

  it("a runner that returns undefined marks the package unpreparable (skipped, no finding)", async () => {
    const runner: NpmPackageRunner = async () => undefined;
    const result = await runNpmDynamicDiscovery({
      worklist: [{ name: "ghost" }],
      packageRunner: runner,
    });
    expect(result.findings).toHaveLength(0);
    expect(result.unpreparable).toEqual(["ghost"]);
  });

  it("requires at least one isolation seam", async () => {
    await expect(
      runNpmDynamicDiscovery({ worklist: [{ name: "pkg" }] } as never),
    ).rejects.toThrow(/packageRunner .* probeFactory/);
  });
});

describe("localSandboxProvider env isolation", () => {
  it("does not expose harness credentials to untrusted package code, but keeps PATH", async () => {
    const prevAnthropic = process.env.ANTHROPIC_API_KEY;
    const prevGithub = process.env.GITHUB_TOKEN;
    process.env.ANTHROPIC_API_KEY = "sk-ant-should-not-leak";
    process.env.GITHUB_TOKEN = "ghp_should_not_leak";
    const provider = localSandboxProvider();
    const session = await provider.create();
    try {
      // Stand in for an untrusted install/exec: a node one-liner that reports
      // whether the secrets and PATH are visible in its own process.env.
      const script =
        "process.stdout.write(JSON.stringify({" +
        "anthropic: process.env.ANTHROPIC_API_KEY ?? 'ABSENT'," +
        "github: process.env.GITHUB_TOKEN ?? 'ABSENT'," +
        "path: process.env.PATH ? 'SET' : 'ABSENT'}))";
      const res = await session.run(execPath, ["-e", script]);
      const seen = JSON.parse(res.stdout);
      expect(seen.anthropic).toBe("ABSENT");
      expect(seen.github).toBe("ABSENT");
      expect(seen.path).toBe("SET");
    } finally {
      await session.dispose();
      if (prevAnthropic === undefined) delete process.env.ANTHROPIC_API_KEY;
      else process.env.ANTHROPIC_API_KEY = prevAnthropic;
      if (prevGithub === undefined) delete process.env.GITHUB_TOKEN;
      else process.env.GITHUB_TOKEN = prevGithub;
    }
  });
});

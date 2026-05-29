import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdirSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

// Mock node:child_process before importing the module under test. The
// installNpmPackage path under test uses execFileSync for both:
//   1. `npm init -y --silent` (writeMinimalPackageJson)
//   2. `npm install <spec> ...` (the call we want to assert about)
// We route the mock per-args.
const execFileSyncMock = vi.fn();
const execSyncMock = vi.fn();
vi.mock("node:child_process", () => ({
  execFileSync: (...args: unknown[]) => execFileSyncMock(...args),
  execSync: (...args: unknown[]) => execSyncMock(...args),
}));

// Mock historical-package-fallback so non-ERESOLVE 404-style failures don't
// accidentally route through it during the negative-path test.
vi.mock("./historical-package-fallback.js", () => ({
  shouldUseHistoricalPackageFallback: () => false,
  restoreHistoricalPackageFixture: () => null,
}));

const {
  installPackageForEcosystem,
  runDependencyAuditForEcosystem,
  walkInstalledNpmTree,
  probePublicNpmRegistry,
} = await import("./package-ecosystems.js");

// ── Fixtures ───────────────────────────────────────────────────────────────

/**
 * Build an `execFileSync` error shaped like Node's SpawnSyncReturns
 * failure: an Error with a `stderr` Buffer property. This is exactly
 * what `execFileSync` throws when the child exits non-zero with
 * stdio:"pipe".
 */
function makeSpawnError(stderr: string, message = "Command failed"): Error & { stderr: Buffer } {
  const err = new Error(message) as Error & { stderr: Buffer };
  err.stderr = Buffer.from(stderr, "utf-8");
  return err;
}

/**
 * Drop a `node_modules/<packageName>/package.json` into the temp dir so
 * the post-install lookup in installNpmPackage succeeds and returns a
 * versioned InstalledPackage. Used to simulate a successful install
 * landing on disk.
 */
function plantNodeModules(cwd: string, packageName: string, version: string): void {
  const dir = join(cwd, "node_modules", packageName);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: packageName, version }), "utf-8");
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe("installNpmPackage — ERESOLVE retry with --legacy-peer-deps", () => {
  beforeEach(() => {
    execFileSyncMock.mockReset();
  });

  it("retries with --legacy-peer-deps when first install fails with ERESOLVE in stderr", () => {
    let installCallCount = 0;

    execFileSyncMock.mockImplementation((cmd: string, args: string[], opts: any) => {
      // `npm init -y --silent` — succeeds, nothing to do.
      if (cmd === "npm" && args[0] === "init") return Buffer.from("");

      // First `npm install` — fail with ERESOLVE.
      // Second `npm install` (with --legacy-peer-deps) — succeed and
      // plant node_modules so the post-install lookup resolves.
      if (cmd === "npm" && args[0] === "install") {
        installCallCount += 1;
        if (installCallCount === 1) {
          throw makeSpawnError(
            "npm error code ERESOLVE\nnpm error ERESOLVE could not resolve\n" +
              "npm error While resolving: @langchain/community@1.1.28\n" +
              "npm error Found: @langchain/core@1.1.38\n",
          );
        }
        // Second call — verify the fallback flag is present in argv,
        // then plant the install result on disk.
        expect(args).toContain("--legacy-peer-deps");
        plantNodeModules(opts.cwd, "@langchain/community", "1.1.28");
        return Buffer.from("");
      }

      throw new Error(`Unexpected execFileSync invocation: ${cmd} ${JSON.stringify(args)}`);
    });

    const emitted: Array<{ type: string; stage?: string; message: string }> = [];
    const result = installPackageForEcosystem(
      "npm",
      "@langchain/community",
      "1.1.28",
      (event) => emitted.push(event),
    );

    expect(installCallCount).toBe(2);
    expect(result.ecosystem).toBe("npm");
    expect(result.name).toBe("@langchain/community");
    expect(result.version).toBe("1.1.28");

    // Confirm the structured warning was emitted on the prepare stage
    // so operators see "this used --legacy-peer-deps" in the findings UI.
    const fallbackWarning = emitted.find(
      (e) => e.stage === "prepare" && /--legacy-peer-deps/i.test(e.message),
    );
    expect(fallbackWarning).toBeDefined();
    expect(fallbackWarning?.type).toBe("stage:end");
  });

  it("does NOT retry on non-ERESOLVE errors (e.g. 404)", () => {
    let installCallCount = 0;

    execFileSyncMock.mockImplementation((cmd: string, args: string[]) => {
      if (cmd === "npm" && args[0] === "init") return Buffer.from("");
      if (cmd === "npm" && args[0] === "install") {
        installCallCount += 1;
        throw makeSpawnError(
          "npm error code E404\nnpm error 404 Not Found - GET https://registry.npmjs.org/totally-not-a-package",
        );
      }
      throw new Error(`Unexpected execFileSync invocation: ${cmd} ${JSON.stringify(args)}`);
    });

    expect(() =>
      installPackageForEcosystem(
        "npm",
        "totally-not-a-package",
        "9.9.9",
        () => {},
      ),
    ).toThrow(/Failed to install/);

    // The 404 error path must NOT trigger a second install attempt.
    expect(installCallCount).toBe(1);
  });

  it("emits a prepare-stage warning message when the ERESOLVE retry succeeds", () => {
    let installCallCount = 0;

    execFileSyncMock.mockImplementation((cmd: string, args: string[], opts: any) => {
      if (cmd === "npm" && args[0] === "init") return Buffer.from("");
      if (cmd === "npm" && args[0] === "install") {
        installCallCount += 1;
        if (installCallCount === 1) {
          throw makeSpawnError("npm ERR! code ERESOLVE\nnpm ERR! ERESOLVE unable to resolve dependency tree");
        }
        plantNodeModules(opts.cwd, "some-pkg", "2.0.0");
        return Buffer.from("");
      }
      throw new Error(`Unexpected execFileSync invocation: ${cmd} ${JSON.stringify(args)}`);
    });

    const emitted: Array<{ type: string; stage?: string; message: string }> = [];
    installPackageForEcosystem("npm", "some-pkg", "2.0.0", (event) => emitted.push(event));

    // Both the "retrying with --legacy-peer-deps" notice and the final
    // structured prepare warning must be emitted so the operator gets
    // both a real-time signal and a persisted entry in the scan output.
    const retryNotice = emitted.find((e) => /retrying with --legacy-peer-deps/i.test(e.message));
    expect(retryNotice).toBeDefined();
    expect(retryNotice?.stage).toBe("discovery");

    const prepareWarning = emitted.find(
      (e) => e.stage === "prepare" && /--legacy-peer-deps fallback/i.test(e.message),
    );
    expect(prepareWarning).toBeDefined();
    expect(prepareWarning?.type).toBe("stage:end");
  });
});

describe("runDependencyAuditForEcosystem — non-npm OSV lookup", () => {
  beforeEach(() => {
    execFileSyncMock.mockReset();
    execSyncMock.mockReset();
  });

  it("queries OSV for PyPI root package advisories instead of invoking pip-audit", () => {
    execFileSyncMock.mockImplementation((cmd: string, args: string[], opts: any) => {
      expect(cmd).toBe("curl");
      expect(args).toContain("https://api.osv.dev/v1/query");
      expect(args).toContain("--data-binary");
      expect(String(opts.input)).toContain('"ecosystem":"PyPI"');
      expect(String(opts.input)).toContain('"name":"django"');
      expect(String(opts.input)).toContain('"version":"3.2.0"');
      return JSON.stringify({
        vulns: [
          {
            id: "PYSEC-2021-1",
            aliases: ["CVE-2021-0001"],
            summary: "test advisory",
            database_specific: { severity: "HIGH" },
            references: [{ url: "https://osv.dev/vulnerability/PYSEC-2021-1" }],
          },
        ],
      });
    });

    const findings = runDependencyAuditForEcosystem(
      "pypi",
      "/tmp/project",
      () => {},
      { name: "django", version: "3.2.0" },
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "django",
      severity: "high",
      title: "test advisory",
      source: "PYSEC-2021-1",
    });
    expect(execFileSyncMock).toHaveBeenCalledOnce();
  });

  it("queries OSV for crates.io root package advisories instead of invoking cargo-audit", () => {
    execFileSyncMock.mockImplementation((cmd: string, args: string[], opts: any) => {
      expect(cmd).toBe("curl");
      expect(args).toContain("https://api.osv.dev/v1/query");
      expect(String(opts.input)).toContain('"ecosystem":"crates.io"');
      expect(String(opts.input)).toContain('"name":"itoa"');
      expect(String(opts.input)).toContain('"version":"1.0.0"');
      return JSON.stringify({ vulns: [] });
    });

    const findings = runDependencyAuditForEcosystem(
      "cargo",
      "/tmp/project",
      () => {},
      { name: "itoa", version: "1.0.0" },
    );

    expect(findings).toEqual([]);
    expect(execFileSyncMock).toHaveBeenCalledOnce();
  });
});

// ── walkInstalledNpmTree (issue #565) ───────────────────────────────────────

describe("walkInstalledNpmTree", () => {
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "walk-tree-test-"));
  });
  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  function plant(relPath: string, name: string, version: string): void {
    const dir = join(root, relPath);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name, version }), "utf-8");
  }

  it("returns hoisted transitive deps and excludes the audited root", () => {
    plant("node_modules/my-app", "my-app", "1.0.0"); // the audited root
    plant("node_modules/dep-a", "dep-a", "2.0.0");
    plant("node_modules/dep-b", "dep-b", "3.1.0");

    const tree = walkInstalledNpmTree(root, "my-app");
    const names = tree.map((t) => t.name).sort();
    expect(names).toEqual(["dep-a", "dep-b"]);
    expect(tree.every((t) => t.depth === 1)).toBe(true);
    const depA = tree.find((t) => t.name === "dep-a");
    expect(depA?.version).toBe("2.0.0");
    expect(depA?.dependencyPath).toEqual(["my-app", "dep-a"]);
  });

  it("handles scoped packages and nested node_modules with deeper depth", () => {
    plant("node_modules/@acme/widgets", "@acme/widgets", "1.0.0");
    plant("node_modules/dep-a", "dep-a", "2.0.0");
    plant("node_modules/dep-a/node_modules/nested", "nested", "0.0.1");

    const tree = walkInstalledNpmTree(root, "my-app");
    const scoped = tree.find((t) => t.name === "@acme/widgets");
    expect(scoped).toBeDefined();
    expect(scoped?.depth).toBe(1);

    const nested = tree.find((t) => t.name === "nested");
    expect(nested).toBeDefined();
    expect(nested?.depth).toBe(2);
    expect(nested?.dependencyPath).toEqual(["my-app", "dep-a", "nested"]);
  });

  it("returns empty when node_modules is absent", () => {
    expect(walkInstalledNpmTree(root, "my-app")).toEqual([]);
  });

  it("respects the maxPackages cap", () => {
    for (let i = 0; i < 10; i++) plant(`node_modules/dep-${i}`, `dep-${i}`, "1.0.0");
    const tree = walkInstalledNpmTree(root, "my-app", 4);
    expect(tree.length).toBe(4);
  });
});

// ── probePublicNpmRegistry (issue #565) ─────────────────────────────────────

describe("probePublicNpmRegistry", () => {
  it("reports exists + latest + maintainers from a 200 response", async () => {
    const fetchImpl = vi.fn(async () =>
      new Response(
        JSON.stringify({
          "dist-tags": { latest: "3.2.1" },
          maintainers: [{ name: "alice" }, "bob"],
        }),
        { status: 200 },
      ),
    );
    const res = await probePublicNpmRegistry("@acme/widgets", { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(res.exists).toBe(true);
    expect(res.latestVersion).toBe("3.2.1");
    expect(res.maintainers).toEqual(["alice", "bob"]);
    // Scoped slash must be percent-encoded in the registry path.
    expect(fetchImpl.mock.calls[0][0]).toContain("@acme%2fwidgets");
  });

  it("reports exists:false on a 404", async () => {
    const fetchImpl = vi.fn(async () => new Response("not found", { status: 404 }));
    const res = await probePublicNpmRegistry("@acme/nope", { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(res.exists).toBe(false);
  });

  it("fails soft (exists:false) when fetch throws", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("offline");
    });
    const res = await probePublicNpmRegistry("@acme/widgets", { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(res.exists).toBe(false);
  });
});

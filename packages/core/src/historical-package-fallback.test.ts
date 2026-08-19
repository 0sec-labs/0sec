import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { restoreHistoricalPackageFixture, shouldUseHistoricalPackageFallback } from "./historical-package-fallback.js";
import { scanForMaliciousPatterns } from "./malicious-detector.js";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "pwnkit-historical-fixture-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0, tempDirs.length)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("historical package fallback", () => {
  it("recognizes npm 404 failures as fallback-eligible", () => {
    expect(shouldUseHistoricalPackageFallback("npm ERR! code E404")).toBe(true);
    expect(shouldUseHistoricalPackageFallback("Server responded 404 not found")).toBe(true);
    expect(shouldUseHistoricalPackageFallback("ERESOLVE unable to resolve dependency tree")).toBe(false);
  });

  it("restores the ngfm fixture into node_modules", () => {
    const tempDir = makeTempDir();
    const restored = restoreHistoricalPackageFixture("ngfm", tempDir);

    expect(restored).toBeTruthy();
    expect(restored?.version).toBe("1.0.0-historical-fixture");
    expect(existsSync(join(tempDir, "node_modules", "ngfm", "package.json"))).toBe(true);
    expect(readFileSync(join(tempDir, "node_modules", "ngfm", "preinstall.js"), "utf8")).toContain("NPM_TOKEN");
  });

  it("yields malicious install-hook findings for restored historical fixtures", () => {
    const tempDir = makeTempDir();
    const restored = restoreHistoricalPackageFixture("rocketrefer", tempDir);
    expect(restored).toBeTruthy();

    const findings = scanForMaliciousPatterns({
      packageName: "rocketrefer",
      packagePath: restored!.path,
    });

    expect(findings.some((finding) => finding.templateId === "malicious-install-hook")).toBe(true);
  });
});

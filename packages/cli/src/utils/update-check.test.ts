import { afterEach, describe, it, expect, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compareVersions, performAutoUpdate, shouldRunCheck } from "./update-check.js";

describe("compareVersions", () => {
  it("equal versions return 0", () => {
    expect(compareVersions("0.10.0", "0.10.0")).toBe(0);
    expect(compareVersions("v0.10.0", "0.10.0")).toBe(0);
  });

  it("major bump: 1.0.0 > 0.99.99", () => {
    expect(compareVersions("1.0.0", "0.99.99")).toBeGreaterThan(0);
  });

  it("minor bump: 0.10.0 > 0.9.0 (lexicographic trap)", () => {
    // The lexicographic-string trap that breaks naive `a > b` checks.
    expect(compareVersions("0.10.0", "0.9.0")).toBeGreaterThan(0);
    expect(compareVersions("0.9.0", "0.10.0")).toBeLessThan(0);
  });

  it("patch bump: 0.9.1 > 0.9.0", () => {
    expect(compareVersions("0.9.1", "0.9.0")).toBeGreaterThan(0);
  });

  it("strips leading v prefix from either side", () => {
    expect(compareVersions("v0.10.0", "v0.9.0")).toBeGreaterThan(0);
    expect(compareVersions("v0.10.0", "0.9.0")).toBeGreaterThan(0);
    expect(compareVersions("0.10.0", "v0.9.0")).toBeGreaterThan(0);
  });

  it("orders prereleases below stable and compares prerelease identifiers", () => {
    expect(compareVersions("0.10.0-rc.1", "0.10.0")).toBeLessThan(0);
    expect(compareVersions("0.10.0", "0.10.0-rc.1")).toBeGreaterThan(0);
    expect(compareVersions("0.10.0-rc.10", "0.10.0-rc.2")).toBeGreaterThan(0);
    expect(compareVersions("0.10.0+build.2", "0.10.0+build.1")).toBe(0);
  });

  it("missing patch defaults to 0", () => {
    expect(compareVersions("0.10", "0.10.0")).toBe(0);
    expect(compareVersions("1", "0.99.99")).toBeGreaterThan(0);
  });

  it("does not qualify malformed release versions as newer", () => {
    for (const invalid of ["999.abc.0", "999.0.0;curl", "", "latest", "999.0.0-01"]) {
      expect(compareVersions(invalid, "0.10.0")).toBe(0);
    }
  });

  it("compares multi-digit versions correctly", () => {
    expect(compareVersions("10.0.0", "9.99.99")).toBeGreaterThan(0);
    expect(compareVersions("0.100.0", "0.99.0")).toBeGreaterThan(0);
    expect(compareVersions("0.0.100", "0.0.99")).toBeGreaterThan(0);
  });

  it("compares v-prefixed tags against bare versions", () => {
    // GitHub release tags use "v0.10.0" format. The current version
    // string from VERSION is bare "0.10.0". This must compare correctly.
    expect(compareVersions("v0.10.0", "0.10.0")).toBe(0);
    expect(compareVersions("v0.11.0", "0.10.0")).toBeGreaterThan(0);
    expect(compareVersions("v0.9.0", "0.10.0")).toBeLessThan(0);
  });
});

describe("shouldRunCheck", () => {
  it("requires an explicit opt-in", () => {
    expect(shouldRunCheck({}, true)).toBe(false);
    expect(shouldRunCheck({ "0SEC_UPDATE_CHECK": "1" }, true)).toBe(true);
  });

  it("honors explicit privacy and CI disablement", () => {
    expect(shouldRunCheck({ "0SEC_UPDATE_CHECK": "1", "0SEC_NO_UPDATE_CHECK": "1" }, true)).toBe(false);
    expect(shouldRunCheck({ "0SEC_UPDATE_CHECK": "1", "0SEC_OFFLINE": "1" }, true)).toBe(false);
    expect(shouldRunCheck({ "0SEC_UPDATE_CHECK": "1", CI: "true" }, true)).toBe(false);
    expect(shouldRunCheck({ "0SEC_UPDATE_CHECK": "1" }, false)).toBe(false);
  });

  describe("with explicit policy", () => {
    it('policy "off" returns false regardless of env', () => {
      // Hard env gates beat policy too, but if those are clear, "off" wins.
      expect(shouldRunCheck({}, true, "off")).toBe(false);
      // Even with explicit opt-in env, "off" wins.
      expect(shouldRunCheck({ "0SEC_UPDATE_CHECK": "1" }, true, "off")).toBe(false);
    });

    it('policy "notify" returns true when no hard gate blocks', () => {
      expect(shouldRunCheck({}, true, "notify")).toBe(true);
      // notify does not require 0SEC_UPDATE_CHECK=1
    });

    it('policy "automatic" returns true when no hard gate blocks', () => {
      expect(shouldRunCheck({}, true, "automatic")).toBe(true);
    });

    it("hard env gates beat explicit policy", () => {
      // CI beats everything including "notify" and "automatic"
      expect(shouldRunCheck({ CI: "1" }, true, "notify")).toBe(false);
      expect(shouldRunCheck({ CI: "true" }, true, "automatic")).toBe(false);
      // NO_UPDATE_CHECK beats everything
      expect(shouldRunCheck({ "0SEC_NO_UPDATE_CHECK": "1" }, true, "notify")).toBe(false);
      expect(shouldRunCheck({ "0SEC_NO_UPDATE_CHECK": "1" }, true, "automatic")).toBe(false);
      // OFFLINE beats everything
      expect(shouldRunCheck({ "0SEC_OFFLINE": "1" }, true, "notify")).toBe(false);
      expect(shouldRunCheck({ "0SEC_OFFLINE": "1" }, true, "automatic")).toBe(false);
    });

    it("non-TTY beats explicit policy", () => {
      expect(shouldRunCheck({}, false, "notify")).toBe(false);
      expect(shouldRunCheck({}, false, "automatic")).toBe(false);
    });

    it("no policy + 0SEC_UPDATE_CHECK=1 is unchanged legacy behavior", () => {
      // When policy is undefined, 0SEC_UPDATE_CHECK=1 + TTY is the gate.
      expect(shouldRunCheck({ "0SEC_UPDATE_CHECK": "1" }, true)).toBe(true);
      expect(shouldRunCheck({}, true)).toBe(false);
    });
  });
});

describe.skipIf(process.platform === "win32")("installer pipeline", () => {
  let fixture: string | undefined;
  afterEach(() => {
    vi.unstubAllEnvs();
    if (fixture) rmSync(fixture, { recursive: true, force: true });
    fixture = undefined;
  });

  function fakeCurl(script: string): string {
    fixture = mkdtempSync(join(tmpdir(), "0sec-update-pipeline-"));
    writeFileSync(join(fixture, "curl"), `#!/bin/sh\n${script}\n`, { mode: 0o700 });
    vi.stubEnv("PATH", `${fixture}:/usr/bin:/bin`);
    vi.stubEnv("HOME", fixture);
    vi.stubEnv("BASH_ENV", "");
    vi.stubEnv("0SEC_OFFLINE", undefined);
    vi.stubEnv("0SEC_NO_UPDATE_CHECK", undefined);
    return fixture;
  }

  it("fails when the download fails even if the installer reads empty input", async () => {
    fakeCurl("exit 22");
    const result = await performAutoUpdate({ version: "v999.0.0" });
    expect(result.success).toBe(false);
    expect(result.installed).toBe(false);
    expect(result.exitCode).toBe(22);
  });

  it("pins the requested release and installation directory", async () => {
    const home = fakeCurl(`cat <<'INSTALL'
printf '%s\\n' "$RELEASE_BASE_URL" "$INSTALL_DIR" > "$PROBE_RECEIPT"
INSTALL`);
    const receipt = join(home, "receipt");
    vi.stubEnv("PROBE_RECEIPT", receipt);
    const destination = join(home, "custom bin");
    const result = await performAutoUpdate({ version: "999.1.2", installDir: destination });
    expect(result.success).toBe(true);
    expect(readFileSync(receipt, "utf8").split("\n")).toEqual([
      "https://github.com/0sec-labs/0sec/releases/download/v999.1.2", destination, "",
    ]);
  });
});
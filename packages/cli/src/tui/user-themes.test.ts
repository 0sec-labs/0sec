import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { THEMES, validateTheme, type Theme } from "./themes.js";
import { loadUserThemes, loadUserThemesForHome, userThemesDir } from "./user-themes.js";

const dirs: string[] = [];

function makeDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "0sec-user-themes-"));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  while (dirs.length > 0) {
    const dir = dirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

/** A complete, valid palette to build fixtures from. */
const GOOD: Theme = THEMES.midnight.palette;

function writeTheme(dir: string, file: string, body: unknown): void {
  writeFileSync(join(dir, file), JSON.stringify(body), "utf8");
}

describe("userThemesDir", () => {
  it("resolves under the per-user 0sec state dir (same as installed themes)", () => {
    expect(userThemesDir("/home/x")).toBe("/home/x/.0sec/themes");
  });
});

describe("loadUserThemes — total & fail-soft", () => {
  it("returns empty for a missing directory (never throws)", () => {
    expect(loadUserThemes(join(makeDir(), "does-not-exist"))).toEqual({
      valid: [],
      rejected: [],
    });
  });

  it("ignores non-.json files rather than rejecting them", () => {
    const dir = makeDir();
    writeFileSync(join(dir, "README.md"), "not a theme", "utf8");
    writeFileSync(join(dir, ".DS_Store"), "x", "utf8");
    expect(loadUserThemes(dir)).toEqual({ valid: [], rejected: [] });
  });
});

describe("loadUserThemes — accepts valid themes", () => {
  it("loads a complete, legible palette as a resolvable entry", () => {
    const dir = makeDir();
    writeTheme(dir, "acme.midnight.json", {
      label: "Acme Midnight",
      description: "A test theme",
      mode: "dark",
      palette: GOOD,
    });
    const { valid, rejected } = loadUserThemes(dir);
    expect(rejected).toEqual([]);
    expect(valid).toHaveLength(1);
    expect(valid[0]).toMatchObject({
      name: "acme.midnight",
      label: "Acme Midnight",
      description: "A test theme",
      mode: "dark",
      palette: GOOD,
    });
  });

  it("defaults label to the id and mode to dark when metadata is absent", () => {
    const dir = makeDir();
    writeTheme(dir, "bare.json", { palette: GOOD });
    const { valid } = loadUserThemes(dir);
    expect(valid[0]).toMatchObject({ name: "bare", label: "bare", mode: "dark" });
  });

  it("returns valid entries sorted by name (deterministic)", () => {
    const dir = makeDir();
    for (const id of ["zeta", "alpha", "mid"]) writeTheme(dir, `${id}.json`, { palette: GOOD });
    expect(loadUserThemes(dir).valid.map((e) => e.name)).toEqual(["alpha", "mid", "zeta"]);
  });
});

describe("loadUserThemes — rejects with a reason (never applies an unreadable theme)", () => {
  it("rejects a malformed (non-hex) token", () => {
    const dir = makeDir();
    writeTheme(dir, "badhex.json", { palette: { ...GOOD, BRAND: "purple" } });
    const { valid, rejected } = loadUserThemes(dir);
    expect(valid).toEqual([]);
    expect(rejected).toHaveLength(1);
    expect(rejected[0]!.name).toBe("badhex");
    expect(rejected[0]!.reason).toMatch(/BRAND/);
  });

  it("rejects a missing token", () => {
    const dir = makeDir();
    const { INFO, ...missing } = GOOD;
    void INFO;
    writeTheme(dir, "thin.json", { palette: missing });
    const { rejected } = loadUserThemes(dir);
    expect(rejected[0]!.reason).toMatch(/missing token INFO/);
  });

  it("rejects a low-contrast text token", () => {
    const dir = makeDir();
    // TEXT nearly the same as the dark CANVAS => well below 4.5:1.
    writeTheme(dir, "faint.json", { palette: { ...GOOD, TEXT: "#0B0F15" } });
    const { valid, rejected } = loadUserThemes(dir);
    expect(valid).toEqual([]);
    expect(rejected[0]!.reason).toMatch(/TEXT/);
    // The reason really is the validator's contrast finding.
    expect(rejected[0]!.reason).toMatch(/below 4\.5:1/);
  });

  it("rejects a file that is not valid JSON", () => {
    const dir = makeDir();
    writeFileSync(join(dir, "broken.json"), "{ not json", "utf8");
    const { rejected } = loadUserThemes(dir);
    expect(rejected[0]!.name).toBe("broken");
    expect(rejected[0]!.reason).toMatch(/could not read or parse/);
  });

  it("rejects a file whose top level is not an object", () => {
    const dir = makeDir();
    writeTheme(dir, "arr.json", [1, 2, 3]);
    const { rejected } = loadUserThemes(dir);
    expect(rejected[0]!.reason).toMatch(/not an object|not a JSON object/);
  });

  it("rejects an unsafe theme name (id) taken from the filename", () => {
    const dir = makeDir();
    // Capitalised leading char is not a safe id per THEME_ID_RE.
    writeTheme(dir, "BadName.json", { palette: GOOD });
    const { valid, rejected } = loadUserThemes(dir);
    expect(valid).toEqual([]);
    expect(rejected[0]!.name).toBe("BadName");
    expect(rejected[0]!.reason).toMatch(/invalid theme name/);
  });

  it("rejects a name that collides with a built-in (never shadows it)", () => {
    const dir = makeDir();
    writeTheme(dir, "dark.json", { palette: GOOD });
    const { valid, rejected } = loadUserThemes(dir);
    expect(valid).toEqual([]);
    expect(rejected[0]!.name).toBe("dark");
    expect(rejected[0]!.reason).toMatch(/built-in theme name/);
  });
});

describe("loadUserThemes — mixed directory", () => {
  it("separates the good from the bad in one pass", () => {
    const dir = makeDir();
    writeTheme(dir, "good.json", { palette: GOOD });
    writeTheme(dir, "badhex.json", { palette: { ...GOOD, ERROR: "nope" } });
    writeTheme(dir, "dark.json", { palette: GOOD }); // built-in collision
    const { valid, rejected } = loadUserThemes(dir);
    expect(valid.map((e) => e.name)).toEqual(["good"]);
    expect(rejected.map((r) => r.name).sort()).toEqual(["badhex", "dark"]);
  });

  it("every valid entry it returns passes validateTheme with no waivers", () => {
    const dir = makeDir();
    writeTheme(dir, "good.json", { palette: GOOD });
    for (const entry of loadUserThemes(dir).valid) {
      expect(validateTheme(entry.palette)).toEqual([]);
    }
  });
});

describe("loadUserThemesForHome", () => {
  it("reads the per-user themes dir under the given home", () => {
    const home = makeDir();
    const dir = userThemesDir(home);
    mkdirSync(dir, { recursive: true });
    writeTheme(dir, "acme.json", { palette: GOOD });
    expect(loadUserThemesForHome(home).valid.map((e) => e.name)).toEqual(["acme"]);
  });
});

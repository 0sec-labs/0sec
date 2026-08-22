import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  runConfigExport,
  runConfigImport,
  runConfigShow,
  type ConfigCommandDeps,
} from "../config.js";
import {
  DEFAULT_SETTINGS,
  loadGlobalSettings,
  readProjectOverrides,
  saveSettings,
} from "../../tui/settings.js";
import { __resetInstalledThemesForTests } from "../../tui/themes.js";

const temp: string[] = [];
function makeDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temp.push(dir);
  return dir;
}

type ImportDeps = ConfigCommandDeps & { scope?: "global" | "project"; yes?: boolean; global?: boolean };
function capture(): { deps: (extra?: Partial<ImportDeps>) => ImportDeps; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    deps: (extra = {}) => ({ out: (l) => out.push(l), err: (l) => err.push(l), ...extra }),
  };
}

beforeEach(() => {
  __resetInstalledThemesForTests();
  process.exitCode = 0;
});
afterEach(() => {
  __resetInstalledThemesForTests();
  process.exitCode = 0;
  while (temp.length > 0) {
    const dir = temp.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

describe("config show", () => {
  it("labels each key with its source layer", () => {
    const home = makeDir("cfg-home-");
    const project = makeDir("cfg-proj-");
    saveSettings({ ...DEFAULT_SETTINGS, showLogo: false }, home);
    writeFileSync(join(project, ".0sec-tmp"), ""); // placeholder to keep dir
    const cap = capture();
    runConfigShow(cap.deps({ homeDir: home, projectDir: project }));
    const text = cap.out.join("\n");
    expect(text).toContain("showLogo");
    expect(text).toContain("[global]");
    expect(process.exitCode).toBe(0);
  });
});

describe("config export", () => {
  it("writes the effective config to a file", () => {
    const home = makeDir("cfg-home-");
    const project = makeDir("cfg-proj-");
    saveSettings({ ...DEFAULT_SETTINGS, density: "compact" }, home);
    const file = join(makeDir("cfg-out-"), "cfg.json");
    const cap = capture();
    runConfigExport(file, cap.deps({ homeDir: home, projectDir: project }));
    const parsed = JSON.parse(readFileSync(file, "utf8"));
    expect(parsed.density).toBe("compact");
  });

  it("prints to stdout when no file is given", () => {
    const home = makeDir("cfg-home-");
    const cap = capture();
    runConfigExport(undefined, cap.deps({ homeDir: home, projectDir: makeDir("cfg-proj-") }));
    expect(cap.out.join("\n")).toContain('"theme"');
  });
});

describe("config import", () => {
  it("merges recognised keys into the global layer and reports changes", () => {
    const home = makeDir("cfg-home-");
    const project = makeDir("cfg-proj-");
    const file = join(makeDir("cfg-in-"), "shared.json");
    writeFileSync(file, JSON.stringify({ showLogo: false, density: "compact", bogusKey: 1 }));
    const cap = capture();

    runConfigImport(file, cap.deps({ homeDir: home, projectDir: project, scope: "global" }));
    expect(process.exitCode).toBe(0);
    expect(loadGlobalSettings(home).showLogo).toBe(false);
    expect(loadGlobalSettings(home).density).toBe("compact");
    expect(cap.out.join("\n")).toMatch(/Skipped unknown\/invalid keys: bogusKey/);
  });

  it("imports into the project layer with --project (sparse)", () => {
    const home = makeDir("cfg-home-");
    const project = makeDir("cfg-proj-");
    const file = join(makeDir("cfg-in-"), "shared.json");
    writeFileSync(file, JSON.stringify({ showLogo: false }));
    const cap = capture();

    runConfigImport(file, cap.deps({ homeDir: home, projectDir: project, scope: "project" }));
    expect(readProjectOverrides(project)).toEqual({ showLogo: false });
    expect(loadGlobalSettings(home).showLogo).toBe(DEFAULT_SETTINGS.showLogo);
  });

  it("accepts a config-artifact wrapper ({kind:'config', config:{…}})", () => {
    const home = makeDir("cfg-home-");
    const file = join(makeDir("cfg-in-"), "artifact.json");
    writeFileSync(file, JSON.stringify({ kind: "config", id: "x.y", config: { showStatusBar: false } }));
    const cap = capture();
    runConfigImport(file, cap.deps({ homeDir: home, projectDir: makeDir("cfg-proj-"), scope: "global" }));
    expect(loadGlobalSettings(home).showStatusBar).toBe(false);
  });

  it("REFUSES to flip a security setting without --yes", () => {
    const home = makeDir("cfg-home-");
    const project = makeDir("cfg-proj-");
    const file = join(makeDir("cfg-in-"), "danger.json");
    writeFileSync(file, JSON.stringify({ allowModelSelfExtension: true, showLogo: false }));
    const cap = capture();

    runConfigImport(file, cap.deps({ homeDir: home, projectDir: project, scope: "global", yes: false }));
    expect(process.exitCode).toBe(1);
    expect(cap.err.join("\n")).toMatch(/security-sensitive/);
    expect(cap.err.join("\n")).toMatch(/allowModelSelfExtension: off -> on/);
    // Nothing was written — not even the safe key.
    expect(loadGlobalSettings(home)).toEqual(DEFAULT_SETTINGS);
  });

  it("applies a security flip when --yes is passed and prints it", () => {
    const home = makeDir("cfg-home-");
    const file = join(makeDir("cfg-in-"), "danger.json");
    writeFileSync(file, JSON.stringify({ allowModelSelfExtension: true }));
    const cap = capture();

    runConfigImport(file, cap.deps({ homeDir: home, projectDir: makeDir("cfg-proj-"), scope: "global", yes: true }));
    expect(process.exitCode).toBe(0);
    expect(loadGlobalSettings(home).allowModelSelfExtension).toBe(true);
    expect(cap.out.join("\n")).toContain("allowModelSelfExtension: off -> on");
  });

  it("errors when the file has no recognised settings", () => {
    const file = join(makeDir("cfg-in-"), "junk.json");
    writeFileSync(file, JSON.stringify({ nope: 1 }));
    const cap = capture();
    runConfigImport(file, cap.deps({ homeDir: makeDir("cfg-home-"), projectDir: makeDir("cfg-proj-") }));
    expect(process.exitCode).toBe(1);
    expect(cap.err.join("\n")).toMatch(/no recognised settings/);
  });
});

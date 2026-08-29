import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  runThemeApply,
  runThemeExport,
  runThemeInstall,
  runThemeList,
  runThemeRemove,
  type ThemeCommandDeps,
  type ThemeCorePort,
} from "../theme.js";
import { THEMES, __resetInstalledThemesForTests, installedThemesDir } from "../../tui/themes.js";
import { loadSettings, readProjectOverrides } from "../../tui/settings.js";
import { __resetSettingsStoreForTests } from "../../tui/settings-store.js";

const temp: string[] = [];
function makeDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temp.push(dir);
  return dir;
}

function capture(): { out: string[]; err: string[]; deps: (extra?: Partial<ThemeCommandDeps>) => ThemeCommandDeps } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    deps: (extra = {}) => ({ out: (l) => out.push(l), err: (l) => err.push(l), ...extra }),
  };
}

/** A fake core port that serves one theme artifact from a "registry". */
function fakeCore(palette: Record<string, string> = { ...THEMES.midnight.palette }): ThemeCorePort {
  return {
    DEFAULT_REGISTRY_URL: "",
    unconfiguredVerifier: { keyConfigured: false, verify: () => false },
    async fetchRegistryIndex() {
      return {
        ok: true,
        result: {
          entries: [],
          artifacts: [
            {
              kind: "theme",
              id: "acme.midnight",
              version: "2.0.0",
              manifest: {
                kind: "theme",
                id: "acme.midnight",
                name: "Acme Midnight",
                version: "2.0.0",
                theme: { label: "Midnight", description: "Deep blue-black.", mode: "dark", palette },
              },
              signatureState: "unverified",
            },
          ],
          dropped: [],
        },
      };
    },
  };
}

beforeEach(() => {
  __resetInstalledThemesForTests();
  __resetSettingsStoreForTests();
  process.exitCode = 0;
});
afterEach(() => {
  __resetInstalledThemesForTests();
  __resetSettingsStoreForTests();
  process.exitCode = 0;
  while (temp.length > 0) {
    const dir = temp.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

describe("theme list", () => {
  it("lists built-ins and marks the default + active", () => {
    const home = makeDir("th-home-");
    const cap = capture();
    runThemeList(cap.deps({ homeDir: home, projectDir: makeDir("th-proj-") }));
    const text = cap.out.join("\n");
    expect(text).toContain("dark");
    expect(text).toMatch(/midnight.*(active|default)/);
  });
});

describe("theme install", () => {
  it("refuses when no registry is configured", async () => {
    const cap = capture();
    await runThemeInstall("acme.midnight", cap.deps({ homeDir: makeDir("th-home-"), core: fakeCore(), registryUrl: "" }));
    expect(process.exitCode).toBe(1);
    expect(cap.err.join("\n")).toMatch(/No registry is configured/);
  });

  it("fetches, validates and writes a theme, then it is installable", async () => {
    const home = makeDir("th-home-");
    const cap = capture();
    await runThemeInstall(
      "acme.midnight",
      cap.deps({ homeDir: home, registryUrl: "https://themes.example/index.json", core: fakeCore() }),
    );
    expect(process.exitCode).toBe(0);
    const written = JSON.parse(readFileSync(join(installedThemesDir(home), "acme.midnight.json"), "utf8"));
    expect(written.id).toBe("acme.midnight");
    expect(written.palette.CANVAS).toBe(THEMES.midnight.palette.CANVAS);
  });

  it("fails closed on an invalid palette (contrast/completeness enforced at install)", async () => {
    const home = makeDir("th-home-");
    const cap = capture();
    await runThemeInstall(
      "acme.midnight",
      cap.deps({ homeDir: home, registryUrl: "https://x/i.json", core: fakeCore({ CANVAS: "#000000" }) }),
    );
    expect(process.exitCode).toBe(1);
    expect(cap.err.join("\n")).toMatch(/invalid palette/);
  });
});

describe("theme apply", () => {
  it("applies a built-in theme by persisting the setting", () => {
    const home = makeDir("th-home-");
    const project = makeDir("th-proj-");
    const cap = capture();
    runThemeApply("slate", cap.deps({ homeDir: home, projectDir: project }));
    expect(process.exitCode).toBe(0);
    expect(loadSettings(home, project).theme).toBe("slate");
  });

  it("applies an INSTALLED theme and it survives normalize (not reset to default)", async () => {
    const home = makeDir("th-home-");
    const project = makeDir("th-proj-");
    await runThemeInstall(
      "acme.midnight",
      capture().deps({ homeDir: home, registryUrl: "https://x/i.json", core: fakeCore() }),
    );
    const cap = capture();
    runThemeApply("acme.midnight", cap.deps({ homeDir: home, projectDir: project }));
    expect(process.exitCode).toBe(0);
    expect(loadSettings(home, project).theme).toBe("acme.midnight");
  });

  it("writes to the project layer with scope:project", () => {
    const home = makeDir("th-home-");
    const project = makeDir("th-proj-");
    runThemeApply("slate", capture().deps({ homeDir: home, projectDir: project, scope: "project" }));
    expect(readProjectOverrides(project)).toEqual({ theme: "slate" });
  });

  it("refuses an unknown theme id", () => {
    const cap = capture();
    runThemeApply("no-such-theme", cap.deps({ homeDir: makeDir("th-home-"), projectDir: makeDir("th-proj-") }));
    expect(process.exitCode).toBe(1);
    expect(cap.err.join("\n")).toMatch(/not a known theme/);
  });
});

describe("theme export", () => {
  it("emits a built-in theme as a theme manifest", () => {
    const cap = capture();
    runThemeExport("dark", undefined, cap.deps({ homeDir: makeDir("th-home-") }));
    const manifest = JSON.parse(cap.out.join("\n"));
    expect(manifest.kind).toBe("theme");
    expect(manifest.id).toBe("dark");
    expect(manifest.theme.palette.CANVAS).toBe(THEMES.dark.palette.CANVAS);
  });

  it("writes to a file when given one", () => {
    const file = join(makeDir("th-out-"), "theme.json");
    runThemeExport("slate", file, capture().deps({ homeDir: makeDir("th-home-") }));
    expect(JSON.parse(readFileSync(file, "utf8")).id).toBe("slate");
  });
});

describe("theme remove", () => {
  it("removes an installed theme", async () => {
    const home = makeDir("th-home-");
    await runThemeInstall(
      "acme.midnight",
      capture().deps({ homeDir: home, registryUrl: "https://x/i.json", core: fakeCore() }),
    );
    const cap = capture();
    runThemeRemove("acme.midnight", cap.deps({ homeDir: home }));
    expect(process.exitCode).toBe(0);
    expect(cap.out.join("\n")).toMatch(/Removed installed theme/);
  });
});

import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  DEFAULT_SETTINGS,
  SETTING_DEFS,
  describeSetting,
  loadSettings,
  normalizeSettings,
  saveSettings,
  settingsFilePath,
  toggleSetting,
  type SettingDef,
  type TuiSettings,
} from "./settings.js";

/** Temp homes created by a test, torn down after it regardless of outcome. */
const tempHomes: string[] = [];

function makeHome(): string {
  const dir = mkdtempSync(join(tmpdir(), "0sec-tui-settings-"));
  tempHomes.push(dir);
  return dir;
}

afterEach(() => {
  while (tempHomes.length > 0) {
    const dir = tempHomes.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

describe("settingsFilePath", () => {
  it("places the file inside the shared 0sec state directory", () => {
    expect(settingsFilePath("/home/someone")).toBe("/home/someone/.0sec/tui-settings.json");
  });

  it("defaults the home directory when none is given", () => {
    expect(settingsFilePath().endsWith(join(".0sec", "tui-settings.json"))).toBe(true);
  });
});

describe("normalizeSettings", () => {
  // The file on disk is user-editable, so "anything at all" is a realistic
  // input, not a hypothetical: each of these must produce a usable object.
  it.each([
    ["null", null],
    ["undefined", undefined],
    ["a number", 42],
    ["a string", "string"],
    ["an array", []],
    ["an empty object", {}],
    ["a boolean", true],
    ["a nested object with no known keys", { nope: { deep: 1 } }],
  ])("returns the full defaults for %s", (_label, raw) => {
    expect(normalizeSettings(raw)).toEqual(DEFAULT_SETTINGS);
  });

  it("falls back per key when every value has the wrong type", () => {
    const raw = {
      showStatusBar: "yes",
      showComposerHints: 1,
      showLogo: null,
      showRuntimeNotices: [],
      showTurnSummary: {},
      showSubagents: "false",
      showTimestamps: 0,
      density: true,
      composerStyle: 7,
    };

    expect(normalizeSettings(raw)).toEqual(DEFAULT_SETTINGS);
  });

  it("drops unknown keys instead of carrying them forward", () => {
    const normalized = normalizeSettings({
      showStatusBar: false,
      legacyShowFooter: true,
      showstatusbar: true,
      __proto__marker: "x",
    });

    expect(normalized).toEqual({ ...DEFAULT_SETTINGS, showStatusBar: false });
    expect(Object.keys(normalized).sort()).toEqual(Object.keys(DEFAULT_SETTINGS).sort());
  });

  it("keeps supplied values and defaults only the missing ones", () => {
    const normalized = normalizeSettings({
      showLogo: false,
      showTimestamps: true,
      density: "compact",
    });

    expect(normalized.showLogo).toBe(false);
    expect(normalized.showTimestamps).toBe(true);
    expect(normalized.density).toBe("compact");
    // Everything not mentioned above must be untouched.
    expect(normalized.showStatusBar).toBe(DEFAULT_SETTINGS.showStatusBar);
    expect(normalized.showComposerHints).toBe(DEFAULT_SETTINGS.showComposerHints);
    expect(normalized.showRuntimeNotices).toBe(DEFAULT_SETTINGS.showRuntimeNotices);
    expect(normalized.showTurnSummary).toBe(DEFAULT_SETTINGS.showTurnSummary);
    expect(normalized.showSubagents).toBe(DEFAULT_SETTINGS.showSubagents);
    expect(normalized.composerStyle).toBe(DEFAULT_SETTINGS.composerStyle);
  });

  it("rejects an enum value outside its choices", () => {
    const normalized = normalizeSettings({ density: "cosy", composerStyle: "double-line" });

    expect(normalized.density).toBe(DEFAULT_SETTINGS.density);
    expect(normalized.composerStyle).toBe(DEFAULT_SETTINGS.composerStyle);
  });

  it("defaults transcriptDetail to expanded and honours a valid override", () => {
    expect(DEFAULT_SETTINGS.transcriptDetail).toBe("expanded");
    expect(normalizeSettings({}).transcriptDetail).toBe("expanded");
    expect(normalizeSettings({ transcriptDetail: "collapsed" }).transcriptDetail).toBe("collapsed");
    // A bogus value degrades to the default rather than crashing.
    expect(normalizeSettings({ transcriptDetail: "folded" }).transcriptDetail).toBe("expanded");
  });

  it("accepts every declared choice for every enum setting", () => {
    for (const def of SETTING_DEFS) {
      if (def.kind !== "enum") continue;
      for (const choice of def.choices ?? []) {
        const normalized = normalizeSettings({ [def.key]: choice }) as unknown as Record<
          string,
          unknown
        >;
        expect(normalized[def.key]).toBe(choice);
      }
    }
  });

  it("does not mutate its input", () => {
    const raw = { showStatusBar: false, density: "bogus", extra: 1 };
    const snapshot = JSON.parse(JSON.stringify(raw));

    normalizeSettings(raw);

    expect(raw).toEqual(snapshot);
  });

  it("returns a fresh object rather than DEFAULT_SETTINGS itself", () => {
    const normalized = normalizeSettings(null);

    expect(normalized).not.toBe(DEFAULT_SETTINGS);
    normalized.showStatusBar = !normalized.showStatusBar;
    expect(DEFAULT_SETTINGS.showStatusBar).toBe(true);
  });
});

describe("loadSettings / saveSettings", () => {
  it("round-trips a settings object through the file", () => {
    const home = makeHome();
    const settings: TuiSettings = {
      ...DEFAULT_SETTINGS,
      showStatusBar: false,
      showTimestamps: true,
      density: "compact",
      composerStyle: "plain",
    };

    expect(saveSettings(settings, home)).toBe(true);
    expect(loadSettings(home)).toEqual(settings);
  });

  it("writes pretty-printed JSON with a trailing newline", () => {
    const home = makeHome();

    saveSettings(DEFAULT_SETTINGS, home);
    const text = readText(settingsFilePath(home));

    expect(text.endsWith("}\n")).toBe(true);
    expect(text).toContain('\n  "showStatusBar": true,');
  });

  it("creates the state directory when it does not exist yet", () => {
    const home = join(makeHome(), "nested", "home");

    expect(saveSettings(DEFAULT_SETTINGS, home)).toBe(true);
    expect(loadSettings(home)).toEqual(DEFAULT_SETTINGS);
  });

  it("returns defaults, without throwing, when nothing has been saved", () => {
    const home = join(makeHome(), "never-created");

    expect(() => loadSettings(home)).not.toThrow();
    expect(loadSettings(home)).toEqual(DEFAULT_SETTINGS);
  });

  it("returns defaults, without throwing, on invalid JSON", () => {
    const home = makeHome();
    mkdirSync(join(home, ".0sec"), { recursive: true });
    writeFileSync(settingsFilePath(home), "{ this is not json, ", "utf8");

    expect(() => loadSettings(home)).not.toThrow();
    expect(loadSettings(home)).toEqual(DEFAULT_SETTINGS);
  });

  it("returns defaults when the file holds valid JSON of the wrong shape", () => {
    const home = makeHome();
    mkdirSync(join(home, ".0sec"), { recursive: true });
    writeFileSync(settingsFilePath(home), '["showStatusBar"]', "utf8");

    expect(loadSettings(home)).toEqual(DEFAULT_SETTINGS);
  });

  it("returns false instead of throwing when the path cannot be created", () => {
    // A regular file standing where a parent directory would have to be makes
    // mkdir fail with ENOTDIR — the cheap, portable stand-in for a home the
    // process may not write to.
    const blocker = join(makeHome(), "not-a-directory");
    writeFileSync(blocker, "occupied", "utf8");
    const home = join(blocker, "home");

    expect(() => saveSettings(DEFAULT_SETTINGS, home)).not.toThrow();
    expect(saveSettings(DEFAULT_SETTINGS, home)).toBe(false);
  });

  it("normalises on the way out, so a corrupt in-memory object cannot be persisted", () => {
    const home = makeHome();
    const corrupt = { showStatusBar: "nope", density: "cosy", stray: 1 } as unknown as TuiSettings;

    expect(saveSettings(corrupt, home)).toBe(true);
    expect(loadSettings(home)).toEqual(DEFAULT_SETTINGS);
    expect(readText(settingsFilePath(home))).not.toContain("stray");
  });
});

describe("toggleSetting", () => {
  it("flips a boolean setting", () => {
    const on = { ...DEFAULT_SETTINGS, showStatusBar: true };

    const off = toggleSetting(on, "showStatusBar");
    expect(off.showStatusBar).toBe(false);
    expect(toggleSetting(off, "showStatusBar").showStatusBar).toBe(true);
  });

  it("leaves the other settings alone when flipping one", () => {
    const next = toggleSetting(DEFAULT_SETTINGS, "showLogo");

    expect({ ...next, showLogo: DEFAULT_SETTINGS.showLogo }).toEqual(DEFAULT_SETTINGS);
  });

  it("cycles a two-value enum and wraps", () => {
    const a = toggleSetting(DEFAULT_SETTINGS, "density");
    expect(a.density).toBe("compact");

    const b = toggleSetting(a, "density");
    expect(b.density).toBe("comfortable");
  });

  it("cycles a three-value enum and wraps", () => {
    const one = toggleSetting(DEFAULT_SETTINGS, "composerStyle");
    const two = toggleSetting(one, "composerStyle");
    const three = toggleSetting(two, "composerStyle");

    expect([one.composerStyle, two.composerStyle, three.composerStyle]).toEqual([
      "rail",
      "plain",
      "border",
    ]);
  });

  it("returns the input unchanged for an unknown key", () => {
    expect(toggleSetting(DEFAULT_SETTINGS, "showFooter")).toBe(DEFAULT_SETTINGS);
    expect(toggleSetting(DEFAULT_SETTINGS, "")).toBe(DEFAULT_SETTINGS);
    expect(toggleSetting(DEFAULT_SETTINGS, "toString")).toBe(DEFAULT_SETTINGS);
  });

  it("repairs an enum value that is not in the choice list", () => {
    const corrupt = { ...DEFAULT_SETTINGS, composerStyle: "neon" as TuiSettings["composerStyle"] };

    expect(toggleSetting(corrupt, "composerStyle").composerStyle).toBe("border");
  });

  it("does not mutate its input", () => {
    const before = { ...DEFAULT_SETTINGS };
    const snapshot = { ...before };

    toggleSetting(before, "showStatusBar");
    toggleSetting(before, "density");

    expect(before).toEqual(snapshot);
  });

  it("returns every setting to its starting value after a full cycle", () => {
    for (const def of SETTING_DEFS) {
      const steps = def.kind === "boolean" ? 2 : (def.choices?.length ?? 0);
      let settings = DEFAULT_SETTINGS;
      for (let i = 0; i < steps; i += 1) settings = toggleSetting(settings, def.key);

      expect(settings).toEqual(DEFAULT_SETTINGS);
    }
  });
});

describe("describeSetting", () => {
  it("renders booleans as on/off with the label and description", () => {
    const text = describeSetting(DEFAULT_SETTINGS, "showStatusBar");

    expect(text).toContain("Status bar");
    expect(text).toContain("on");
    expect(describeSetting({ ...DEFAULT_SETTINGS, showStatusBar: false }, "showStatusBar")).toContain(
      "off",
    );
  });

  it("renders the current enum value", () => {
    expect(describeSetting({ ...DEFAULT_SETTINGS, density: "compact" }, "density")).toContain(
      "compact",
    );
  });

  it("returns an empty string for an unknown key rather than throwing", () => {
    expect(describeSetting(DEFAULT_SETTINGS, "nope")).toBe("");
  });

  it("produces a single line for every declared setting", () => {
    for (const def of SETTING_DEFS) {
      const text = describeSetting(DEFAULT_SETTINGS, def.key);
      expect(text.length).toBeGreaterThan(0);
      expect(text).not.toContain("\n");
    }
  });
});

describe("subagent messaging settings", () => {
  // These two are the only settings that gate a security boundary rather than
  // chrome, so they get their own assertions: the shipped default, the group
  // they surface under, and a description an operator can act on.
  const CHANNEL_KEYS = ["allowSubagentPeerMessaging", "allowSubagentOperatorMessaging"] as const;

  it("ships both subagent messaging channels ON", () => {
    for (const key of CHANNEL_KEYS) {
      expect(DEFAULT_SETTINGS[key]).toBe(true);
    }
  });

  it("files both channels under Security", () => {
    for (const key of CHANNEL_KEYS) {
      const def = SETTING_DEFS.find((d) => d.key === key);
      expect(def?.group).toBe("Security");
      expect(def?.kind).toBe("boolean");
    }
  });

  it("describes the concrete risk in one sentence instead of hedging", () => {
    for (const def of SETTING_DEFS.filter((d) => d.group === "Security")) {
      // "may be unsafe" tells an operator nothing they can act on.
      expect(def.description).not.toMatch(/may be unsafe|potentially unsafe|use with caution|be careful/i);
      expect(def.description.trim().endsWith(".")).toBe(true);
      // One sentence: no interior sentence break.
      expect(def.description.trim().slice(0, -1)).not.toMatch(/[.!?]\s/);
    }
  });

  it("toggles each channel off and back on", () => {
    for (const key of CHANNEL_KEYS) {
      const off = toggleSetting(DEFAULT_SETTINGS, key);
      expect(off[key]).toBe(false);
      expect(toggleSetting(off, key)[key]).toBe(true);
    }
  });

  it("round-trips a disabled channel through save and load", () => {
    const home = makeHome();
    const disabled: TuiSettings = {
      ...DEFAULT_SETTINGS,
      allowSubagentPeerMessaging: false,
      allowSubagentOperatorMessaging: false,
    };

    expect(saveSettings(disabled, home)).toBe(true);
    const loaded = loadSettings(home);
    expect(loaded.allowSubagentPeerMessaging).toBe(false);
    expect(loaded.allowSubagentOperatorMessaging).toBe(false);
  });
});

describe("sidebar settings", () => {
  it("both ship OFF by default", () => {
    expect(DEFAULT_SETTINGS.showRightSidebar).toBe(false);
    expect(DEFAULT_SETTINGS.showLeftSidebar).toBe(false);
  });

  it("are Display booleans", () => {
    for (const key of ["showRightSidebar", "showLeftSidebar"] as const) {
      const def = SETTING_DEFS.find((d) => d.key === key);
      expect(def?.group).toBe("Display");
      expect(def?.kind).toBe("boolean");
    }
  });

  it("toggle on and back off", () => {
    const on = toggleSetting(DEFAULT_SETTINGS, "showRightSidebar");
    expect(on.showRightSidebar).toBe(true);
    expect(toggleSetting(on, "showRightSidebar").showRightSidebar).toBe(false);

    const left = toggleSetting(DEFAULT_SETTINGS, "showLeftSidebar");
    expect(left.showLeftSidebar).toBe(true);
    expect(toggleSetting(left, "showLeftSidebar").showLeftSidebar).toBe(false);
  });

  it("round-trip an enabled sidebar through save and load", () => {
    const home = makeHome();
    expect(
      saveSettings(
        { ...DEFAULT_SETTINGS, showRightSidebar: true, showLeftSidebar: true },
        home,
      ),
    ).toBe(true);
    expect(loadSettings(home).showRightSidebar).toBe(true);
    expect(loadSettings(home).showLeftSidebar).toBe(true);
  });

  it("honours the legacy `showAgentRail` key on load", () => {
    // A file written before the rename carries only `showAgentRail`.
    expect(normalizeSettings({ showAgentRail: true }).showRightSidebar).toBe(true);
    // The new key wins when both are present.
    expect(
      normalizeSettings({ showAgentRail: true, showRightSidebar: false }).showRightSidebar,
    ).toBe(false);
  });
});

describe("telemetry settings", () => {
  // The four telemetry knobs ship OFF/neutral by default: token counts, cost
  // and a context meter are noise until an operator asks for them, and the model
  // stays in the status bar (its established home) rather than moving.
  const OFF_BY_DEFAULT = ["showTokenUsage", "showCost", "showContextMeter"] as const;

  it("ships the token/cost/meter toggles OFF", () => {
    for (const key of OFF_BY_DEFAULT) {
      expect(DEFAULT_SETTINGS[key]).toBe(false);
    }
  });

  it("defaults modelDisplay to the status bar", () => {
    expect(DEFAULT_SETTINGS.modelDisplay).toBe("statusbar");
  });

  it("files every telemetry setting under Telemetry", () => {
    for (const key of [...OFF_BY_DEFAULT, "modelDisplay"] as const) {
      expect(SETTING_DEFS.find((d) => d.key === key)?.group).toBe("Telemetry");
    }
  });

  it("offers modelDisplay exactly statusbar / message / off", () => {
    const def = SETTING_DEFS.find((d) => d.key === "modelDisplay");
    expect(def?.kind).toBe("enum");
    expect(def?.choices).toEqual(["statusbar", "message", "off"]);
  });

  it("cycles modelDisplay through its three values and wraps", () => {
    const one = toggleSetting(DEFAULT_SETTINGS, "modelDisplay");
    const two = toggleSetting(one, "modelDisplay");
    const three = toggleSetting(two, "modelDisplay");
    expect([one.modelDisplay, two.modelDisplay, three.modelDisplay]).toEqual([
      "message",
      "off",
      "statusbar",
    ]);
  });

  it("round-trips the telemetry settings through save and load", () => {
    const home = makeHome();
    const on: TuiSettings = {
      ...DEFAULT_SETTINGS,
      showTokenUsage: true,
      showCost: true,
      showContextMeter: true,
      modelDisplay: "message",
    };
    expect(saveSettings(on, home)).toBe(true);
    expect(loadSettings(home)).toEqual(on);
  });

  it("rejects an out-of-range modelDisplay value", () => {
    expect(normalizeSettings({ modelDisplay: "sidebar" }).modelDisplay).toBe("statusbar");
  });
});

describe("header display settings", () => {
  // The two header segments (target/scope) ship ON and live under Display; the
  // chat-screen header gates each segment on its flag.
  const HEADER_KEYS = ["showTarget", "showScope"] as const;

  it("ships both header segments ON", () => {
    for (const key of HEADER_KEYS) {
      expect(DEFAULT_SETTINGS[key]).toBe(true);
    }
  });

  it("files both header segments under Display as booleans", () => {
    for (const key of HEADER_KEYS) {
      const def = SETTING_DEFS.find((d) => d.key === key);
      expect(def?.group).toBe("Display");
      expect(def?.kind).toBe("boolean");
    }
  });

  it("toggles each header segment off and back on", () => {
    for (const key of HEADER_KEYS) {
      const off = toggleSetting(DEFAULT_SETTINGS, key);
      expect(off[key]).toBe(false);
      expect(toggleSetting(off, key)[key]).toBe(true);
    }
  });

  it("round-trips the header segments through save and load", () => {
    const home = makeHome();
    const hidden: TuiSettings = { ...DEFAULT_SETTINGS, showTarget: false, showScope: false };
    expect(saveSettings(hidden, home)).toBe(true);
    const loaded = loadSettings(home);
    expect(loaded.showTarget).toBe(false);
    expect(loaded.showScope).toBe(false);
  });
});

describe("motion settings", () => {
  const MOTION_KEYS = ["logoAnimation", "reduceMotion"] as const;

  it("files both motion knobs under Motion", () => {
    for (const key of MOTION_KEYS) {
      expect(SETTING_DEFS.find((d) => d.key === key)?.group).toBe("Motion");
    }
  });

  it("defaults logoAnimation to glitch (its first choice) and reduceMotion off", () => {
    expect(DEFAULT_SETTINGS.logoAnimation).toBe("glitch");
    expect(DEFAULT_SETTINGS.reduceMotion).toBe(false);
  });

  it("offers logoAnimation the full style list, glitch first and off last", () => {
    const def = SETTING_DEFS.find((d) => d.key === "logoAnimation");
    expect(def?.kind).toBe("enum");
    expect(def?.choices).toEqual([
      "glitch",
      "rainbow",
      "matrix",
      "wave",
      "neon",
      "shimmer",
      "pulse",
      "strike",
      "draw",
      "fade",
      "typein",
      "sweep",
      "swiss",
      "off",
    ]);
  });

  it("cycles logoAnimation through every value and wraps back to glitch", () => {
    const def = SETTING_DEFS.find((d) => d.key === "logoAnimation");
    const choices = def?.choices ?? [];
    let s = DEFAULT_SETTINGS;
    const seen: string[] = [];
    for (let i = 0; i < choices.length; i += 1) {
      s = toggleSetting(s, "logoAnimation");
      seen.push(s.logoAnimation);
    }
    // One full lap: the choices after the head, then the head again.
    expect(seen).toEqual([...choices.slice(1), choices[0]]);
    expect(seen[seen.length - 1]).toBe("glitch");
  });

  it("rejects an out-of-range logoAnimation value", () => {
    expect(normalizeSettings({ logoAnimation: "slide" }).logoAnimation).toBe("glitch");
  });

  it("round-trips the motion settings through save and load", () => {
    const home = makeHome();
    const on: TuiSettings = { ...DEFAULT_SETTINGS, logoAnimation: "shimmer", reduceMotion: true };
    expect(saveSettings(on, home)).toBe(true);
    expect(loadSettings(home)).toEqual(on);
  });
});

describe("SETTING_DEFS", () => {
  // The table and the interface are two halves of one declaration; nothing but
  // a test stops a new field from being added to `TuiSettings` without a def
  // (invisible in the settings UI) or a def from outliving its field.
  it("has one def per TuiSettings field", () => {
    const defKeys = SETTING_DEFS.map((def) => def.key).sort();
    const fieldKeys = Object.keys(DEFAULT_SETTINGS).sort();

    expect(defKeys).toEqual(fieldKeys);
  });

  it("has a field for every def", () => {
    for (const def of SETTING_DEFS) {
      expect(Object.prototype.hasOwnProperty.call(DEFAULT_SETTINGS, def.key)).toBe(true);
    }
  });

  it("has a def for every field", () => {
    const defKeys = new Set(SETTING_DEFS.map((def) => def.key));

    for (const key of Object.keys(DEFAULT_SETTINGS)) {
      expect(defKeys.has(key)).toBe(true);
    }
  });

  it("declares each key exactly once", () => {
    const keys = SETTING_DEFS.map((def) => def.key);

    expect(new Set(keys).size).toBe(keys.length);
  });

  it("agrees with DEFAULT_SETTINGS on every default value", () => {
    const defaults = DEFAULT_SETTINGS as unknown as Record<string, unknown>;

    for (const def of SETTING_DEFS) {
      expect(def.default).toEqual(defaults[def.key]);
    }
  });

  it("gives every def a label, description and group", () => {
    for (const def of SETTING_DEFS) {
      expect(def.label.length).toBeGreaterThan(0);
      expect(def.description.length).toBeGreaterThan(0);
      expect(def.group.length).toBeGreaterThan(0);
    }
  });

  it("gives enums at least two choices including their default, and booleans none", () => {
    for (const def of SETTING_DEFS as readonly SettingDef[]) {
      if (def.kind === "enum") {
        expect(def.choices?.length ?? 0).toBeGreaterThanOrEqual(2);
        expect(def.choices).toContain(def.default);
        expect(typeof def.default).toBe("string");
      } else {
        expect(def.choices).toBeUndefined();
        expect(typeof def.default).toBe("boolean");
      }
    }
  });

  it("makes every enum's default its first choice", () => {
    // toggleSetting cycles from choices[0], and the settings UI leans on the
    // default being the head of the list; keep that invariant explicit.
    for (const def of SETTING_DEFS as readonly SettingDef[]) {
      if (def.kind !== "enum") continue;
      expect(def.choices?.[0]).toBe(def.default);
    }
  });
});

/** Reads back a file the tests just wrote. */
function readText(path: string): string {
  return readFileSync(path, "utf8");
}

// ── Two-level configuration (global + project override) ───────────────────────

import { mkdtempSync as mkdtempSync2 } from "node:fs";
import {
  loadGlobalSettings,
  loadLayeredSettings,
  projectSettingsExist,
  projectSettingsFilePath,
  readProjectOverrides,
  resolveLayeredSettings,
  sanitizeOverrides,
  saveProjectOverrides,
} from "./settings.js";
import {
  __resetInstalledThemesForTests,
  reloadInstalledThemes,
  writeInstalledTheme,
} from "./themes.js";

function makeProjectDir(): string {
  const dir = mkdtempSync2(join(tmpdir(), "0sec-project-"));
  tempHomes.push(dir);
  return dir;
}

function writeGlobalFull(home: string, settings: TuiSettings): void {
  saveSettings(settings, home);
}
function writeProjectRaw(projectDir: string, raw: unknown): void {
  const path = projectSettingsFilePath(projectDir);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, typeof raw === "string" ? raw : JSON.stringify(raw), "utf8");
}

// dirname is needed above.
import { dirname } from "node:path";

describe("two-level layering", () => {
  it("global-only: every key comes from the global file", () => {
    const home = makeHome();
    const project = makeProjectDir();
    writeGlobalFull(home, { ...DEFAULT_SETTINGS, showLogo: false, density: "compact" });

    const { settings, sources } = loadLayeredSettings({ homeDir: home, projectDir: project });
    expect(settings.showLogo).toBe(false);
    expect(settings.density).toBe("compact");
    expect(sources.showLogo).toBe("global");
    expect(sources.showTimestamps).toBe("global"); // present in the full global file
  });

  it("project overrides global per key; unset keys fall through", () => {
    const home = makeHome();
    const project = makeProjectDir();
    writeGlobalFull(home, { ...DEFAULT_SETTINGS, showLogo: false, showStatusBar: false });
    writeProjectRaw(project, { showLogo: true, density: "compact" });

    const { settings, sources } = loadLayeredSettings({ homeDir: home, projectDir: project });
    expect(settings.showLogo).toBe(true); // project wins
    expect(sources.showLogo).toBe("project");
    expect(settings.density).toBe("compact");
    expect(sources.density).toBe("project");
    expect(settings.showStatusBar).toBe(false); // falls through to global
    expect(sources.showStatusBar).toBe("global");
  });

  it("corrupt project file falls through to global entirely", () => {
    const home = makeHome();
    const project = makeProjectDir();
    writeGlobalFull(home, { ...DEFAULT_SETTINGS, showLogo: false });
    writeProjectRaw(project, "{ not json ,,");

    const { settings, sources } = loadLayeredSettings({ homeDir: home, projectDir: project });
    expect(settings.showLogo).toBe(false);
    expect(sources.showLogo).toBe("global");
  });

  it("an invalid project value for one key falls through, not to default", () => {
    const home = makeHome();
    const project = makeProjectDir();
    writeGlobalFull(home, { ...DEFAULT_SETTINGS, density: "compact" });
    writeProjectRaw(project, { density: "cosy" }); // invalid enum

    const { settings, sources } = loadLayeredSettings({ homeDir: home, projectDir: project });
    expect(settings.density).toBe("compact"); // global, not the default
    expect(sources.density).toBe("global");
  });

  it("defaults win when neither layer has a valid key", () => {
    const home = join(makeHome(), "empty");
    const project = makeProjectDir();
    const { settings, sources } = loadLayeredSettings({ homeDir: home, projectDir: project });
    expect(settings).toEqual(DEFAULT_SETTINGS);
    for (const key of Object.keys(DEFAULT_SETTINGS)) {
      expect(sources[key as keyof TuiSettings]).toBe("default");
    }
  });

  it("resolveLayeredSettings is pure and total on garbage layers", () => {
    expect(() => resolveLayeredSettings(null, 42)).not.toThrow();
    expect(resolveLayeredSettings(null, 42).settings).toEqual(DEFAULT_SETTINGS);
  });

  it("projectSettingsExist reflects a present, object-shaped override", () => {
    const project = makeProjectDir();
    expect(projectSettingsExist(project)).toBe(false);
    writeProjectRaw(project, { showLogo: true });
    expect(projectSettingsExist(project)).toBe(true);
    writeProjectRaw(project, "[]"); // array is not layerable
    expect(projectSettingsExist(project)).toBe(false);
  });
});

describe("project override writes", () => {
  it("sanitizeOverrides keeps known valid keys and drops the rest, sparsely", () => {
    const patch = sanitizeOverrides({ showLogo: false, density: "compact", nope: 1, showStatusBar: "x" });
    expect(patch).toEqual({ showLogo: false, density: "compact" });
  });

  it("round-trips a sparse project override", () => {
    const project = makeProjectDir();
    expect(saveProjectOverrides({ showLogo: false }, project)).toBe(true);
    expect(readProjectOverrides(project)).toEqual({ showLogo: false });
  });
});

import { THEMES as THEMES_FIXTURE } from "./themes.js";

describe("installed theme survives normalize + layering", () => {
  it("keeps an installed theme id set in the global file", () => {
    __resetInstalledThemesForTests();
    const home = makeHome();
    const project = makeProjectDir();
    writeInstalledTheme({ id: "acme.midnight", label: "Mid", palette: THEMES_FIXTURE.midnight.palette }, home);
    reloadInstalledThemes(home);
    // Persist the installed theme id via the global full-object save path.
    saveSettings({ ...DEFAULT_SETTINGS, theme: "acme.midnight" }, home);

    const { settings, sources } = loadLayeredSettings({ homeDir: home, projectDir: project });
    expect(settings.theme).toBe("acme.midnight");
    expect(sources.theme).toBe("global");
    // And a direct normalize keeps it too (cache populated).
    expect(normalizeSettings({ theme: "acme.midnight" }).theme).toBe("acme.midnight");
    __resetInstalledThemesForTests();
  });
});

describe("loadGlobalSettings", () => {
  it("reads only the global layer, ignoring a project override", () => {
    const home = makeHome();
    const project = makeProjectDir();
    writeGlobalFull(home, { ...DEFAULT_SETTINGS, showLogo: false });
    writeProjectRaw(project, { showLogo: true });
    expect(loadGlobalSettings(home).showLogo).toBe(false);
  });
});

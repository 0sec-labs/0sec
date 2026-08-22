import { describe, expect, it } from "vitest";
import {
  findCommand,
  filterCommands,
  getCommandByName,
  SLASH_COMMANDS,
} from "./slash-commands.js";

describe("SLASH_COMMANDS", () => {
  it("has unique canonical names", () => {
    const names = SLASH_COMMANDS.map((c) => c.name);
    expect(new Set(names).size).toBe(names.length);
  });

  it("has no alias overlapping another canonical name", () => {
    const allNames = new Set(SLASH_COMMANDS.map((c) => c.name));
    for (const cmd of SLASH_COMMANDS) {
      for (const alias of cmd.aliases) {
        expect(allNames.has(alias)).toBe(false);
      }
    }
  });

  it("includes exit as a system command with quit alias", () => {
    const exit = SLASH_COMMANDS.find((c) => c.name === "exit");
    expect(exit).toBeDefined();
    expect(exit!.category).toBe("system");
    expect(exit!.aliases).toContain("quit");
  });

  it("marks navigation commands as tuiOnly", () => {
    const navigations = SLASH_COMMANDS.filter((c) => c.category === "navigation");
    expect(navigations.length).toBeGreaterThan(0);
    for (const cmd of navigations) {
      expect(cmd.tuiOnly).toBe(true);
    }
  });

  it("describes the three execution policies", () => {
    const mode = getCommandByName("mode");
    expect(mode?.usage).toBe("/mode [standard|copilot|yolo]");
    expect(mode?.description).toContain("Standard");
    expect(mode?.description).toContain("Co-pilot");
    expect(mode?.description).toContain("YOLO");
  });
});

describe("findCommand", () => {
  // ── non-slash ─────────────────────────────────────────────────────────
  it("returns non-slash for plain text", () => {
    const result = findCommand("hello world");
    expect(result.isSlash).toBe(false);
    expect(result.isKnown).toBe(false);
    expect(result.isUnknown).toBe(false);
    expect(result.command).toBeUndefined();
    expect(result.rawName).toBe("");
    expect(result.args).toBe("");
  });

  it("returns non-slash for empty string", () => {
    const result = findCommand("");
    expect(result.isSlash).toBe(false);
    expect(result.isUnknown).toBe(false);
  });

  // ── known commands ────────────────────────────────────────────────────
  it("recognises /help by canonical name", () => {
    const result = findCommand("/help");
    expect(result.isSlash).toBe(true);
    expect(result.isKnown).toBe(true);
    expect(result.isUnknown).toBe(false);
    expect(result.command).toBe("help");
    expect(result.rawName).toBe("help");
    expect(result.args).toBe("");
  });

  it("recognises /help by alias ?", () => {
    const result = findCommand("/?");
    expect(result.isSlash).toBe(true);
    expect(result.isKnown).toBe(true);
    expect(result.command).toBe("help");
    expect(result.rawName).toBe("?");
  });

  it("recognises /help by alias commands", () => {
    const result = findCommand("/commands");
    expect(result.isSlash).toBe(true);
    expect(result.isKnown).toBe(true);
    expect(result.command).toBe("help");
  });

  it("recognises /clear by alias new", () => {
    const result = findCommand("/new");
    expect(result.isSlash).toBe(true);
    expect(result.isKnown).toBe(true);
    expect(result.command).toBe("clear");
  });

  it("recognises /exit by alias quit", () => {
    const result = findCommand("/quit");
    expect(result.isSlash).toBe(true);
    expect(result.isKnown).toBe(true);
    expect(result.command).toBe("exit");
  });

  it("recognises /findings by alias finds", () => {
    const result = findCommand("/finds");
    expect(result.isSlash).toBe(true);
    expect(result.isKnown).toBe(true);
    expect(result.command).toBe("findings");
  });

  it("recognises /launcher by alias home", () => {
    const result = findCommand("/home");
    expect(result.isSlash).toBe(true);
    expect(result.isKnown).toBe(true);
    expect(result.command).toBe("launcher");
  });

  it("recognises /ops by alias runs", () => {
    const result = findCommand("/runs");
    expect(result.isSlash).toBe(true);
    expect(result.isKnown).toBe(true);
    expect(result.command).toBe("ops");
  });

  // ── whitespace handling ───────────────────────────────────────────────
  it("handles leading whitespace", () => {
    const result = findCommand("  /help");
    expect(result.isSlash).toBe(true);
    expect(result.isKnown).toBe(true);
    expect(result.command).toBe("help");
  });

  it("extracts arguments after command name", () => {
    const result = findCommand("/mode copilot");
    expect(result.isSlash).toBe(true);
    expect(result.isKnown).toBe(true);
    expect(result.command).toBe("mode");
    expect(result.rawName).toBe("mode");
    expect(result.args).toBe("copilot");
  });

  it("handles multiple space-separated arguments", () => {
    const result = findCommand("/mode yolo  --force");
    expect(result.command).toBe("mode");
    expect(result.args).toBe("yolo  --force");
  });

  it("handles trailing whitespace in args", () => {
    const result = findCommand("/help  foo  ");
    expect(result.command).toBe("help");
    expect(result.args).toBe("foo");
  });

  it("handles commands with no args but trailing whitespace", () => {
    const result = findCommand("/tools   ");
    expect(result.isSlash).toBe(true);
    expect(result.isKnown).toBe(true);
    expect(result.command).toBe("tools");
    expect(result.args).toBe("");
  });

  // ── unknown slash commands ────────────────────────────────────────────
  it("flags unknown slash commands", () => {
    const result = findCommand("/blarg");
    expect(result.isSlash).toBe(true);
    expect(result.isKnown).toBe(false);
    expect(result.isUnknown).toBe(true);
    expect(result.command).toBeUndefined();
    expect(result.rawName).toBe("blarg");
    expect(result.args).toBe("");
  });

  it("flags unknown slash commands with args", () => {
    const result = findCommand("/nonexistent arg1 arg2");
    expect(result.isSlash).toBe(true);
    expect(result.isUnknown).toBe(true);
    expect(result.rawName).toBe("nonexistent");
    expect(result.args).toBe("arg1 arg2");
  });

  it("treats single slash as unknown", () => {
    const result = findCommand("/");
    expect(result.isSlash).toBe(true);
    expect(result.isUnknown).toBe(true);
    expect(result.rawName).toBe("");
    expect(result.args).toBe("");
  });

  it("treats slash followed by only whitespace as unknown", () => {
    const result = findCommand("/   ");
    expect(result.isSlash).toBe(true);
    expect(result.isUnknown).toBe(true);
    expect(result.rawName).toBe("");
    expect(result.args).toBe("");
  });
});

describe("filterCommands", () => {
  it("returns all commands for empty query", () => {
    const all = filterCommands("");
    expect(all.length).toBe(SLASH_COMMANDS.length);
  });

  it("filters by canonical name prefix (case-insensitive)", () => {
    const results = filterCommands("h");
    const names = results.map((c) => c.name);
    expect(names).toContain("help");
    expect(names).toContain("history");
    expect(names).not.toContain("clear");
  });

  it("filters by alias prefix", () => {
    const results = filterCommands("comm");
    const names = results.map((c) => c.name);
    expect(names).toContain("help"); // /commands → help
  });

  it("returns empty array for no match", () => {
    const results = filterCommands("zzzzz");
    expect(results).toEqual([]);
  });

  it("filters case-insensitively", () => {
    const upper = filterCommands("M");
    const lower = filterCommands("m");
    // Both should return mode
    expect(upper.map((c) => c.name)).toContain("mode");
    expect(lower.map((c) => c.name)).toEqual(upper.map((c) => c.name));
  });

  it("matches partial prefix uniquely", () => {
    const results = filterCommands("fi");
    const names = results.map((c) => c.name);
    expect(names).toContain("findings");
    // "fi" doesn't match "history" or "help"
    expect(names).not.toContain("history");
  });

  it("matches '?' alias for help", () => {
    const results = filterCommands("?");
    const names = results.map((c) => c.name);
    expect(names).toContain("help");
  });
});

describe("getCommandByName", () => {
  it("returns command by canonical name", () => {
    const cmd = getCommandByName("help");
    expect(cmd).toBeDefined();
    expect(cmd!.name).toBe("help");
  });

  it("returns command by alias", () => {
    const cmd = getCommandByName("quit");
    expect(cmd).toBeDefined();
    expect(cmd!.name).toBe("exit");
  });

  it("returns undefined for unknown name", () => {
    const cmd = getCommandByName("blarg");
    expect(cmd).toBeUndefined();
  });
});
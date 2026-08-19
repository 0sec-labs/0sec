/**
 * Run-scoped CODEX_HOME for agent runs whose cwd is downloaded code.
 *
 * The regression these guard: the package-audit pipeline ran `codex exec` with
 * cwd inside `$TMPDIR/pwnkit-audit-<uuid>/node_modules/<pkg>`, and Codex wrote
 * a `[projects."…"] trust_level = "trusted"` entry per audited package into the
 * operator's own `~/.codex/config.toml`. Sixteen such entries were found on the
 * dev host. Trust gates project-local config, hooks, exec policies and MCP
 * servers, so those entries are an execution path for a hostile package.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createEphemeralCodexHome, isEphemeralScope, stripProjectTrust } from "./codex-home.js";

const OPERATOR_CONFIG = [
  'model_reasoning_effort = "medium"',
  'sandbox_mode = "danger-full-access"',
  "",
  "[features]",
  "hooks = true",
  "",
  '[model_providers.azure]',
  'base_url = "https://example.openai.azure.com/openai/v1"',
  'wire_api = "responses"',
  "",
  '[projects."/Users/peak"]',
  'trust_level = "trusted"',
  "",
  '[projects."/private/var/folders/2b/T/pwnkit-audit-8103b3c8/node_modules/lodash"]',
  'trust_level = "trusted"',
  "",
  '[mcp_servers.hindsight]',
  'command = "hindsight"',
  "",
].join("\n");

describe("stripProjectTrust", () => {
  it("removes every projects section and nothing else", () => {
    const stripped = stripProjectTrust(OPERATOR_CONFIG);
    expect(stripped).not.toContain("[projects.");
    expect(stripped).not.toContain("trust_level");
    expect(stripped).not.toContain("pwnkit-audit-8103b3c8");
    // Provider config, features and MCP servers survive intact.
    expect(stripped).toContain('[model_providers.azure]');
    expect(stripped).toContain('base_url = "https://example.openai.azure.com/openai/v1"');
    expect(stripped).toContain("[features]");
    expect(stripped).toContain("hooks = true");
    expect(stripped).toContain("[mcp_servers.hindsight]");
    expect(stripped).toContain('model_reasoning_effort = "medium"');
  });

  it("handles a bare [projects] table and resumes at the next section", () => {
    const stripped = stripProjectTrust(
      ["[projects]", 'foo = "bar"', "", "[model]", 'name = "x"'].join("\n"),
    );
    expect(stripped).not.toContain("[projects]");
    expect(stripped).not.toContain('foo = "bar"');
    expect(stripped).toContain("[model]");
    expect(stripped).toContain('name = "x"');
  });

  it("does not eat a section whose name merely starts with 'projects'", () => {
    const stripped = stripProjectTrust(["[projects_extra]", 'k = "v"'].join("\n"));
    expect(stripped).toContain("[projects_extra]");
    expect(stripped).toContain('k = "v"');
  });

  it("is a no-op on a config with no projects sections", () => {
    const toml = ['model = "gpt-5.5"', "", "[features]", "hooks = true"].join("\n");
    expect(stripProjectTrust(toml)).toBe(toml);
  });
});

describe("isEphemeralScope", () => {
  const dirs: string[] = [];

  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  it("is true for an audit tree under the OS temp dir", () => {
    // Real-pathing matters on macOS: tmpdir() is /var/folders/… which is a
    // symlink into /private/var/folders/…, and the two never compare equal.
    const tempDir = mkdtempSync(join(tmpdir(), "pwnkit-audit-"));
    dirs.push(tempDir);
    const pkgDir = join(tempDir, "node_modules", "lodash");
    mkdirSync(pkgDir, { recursive: true });
    expect(isEphemeralScope(pkgDir)).toBe(true);
  });

  it("is false for a real checkout", () => {
    expect(isEphemeralScope(process.cwd())).toBe(false);
  });

  it("fails closed on a path that does not exist", () => {
    expect(isEphemeralScope(join(tmpdir(), "pwnkit-does-not-exist-xyz"))).toBe(false);
  });
});

describe("createEphemeralCodexHome", () => {
  const dirs: string[] = [];
  let operatorHome: string;

  beforeEach(() => {
    operatorHome = mkdtempSync(join(tmpdir(), "pwnkit-fake-codex-home-"));
    dirs.push(operatorHome);
    writeFileSync(join(operatorHome, "config.toml"), OPERATOR_CONFIG);
    vi.stubEnv("CODEX_HOME", operatorHome);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  it("seeds provider config WITHOUT any trust entry, and is not the operator's home", () => {
    const home = createEphemeralCodexHome()!;
    dirs.push(home.path);
    expect(home.path).not.toBe(operatorHome);

    const seeded = readFileSync(join(home.path, "config.toml"), "utf8");
    expect(seeded).toContain("[model_providers.azure]");
    expect(seeded).not.toContain("[projects.");
    expect(seeded).not.toContain("trust_level");
    home.dispose();
  });

  it("carries auth.json through at 0600 so credentials still resolve", () => {
    const auth = JSON.stringify({ tokens: { access_token: "at-1", refresh_token: "rt-1" } });
    writeFileSync(join(operatorHome, "auth.json"), auth);

    const home = createEphemeralCodexHome()!;
    dirs.push(home.path);
    const scopedAuth = join(home.path, "auth.json");
    expect(readFileSync(scopedAuth, "utf8")).toBe(auth);
    expect(statSync(scopedAuth).mode & 0o777).toBe(0o600);
    home.dispose();
  });

  it("deletes the directory on dispose, taking any trust entry the run wrote with it", () => {
    const home = createEphemeralCodexHome()!;
    // Simulate what `codex exec` does when it runs in an untrusted directory.
    writeFileSync(
      join(home.path, "config.toml"),
      readFileSync(join(home.path, "config.toml"), "utf8")
        + '\n[projects."/tmp/pwnkit-audit-deadbeef/node_modules/evil"]\ntrust_level = "trusted"\n',
    );

    home.dispose();

    expect(existsSync(home.path)).toBe(false);
    // The operator's config is untouched — no new trust entry.
    expect(readFileSync(join(operatorHome, "config.toml"), "utf8")).toBe(OPERATOR_CONFIG);
  });

  it("syncs back a ROTATED credential so the operator's login survives", () => {
    const before = JSON.stringify({ tokens: { access_token: "at-1", refresh_token: "rt-1" } });
    writeFileSync(join(operatorHome, "auth.json"), before);

    const home = createEphemeralCodexHome()!;
    const rotated = JSON.stringify({ tokens: { access_token: "at-2", refresh_token: "rt-2" } });
    writeFileSync(join(home.path, "auth.json"), rotated);

    home.dispose();

    // Codex invalidates the old refresh token when it rotates; dropping the new
    // one would leave the operator holding a dead credential.
    expect(readFileSync(join(operatorHome, "auth.json"), "utf8")).toBe(rotated);
  });

  it("refuses to sync back a credential file that is no longer credentials", () => {
    const before = JSON.stringify({ tokens: { access_token: "at-1", refresh_token: "rt-1" } });
    writeFileSync(join(operatorHome, "auth.json"), before);

    const home = createEphemeralCodexHome()!;
    writeFileSync(join(home.path, "auth.json"), "}{ not json");

    home.dispose();

    expect(readFileSync(join(operatorHome, "auth.json"), "utf8")).toBe(before);
  });

  it("does not create an auth.json the operator never had", () => {
    const home = createEphemeralCodexHome()!;
    dirs.push(home.path);
    expect(existsSync(join(home.path, "auth.json"))).toBe(false);
    home.dispose();
    expect(existsSync(join(operatorHome, "auth.json"))).toBe(false);
  });

  it("still produces a usable home when the operator has no config at all", () => {
    rmSync(join(operatorHome, "config.toml"));
    const home = createEphemeralCodexHome()!;
    dirs.push(home.path);
    expect(existsSync(home.path)).toBe(true);
    expect(existsSync(join(home.path, "config.toml"))).toBe(false);
    home.dispose();
  });
});

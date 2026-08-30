import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { detectAndRoute } from "../../packages/cli/src/routing.js";
import { ToolExecutor } from "../../packages/core/src/agent/tools.js";

const thisDir = fileURLToPath(new URL(".", import.meta.url));
const cliPath = join(thisDir, "../../packages/cli/src/index.ts");
// Invoke tsx's cli.mjs with node directly. The node_modules/.bin/tsx shim is a
// /bin/sh script, and on dash-based systems /bin/sh strips environment
// variables whose names are not shell identifiers — which includes the
// digit-leading 0SEC_* contract this suite exercises.
const tsxCliPath = join(thisDir, "../node_modules/tsx/dist/cli.mjs");
const tsconfigPath = join(thisDir, "../tsconfig.cli-e2e.json");
const testDbPath = join(tmpdir(), `0sec-cli-test-${Date.now()}.db`);

const projectRoot = join(thisDir, "../..");

const noApiEnv = {
  OPENROUTER_API_KEY: "",
  ANTHROPIC_API_KEY: "",
  AZURE_OPENAI_API_KEY: "",
  DEEPSEEK_API_KEY: "",
  OPENAI_API_KEY: "",
  Z_AI_API_KEY: "",
  QWEN_API_KEY: "",
  KIMI_API_KEY: "",
  "0SEC_CHATGPT_ACCESS_TOKEN": "",
  "0SEC_CHATGPT_OAUTH_REFRESH_TOKEN": "",
  "0SEC_CHATGPT_ACCOUNT_ID": "",
  "0SEC_CODEX_AUTH_JSON_PATH": join(tmpdir(), "0sec-cli-test-no-codex-auth.json"),
  "0SEC_CHATGPT_AUTH_FILE": join(tmpdir(), "0sec-cli-test-no-codex-auth.json"),
  "0SEC_SKIP_PROVIDER_BANNER": "1",
};

const run = (args: string[], timeout = 30_000, extraEnv: Record<string, string | undefined> = {}) => {
  // Build a clean env, stripping NODE_OPTIONS and npm_*/pnpm_* vars
  // that pnpm injects and can interfere with native module loading
  // (e.g. better-sqlite3) or npm install in the child process.
  const cleanEnv: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (k === "NODE_OPTIONS") continue;
    if (k.startsWith("npm_")) continue;
    if (k.startsWith("pnpm_") || k === "PNPM_PACKAGE_NAME") continue;
    if (v !== undefined) cleanEnv[k] = v;
  }
  return spawnSync(process.execPath, [tsxCliPath, "--tsconfig", tsconfigPath, cliPath, ...args], {
    cwd: projectRoot,
    encoding: "utf-8",
    timeout,
    env: { ...cleanEnv, NO_COLOR: "1", ...extraEnv },
  });
};

describe("CLI E2E", () => {
  it("--help shows all commands", () => {
    const result = run(["--help"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("0sec");
    for (const cmd of ["scan", "audit", "review", "history", "findings", "replay", "doctor"]) {
      expect(result.stdout).toContain(cmd);
    }
  });

  it("auto-routes an existing bare relative path to deep source review", () => {
    expect(detectAndRoute("src")).toEqual(["review", "src", "--depth", "deep"]);
  });

  it("allows piped analysis commands without invoking shell operators", async () => {
    const executor = new ToolExecutor({
      target: "http://example.com",
      scanId: "test",
      findings: [],
      attackResults: [],
      targetInfo: {},
      scopePath: projectRoot,
      persistFindings: false,
    }, null);

    const ok = await executor.execute({
      name: "run_command",
      arguments: { command: "cat package.json | head -n 1" },
    });
    expect(ok.success).toBe(true);

    const blocked = await executor.execute({
      name: "run_command",
      arguments: { command: "cat package.json || head -n 1" },
    });
    expect(blocked.success).toBe(false);
    expect(String(blocked.error)).toContain("Empty pipe segments");
  });

  it("--version shows version", () => {
    const result = run(["--version"]);
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("audit --help shows audit options", () => {
    const result = run(["audit", "--help"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("--depth");
    expect(result.stdout).toContain("--format");
    expect(result.stdout).toContain("--runtime");
  });

  it("audit is-odd --runtime api --format json degrades cleanly without API key", () => {
    const result = run(
      ["audit", "is-odd", "--runtime", "api", "--format", "json", "--db-path", testDbPath],
      60_000,
      noApiEnv,
    );
    expect(result.status).toBe(0);
    const parsed = JSON.parse(result.stdout);
    expect(parsed.package).toBe("is-odd");
    expect(parsed.summary.totalFindings).toBeTypeOf("number");
    const combined = result.stdout + result.stderr;
    expect(combined).toContain('"package": "is-odd"');
  }, 60_000);

  it("review --help shows review options", () => {
    const result = run(["review", "--help"]);
    expect(result.status).toBe(0);
  });

  it("history works (empty or with data)", () => {
    const result = run(["history", "--db-path", "/tmp/0sec-test-empty.db"]);
    expect([0, 1]).toContain(result.status);
  });

  it("scan --help shows scan options", () => {
    const result = run(["scan", "--help"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("--target");
    expect(result.stdout).toContain("--mode");
  });

  it("share URL is still generated for a successful degraded deterministic run", () => {
    const result = run(
      ["audit", "is-odd", "--runtime", "api", "--format", "terminal", "--db-path", testDbPath + "-share"],
      60_000,
      noApiEnv,
    );
    const output = result.stdout + result.stderr;
    expect(result.status).toBe(0);
    expect(output).toContain("0sec.ai/r#");
    expect(output).toContain("No vulnerabilities found");
  }, 60_000);

  it("emits a machine-readable result line when requested on degraded api runs", () => {
    const result = run(
      ["audit", "is-odd", "--runtime", "api", "--format", "json", "--db-path", testDbPath + "-result-line"],
      60_000,
      {
        ...noApiEnv,
        "0SEC_EMIT_RESULT_LINE": "1",
      },
    );
    const output = result.stdout + result.stderr;
    expect(result.status).toBe(0);
    const line = output.split("\n").find((entry) => entry.startsWith("0SEC_RESULT="));
    expect(line).toBeTruthy();
    const parsed = JSON.parse(line!.slice("0SEC_RESULT=".length));
    expect(parsed.ok).toBe(true);
    expect(parsed.exitCode).toBe(0);
    expect(parsed.targetType).toBe("npm-package");
  }, 60_000);
});

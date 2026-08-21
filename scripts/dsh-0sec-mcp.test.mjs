import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  GENERIC_DSH_TOOL_ROWS,
  DEFAULT_MCP_TOOLS,
  UsageError,
  assertRequestedEnvironment,
  buildDshArgs,
  buildMcpArgs,
  buildProfilePatch,
  parseRunnerArgs,
  runRunner,
} from "./dsh-0sec-mcp.mjs";

const baseArgs = [
  "--target", "https://example.test",
  "--scan-id", "scan-123",
  "--scope", "scope.json",
  "Use only 0sec MCP tools.",
];

test("DSH runner requires an explicitly scoped target and one task", () => {
  assert.throws(
    () => parseRunnerArgs(["--target", "https://example.test", "--scan-id", "scan-123", "task"]),
    UsageError,
  );
  assert.throws(
    () => parseRunnerArgs([...baseArgs, "unexpected"]),
    /exactly one non-empty headless task/,
  );
});

test("DSH runner defaults to the bounded recon tool set", () => {
  const options = parseRunnerArgs(baseArgs, "/workspace");
  assert.equal(options.mcpTools, DEFAULT_MCP_TOOLS);
  assert.deepEqual(
    buildMcpArgs(options, "/opt/0sec/dist/0sec.js").slice(-2),
    ["--tools", DEFAULT_MCP_TOOLS],
  );
});

test("DSH runner preserves 0sec engagement arguments", () => {
  const options = parseRunnerArgs([
    "--target", "https://example.test",
    "--scan-id", "scan-123",
    "--scope", "scope.json",
    "--db-path", "runs/scan.sqlite",
    "--timeout", "45000",
    "--rate-limit", "example.test=1",
    "--mcp-tools", "http_request,crawl",
    "--engagement-profile", "conservative",
    "--allow-scanners",
    "--no-waf-evasion",
    "--mcp-env", "0SEC_MCP_AUTH_JSON",
    "--mcp-env", "0SEC_MCP_AUTH_JSON",
    "Use only 0sec MCP tools.",
  ], "/workspace");

  assert.equal(options.scope, "/workspace/scope.json");
  assert.equal(options.dbPath, "/workspace/runs/scan.sqlite");
  assert.deepEqual(options.mcpEnv, ["0SEC_MCP_AUTH_JSON"]);
  assert.deepEqual(
    buildMcpArgs(options, "/opt/0sec/dist/0sec.js"),
    [
      "/opt/0sec/dist/0sec.js",
      "mcp-server",
      "--target", "https://example.test",
      "--scan-id", "scan-123",
      "--scope", "/workspace/scope.json",
      "--db-path", "/workspace/runs/scan.sqlite",
      "--timeout", "45000",
      "--rate-limit", "example.test=1",
      "--tools", "http_request,crawl",
      "--engagement-profile", "conservative",
      "--allow-scanners",
      "--no-waf-evasion",
    ],
  );
});

test("DSH patch exposes only 0sec MCP tools from the shipped base profile", () => {
  const patch = buildProfilePatch({
    entrypoint: "/opt/0sec/dist/0sec.js",
    serverCwd: "/opt/0sec",
    mcpArgs: [
      "/opt/0sec/dist/0sec.js",
      "mcp-server",
      "--target", "https://example.test",
      "--scan-id", "scan-123",
      "--scope", "/workspace/scope.json",
    ],
    mcpEnv: ["0SEC_MCP_AUTH_JSON"],
  });

  assert.match(patch, /- id: tools\n  config:\n    mode: native/);
  for (const id of GENERIC_DSH_TOOL_ROWS) {
    assert.match(patch, new RegExp(`- id: ${id}\\n  disabled: true`));
  }
  assert.match(patch, /name: '@deepseek-ai\/dsh-mcp-client'/);
  assert.match(patch, /transport: stdio/);
  assert.match(patch, /serverName: "0sec"/);
  assert.match(patch, /failOnStartupError: true/);
  assert.match(patch, /reconnect:\n          enabled: false/);
  assert.match(patch, /0SEC_MCP_AUTH_JSON: !!js process\.env\["0SEC_MCP_AUTH_JSON"\]/);
  assert.doesNotMatch(patch, /0SEC_MCP_AUTH_JSON=[^\n]+/);
});

test("DSH invocation stays a one-shot headless profile command", () => {
  assert.deepEqual(
    buildDshArgs("/tmp/0sec-mcp.patch.yml", "Use only 0sec MCP tools."),
    [
      "--profile",
      "headless",
      "--patch",
      "/tmp/0sec-mcp.patch.yml",
      "Use only 0sec MCP tools.",
    ],
  );
});

test("explicit child environment variables must exist", () => {
  assert.doesNotThrow(() => assertRequestedEnvironment(["ZEROSEC_TOKEN"], { ZEROSEC_TOKEN: "value" }));
  assert.throws(
    () => assertRequestedEnvironment(["ZEROSEC_TOKEN"], {}),
    /ZEROSEC_TOKEN was requested but is not set/,
  );
});

test("invalid child environment names are rejected", () => {
  assert.throws(
    () => parseRunnerArgs([...baseArgs.slice(0, -1), "--mcp-env", "0SEC-BAD", baseArgs.at(-1)]),
    /environment-variable name/,
  );
});

test("runner gives DSH a private patch and removes it after the one-shot", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "0sec-dsh-runner-test-"));
  const entrypoint = join(fixture, "0sec.js");
  const scope = join(fixture, "scope.json");
  const observed = join(fixture, "observed.json");
  const dsh = join(fixture, "dsh");

  try {
    await writeFile(entrypoint, "");
    await writeFile(scope, "{\"in_scope\":[\"example.test\"]}");
    await writeFile(
      dsh,
      `#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";

const args = process.argv.slice(2);
if (args[0] !== "--profile" || args[1] !== "headless" || args[2] !== "--patch" || args.length !== 5) {
  process.exit(23);
}
const patchPath = args[3];
if (!existsSync(patchPath)) process.exit(24);
const patch = readFileSync(patchPath, "utf8");
if (!patch.includes("name: '@deepseek-ai/dsh-mcp-client'") || !patch.includes("--scan-id")) {
  process.exit(25);
}
writeFileSync(${JSON.stringify(observed)}, JSON.stringify({ args, patchPath }));
`,
      { mode: 0o700 },
    );
    await chmod(dsh, 0o700);

    const exitCode = await runRunner([
      "--target", "https://example.test",
      "--scan-id", "scan-123",
      "--scope", scope,
      "--entrypoint", entrypoint,
      "--dsh-bin", dsh,
      "Use only 0sec MCP tools.",
    ]);

    assert.equal(exitCode, 0);
    const result = JSON.parse(await readFile(observed, "utf8"));
    assert.deepEqual(result.args.slice(0, 3), ["--profile", "headless", "--patch"]);
    assert.equal(result.args.at(-1), "Use only 0sec MCP tools.");
    assert.equal(existsSync(result.patchPath), false);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

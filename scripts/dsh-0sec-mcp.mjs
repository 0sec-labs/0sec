import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs as parseNodeArgs } from "node:util";

const scriptPath = fileURLToPath(import.meta.url);
export const repoRoot = resolve(dirname(scriptPath), "..");

export const GENERIC_DSH_TOOL_ROWS = [
  "plan-mode",
  "tool-bash",
  "tool-pwsh",
  "tool-jobs",
  "tool-fs",
  "tool-fs-search",
  "tool-skill",
  "tool-subagent-control",
  "tool-subagent-list-agents",
  "tool-subagent",
  "tool-subagent-fork",
  "tool-subagent-report",
  "tool-workflow",
  "tool-todo",
  "tool-goal",
  "tool-ralph",
  "tool-str-replace-editor",
  "tool-web",
  "web",
  "web-search-deepseek",
];

export const DEFAULT_MCP_TOOLS = "http_request,crawl,submit_form,send_prompt";

const ENV_NAME = /^[A-Za-z0-9_]+$/;

export class UsageError extends Error {}

export function usage() {
  return `Usage:
  node scripts/dsh-0sec-mcp.mjs \\
    --target <authorized-url> \\
    --scan-id <scan-id> \\
    --scope <scope.json> \\
    [--db-path <database.sqlite>] \\
    [--timeout <milliseconds>] \\
    [--rate-limit <spec>] \\
    [--mcp-tools <comma-separated-names>] [--engagement-profile <standard|conservative>]
    [--allow-scanners] [--no-waf-evasion] \\
    [--mcp-env <NAME> ...] [--entrypoint <0sec.js>] \\
    [--dsh-bin <dsh>] [--dry-run] \\
    "<one headless task>"

Starts DeepSeek Harness as an external headless host and mounts only the
0sec stdio MCP tools. The runner creates a private temporary DSH patch and
removes it after dsh exits; it does not modify DSH profiles or 0sec config.

--scope is required even though 0sec mcp-server itself permits omission.
Use --mcp-env only for an explicit 0sec child-process environment variable,
for example --mcp-env 0SEC_MCP_AUTH_JSON. The value is never written into the
temporary patch.
When --mcp-tools is omitted, the runner exposes the bounded recon set:
http_request, crawl, submit_form, and send_prompt.

`;
}

function required(value, flag) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new UsageError(`${flag} is required`);
  }
  return value.trim();
}

function optional(value) {
  if (value === undefined) return undefined;
  return required(value, "option");
}

export function parseRunnerArgs(argv, cwd = process.cwd()) {
  let parsed;
  try {
    parsed = parseNodeArgs({
      args: argv,
      allowPositionals: true,
      strict: true,
      options: {
        target: { type: "string" },
        "scan-id": { type: "string" },
        scope: { type: "string" },
        "db-path": { type: "string" },
        timeout: { type: "string" },
        "rate-limit": { type: "string" },
        "mcp-tools": { type: "string" },
        "engagement-profile": { type: "string" },
        "allow-scanners": { type: "boolean" },
        "no-waf-evasion": { type: "boolean" },
        "mcp-env": { type: "string", multiple: true },
        entrypoint: { type: "string" },
        "dsh-bin": { type: "string" },
        "dry-run": { type: "boolean" },
        help: { type: "boolean", short: "h" },
      },
    });
  } catch (error) {
    throw new UsageError(error instanceof Error ? error.message : String(error));
  }

  const { values, positionals } = parsed;
  if (values.help) return { help: true };
  if (positionals.length !== 1 || positionals[0].trim() === "") {
    throw new UsageError("provide exactly one non-empty headless task");
  }

  const mcpEnv = values["mcp-env"] ?? [];
  for (const name of mcpEnv) {
    if (!ENV_NAME.test(name)) {
      throw new UsageError(`--mcp-env must be an environment-variable name: ${name}`);
    }
  }

  return {
    help: false,
    target: required(values.target, "--target"),
    scanId: required(values["scan-id"], "--scan-id"),
    scope: resolve(cwd, required(values.scope, "--scope")),
    dbPath: values["db-path"] === undefined ? undefined : resolve(cwd, optional(values["db-path"])),
    timeout: optional(values.timeout),
    rateLimit: optional(values["rate-limit"]),
    mcpTools: optional(values["mcp-tools"]) ?? DEFAULT_MCP_TOOLS,
    engagementProfile: optional(values["engagement-profile"]),
    allowScanners: values["allow-scanners"] === true,
    noWafEvasion: values["no-waf-evasion"] === true,
    mcpEnv: [...new Set(mcpEnv)],
    entrypoint: values.entrypoint === undefined ? undefined : resolve(cwd, optional(values.entrypoint)),
    dshBin: optional(values["dsh-bin"]),
    dryRun: values["dry-run"] === true,
    task: positionals[0],
  };
}

export function buildMcpArgs(options, entrypoint) {
  const args = [
    entrypoint,
    "mcp-server",
    "--target",
    options.target,
    "--scan-id",
    options.scanId,
    "--scope",
    options.scope,
  ];

  if (options.dbPath) args.push("--db-path", options.dbPath);
  if (options.timeout) args.push("--timeout", options.timeout);
  if (options.rateLimit) args.push("--rate-limit", options.rateLimit);
  if (options.mcpTools) args.push("--tools", options.mcpTools);
  if (options.engagementProfile) args.push("--engagement-profile", options.engagementProfile);
  if (options.allowScanners) args.push("--allow-scanners");
  if (options.noWafEvasion) args.push("--no-waf-evasion");
  return args;
}

function yamlString(value) {
  return JSON.stringify(value);
}

function renderEnv(names) {
  if (names.length === 0) return "";
  return `\n        env:\n${names.map((name) =>
    `          ${name}: !!js process.env[${JSON.stringify(name)}]`,
  ).join("\n")}`;
}

export function buildProfilePatch({ entrypoint, serverCwd, mcpArgs, mcpEnv }) {
  const disabledRows = GENERIC_DSH_TOOL_ROWS.map((id) => `- id: ${id}\n  disabled: true`).join("\n\n");
  const renderedArgs = mcpArgs.map((arg) => `          - ${yamlString(arg)}`).join("\n");

  return `# Generated by scripts/dsh-0sec-mcp.mjs. Do not persist credentials here.
# This final overlay keeps the DSH tool registry but exposes only 0sec MCP tools.
- id: tools
  config:
    mode: native

${disabledRows}

- insert:
    - id: mcp-0sec
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        transport: stdio
        serverName: "0sec"
        command: ${yamlString(process.execPath)}
        args:
${renderedArgs}
        cwd: ${yamlString(serverCwd)}${renderEnv(mcpEnv)}
        toolCallTimeoutMs: 60000
        failOnStartupError: true
        reconnect:
          enabled: false
`;
}

export function buildDshArgs(patchPath, task) {
  return ["--profile", "headless", "--patch", patchPath, task];
}

export function assertRequestedEnvironment(names, env = process.env) {
  for (const name of names) {
    if (env[name] === undefined) {
      throw new UsageError(`--mcp-env ${name} was requested but is not set`);
    }
  }
}

function runProcess(command, args, env) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, args, { cwd: process.cwd(), env, stdio: "inherit" });
    child.once("error", rejectPromise);
    child.once("exit", (code, signal) => {
      if (signal) {
        resolvePromise(1);
        return;
      }
      resolvePromise(code ?? 1);
    });
  });
}

export async function runRunner(argv = process.argv.slice(2), env = process.env) {
  const options = parseRunnerArgs(argv);
  if (options.help) {
    process.stdout.write(usage());
    return 0;
  }

  assertRequestedEnvironment(options.mcpEnv, env);
  const entrypoint = options.entrypoint ?? join(repoRoot, "dist", "0sec.js");
  const mcpArgs = buildMcpArgs(options, entrypoint);
  const patch = buildProfilePatch({
    entrypoint,
    serverCwd: repoRoot,
    mcpArgs,
    mcpEnv: options.mcpEnv,
  });

  if (options.dryRun) {
    process.stdout.write(`${patch}\n# dsh invocation\n${[options.dshBin ?? env.DSH_BIN ?? "dsh", ...buildDshArgs("<temporary-patch>", options.task)].map(yamlString).join(" ")}\n`);
    return 0;
  }

  if (!existsSync(entrypoint)) {
    throw new UsageError(`0sec entrypoint does not exist: ${entrypoint}; run pnpm build or pass --entrypoint`);
  }

  const tempDir = await mkdtemp(join(tmpdir(), "0sec-dsh-mcp-"));
  const patchPath = join(tempDir, "0sec-mcp.patch.yml");
  try {
    await writeFile(patchPath, patch, { encoding: "utf8", mode: 0o600 });
    return await runProcess(
      options.dshBin ?? env.DSH_BIN ?? "dsh",
      buildDshArgs(patchPath, options.task),
      env,
    );
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

const isMain = process.argv[1] !== undefined && resolve(process.argv[1]) === scriptPath;
if (isMain) {
  runRunner().then((exitCode) => {
    process.exitCode = exitCode;
  }).catch((error) => {
    process.stderr.write(`dsh-0sec-mcp: ${error instanceof Error ? error.message : String(error)}\n\n${usage()}`);
    process.exitCode = error instanceof UsageError ? 2 : 1;
  });
}

import type { Command } from "commander";
import chalk from "chalk";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ToolExecutor,
  getToolsForRole,
  loadScope,
  extractAttributionFromScopeJson,
  resolveAttribution,
  RateLimiter,
  parseRateLimitFlag,
  resolveEngagementProfile,
  extractEngagementFromScopeJson,
  describeEngagementPosture,
} from "@0sec/core";
import type {
  EngagementPosture,
  EngagementProfileInputs,
  HostRateConfig,
  RateLimiterConfig,
} from "@0sec/core";
import { osecDB, resolveOsecRunStorage } from "@0sec/db";
import type { AuthConfig } from "@0sec/shared";
import { z } from "zod";

type McpServerOptions = {
  target: string;
  scanId: string;
  dbPath?: string;
  timeout?: string;
  scope?: string;
  tools?: string;
  rateLimit?: string;
  allowScanners?: boolean;
  engagementProfile?: string;
  /**
   * Commander's `--no-waf-evasion` inverse flag: `false` when the operator
   * passed it, `true` when they did not. Never "unset" — see the mapping in
   * the action, which turns the absent case back into `undefined` so the
   * scope file and env keep their precedence.
   */
  wafEvasion?: boolean;
};

/**
 * Per-host rps the server falls back to when no `--rate-limit` spec is given.
 * Matches the historical default so an unconfigured session is unchanged.
 */
const MCP_DEFAULT_RPS = 5;

type ToolParam = ReturnType<typeof getToolsForRole>[number]["parameters"][string];

const MCP_LIVE_TOOL_NAMES = new Set([
  "http_request",
  "crawl",
  "submit_form",
  "send_prompt",
  "save_finding",
  "update_target",
  "query_findings",
  "update_finding",
  "done",
  "payload_lookup",
  "wp_fingerprint",
  "mongo_objectid",
]);

function resolveMcpToolNames(raw: string | undefined): ReadonlySet<string> {
  if (raw === undefined) return MCP_LIVE_TOOL_NAMES;
  const requested = [...new Set(raw.split(",").map((name) => name.trim()).filter(Boolean))];
  if (requested.length === 0) {
    throw new Error("--tools must name at least one 0sec MCP tool.");
  }
  const unsupported = requested.filter((name) => !MCP_LIVE_TOOL_NAMES.has(name));
  if (unsupported.length > 0) {
    throw new Error(`--tools contains unsupported 0sec MCP tool(s): ${unsupported.join(", ")}`);
  }
  return new Set(requested);
}

function parseJsonEnv<T>(name: string): T | undefined {
  const raw = process.env[name];
  if (!raw?.trim()) return undefined;
  try {
    return JSON.parse(raw) as T;
  } catch {
    throw new Error(`${name} must contain valid JSON.`);
  }
}

function parseAuthEnv(): AuthConfig | undefined {
  const auth = parseJsonEnv<Partial<AuthConfig>>("0SEC_MCP_AUTH_JSON");
  if (!auth) return undefined;

  const requireString = (key: string): string => {
    const value = (auth as Record<string, unknown>)[key];
    if (typeof value !== "string" || value.trim().length === 0) {
      throw new Error(`0SEC_MCP_AUTH_JSON ${auth.type ?? "auth"} auth requires non-empty string field '${key}'.`);
    }
    return value;
  };

  switch (auth.type) {
    case "bearer":
      requireString("token");
      break;
    case "cookie":
      // AuthConfigCookie stores the complete Cookie header value, e.g. "sid=abc".
      requireString("value");
      break;
    case "basic":
      requireString("username");
      requireString("password");
      break;
    case "header":
      requireString("name");
      requireString("value");
      break;
    default:
      throw new Error("0SEC_MCP_AUTH_JSON has an invalid auth type.");
  }

  return auth as AuthConfig;
}

function zodForParam(param: ToolParam): z.ZodTypeAny {
  let schema: z.ZodTypeAny;
  if (param.enum && param.enum.length > 0) {
    schema = z.enum(param.enum as [string, ...string[]]);
  } else if (param.type === "number") {
    schema = z.number();
  } else if (param.type === "boolean") {
    schema = z.boolean();
  } else if (param.type === "object") {
    schema = z.record(z.unknown());
  } else {
    schema = z.string();
  }
  return schema.describe(param.description);
}

function zodForTool(tool: ReturnType<typeof getToolsForRole>[number]): z.ZodObject<z.ZodRawShape> {
  const required = new Set(tool.required ?? []);
  const shape: z.ZodRawShape = {};
  for (const [name, param] of Object.entries(tool.parameters)) {
    const schema = zodForParam(param);
    shape[name] = required.has(name) ? schema : schema.optional();
  }
  return z.object(shape);
}

function toTextResult(text: string, structuredContent?: Record<string, unknown>) {
  return {
    content: [{ type: "text" as const, text }],
    ...(structuredContent ? { structuredContent } : {}),
  };
}

function toolResultToMcp(result: Awaited<ReturnType<ToolExecutor["execute"]>>) {
  if (!result.success) {
    return toTextResult(`ERROR: ${result.error ?? "tool failed"}`, {
      success: false,
      error: result.error,
    });
  }

  const text =
    typeof result.output === "string"
      ? result.output
      : JSON.stringify(result.output ?? {}, null, 2);
  return toTextResult(text, { success: true, output: result.output });
}

function withToolTimeout(
  task: Promise<Awaited<ReturnType<ToolExecutor["execute"]>>>,
  timeoutMs: number,
) {
  return new Promise<Awaited<ReturnType<ToolExecutor["execute"]>>>((resolve) => {
    const timer = setTimeout(() => {
      resolve({
        success: false,
        output: null,
        error: `MCP tool timed out after ${timeoutMs}ms`,
      });
    }, timeoutMs);
    task.then(
      (result) => {
        clearTimeout(timer);
        resolve(result);
      },
      (error) => {
        clearTimeout(timer);
        resolve({
          success: false,
          output: null,
          error: error instanceof Error ? error.message : String(error),
        });
      },
    );
  });
}

/**
 * Resolve the engagement hardening posture, or exit 2 on malformed config.
 *
 * Same contract as the `0sec scan` pre-flight: a typo'd
 * `--engagement-profile`, a bad `0SEC_ENGAGEMENT_RATE_RPS`, or a malformed
 * scope-file `engagement` block is an operator error that must surface at boot
 * — not after the server has already served a session at default noise levels.
 * Exit code 2 matches `scan` so callers can treat "bad posture config" the same
 * way whichever entry point they drove.
 */
function resolveEngagementPostureOrExit(inputs: EngagementProfileInputs): EngagementPosture {
  try {
    return resolveEngagementProfile(inputs);
  } catch (err) {
    console.error(chalk.red(err instanceof Error ? err.message : String(err)));
    process.exit(2);
  }
}

/**
 * Clamp a parsed `--rate-limit` config to an active engagement posture.
 *
 * The posture may only ever make the server QUIETER. Every configured rate —
 * the default bucket and every per-host override — becomes the MINIMUM of
 * itself and the posture's rps, and the posture's full-jitter config is applied
 * to every bucket. So `--engagement-profile conservative --rate-limit 50` runs
 * at 1 rps, while `--engagement-profile conservative --rate-limit 0.2` still
 * runs at 0.2: the flag can lower the ceiling below the profile but never raise
 * it above.
 *
 * This is deliberately STRONGER than the scan path's `effectiveFallbackRps`,
 * where the posture only supplies the fallback and an explicit `--rate-limit`
 * default wins. A scan is one operator command with a visible end; an MCP
 * server is a long-lived session driven by an external client, so the posture
 * is a hard ceiling here rather than a default.
 *
 * Burst is clamped alongside rps because burst is the bucket capacity: leaving
 * a burst of 10 on a 1 rps bucket would let the first ten requests to each host
 * fire at the loud rate anyway.
 *
 * Returns `cfg` untouched for an inactive posture, so a session with no profile
 * requested is byte-for-byte unchanged.
 */
function clampRateLimitToPosture(
  cfg: RateLimiterConfig,
  posture: EngagementPosture,
): RateLimiterConfig {
  if (!posture.active) return cfg;
  const clamp = (host: HostRateConfig): HostRateConfig => {
    const rps = Math.min(host.rps, posture.rateLimitRps);
    return host.burst === undefined ? { rps } : { rps, burst: Math.min(host.burst, rps) };
  };
  return {
    ...cfg,
    default: clamp(cfg.default),
    perHost: cfg.perHost
      ? Object.fromEntries(Object.entries(cfg.perHost).map(([host, c]) => [host, clamp(c)]))
      : undefined,
    jitter: posture.jitter ? { baseMs: posture.jitter.baseMs } : cfg.jitter,
  };
}

export function registerMcpServerCommand(program: Command): void {
  program
    .command("mcp-server")
    .description("Run 0sec's MCP stdio server for live target interaction tools")
    .requiredOption("--target <target>", "Target URL for this MCP session")
    .requiredOption("--scan-id <scanId>", "Scan ID to associate persisted findings and target updates with")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--timeout <ms>", "Default tool timeout in milliseconds", "30000")
    .option("--scope <path>", "Path to a 0sec scope JSON file. Out-of-scope URLs are refused by every target tool.")
    .option("--tools <names>", "Comma-separated live 0sec MCP tools to expose (default: all).")
    .option("--rate-limit <spec>", "Per-host request rate-limit spec. Defaults to 5 rps when unset. An active --engagement-profile caps this: the effective rate is the minimum of the two, so the profile can only lower it.")
    .option("--allow-scanners", "Disable generic-scanner suppression for scoped engagements.", false)
    .option(
      "--engagement-profile <name>",
      "Engagement hardening posture for authorized enterprise work. 'standard' (default) is the existing behaviour. 'conservative' applies the quiet posture to this MCP session: no adaptive WAF-evasion ladder, full jitter on the per-host token bucket, and a 1 rps/host ceiling. The profile can only ever make the session quieter — the effective rate is the minimum of the profile and --rate-limit. The applied posture is recorded as an `engagement_posture_applied` event on the scan so it can be handed to the client as evidence. Lower precedence than the scope file's `engagement` block and 0SEC_ENGAGEMENT_PROFILE.",
    )
    .option(
      "--no-waf-evasion",
      "Disable the adaptive WAF-evasion ladder (default: on). When a response classifies as blocked, the engine normally retries with encoding/casing/whitespace-mutated payload variants, which escalates a routine WAF block into a SOC incident. Detection and reporting of the block are unaffected. Independent of --engagement-profile; env form: 0SEC_WAF_EVASION=0.",
    )
    .action(async (opts: McpServerOptions) => {
      const timeoutMs = Math.max(1_000, parseInt(opts.timeout ?? "30000", 10));
      const target = opts.target.trim();
      const scanId = opts.scanId.trim();
      const scope = opts.scope ? loadScope(opts.scope) : undefined;
      if (scope) {
        const verdict = scope.match(target);
        if (!verdict.allowed) {
          throw new Error(`--target ${target} is out of scope per ${opts.scope}: ${verdict.reason}`);
        }
      }
      const selectedToolNames = resolveMcpToolNames(opts.tools);
      // Engagement hardening posture (`scope/engagement-profile.ts`). Resolved
      // BEFORE the DB is opened, matching the scope-rejection ordering above:
      // a config error must fail without leaving a DB handle behind. Same
      // scope-file > env > CLI precedence and same exit code as `0sec scan`.
      //
      // `--no-waf-evasion` sets opts.wafEvasion to false; commander leaves it
      // `true` when the flag is absent, which we map back to "unset" so the
      // scope file / env keep their precedence.
      const cliWafEvasion = opts.wafEvasion === false ? false : undefined;
      const posture = resolveEngagementPostureOrExit({
        scopeFileBlock: scope ? extractEngagementFromScopeJson(scope.raw) : undefined,
        env: process.env,
        cliProfile: opts.engagementProfile,
        cliWafEvasion,
      });

      const storage = resolveOsecRunStorage({
        dbPath: opts.dbPath,
        runId: scanId,
        resume: true,
      });
      const db = new osecDB(storage.dbPath);

      const attributionHeaders =
        parseJsonEnv<string[]>("0SEC_MCP_ATTRIBUTION_HEADERS_JSON");
      const attribution = resolveAttribution({
        scopeFileBlock: scope ? extractAttributionFromScopeJson(scope.raw) : undefined,
        env: process.env,
        cliHeaders: attributionHeaders,
        cliUaToken: process.env["0SEC_MCP_ATTRIBUTION_UA_TOKEN"],
      });
      const rateLimitConfig = clampRateLimitToPosture(
        parseRateLimitFlag(opts.rateLimit ?? "", MCP_DEFAULT_RPS),
        posture,
      );
      const rateLimiter = new RateLimiter(rateLimitConfig);

      // Auditable evidence of how this session actually ran: the same
      // `engagement_posture_applied` record the scan path writes, so an
      // MCP-driven engagement can answer "how did you run this against our
      // estate?" from the DB as well as from the session transcript. Only when
      // a profile is active — a default session records nothing new.
      // The record's `per_host_rps` is the posture's nominal rate. Because the
      // clamp above can only lower it, the record can never claim the session
      // ran quieter than it did; the stderr line prints the exact effective
      // rate for the case where `--rate-limit` was stricter still.
      if (posture.active) {
        const postureRecord = describeEngagementPosture(posture);
        try {
          db.logEvent({
            scanId,
            stage: "mcp-server",
            eventType: "engagement_posture_applied",
            payload: { ...postureRecord },
            timestamp: Date.now(),
          });
        } catch (err) {
          // pipeline_events FKs to scans(id). An MCP session pointed at a scan
          // this DB has never seen must not fail to start over an audit row —
          // the stderr record below still stands as evidence.
          console.error(
            `warning: could not persist engagement posture for scan ${scanId}: ` +
              (err instanceof Error ? err.message : String(err)),
          );
        }
        // stdout is the MCP transport, so operator-facing output goes to stderr.
        console.error(
          `Engagement profile '${postureRecord.profile}': ` +
            `WAF evasion ladder ${postureRecord.waf_evasion_ladder}, ` +
            `${rateLimitConfig.default.rps} rps/host with ${postureRecord.request_jitter}`,
        );
      }

      const executor = new ToolExecutor(
        {
          target,
          scanId,
          findings: [],
          attackResults: [],
          targetInfo: {},
          persistFindings: true,
          scope,
          rateLimiter,
          allowScanners: opts.allowScanners,
          attribution,
          engagement: posture,
          authConfig: parseAuthEnv(),
        },
        db,
      );

      const server = new McpServer(
        { name: "0sec-mcp", version: "0.1.0" },
        { capabilities: { logging: {} } },
      );

      const tools = getToolsForRole("attack", { webMode: true })
        .filter((tool) => selectedToolNames.has(tool.name));
      for (const tool of tools) {
        server.registerTool(
          tool.name,
          {
            title: tool.name,
            description: tool.description,
            inputSchema: zodForTool(tool),
          },
          async (args) => toolResultToMcp(
            await withToolTimeout(
              executor.execute({
                name: tool.name,
                arguments: args as Record<string, unknown>,
              }),
              timeoutMs,
            ),
          ),
        );
      }

      const transport = new StdioServerTransport();

      const shutdown = async () => {
        await executor.cleanup();
        await server.close();
        db.close();
        process.exit(0);
      };

      process.on("SIGINT", () => { void shutdown(); });
      process.on("SIGTERM", () => { void shutdown(); });

      try {
        await server.connect(transport);
        console.error(`0sec MCP server running for ${target} (scan ${scanId})`);
      } catch (error) {
        console.error("Fatal error in 0sec MCP server:", error);
        await executor.cleanup();
        db.close();
        process.exit(1);
      }
    });
}

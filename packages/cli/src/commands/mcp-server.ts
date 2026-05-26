import type { Command } from "commander";
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
} from "@pwnkit/core";
import { pwnkitDB } from "@pwnkit/db";
import type { AuthConfig } from "@pwnkit/shared";
import { z } from "zod";

type McpServerOptions = {
  target: string;
  scanId: string;
  dbPath?: string;
  timeout?: string;
  scope?: string;
  rateLimit?: string;
  allowScanners?: boolean;
};

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
  const auth = parseJsonEnv<Partial<AuthConfig>>("PWNKIT_MCP_AUTH_JSON");
  if (!auth) return undefined;

  const requireString = (key: string): string => {
    const value = (auth as Record<string, unknown>)[key];
    if (typeof value !== "string" || value.trim().length === 0) {
      throw new Error(`PWNKIT_MCP_AUTH_JSON ${auth.type ?? "auth"} auth requires non-empty string field '${key}'.`);
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
      throw new Error("PWNKIT_MCP_AUTH_JSON has an invalid auth type.");
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

export function registerMcpServerCommand(program: Command): void {
  program
    .command("mcp-server")
    .description("Run pwnkit's MCP stdio server for live target interaction tools")
    .requiredOption("--target <target>", "Target URL for this MCP session")
    .requiredOption("--scan-id <scanId>", "Scan ID to associate persisted findings and target updates with")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--timeout <ms>", "Default tool timeout in milliseconds", "30000")
    .option("--scope <path>", "Path to a pwnkit scope JSON file. Out-of-scope URLs are refused by every target tool.")
    .option("--rate-limit <spec>", "Per-host request rate-limit spec. Defaults to 5 rps when unset.")
    .option("--allow-scanners", "Disable generic-scanner suppression for scoped engagements.", false)
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
      const db = new pwnkitDB(opts.dbPath);

      const attributionHeaders =
        parseJsonEnv<string[]>("PWNKIT_MCP_ATTRIBUTION_HEADERS_JSON");
      const attribution = resolveAttribution({
        scopeFileBlock: scope ? extractAttributionFromScopeJson(scope.raw) : undefined,
        env: process.env,
        cliHeaders: attributionHeaders,
        cliUaToken: process.env.PWNKIT_MCP_ATTRIBUTION_UA_TOKEN,
      });
      const rateLimiter = new RateLimiter(parseRateLimitFlag(opts.rateLimit ?? "", 5));
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
          authConfig: parseAuthEnv(),
        },
        db,
      );

      const server = new McpServer(
        { name: "pwnkit-mcp", version: "0.1.0" },
        { capabilities: { logging: {} } },
      );

      const tools = getToolsForRole("attack", { webMode: true })
        .filter((tool) => MCP_LIVE_TOOL_NAMES.has(tool.name));
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
        console.error(`pwnkit MCP server running for ${target} (scan ${scanId})`);
      } catch (error) {
        console.error("Fatal error in pwnkit MCP server:", error);
        await executor.cleanup();
        db.close();
        process.exit(1);
      }
    });
}

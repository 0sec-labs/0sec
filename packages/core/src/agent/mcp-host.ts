/**
 * MCP client host — the networked half of the MCP client.
 *
 * Connects to external MCP tool servers (over stdio, or any injected transport),
 * discovers their tools, exposes them to the agent as namespaced 0sec
 * `ToolDefinition`s, and routes invocations back. Sibling to the plugin
 * `PluginHost`: an out-of-process tool provider whose tools flow through the same
 * gates. The deterministic name/schema/result adaptation lives in `mcp-adapt.ts`
 * (unit-tested there); this file is the thin SDK glue over it, so `register`
 * takes a transport and is exercised end-to-end against an in-memory server.
 *
 * Security: every tool is namespaced `mcp__<server>__<tool>` (inherits the
 * `isUntrustedSourceTool` fence — an MCP result is untrusted, attacker-influenced
 * data), and the caller gates the tools through the capability/scope maps with
 * MCP tools defaulting to network-capable (danger-by-omission). This host does
 * not weaken any gate; it only connects, lists, and forwards.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import type { ToolDefinition, ToolResult } from "./types.js";
import {
  isSafeMcpServerId,
  mcpResultText,
  mcpToolsToDefinitions,
  parseMcpToolName,
  type McpToolSpec,
} from "./mcp-adapt.js";

/** The transport type `Client.connect` accepts, without importing its module path. */
type ClientTransport = Parameters<Client["connect"]>[0];

/** A stdio MCP server to spawn + connect to. */
export interface McpStdioServerConfig {
  readonly id: string;
  readonly command: string;
  readonly args?: readonly string[];
  readonly env?: Record<string, string>;
  readonly cwd?: string;
}

interface ConnectedServer {
  readonly client: Client;
  readonly defs: ToolDefinition[];
}

/**
 * Holds the connected MCP servers for a session. Created once (like the plugin
 * host) and torn down with `closeAll()` so no client/transport outlives the
 * session.
 */
export class McpHost {
  private readonly servers = new Map<string, ConnectedServer>();

  /** All discovered tools across every connected server, namespaced. */
  registeredTools(): ToolDefinition[] {
    const out: ToolDefinition[] = [];
    for (const s of this.servers.values()) out.push(...s.defs);
    return out;
  }

  /** Ids of the currently connected servers. */
  serverIds(): string[] {
    return [...this.servers.keys()];
  }

  hasServer(id: string): boolean {
    return this.servers.has(id);
  }

  /**
   * Connect a client over `transport`, discover its tools, and register them.
   * The transport is injected so this is testable against an in-memory server
   * (and `connectStdio` builds a real one). Fails closed: a discovery error
   * closes the client and rejects rather than leaving a half-registered server.
   */
  async register(id: string, transport: ClientTransport): Promise<ToolDefinition[]> {
    if (!isSafeMcpServerId(id)) throw new Error(`unsafe MCP server id: ${JSON.stringify(id)}`);
    if (this.servers.has(id)) throw new Error(`MCP server "${id}" is already connected`);
    const client = new Client({ name: "0sec", version: "0.1.0" }, { capabilities: {} });
    await client.connect(transport);
    let defs: ToolDefinition[];
    try {
      const listed = await client.listTools();
      const specs: McpToolSpec[] = (listed.tools ?? []).map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema as McpToolSpec["inputSchema"],
      }));
      defs = mcpToolsToDefinitions(id, specs);
    } catch (err) {
      await client.close().catch(() => undefined);
      throw err;
    }
    this.servers.set(id, { client, defs });
    return defs;
  }

  /** Spawn + connect to a stdio MCP server. */
  async connectStdio(config: McpStdioServerConfig): Promise<ToolDefinition[]> {
    const transport = new StdioClientTransport({
      command: config.command,
      args: [...(config.args ?? [])],
      ...(config.env ? { env: config.env } : {}),
      ...(config.cwd ? { cwd: config.cwd } : {}),
    });
    return this.register(config.id, transport);
  }

  /**
   * Invoke a namespaced MCP tool. Returns a 0sec `ToolResult`; the flattened text
   * output is still routed through the untrusted fence by the caller via the
   * `mcp__` name. Never throws — a transport/tool error is data.
   */
  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    const parsed = parseMcpToolName(name);
    if (!parsed) return { success: false, output: null, error: `not an MCP tool name: ${name}` };
    const server = this.servers.get(parsed.server);
    if (!server) return { success: false, output: null, error: `MCP server "${parsed.server}" is not connected` };
    try {
      const res = (await server.client.callTool({ name: parsed.tool, arguments: args })) as {
        content?: unknown;
        isError?: boolean;
      };
      const text = mcpResultText(res.content);
      if (res.isError) return { success: false, output: null, error: text || "MCP tool returned an error" };
      return { success: true, output: { text } };
    } catch (err) {
      return { success: false, output: null, error: err instanceof Error ? err.message : String(err) };
    }
  }

  /** Close every connected client (session teardown). Never rejects. */
  async closeAll(): Promise<void> {
    const clients = [...this.servers.values()];
    this.servers.clear();
    await Promise.allSettled(clients.map((s) => s.client.close()));
  }
}

/**
 * Parse an MCP server config blob (e.g. the `0SEC_MCP` env var) — a JSON array of
 * `{id, command, args?, env?, cwd?}` — into validated stdio configs. Total and
 * fail-soft: malformed JSON, a non-array, or a bad entry yields fewer (or zero)
 * servers rather than throwing, so a typo never takes a console down.
 */
export function parseMcpConfig(raw: string | undefined): McpStdioServerConfig[] {
  if (!raw || !raw.trim()) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  const out: McpStdioServerConfig[] = [];
  for (const item of parsed) {
    if (!item || typeof item !== "object") continue;
    const o = item as Record<string, unknown>;
    if (typeof o.id !== "string" || !isSafeMcpServerId(o.id)) continue;
    if (typeof o.command !== "string" || o.command.trim().length === 0) continue;
    const args = Array.isArray(o.args) ? o.args.filter((a): a is string => typeof a === "string") : undefined;
    const env =
      o.env && typeof o.env === "object" && !Array.isArray(o.env)
        ? (Object.fromEntries(
            Object.entries(o.env as Record<string, unknown>).filter(([, v]) => typeof v === "string"),
          ) as Record<string, string>)
        : undefined;
    const cwd = typeof o.cwd === "string" ? o.cwd : undefined;
    out.push({
      id: o.id,
      command: o.command,
      ...(args && args.length > 0 ? { args } : {}),
      ...(env && Object.keys(env).length > 0 ? { env } : {}),
      ...(cwd ? { cwd } : {}),
    });
  }
  return out;
}

/**
 * Build a host and connect the given stdio servers, fail-soft: a server that
 * fails to spawn/handshake is skipped, not fatal. Returns the host only if at
 * least one server connected (else undefined, so a caller can omit `mcpHost`).
 */
export async function connectMcpServers(configs: readonly McpStdioServerConfig[]): Promise<McpHost | undefined> {
  if (configs.length === 0) return undefined;
  const host = new McpHost();
  for (const cfg of configs) {
    try {
      await host.connectStdio(cfg);
    } catch {
      // Skip a server that won't connect; the rest still load.
    }
  }
  return host.serverIds().length > 0 ? host : undefined;
}

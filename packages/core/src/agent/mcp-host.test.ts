import { describe, expect, it } from "vitest";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import { McpHost } from "./mcp-host.js";

/** Spin up an in-memory MCP server exposing an `echo` tool, linked to the host. */
async function connectEchoServer(host: McpHost, id = "testsrv"): Promise<McpServer> {
  const server = new McpServer({ name: "test", version: "1.0.0" }, { capabilities: {} });
  server.registerTool(
    "echo",
    { description: "Echo a message back", inputSchema: { msg: z.string() } },
    async ({ msg }) => ({ content: [{ type: "text" as const, text: `echo: ${msg}` }] }),
  );
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await host.register(id, clientTransport);
  return server;
}

describe("McpHost (in-memory e2e)", () => {
  it("connects, discovers a namespaced tool, and invokes it round-trip", async () => {
    const host = new McpHost();
    const server = await connectEchoServer(host);

    expect(host.serverIds()).toEqual(["testsrv"]);
    expect(host.registeredTools().map((d) => d.name)).toContain("mcp__testsrv__echo");
    // The discovered def carries the untrusted-external marker from the adapter.
    const def = host.registeredTools().find((d) => d.name === "mcp__testsrv__echo")!;
    expect(def.description).toContain("untrusted");

    const res = await host.callTool("mcp__testsrv__echo", { msg: "hi" });
    expect(res.success).toBe(true);
    expect((res.output as { text: string }).text).toBe("echo: hi");

    await host.closeAll();
    await server.close();
    expect(host.serverIds()).toEqual([]);
  });

  it("rejects a duplicate server id", async () => {
    const host = new McpHost();
    const server = await connectEchoServer(host, "dup");
    const [c] = InMemoryTransport.createLinkedPair();
    await expect(host.register("dup", c)).rejects.toThrow(/already connected/);
    await host.closeAll();
    await server.close();
  });

  it("rejects an unsafe server id", async () => {
    const host = new McpHost();
    const [c] = InMemoryTransport.createLinkedPair();
    await expect(host.register("../evil", c)).rejects.toThrow(/unsafe/);
  });

  it("returns an error result for a non-mcp name or unconnected server", async () => {
    const host = new McpHost();
    expect((await host.callTool("bash", {})).success).toBe(false);
    expect((await host.callTool("mcp__ghost__t", {})).error).toMatch(/not connected/);
  });
});

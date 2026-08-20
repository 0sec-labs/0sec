/** Canonical object narrowing for untrusted HTTP and MCP payloads in this package. */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

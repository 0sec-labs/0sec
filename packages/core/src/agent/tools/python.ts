/**
 * Python kernel tool definition (Phase-0 `python_exec`).
 *
 * A persistent, COMPUTE-ONLY Python REPL for payload construction, parsing,
 * crypto, and encoding work. State persists across calls within a scan. When
 * an engagement scope is active the kernel blocks all networking at the socket
 * source — the agent must use `http_request` for HTTP and file evidence via
 * `save_finding`.
 *
 * Pure `ToolDefinition` metadata (name / description / parameter schema). The
 * ./tools/index.ts barrel merges this into the canonical `TOOL_DEFINITIONS`
 * registry; the matching runtime handler (`pythonExec`) lives on the
 * `ToolExecutor` class in agent/tools.ts.
 */
import type { ToolDefinition } from "../types.js";

export const pythonToolDefinitions: Record<string, ToolDefinition> = {
  python_exec: {
    name: "python_exec",
    description:
      "Run Python in a PERSISTENT, COMPUTE-ONLY kernel — variables, imports, and " +
      "functions persist across calls. Ideal for payload/exploit construction, " +
      "parsing responses, crypto (hashlib/hmac/pycryptodome), and encode/decode " +
      "(base64/url/jwt/hex). Returns stdout, stderr, and the repr of a trailing " +
      "expression (REPL-style). NETWORKING IS BLOCKED during an authorized " +
      "engagement — use the `http_request` tool for all HTTP, and file findings " +
      "via `save_finding` with the request/response text. Set `reset: true` to " +
      "wipe kernel state and start fresh.",
    parameters: {
      code: {
        type: "string",
        description: "Python source to execute in the persistent kernel. A trailing expression is echoed as its repr().",
      },
      timeout: {
        type: "number",
        description: "Per-call timeout in seconds (default 30, max 120). A hung call resets the kernel.",
      },
      reset: {
        type: "boolean",
        description: "When true, respawn a fresh kernel (clears all persistent state) before running `code`.",
      },
    },
    required: ["code"],
  },
};

// Tool-name → ToolExecutor handler-method name (pwnkit#614). Co-located with
// this domain's definition so a new tool adds its route here, not in a shared
// dispatch switch. Assembled by ./dispatch.ts; resolved off the executor
// instance in agent/tools.ts (the handler body stays a private method).
export const pythonDispatch: Record<string, string> = {
  python_exec: "pythonExec",
};

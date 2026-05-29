/**
 * System / execution tool definitions (pwnkit#611 — split out of the monolithic
 * agent/tools.ts registry).
 *
 * Local execution, filesystem reads, interactive sessions, sub-agent
 * spawning and target-profile updates.
 *
 * Pure `ToolDefinition` metadata (name / description / parameter schema). The
 * ./tools/index.ts barrel merges every per-domain map into the canonical
 * `TOOL_DEFINITIONS` registry; the matching runtime handlers live on the
 * `ToolExecutor` class in agent/tools.ts.
 */
import type { ToolDefinition } from "../types.js";

export const systemToolDefinitions: Record<string, ToolDefinition> = {
  read_file: {
    name: "read_file",
    description: "Read a source code file. Returns numbered lines. Path must be within the scoped directory (usually the package or repo root). Start by reading package.json to understand the project structure, then follow imports.",
    parameters: {
      path: { type: "string", description: "File path (relative to scope root or absolute)" },
      max_lines: { type: "number", description: "Max lines to read (default 500). Use for large files." },
    },
    required: ["path"],
  },

  run_command: {
    name: "run_command",
    description:
      "Run a local command for code analysis. Allowed commands: grep, rg, find, ls, cat, head, tail, wc, foxguard, semgrep, codeql, jq, file, stat, npm (audit/view/ls). Supports piping with |. Examples: 'rg --files .', 'grep -rn \"eval\" .', 'find . -name \"*.js\"', 'cat package.json | jq .main', 'rg \"__proto__\" . | head -20'.",
    parameters: {
      command: { type: "string", description: "Command to execute. Use pipe (|) for chaining. No shell operators like ;, &&, <, >, $." },
      cwd: { type: "string", description: "Working directory (defaults to package/repo root)" },
      timeout: { type: "number", description: "Timeout in ms (default 30000)" },
    },
    required: ["command"],
  },

  update_target: {
    name: "update_target",
    description:
      "Update the target profile with discovered information (type, model, endpoints, system prompt).",
    parameters: {
      type: {
        type: "string",
        description: "Target type",
        enum: ["api", "chatbot", "agent", "mcp", "web-app", "unknown"],
      },
      model: { type: "string", description: "Detected model name" },
      system_prompt: { type: "string", description: "Extracted system prompt" },
      endpoints: { type: "string", description: "JSON array of discovered endpoints" },
      features: { type: "string", description: "JSON array of detected features" },
    },
  },

  bash: {
    name: "bash",
    description:
      "Run a shell command. Use curl, python3, jq, or any installed tool. Supports pipes, redirects, and multi-line scripts.",
    parameters: {
      command: { type: "string", description: "Shell command to execute. Supports pipes, redirects, and multi-line scripts." },
      timeout: { type: "number", description: "Timeout in seconds (default 30, max 120)" },
    },
    required: ["command"],
  },

  spawn_agent: {
    name: "spawn_agent",
    description:
      "Spawn a focused sub-agent with fresh context for a specific exploitation task. Use when you've found a vulnerability and need deep exploitation (e.g., SQLi table enumeration, multi-step auth chain). The sub-agent gets its own turn budget and returns findings.",
    parameters: {
      task: { type: "string", description: "What the sub-agent should do. Be specific: include the target URL, the vulnerability found, and what to extract." },
      max_turns: { type: "number", description: "Turn budget for the sub-agent (default 15, max 25)" },
    },
    required: ["task"],
  },

  pty_session: {
    name: "pty_session",
    description:
      "Manage interactive terminal sessions for exploits requiring interactivity (reverse shells, database clients, SSH). Sessions persist across tool calls, allowing multi-step interactive workflows.",
    parameters: {
      action: {
        type: "string",
        description: "Session action",
        enum: ["create", "send", "read", "close", "list"],
      },
      session_name: { type: "string", description: "Session name (for create/send/read/close)" },
      input: { type: "string", description: "Input to send to the session (for send action)" },
      timeout: { type: "number", description: "Read timeout in ms (for read action, default 5000)" },
    },
    required: ["action"],
  },
};

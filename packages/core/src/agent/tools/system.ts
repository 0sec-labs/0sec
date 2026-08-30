/**
 * System / execution tool definitions (0sec#611 — split out of the monolithic
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
    description:
      "Read a source code file, or a window of one. Path must be within the scoped directory (usually the package or repo root). " +
      "Returns raw lines plus startLine/endLine/totalLines for exact file:line citations. " +
      "Use offset (1-based, matching grep -n and rg -n) to read the middle of a large file. " +
      "When a window does not reach end-of-file, the result gives the next offset to continue from.",
    parameters: {
      path: { type: "string", description: "File path (relative to scope root or absolute)" },
      max_lines: { type: "number", description: "Max lines to read (default 500). Use for large files." },
      offset: {
        type: "number",
        description: "1-based line number to start reading at (default 1). An offset past EOF returns an empty window with the file length.",
      },
    },
    required: ["path"],
  },

  list_files: {
    name: "list_files",
    description:
      "List regular files under the scoped source directory. Skips .git, node_modules, and symlinks. Use this to map source before reading individual files.",
    parameters: {
      path: { type: "string", description: "Optional file or directory path within the scoped source directory" },
      limit: { type: "number", description: "Maximum files to return (default 100, maximum 500)" },
    },
  },

  search_files: {
    name: "search_files",
    description:
      "Search regular text files under the scoped source directory for a literal string. Skips symlinks, files larger than 256 KiB, .git, and node_modules.",
    parameters: {
      query: { type: "string", description: "Literal text to search for" },
      path: { type: "string", description: "Optional file or directory path within the scoped source directory" },
      case_sensitive: { type: "boolean", description: "Match case exactly (default false)" },
      max_results: { type: "number", description: "Maximum matching lines to return (default 50, maximum 200)" },
    },
    required: ["query"],
  },

  str_replace: {
    name: "str_replace",
    description:
      "PREFER THIS for editing a single existing file: replace one exact string with another. " +
      "`old_string` must match the file contents EXACTLY — including all whitespace and indentation — and must be UNIQUE (appear once), " +
      "so include a few surrounding lines when a bare snippet would be ambiguous. Set `replace_all: true` to replace every occurrence instead. " +
      "This has no fragile context hunks, so it avoids the context-mismatch failures of apply_patch. " +
      "Errors are explicit and self-correctable (not found / N matches not unique). " +
      "Use apply_patch instead only for multi-file patches or creating/deleting whole files. Path must be within the scoped directory.",
    parameters: {
      path: { type: "string", description: "File path (relative to scope root or absolute) of an existing file to edit" },
      old_string: { type: "string", description: "Exact text to find, matching the file byte-for-byte including whitespace/indentation. Must be unique unless replace_all is set." },
      new_string: { type: "string", description: "Text to replace it with. May be empty to delete the matched text." },
      replace_all: { type: "boolean", description: "Replace every occurrence instead of requiring a unique match (default false)." },
    },
    required: ["path", "old_string", "new_string"],
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

  plan: {
    name: "plan",
    description:
      "Maintain the scan's compact task ledger. Add concrete next steps, mark the one currently being worked, then complete or drop it. Use list to review open work before changing approach.",
    parameters: {
      action: {
        type: "string",
        description: "Plan action",
        enum: ["add", "start", "complete", "drop", "note", "list"],
      },
      title: {
        type: "string",
        description: "Task title for action add. A newline-separated list adds several tasks.",
      },
      id: {
        type: "string",
        description: "Task id for start, complete, drop, or note (for example task-2).",
      },
      detail: {
        type: "string",
        description: "Optional concrete note for add, complete, or drop; required for note.",
      },
    },
    required: ["action"],
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

  spawn_agents: {
    name: "spawn_agents",
    description:
      "Spawn MULTIPLE focused sub-agents that run CONCURRENTLY (bounded), each with fresh context and its own turn budget. Use to fan out independent exploitation tasks in parallel (e.g. probe several endpoints or leads at once) instead of one-at-a-time spawn_agent. Returns each sub-agent's findings and summary. Max 8 tasks per call.",
    parameters: {
      tasks: {
        type: "array",
        description:
          "The sub-agent tasks to run concurrently (1-8). Each item is an object { task, max_turns? }.",
        items: {
          type: "object",
          properties: {
            task: {
              type: "string",
              description:
                "What this sub-agent should do. Be specific: include the target URL, the vulnerability, and what to extract.",
            },
            max_turns: {
              type: "number",
              description: "Turn budget for this sub-agent (default 15, max 25)",
            },
          },
          required: ["task"],
        },
      },
    },
    required: ["tasks"],
  },

  monitor: {
    name: "monitor",
    description:
      "Run and supervise a LONG-RUNNING process in the background across turns — a dev server to test against, a reverse-shell/OAST listener, a payload-hosting server, a long scanner (nuclei/ffuf/nmap) or fuzzer, or a build. Use this instead of bash for anything that must keep running while you keep working (bash is one-shot, 120s max). Ops: 'start' launches it (args as an array, no shell) with an optional ready-gate that blocks until a log line matches or a TCP port opens; 'logs' tails output by cursor with a grep filter (no re-reading); 'wait' blocks until it exits / a pattern appears / a timeout; 'stop' sends a signal; 'ps' lists processes with pid+status; 'send' writes to stdin.",
    parameters: {
      op: { type: "string", description: "start | logs | wait | stop | ps | send" },
      name: { type: "string", description: "Stable handle for the process (required for all ops except ps)." },
      command: { type: "string", description: "start: the executable to run (no shell; use args for arguments)." },
      args: { type: "array", items: { type: "string" }, description: "start: argument vector (no shell quoting)." },
      cwd: { type: "string", description: "start: working directory." },
      ready_log: { type: "string", description: "start: regex; block until a stdout/stderr line matches (ready-gate)." },
      ready_port: { type: "number", description: "start: TCP port; block until it accepts connections (ready-gate)." },
      ready_timeout_s: { type: "number", description: "start: ready-gate timeout in seconds (default 30, max 300)." },
      cursor: { type: "number", description: "logs: resume offset from a previous logs call (0 = from the start)." },
      grep: { type: "string", description: "logs: regex to filter lines." },
      limit: { type: "number", description: "logs: max lines to return." },
      wait_for: { type: "string", description: "wait: 'exit' or 'ready'." },
      pattern: { type: "string", description: "wait: regex over new output that satisfies the wait." },
      timeout_s: { type: "number", description: "wait: timeout in seconds (default 30, max 300)." },
      signal: { type: "string", description: "stop: TERM | KILL | INT | HUP (default TERM)." },
      text: { type: "string", description: "send: text to write to the process stdin." },
    },
    required: ["op"],
  },

  spawn_persistent_agent: {
    name: "spawn_persistent_agent",
    description:
      "Spawn a LONG-LIVED teammate agent that runs a task, then PARKS (stays alive and addressable) instead of finishing. Message it with send_message to REVIVE it for follow-up work — it keeps its place in the roster between messages. Use for an ongoing collaborator you coordinate with over time; for a one-shot task use spawn_agent. Returns the agent's id and name immediately and runs in the background.",
    parameters: {
      task: { type: "string", description: "The initial task for the persistent agent. Be specific: target, goal, and what to report back." },
      name: { type: "string", description: "Optional display name (else an auto AdjectiveNoun name is assigned)." },
      max_turns: { type: "number", description: "Turn budget per task/revive (default 15, max 25)." },
    },
    required: ["task"],
  },

  self_extend: {
    name: "self_extend",
    description:
      "Register NEW model-authored tools into THIS session (the 'it builds itself' capability). " +
      "Additive-only and session-scoped: registered tools live in memory for this session, are never " +
      "written to disk, and never affect another session. Off unless the operator enabled " +
      "`allowModelSelfExtension` — when disabled this tool is absent or refuses. " +
      "Submit a plugin `manifest` naming the tools to add. Each tool MUST declare `capabilities` " +
      "(non-empty; one or more of: network, filesystem-read, filesystem-write, process-exec, findings-write) — " +
      "those declared capabilities become the tool's authorization gate, so a self-authored tool can never " +
      "grant itself more capability than it declares. A tool name may not shadow a built-in. Per-session limits " +
      "apply (at most 8 extensions, 8 tools per extension, 32 tools total, 16KiB per manifest); an over-limit or " +
      "malformed submission is rejected with an error and registers nothing.",
    parameters: {
      manifest: {
        type: "object",
        description:
          "The plugin manifest. Shape: { id: string (lowercase dotted id, e.g. \"scan.sqli-pack\"), " +
          "name: string, version: string (\"MAJOR.MINOR.PATCH\"), tools: [ { name: string (lowercase [a-z0-9_], " +
          "no built-in collision), description: string, parameters: object (JSON-schema properties bag), " +
          "required?: string[], capabilities: string[] (non-empty) } ] }.",
      },
    },
    required: ["manifest"],
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

// Tool-name → ToolExecutor handler-method name (0sec#614). Co-located with
// this domain's definitions so a new tool adds its route here, not in a
// shared dispatch switch. Assembled by ./dispatch.ts; resolved off the
// executor instance in agent/tools.ts (handler bodies stay private methods).
export const systemDispatch: Record<string, string> = {
  read_file: "readFile",
  list_files: "listFiles",
  search_files: "searchFiles",
  str_replace: "strReplace",
  run_command: "runCommand",
  update_target: "updateTarget",
  bash: "shellExec",
  spawn_agent: "spawnAgent",
  spawn_agents: "spawnAgents",
  spawn_persistent_agent: "spawnPersistentAgent",
  monitor: "monitor",
  pty_session: "ptySession",
  plan: "planTool",
  self_extend: "selfExtend",
};

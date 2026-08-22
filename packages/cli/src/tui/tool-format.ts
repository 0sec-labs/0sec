/**
 * Operator-facing tool-activity formatting.
 *
 * The console transcript used to print each tool call as its raw JSON
 * arguments and a truncated JSON result blob. An operator watching a scan
 * therefore read `{"query":"child_process","path":"packages/core/src",...}`
 * and a half-cut `{"matches":[{"path":"...` — neither of which answers the
 * only questions they have: what is this call doing, and did it find anything?
 *
 * This module turns a (call, result) pair into short, readable, single-line
 * text. It is PURE: no I/O, no `process`, no printing, no throwing. Every
 * public function is total over its input — `arguments` may be a string, null,
 * an array, or malformed JSON, and `output` may be any shape at all.
 *
 * The per-tool summaries below are derived from the ACTUAL argument and result
 * shapes in `@0sec/core`'s agent/tools registry (see the header comment on each
 * case for where the shape was read). Anything we could not pin to a source
 * shape falls through to the generic key=value / count path rather than
 * guessing — a wrong count is worse than an honest generic one.
 */

import { fitTuiText, sanitizeTuiText } from "./text.js";

export interface ToolCallLike {
  name: string;
  arguments?: unknown;
}

export interface ToolResultLike {
  success: boolean;
  output?: unknown;
  error?: string | null;
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/**
 * Hard ceiling on every string this module returns. The transcript renders
 * these on a single line next to a status glyph, so a value that ran to the
 * width of a 50 kB argument would wrap or clip the whole row. `fitTuiText`
 * also strips control characters and collapses whitespace, so a bounded return
 * is additionally guaranteed single-line and blob-free.
 */
export const MAX_SUMMARY_CHARS = 120;

/** Detail lines sit under the summary; keep each shorter than the summary. */
const MAX_DETAIL_CHARS = 100;
const DEFAULT_DETAIL_LINES = 3;

/**
 * Per-value budget inside a multi-field summary (generic key=value list, save
 * finding, etc.). Smaller than the line cap so several fields can share a line.
 */
const VALUE_BUDGET = 48;

// ---------------------------------------------------------------------------
// Secrets discipline
// ---------------------------------------------------------------------------

/**
 * Keys whose VALUE is treated as credential-bearing and replaced before it can
 * reach the transcript. Matched case-insensitively as a substring of the key,
 * so `Authorization`, `X-API-Key`, `sessionToken`, and `db_password` are all
 * covered. The doctrine here is "when in doubt, redact": a bare `auth` or
 * `key` will over-match a few innocent keys, and that is the intended trade —
 * a redacted description of a real field beats leaking a bearer token into a
 * durable log.
 */
const CREDENTIAL_KEY_PATTERN =
  /(authorization|auth|bearer|api[\W_]*key|access[\W_]*key|secret|password|passwd|pwd|token|cookie|session|credential|private[\W_]*key|client[\W_]*secret|passphrase|x[\W_]*api[\W_]*key)/i;

const REDACTED = "[redacted]";

function isCredentialKey(key: string): boolean {
  return CREDENTIAL_KEY_PATTERN.test(key);
}

// ---------------------------------------------------------------------------
// Defensive accessors — total over any input, never throw
// ---------------------------------------------------------------------------

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Coerce a tool call's `arguments` into a record we can read fields off.
 * `arguments` reaches us as whatever the model/provider produced: an object in
 * the happy path, but also a JSON string, a bare string, null, or an array. A
 * JSON string that parses to an object is unwrapped; everything else yields an
 * empty record so field lookups are safe no-ops (the raw value is still
 * available to the generic path via {@link rawArguments}).
 */
function argRecord(value: unknown): Record<string, unknown> {
  if (isPlainObject(value)) return value;
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      if (isPlainObject(parsed)) return parsed;
    } catch {
      /* not JSON — fall through to empty record */
    }
  }
  return {};
}

function str(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return undefined;
}

function num(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function arr(value: unknown): unknown[] | undefined {
  return Array.isArray(value) ? value : undefined;
}

// ---------------------------------------------------------------------------
// Presentation helpers
// ---------------------------------------------------------------------------

/** Sanitize + cap to the summary line ceiling. */
function line(value: unknown): string {
  return fitTuiText(value, MAX_SUMMARY_CHARS);
}

/** Sanitize + cap a value fragment, keeping the middle of long paths/URLs. */
function frag(value: unknown, budget = VALUE_BUDGET): string {
  return fitTuiText(value, budget, { mode: "middle" });
}

/** Human byte size, e.g. `312 B`, `4.2 kB`, `1.3 MB`. */
function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "0 B";
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} kB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** UTF-8 byte length; falls back to code-unit count if TextEncoder is absent. */
function byteLength(text: string): number {
  try {
    return new TextEncoder().encode(text).length;
  } catch {
    return text.length;
  }
}

function countLines(text: string): number {
  if (text.length === 0) return 0;
  let n = 1;
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

/**
 * A single flat token for an arbitrary value, WITHOUT recursing — a scanner
 * result can carry cyclic or megabyte-deep objects, and `JSON.stringify` would
 * throw on the former and blow the line budget on the latter. Containers
 * collapse to their size; scalars render (redacted when the key demands it).
 */
function briefValue(key: string, value: unknown): string {
  if (isCredentialKey(key)) return REDACTED;
  if (value === null || value === undefined) return "";
  if (Array.isArray(value)) return `[${value.length}]`;
  if (typeof value === "object") return `{${Object.keys(value as object).length}}`;
  return frag(str(value) ?? "");
}

/**
 * Render a record as `key=value` fragments, most-salient first. "Salient" is a
 * fixed priority list of the fields an operator cares about across tools
 * (target/url/path/command/…); the rest follow in insertion order. Longest
 * values are already bounded by {@link briefValue}.
 */
const SALIENT_KEYS = [
  "url",
  "path",
  "query",
  "command",
  "task",
  "binary_path",
  "title",
  "name",
  "action",
  "target",
  "method",
  "id",
];

function kvSummary(record: Record<string, unknown>, maxPairs = 4): string {
  const keys = Object.keys(record);
  keys.sort((a, b) => {
    const ia = SALIENT_KEYS.indexOf(a);
    const ib = SALIENT_KEYS.indexOf(b);
    const ra = ia === -1 ? Number.MAX_SAFE_INTEGER : ia;
    const rb = ib === -1 ? Number.MAX_SAFE_INTEGER : ib;
    return ra - rb;
  });

  const pairs: string[] = [];
  for (const key of keys) {
    if (pairs.length >= maxPairs) break;
    const rendered = briefValue(key, record[key]);
    if (rendered === "") continue;
    pairs.push(`${key}=${rendered}`);
  }
  return line(pairs.join(" "));
}

/** Distinct entries of `field` across an array of result rows. */
function distinctCount(rows: unknown[], field: string): number {
  const seen = new Set<string>();
  for (const row of rows) {
    if (isPlainObject(row)) {
      const v = row[field];
      if (typeof v === "string") seen.add(v);
    }
  }
  return seen.size;
}

// ---------------------------------------------------------------------------
// formatToolArgs
// ---------------------------------------------------------------------------

/**
 * One-line summary of what a call is about to do.
 *
 * Each covered case reads the argument schema of the matching tool in
 * `@0sec/core` agent/tools; unknown tools use {@link kvSummary}.
 */
export function formatToolArgs(call: ToolCallLike): string {
  const name = typeof call?.name === "string" ? call.name : "";
  const a = argRecord(call?.arguments);

  switch (name) {
    // search_files — args { query, path?, case_sensitive?, max_results? }
    // (packages/core/src/agent/tools/system.ts). Matches the transcript sample
    // exactly: `"child_process" in packages/core/src`.
    case "search_files": {
      const query = str(a.query) ?? "";
      const path = str(a.path);
      const q = `"${query}"`;
      return line(path ? `${q} in ${path}` : q);
    }

    // list_files — args { path?, limit? }.
    case "list_files": {
      const path = str(a.path);
      return line(path ?? "(scope root)");
    }

    // read_file — args { path, max_lines?, offset? }. Offset is 1-based.
    case "read_file": {
      const path = frag(str(a.path) ?? "", 90);
      const offset = num(a.offset);
      return line(offset && offset > 1 ? `${path} @${offset}` : path);
    }

    // run_command — args { command, cwd?, timeout? }.
    case "run_command":
    case "bash": {
      return line(str(a.command) ?? "(no command)");
    }

    // http_request — args { url, method?, body?, headers? }. Method defaults to
    // POST server-side (recon.ts). Headers can carry credentials → never shown
    // here; only method + url are.
    case "http_request": {
      const method = (str(a.method) ?? "POST").toUpperCase();
      const url = frag(str(a.url) ?? "", 90);
      return line(`${method} ${url}`);
    }

    // apply_patch — arg { patch } is a string envelope; count its file ops
    // (Add/Update/Delete File markers) rather than dumping the DSL.
    case "apply_patch": {
      const patch = str(a.patch) ?? "";
      const ops = (patch.match(/^\*\*\*\s+(Add|Update|Delete)\s+File:/gim) ?? []).length;
      return line(ops > 0 ? `${plural(ops, "file")}` : "patch");
    }

    // save_finding — args { title, severity, category, ... }.
    case "save_finding": {
      const severity = str(a.severity);
      const category = str(a.category);
      const title = str(a.title);
      const head = [severity, category].filter(Boolean).join(" ");
      if (title && head) return line(`${head}: ${title}`);
      return line(title ?? head ?? "finding");
    }

    // spawn_agent — args { task, max_turns? }.
    case "spawn_agent": {
      return line(str(a.task) ?? "(no task)");
    }

    // spawn_agents — args { tasks: Array<{ task, max_turns? }> }.
    case "spawn_agents": {
      const tasks = arr(a.tasks) ?? [];
      const first = tasks.length > 0 && isPlainObject(tasks[0]) ? str(tasks[0].task) : undefined;
      const count = plural(tasks.length, "agent");
      return line(first ? `${count}: ${frag(first, 70)}` : count);
    }

    // analyze_binary — args { binary_path, bug_class?, backend?, timeout_s? }
    // (packages/core/src/agent/tools/0verse.ts).
    case "analyze_binary": {
      const path = frag(str(a.binary_path) ?? "", 80);
      const bugClass = str(a.bug_class);
      return line(bugClass ? `${path} (${bugClass})` : path);
    }

    default: {
      // Unknown tool: fall back to the generic key=value summary. A bare/JSON
      // string that did not parse to a record is shown directly (bounded),
      // which beats an empty summary for tools we have not modelled.
      const summary = kvSummary(a);
      if (summary) return summary;
      if (typeof call?.arguments === "string") return line(call.arguments);
      return "";
    }
  }
}

// ---------------------------------------------------------------------------
// formatToolResult
// ---------------------------------------------------------------------------

/**
 * One-line summary of the OUTCOME of a call.
 *
 * Failures are first-class: when `success` is false the line leads with the
 * failure and carries the error text, trimmed to one bounded line — the
 * operator never has to expand a detail view to learn a call failed.
 */
export function formatToolResult(call: ToolCallLike, result: ToolResultLike): string {
  if (!result || result.success !== true) {
    const err = str(result?.error) ?? "";
    return line(err ? `failed: ${err}` : "failed");
  }

  const name = typeof call?.name === "string" ? call.name : "";
  const out = result.output;

  switch (name) {
    // search_files → { matches: Array<{ path, line, content }>, truncated }
    // (packages/core/src/agent/tools/scoped-source.ts).
    case "search_files": {
      if (isPlainObject(out)) {
        const matches = arr(out.matches) ?? [];
        const files = distinctCount(matches, "path");
        const base = `${plural(matches.length, "match", "matches")} in ${plural(files, "file")}`;
        return line(out.truncated === true ? `${base} (truncated)` : base);
      }
      return genericResult(out);
    }

    // list_files → { files: string[], truncated }.
    case "list_files": {
      if (isPlainObject(out)) {
        const files = arr(out.files) ?? [];
        const base = plural(files.length, "file");
        return line(out.truncated === true ? `${base} (truncated)` : base);
      }
      return genericResult(out);
    }

    // read_file → { content, totalLines, truncated, startLine, endLine, ... }.
    case "read_file": {
      if (isPlainObject(out)) {
        const total = num(out.totalLines);
        if (total !== undefined) {
          const base = plural(total, "line");
          return line(out.truncated === true ? `${base} (windowed)` : base);
        }
      }
      return genericResult(out);
    }

    // run_command / bash → output is a plain string (executePipeline returns
    // stdout). Summarize its size so a big grep does not paste into the log.
    case "run_command":
    case "bash": {
      const text = str(out) ?? "";
      if (text.trim().length === 0) return line("no output");
      return line(`${plural(countLines(text), "line")} · ${formatBytes(byteLength(text))}`);
    }

    // http_request → { status, headers, body, waf? }. Body is already
    // credential-redacted server-side; we report status + body size.
    case "http_request": {
      if (isPlainObject(out)) {
        const status = num(out.status);
        const body = str(out.body) ?? "";
        const size = formatBytes(byteLength(body));
        const waf = isPlainObject(out.waf) && out.waf.blocked === true ? " · WAF blocked" : "";
        return line(`${status ?? "?"} · ${size}${waf}`);
      }
      return genericResult(out);
    }

    // apply_patch → { applied: Array<{ kind, path }> }.
    case "apply_patch": {
      if (isPlainObject(out)) {
        const applied = arr(out.applied) ?? [];
        return line(`${plural(applied.length, "file")} patched`);
      }
      return genericResult(out);
    }

    // save_finding → { findingId, message }.
    case "save_finding": {
      if (isPlainObject(out)) {
        const id = str(out.findingId);
        return line(id ? `saved ${id}` : "saved");
      }
      return genericResult(out);
    }

    // spawn_agent → { turns, findings, summary, done }.
    case "spawn_agent": {
      if (isPlainObject(out)) {
        const findings = num(out.findings) ?? 0;
        const turns = num(out.turns) ?? 0;
        return line(`${plural(findings, "finding")} in ${plural(turns, "turn")}`);
      }
      return genericResult(out);
    }

    // spawn_agents → { spawned, succeeded, failed, agents }.
    case "spawn_agents": {
      if (isPlainObject(out)) {
        const spawned = num(out.spawned) ?? 0;
        const ok = num(out.succeeded) ?? 0;
        const failed = num(out.failed) ?? 0;
        return line(`${plural(spawned, "agent")}: ${ok} ok, ${failed} failed`);
      }
      return genericResult(out);
    }

    // analyze_binary → { confirmed: [], hypotheses: [], note, stats, ... }.
    case "analyze_binary": {
      if (isPlainObject(out)) {
        const confirmed = (arr(out.confirmed) ?? []).length;
        const hypotheses = (arr(out.hypotheses) ?? []).length;
        return line(`${confirmed} confirmed, ${hypotheses} hypotheses`);
      }
      return genericResult(out);
    }

    default:
      return genericResult(out);
  }
}

/**
 * Generic result summary for unknown tools / unexpected shapes. Prefers a
 * count of array entries or object keys over the underlying text — the whole
 * point of this module is to never repaint a JSON blob.
 */
function genericResult(out: unknown): string {
  if (out === null || out === undefined) return line("ok");
  if (Array.isArray(out)) return line(plural(out.length, "item"));
  if (typeof out === "string") {
    if (out.trim().length === 0) return line("ok");
    return line(`${plural(countLines(out), "line")} · ${formatBytes(byteLength(out))}`);
  }
  if (typeof out === "object") return line(plural(Object.keys(out as object).length, "field"));
  return line(str(out) ?? "ok");
}

// ---------------------------------------------------------------------------
// toolResultDetail
// ---------------------------------------------------------------------------

/**
 * Extra detail lines shown UNDER the summary; may be empty. Bounded to
 * `maxLines` short lines. Only the tools where a couple of concrete rows help
 * an operator triage (which files matched, which child failed) return detail;
 * everything else returns `[]` deliberately.
 */
export function toolResultDetail(
  call: ToolCallLike,
  result: ToolResultLike,
  maxLines = DEFAULT_DETAIL_LINES,
): string[] {
  const cap = Number.isFinite(maxLines) ? Math.max(0, Math.trunc(maxLines)) : DEFAULT_DETAIL_LINES;
  if (cap === 0) return [];
  if (!result || result.success !== true) return [];

  const name = typeof call?.name === "string" ? call.name : "";
  const out = result.output;
  const detail = (value: unknown): string => fitTuiText(value, MAX_DETAIL_CHARS, { mode: "middle" });

  switch (name) {
    // Show where the first matches landed, `path:line`.
    case "search_files": {
      if (!isPlainObject(out)) return [];
      const matches = arr(out.matches) ?? [];
      const lines: string[] = [];
      for (const m of matches) {
        if (lines.length >= cap) break;
        if (isPlainObject(m)) {
          const path = str(m.path) ?? "?";
          const ln = num(m.line);
          lines.push(detail(ln !== undefined ? `${path}:${ln}` : path));
        }
      }
      return lines;
    }

    // Show the first files listed.
    case "list_files": {
      if (!isPlainObject(out)) return [];
      const files = arr(out.files) ?? [];
      return files.slice(0, cap).map((f) => detail(str(f) ?? "?"));
    }

    // Show each patched file with its op kind.
    case "apply_patch": {
      if (!isPlainObject(out)) return [];
      const applied = arr(out.applied) ?? [];
      const lines: string[] = [];
      for (const op of applied) {
        if (lines.length >= cap) break;
        if (isPlainObject(op)) {
          const kind = str(op.kind) ?? "edit";
          const path = str(op.path) ?? "?";
          lines.push(detail(`${kind} ${path}`));
        }
      }
      return lines;
    }

    // Surface any child agent that failed, so a partial fan-out is visible.
    case "spawn_agents": {
      if (!isPlainObject(out)) return [];
      const agents = arr(out.agents) ?? [];
      const lines: string[] = [];
      for (const child of agents) {
        if (lines.length >= cap) break;
        if (isPlainObject(child) && child.ok === false) {
          lines.push(detail(`agent ${str(child.index) ?? "?"} failed: ${str(child.error) ?? ""}`));
        }
      }
      return lines;
    }

    // Confirmed PoVs are the operator's headline; list their titles.
    case "analyze_binary": {
      if (!isPlainObject(out)) return [];
      const confirmed = arr(out.confirmed) ?? [];
      const lines: string[] = [];
      for (const f of confirmed) {
        if (lines.length >= cap) break;
        if (isPlainObject(f)) {
          const title = str(f.title) ?? str(f.bug_class) ?? sanitizeTuiText(f);
          lines.push(detail(title));
        }
      }
      return lines;
    }

    default:
      return [];
  }
}

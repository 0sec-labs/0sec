/**
 * XML-tag dispatch fallback for cheap-model resilience (0sec#232).
 *
 * Cheap OpenRouter models (DeepSeek, Gemini-flash, etc.) routinely emit
 * malformed JSON tool calls under load — strings break, brackets stay
 * unbalanced, etc. The native JSON dispatch path then fails on the protocol
 * violation and the loop wastes turns retrying the format error rather
 * than the challenge.
 *
 * This module provides a SIBLING dispatch mode that uses XML-style tags
 * the model can produce reliably even when its JSON is broken:
 *
 *   <command>curl -s http://target/admin</command>
 *   <flag>FLAG{...}</flag>
 *   <finding>title: ...; severity: ...; evidence: ...</finding>  (optional)
 *   <note>free-form scratch note</note>                          (optional)
 *
 * Tool results are wrapped back as `<output>...</output>`.
 *
 * Mirrors BoxPwnr's `single_loop_xmltag.py`. Their claim: works with all
 * models including Gemini, OpenAI, and Anthropic.
 *
 * Selection: `AgentConfig.dispatchMode === "xml"` opts in. `"auto"` (the
 * default in callers that pass it through) picks XML when the model name
 * matches `gemini|deepseek|openrouter` (substring), JSON otherwise.
 *
 * IMPORTANT: this is additive to the JSON path, NOT a replacement. Models
 * that emit JSON correctly should keep using JSON.
 */

import type { ToolCall, ToolDefinition } from "./types.js";

export type DispatchMode = "json" | "xml" | "auto";

// ── Auto-detection ──

/**
 * Resolve "auto" against a model identifier. Substring match keeps this
 * simple — full slug matrix would be brittle as new providers ship.
 *
 * Matches: gemini, deepseek, openrouter, qwen, mistral, llama (the
 * cohort that BoxPwnr identified as needing the XML fallback).
 */
export function resolveDispatchMode(
  mode: DispatchMode | undefined,
  modelHint: string | undefined,
): "json" | "xml" {
  if (mode === "xml" || mode === "json") return mode;
  // env override wins over auto; respected here so callers don't have
  // to re-implement it at every entry point.
  const env = process.env["0SEC_DISPATCH"];
  if (env === "xml" || env === "json") return env;
  if (!modelHint) return "json";
  const m = modelHint.toLowerCase();
  if (
    m.includes("gemini") ||
    m.includes("deepseek") ||
    m.includes("openrouter") ||
    m.includes("qwen") ||
    m.includes("mistral") ||
    m.includes("llama")
  ) {
    return "xml";
  }
  return "json";
}

// ── Parser ──

/** Result of parsing a single assistant turn under XML dispatch. */
export interface XmlDispatchParse {
  /** Tool calls extracted, in the order the loop should dispatch them. */
  calls: ToolCall[];
  /** Free-form notes. Not dispatched; kept for logging / state inspection. */
  notes: string[];
  /**
   * If the response had an unclosed `<command>` / `<flag>` / `<finding>` /
   * `<note>` tag, this carries a clear, terminal error. The loop should
   * surface it back to the model rather than silently corrupting state.
   */
  error?: string;
}

const TAG_NAMES = ["command", "flag", "finding", "note"] as const;
type TagName = (typeof TAG_NAMES)[number];

interface RawTag {
  tag: TagName;
  body: string;
  /** Position of the opening `<tag>` in the source text. */
  start: number;
}

/**
 * Find every closed `<tag>...</tag>` for our four supported tags, in
 * source order. Greedy/lazy semantics: each match captures the SHORTEST
 * body that closes the tag, so `<command>a</command><command>b</command>`
 * yields two distinct calls instead of one big blob.
 */
function findTags(text: string): RawTag[] {
  const out: RawTag[] = [];
  for (const tag of TAG_NAMES) {
    const re = new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      out.push({ tag, body: m[1], start: m.index });
    }
  }
  out.sort((a, b) => a.start - b.start);
  return out;
}

/**
 * Detect an opening tag with no matching closer. We look for `<tag>` whose
 * position is past the last successful close — that's the diagnostic the
 * issue spec calls out ("given a response with unclosed `<command>`, fail
 * with a clear error").
 */
function findUnclosed(text: string): TagName | null {
  for (const tag of TAG_NAMES) {
    const openRe = new RegExp(`<${tag}>`, "g");
    const closeRe = new RegExp(`<\\/${tag}>`, "g");
    const opens: number[] = [];
    const closes: number[] = [];
    let m: RegExpExecArray | null;
    while ((m = openRe.exec(text)) !== null) opens.push(m.index);
    while ((m = closeRe.exec(text)) !== null) closes.push(m.index);
    if (opens.length > closes.length) return tag;
  }
  return null;
}

/**
 * Parse a model response under XML dispatch into tool calls.
 *
 * Precedence rules (mirrors BoxPwnr):
 *  - `<flag>` is checked FIRST. If a flag tag is present, the loop stops
 *    further dispatch in this turn and routes the flag to the `done` tool.
 *    This matters because a model that finds the flag mid-thought
 *    sometimes emits both a stray `<command>` and a `<flag>`; the flag is
 *    the answer and must win.
 *  - Otherwise: every `<command>` becomes a `bash` call, in source order.
 *  - `<finding>` becomes `save_finding` (best-effort parsing of
 *    `key: value` pairs).
 *  - `<note>` is NOT dispatched — kept on the parse result for logging.
 *
 * Errors:
 *  - Unclosed `<command>` / `<flag>` / `<finding>` / `<note>`: the parser
 *    flags the response with a terminal `error` so the loop surfaces a
 *    clear protocol violation instead of silently dropping or guessing.
 */
export function parseXmlDispatch(text: string): XmlDispatchParse {
  const unclosed = findUnclosed(text);
  if (unclosed) {
    return {
      calls: [],
      notes: [],
      error: `Unclosed <${unclosed}> tag. Every <${unclosed}> must be terminated with </${unclosed}>. Re-emit the full response with balanced tags.`,
    };
  }

  const tags = findTags(text);

  // Flag-first: if any <flag> was emitted in this turn, the rest is moot.
  // We still capture preceding <note>s for logging so the model's reasoning
  // doesn't vanish, but we do NOT dispatch <command>s after a flag.
  const flagTag = tags.find((t) => t.tag === "flag");
  if (flagTag) {
    const flag = flagTag.body.trim();
    const notes = tags.filter((t) => t.tag === "note").map((t) => t.body.trim());
    return {
      calls: [
        {
          name: "done",
          arguments: {
            summary: `Flag captured: ${flag}`,
            flag,
          },
        },
      ],
      notes,
    };
  }

  const calls: ToolCall[] = [];
  const notes: string[] = [];

  for (const t of tags) {
    if (t.tag === "command") {
      const command = t.body.trim();
      if (command.length === 0) continue;
      calls.push({ name: "bash", arguments: { command } });
    } else if (t.tag === "finding") {
      const args = parseFindingBody(t.body);
      if (args) {
        calls.push({ name: "save_finding", arguments: args });
      }
    } else if (t.tag === "note") {
      notes.push(t.body.trim());
    }
  }

  return { calls, notes };
}

/**
 * Best-effort parser for `<finding>` bodies. The model is instructed to
 * write `key: value; key: value` pairs; we accept newline-separated form
 * too. Unknown keys are dropped. If the body has neither `title` nor
 * `evidence`, we discard it — partial findings are noise.
 */
function parseFindingBody(body: string): Record<string, unknown> | null {
  const out: Record<string, unknown> = {};
  // Normalise: split on `;` OR newline, since both arrive in the wild.
  const segments = body
    .split(/[;\n]/)
    .map((s) => s.trim())
    .filter(Boolean);
  for (const seg of segments) {
    const idx = seg.indexOf(":");
    if (idx === -1) continue;
    const key = seg.slice(0, idx).trim().toLowerCase();
    const value = seg.slice(idx + 1).trim();
    if (!key || !value) continue;
    if (
      key === "title" ||
      key === "severity" ||
      key === "category" ||
      key === "evidence" ||
      key === "evidence_request" ||
      key === "evidence_response"
    ) {
      out[key] = value;
    }
  }
  if (!out.title && !out.evidence && !out.evidence_request) return null;
  // The save_finding tool expects evidence_request/evidence_response;
  // map a single `evidence` field into evidence_response so cheap models
  // don't have to remember both.
  if (out.evidence && !out.evidence_response) {
    out.evidence_response = out.evidence;
    delete out.evidence;
  }
  return out;
}

// ── Output formatter ──

/**
 * Format a tool execution result back into the XML dispatch protocol.
 *
 * BoxPwnr wraps every shell result in `<output>...</output>`. We do the
 * same, plus prefix the tool name and OK/ERROR status so the agent can
 * distinguish bash output from save_finding ack from done ack.
 *
 * Long outputs are truncated at 8 KB to protect the context window — the
 * threshold is generous enough that `curl -i` and `find /` still fit
 * unaltered, but a runaway `cat /var/log/...` won't blow up the chat.
 */
export function formatXmlOutput(
  toolName: string,
  result: { success: boolean; output: unknown; error?: string },
  opts: { maxBytes?: number } = {},
): string {
  const maxBytes = opts.maxBytes ?? 8192;
  const status = result.success ? "OK" : "ERROR";
  const raw = result.error ?? stringify(result.output);
  const body = raw.length > maxBytes ? `${raw.slice(0, maxBytes)}\n[... truncated ${raw.length - maxBytes} bytes ...]` : raw;
  return `<output tool="${toolName}" status="${status}">\n${body}\n</output>`;
}

function stringify(v: unknown): string {
  if (typeof v === "string") return v;
  if (v == null) return "";
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

// ── System prompt builder ──

/**
 * Build the XML-dispatch system prompt block. Concatenates onto the
 * caller's own role / scope prose so the loop doesn't need to know what
 * the agent is for — it just appends the protocol instructions.
 *
 * `tools` is the same list the JSON dispatcher receives; we only surface
 * the four protocol verbs (`bash`, `save_finding`, `done`, plus a free
 * `<note>` channel) to the model since BoxPwnr's experience shows that
 * narrowing the action space is what makes XML dispatch reliable.
 */
export function buildXmlDispatchPrompt(opts: {
  role: string;
  target: string;
  scanId: string;
  tools: ToolDefinition[];
}): string {
  const { role, target, scanId } = opts;
  return [
    `You are a ${role} agent for 0sec, an AI red-teaming toolkit.`,
    `Target: ${target}`,
    `Scan ID: ${scanId}`,
    "Authorization: The operator has confirmed this target is owned by them or explicitly authorized for this assessment.",
    "Scope: Non-destructive security testing only. Do not perform denial of service, persistence, credential abuse, or destructive actions.",
    "",
    "## Output Protocol — XML Tags",
    "",
    "Emit your actions using ONLY these four XML tags. The harness parses with a strict regex; any other format is ignored.",
    "",
    "<command>SHELL_COMMAND_HERE</command>",
    "  Run a shell command (curl, python3, jq, nmap, etc.). One <command> per shell invocation. Multiple <command> tags in a single response will be executed in order.",
    "",
    "<flag>FLAG_VALUE_HERE</flag>",
    "  You found the flag. Emit the verbatim flag string. This terminates the run; do NOT mix with <command> in the same turn.",
    "",
    "<finding>title: ...; severity: critical|high|medium|low; category: ...; evidence: ...</finding>",
    "  Optional. Record a finding without ending the run. `;` separates fields.",
    "",
    "<note>FREE_FORM_NOTE</note>",
    "  Optional. Scratch reasoning. Not dispatched; logged only.",
    "",
    "## Rules",
    "- Tags must be balanced: every `<command>` must have a matching `</command>`. Unclosed tags fail the turn.",
    "- A single `<flag>` always wins over any `<command>` in the same response.",
    "- Do NOT wrap tags in code fences (no ```xml). Emit them inline.",
    "- Tool results are returned wrapped in `<output tool=\"...\" status=\"...\">...</output>`.",
    "",
    "## Example",
    "",
    "<note>probing the admin panel for default creds</note>",
    "<command>curl -s -u admin:admin http://target/admin/</command>",
    "",
    "After the harness returns:",
    "",
    "<output tool=\"bash\" status=\"OK\">",
    "HTTP/1.1 200 OK",
    "...",
    "</output>",
  ].join("\n");
}

// ── Multi-turn output joiner ──

/**
 * Join multiple tool results into a single user message for the model.
 * Kept here (rather than inlined in the loop) so callers and tests share
 * exactly the same wire format.
 */
export function formatXmlOutputBatch(
  results: Array<{ name: string; result: { success: boolean; output: unknown; error?: string } }>,
): string {
  return results.map((r) => formatXmlOutput(r.name, r.result)).join("\n\n");
}

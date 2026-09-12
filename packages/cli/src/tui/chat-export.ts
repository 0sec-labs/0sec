import { chmodSync, closeSync, mkdtempSync, openSync, rmdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

type PublicBlock =
  | { type: "text"; text: string }
  | { type: "tool_use"; id: string; name: string; input: Record<string, unknown> }
  | { type: "tool_result"; tool_use_id: string; content: string; is_error?: boolean };

function record(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

// Tool arguments are public JSON data, not a provider message envelope. Reject
// non-JSON values/cycles instead of invoking custom serialization hooks.
function jsonData(value: unknown, ancestors = new Set<object>()): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (!Array.isArray(value) && !record(value)) throw new Error("Non-JSON tool input");
  if (ancestors.has(value)) throw new Error("Cyclic tool input");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) return value.map((item) => jsonData(item, ancestors));
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, jsonData(item, ancestors)]));
  } finally {
    ancestors.delete(value);
  }
}

function publicText(content: unknown): string | undefined {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return undefined;
  const texts = content.flatMap((block) =>
    record(block) && block.type === "text" && typeof block.text === "string" ? [block.text] : [],
  );
  return texts.length ? texts.join("\n") : undefined;
}

function publicBlock(value: unknown): PublicBlock | undefined {
  if (!record(value)) return undefined;
  if (value.type === "text" && typeof value.text === "string") {
    return { type: "text", text: value.text };
  }
  if (value.type === "tool_use" && typeof value.id === "string" && typeof value.name === "string" && record(value.input)) {
    try {
      return { type: "tool_use", id: value.id, name: value.name, input: jsonData(value.input) as Record<string, unknown> };
    } catch {
      return undefined;
    }
  }
  if (value.type === "tool_result" && typeof value.tool_use_id === "string") {
    const content = publicText(value.content);
    if (content === undefined) return undefined;
    return {
      type: "tool_result",
      tool_use_id: value.tool_use_id,
      content,
      ...(typeof value.is_error === "boolean" ? { is_error: value.is_error } : {}),
    };
  }
  return undefined;
}

/** Export all supplied public history, never a viewport or runtime snapshot.
 * Malformed/unsupported messages and blocks are omitted. If none remain, throw
 * before creating a file. Filesystem errors propagate; no false path is returned.
 */
export function exportChatConversation(messages: readonly unknown[]): { text: string; path: string } {
  const publicMessages = messages.flatMap((message) => {
    if (!record(message) || (message.role !== "user" && message.role !== "assistant")) return [];
    const raw = typeof message.content === "string"
      ? [{ type: "text", text: message.content }]
      : Array.isArray(message.content) ? message.content : [];
    const content = raw.flatMap((block) => {
      const projected = publicBlock(block);
      return projected ? [projected] : [];
    });
    return content.length ? [{ role: message.role, content }] : [];
  });
  if (!publicMessages.length) throw new Error("No public conversation content to export.");
  const text = publicMessages.map((message) => {
    const body = message.content.map((block) => {
      if (block.type === "text") return block.text;
      if (block.type === "tool_use") return `Tool: ${block.name} (${block.id})\n${JSON.stringify(block.input, null, 2)}`;
      return `Tool result: ${block.tool_use_id}${block.is_error ? " (error)" : ""}\n${block.content}`;
    }).join("\n\n");
    return `${message.role === "user" ? "User" : "Assistant"}\n${body}`;
  }).join("\n\n");
  const json = JSON.stringify(publicMessages, null, 2);
  const directory = mkdtempSync(join(tmpdir(), "0sec-chat-export-"));
  const path = join(directory, "conversation.json");
  let created = false;
  try {
    chmodSync(directory, 0o700);
    const fd = openSync(path, "wx", 0o600);
    created = true;
    try { writeFileSync(fd, json, { encoding: "utf8" }); } finally { closeSync(fd); }
    return { text, path };
  } catch (error) {
    // Only this invocation's newly created directory/file can be removed.
    if (created) {
      try { rmSync(path, { force: true }); } catch { /* Preserve the original failure. */ }
    }
    try { rmdirSync(directory); } catch { /* Preserve the original failure. */ }
    throw error;
  }
}

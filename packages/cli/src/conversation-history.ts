import { redactSensitiveHeaders, type ConsoleConversationHistory } from "@0sec/core";
import { isValidSessionId, listSessions, loadSession, type StoredSessionMeta } from "./tui/session-store.js";
import { sanitizeComposerText } from "./tui/text.js";

const MAX_PAGE_CHARS = 16_000;
const MAX_MESSAGE_CHARS = 4_000;

function cleanText(value: string): string {
  return redactSensitiveHeaders(sanitizeComposerText(value))
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g, "[private key redacted]")
    .replace(/\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,})\b/g, "[credential redacted]")
    .replace(/((?:[A-Za-z0-9_-]*(?:api[_-]?key|access[_-]?token|password|secret)|authorization|cookie)\s*[=:]\s*)(?:"[^"\n]*"|'[^'\n]*'|[^\s,;]+)/gi, "$1[redacted]");
}

function metadata(session: StoredSessionMeta) {
  return {
    id: session.id,
    savedAt: session.savedAt,
    cwd: cleanText(session.cwd).slice(0, 512),
    target: session.target ? cleanText(session.target).slice(0, 256) : undefined,
    model: session.model ? cleanText(session.model).slice(0, 128) : undefined,
    messageCount: session.messageCount,
    preview: cleanText(session.preview),
    summary: session.summary ? cleanText(session.summary) : undefined,
  };
}

function pageLimit(value: number | undefined): number {
  if (value === undefined) return 20;
  if (!Number.isSafeInteger(value) || value < 1 || value > 100) throw new Error("limit must be an integer from 1 to 100");
  return value;
}

/** Reads the same store as /resume; never exposes provider payloads or tool results. */
export function createConversationHistory(options: { cwd?: string; homeDir?: string } = {}): ConsoleConversationHistory {
  const cwd = options.cwd ?? process.cwd();
  return {
    list({ query, allProjects, limit }) {
      const count = pageLimit(limit);
      if (query !== undefined && (typeof query !== "string" || query.length > 256)) throw new Error("Invalid conversation search query");
      if (allProjects !== undefined && typeof allProjects !== "boolean") throw new Error("allProjects must be a boolean");
      const needle = query?.trim().toLowerCase();
      const matches = listSessions(options.homeDir, { cwd: allProjects ? undefined : cwd })
        .map(metadata)
        .filter(session => !needle || [session.id, session.cwd, session.target, session.preview, session.summary]
          .some(value => value?.toLowerCase().includes(needle)));
      return { conversations: matches.slice(0, count), total: matches.length, hasMore: matches.length > count };
    },
    read({ sessionId, offset = 0, limit }) {
      const count = pageLimit(limit);
      if (!isValidSessionId(sessionId)) throw new Error("Invalid saved conversation ID");
      if (!Number.isSafeInteger(offset) || offset < 0) throw new Error("offset must be a nonnegative integer");
      const session = loadSession(sessionId, options.homeDir);
      if (!session) throw new Error(`Saved conversation ${sessionId} was not found or could not be read`);
      const messages: Array<{ index: number; role: "user" | "assistant"; text: string; truncated: boolean }> = [];
      let remaining = MAX_PAGE_CHARS;
      let next = Math.min(offset, session.messages.length);
      const end = Math.min(session.messages.length, next + count);
      for (; next < end && remaining > 0; next++) {
        const message = session.messages[next];
        if (!message || typeof message !== "object") continue;
        const row = message as { role?: unknown; content?: unknown };
        if (row.role !== "user" && row.role !== "assistant") continue;
        const text = typeof row.content === "string" ? row.content : Array.isArray(row.content)
          ? row.content.flatMap(block => block && typeof block === "object" && block.type === "text" && typeof block.text === "string" ? [block.text] : []).join("\n")
          : "";
        if (!text) continue;
        const clean = cleanText(text);
        const budget = Math.min(remaining, MAX_MESSAGE_CHARS);
        const clipped = clean.slice(0, budget);
        messages.push({ index: next, role: row.role, text: clipped, truncated: clean.length > budget });
        remaining -= clipped.length;
      }
      return {
        ...metadata(session),
        messages,
        offset,
        totalMessages: session.messages.length,
        nextOffset: next < session.messages.length ? next : null,
      };
    },
  };
}

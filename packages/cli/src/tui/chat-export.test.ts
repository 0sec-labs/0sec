import { readFileSync, rmSync, statSync } from "node:fs";
import { dirname } from "node:path";
import { describe, expect, it } from "vitest";
import { exportChatConversation } from "./chat-export.js";

describe("public chat export", () => {
  it("preserves complete public history and private permissions without provider state", () => {
    const messages = Array.from({ length: 120 }, (_, i) => ({ role: "user", content: `Message ${i} — 日本語` }));
    const result = exportChatConversation([...messages, {
      role: "assistant", provider_state: "SECRET", content: [
        { type: "thinking", thinking: "SECRET" },
        { type: "text", text: "Public answer", signature: "SECRET" },
        { type: "tool_use", id: "call1", name: "read", input: { path: "example.txt" }, provider: "SECRET" },
        { type: "tool_result", tool_use_id: "call1", is_error: false, content: [
          { type: "text", text: "Public observation", signature: "SECRET" },
          { type: "thinking", text: "SECRET" },
          { type: "image", data: "SECRET" },
        ], internal: "SECRET" },
      ],
    }]);
    try {
      const json = readFileSync(result.path, "utf8");
      const parsed = JSON.parse(json);
      expect(parsed.slice(0, 120).map((m: { content: { text: string }[] }) => m.content[0].text)).toEqual(messages.map(m => m.content));
      expect(parsed[120].content).toEqual([
        { type: "text", text: "Public answer" },
        { type: "tool_use", id: "call1", name: "read", input: { path: "example.txt" } },
        { type: "tool_result", tool_use_id: "call1", is_error: false, content: "Public observation" },
      ]);
      expect(json).not.toContain("SECRET");
      expect(result.text).not.toContain("SECRET");
      expect(result.text).toContain("Message 0 — 日本語");
      expect(result.text).toContain("Message 119 — 日本語");
      expect(statSync(dirname(result.path)).mode & 0o777).toBe(0o700);
      expect(statSync(result.path).mode & 0o777).toBe(0o600);
    } finally { rmSync(dirname(result.path), { recursive: true }); }
  });

  it("omits malformed and cyclic tool data without losing valid observations", () => {
    const cycle: Record<string, unknown> = {}; cycle.self = cycle;
    const result = exportChatConversation([null, { role: "system", content: "PRIVATE" }, {
      role: "user", content: [
        { type: "tool_use", id: "bad", name: "tool", input: cycle },
        { type: "tool_result", tool_use_id: "bad", content: { text: "PRIVATE", reasoning: "PRIVATE" } },
        { type: "tool_result", tool_use_id: "ok", content: "Permission denied", is_error: true },
      ],
    }]);
    try {
      expect(JSON.parse(readFileSync(result.path, "utf8"))).toEqual([{ role: "user", content: [
        { type: "tool_result", tool_use_id: "ok", content: "Permission denied", is_error: true },
      ] }]);
      expect(result.text).toContain("(error)");
    } finally { rmSync(dirname(result.path), { recursive: true }); }
  });

  it("rejects an empty or entirely non-public transcript", () => {
    expect(() => exportChatConversation([])).toThrow("No public conversation");
    expect(() => exportChatConversation([{ role: "assistant", content: [{ type: "thinking", thinking: "private" }] }])).toThrow("No public conversation");
  });
});

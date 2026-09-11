import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createConversationHistory } from "./conversation-history.js";
import { saveSession } from "./tui/session-store.js";

const homes: string[] = [];
function fixture() {
  const home = mkdtempSync(join(tmpdir(), "0sec-conversation-history-"));
  homes.push(home);
  const save = (id: string, cwd: string, messages: unknown[], preview = "") => {
    if (!saveSession({ id, cwd, savedAt: 1, preview, messageCount: messages.length, messages }, home)) throw new Error("Cannot save fixture");
  };
  return { home, save, history: createConversationHistory({ cwd: "/project-a", homeDir: home }) };
}

afterEach(() => {
  for (const home of homes.splice(0)) rmSync(home, { recursive: true, force: true });
});

describe("saved conversation access", () => {
  it("keeps discovery project-local unless explicitly widened and supports search", async () => {
    const { save, history } = fixture();
    save("project-a-chat", "/project-a", [{ role: "user", content: "Review authentication" }], "Review authentication");
    save("project-b-chat", "/project-b", [{ role: "user", content: "Review billing" }], "Review billing");
    expect(await history.list({})).toMatchObject({ conversations: [{ id: "project-a-chat" }], total: 1 });
    expect(await history.list({ allProjects: true, query: "billing" })).toMatchObject({ conversations: [{ id: "project-b-chat" }], total: 1 });
  });

  it("paginates public text while omitting private reasoning, provider payloads and tool results", async () => {
    const { save, history } = fixture();
    save("private-chat", "/project-a", [
      { role: "user", content: "Authorization: Bearer credential-value" },
      { role: "assistant", providerRaw: { token: "raw-secret" }, content: [{ type: "thinking", thinking: "hidden-reasoning" }, { type: "text", text: "Public answer" }, { type: "tool_use", input: { secret: "tool-secret" } }] },
      { role: "user", content: [{ type: "tool_result", content: "tool-response-secret" }] },
      { role: "assistant", content: "Follow-up answer" },
    ]);
    const first = await history.read({ sessionId: "private-chat", limit: 2 });
    expect(first).toMatchObject({ nextOffset: 2, messages: [{ index: 0 }, { index: 1, text: "Public answer" }] });
    const serialized = JSON.stringify(first);
    for (const hidden of ["credential-value", "hidden-reasoning", "raw-secret", "tool-secret", "tool-response-secret"]) expect(serialized).not.toContain(hidden);
    expect(await history.read({ sessionId: "private-chat", offset: 2, limit: 2 })).toMatchObject({ nextOffset: null, messages: [{ index: 3, text: "Follow-up answer" }] });
  });

  it("bounds large transcript pages and rejects invalid IDs and offsets", async () => {
    const { save, history } = fixture();
    save("large-chat", "/project-a", Array.from({ length: 6 }, () => ({ role: "assistant", content: "word ".repeat(2000) })));
    const page = await history.read({ sessionId: "large-chat", limit: 100 }) as { messages: Array<{ text: string; truncated: boolean }>; nextOffset: number };
    expect(page.messages.reduce((sum, message) => sum + message.text.length, 0)).toBeLessThanOrEqual(16_000);
    expect(page.messages.every(message => message.truncated)).toBe(true);
    expect(page.nextOffset).toBe(4);
    expect(() => history.read({ sessionId: "../escape" })).toThrow();
    expect(() => history.read({ sessionId: "large-chat", offset: -1 })).toThrow();
    expect(() => history.read({ sessionId: "missing-chat" })).toThrow();
  });
});

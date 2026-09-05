import { describe, expect, it } from "vitest";
import { connectionRecoveryForError } from "./connection-recovery.js";

describe("connectionRecoveryForError", () => {
  it("routes a broken Codex refresh token into ChatGPT Codex connection", () => {
    const recovery = connectionRecoveryForError(
      "ChatGPT (Codex backend) API error: token refresh failed: 401",
    );
    expect(recovery).toMatchObject({
      providerId: "chatgpt-codex",
      title: "ChatGPT Codex needs to reconnect",
    });
  });

  it("routes every configurable API-key provider to its own credential form", () => {
    for (const [error, providerId] of [
      ["Azure OpenAI API error: invalid credential", "azure"],
      ["Anthropic API error: invalid key", "anthropic"],
      ["OpenRouter HTTP 401", "openrouter"],
      ["DeepSeek API error: invalid key", "deepseek"],
      ["Z.ai GLM API error", "z-ai"],
      ["Moonshot Kimi API error", "kimi"],
      ["Alibaba Model Studio API error", "qwen"],
      ["xAI Grok API error", "xai"],
      ["OpenCode Zen API error", "opencode"],
      ["OpenAI API error: invalid key", "openai"],
    ]) {
      expect(connectionRecoveryForError(error)).toMatchObject({ providerId });
    }
  });

  it("keeps non-provider failures in the transcript", () => {
    expect(connectionRecoveryForError("read_file denied outside approved scope")).toBeNull();
  });
});

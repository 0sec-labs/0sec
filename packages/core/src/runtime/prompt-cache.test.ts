import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  BREAKPOINT_SPACING_BLOCKS,
  CACHE_LOOKBACK_BLOCKS,
  MAX_CACHE_BREAKPOINTS,
  MESSAGE_CACHE_BREAKPOINTS,
  planMessageBreakpoints,
  providerSupportsPromptCache,
  readCacheUsage,
  withCacheControl,
} from "./prompt-cache.js";

/** Build a message carrying `n` placeholder content blocks. */
function msg(n: number): { content: unknown[] } {
  return { content: Array.from({ length: n }, (_, i) => ({ type: "text", text: `b${i}` })) };
}

describe("prompt-cache breakpoint budget", () => {
  it("never plans more breakpoints than the API allows", () => {
    // The 4-breakpoint cap is a hard API limit — a fifth is a request error.
    // One is reserved for tools+system, so messages may use at most 3.
    expect(MESSAGE_CACHE_BREAKPOINTS).toBe(MAX_CACHE_BREAKPOINTS - 1);

    const messages = Array.from({ length: 400 }, () => msg(3));
    const picks = planMessageBreakpoints(messages);
    expect(picks.length).toBeLessThanOrEqual(MESSAGE_CACHE_BREAKPOINTS);
  });

  it("keeps breakpoint spacing under the 20-block lookback window", () => {
    expect(BREAKPOINT_SPACING_BLOCKS).toBeLessThan(CACHE_LOOKBACK_BLOCKS);
  });
});

describe("planMessageBreakpoints", () => {
  it("returns nothing for an empty conversation", () => {
    expect(planMessageBreakpoints([])).toEqual([]);
  });

  it("returns nothing when no budget is available", () => {
    expect(planMessageBreakpoints([msg(1), msg(1)], 0)).toEqual([]);
  });

  it("always marks the growing edge — the newest message", () => {
    const messages = [msg(1), msg(1), msg(1)];
    expect(planMessageBreakpoints(messages)).toContain(messages.length - 1);
  });

  it("spends its single breakpoint on the tail, not the head, when budget is 1", () => {
    // The tail is the only breakpoint that grows with the conversation, so it
    // outranks the head anchor when there is only one to spend.
    expect(planMessageBreakpoints([msg(1), msg(1), msg(1)], 1)).toEqual([2]);
  });

  it("anchors message 0 once budget allows", () => {
    // Message 0 is the task prompt: largest, oldest, and preserved verbatim by
    // compaction, so it is the most valuable static anchor.
    expect(planMessageBreakpoints([msg(1), msg(1), msg(1)])).toEqual([0, 2]);
  });

  it("does not emit redundant bridges on a short conversation", () => {
    // Under the spacing threshold the tail breakpoint can already see the
    // previous entry within the lookback window; extra markers buy nothing.
    const messages = [msg(1), msg(1), msg(1), msg(1)];
    expect(planMessageBreakpoints(messages)).toEqual([0, 3]);
  });

  it("bridges long conversations with a rolling breakpoint behind the tail", () => {
    // 40 single-block messages. A lone tail breakpoint tolerates a turn growth
    // of at most 20 blocks before it can no longer see the previous turn's
    // entry; the bridge sits BREAKPOINT_SPACING_BLOCKS further back and extends
    // that tolerance to ~35.
    const messages = Array.from({ length: 40 }, () => msg(1));
    const picks = planMessageBreakpoints(messages);

    expect(picks).toContain(39);
    // Head anchor at 0, one bridge, and the tail.
    expect(picks).toEqual([0, 24, 39]);

    const blockIndex = (messageIndex: number): number =>
      messages.slice(0, messageIndex + 1).reduce((sum, m) => sum + m.content.length, 0);

    // The ROLLING breakpoints must chain within the lookback window. The head
    // anchor is excluded on purpose: it is pinned to message 0, so its entry is
    // re-found at distance zero every turn and never needs a bridge to reach.
    const rolling = picks.filter((index) => index !== 0);
    expect(rolling.length).toBeGreaterThan(1);
    for (let i = 1; i < rolling.length; i++) {
      const gap = blockIndex(rolling[i]!) - blockIndex(rolling[i - 1]!);
      expect(gap).toBeLessThanOrEqual(CACHE_LOOKBACK_BLOCKS);
    }
  });

  it("accounts for fat turns that append many blocks at once", () => {
    // A parallel-tool turn appends one block per tool_use plus one per
    // tool_result. Spacing is measured in BLOCKS, not messages, so a handful of
    // fat messages must still trigger a bridge.
    const messages = [msg(1), msg(12), msg(12), msg(12)];
    const picks = planMessageBreakpoints(messages);
    expect(picks).toContain(3);
    expect(picks.length).toBeGreaterThan(1);
  });

  it("returns ascending, de-duplicated indices", () => {
    // Single-message conversation: tail and head anchor are the same index.
    expect(planMessageBreakpoints([msg(1)])).toEqual([0]);

    const picks = planMessageBreakpoints(Array.from({ length: 60 }, () => msg(2)));
    expect([...picks].sort((a, b) => a - b)).toEqual(picks);
    expect(new Set(picks).size).toBe(picks.length);
  });

  it("re-establishes breakpoints after compaction rewrites history", () => {
    // Compaction collapses the middle of the transcript into one summary
    // message. Because placement is recomputed from the CURRENT array on every
    // call and never carried across turns, the post-compaction plan is a valid
    // fresh plan over the rewritten history — not a stale set of indices
    // pointing at messages that no longer exist.
    const before = Array.from({ length: 40 }, () => msg(2));
    const beforePicks = planMessageBreakpoints(before);

    // What compactMessagesWithLLM produces: message 0 preserved verbatim, the
    // middle replaced by a summary, a tail of recent turns kept.
    const after = [before[0]!, msg(1), ...before.slice(-10)];
    const afterPicks = planMessageBreakpoints(after);

    expect(afterPicks.length).toBeGreaterThan(0);
    // Every index must be in range for the NEW array — a stale plan would point
    // past the end of the compacted transcript.
    for (const index of afterPicks) {
      expect(index).toBeLessThan(after.length);
      expect(index).toBeGreaterThanOrEqual(0);
    }
    // The head anchor survives compaction, so it is still marked.
    expect(afterPicks).toContain(0);
    // The tail still tracks the new growing edge.
    expect(afterPicks).toContain(after.length - 1);
    // And the plan genuinely changed shape with the array.
    expect(afterPicks).not.toEqual(beforePicks);
  });
});

describe("providerSupportsPromptCache", () => {
  const origEnv = { ...process.env };

  beforeEach(() => {
    delete process.env["0SEC_PROMPT_CACHE_EXTRA_PROVIDERS"];
  });

  afterEach(() => {
    Object.assign(process.env, origEnv);
  });

  it("supports Anthropic", () => {
    expect(providerSupportsPromptCache("anthropic")).toBe(true);
  });

  it("does not send Anthropic-shaped fields to other wires", () => {
    for (const provider of ["openai", "azure", "openrouter", "chatgpt-codex", "deepseek"]) {
      expect(providerSupportsPromptCache(provider)).toBe(false);
    }
  });

  it("keeps unverified Anthropic-compatible providers opt-in", () => {
    // z-ai and kimi ride the same /v1/messages wire but have not been verified
    // to accept cache_control, so they must stay off by default.
    expect(providerSupportsPromptCache("z-ai")).toBe(false);
    expect(providerSupportsPromptCache("kimi")).toBe(false);
  });

  it("honours the opt-in env allowlist", () => {
    process.env["0SEC_PROMPT_CACHE_EXTRA_PROVIDERS"] = "z-ai, kimi";
    expect(providerSupportsPromptCache("z-ai")).toBe(true);
    expect(providerSupportsPromptCache("kimi")).toBe(true);
  });

  it("fails closed — the allowlist cannot enable a non-Anthropic wire", () => {
    process.env["0SEC_PROMPT_CACHE_EXTRA_PROVIDERS"] = "openai,azure,bogus";
    expect(providerSupportsPromptCache("openai")).toBe(false);
    expect(providerSupportsPromptCache("azure")).toBe(false);
    expect(providerSupportsPromptCache("bogus")).toBe(false);
  });
});

describe("withCacheControl", () => {
  it("attaches an ephemeral breakpoint without mutating the source block", () => {
    const block = { type: "text", text: "hi" };
    const marked = withCacheControl(block);

    expect(marked).toEqual({ type: "text", text: "hi", cache_control: { type: "ephemeral" } });
    // Non-mutating: the caller's block must not gain a wire field that would
    // then be replayed (and persisted) on every subsequent turn.
    expect(block).not.toHaveProperty("cache_control");
  });
});

describe("readCacheUsage", () => {
  it("returns undefined for a missing or non-object usage", () => {
    expect(readCacheUsage(undefined)).toBeUndefined();
    expect(readCacheUsage(null)).toBeUndefined();
    expect(readCacheUsage("nope")).toBeUndefined();
  });

  it("passes uncached usage through unchanged", () => {
    expect(readCacheUsage({ input_tokens: 100, output_tokens: 20 })).toEqual({
      inputTokens: 100,
      outputTokens: 20,
    });
  });

  it("normalises inputTokens back to TOTAL prompt size", () => {
    // Anthropic reports input_tokens as the UNCACHED remainder. Reporting that
    // verbatim would make prompts look ~10x smaller than they are, silently
    // under-reporting cost and starving the compaction trigger.
    const usage = readCacheUsage({
      input_tokens: 500,
      output_tokens: 200,
      cache_read_input_tokens: 40_000,
      cache_creation_input_tokens: 1_500,
    });

    expect(usage).toEqual({
      inputTokens: 42_000,
      outputTokens: 200,
      cachedInputTokens: 40_000,
      cacheWriteTokens: 1_500,
    });
  });

  it("omits cache fields entirely when the provider reports none", () => {
    const usage = readCacheUsage({ input_tokens: 10, output_tokens: 2 });
    expect(usage).not.toHaveProperty("cachedInputTokens");
    expect(usage).not.toHaveProperty("cacheWriteTokens");
  });

  it("tolerates malformed token counts", () => {
    expect(readCacheUsage({ input_tokens: "x", output_tokens: null })).toEqual({
      inputTokens: 0,
      outputTokens: 0,
    });
  });
});

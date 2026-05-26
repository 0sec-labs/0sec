import { describe, it, expect } from "vitest";
import {
  estimateCost,
  getRates,
  MODEL_PRICING,
  modelProvider,
  priceRun,
  PRICING_SNAPSHOT_DATE,
  splitCost,
} from "./cost.js";

describe("estimateCost", () => {
  it("uses default rates when model is missing", () => {
    const cost = estimateCost({ inputTokens: 1_000_000, outputTokens: 0 });
    expect(cost).toBeCloseTo(3.0, 5);
  });

  it("prices Sonnet 4.6 at the published rate", () => {
    // 10M input + 1M output → 10*3 + 1*15 = 45
    const cost = estimateCost(
      { inputTokens: 10_000_000, outputTokens: 1_000_000 },
      "claude-sonnet-4-6",
    );
    expect(cost).toBeCloseTo(45.0, 5);
  });

  it("strips OpenRouter-style vendor prefix", () => {
    const cost = estimateCost(
      { inputTokens: 1_000_000, outputTokens: 0 },
      "anthropic/claude-sonnet-4-6",
    );
    expect(cost).toBeCloseTo(3.0, 5);
  });

  it("strips z-ai prefix and prices GLM 5.1", () => {
    // GLM 5.1 at $1.40 input + $4.40 output per 1M
    const cost = estimateCost(
      { inputTokens: 1_000_000, outputTokens: 1_000_000 },
      "z-ai/glm-5.1",
    );
    expect(cost).toBeCloseTo(1.4 + 4.4, 5);
  });

  it("applies cached-input rate when cachedInputTokens is set", () => {
    // Sonnet 4.6: $3 input, $0.30 cached. 1M input total, 600k cached, 400k uncached
    // → 0.4 * 3 + 0.6 * 0.30 = 1.2 + 0.18 = 1.38
    const cost = estimateCost(
      {
        inputTokens: 1_000_000,
        outputTokens: 0,
        cachedInputTokens: 600_000,
      },
      "claude-sonnet-4-6",
    );
    expect(cost).toBeCloseTo(1.38, 5);
  });

  it("falls back to the input rate when cachedInputTokens is set but no cachedInput rate exists", () => {
    // GPT-4o has no cachedInput rate in the table → cached tokens cost the same as uncached
    const noCache = estimateCost(
      { inputTokens: 1_000_000, outputTokens: 0 },
      "gpt-4o",
    );
    const withCache = estimateCost(
      { inputTokens: 1_000_000, outputTokens: 0, cachedInputTokens: 500_000 },
      "gpt-4o",
    );
    expect(withCache).toBeCloseTo(noCache, 5);
  });
});

describe("priceRun", () => {
  it("is the shared run-pricing helper alias for estimateCost", () => {
    const usage = { inputTokens: 123_000, outputTokens: 45_000, cachedInputTokens: 20_000 };
    expect(priceRun(usage, "claude-sonnet-4-6")).toBeCloseTo(
      estimateCost(usage, "claude-sonnet-4-6"),
      5,
    );
  });
});

describe("getRates", () => {
  it("exposes a dated shared pricing table", () => {
    expect(PRICING_SNAPSHOT_DATE).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(MODEL_PRICING["claude-sonnet-4-6"]).toEqual({
      input: 3.00,
      output: 15.00,
      cachedInput: 0.30,
    });
  });

  it("returns GLM 5.1 cached-input rate from the Provos post", () => {
    const rates = getRates("glm-5.1");
    expect(rates.cachedInput).toBe(0.26);
  });

  it("returns the default-table rate for an unknown model", () => {
    const rates = getRates("totally-made-up-model-9000");
    expect(rates.input).toBe(3.0);
    expect(rates.output).toBe(15.0);
  });
});

describe("splitCost", () => {
  it("splits a usage record into in/out dollar components that sum to estimateCost", () => {
    const usage = { inputTokens: 500_000, outputTokens: 100_000 };
    const split = splitCost(usage, "claude-sonnet-4-6");
    const total = estimateCost(usage, "claude-sonnet-4-6");
    expect(split.cost_in + split.cost_out).toBeCloseTo(total, 5);
    // Sonnet: 500k * $3 + 100k * $15 = $1.50 + $1.50 = $3.00
    expect(split.cost_in).toBeCloseTo(1.50, 5);
    expect(split.cost_out).toBeCloseTo(1.50, 5);
  });

  it("emits cost_cache_read only when the caller supplied cachedInputTokens", () => {
    const without = splitCost({ inputTokens: 1_000_000, outputTokens: 0 }, "claude-sonnet-4-6");
    const with_ = splitCost(
      { inputTokens: 1_000_000, outputTokens: 0, cachedInputTokens: 0 },
      "claude-sonnet-4-6",
    );
    expect(without.cost_cache_read).toBeUndefined();
    expect(with_.cost_cache_read).toBe(0); // tracked-but-zero, distinct from untracked
  });

  it("computes cache savings: 600k cached + 400k uncached on Sonnet", () => {
    // Sonnet: $3 input, $0.30 cached. 400k uncached = $1.20, 600k cached = $0.18.
    const split = splitCost(
      { inputTokens: 1_000_000, outputTokens: 0, cachedInputTokens: 600_000 },
      "claude-sonnet-4-6",
    );
    expect(split.cost_in).toBeCloseTo(1.20, 5);
    expect(split.cost_cache_read).toBeCloseTo(0.18, 5);
  });
});

describe("modelProvider", () => {
  it("strips known vendor prefixes", () => {
    expect(modelProvider("openai/gpt-4o")).toBe("openai");
    expect(modelProvider("anthropic/claude-opus-4-7")).toBe("anthropic");
    expect(modelProvider("z-ai/glm-5.1")).toBe("z-ai");
  });

  it("falls back to family-based detection for bare model names", () => {
    expect(modelProvider("gpt-5.4")).toBe("openai");
    expect(modelProvider("claude-opus-4-7")).toBe("anthropic");
    expect(modelProvider("gemini-2.5-pro")).toBe("google");
    expect(modelProvider("deepseek-chat")).toBe("deepseek");
    expect(modelProvider("llama-4-maverick")).toBe("meta");
    expect(modelProvider("mistral-large")).toBe("mistral");
    expect(modelProvider("glm-5.1")).toBe("z-ai");
  });

  it("returns 'unknown' for empty / unrecognisable model ids", () => {
    expect(modelProvider()).toBe("unknown");
    expect(modelProvider("")).toBe("unknown");
    expect(modelProvider("totally-made-up-model-9000")).toBe("unknown");
  });
});

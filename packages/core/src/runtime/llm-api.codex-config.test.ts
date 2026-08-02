/**
 * `~/.codex/config.toml` parsing — specifically that `model_reasoning_effort`
 * is read from the section it belongs to.
 *
 * The regex used to be unscoped while every sibling was scoped to
 * `[model_providers.azure]`, so it matched the first occurrence ANYWHERE in the
 * file. The dev host's config has one at the top level and another inside
 * `[plugins."github@openai-curated"]`; reordering the file would have silently
 * handed an unrelated plugin's effort to every Responses-path scan.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LlmApiRuntime } from "./llm-api.js";

/** Point HOME at a throwaway dir holding just this config.toml. */
function withCodexConfig(toml: string): string {
  const home = mkdtempSync(join(tmpdir(), "pwnkit-codex-config-"));
  mkdirSync(join(home, ".codex"));
  writeFileSync(join(home, ".codex", "config.toml"), toml);
  return home;
}

/** Resolved reasoning effort for a runtime detected as the azure provider. */
function effortFor(toml: string): { home: string; effort: string | undefined } {
  const home = withCodexConfig(toml);
  vi.stubEnv("HOME", home);
  const rt = new LlmApiRuntime({ type: "api", timeout: 5000 });
  return { home, effort: (rt as any).reasoningEffort };
}

const AZURE_SECTION = [
  "",
  '[model_providers.azure]',
  'base_url = "https://example.openai.azure.com/openai/v1"',
  'wire_api = "responses"',
  'model = "gpt-5.6-sol"',
].join("\n");

const PLUGIN_SECTION = [
  "",
  '[plugins."github@openai-curated"]',
  'model_reasoning_effort = "high"',
].join("\n");

describe("model_reasoning_effort scoping in ~/.codex/config.toml", () => {
  const homes: string[] = [];

  beforeEach(() => {
    // Azure must win provider detection, and nothing may pre-empt the file.
    for (const key of [
      "PWNKIT_REASONING_EFFORT",
      "PWNKIT_MODEL",
      "PWNKIT_CHATGPT_ACCESS_TOKEN",
      "PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN",
      "ANTHROPIC_API_KEY",
      "Z_AI_API_KEY",
      "KIMI_API_KEY",
      "OPENAI_API_KEY",
      "OPENROUTER_API_KEY",
      "AZURE_OPENAI_WIRE_API",
    ]) {
      vi.stubEnv(key, undefined);
    }
    vi.stubEnv("AZURE_OPENAI_API_KEY", "azure-test-key");
    vi.stubEnv("PWNKIT_SKIP_PROVIDER_BANNER", "1");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    for (const home of homes.splice(0)) rmSync(home, { recursive: true, force: true });
  });

  it("takes the top-level value, not a plugin section's", () => {
    const { home, effort } = effortFor(
      ['model_reasoning_effort = "medium"', 'model_provider = "azure"', AZURE_SECTION, PLUGIN_SECTION].join("\n"),
    );
    homes.push(home);
    expect(effort).toBe("medium");
  });

  it("prefers the azure section over the top level", () => {
    const { home, effort } = effortFor(
      [
        'model_reasoning_effort = "medium"',
        'model_provider = "azure"',
        AZURE_SECTION,
        'model_reasoning_effort = "low"',
        PLUGIN_SECTION,
      ].join("\n"),
    );
    homes.push(home);
    expect(effort).toBe("low");
  });

  it("ignores a plugin section's value entirely when nothing else sets one", () => {
    const { home, effort } = effortFor(
      ['model_provider = "azure"', AZURE_SECTION, PLUGIN_SECTION].join("\n"),
    );
    homes.push(home);
    expect(effort).toBeUndefined();
  });
});

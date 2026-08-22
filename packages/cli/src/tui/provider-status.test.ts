import { describe, expect, it } from "vitest";

import { PROVIDERS, isProviderConfigured, providerStates } from "./provider-status.js";

/** No env at all — the state of a fresh container. */
const EMPTY: Record<string, string | undefined> = {};

function stateFor(id: string, env: Record<string, string | undefined>) {
  const state = providerStates(env).find((candidate) => candidate.id === id);
  if (!state) throw new Error(`no provider "${id}" in PROVIDERS`);
  return state;
}

describe("PROVIDERS", () => {
  it("gives every provider an id, a label, credentials, and a hint", () => {
    expect(PROVIDERS.length).toBeGreaterThan(0);
    for (const provider of PROVIDERS) {
      expect(provider.id.length).toBeGreaterThan(0);
      expect(provider.label.length).toBeGreaterThan(0);
      // A provider with no env var must document the file it reads instead,
      // or the picker has no way to tell an operator how to turn it on.
      expect(provider.envVars.length > 0 || (provider.fileSource ?? "").length > 0).toBe(true);
      expect(provider.hint.length).toBeGreaterThan(0);
    }
  });

  it("uses unique ids", () => {
    expect(new Set(PROVIDERS.map((provider) => provider.id)).size).toBe(PROVIDERS.length);
  });

  it("names the variable it wants in the hint, so the hint is actionable", () => {
    for (const provider of PROVIDERS) {
      const named = provider.envVars.some((name) => provider.hint.includes(name));
      // chatgpt-codex is allowed to point at `codex login` instead, but it
      // still names one of its tokens.
      expect(named).toBe(true);
    }
  });

  it("covers exactly the providers the runtime can detect", () => {
    // Mirrors the ApiProvider union + VALID_PROVIDERS table in
    // packages/core/src/runtime/llm-api.ts (L580, L626-629). A drift here
    // means the picker is lying about what the machine can reach.
    expect(PROVIDERS.map((provider) => provider.id).sort()).toEqual(
      [
        "anthropic",
        "azure",
        "chatgpt-codex",
        "deepseek",
        "kimi",
        "openai",
        "openrouter",
        "qwen",
        "xai",
        "z-ai",
      ].sort(),
    );
  });
});

describe("providerStates", () => {
  it("marks nothing configured under an empty environment", () => {
    const states = providerStates(EMPTY);
    expect(states).toHaveLength(PROVIDERS.length);
    expect(states.every((state) => state.configured === false)).toBe(true);
    expect(states.every((state) => state.via === undefined)).toBe(true);
  });

  it("configures exactly the provider whose var is set, and reports it in `via`", () => {
    const states = providerStates({ ANTHROPIC_API_KEY: "sk-ant-real" });
    const configured = states.filter((state) => state.configured);
    expect(configured).toHaveLength(1);
    expect(configured[0]?.id).toBe("anthropic");
    expect(configured[0]?.via).toBe("ANTHROPIC_API_KEY");
  });

  it("does not confuse the lookalike Azure and OpenAI keys", () => {
    // AZURE_OPENAI_API_KEY contains "OPENAI_API_KEY" as a substring; a
    // prefix/contains match here would light up the wrong provider.
    const states = providerStates({ AZURE_OPENAI_API_KEY: "azure-key" });
    expect(stateFor("azure", { AZURE_OPENAI_API_KEY: "azure-key" }).configured).toBe(true);
    expect(states.find((state) => state.id === "openai")?.configured).toBe(false);
  });

  it("treats an empty-string value as unconfigured", () => {
    // `export OPENAI_API_KEY=` in a profile leaves the name present.
    expect(stateFor("openai", { OPENAI_API_KEY: "" }).configured).toBe(false);
    expect(stateFor("openai", { OPENAI_API_KEY: "" }).via).toBeUndefined();
  });

  it("treats a whitespace-only value as unconfigured", () => {
    expect(stateFor("openai", { OPENAI_API_KEY: "   " }).configured).toBe(false);
    expect(stateFor("xai", { XAI_API_KEY: "\n" }).configured).toBe(false);
    expect(stateFor("kimi", { KIMI_API_KEY: "\t \n" }).configured).toBe(false);
  });

  it("accepts a value that merely has surrounding whitespace", () => {
    const state = stateFor("z-ai", { Z_AI_API_KEY: "  zk-real  " });
    expect(state.configured).toBe(true);
    expect(state.via).toBe("Z_AI_API_KEY");
  });

  it("is satisfied by EITHER of a multi-var provider's accepted vars", () => {
    const viaAccess = stateFor("chatgpt-codex", { "0SEC_CHATGPT_ACCESS_TOKEN": "at-1" });
    expect(viaAccess.configured).toBe(true);
    expect(viaAccess.via).toBe("0SEC_CHATGPT_ACCESS_TOKEN");

    const viaRefresh = stateFor("chatgpt-codex", { "0SEC_CHATGPT_OAUTH_REFRESH_TOKEN": "rt-1" });
    expect(viaRefresh.configured).toBe(true);
    expect(viaRefresh.via).toBe("0SEC_CHATGPT_OAUTH_REFRESH_TOKEN");
  });

  it("reports the most-preferred var in `via` when several are set", () => {
    const state = stateFor("chatgpt-codex", {
      "0SEC_CHATGPT_ACCESS_TOKEN": "at-1",
      "0SEC_CHATGPT_OAUTH_REFRESH_TOKEN": "rt-1",
    });
    expect(state.via).toBe(PROVIDERS.find((provider) => provider.id === "chatgpt-codex")?.envVars[0]);
    expect(state.via).toBe("0SEC_CHATGPT_ACCESS_TOKEN");
  });

  it("skips a blank preferred var and falls through to the next one", () => {
    const state = stateFor("chatgpt-codex", {
      "0SEC_CHATGPT_ACCESS_TOKEN": "  ",
      "0SEC_CHATGPT_OAUTH_REFRESH_TOKEN": "rt-1",
    });
    expect(state.configured).toBe(true);
    expect(state.via).toBe("0SEC_CHATGPT_OAUTH_REFRESH_TOKEN");
  });

  it("configures each provider from its own documented var", () => {
    for (const provider of PROVIDERS) {
      for (const name of provider.envVars) {
        const state = stateFor(provider.id, { [name]: "value" });
        expect(state.configured).toBe(true);
        expect(state.via).toBe(name);
      }
    }
  });

  it("does not mutate the env object it is given", () => {
    const env: Record<string, string | undefined> = { ANTHROPIC_API_KEY: "sk-ant", NOISE: "keep" };
    const snapshot = JSON.stringify(env);
    providerStates(env);
    expect(JSON.stringify(env)).toBe(snapshot);
    expect(Object.keys(env)).toEqual(["ANTHROPIC_API_KEY", "NOISE"]);
  });

  it("does not let a caller mutate PROVIDERS through a returned state", () => {
    const state = stateFor("anthropic", EMPTY);
    state.label = "tampered";
    expect(PROVIDERS.find((provider) => provider.id === "anthropic")?.label).toBe("Anthropic");
  });
});

describe("isProviderConfigured", () => {
  it("answers for a known provider", () => {
    expect(isProviderConfigured("qwen", { QWEN_API_KEY: "qk" })).toBe(true);
    expect(isProviderConfigured("qwen", EMPTY)).toBe(false);
    expect(isProviderConfigured("qwen", { QWEN_API_KEY: " " })).toBe(false);
  });

  it("returns false for an unknown id instead of throwing", () => {
    // The model catalog carries vendors with no direct runtime path.
    for (const id of ["google", "meta", "mistral", "unknown", "", "ANTHROPIC"]) {
      expect(isProviderConfigured(id, { ANTHROPIC_API_KEY: "sk-ant" })).toBe(false);
    }
  });

  it("agrees with providerStates for every provider", () => {
    const env = { ANTHROPIC_API_KEY: "sk-ant", OPENAI_API_KEY: "", XAI_API_KEY: "xk" };
    for (const state of providerStates(env)) {
      expect(isProviderConfigured(state.id, env)).toBe(state.configured);
    }
  });
});

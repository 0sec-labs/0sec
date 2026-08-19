import { describe, expect, it } from "vitest";
import { allowlistedChildEnv, sanitizedEnv } from "./sanitized-env.js";

describe("allowlistedChildEnv", () => {
  it("carries only allowlisted basics from the parent env", () => {
    const env = allowlistedChildEnv({}, {
      PATH: "/usr/bin",
      HOME: "/home/x",
      GITHUB_TOKEN: "ghp_secret",
      AWS_SECRET_ACCESS_KEY: "aws-secret",
      OPENAI_API_KEY: "sk-x",
      MY_CUSTOM_VAR: "keepme",
    });
    expect(env.PATH).toBe("/usr/bin");
    expect(env.HOME).toBe("/home/x");
    expect(env.GITHUB_TOKEN).toBeUndefined();
    expect(env.AWS_SECRET_ACCESS_KEY).toBeUndefined();
    expect(env.OPENAI_API_KEY).toBeUndefined();
    // Non-allowlisted vars never flow through unless passed as extras.
    expect(env.MY_CUSTOM_VAR).toBeUndefined();
  });

  it("merges caller extras", () => {
    const env = allowlistedChildEnv({ "0SEC_TARGET": "https://t.example" }, { PATH: "/bin" });
    expect(env["0SEC_TARGET"]).toBe("https://t.example");
    expect(env.PATH).toBe("/bin");
  });

  it("still screens extras against sensitive patterns", () => {
    const env = allowlistedChildEnv({ GITHUB_TOKEN: "leak" }, { PATH: "/bin" });
    expect(env.GITHUB_TOKEN).toBeUndefined();
  });

  it("sanitizedEnv denylist still filters known secrets (defense in depth)", () => {
    const env = sanitizedEnv({
      PATH: "/bin",
      ANTHROPIC_API_KEY: "sk-ant-x",
      "0SEC_CLOUD_TOKEN": "tok",
    });
    expect(env.PATH).toBe("/bin");
    expect(env.ANTHROPIC_API_KEY).toBeUndefined();
    expect(env["0SEC_CLOUD_TOKEN"]).toBeUndefined();
  });
});

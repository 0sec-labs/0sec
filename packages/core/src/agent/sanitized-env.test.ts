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

describe("newly covered credential shapes", () => {
  // These names are read by the runtime/intel/verify lanes but were absent from
  // SENSITIVE_ENV_PATTERNS. The allowlist already dropped them from the parent
  // copy; this pins the `extras` path too, so a caller cannot reintroduce one.
  it.each([
    ["QWEN_API_KEY", "qwen-secret"],
    ["NVD_API_KEY", "nvd-secret"],
    ["E2B_API_KEY", "e2b-secret"],
    ["0SEC_LLM_TARGET_KEY", "target-secret"],
  ])("screens %s out of caller extras", (name, value) => {
    const env = allowlistedChildEnv({ [name]: value }, { PATH: "/bin" });
    expect(env[name]).toBeUndefined();
    expect(env.PATH).toBe("/bin");
  });

  it("does not carry them from the parent environment either", () => {
    const env = allowlistedChildEnv({}, {
      PATH: "/bin",
      QWEN_API_KEY: "q",
      NVD_API_KEY: "n",
      E2B_API_KEY: "e",
      "0SEC_LLM_TARGET_KEY": "t",
    });
    expect(Object.keys(env)).toEqual(["PATH"]);
  });
});

describe("generic credential-shape screening (extras path)", () => {
  // Names that no vendor-specific pattern anticipated but every generic shape
  // should catch. Each is a real credential envelope the task called out.
  it.each([
    ["NVD_CREDS", "generic CRED shape"],
    ["MY_COMPANY_APIKEY", "APIKEY with no separator"],
    ["GH_PAT", "personal access token (_PAT)"],
    ["AWS_SESSION_TOKEN", "generic TOKEN shape"],
    ["AWS_ACCESS_KEY_ID", "ACCESS_KEY shape"],
    ["AWS_SECRET_ACCESS_KEY", "SECRET shape"],
    ["DATABASE_PASSWORD", "PASSWORD shape"],
    ["SSH_PASSPHRASE", "PASSPHRASE shape"],
    ["MY_PRIVATE_KEY", "PRIVATE_KEY shape"],
    ["SERVICE_CLIENT_SECRET", "SECRET shape"],
    ["SOME_BEARER_TOKEN", "BEARER shape"],
    ["VENDOR_AUTH_TOKEN", "AUTH_TOKEN shape"],
  ])("screens %s out of caller extras (%s)", (name) => {
    const env = allowlistedChildEnv({ [name]: "leak" }, { PATH: "/bin" });
    expect(env[name]).toBeUndefined();
    expect(env.PATH).toBe("/bin");
  });

  it("matches credential shapes case-insensitively", () => {
    const env = allowlistedChildEnv(
      { github_token: "leak", Aws_Session_Token: "leak", api_key: "leak" },
      { PATH: "/bin" },
    );
    expect(env.github_token).toBeUndefined();
    expect(env.Aws_Session_Token).toBeUndefined();
    expect(env.api_key).toBeUndefined();
  });

  it("does not over-block: PATH is not treated as a _PAT credential", () => {
    // "PATH".includes("PAT") is true, but the pattern is "_PAT" (underscore),
    // so a legitimate PATH extra survives.
    const env = allowlistedChildEnv({ PATH: "/opt/bin" }, {});
    expect(env.PATH).toBe("/opt/bin");
  });

  it("still passes the non-secret child-runtime extras callers rely on", () => {
    // Regression guard: the block-net flag, verify marker, scan id and target
    // must NOT be caught by the widened patterns.
    const env = allowlistedChildEnv(
      {
        "0SEC_KERNEL_BLOCK_NET": "1",
        "0SEC_VERIFY": "1",
        TARGET: "https://t.example",
      },
      { PATH: "/bin" },
    );
    expect(env["0SEC_KERNEL_BLOCK_NET"]).toBe("1");
    expect(env["0SEC_VERIFY"]).toBe("1");
    expect(env.TARGET).toBe("https://t.example");
  });
});

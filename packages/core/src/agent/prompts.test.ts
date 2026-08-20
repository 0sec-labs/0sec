import { describe, expect, it } from "vitest";
import {
  blindVerifyPrompt,
  buildAuthPromptBlock,
  researchPrompt,
  shellPentestPrompt,
  sourceVerifyPrompt,
  webPentestAttackPrompt,
} from "./prompts.js";

describe("shellPentestPrompt", () => {
  it("includes explicit browser-first XSS guidance when browser support exists", () => {
    const prompt = shellPentestPrompt("http://target.test", undefined, { hasBrowser: true });

    expect(prompt).toContain("## Browser tool (Playwright)");
    expect(prompt).toContain("### XSS browser flow");
    expect(prompt).toContain("Never save an XSS finding without browser evidence");
    expect(prompt).toContain("do NOT save an XSS unless browser evidence proves execution");
  });

  it("does not mention browser-specific XSS flow when browser support is unavailable", () => {
    const prompt = shellPentestPrompt("http://target.test");

    expect(prompt).not.toContain("## Browser tool (Playwright)");
    expect(prompt).not.toContain("### XSS browser flow");
  });

  it("includes efficiency-discipline guardrails against bundle paralysis and auth neglect", () => {
    // Guards the anti-paralysis guidance landed in 0.7.10 after real scans
    // showed the attack agent spending 6-8 turns re-grepping a single
    // minified JS bundle while ignoring the login endpoints it had
    // already discovered. The guidance is inlined into the shell-first
    // web pentest prompt and these assertions make sure a future prompt
    // refactor doesn't accidentally strip it out.
    const prompt = shellPentestPrompt("https://demo.target.test");

    // Section header is present so the agent sees this as a distinct rule
    // block, not buried inline text.
    expect(prompt).toContain("## Efficiency discipline");

    // Bundle-paralysis rule — the specific behavior we observed and want
    // to prevent recurring.
    expect(prompt).toContain("Bundle paralysis");
    expect(prompt).toContain("**at most 2 turns of static-asset analysis per file**");

    // Passive-recon rule — must start sending real attack payloads early.
    expect(prompt).toContain("Passive-only recon");

    // Auth endpoint neglect rule with the concrete follow-up checklist.
    expect(prompt).toContain("Auth endpoint neglect");
    expect(prompt).toMatch(/default\/weak credentials/);
    expect(prompt).toMatch(/SQL injection in the login body/);
    expect(prompt).toMatch(/JWT/);
    expect(prompt).toMatch(/IDOR/);

    // Repeat-payload trap — no re-sending the same failed payload.
    expect(prompt).toContain("Repeat-payload trap");
  });

  it("defaults normal web scans to real audit objectives, not CTF flag hunting", () => {
    const prompt = shellPentestPrompt("https://example.com");

    expect(prompt).toContain("real web application security audit");
    expect(prompt).toContain("confirmed vulnerability");
    expect(prompt).not.toContain("Extract the hidden flag");
    expect(prompt).not.toContain("extract FLAG");
    expect(prompt).not.toContain("Save the flag");
    expect(prompt).not.toContain("cat /flag");
    expect(prompt).not.toContain("/flag.txt");
  });
});

describe("buildAuthPromptBlock", () => {
  it("keeps every credential shape out of model-visible instructions", () => {
    const configs = [
      { type: "bearer" as const, token: "bearer-secret-canary" },
      { type: "cookie" as const, value: "session=cookie-secret-canary" },
      { type: "basic" as const, username: "user-canary", password: "basic-secret-canary" },
      { type: "header" as const, name: "X-Api-Key", value: "header-secret-canary" },
    ];

    for (const config of configs) {
      const prompt = buildAuthPromptBlock(config);
      expect(prompt).toContain("Authenticated requests are configured");
      expect(prompt).not.toContain("bearer-secret-canary");
      expect(prompt).not.toContain("cookie-secret-canary");
      expect(prompt).not.toContain("user-canary");
      expect(prompt).not.toContain("basic-secret-canary");
      expect(prompt).not.toContain("header-secret-canary");
    }
  });
});

describe("webPentestAttackPrompt", () => {
  it("keeps the structured web attack prompt on audit impact instead of flags", () => {
    const prompt = webPentestAttackPrompt("https://example.com", "login form at /login");

    expect(prompt).toContain("REAL AUDIT OBJECTIVE");
    expect(prompt).toContain("confirmed vulnerabilities with impact and evidence");
    expect(prompt).not.toContain("EXTRACT THE FLAG");
    expect(prompt).not.toContain("extract FLAG");
    expect(prompt).not.toContain("cat /flag");
    expect(prompt).not.toContain("/flag.txt");
  });
});

describe("scoped source prompts", () => {
  it("uses only the scoped source-browsing tools", () => {
    const research = researchPrompt("/scope", [], [], "npm:example@1.0.0");
    const verify = sourceVerifyPrompt("/scope", []);
    const blind = blindVerifyPrompt("src/index.ts", "input", "high", "/scope");

    for (const prompt of [research, verify, blind]) {
      expect(prompt).toContain("read_file");
      expect(prompt).toContain("search_files");
      expect(prompt).not.toContain("run_command");
    }
    expect(research).toContain("list_files");

  });
});

describe("shellPentestPrompt — OAST blind/out-of-band guidance", () => {
  it("steers blind candidates through oast_register / oast_poll before timing fallback", () => {
    const prompt = shellPentestPrompt("https://target.test");

    expect(prompt).toContain("oast_register");
    expect(prompt).toContain("oast_poll");
    expect(prompt).toContain("oast_handle_id");
    expect(prompt).toContain("token-matched callback");
    expect(prompt).toContain("OOB RCE");
    expect(prompt).toContain("OOB SQLi");
    expect(prompt).toContain("XXE-OOB");
    expect(prompt).toContain("JNDI/log4shell");
  });
});

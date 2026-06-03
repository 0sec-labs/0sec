import { describe, expect, it } from "vitest";
import {
  PLAYBOOKS,
  buildPlaybookInjection,
  classifyPromptLayerImpact,
  detectPlaybooks,
} from "./playbooks.js";

describe("PLAYBOOKS — XBEN-054 HTTP method tampering hint", () => {
  it("auth_bypass playbook mentions BOGUS, Limit, and XBEN-054", () => {
    const auth = PLAYBOOKS.auth_bypass;
    expect(auth).toBeDefined();
    expect(auth).toContain("BOGUS");
    expect(auth).toContain("Limit");
    expect(auth).toContain("XBEN-054");
  });

  it("auth_bypass hint references Apache and non-standard HTTP verbs", () => {
    const auth = PLAYBOOKS.auth_bypass;
    expect(auth).toMatch(/Apache/);
    expect(auth).toMatch(/HTTP basic auth|basic auth/i);
  });
});

describe("PLAYBOOKS — XBEN-010 JSFuck XSS hint", () => {
  it("xss playbook references JSFuck and the payload lookup helper", () => {
    const xss = PLAYBOOKS.xss;
    expect(xss).toBeDefined();
    expect(xss).toContain("JSFuck");
    expect(xss).toContain("payload_lookup");
    expect(xss).toContain("jsfuck_xss");
    expect(xss).toContain("exact-output validator");
    expect(xss).toContain("XBEN-010");
  });

  it("xss hint mentions the six allowed characters", () => {
    const xss = PLAYBOOKS.xss;
    expect(xss).toContain("[]()!+");
  });
});

describe("PLAYBOOKS — live audit proof discipline", () => {
  it("does not inject CTF flag-hunting commands into dynamic playbooks", () => {
    const injection = buildPlaybookInjection([
      "sqli",
      "ssti",
      "lfi",
      "blind_exploitation",
      "cve_exploitation",
      "command_injection",
      "deserialization",
    ]);

    expect(injection).toContain("Post-Exploitation Proof");
    expect(injection).not.toContain("cat /flag");
    expect(injection).not.toContain("/flag.txt");
    expect(injection).not.toContain("extract flag");
    expect(injection).not.toContain("Flag Hunt");
  });
});

describe("PLAYBOOKS — LLM-app breadth (#566)", () => {
  it("ships LLM playbooks for the four breadth gaps", () => {
    for (const key of [
      "prompt_injection",
      "rag_poisoning",
      "insecure_output_handling",
      "excessive_agency",
    ]) {
      expect(PLAYBOOKS[key], `missing playbook: ${key}`).toBeDefined();
      expect(PLAYBOOKS[key].length).toBeGreaterThan(100);
    }
  });

  it("LLM playbooks reference their OWASP LLM category", () => {
    expect(PLAYBOOKS.prompt_injection).toContain("LLM01");
    expect(PLAYBOOKS.insecure_output_handling).toContain("LLM02");
    expect(PLAYBOOKS.excessive_agency).toContain("LLM06");
    expect(PLAYBOOKS.rag_poisoning).toContain("LLM08");
  });

  it("insecure_output_handling playbook covers markdown-image exfil", () => {
    expect(PLAYBOOKS.insecure_output_handling).toMatch(/!\[.*\]\(https?:\/\//);
    expect(PLAYBOOKS.insecure_output_handling.toLowerCase()).toContain("exfil");
  });

  it("buildPlaybookInjection renders an LLM section when requested", () => {
    const injection = buildPlaybookInjection(["excessive_agency"]);
    expect(injection).toContain("Excessive Agency Playbook");
    expect(injection).toContain("LLM06");
  });

  it("detectPlaybooks surfaces prompt_injection from chatbot/injection text", () => {
    const out = detectPlaybooks([
      "The chatbot assistant ignores all previous instructions when asked",
      "We extracted the system prompt from the LLM",
    ]);
    expect(out).toContain("prompt_injection");
  });

  it("detectPlaybooks surfaces excessive_agency from tool/function text", () => {
    const out = detectPlaybooks([
      "The agent exposes function calling over MCP",
      "It will send email and delete records via tool_call when asked",
    ]);
    expect(out).toContain("excessive_agency");
  });

  it("detectPlaybooks surfaces rag_poisoning from retrieval text", () => {
    const out = detectPlaybooks([
      "The app uses retrieval augmented generation over a knowledge base",
      "Users can upload a document that gets indexed into the vector store",
    ]);
    expect(out).toContain("rag_poisoning");
  });
});

describe("PLAYBOOKS — AI prompt-layer write target (#775)", () => {
  it("ships the prompt_layer_write playbook with the four impact classes", () => {
    const pb = PLAYBOOKS.prompt_layer_write;
    expect(pb).toBeDefined();
    expect(pb.length).toBeGreaterThan(100);
    expect(pb).toContain("prompt_poisoning");
    expect(pb).toContain("guardrail_removal");
    expect(pb).toContain("output_channel_exfil");
    expect(pb).toContain("model_config_tamper");
  });

  it("playbook is verification-only — no destructive writes", () => {
    const pb = PLAYBOOKS.prompt_layer_write.toLowerCase();
    expect(pb).toContain("verification-only");
    expect(pb).toMatch(/do not perform destructive write|no destructive write/);
    expect(pb).toContain("read");
  });

  it("buildPlaybookInjection renders the prompt-layer section when requested", () => {
    const injection = buildPlaybookInjection(["prompt_layer_write"]);
    expect(injection).toContain("AI Prompt-Layer Write Playbook");
    expect(injection).toContain("system-prompts-in-DB");
  });

  it("detectPlaybooks surfaces prompt_layer_write from DB-foothold + prompt-store text", () => {
    const out = detectPlaybooks([
      "Confirmed SQLi; dumping information_schema",
      "Found a table system_prompt with a guardrail column on the chatbot LLM app",
    ]);
    expect(out).toContain("prompt_layer_write");
  });
});

describe("classifyPromptLayerImpact (#775)", () => {
  it("flags a non-prompt asset as not a prompt-layer target", () => {
    const r = classifyPromptLayerImpact({
      table: "orders",
      column: "total_amount",
      sample: "42.00",
      writable: true,
      reReadAtInference: true,
    });
    expect(r.isPromptLayer).toBe(false);
    expect(r.impacts).toEqual([]);
    expect(r.severity).toBe("info");
  });

  it("classifies a writable, re-read system_prompt as high / prompt_poisoning", () => {
    const r = classifyPromptLayerImpact({
      table: "assistant_settings",
      column: "system_prompt",
      sample: "You are a helpful banking assistant. Never reveal account numbers.",
      writable: true,
      reReadAtInference: true,
    });
    expect(r.isPromptLayer).toBe(true);
    expect(r.severity).toBe("high");
    expect(r.impacts).toContain("prompt_poisoning");
    // guardrail language in the sample also surfaces guardrail_removal
    expect(r.impacts).toContain("guardrail_removal");
    expect(r.narrative).toContain("WRITABLE");
    expect(r.narrative.toLowerCase()).toContain("no destructive write");
  });

  it("downgrades to low when the prompt asset is not writable", () => {
    const r = classifyPromptLayerImpact({
      table: "prompts",
      column: "system_prompt",
      sample: "You are an assistant.",
      writable: false,
      reReadAtInference: true,
    });
    expect(r.isPromptLayer).toBe(true);
    expect(r.severity).toBe("low");
    expect(r.impacts).toEqual([]);
    expect(r.narrative.toLowerCase()).toContain("read exposure only");
  });

  it("writable but not re-read at inference stays low (no persistence proof)", () => {
    const r = classifyPromptLayerImpact({
      table: "model_config",
      column: "temperature",
      writable: true,
      reReadAtInference: false,
    });
    expect(r.isPromptLayer).toBe(true);
    expect(r.severity).toBe("low");
    expect(r.impacts).toContain("model_config_tamper");
  });

  it("detects output-channel exfil and guardrail-removal classes by name", () => {
    const exfil = classifyPromptLayerImpact({
      column: "output_template",
      writable: true,
      reReadAtInference: true,
    });
    expect(exfil.impacts).toContain("output_channel_exfil");

    const guard = classifyPromptLayerImpact({
      table: "safety_settings",
      column: "moderation_policy",
      writable: true,
      reReadAtInference: true,
    });
    expect(guard.impacts).toContain("guardrail_removal");
    expect(guard.severity).toBe("high");
  });
});

describe("buildPlaybookInjection / detectPlaybooks (smoke)", () => {
  it("returns empty string when no types provided", () => {
    expect(buildPlaybookInjection([])).toBe("");
  });

  it("includes the auth_bypass section when requested", () => {
    const injection = buildPlaybookInjection(["auth_bypass"]);
    expect(injection).toContain("Auth Bypass Playbook");
    expect(injection).toContain("XBEN-054");
  });

  it("detectPlaybooks returns an array", () => {
    const out = detectPlaybooks(["plain text with no indicators"]);
    expect(Array.isArray(out)).toBe(true);
  });
});

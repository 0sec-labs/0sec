import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { validateFlagShape, validateFlagInText } from "./flag-validator.js";
import { ToolExecutor } from "./tools.js";
import type { ToolContext } from "./types.js";

// ── validateFlagShape: known-good flags ──

describe("validateFlagShape — known-good flags", () => {
  it("accepts the real XBEN-079 hex flag with high confidence", () => {
    const result = validateFlagShape("FLAG{7dda4e738d29a996f343a610}");
    expect(result.ok).toBe(true);
    expect(result.confidence).toBeGreaterThanOrEqual(0.9);
    expect(result.wrapped).toBe(true);
    expect(result.inner).toBe("7dda4e738d29a996f343a610");
  });

  it("accepts a UUID4-shaped flag with very high confidence", () => {
    const result = validateFlagShape("FLAG{9b2f6e3a-7c4d-4a2f-8b1c-1e3f4a5b6c7d}");
    expect(result.ok).toBe(true);
    expect(result.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it("accepts a sha256-length hex digest", () => {
    const inner = "a".repeat(64);
    const result = validateFlagShape(`FLAG{${inner}}`);
    expect(result.ok).toBe(true);
    expect(result.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it("accepts an 8-character short hex flag at reduced confidence", () => {
    const result = validateFlagShape("FLAG{deadbeef}");
    expect(result.ok).toBe(true);
    expect(result.confidence).toBeGreaterThanOrEqual(0.5);
    expect(result.confidence).toBeLessThan(0.9);
  });

  it("is case-insensitive on the FLAG wrapper", () => {
    const result = validateFlagShape("flag{7dda4e738d29a996f343a610}");
    expect(result.ok).toBe(true);
  });
});

// ── validateFlagShape: known decoys ──

describe("validateFlagShape — known decoys", () => {
  it("rejects the XBEN-079 decoy FLAG{I'm_a_Script_Kiddie}", () => {
    const result = validateFlagShape("FLAG{I'm_a_Script_Kiddie}");
    expect(result.ok).toBe(false);
    expect(result.confidence).toBeLessThan(0.5);
    expect(result.confidence).toBeLessThanOrEqual(0.1);
    expect(result.reason.toLowerCase()).toContain("decoy");
  });

  it("rejects sentence-style content with spaces", () => {
    const result = validateFlagShape("FLAG{you got pwned}");
    expect(result.ok).toBe(false);
    expect(result.confidence).toBeLessThan(0.5);
  });

  it("rejects an explicit DECOY marker", () => {
    const result = validateFlagShape("FLAG{DECOY_1234}");
    expect(result.ok).toBe(false);
    expect(result.confidence).toBeLessThanOrEqual(0.1);
  });

  it("rejects FAKE substring (case-insensitive)", () => {
    const result = validateFlagShape("FLAG{fake_flag_here}");
    expect(result.ok).toBe(false);
    expect(result.confidence).toBeLessThanOrEqual(0.1);
  });

  it("rejects HONEYPOT substring", () => {
    const result = validateFlagShape("FLAG{abcd_honeypot_1234}");
    expect(result.ok).toBe(false);
    expect(result.confidence).toBeLessThanOrEqual(0.1);
  });

  it("rejects a chain of alphabetic word tokens joined by underscores", () => {
    const result = validateFlagShape("FLAG{try_harder_next_time}");
    expect(result.ok).toBe(false);
    expect(result.confidence).toBeLessThan(0.5);
  });
});

// ── validateFlagShape: edge cases ──

describe("validateFlagShape — edge cases", () => {
  it("rejects an empty string", () => {
    const result = validateFlagShape("");
    expect(result.ok).toBe(false);
    expect(result.confidence).toBe(0);
  });

  it("rejects a string with no FLAG{} wrapper", () => {
    const result = validateFlagShape("7dda4e738d29a996f343a610");
    expect(result.ok).toBe(false);
    expect(result.wrapped).toBe(false);
  });

  it("rejects an empty FLAG{} wrapper", () => {
    const result = validateFlagShape("FLAG{}");
    expect(result.ok).toBe(false);
    expect(result.inner).toBe("");
  });

  it("penalizes inner content shorter than 8 chars", () => {
    const result = validateFlagShape("FLAG{abc}");
    expect(result.ok).toBe(false);
    expect(result.confidence).toBeLessThanOrEqual(0.3);
  });

  it("penalizes inner content longer than 100 chars", () => {
    const inner = "a".repeat(120);
    const result = validateFlagShape(`FLAG{${inner}}`);
    expect(result.ok).toBe(false);
    expect(result.confidence).toBeLessThanOrEqual(0.3);
  });

  it("accepts a hex-shaped flag even if expectedShape=hex explicitly requested", () => {
    const result = validateFlagShape("FLAG{7dda4e738d29a996f343a610}", "hex");
    expect(result.ok).toBe(true);
  });

  it("penalizes when expectedShape=uuid but inner is plain hex", () => {
    const result = validateFlagShape("FLAG{7dda4e738d29a996f343a610}", "uuid");
    // Shape mismatch clamps confidence to <= 0.4, so ok is false.
    expect(result.confidence).toBeLessThanOrEqual(0.4);
    expect(result.ok).toBe(false);
  });
});

// ── validateFlagInText ──

describe("validateFlagInText", () => {
  it("extracts a FLAG{...} from a summary sentence", () => {
    const summary = "I found the flag in /etc/passwd: FLAG{7dda4e738d29a996f343a610}";
    const result = validateFlagInText(summary);
    expect(result).not.toBeNull();
    expect(result!.ok).toBe(true);
  });

  it("returns null when no flag token is present", () => {
    const result = validateFlagInText("I gave up, nothing exploitable here.");
    expect(result).toBeNull();
  });

  it("flags a decoy extracted from a summary", () => {
    const summary = "Got it! The flag is FLAG{I'm_a_Script_Kiddie}";
    const result = validateFlagInText(summary);
    expect(result).not.toBeNull();
    expect(result!.ok).toBe(false);
    expect(result!.confidence).toBeLessThan(0.5);
  });
});

// ── Integration: `done` tool rejects decoys, accepts retry ──

function makeCtx(): ToolContext {
  return {
    target: "http://localhost",
    scanId: "test-scan",
    findings: [],
    attackResults: [],
    targetInfo: {},
  };
}

describe("ToolExecutor.done — anti-honeypot integration", () => {
  const originalEnv = process.env.PWNKIT_FEATURE_DECOY_DETECTION;

  beforeEach(() => {
    delete process.env.PWNKIT_FEATURE_DECOY_DETECTION;
  });

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.PWNKIT_FEATURE_DECOY_DETECTION;
    } else {
      process.env.PWNKIT_FEATURE_DECOY_DETECTION = originalEnv;
    }
  });

  it("rejects a done call whose summary embeds a decoy flag", async () => {
    const exec = new ToolExecutor(makeCtx());
    const result = await exec.execute({
      name: "done",
      arguments: {
        summary: "Found the flag: FLAG{I'm_a_Script_Kiddie}",
      },
    });
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
    expect(result.error).toContain("low shape confidence");
    expect(result.error).toContain("FLAG{I'm_a_Script_Kiddie}");
  });

  it("accepts a second done call with the same decoy flag (override path)", async () => {
    const exec = new ToolExecutor(makeCtx());
    const summary = "Found the flag: FLAG{I'm_a_Script_Kiddie}";
    const first = await exec.execute({ name: "done", arguments: { summary } });
    expect(first.success).toBe(false);

    const second = await exec.execute({ name: "done", arguments: { summary } });
    expect(second.success).toBe(true);
    expect((second.output as { done: boolean }).done).toBe(true);
  });

  it("accepts a high-confidence hex flag on the first call", async () => {
    const exec = new ToolExecutor(makeCtx());
    const result = await exec.execute({
      name: "done",
      arguments: {
        summary: "Exploited LFI and recovered FLAG{7dda4e738d29a996f343a610}",
      },
    });
    expect(result.success).toBe(true);
  });

  it("accepts a done call with no flag token (agent giving up)", async () => {
    const exec = new ToolExecutor(makeCtx());
    const result = await exec.execute({
      name: "done",
      arguments: {
        summary: "Attack surface exhausted, no vulnerability found.",
      },
    });
    expect(result.success).toBe(true);
  });

  it("passes the decoy through when PWNKIT_FEATURE_DECOY_DETECTION=0", async () => {
    process.env.PWNKIT_FEATURE_DECOY_DETECTION = "0";
    const exec = new ToolExecutor(makeCtx());
    const result = await exec.execute({
      name: "done",
      arguments: {
        summary: "Found the flag: FLAG{I'm_a_Script_Kiddie}",
      },
    });
    expect(result.success).toBe(true);
  });
});

import { describe, it, expect } from "vitest";
import type { AttackCategory, Finding } from "@pwnkit/shared";
import type {
  NativeRuntime,
  NativeMessage,
  NativeToolDef,
  NativeRuntimeResult,
} from "../runtime/types.js";
import {
  generatePov,
  judgePovEvidence,
  memCorruptionVerdict,
  oracleForCategory,
} from "./pov-gate.js";
import type { CrashArtifact } from "./memsafety-types.js";
import type { OracleResult } from "./oracles.js";
import { VERIFY_EVIDENCE_KINDS, isDisclosureWorthy } from "./verify-verdict.js";

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "pov-test",
    templateId: "audit-sink",
    title: "Blind SQLi in /search",
    description: "single-quote induces SQL error",
    severity: "high",
    category: "sql-injection" as AttackCategory,
    status: "discovered",
    evidence: {
      request: "GET /search?q=foo HTTP/1.1\nHost: example.com\n\n",
      response: "",
      analysis: "Error on quote suggests SQLi",
    },
    confidence: 0.6,
    timestamp: Date.now(),
    ...overrides,
  };
}

/**
 * Builds a scripted NativeRuntime that returns a fixed sequence of
 * NativeRuntimeResult objects (one per turn).
 */
function scriptedRuntime(script: NativeRuntimeResult[]): NativeRuntime & { calls: number } {
  let i = 0;
  const rt: NativeRuntime & { calls: number } = {
    type: "api" as const,
    calls: 0,
    async executeNative(
      _system: string,
      _messages: NativeMessage[],
      _tools: NativeToolDef[],
    ): Promise<NativeRuntimeResult> {
      rt.calls = ++i;
      const step = script[i - 1] ?? script[script.length - 1];
      return step;
    },
    async isAvailable() {
      return true;
    },
  };
  return rt;
}

const EVIDENCE_SQL = [
  "HTTP/1.1 200 OK",
  "<html><body>",
  "ERROR 1064 (42000): You have an error in your SQL syntax near 'foo''",
  "MariaDB version: 10.6.12-MariaDB-ubuntu",
  "</body></html>",
].join("\n");

// ────────────────────────────────────────────────────────────────────
// judgePovEvidence
// ────────────────────────────────────────────────────────────────────

describe("judgePovEvidence", () => {
  it("accepts SQL error + version string for sql-injection", () => {
    const v = judgePovEvidence(makeFinding(), EVIDENCE_SQL);
    expect(v.passed).toBe(true);
    expect(v.label).toMatch(/sqli/i);
  });

  it("rejects a bare 200 OK for sql-injection", () => {
    const v = judgePovEvidence(makeFinding(), "HTTP/1.1 200 OK\n<html>ok</html>");
    expect(v.passed).toBe(false);
  });

  it("accepts /etc/passwd for path-traversal", () => {
    const v = judgePovEvidence(
      makeFinding({ category: "path-traversal" as AttackCategory }),
      "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin/nologin",
    );
    expect(v.passed).toBe(true);
  });

  it("accepts uid= output for command-injection", () => {
    const v = judgePovEvidence(
      makeFinding({ category: "command-injection" as AttackCategory }),
      "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
    );
    expect(v.passed).toBe(true);
  });

  it("falls back to generic patterns for unknown categories", () => {
    const v = judgePovEvidence(
      makeFinding({ category: "prompt-injection" as AttackCategory }),
      "leaked flag{hackme_123}",
    );
    expect(v.passed).toBe(true);
  });
});

// ────────────────────────────────────────────────────────────────────
// generatePov
// ────────────────────────────────────────────────────────────────────

describe("generatePov", () => {
  it("returns hasPov:true when the agent runs a working exploit and submits proof", async () => {
    const runtime = scriptedRuntime([
      // Turn 1: run a curl that hits the SQLi
      {
        content: [
          {
            type: "tool_use",
            id: "t1",
            name: "bash",
            input: {
              command: "curl -s 'http://example.com/search?q=foo%27'",
            },
          },
        ],
        stopReason: "tool_use",
        durationMs: 10,
      },
      // Turn 2: submit the PoV with real evidence
      {
        content: [
          {
            type: "tool_use",
            id: "t2",
            name: "submit_pov",
            input: {
              artifact_type: "curl",
              artifact: "curl -s 'http://example.com/search?q=foo%27'",
              execution_evidence: EVIDENCE_SQL,
            },
          },
        ],
        stopReason: "tool_use",
        durationMs: 10,
      },
    ]);

    const result = await generatePov(
      makeFinding(),
      "http://example.com",
      runtime,
      5,
      { disableBash: true, disableHttp: true },
    );

    expect(result.hasPov).toBe(true);
    expect(result.artifactType).toBe("curl");
    expect(result.povArtifact).toContain("curl");
    expect(result.executionEvidence).toContain("SQL syntax");
    expect(result.confidence).toBeGreaterThan(0.7);
    expect(result.turnsUsed).toBe(2);
    expect(result.reason).toMatch(/PoV confirmed/);
  });

  it("returns hasPov:false when the agent only describes and never executes", async () => {
    const runtime = scriptedRuntime([
      // Agent just emits text — no tool calls
      {
        content: [
          {
            type: "text",
            text: "I believe this endpoint would be vulnerable to SQLi because the quote produces an error.",
          },
        ],
        stopReason: "end_turn",
        durationMs: 10,
      },
      // Second turn: still talking
      {
        content: [
          {
            type: "text",
            text: "Based on the prior evidence, the exploit would extract the version.",
          },
        ],
        stopReason: "end_turn",
        durationMs: 10,
      },
      // Third turn: give up
      {
        content: [
          {
            type: "tool_use",
            id: "g1",
            name: "give_up",
            input: { reason: "cannot reach target" },
          },
        ],
        stopReason: "tool_use",
        durationMs: 10,
      },
    ]);

    const result = await generatePov(
      makeFinding(),
      "http://example.com",
      runtime,
      5,
      { disableBash: true, disableHttp: true },
    );

    expect(result.hasPov).toBe(false);
    expect(result.artifactType).toBe("none");
    expect(result.povArtifact).toBeNull();
    expect(result.confidence).toBe(0);
    expect(result.reason).toMatch(/gave up/);
  });

  it("returns hasPov:false when the agent submits evidence that fails the judge", async () => {
    const runtime = scriptedRuntime([
      {
        content: [
          {
            type: "tool_use",
            id: "s1",
            name: "submit_pov",
            input: {
              artifact_type: "curl",
              artifact: "curl http://example.com/search?q=test",
              execution_evidence: "HTTP/1.1 200 OK\n<html>no proof here</html>",
            },
          },
        ],
        stopReason: "tool_use",
        durationMs: 10,
      },
    ]);

    const result = await generatePov(
      makeFinding(),
      "http://example.com",
      runtime,
      5,
      { disableBash: true, disableHttp: true },
    );

    expect(result.hasPov).toBe(false);
    // The PoC artifact is still captured so the caller can see what was tried
    expect(result.povArtifact).toContain("curl");
    expect(result.reason).toMatch(/did not contain category-specific proof/);
  });

  it("returns hasPov:false when maxTurns is exceeded without submission", async () => {
    // Every turn the agent makes a useless bash call and never submits
    const turn: NativeRuntimeResult = {
      content: [
        {
          type: "tool_use",
          id: "b1",
          name: "bash",
          input: { command: "echo still trying" },
        },
      ],
      stopReason: "tool_use",
      durationMs: 5,
    };
    const runtime = scriptedRuntime([turn, turn, turn]);

    const result = await generatePov(
      makeFinding(),
      "http://example.com",
      runtime,
      3,
      { disableBash: true, disableHttp: true },
    );

    expect(result.hasPov).toBe(false);
    expect(result.turnsUsed).toBe(3);
    expect(result.reason).toMatch(/max turns/);
    expect(result.confidence).toBe(0);
  });

  it("propagates runtime errors as hasPov:false", async () => {
    const runtime = scriptedRuntime([
      {
        content: [],
        stopReason: "error",
        durationMs: 1,
        error: "rate limited",
      },
    ]);

    const result = await generatePov(
      makeFinding(),
      "http://example.com",
      runtime,
      3,
      { disableBash: true, disableHttp: true },
    );

    expect(result.hasPov).toBe(false);
    expect(result.reason).toMatch(/runtime error/);
  });

  it("accepts a custom judge for test overrides", async () => {
    const runtime = scriptedRuntime([
      {
        content: [
          {
            type: "tool_use",
            id: "s1",
            name: "submit_pov",
            input: {
              artifact_type: "python",
              artifact: "import requests; requests.get('...')",
              execution_evidence: "anything",
            },
          },
        ],
        stopReason: "tool_use",
        durationMs: 1,
      },
    ]);

    const result = await generatePov(
      makeFinding(),
      "http://example.com",
      runtime,
      5,
      {
        disableBash: true,
        disableHttp: true,
        judge: () => ({ passed: true, label: "test override" }),
      },
    );

    expect(result.hasPov).toBe(true);
    expect(result.artifactType).toBe("python");
  });

  it("tags regex-fallback categories with oracle:'regex-fallback'", async () => {
    const runtime = scriptedRuntime([
      {
        content: [
          {
            type: "tool_use",
            id: "s1",
            name: "submit_pov",
            input: {
              artifact_type: "curl",
              artifact: "curl -s 'http://example.com/search?q=foo%27'",
              execution_evidence: EVIDENCE_SQL,
            },
          },
        ],
        stopReason: "tool_use",
        durationMs: 10,
      },
    ]);

    // sql-injection has no headless-browser / OAST oracle → regex fallback.
    const result = await generatePov(
      makeFinding({ category: "sql-injection" as AttackCategory }),
      "http://example.com",
      runtime,
      5,
      { disableBash: true, disableHttp: true },
    );

    expect(result.hasPov).toBe(true);
    expect(result.oracle).toBe("regex-fallback");
  });
});

// ────────────────────────────────────────────────────────────────────
// oracleForCategory
// ────────────────────────────────────────────────────────────────────

describe("oracleForCategory", () => {
  it("routes xss to the headless browser oracle", () => {
    expect(oracleForCategory("xss" as AttackCategory)).toBe("headless-browser");
  });

  it("routes ssrf and command/code injection to the OAST callback oracle", () => {
    expect(oracleForCategory("ssrf" as AttackCategory)).toBe("oast-callback");
    expect(oracleForCategory("command-injection" as AttackCategory)).toBe(
      "oast-callback",
    );
    expect(oracleForCategory("code-injection" as AttackCategory)).toBe(
      "oast-callback",
    );
  });

  it("falls back to regex for categories without a deterministic oracle", () => {
    expect(oracleForCategory("sql-injection" as AttackCategory)).toBe(
      "regex-fallback",
    );
    expect(oracleForCategory("path-traversal" as AttackCategory)).toBe(
      "regex-fallback",
    );
    expect(oracleForCategory("information-disclosure" as AttackCategory)).toBe(
      "regex-fallback",
    );
  });
});

// ────────────────────────────────────────────────────────────────────
// generatePov — deterministic oracle delegation
//
// The whole point of issue #553: for categories with a deterministic oracle
// (XSS → browser, SSRF/blind-RCE → OAST), the verdict comes from the oracle,
// NOT from regex over the agent's self-reported evidence.
// ────────────────────────────────────────────────────────────────────

/** A `submit_pov` turn carrying arbitrary evidence text. */
function submitTurn(evidence: string, artifact = "<script>alert(1)</script>") {
  return scriptedRuntime([
    {
      content: [
        {
          type: "tool_use",
          id: "s1",
          name: "submit_pov",
          input: {
            artifact_type: "javascript",
            artifact,
            execution_evidence: evidence,
          },
        },
      ],
      stopReason: "tool_use",
      durationMs: 5,
    },
  ]);
}

describe("generatePov — oracle delegation (XSS / headless-browser)", () => {
  it("INTENTIONAL REGRESSION: regex-passing <script>alert(1) text is hasPov:false when the browser oracle does not fire", async () => {
    // The agent submits evidence that the OLD regex judge would have accepted
    // (it literally contains "<script>alert(1)"), but the real browser oracle
    // reports no dialog fired.
    const runtime = submitTurn(
      "Response body: <script>alert(1)</script> reflected unencoded",
    );
    // The browser oracle ran to completion (no infra error) and the dialog
    // never fired — a clean negative, not inconclusive.
    const mockedOracle = async (): Promise<OracleResult> => ({
      verified: false,
      confidence: 0,
      evidence: "",
      reason: "no xss reflection or alert captured",
    });

    const result = await generatePov(
      makeFinding({ category: "xss" as AttackCategory }),
      "http://example.com",
      runtime,
      5,
      { disableBash: true, disableHttp: true, oracle: mockedOracle },
    );

    expect(result.hasPov).toBe(false);
    expect(result.oracle).toBe("headless-browser");
    expect(result.inconclusive).toBeFalsy();
    expect(result.reason).toMatch(/did not reproduce/i);
  });

  it("real browser fire → hasPov:true with oracle:'headless-browser'", async () => {
    const runtime = submitTurn("alert dialog observed");
    const mockedOracle = async (): Promise<OracleResult> => ({
      verified: true,
      confidence: 1.0,
      evidence: "playwright dialog captured token=pwnkit_abc message=\"abc\"",
      reason: "",
    });

    const result = await generatePov(
      makeFinding({ category: "xss" as AttackCategory }),
      "http://example.com",
      runtime,
      5,
      { disableBash: true, disableHttp: true, oracle: mockedOracle },
    );

    expect(result.hasPov).toBe(true);
    expect(result.oracle).toBe("headless-browser");
    expect(result.reason).toMatch(/playwright dialog captured/);
    expect(result.executionEvidence).toMatch(/playwright dialog captured/);
  });

  it("oracle ERROR (thrown) → inconclusive, never a pass", async () => {
    const runtime = submitTurn("<script>alert(1)</script>");
    const throwingOracle = async (): Promise<OracleResult> => {
      throw new Error("chromium failed to launch");
    };

    const result = await generatePov(
      makeFinding({ category: "xss" as AttackCategory }),
      "http://example.com",
      runtime,
      5,
      { disableBash: true, disableHttp: true, oracle: throwingOracle },
    );

    expect(result.hasPov).toBe(false);
    expect(result.inconclusive).toBe(true);
    expect(result.oracle).toBe("headless-browser");
    expect(result.reason).toMatch(/inconclusive/i);
  });

  it("oracle infra-error reason (browser launch failed) → inconclusive, not a clean fail", async () => {
    const runtime = submitTurn("<script>alert(1)</script>");
    const erroringOracle = async (): Promise<OracleResult> => ({
      verified: false,
      confidence: 0,
      evidence: "",
      reason: "playwright navigation failed: net::ERR_CONNECTION_REFUSED",
    });

    const result = await generatePov(
      makeFinding({ category: "xss" as AttackCategory }),
      "http://example.com",
      runtime,
      5,
      { disableBash: true, disableHttp: true, oracle: erroringOracle },
    );

    expect(result.hasPov).toBe(false);
    expect(result.inconclusive).toBe(true);
    expect(result.oracle).toBe("headless-browser");
  });
});

describe("generatePov — oracle delegation (SSRF / OAST callback)", () => {
  it("blind SSRF passes only when the collector callback is observed", async () => {
    const runtime = submitTurn("sent request to collector", "curl http://x");
    const collectorHit = async (): Promise<OracleResult> => ({
      verified: true,
      confidence: 1.0,
      evidence: "collector hit: nonce=ssrf123 path=/ssrf123",
      reason: "",
    });

    const result = await generatePov(
      makeFinding({ category: "ssrf" as AttackCategory }),
      "http://example.com",
      runtime,
      5,
      { disableBash: true, disableHttp: true, oracle: collectorHit },
    );

    expect(result.hasPov).toBe(true);
    expect(result.oracle).toBe("oast-callback");
    expect(result.reason).toMatch(/collector hit/);
  });

  it("blind SSRF with no collector hit → hasPov:false (clean negative)", async () => {
    const runtime = submitTurn("sent request to collector", "curl http://x");
    const noHit = async (): Promise<OracleResult> => ({
      verified: false,
      confidence: 0,
      evidence: "",
      reason: "collector never received a request for nonce=ssrf123",
    });

    const result = await generatePov(
      makeFinding({ category: "ssrf" as AttackCategory }),
      "http://example.com",
      runtime,
      5,
      { disableBash: true, disableHttp: true, oracle: noHit },
    );

    expect(result.hasPov).toBe(false);
    expect(result.inconclusive).toBeFalsy();
    expect(result.oracle).toBe("oast-callback");
  });

  it("reuses a precomputed oracle result instead of re-running the oracle", async () => {
    const runtime = submitTurn("sent request to collector", "curl http://x");
    let ran = 0;
    const countingOracle = async (): Promise<OracleResult> => {
      ran += 1;
      return { verified: false, confidence: 0, evidence: "", reason: "should not run" };
    };

    const result = await generatePov(
      makeFinding({ category: "ssrf" as AttackCategory }),
      "http://example.com",
      runtime,
      5,
      {
        disableBash: true,
        disableHttp: true,
        oracle: countingOracle,
        precomputedOracle: {
          verified: true,
          confidence: 0.9,
          evidence: "collector hit: nonce=ssrfPRE",
          reason: "",
        },
      },
    );

    expect(ran).toBe(0); // oracle was NOT re-run
    expect(result.hasPov).toBe(true);
    expect(result.oracle).toBe("oast-callback");
    expect(result.reason).toMatch(/ssrfPRE/);
  });
});

// ────────────────────────────────────────────────────────────────────
// memCorruptionVerdict — N× reproduction gate
// ────────────────────────────────────────────────────────────────────

describe("memCorruptionVerdict — N× reproduction gate", () => {
  function crash(overrides: Partial<CrashArtifact> = {}): CrashArtifact {
    return {
      kind: "asan",
      signature: "sig-uaf-1",
      rawOutput: "==1==ERROR: AddressSanitizer: heap-use-after-free",
      inputPath: "/tmp/poc.bin",
      ...overrides,
    };
  }

  it("legacy single-shot (no reproConfirmations) stays confirmed@0.95", () => {
    const v = memCorruptionVerdict(crash());
    expect(v.verdict).toBe("confirmed");
    expect(v.confidence).toBe(0.95);
    // no repro fraction appended when the field is absent
    expect(v.signals[0]?.reasoning).not.toMatch(/repro=/);
  });

  it("N×-confirmed (>=2) is confirmed@0.95 and notes the fraction", () => {
    const v = memCorruptionVerdict(crash({ reproConfirmations: 3, reproAttempts: 3 }));
    expect(v.verdict).toBe("confirmed");
    expect(v.confidence).toBe(0.95);
    expect(v.reasoning).toMatch(/3\/3.*confirmed/);
    expect(v.signals[0]?.reasoning).toMatch(/repro=3\/3/);
  });

  it("1-of-N reproduction is confirmed but dampened + flagged flaky", () => {
    const v = memCorruptionVerdict(crash({ reproConfirmations: 1, reproAttempts: 5 }));
    expect(v.verdict).toBe("confirmed"); // never silently rejected (#518)
    expect(v.confidence).toBe(0.82);
    expect(v.confidence).toBeLessThan(0.95);
    expect(v.reasoning).toMatch(/flaky-repro risk/);
    expect(v.signals[0]?.reasoning).toMatch(/repro=1\/5/);
  });

  it("single attempt (N=1) is dampened and asks for a re-run", () => {
    const v = memCorruptionVerdict(crash({ reproConfirmations: 1, reproAttempts: 1 }));
    expect(v.confidence).toBe(0.82);
    expect(v.reasoning).toMatch(/Single-shot reproduction/);
  });

  it("non-reproduced crash is inconclusive, never rejected", () => {
    const v = memCorruptionVerdict(crash({ inputPath: undefined }));
    expect(v.verdict).toBe("inconclusive");
    expect(v.confidence).toBe(0);
  });

  // #701 collapse invariant: the memcorruption kind the verdict stamps must be a
  // member of the canonical parity-locked tuple (no longer an engine-ext-only
  // string), so a sanitizer-reproduced crash surfaces to the cloud/dashboard as
  // a first-class evidence kind rather than being coerced to source-only.
  it("stamps a canonical (cloud-parity) evidenceKind on a reproduced crash (#701)", () => {
    const v = memCorruptionVerdict(crash());
    expect(v.evidenceKind).toBe("reproduced-memcorruption-poc");
    expect(VERIFY_EVIDENCE_KINDS).toContain(v.evidenceKind);
  });

  // #702-adjacent, fixture level: a confirmed memcorruption verdict flows through
  // the unified disclosure funnel as KEPT — the loop's verdict reaches disclosure
  // gating without being dropped (crash → primitive → verdict → keep).
  it("a confirmed memcorruption verdict is disclosure-worthy (kept) (#702)", () => {
    const v = memCorruptionVerdict(crash());
    const finding: Finding = {
      id: "f-uaf",
      templateId: "memsafety-asan",
      title: "heap UAF in parser",
      description: "reproduced under ASan",
      severity: "high",
      category: "use-after-free" as AttackCategory,
      status: "discovered",
      evidence: { request: "poc.bin", response: "ASAN", analysis: "confirmed" },
      confidence: 0.95,
      timestamp: Date.now(),
    };
    expect(isDisclosureWorthy(finding, v).keep).toBe(true);
  });
});

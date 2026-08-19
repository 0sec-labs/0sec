/**
 * Tests for the runtime validation schemas (`findingSchema`,
 * `pocStepArraySchema`) that guard the two highest-risk
 * `JSON.parse(...) as T` sites in the CLI: `pwnkit verify --finding <path>`
 * and the DB-stored `pocSteps` blob consumed by `pwnkit disclose`.
 *
 * The schemas are intentionally permissive on unknown top-level fields
 * (`.passthrough()`) but strict on the load-bearing core (`id`, `severity`
 * enum, evidence object, etc.). These tests pin that contract.
 */

import { describe, it, expect } from "vitest";
import { z } from "zod";
import {
  findingSchema,
  pocStepArraySchema,
  pocStepSchema,
  reportSummarySchema,
  formatZodError,
} from "../schemas.js";

function validFinding(): Record<string, unknown> {
  return {
    id: "f-001",
    templateId: "tmpl-xss",
    title: "Reflected XSS in /search",
    description: "User-controlled q= parameter renders into HTML without escape.",
    severity: "high",
    category: "xss",
    status: "verified",
    evidence: {
      request: "GET /search?q=<script>1</script>",
      response: "<html>… <script>1</script> …</html>",
    },
    timestamp: 1_700_000_000_000,
  };
}

describe("findingSchema", () => {
  it("accepts a valid minimal Finding", () => {
    const parsed = findingSchema.parse(validFinding());
    expect(parsed.id).toBe("f-001");
    expect(parsed.severity).toBe("high");
    expect(parsed.category).toBe("xss");
  });

  it("rejects a finding missing `id`", () => {
    const f = validFinding();
    delete f.id;
    expect(() => findingSchema.parse(f)).toThrow(z.ZodError);
  });

  it("rejects a finding with an empty `id` string", () => {
    const f = validFinding();
    f.id = "";
    expect(() => findingSchema.parse(f)).toThrow(z.ZodError);
  });

  it("rejects a finding with an invalid `severity` enum value", () => {
    const f = validFinding();
    f.severity = "super-critical";
    expect(() => findingSchema.parse(f)).toThrow(z.ZodError);
  });

  it("rejects a finding with an invalid `category` enum value", () => {
    const f = validFinding();
    f.category = "not-a-real-category";
    expect(() => findingSchema.parse(f)).toThrow(z.ZodError);
  });

  it("rejects a finding with non-object `evidence`", () => {
    const f = validFinding();
    f.evidence = "not an object";
    expect(() => findingSchema.parse(f)).toThrow(z.ZodError);
  });

  it("permits unknown extra fields (passthrough)", () => {
    const f = validFinding();
    f.someCloudAnnotation = { foo: 1 };
    f.experimentalField = "ok";
    const parsed = findingSchema.parse(f);
    expect((parsed as Record<string, unknown>).someCloudAnnotation).toEqual({ foo: 1 });
    expect((parsed as Record<string, unknown>).experimentalField).toBe("ok");
  });

  it("accepts an embedded valid pocSteps array", () => {
    const f = validFinding();
    f.pocSteps = [
      {
        id: "s1",
        kind: "exploit",
        summary: "Send payload",
        action: { type: "shell", cmd: "curl http://localhost/x" },
      },
    ];
    const parsed = findingSchema.parse(f);
    expect(parsed.pocSteps).toHaveLength(1);
    expect(parsed.pocSteps?.[0].action.type).toBe("shell");
  });

  it("rejects an embedded pocSteps array with a malformed step", () => {
    const f = validFinding();
    f.pocSteps = [{ id: "s1", kind: "exploit", summary: "x" }]; // missing action
    expect(() => findingSchema.parse(f)).toThrow(z.ZodError);
  });
});

describe("pocStepArraySchema", () => {
  it("parses a valid PocStep array", () => {
    const arr = [
      {
        id: "s1",
        kind: "setup",
        summary: "Boot the target",
        action: { type: "docker", image: "alpine", args: ["echo", "hi"] },
      },
      {
        id: "s2",
        kind: "exploit",
        summary: "Trigger the bug",
        action: {
          type: "http",
          method: "POST",
          url: "http://localhost/x",
          headers: { "content-type": "application/json" },
          body: "{}",
        },
        expect: { type: "http-status", status: 200 },
      },
    ];
    const parsed = pocStepArraySchema.parse(arr);
    expect(parsed).toHaveLength(2);
    expect(parsed[1].action.type).toBe("http");
    expect(parsed[1].expect?.type).toBe("http-status");
  });

  it("rejects a non-array input", () => {
    expect(() => pocStepArraySchema.parse({ id: "s1" })).toThrow(z.ZodError);
    expect(() => pocStepArraySchema.parse("not-an-array")).toThrow(z.ZodError);
    expect(() => pocStepArraySchema.parse(null)).toThrow(z.ZodError);
  });

  it("rejects an array with a malformed step (missing action)", () => {
    const arr = [{ id: "s1", kind: "exploit", summary: "x" }];
    expect(() => pocStepArraySchema.parse(arr)).toThrow(z.ZodError);
  });

  it("rejects a step with an unknown action.type", () => {
    const arr = [
      {
        id: "s1",
        kind: "exploit",
        summary: "x",
        action: { type: "telepathy", cmd: "think hard" },
      },
    ];
    expect(() => pocStepArraySchema.parse(arr)).toThrow(z.ZodError);
  });

  it("rejects a step with an invalid `kind`", () => {
    const arr = [
      {
        id: "s1",
        kind: "not-a-kind",
        summary: "x",
        action: { type: "shell", cmd: "echo" },
      },
    ];
    expect(() => pocStepArraySchema.parse(arr)).toThrow(z.ZodError);
  });

  it("accepts a note action without an expect predicate", () => {
    const arr = [
      {
        id: "n1",
        kind: "prerequisite",
        summary: "Reviewer note",
        action: { type: "note", text: "Run this in a sandbox." },
      },
    ];
    const parsed = pocStepArraySchema.parse(arr);
    expect(parsed[0].action.type).toBe("note");
  });
});

describe("pocStepSchema", () => {
  it("accepts a single well-formed step", () => {
    const step = {
      id: "s1",
      kind: "verify" as const,
      summary: "Confirm crash",
      action: { type: "shell" as const, cmd: "test -f /tmp/x" },
      expect: { type: "file-exists" as const, path: "/tmp/x" },
    };
    const parsed = pocStepSchema.parse(step);
    expect(parsed.id).toBe("s1");
    expect(parsed.expect?.type).toBe("file-exists");
  });
});

describe("reportSummarySchema", () => {
  function validSummary(): Record<string, unknown> {
    return {
      totalAttacks: 12,
      totalFindings: 3,
      critical: 1,
      high: 1,
      medium: 1,
      low: 0,
      info: 0,
    };
  }

  it("accepts a valid summary", () => {
    const parsed = reportSummarySchema.parse(validSummary());
    expect(parsed.totalAttacks).toBe(12);
    expect(parsed.critical).toBe(1);
  });

  it("rejects a summary missing a required counter", () => {
    const s = validSummary();
    delete s.totalAttacks;
    expect(() => reportSummarySchema.parse(s)).toThrow(z.ZodError);
  });

  it("rejects a summary with a negative counter", () => {
    const s = validSummary();
    s.critical = -1;
    expect(() => reportSummarySchema.parse(s)).toThrow(z.ZodError);
  });

  it("rejects a summary with a string-typed counter", () => {
    const s = validSummary();
    s.high = "1";
    expect(() => reportSummarySchema.parse(s)).toThrow(z.ZodError);
  });

  it("rejects a summary with a non-integer counter", () => {
    const s = validSummary();
    s.medium = 1.5;
    expect(() => reportSummarySchema.parse(s)).toThrow(z.ZodError);
  });

  it("permits forward-compatible extra counters (passthrough)", () => {
    const s = validSummary();
    s.exploitable = 2;
    s.suppressed = 4;
    const parsed = reportSummarySchema.parse(s);
    expect((parsed as Record<string, unknown>).exploitable).toBe(2);
    expect((parsed as Record<string, unknown>).suppressed).toBe(4);
  });
});

describe("formatZodError", () => {
  it("names the failing field path in the message", () => {
    try {
      const f = validFinding();
      f.severity = "super-critical";
      findingSchema.parse(f);
      throw new Error("expected parse to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(z.ZodError);
      const msg = formatZodError(err as z.ZodError, "finding JSON");
      expect(msg).toContain("finding JSON");
      expect(msg).toContain("severity");
    }
  });

  it("handles a root-level type mismatch", () => {
    try {
      pocStepArraySchema.parse("nope");
      throw new Error("expected parse to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(z.ZodError);
      const msg = formatZodError(err as z.ZodError, "pocSteps");
      expect(msg).toContain("pocSteps");
    }
  });
});

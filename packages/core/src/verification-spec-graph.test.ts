/**
 * pwnkit#193 / pwnkit-cloud#111 — Finding.verificationSpec wire contract.
 *
 * Coverage:
 *   1. Type narrowing on the VerificationCodePredicate discriminated union.
 *   2. JSON serialisation round-trip on a populated VerificationSpec.
 *   3. Backward-compat: a Finding with no verificationSpec is still a valid
 *      Finding and round-trips cleanly.
 *   4. The agent-tool `parseVerificationSpecArg` helper accepts both already-
 *      parsed objects and JSON strings, and rejects malformed payloads
 *      cleanly.
 *   5. The cloud-sink `normalizeFinding` passes verificationSpec through
 *      without dropping the finding when the spec itself is malformed.
 *
 * The spec is OPTIONAL and ADDITIVE — existing prose evidence + pocSteps
 * remain intact alongside it.
 */
import { randomUUID } from "node:crypto";
import { describe, it, expect } from "vitest";
import type {
  Finding,
  VerificationCodePredicate,
  VerificationSpec,
} from "@pwnkit/shared";
import { parseVerificationSpecArg } from "./agent/tools.js";
import { normalizeFinding } from "./cloud-sink.js";

function makeSpec(): VerificationSpec {
  return {
    code: [
      {
        kind: "file-contains",
        file: "app/users.ts",
        pattern: "db\\.query.*req\\.body",
      },
      {
        kind: "file-missing-pattern",
        file: "app/users.ts",
        pattern: "WHERE name = \\?",
      },
      { kind: "file-exists", file: "lib/db.ts" },
    ],
    behavior: {
      steps: [
        { method: "POST", path: "/users", body: { name: "x" }, expect: "success" },
      ],
    },
  };
}

describe("VerificationCodePredicate types (pwnkit#193)", () => {
  it("narrows kind to the right predicate fields", () => {
    const fc: VerificationCodePredicate = {
      kind: "file-contains",
      file: "a.ts",
      pattern: "x",
    };
    const fmp: VerificationCodePredicate = {
      kind: "file-missing-pattern",
      file: "a.ts",
      pattern: "x",
    };
    const fe: VerificationCodePredicate = { kind: "file-exists", file: "a.ts" };
    const ast: VerificationCodePredicate = {
      kind: "ast-shape",
      file: "a.ts",
      query: "(call_expression)",
    };

    const diff: VerificationCodePredicate = {
      kind: "git-diff-applies",
      baseCommit: "a".repeat(40),
      diff: "diff --git a/proof.ts b/proof.ts\n",
    };

    if (fc.kind === "file-contains") expect(fc.pattern).toBe("x");
    if (fmp.kind === "file-missing-pattern") expect(fmp.pattern).toBe("x");
    if (fe.kind === "file-exists") expect(fe.file).toBe("a.ts");
    if (ast.kind === "ast-shape") expect(ast.query).toBe("(call_expression)");
    if (diff.kind === "git-diff-applies") expect(diff.baseCommit).toHaveLength(40);
  });
});

describe("Finding.verificationSpec backward compatibility (pwnkit#193)", () => {
  it("a Finding without verificationSpec is still a valid Finding", () => {
    // Legacy shape: prose evidence only, no spec. Every renderer / sink /
    // DB writer must keep working when verificationSpec is undefined.
    const legacy: Finding = {
      id: randomUUID(),
      templateId: "manual",
      title: "Legacy reflected XSS",
      description: "q param reflected without encoding",
      severity: "high",
      category: "xss",
      status: "discovered",
      evidence: {
        request: "GET /search?q=<script>",
        response: "<script> echoed",
        analysis: "no encoding in the template",
      },
      timestamp: 1_700_000_000_000,
    };
    expect(legacy.verificationSpec).toBeUndefined();
    // And it round-trips through JSON unchanged.
    const restored = JSON.parse(JSON.stringify(legacy)) as Finding;
    expect(restored).toEqual(legacy);
    expect(restored.verificationSpec).toBeUndefined();
  });

  it("a Finding with verificationSpec coexists with prose evidence (additive)", () => {
    const enriched: Finding = {
      id: randomUUID(),
      templateId: "manual",
      title: "SQL injection on /users",
      description: "user input concatenated into a SQL string",
      severity: "critical",
      category: "sql-injection",
      status: "discovered",
      evidence: {
        request: "POST /users name=' OR 1=1 --",
        response: "[{...}]",
        analysis: "db.query interpolates req.body.name",
      },
      verificationSpec: makeSpec(),
      timestamp: 1_700_000_000_000,
    };
    // Both halves of the contract present.
    expect(enriched.evidence.request).toContain("OR 1=1");
    expect(enriched.verificationSpec).toBeDefined();
    expect(enriched.verificationSpec!.code).toHaveLength(3);
    expect(enriched.verificationSpec!.behavior).toBeDefined();
  });

  it("JSON serialisation round-trips a populated spec byte-identically", () => {
    const spec = makeSpec();
    const wire = JSON.stringify(spec);
    const restored = JSON.parse(wire) as VerificationSpec;
    expect(restored).toEqual(spec);
    expect(restored).not.toBe(spec);
    expect(JSON.stringify(restored)).toBe(wire);
  });
});

describe("parseVerificationSpecArg (agent tool wire shape, pwnkit#193)", () => {
  it("returns null for nullish / empty / wrong-type input", () => {
    expect(parseVerificationSpecArg(null)).toBeNull();
    expect(parseVerificationSpecArg(undefined)).toBeNull();
    expect(parseVerificationSpecArg("")).toBeNull();
    expect(parseVerificationSpecArg(42)).toBeNull();
    expect(parseVerificationSpecArg(true)).toBeNull();
    expect(parseVerificationSpecArg([])).toBeNull();
  });

  it("returns null for malformed JSON", () => {
    expect(parseVerificationSpecArg("[{")).toBeNull();
    expect(parseVerificationSpecArg("not json")).toBeNull();
  });

  it("returns null when code is missing", () => {
    expect(parseVerificationSpecArg('{"behavior":{"steps":[]}}')).toBeNull();
  });

  it("parses a JSON-encoded string of a valid spec", () => {
    const spec = makeSpec();
    const out = parseVerificationSpecArg(JSON.stringify(spec));
    expect(out).not.toBeNull();
    expect(out!.code).toHaveLength(3);
    expect(out!.behavior?.steps).toHaveLength(1);
  });

  it("accepts an already-parsed object", () => {
    const spec = makeSpec();
    const out = parseVerificationSpecArg(spec);
    expect(out).toEqual(spec);
  });

  it("drops individual malformed predicates but keeps well-formed ones", () => {
    const mixed = {
      code: [
        // good
        { kind: "file-contains", file: "a.ts", pattern: "x" },
        // missing file
        { kind: "file-contains", pattern: "x" },
        // unknown kind
        { kind: "armageddon", file: "a.ts" },
        // missing pattern on file-contains
        { kind: "file-contains", file: "b.ts" },
        // bad ast-shape (no query)
        { kind: "ast-shape", file: "a.ts" },
        // not an object
        "nope",
        null,
      ],
    };
    const out = parseVerificationSpecArg(mixed);
    expect(out).not.toBeNull();
    expect(out!.code).toHaveLength(1);
    expect(out!.code[0].kind).toBe("file-contains");
  });

  it("accepts a bounded full-commit git diff predicate", () => {
    const diff = "diff --git a/proof.ts b/proof.ts\n";
    const out = parseVerificationSpecArg({
      code: [{ kind: "git-diff-applies", baseCommit: "a".repeat(40), diff }],
    });
    expect(out?.code).toEqual([
      { kind: "git-diff-applies", baseCommit: "a".repeat(40), diff },
    ]);
  });

  it("drops a git diff predicate with an invalid base commit or empty diff", () => {
    const out = parseVerificationSpecArg({
      code: [
        { kind: "git-diff-applies", baseCommit: "deadbeef", diff: "diff --git a/a b/a\n" },
        { kind: "git-diff-applies", baseCommit: "a".repeat(40), diff: "" },
      ],
    });
    expect(out).toBeNull();
  });

  it("drops a malformed behavior block but keeps the spec", () => {
    const out = parseVerificationSpecArg({
      code: [{ kind: "file-exists", file: "a.ts" }],
      behavior: { steps: "not an array" },
    });
    expect(out).not.toBeNull();
    expect(out!.code).toHaveLength(1);
    expect(out!.behavior).toBeUndefined();
  });

  it("drops behavior steps with malformed expect", () => {
    const out = parseVerificationSpecArg({
      code: [{ kind: "file-exists", file: "a.ts" }],
      behavior: {
        steps: [
          // good
          { method: "GET", path: "/", expect: "success" },
          // bad string
          { method: "GET", path: "/", expect: "explode" },
          // bad object (status not a number)
          { method: "GET", path: "/", expect: { status: "200" } },
          // good with status
          { method: "POST", path: "/", expect: { status: 403 } },
        ],
      },
    });
    expect(out).not.toBeNull();
    expect(out!.behavior?.steps).toHaveLength(2);
  });

  it("returns null when the spec collapses to nothing usable", () => {
    // No usable predicates AND no usable behavior → nothing to attach.
    const out = parseVerificationSpecArg({
      code: [{ kind: "armageddon" }, "junk"],
    });
    expect(out).toBeNull();
  });
});

describe("cloud-sink normalizeFinding pass-through of verificationSpec (pwnkit#193)", () => {
  it("passes a structured verificationSpec through unchanged", () => {
    const spec = makeSpec();
    const out = normalizeFinding({
      id: "f-1",
      title: "SQLi",
      severity: "critical",
      evidence: { request: "x", response: "y" },
      verificationSpec: spec,
    });
    expect(out.verificationSpec).toEqual(spec);
  });

  it("parses a JSON-encoded verification_spec string (LLM tool-call shape)", () => {
    const spec = makeSpec();
    const out = normalizeFinding({
      title: "SQLi",
      severity: "high",
      evidence_request: "x",
      evidence_response: "y",
      verification_spec: JSON.stringify(spec),
    });
    expect(out.verificationSpec).toBeDefined();
    expect(out.verificationSpec).toEqual(spec);
  });

  it("drops a malformed verificationSpec without dropping the finding", () => {
    const out = normalizeFinding({
      title: "still useful",
      severity: "high",
      evidence: { request: "x", response: "y" },
      verificationSpec: "not json [",
    });
    expect(out.verificationSpec).toBeUndefined();
    expect(out.title).toBe("still useful");
  });

  it("omits verificationSpec when the input has none (legacy findings)", () => {
    const out = normalizeFinding({
      title: "legacy",
      severity: "low",
      evidence: { request: "x", response: "y" },
    });
    expect(out.verificationSpec).toBeUndefined();
  });
});

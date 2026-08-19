import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { AttackCategory, Finding } from "@pwnkit/shared";

import { checkReachability, extractSinkLocation } from "./reachability.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "reach-test",
    templateId: "audit-sink",
    title: "Potential vuln",
    description: "A sink was flagged",
    severity: "high",
    category: "path-traversal" as AttackCategory,
    status: "discovered",
    evidence: { request: "", response: "" },
    confidence: 0.7,
    timestamp: Date.now(),
    ...overrides,
  };
}

let root: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "pwnkit-reach-"));
});

afterEach(() => {
  try {
    rmSync(root, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

function write(relPath: string, content: string): void {
  const abs = join(root, relPath);
  const dirEnd = abs.lastIndexOf("/");
  if (dirEnd > 0) mkdirSync(abs.slice(0, dirEnd), { recursive: true });
  writeFileSync(abs, content, "utf8");
}

describe("extractSinkLocation", () => {
  it("pulls a file path hint from the description", () => {
    const f = makeFinding({
      description:
        "The sink lives in src/utils/path-helper.ts:42 and is called with user input.",
    });
    const sink = extractSinkLocation(f);
    expect(sink.file).toBe("src/utils/path-helper.ts");
  });

  it("returns nulls when the finding has no hints", () => {
    const f = makeFinding({ description: "just some prose" });
    const sink = extractSinkLocation(f);
    expect(sink.file).toBeNull();
  });
});

describe("checkReachability", () => {
  it("marks a finding reachable when the sink file is imported by a route", async () => {
    write(
      "src/utils/helper.ts",
      `export function writeThing(p: string) { return p; }\n`,
    );
    write(
      "src/routes/users.ts",
      `import { writeThing } from "../utils/helper";\nexport function handler(req: any) { return writeThing(req.body.p); }\n`,
    );
    const finding = makeFinding({
      description: "Vulnerable sink at src/utils/helper.ts in writeThing",
    });
    const result = await checkReachability(finding, root);
    expect(result.reachable).toBe(true);
    expect(result.entryPoints.some((e) => e.includes("routes"))).toBe(true);
  });

  it("marks a finding unreachable when the sink is only imported by a test file", async () => {
    write(
      "src/utils/helper.ts",
      `export function writeThing(p: string) { return p; }\n`,
    );
    write(
      "src/utils/__tests__/helper.test.ts",
      `import { writeThing } from "../helper";\ntest("x", () => { writeThing("a"); });\n`,
    );
    // Need at least one entry point so the gate knows the tree has entries.
    write(
      "src/routes/health.ts",
      `export function handler() { return "ok"; }\n`,
    );
    const finding = makeFinding({
      description: "Vulnerable sink at src/utils/helper.ts in writeThing",
    });
    const result = await checkReachability(finding, root);
    expect(result.reachable).toBe(false);
    expect(result.confidence).toBeGreaterThanOrEqual(0.7);
    expect(result.reason.toLowerCase()).toContain("test");
  });

  it("marks a finding unreachable when the sink file has no importers at all", async () => {
    write(
      "src/dead/orphan.ts",
      `export function thing(p: string) { return p; }\n`,
    );
    write(
      "src/routes/users.ts",
      `export function handler() { return "ok"; }\n`,
    );
    const finding = makeFinding({
      description: "Vulnerable sink at src/dead/orphan.ts",
    });
    const result = await checkReachability(finding, root);
    expect(result.reachable).toBe(false);
    expect(result.reason.toLowerCase()).toMatch(/dead code|no importers/);
  });

  it("marks a finding unreachable when the sink lives under __internal__", async () => {
    write(
      "src/__internal__/tool.ts",
      `export function thing(p: string) { return p; }\n`,
    );
    write(
      "src/routes/users.ts",
      `import { thing } from "../__internal__/tool";\nexport function handler() { return thing("x"); }\n`,
    );
    const finding = makeFinding({
      description: "Vulnerable sink at src/__internal__/tool.ts",
    });
    const result = await checkReachability(finding, root);
    expect(result.reachable).toBe(false);
    expect(result.reason).toMatch(/__internal__|internal/);
  });

  it("returns a low-confidence reachable verdict when the sink file cannot be located", async () => {
    write(
      "src/routes/users.ts",
      `export function handler() { return "ok"; }\n`,
    );
    const finding = makeFinding({
      description: "Something vague without any file path",
    });
    const result = await checkReachability(finding, root);
    expect(result.reachable).toBe(true);
    expect(result.confidence).toBeLessThan(0.7);
  });

  it("treats a file that itself registers routes as an entry point", async () => {
    write(
      "src/server.ts",
      `import express from "express";\nconst app = express();\napp.post("/users", (req, res) => { eval(req.body.code); });\n`,
    );
    const finding = makeFinding({
      description: "eval sink at src/server.ts",
    });
    const result = await checkReachability(finding, root);
    expect(result.reachable).toBe(true);
    expect(result.entryPoints).toContain("src/server.ts");
  });
});

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { runFileReviewPipeline } from "./pipeline.js";
import type { ReviewInvocation, ReviewInvoker } from "./types.js";

// A fake target repo with one or more injectable files.
function makeTarget(files: readonly string[] = ["app.ts"]): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pwnkit-fr-pipe-"));
  fs.mkdirSync(path.join(root, "src"), { recursive: true });
  for (const fileName of files) {
    fs.writeFileSync(
      path.join(root, "src", fileName),
      ['const q = `SELECT * FROM users WHERE id = ${req.params.id}`;', "fetch(req.body.url);"].join("\n"),
    );
  }
  return root;
}

function investigationFilePath(prompt: string): string {
  const match = prompt.match(/## Target Files\n-\s+`([^`]+)`/);
  if (!match) throw new Error("Investigation prompt did not list a file");
  return match[1];
}

function revalidationFindingId(prompt: string): string {
  const match = prompt.match(/^- `([^`]+)` \(alias F1,/m);
  if (!match) throw new Error("Revalidation prompt did not list a finding ID");
  return match[1];
}

function inventoryOutput(representativeFile: string): string {
  return JSON.stringify({
    infoMarkdown: [
      "## What this codebase does",
      "Test service.",
      "## Auth shape",
      "No auth in fixture.",
      "## Threat model",
      "Untrusted request input.",
      "## Project-specific patterns to flag",
      "Raw query construction.",
      "## Known false-positives",
      "None.",
    ].join("\n"),
    surfaces: [{
      id: "public-route",
      kind: "http",
      description: "Fixture request handler.",
      fileGlobs: [representativeFile],
      representativeFiles: [representativeFile],
      exposure: "public",
      anchorPatterns: [],
    }],
    inspectedPaths: ["src/"],
  });
}

// Invoker that mirrors the response contract: it returns a finding for the
// file the investigation prompt names and echoes the exact finding ID shown to
// it during revalidation.
function scriptedInvoker(): ReviewInvoker {
  return async (prompt: string, label: string): Promise<ReviewInvocation> => {
    if (label === "inventory") {
      return {
        output: inventoryOutput("src/app.ts"),
        usage: { inputTokens: 200, outputTokens: 100 },
        durationMs: 10,
        costUsd: 0.002,
      };
    }
    if (label === "revalidate") {
      return {
        output: JSON.stringify([{
          findingId: revalidationFindingId(prompt),
          verdict: "true-positive",
          reasoning: "Confirmed — user input reaches the sink with no sanitization.",
        }]),
        usage: { inputTokens: 100, outputTokens: 50 },
        durationMs: 10,
        costUsd: 0.001,
      };
    }
    if (label === "refusal") {
      return {
        output: JSON.stringify({ refused: false }),
        usage: { inputTokens: 10, outputTokens: 5 },
        durationMs: 5,
        costUsd: 0.001,
      };
    }
    return {
      output:
        "```json\n" +
        JSON.stringify([{
          filePath: investigationFilePath(prompt),
          findings: [{
            severity: "high",
            vulnSlug: "sql-injection",
            title: "SQLi via request id",
            description: "Template-literal SQL interpolates req.params.id.",
            lineNumbers: [1],
            recommendation: "Parameterize the query.",
            confidence: "high",
          }],
        }]) +
        "\n```",
      usage: { inputTokens: 500, outputTokens: 200 },
      durationMs: 20,
      costUsd: 0.005,
    };
  };
}

describe("runFileReviewPipeline", () => {
  it("runs scan → process → revalidate end to end with exit code 1", async () => {
    const root = makeTarget();
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "pwnkit-fr-data-"));
    const result = await runFileReviewPipeline({
      rootPath: root,
      dataDir,
      invoker: scriptedInvoker(),
      withRevalidate: true,
      log: () => {},
    });

    expect(result.exitCode).toBe(1);
    expect(result.stats.filesScanned).toBeGreaterThan(0);
    expect(result.stats.candidatesFound).toBeGreaterThan(0);
    expect(result.stats.netNewFindings).toBe(1);
    expect(result.stats.truePositives).toBe(1);
    expect(result.stats.totalCostUsd).toBeGreaterThan(0);
  });

  it("blocks paid processing when an explicit inventory coverage gate fails", async () => {
    const root = makeTarget();
    fs.writeFileSync(path.join(root, "src", "clean.ts"), "export const clean = true;\n");
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "pwnkit-fr-data-"));
    const labels: string[] = [];
    const invoker: ReviewInvoker = async (_prompt, label) => {
      labels.push(label);
      if (label === "inventory") {
        return {
          output: inventoryOutput("src/clean.ts"),
          durationMs: 10,
          costUsd: 0.003,
        };
      }
      throw new Error(`paid stage should not run after failed coverage: ${label}`);
    };

    const result = await runFileReviewPipeline({
      rootPath: root,
      dataDir,
      invoker,
      withInventory: true,
      log: () => {},
    });

    expect(result.exitCode).toBe(2);
    expect(result.stats.coveragePassed).toBe(false);
    expect(result.stats.totalCostUsd).toBe(0.003);
    expect(labels).toEqual(["inventory"]);
  });

  it("counts inventory spend against the whole-run cost cap", async () => {
    const root = makeTarget();
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "pwnkit-fr-data-"));

    const result = await runFileReviewPipeline({
      rootPath: root,
      dataDir,
      invoker: scriptedInvoker(),
      withInventory: true,
      maxCostUsd: 0.001,
      log: () => {},
    });

    expect(result.exitCode).toBe(3);
    expect(result.stats.totalCostUsd).toBe(0.002);
  });

  it("returns exit code 3 when revalidation exhausts the remaining run budget", async () => {
    const root = makeTarget();
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "pwnkit-fr-data-"));
    const result = await runFileReviewPipeline({
      rootPath: root,
      dataDir,
      invoker: scriptedInvoker(),
      withRevalidate: true,
      // Process costs $0.006; revalidation is allowed to start with $0.0005
      // remaining and then crosses the whole-run cap at its checkpoint.
      maxCostUsd: 0.0065,
      log: () => {},
    });

    expect(result.exitCode).toBe(3);
    expect(result.stats.truePositives).toBe(1);
    expect(result.stats.totalCostUsd).toBeGreaterThan(0.0065);
  });

  it("returns exit code 3 at a cost limit and resumes cleanly", async () => {
    const root = makeTarget(["app.ts", "other.ts"]);
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "pwnkit-fr-data-"));
    // The first batch completes; the cost cap blocks the next one.
    const limited = await runFileReviewPipeline({
      rootPath: root,
      dataDir,
      invoker: scriptedInvoker(),
      maxCostUsd: 0.004,
      batchSize: 1,
      concurrency: 1,
      log: () => {},
    });
    expect(limited.exitCode).toBe(3);
    expect(limited.stats.netNewFindings).toBe(1);

    // Re-running preserves the completed first batch and processes the pending second one.
    const resumed = await runFileReviewPipeline({
      rootPath: root,
      dataDir,
      invoker: scriptedInvoker(),
      log: () => {},
    });
    expect(resumed.exitCode).toBe(1);
    expect(resumed.stats.netNewFindings).toBe(1);
  });

  it("is clean (exit 0) when the repo has no candidates", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "pwnkit-fr-clean-"));
    fs.writeFileSync(path.join(root, "README.ts"), "export const x = 1;\n");
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "pwnkit-fr-data-"));
    const result = await runFileReviewPipeline({
      rootPath: root,
      dataDir,
      invoker: scriptedInvoker(),
      log: () => {},
    });
    expect(result.exitCode).toBe(0);
    expect(result.stats.netNewFindings).toBe(0);
  });
});

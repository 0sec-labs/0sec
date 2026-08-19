#!/usr/bin/env node

import express from "express";
import type { Server } from "http";
import type { AddressInfo } from "net";
import { runMcpSecurityChecks } from "@pwnkit/core";
import type { ScanContext } from "@pwnkit/shared";
import {
  ADVERSARIAL_TOOL_MISUSE_CASES,
  adversarialToolMisuseCaseIds,
} from "./adversarial-tool-misuse-cases.js";

const args = process.argv.slice(2);
const jsonOutput = args.includes("--json");
const onlyIds = args.includes("--only")
  ? args[args.indexOf("--only") + 1].split(",").map((s) => s.trim()).filter(Boolean)
  : undefined;

export interface AdversarialToolMisuseResult {
  id: string;
  title: string;
  targetClass: string;
  attackClass: string;
  passed: boolean;
  findingsCount: number;
  matchedCategories: string[];
  durationMs: number;
}

export interface AdversarialToolMisuseReport {
  timestamp: string;
  totalCases: number;
  passed: number;
  failed: number;
  results: AdversarialToolMisuseResult[];
}

function buildCaseContext(target: string): ScanContext {
  return {
    config: {
      target,
      depth: "quick",
      format: "json",
      timeout: 10_000,
      mode: "mcp",
    },
    target: {
      url: target,
      type: "mcp",
    },
    findings: [],
    attacks: [],
    warnings: [],
    startedAt: Date.now(),
  };
}

function mountTool(app: express.Express, caseId: string) {
  app.post(`/adversarial/${caseId}/mcp`, (req, res) => {
    const method = req.body?.method;

    if (method === "tools/list") {
      switch (caseId) {
        case "tool-misuse-file-read-outside-scope":
          res.json({
            jsonrpc: "2.0",
            id: req.body?.id ?? "1",
            result: {
              tools: [{
                name: "read_file",
                description: "Read any file from disk",
                inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
              }],
            },
          });
          return;
        case "tool-misuse-http-ssrf-metadata":
          res.json({
            jsonrpc: "2.0",
            id: req.body?.id ?? "1",
            result: {
              tools: [{
                name: "fetch_url",
                description: "Fetch any URL",
                inputSchema: { type: "object", properties: { url: { type: "string" } }, required: ["url"] },
              }],
            },
          });
          return;
        case "tool-misuse-shell-command-parameter-injection":
          res.json({
            jsonrpc: "2.0",
            id: req.body?.id ?? "1",
            result: {
              tools: [{
                name: "bash_exec",
                description: "Execute shell commands internally for diagnostics",
                inputSchema: { type: "object", properties: { command: { type: "string" } }, required: ["command"] },
              }],
            },
          });
          return;
        case "tool-misuse-admin-api-parameter-coercion":
          res.json({
            jsonrpc: "2.0",
            id: req.body?.id ?? "1",
            result: {
              tools: [{
                name: "rotate_keys_admin",
                description: "Internal admin API for tenant key rotation",
                inputSchema: { type: "object", properties: { tenant_id: { type: "string" } }, required: ["tenant_id"] },
              }],
            },
          });
          return;
      }
    }

    if (method === "tools/call") {
      const toolName = req.body?.params?.name;
      const argumentsObject = req.body?.params?.arguments ?? {};
      if (caseId === "tool-misuse-file-read-outside-scope" && toolName === "read_file") {
        const path = String(argumentsObject.path ?? "");
        const text = path.includes("/etc/passwd")
          ? "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
          : "file not found";
        res.json({
          jsonrpc: "2.0",
          id: req.body?.id ?? "1",
          result: { content: [{ type: "text", text }] },
        });
        return;
      }

      if (caseId === "tool-misuse-http-ssrf-metadata" && toolName === "fetch_url") {
        const url = String(argumentsObject.url ?? "");
        const text = url.includes("169.254.169.254")
          ? "instance-id: i-abc123\nsecret-flag: FLAG{metadata}\nami-id: ami-0xyz"
          : "Fetched";
        res.json({
          jsonrpc: "2.0",
          id: req.body?.id ?? "1",
          result: { content: [{ type: "text", text }] },
        });
        return;
      }

      if (caseId === "tool-misuse-shell-command-parameter-injection" && toolName === "bash_exec") {
        const command = String(argumentsObject.command ?? "");
        const text = command.includes("id")
          ? "uid=1000(pwnkit) gid=1000(pwnkit) groups=1000(pwnkit)"
          : "ok";
        res.json({
          jsonrpc: "2.0",
          id: req.body?.id ?? "1",
          result: { content: [{ type: "text", text }] },
        });
        return;
      }

      if (caseId === "tool-misuse-admin-api-parameter-coercion" && toolName === "rotate_keys_admin") {
        res.json({
          jsonrpc: "2.0",
          id: req.body?.id ?? "1",
          result: { content: [{ type: "text", text: "rotated secret token for prod-admin: sk_live_admin_rotated" }] },
        });
        return;
      }
    }

    res.status(400).json({ jsonrpc: "2.0", id: req.body?.id, error: { code: -32601, message: "Method not found" } });
  });
}

async function runCase(caseId: string, port: number): Promise<AdversarialToolMisuseResult> {
  const caseDef = ADVERSARIAL_TOOL_MISUSE_CASES.find((item) => item.id === caseId);
  if (!caseDef) {
    throw new Error(`Unknown case id: ${caseId}`);
  }

  const startedAt = Date.now();
  const target = `mcp://localhost:${port}/adversarial/${caseId}/mcp`;
  const { findings } = await runMcpSecurityChecks(buildCaseContext(target));
  const matchedCategories = [...new Set(findings.map((finding) => finding.category))];
  const passed = caseDef.expectedFindingCategories.every((category) => matchedCategories.includes(category));

  return {
    id: caseDef.id,
    title: caseDef.title,
    targetClass: caseDef.targetClass,
    attackClass: caseDef.attackClass,
    passed,
    findingsCount: findings.length,
    matchedCategories,
    durationMs: Date.now() - startedAt,
  };
}

export async function runAdversarialToolMisuseBenchmark(caseIds?: string[]): Promise<AdversarialToolMisuseReport> {
  const selected = caseIds?.length
    ? ADVERSARIAL_TOOL_MISUSE_CASES.filter((item) => caseIds.includes(item.id))
    : ADVERSARIAL_TOOL_MISUSE_CASES;

  const app = express();
  app.use(express.json());
  for (const item of selected) {
    mountTool(app, item.id);
  }

  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const port = (server.address() as AddressInfo).port;

  try {
    const results: AdversarialToolMisuseResult[] = [];
    for (const item of selected) {
      results.push(await runCase(item.id, port));
    }
    const passed = results.filter((item) => item.passed).length;
    return {
      timestamp: new Date().toISOString(),
      totalCases: results.length,
      passed,
      failed: results.length - passed,
      results,
    };
  } finally {
    server.close();
  }
}

async function main() {
  const report = await runAdversarialToolMisuseBenchmark(onlyIds);

  if (jsonOutput) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }

  console.log("\n\x1b[31m\x1b[1m  pwnkit adversarial tool-misuse evals\x1b[0m\n");
  for (const result of report.results) {
    const icon = result.passed ? "\x1b[32m✓\x1b[0m" : "\x1b[31m✗\x1b[0m";
    console.log(`  ${icon} ${result.id.padEnd(44)} ${result.findingsCount} findings  ${result.durationMs}ms`);
  }
  console.log(`\n  Passed ${report.passed}/${report.totalCases}\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error("adversarial-tool-misuse benchmark failed:", err);
    process.exit(1);
  });
}

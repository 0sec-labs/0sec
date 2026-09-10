#!/usr/bin/env node
/** Real provider-backed repair of a deliberately mislocated source-review draft. */
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { maybeLoadCodexAuth } from "../packages/cli/dist/codex-auth.js";
import { runNativeAgentLoop } from "../packages/core/dist/agent/native-loop.js";
import { TOOL_DEFINITIONS } from "../packages/core/dist/agent/tools.js";
import { LlmApiRuntime } from "../packages/core/dist/runtime/llm-api.js";
import { osecDB } from "../packages/db/dist/index.js";
import { getRates, MODEL_PRICING } from "../packages/shared/dist/index.js";

maybeLoadCodexAuth();
process.env["0SEC_DISABLE_HUNT_MEMORY"] = "1";
process.env["0SEC_CLOUD_SINK"] = "";
const temporary = mkdtempSync(join(tmpdir(), "0sec-citation-e2e-"));
const root = join(temporary, "source");
mkdirSync(root);
const cleanup = () => rmSync(temporary, { recursive: true, force: true });
process.on("exit", cleanup);
const deadline = setTimeout(() => { console.error("Source citation E2E exceeded five minutes"); process.exit(1); }, 300000);
let db;
try {
  writeFileSync(join(root, "proxy.py"), 'import requests\nfrom flask import Flask, request\napp = Flask(__name__)\n@app.get("/proxy")\ndef proxy():\n    return requests.get(request.args["url"]).text\n');
  const model = process.env["0SEC_MODEL"] || "gpt-5.6-luna";
  assert.notEqual(getRates(model), MODEL_PRICING.default, "model pricing must be known");
  const runtime = new LlmApiRuntime({ type: "api", model, timeout: 60000 });
  db = new osecDB(join(temporary, "findings.db"));
  const scanId = db.createScan({ target: root, mode: "deep", depth: "quick", format: "json", timeout: 60000 });
  const draft = {
    title: "Caller-controlled proxy URL", severity: "high", category: "ssrf", cwe: "CWE-918", confidence: 0.7,
    description: "The proxy passes caller-controlled URLs directly to an outbound HTTP client without destination restrictions.",
    evidence_request: "Source inspection of the /proxy handler; no HTTP request was executed.",
    evidence_response: "The handler returns the response from requests.get(request.args[\"url\"]).",
    evidence_analysis: "CWE-918: request.args[\"url\"] flows directly into requests.get without a destination allow-list. This is a source-only lead, not a reproduced exploit.",
    source_path: "proxy.py", source_start_line: 7, source_end_line: 7,
  };
  const badDraftCalls = new Set();
  const rejectedCalls = new Set();
  const observedRuntime = {
    type: "api", isAvailable: () => runtime.isAvailable(), resolvedModel: () => runtime.resolvedModel(),
    executeNative: async (...args) => {
      for (const message of args[1]) {
        if (!Array.isArray(message.content)) continue;
        for (const block of message.content) {
          if (block.type !== "tool_result" || !badDraftCalls.has(block.tool_use_id) || rejectedCalls.has(block.tool_use_id)) continue;
          assert.equal(block.is_error, true, "the host must reject the invalid citation");
          assert.match(typeof block.content === "string" ? block.content : JSON.stringify(block.content), /source_start_line/, "rejection must identify the invalid source coordinates");
          assert.equal(db.getScanFindings(scanId).length, 0, "invalid source coordinates must not create a finding record");
          rejectedCalls.add(block.tool_use_id);
        }
      }
      const response = await runtime.executeNative(...args);
      for (const block of response.content) {
        if (block.type === "tool_use" && block.name === "save_finding" && block.input.source_path === "proxy.py" && block.input.source_start_line === 7) badDraftCalls.add(block.id);
      }
      return response;
    },
  };
  console.error("[source-citation] submitting a controlled bad-coordinate draft and exercising model repair");
  const state = await runNativeAgentLoop({
    config: {
      scanId, role: "review", scopePath: root, target: root,
      tools: [TOOL_DEFINITIONS.read_file, TOOL_DEFINITIONS.save_finding, TOOL_DEFINITIONS.done],
      maxTurns: 12, costModel: model, costCeilingUsd: 0.5,
      systemPrompt: "This is an authorized, controlled test of source-citation validation, not an exploit run. First submit the supplied draft unchanged with save_finding as your only tool call; its deliberately incorrect coordinates exercise host validation. After rejection, read proxy.py, correct the citation using the actual source, and resubmit the source-only finding. Do not drop source_path or claim runtime verification. Once the corrected finding is saved, call done. Do not make network requests or edit files. Draft: " + JSON.stringify(draft),
    },
    runtime: observedRuntime, db,
  });
  assert(!state.errorExit && !state.costCeilingExceeded && state.done, "the real model must finish the repair run");
  assert(rejectedCalls.size > 0, "the model must receive the actual invalid-citation error");
  assert.equal(state.findings.length, 1, "only the corrected finding may survive");
  const finding = state.findings[0];
  assert.equal(finding.reviewAnnotation?.path, "proxy.py");
  const annotation = finding.reviewAnnotation;
  assert(annotation && annotation.startLine >= 1 && annotation.startLine <= 6 && (annotation.endLine ?? annotation.startLine) === 6, "the corrected source span must include the sink and stay within the file");
  assert.equal(finding.status, "discovered", "citation repair must not manufacture exploit verification");
  assert.equal(db.getScanFindings(scanId).length, 1);
  assert(Number.isFinite(state.estimatedCostUsd) && state.estimatedCostUsd > 0 && state.estimatedCostUsd <= 0.5, "model use must have bounded cost receipts");
  console.log(JSON.stringify({ outcome: "passed", model, controlledInvalidDraft: true, rejectedBeforePersistence: true, modelCorrectedCitation: true, sourceOnlyFinding: true, estimatedCostUsd: state.estimatedCostUsd }));
} catch (error) {
  console.error(JSON.stringify({ outcome: "failed", error: error instanceof Error ? error.stack : String(error) }));
  process.exitCode = 1;
} finally {
  clearTimeout(deadline);
  db?.close();
  cleanup();
  process.removeListener("exit", cleanup);
}

#!/usr/bin/env node
/** Real provider-backed synthesis, validation, promotion, reload, and retirement.
 * Uses a deliberately limited baseline lens and independently authored fixtures.
 * No synthetic registrations, fake findings, dry-run, or skip-as-success mode.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { maybeLoadCodexAuth } from "../packages/cli/dist/codex-auth.js";
import { runLensSynthesisInput } from "../packages/cli/dist/commands/lens-synth.js";
import {
  approveObservation, captureObservation, claimForProcessing, getObservation,
  inspectLensRegistry, makeFinderLensProbe, markProcessed, releaseClaim, retireArchetype,
} from "../packages/core/dist/stages/lens-synthesis/index.js";
import { loadAppsecFinderLenses } from "../packages/core/dist/stages/appsec-catalog.js";
import { LlmApiRuntime } from "../packages/core/dist/runtime/llm-api.js";
import { estimateCost, getRates, MODEL_PRICING } from "../packages/shared/dist/index.js";

maybeLoadCodexAuth();
process.env["0SEC_DISABLE_HUNT_MEMORY"] = "1";
process.env["0SEC_CLOUD_SINK"] = "";
const root = mkdtempSync(join(tmpdir(), "0sec-lens-e2e-"));
const registry = join(root, "lenses.json");
const queue = { storePath: join(root, "observations.json") };
const previousRegistry = process.env["0SEC_APPSEC_LENS_REGISTRY"];
process.env["0SEC_APPSEC_LENS_REGISTRY"] = registry;
const cleanup = () => rmSync(root, { recursive: true, force: true });
process.on("exit", cleanup);
// Two trials cover development and held-out lanes, each with clean controls:
// sixteen probes execute twenty-four serial finder runs.
const deadline = setTimeout(() => {
  console.error("Lens evolution E2E exceeded its forty-minute deadline");
  process.exit(1);
}, 2400000);
let claim;
try {
  const modelId = process.env["0SEC_MODEL"] || "gpt-5.6-luna";
  assert.notEqual(getRates(modelId), MODEL_PRICING.default, "model pricing must be known");
  const fixture = (id, filename, code, expectedRange) => {
    const directory = join(root, id);
    mkdirSync(directory);
    const path = join(directory, filename);
    writeFileSync(path, code);
    return {
      id, path, contentDigest: `sha256:${createHash("sha256").update(code).digest("hex")}`,
      ...(expectedRange ? { expectedCwe: "CWE-918", expectedFile: filename, expectedRange }
        : { cleanProvenance: "independent-source-review:constant-public-URL-no-user-input" }),
    };
  };
  const positive = fixture("development", "proxy.js", 'import express from "express";\nconst app = express();\napp.get("/proxy", async (req, res) => {\n  const upstream = await fetch(req.query.url);\n  res.send(await upstream.text());\n});\n', [3, 5]);
  const heldOut = fixture("held-out", "proxy.py", 'import requests\nfrom flask import Flask, request\napp = Flask(__name__)\n@app.get("/proxy")\ndef proxy():\n    return requests.get(request.args["url"]).text\n', [5, 6]);
  const clean = fixture("negative-control", "status.js", 'export async function status() {\n  const response = await fetch("https://example.com/status");\n  return response.status;\n}\n');
  const corpus = { positives: [positive], heldOut: [heldOut], negativeControls: [clean] };
  const trials = 2;
  const maxProbeCalls = trials * 2 * (corpus.positives.length + corpus.heldOut.length + 2 * corpus.negativeControls.length);
  const observation = captureObservation({
    classHint: "CWE-918 server-side request forgery", sinkPattern: "HTTP request URL reaches fetch without an allow-list",
    exampleFileLine: `${positive.path}:4`, whyMissed: "The seed lens only examines OS command execution, not HTTP clients.",
    source: "confirmed-miss", scanId: "live-lens-e2e", sourceRevisionDigest: positive.contentDigest,
    evidenceRefs: [{ file: positive.path, digest: positive.contentDigest.slice(7) }], consent: true,
  }, queue);
  approveObservation(observation.id, corpus, { ...queue, allowModelSourceAccess: true });
  [claim] = claimForProcessing(queue);
  assert.equal(claim?.id, observation.id);
  assert.deepEqual(claimForProcessing(queue), [], "a second consumer cannot steal the live claim");
  const before = loadAppsecFinderLenses();
  const seed = [{ id: "os-command-injection", challengeHint: "Hunt only OS command injection through child_process or subprocess. HTTP fetches are outside this lens; do not report SSRF under this lens." }];
  const realProbe = makeFinderLensProbe({ runtime: "api", models: [modelId], depth: "quick", concurrency: 1, costCeilingUsd: 0.5, baseLenses: () => seed, log: (message) => console.error(message) });
  let probeCalls = 0;
  let validationCostUsd = 0;
  const probe = Object.assign(async (...args) => {
    assert(++probeCalls <= maxProbeCalls, "bounded fixture/variant/trial count exceeded");
    assert(validationCostUsd + 0.5 <= 6, "validation spend ceiling reached");
    const started = performance.now();
    console.error(JSON.stringify({ phase: "probe-start", probe: probeCalls, variant: args[0]?.id ?? "baseline", fixture: args[1].id }));
    const outcome = await realProbe(...args);
    assert(Number.isFinite(outcome.costUsd), outcome.error || "missing probe cost receipt");
    validationCostUsd += outcome.costUsd;
    console.error(JSON.stringify({ phase: "probe-complete", probe: probeCalls, durationMs: performance.now() - started, costUsd: outcome.costUsd, findings: outcome.findings?.length, error: outcome.error }));
    return outcome;
  }, { baselineSnapshot: () => realProbe.baselineSnapshot() });
  let modelCalls = 0;
  let synthesisCostUsd = 0;
  const runtime = new LlmApiRuntime({ type: "api", model: modelId, timeout: 60000 });
  const model = async (system, messages, tools) => {
    assert(++modelCalls <= 1, "one cluster must require only one synthesis call");
    const result = await runtime.executeNative(system, messages, tools, undefined, AbortSignal.timeout(60000));
    assert(result.usage, result.error || "synthesis usage missing");
    synthesisCostUsd += estimateCost(result.usage, runtime.resolvedModel()) + (result.usage.cacheWriteTokens ?? 0) / 1000000 * getRates(runtime.resolvedModel()).input * 0.25;
    assert(synthesisCostUsd <= 2, "synthesis spend ceiling exceeded");
    return result;
  };
  const result = await runLensSynthesisInput({
    misses: { curatedCandidates: [{ classHint: claim.classHint, sinkPattern: claim.sinkPattern, exampleFileLine: claim.exampleFileLine, whyMissed: claim.whyMissed, source: claim.source }] },
    corpus: claim.approvedShape,
  }, { registry, promote: true, trials, maxRegister: 1, model: modelId }, { model, probe, log: (message) => console.error(message) });
  console.log(JSON.stringify({ phase: "validation", validations: result.validations, rejected: result.rejected, warnings: result.warnings }));
  assert.equal(result.registered.length, 1, "real candidate must pass every validation gate and register");
  const promoted = result.registered[0];
  assert(markProcessed(claim.id, { registeredLensIds: [promoted.id], registeredLenses: result.registered, validatedAt: new Date().toISOString(), validationReports: result.validations }, claim.claimToken, queue));
  claim = undefined;
  assert.equal(getObservation(observation.id, queue)?.status, "processed");
  const isPromoted = (lens) => lens.id === promoted.id && lens.versionDigest === promoted.lensVersionDigest;
  assert(!before.some(isPromoted), "previously captured readers cannot acquire a new lens");
  const after = loadAppsecFinderLenses();
  assert(after.some(isPromoted), "a new reader must load the promoted version without restart");
  assert.equal(inspectLensRegistry(registry).activeLensCount, 1);
  assert(retireArchetype(promoted.id, { registryPath: registry }).retired);
  assert(!loadAppsecFinderLenses().some(isPromoted), "new readers must honor retirement");
  assert(after.some(isPromoted), "captured readers retain their original lens version");
  const status = inspectLensRegistry(registry);
  assert(status.valid && status.activeLensCount === 0 && status.ledgerEntries === 2);
  console.log(JSON.stringify({ outcome: "passed", model: modelId, synthesisCostUsd, validationCostUsd, probeCalls, perFixtureCostCeilingUsd: 0.5, registered: promoted, observationProcessed: true, nextRunReload: true, capturedReaderPinning: true, retirement: true }));
} catch (error) {
  console.error(JSON.stringify({ outcome: "failed", error: error instanceof Error ? error.message : String(error) }));
  process.exitCode = 1;
} finally {
  if (claim) releaseClaim(claim.id, claim.claimToken, queue);
  clearTimeout(deadline);
  if (previousRegistry === undefined) delete process.env["0SEC_APPSEC_LENS_REGISTRY"];
  else process.env["0SEC_APPSEC_LENS_REGISTRY"] = previousRegistry;
  cleanup();
}

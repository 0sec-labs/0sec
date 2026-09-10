#!/usr/bin/env node
/** Real provider + Docker lifecycle. Requires built packages and node:22-alpine.
 * Deliberately small credential-finder benchmark, not a general security claim.
 * No host execution of generated source, injected model, or isolation fallback.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { maybeLoadCodexAuth } from "../packages/cli/dist/codex-auth.js";
import {
  approveEvolutionCandidate, loadEvolutionRegistry, parseEvolutionConfig,
  resolveEvolutionImage, rollbackEvolutionVersion, runEvolution,
} from "../packages/core/dist/improvement/index.js";
import { createEvolvedFinder } from "../packages/core/dist/stages/evolved-finder.js";

maybeLoadCodexAuth();
process.env["0SEC_DISABLE_HUNT_MEMORY"] = "1";
process.env["0SEC_CLOUD_SINK"] = "";
const root = mkdtempSync(join(tmpdir(), "0sec-source-e2e-"));
const sourceRoot = join(root, "source");
const storePath = join(root, "store");
const cleanup = () => rmSync(root, { recursive: true, force: true });
process.on("exit", cleanup);
const controller = new AbortController();
const deadline = setTimeout(() => controller.abort(new Error("Source evolution E2E exceeded its ten-minute deadline")), 600000);

try {
  assert.notEqual(process.getuid?.(), 0, "run as a non-root user with Docker access");
  execFileSync("docker", ["info", "--format", "{{.ServerVersion}}"], { timeout: 10000, stdio: "pipe" });
  const image = await resolveEvolutionImage("node:22-alpine");
  mkdirSync(sourceRoot);
  const worker = String.raw`import { readFileSync } from 'node:fs';
const input = JSON.parse(readFileSync(0, 'utf8'));
const findings = [];
for (const [index, line] of input.file.content.split('\n').entries()) {
  if (/\bpassword\s*=\s*["'][^"']+["']/.test(line)) {
    findings.push({title:'Hardcoded credential', severity:'high', line:index+1, analysis:'Literal credential assigned.'});
  }
}
console.log(JSON.stringify({schemaVersion:'0sec.finder.output/v1', findings}));
`;
  writeFileSync(join(sourceRoot, "finder.mjs"), worker);
  const finding = { title: "Hardcoded credential", severity: "high", line: 1, analysis: "Literal credential assigned." };
  const makeCase = (id, lane, content, vulnerable) => ({
    id, lane,
    input: { schemaVersion: "0sec.finder.input/v1", file: { path: `${id}.js`, content }, lensId: "credentials", challengeHint: "Find literal credentials." },
    expected: { schemaVersion: "0sec.finder.output/v1", findings: vulnerable ? [finding] : [] },
  });
  const cases = [
    makeCase("dev-secret", "development", 'const secret = "dev-a";', true),
    makeCase("dev-passwd", "development", 'let passwd = "dev-b";', true),
    makeCase("dev-password", "development", 'var password = "dev-c";', true),
    makeCase("held-token", "held-out", 'const token = "hold-a";', true),
    makeCase("held-camel", "held-out", 'let apiKey = "hold-b";', true),
    makeCase("held-snake", "held-out", 'var api_key = "hold-c";', true),
    makeCase("clean-name", "negative-control", 'const name = "example";', false),
    makeCase("clean-env", "negative-control", 'const password = process.env.PASSWORD;', false),
    makeCase("clean-empty", "negative-control", 'const token = "";', false),
  ];
  const config = parseEvolutionConfig({
    schemaVersion: 1, kind: "source", sourceRoot, storePath, image,
    sourcePaths: ["finder.mjs"], editablePaths: ["finder.mjs"], command: ["node", "finder.mjs"], cases,
    model: process.env["0SEC_MODEL"] || "gpt-5.6-luna",
    objective: "Improve literal credential detection for password, passwd, secret, token, apiKey, and api_key assignments. Detect only nonempty quoted string assignments to credential keys, never ordinary names, environment reads, or empty strings. Preserve the existing output schema and finding title, severity, analysis, and line-number convention. Generalize the recognition logic rather than matching fixture identities.",
    allowModelSourceAccess: true, autoPromote: false, repeats: 2, canaryTrials: 2,
    maxIterations: 2, maxModelTurns: 6, maxModelCostUsd: 2, maxEvaluationCostUsd: 2,
    computeUsdPerSecond: 0.001, timeoutMs: 10000, maxChangedBytes: 8192,
    promotionPolicy: { minimumCases: 3 },
  });
  const result = await runEvolution(config, { signal: controller.signal, log: (message) => console.error(message) });
  console.log(JSON.stringify({ phase: "evaluation", ...result }));
  const accepted = result.iterations.find((iteration) => iteration.state === "awaiting_approval");
  assert(accepted, "real model did not produce a candidate passing every evaluation gate");
  const receipt = JSON.parse(readFileSync(accepted.receiptPath, "utf8"));
  assert(receipt.attempts.baseline.some((attempt) => !attempt.matched), "baseline must exhibit the genuine defect");
  assert(receipt.attempts.candidate.every((attempt) => attempt.matched && !attempt.inconclusive));
  const oldFinder = await createEvolvedFinder(config, "before-promotion");
  const approval = await approveEvolutionCandidate(storePath, accepted.candidateId, { signal: controller.signal });
  const newFinder = await createEvolvedFinder(config, "after-promotion");
  assert.notEqual(newFinder.versionId, oldFinder.versionId);
  assert.equal(newFinder.versionId, accepted.candidateId);
  const target = join(root, "target");
  mkdirSync(target);
  writeFileSync(join(target, "deployment.js"), 'const apiKey = "deployment-only-value";\n');
  const input = { candidate: { path: "deployment.js" }, lens: { id: "deployment", challengeHint: "Inspect literal credentials." }, challengeHint: "Inspect literal credentials.", attempt: 0, signal: controller.signal };
  const before = await oldFinder.find(target, input);
  const after = await newFinder.find(target, input);
  assert.deepEqual(before.findings, []);
  assert.equal(after.findings.length, 1);
  assert.equal(after.findings[0].status, "discovered");
  assert.equal(after.findings[0].reviewAnnotation.startLine, 1);
  await rollbackEvolutionVersion(storePath, newFinder.versionId, "E2E operator rollback");
  const restored = await createEvolvedFinder(config, "after-rollback");
  assert.equal(restored.versionId, oldFinder.versionId);
  assert.deepEqual((await restored.find(target, input)).findings, []);
  assert.equal((await newFinder.find(target, input)).findings.length, 1, "captured engagements retain their exact version after rollback");
  assert.equal(readFileSync(join(sourceRoot, "finder.mjs"), "utf8"), worker, "active source checkout must remain unchanged");
  assert.equal(loadEvolutionRegistry(storePath).activeId, oldFinder.versionId);
  console.log(JSON.stringify({ outcome: "passed", model: config.model, image, cases: cases.length, repeats: config.repeats, canaryTrials: config.canaryTrials, modelCostUsd: result.modelCostUsd, evaluationCostUsd: result.evaluationCostUsd + approval.evaluationCostUsd, baselineVersion: oldFinder.versionId, evolvedVersion: newFinder.versionId, deployedFindings: after.findings.length, engagementPinning: true, rollback: true }));
} catch (error) {
  console.error(JSON.stringify({ outcome: "failed", error: error instanceof Error ? error.message : String(error) }));
  process.exitCode = 1;
} finally {
  clearTimeout(deadline);
  cleanup();
}

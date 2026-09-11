#!/usr/bin/env node
/** Real guest lifecycle. Requires built packages and a provisioned toolbox.
 * 0SEC_PLUGIN_BACKEND=docker|smolvm; smolvm requires 0SEC_SMOLVM_IMAGE_ARCHIVE.
 * Set 0SEC_EVOLVE_REAL=1 for real-provider code evolution; missing credentials,
 * failed evaluation, failed activation, and failed rollback are test failures.
 */
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { SelfExtensionRegistry } from "../packages/core/dist/plugins/self-extension.js";
import { ExecutablePluginManager } from "../packages/core/dist/plugins/executable.js";
import { BUILTIN_GUARDS } from "../packages/core/dist/plugins/guards.js";
import { SELF_EXTENSION_RESERVED_TOOL_NAMES } from "../packages/core/dist/agent/tools.js";
import { parseEvolutionConfig } from "../packages/core/dist/improvement/config.js";

const backend = process.env["0SEC_PLUGIN_BACKEND"] ?? "docker";
assert(["docker", "smolvm"].includes(backend));
const imageArchive = process.env["0SEC_SMOLVM_IMAGE_ARCHIVE"];
if (backend === "smolvm") assert(imageArchive, "provide a local toolbox archive");
const image = process.env["0SEC_PLUGIN_IMAGE"] ?? "0sec-toolbox:qualification";
const root = mkdtempSync(join(tmpdir(), "0sec-executable-smoke-"));
const controller = new AbortController();
const abort = () => controller.abort(new Error("qualification cancelled"));
process.once("SIGINT", abort); process.once("SIGTERM", abort);
const timer = setTimeout(abort, 20 * 60 * 1000);
const context = { signal: controller.signal };
const managers = [];
const passed = [];
function newManager(overrides = {}) {
  const registry = new SelfExtensionRegistry({ enabled: true, baseGuards: BUILTIN_GUARDS, reservedToolNames: SELF_EXTENSION_RESERVED_TOOL_NAMES });
  const manager = new ExecutablePluginManager({ registry, root, backend, image,
    ...(backend === "smolvm" ? { imageArchive } : {}),
    timeoutMs: 90000, memoryMb: 2048, cpus: 2, maxBrokerCalls: 3, ...overrides });
  managers.push(manager);
  return manager;
}
function manifest(id, tools) { return { id, name: id, version: "1.0.0", tools }; }
function tool(name, capabilities = ["compute"]) { return { name, description: name, parameters: {}, capabilities }; }
function source(body) { return `export async function run(toolName: string, args: Record<string, any>, sdk: any) { ${body} }`; }
function output(result) { assert.equal(result.success, true, result.error); return result.output; }
async function step(name, work) { await work(); passed.push(name); console.log(JSON.stringify({ check: name, outcome: "passed" })); }
let manager = newManager();
try {
  await manager.ready;
  let original;
  await step("TypeScript arguments reach the correct executable owner", async () => {
    original = output(await manager.submit({ manifest: manifest("smoke.echo", [tool("smoke_echo")]),
      entry: "main.ts", files: { "main.ts": source("return { tool: toolName, args }; ") } }, context)).versionId;
    const args = { value: "Hello", count: 7, nested: { ok: true } };
    assert.deepEqual(output(await manager.execute("smoke_echo", args, context)), { tool: "smoke_echo", args });
    output(await manager.submit({ manifest: manifest("smoke.math", [tool("smoke_add"), tool("smoke_multiply")]),
      entry: "src/main.ts", kind: "skill", files: {
        "src/main.ts": "import { calculate } from './math.ts'; export async function run(name: string, args: any) { return calculate(name, args); }",
        "src/math.ts": "export function calculate(name: string, args: any) { return name === 'smoke_add' ? args.a + args.b : args.a * args.b; }",
      } }, context));
    assert.equal(output(await manager.execute("smoke_add", { a: 3, b: 7 }, context)), 10);
    assert.equal(output(await manager.execute("smoke_multiply", { a: 3, b: 7 }, context)), 21);
  });
  await step("Concurrent SDK tool and skill composition returns correlated results", async () => {
    output(await manager.submit({ manifest: manifest("smoke.compose", [tool("smoke_compose")]), entry: "main.ts", kind: "skill",
      files: { "main.ts": source("const [sum, product] = await Promise.all([sdk.callSkill('smoke_add', args), sdk.callTool('smoke_multiply', args)]); return { sum, product };") } }, context));
    assert.deepEqual(output(await manager.execute("smoke_compose", { a: 3, b: 7 }, context)), { sum: 10, product: 21 });
  });
  let replacement;
  await step("Replacement activates new source while retaining the previous version", async () => {
    replacement = output(await manager.submit({ manifest: manifest("smoke.echo", [tool("smoke_echo")]), entry: "main.ts",
      files: { "main.ts": source("return { value: String(args.value).toUpperCase() };") } }, context)).versionId;
    assert.equal(output(await manager.execute("smoke_echo", { value: "next" }, context)).value, "NEXT");
    const versions = manager.list().filter(item => item.id === "smoke.echo");
    assert(versions.some(item => item.versionId === original && !item.active));
    assert(versions.some(item => item.versionId === replacement && item.active && item.evidenceStatus === "structural"));
  });
  await step("Runtime failures survive a cold manager restart", async () => {
    output(await manager.submit({ manifest: manifest("smoke.failure", [tool("smoke_failure")]), entry: "main.ts",
      files: { "main.ts": source("throw new Error('intentional execution failure');") } }, context));
    assert.equal((await manager.execute("smoke_failure", {}, context)).success, false);
    await manager.close();
    manager = newManager(); await manager.ready;
    const failure = manager.list().find(item => item.id === "smoke.failure");
    assert.equal(failure.failureCount, 1);
    assert.match(failure.lastError, /intentional execution failure/);
    assert.equal(output(await manager.execute("smoke_echo", { value: "restored" }, context)).value, "RESTORED");
  });
  await step("Rollback restores executable behavior and discovery", async () => {
    output(await manager.rollback("smoke.echo", original, context));
    assert.deepEqual(output(await manager.execute("smoke_echo", { value: "original" }, context)), { tool: "smoke_echo", args: { value: "original" } });
    assert.equal(manager.list().find(item => item.id === "smoke.echo" && item.active).versionId, original);
  });
  await step("Invalid source admission leaves the working version intact", async () => {
    const rejected = await manager.submit({ manifest: manifest("smoke.echo", [tool("smoke_echo")]), entry: "main.ts",
      files: { "main.ts": "export async function run( {" } }, context);
    assert.equal(rejected.success, false);
    assert.equal(manager.list().find(item => item.id === "smoke.echo" && item.active).versionId, original);
    assert.deepEqual(output(await manager.execute("smoke_echo", { value: "preserved" }, context)).args, { value: "preserved" });
  });
  await step("Recursion, shared broker budgets, and capability escalation terminate", async () => {
    output(await manager.submit({ manifest: manifest("smoke.limits", [tool("smoke_recursive"), tool("smoke_burst"), tool("smoke_denied"), tool("smoke_escalate"), tool("smoke_privileged", ["model-call"])]), entry: "main.ts", files: {
      "main.ts": source(`
        if (toolName === 'smoke_recursive') return sdk.callSkill('smoke_recursive', {});
        if (toolName === 'smoke_burst') return Promise.all(Array.from({length:4}, () => sdk.callSkill('smoke_add', {a:1,b:2})));
        if (toolName === 'smoke_denied') return sdk.callTool('bash', {command:'exit 0'});
        if (toolName === 'smoke_escalate') return sdk.callSkill('smoke_privileged', {});
        return 42;
      `),
    } }, context));
    for (const name of ["smoke_recursive", "smoke_burst", "smoke_escalate"]) {
      const result = await manager.execute(name, {}, context);
      assert.equal(result.success, false, `${name} unexpectedly succeeded`);
      assert.match(result.error, /recursion|depth|budget|capabilit/i);
    }
    let called = false;
    const denied = await manager.execute("smoke_denied", {}, { ...context, invokeTool: async () => { called = true; return { success: true, output: "escaped" }; } });
    assert.equal(denied.success, false); assert.equal(called, false);
  });
  await step("Tampered source is rejected before execution", async () => {
    const registry = JSON.parse(readFileSync(join(root, "registry.json"), "utf8"));
    const version = registry.plugins["smoke.echo"].versions.find(item => item.versionId === original);
    const path = join(version.snapshot.root, "main.ts");
    const prior = readFileSync(path, "utf8");
    try {
      chmodSync(path, 0o600); writeFileSync(path, source("return 'tampered';")); chmodSync(path, 0o444);
      const rejected = await manager.execute("smoke_echo", {}, context);
      assert.equal(rejected.success, false); assert.match(rejected.error, /digest|size|integrity/i);
    } finally { chmodSync(path, 0o600); writeFileSync(path, prior); chmodSync(path, 0o444); }
    assert.deepEqual(output(await manager.execute("smoke_echo", {}, context)), { tool: "smoke_echo", args: {} });
  });
  await step("A corrupt active pointer fails closed on restart", async () => {
    const path = join(root, "registry.json"), prior = readFileSync(path, "utf8");
    const corrupt = JSON.parse(prior); corrupt.plugins["smoke.echo"].activeVersionId = randomUUID();
    try {
      writeFileSync(path, JSON.stringify(corrupt));
      const invalid = newManager();
      await assert.rejects(invalid.ready);
      await invalid.close();
    } finally { writeFileSync(path, prior); }
    assert.equal(manager.list().find(item => item.id === "smoke.echo" && item.active).versionId, original);
  });
  if (process.env["0SEC_EVOLVE_REAL"] === "1") {
    const { maybeLoadCodexAuth } = await import("../packages/cli/dist/codex-auth.js");
    maybeLoadCodexAuth();
    process.env["0SEC_DISABLE_HUNT_MEMORY"] = "1";
    process.env["0SEC_CLOUD_SINK"] = "";
    await step("Real provider repairs source and activates a measured version", async () => {
      const buggy = output(await manager.submit({ manifest: manifest("smoke.evolve", [tool("smoke_evolve")]), entry: "main.ts", kind: "agent", files: {
        "main.ts": source("if (typeof args.value !== 'number' || !Number.isFinite(args.value)) return {error:'invalid'}; return {result:args.value - 42};"),
        "evaluate.mjs": "import { readFileSync } from 'node:fs'; import { run } from './main.ts'; console.log(JSON.stringify(await run('smoke_evolve', JSON.parse(readFileSync(0, 'utf8')), {})));",
      } }, context)).versionId;
      assert.deepEqual(output(await manager.execute("smoke_evolve", { value: 10 }, context)), { result: -32 });
      const cases = [
        ...[10, 0, -5].map((value, i) => ({ id: `development-${i}`, lane: "development", input: { value }, expected: { result: value + 42 } })),
        ...[100, -100, 0.5].map((value, i) => ({ id: `held-${i}`, lane: "held-out", input: { value }, expected: { result: value + 42 } })),
        ...[{ value: "bad" }, {}, { value: null }].map((input, i) => ({ id: `negative-${i}`, lane: "negative-control", input, expected: { error: "invalid" } })),
      ];
      const profile = parseEvolutionConfig({ schemaVersion: 1, kind: "source", backend, image,
        ...(backend === "smolvm" ? { imageArchive } : {}),
        sourceRoot: join(root, "profile-source"), storePath: join(root, "profile-store"),
        sourcePaths: ["main.ts", "evaluate.mjs"], editablePaths: ["main.ts"],
        command: ["node", "--experimental-strip-types", "evaluate.mjs"], cases,
        model: process.env["0SEC_MODEL"] ?? "gpt-5.6-luna",
        objective: "Fix run() to return {result: value + 42} for finite numeric args.value. Preserve {error:'invalid'} for absent, nonnumeric, or nonfinite values. Preserve the run export and all existing argument handling; fix the general arithmetic rather than matching fixture inputs.",
        allowModelSourceAccess: true, autoPromote: true, repeats: 2, canaryTrials: 1,
        maxIterations: 2, maxModelTurns: 6, maxModelCostUsd: 1, maxEvaluationCostUsd: 1,
        computeUsdPerSecond: 0.00001, timeoutMs: 90000, memoryMb: 2048, cpus: 2,
        maxChangedBytes: 8192, maxSourceBytes: 1024 * 1024, promotionPolicy: { minimumCases: 3 },
      });
      const evolved = output(await manager.evolve("smoke.evolve", profile, { signal: controller.signal }, context));
      if (!evolved.versionId) console.error(JSON.stringify({
        phase: "evolution-not-promoted",
        iterations: evolved.evaluation?.iterations?.map(iteration => ({
          candidateId: iteration.candidateId, error: iteration.error,
          status: iteration.decision?.status,
          failedChecks: iteration.decision?.checks?.filter(check => !check.passed),
        })),
      }));
      assert(evolved.versionId && evolved.versionId !== buggy, `real provider must produce an activated executable version: ${JSON.stringify(evolved)}`);
      assert.equal(evolved.evidenceStatus, "measured");
      assert.deepEqual(output(await manager.execute("smoke_evolve", { value: 73 }, context)), { result: 115 });
      await manager.close(); manager = newManager(); await manager.ready;
      assert.deepEqual(output(await manager.execute("smoke_evolve", { value: 9 }, context)), { result: 51 });
      output(await manager.rollback("smoke.evolve", buggy, context));
      assert.deepEqual(output(await manager.execute("smoke_evolve", { value: 10 }, context)), { result: -32 });
      console.log(JSON.stringify({ phase: "real-evolution", model: profile.model, baselineVersion: buggy, evolvedVersion: evolved.versionId, coldRestore: true, rollback: true }));
    });
  }
  console.log(JSON.stringify({ outcome: "passed", backend, checks: passed, realProviderEvolution: process.env["0SEC_EVOLVE_REAL"] === "1" }));
} finally {
  controller.abort();
  await Promise.allSettled(managers.map(instance => instance.close()));
  clearTimeout(timer); process.removeListener("SIGINT", abort); process.removeListener("SIGTERM", abort);
  function unlock(directory) { chmodSync(directory, 0o700); for (const entry of readdirSync(directory, { withFileTypes: true })) if (entry.isDirectory()) unlock(join(directory, entry.name)); }
  unlock(root); rmSync(root, { recursive: true, force: true });
}

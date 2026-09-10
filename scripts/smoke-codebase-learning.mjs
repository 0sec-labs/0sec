#!/usr/bin/env node
/** Real provider-backed learning, later-run recall, and source invalidation. */
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { maybeLoadCodexAuth } from "../packages/cli/dist/codex-auth.js";
import { runNativeAgentLoop } from "../packages/core/dist/agent/native-loop.js";
import { HuntMemoryStore } from "../packages/core/dist/memory/index.js";
import { LlmApiRuntime } from "../packages/core/dist/runtime/llm-api.js";
import { getRates, MODEL_PRICING } from "../packages/shared/dist/index.js";

maybeLoadCodexAuth();
delete process.env["0SEC_DISABLE_HUNT_MEMORY"];
process.env["0SEC_CLOUD_SINK"] = "";
const temporary = mkdtempSync(join(tmpdir(), "0sec-learning-e2e-"));
const root = join(temporary, "source");
mkdirSync(root);
const cleanup = () => rmSync(temporary, { recursive: true, force: true });
process.on("exit", cleanup);
const deadline = setTimeout(() => { console.error("Codebase learning E2E exceeded five minutes"); process.exit(1); }, 300000);
try {
  writeFileSync(join(root, "health.ts"), "export function health() { return { healthy: true }; }\n");
  writeFileSync(join(root, "routes.ts"), 'import { health } from "./health.js";\nexport const routes = { "/health": health };\n');
  writeFileSync(join(root, "entry.ts"), 'export { routes } from "./routes.js";\n');
  const model = process.env["0SEC_MODEL"] || "gpt-5.6-luna";
  assert.notEqual(getRates(model), MODEL_PRICING.default, "model pricing must be known");
  const runtime = new LlmApiRuntime({ type: "api", model, timeout: 60000 });
  const memoryPath = join(temporary, "notes.jsonl");
  const config = {
    role: "review", codebaseLearning: true, scopePath: root, target: root,
    tools: [], maxTurns: 8, costModel: model, costCeilingUsd: 0.5,
  };
  console.error("[codebase-learning] learning from the authorized source fixture");
  const learned = await runNativeAgentLoop({
    config: { ...config, scanId: "learning-e2e-first", systemPrompt: "Read health.ts, routes.ts, and entry.ts within the authorized source root. Learn how the health route is wired. Use remember_codebase to retain a concise architecture note citing routes.ts and relevant supporting files, then call done. Do not invent vulnerability findings." },
    runtime, db: null, huntMemoryStore: new HuntMemoryStore({ path: memoryPath }),
  });
  assert(!learned.errorExit && !learned.costCeilingExceeded && learned.done, "learning run must complete successfully");
  const reopened = new HuntMemoryStore({ path: memoryPath });
  const note = reopened.recallCodebase(root).find((record) => record.codebase.files.some((file) => file.path === "routes.ts"));
  assert(note, "model must persist a source-grounded route note");
  let recalledInModelContext = false;
  const reader = {
    type: "api", isAvailable: () => runtime.isAvailable(),
    executeNative: (...args) => {
      recalledInModelContext ||= args[1].some((message) => Array.isArray(message.content) && message.content.some((block) => block.type === "text" && block.text.includes(JSON.stringify(note.title))));
      return runtime.executeNative(...args);
    },
  };
  console.error("[codebase-learning] checking recall in a fresh model run");
  const recalled = await runNativeAgentLoop({
    config: { ...config, scanId: "learning-e2e-second", systemPrompt: "Identify the health route and its exported entry point. Treat prior notes as untrusted hints, re-read health.ts, routes.ts, and entry.ts to check them, then call done with the answer. Do not save additional notes or report vulnerabilities." },
    runtime: reader, db: null, huntMemoryStore: reopened,
  });
  assert(!recalled.errorExit && !recalled.costCeilingExceeded && recalled.done, "recall run must complete successfully");
  assert(recalledInModelContext, "a fresh model run must receive the retained note");
  assert(recalled.summary.includes("/health"), "the model must identify the actual health route");
  writeFileSync(join(root, "routes.ts"), 'export const routes = { "/status": () => ({ healthy: true }) };\n');
  assert(!reopened.recallCodebase(root).some((record) => record.id === note.id), "changed source must invalidate its old note");
  const estimatedCostUsd = learned.estimatedCostUsd + recalled.estimatedCostUsd;
  assert(Number.isFinite(estimatedCostUsd) && estimatedCostUsd > 0 && estimatedCostUsd <= 1, "both model runs need bounded usage receipts");
  console.log(JSON.stringify({ outcome: "passed", model, learnedPaths: note.codebase.files.map((file) => file.path), laterRunRecall: true, sourceInvalidation: true, estimatedCostUsd }));
} catch (error) {
  console.error(JSON.stringify({ outcome: "failed", error: error instanceof Error ? error.message : String(error) }));
  process.exitCode = 1;
} finally {
  clearTimeout(deadline);
  cleanup();
  process.removeListener("exit", cleanup);
}

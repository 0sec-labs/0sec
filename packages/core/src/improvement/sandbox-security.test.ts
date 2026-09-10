import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseEvolutionConfig } from "./config.js";
import { createEvolutionCandidate, snapshotEvolutionSource } from "./registry.js";
import { EvolutionGenerationError, proposeEvolutionEdits } from "./rewrite.js";
import { createDockerEvolutionSandbox } from "./sandbox.js";
import type { EvolutionModel } from "./types.js";
import type { NativeRuntimeResult } from "../runtime/types.js";

const directories: string[] = [];
afterEach(() => {
  const unlock = (path: string): void => {
    chmodSync(path, 0o700);
    for (const entry of readdirSync(path, { withFileTypes: true })) if (entry.isDirectory()) unlock(join(path, entry.name));
  };
  for (const path of directories.splice(0)) { unlock(path); rmSync(path, { recursive: true, force: true }); }
});

async function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "0sec-source-generation-"));
  directories.push(directory);
  const sourceRoot = join(directory, "source");
  mkdirSync(join(sourceRoot, "src"), { recursive: true });
  writeFileSync(join(sourceRoot, "src/a.cjs"), "// context filler\n".repeat(70000));
  writeFileSync(join(sourceRoot, "src/z.cjs"), "module.exports = 'selected-source-marker';\n");
  const config = parseEvolutionConfig({
    schemaVersion: 1, sourceRoot, storePath: join(directory, "store"), image: "node:22-alpine",
    sourcePaths: ["src"], editablePaths: ["src"], command: ["node", "src/z.cjs"],
    objective: "Correct the worker", computeUsdPerSecond: 0.001, model: "gpt-4o-mini",
    allowModelSourceAccess: true, repeats: 2, maxOutputBytes: 1024, maxModelTurns: 2,
    promotionPolicy: { minimumCases: 3 },
    cases: ["development", "held-out", "negative-control"].flatMap((lane, group) => [0, 1, 2].map((index) => ({
      id: `${lane}-${index}`, lane,
      input: { index: group * 3 + index, ...(group === 1 ? { privateInput: "hidden-oracle-input-891" } : {}) },
      expected: { result: group !== 2 },
    }))),
  });
  return { config, snapshot: await snapshotEvolutionSource(config) };
}
function response(name: string, input: Record<string, unknown>, id = "call"): NativeRuntimeResult {
  return { content: [{ type: "tool_use", id, name, input }], stopReason: "tool_use", durationMs: 1, usage: { inputTokens: 100, outputTokens: 100 } };
}

describe("source generation trust boundary", () => {
  it("does not disclose source when consent is absent", async () => {
    const { config, snapshot } = await fixture();
    let disclosures = 0;
    const model: EvolutionModel = async () => { disclosures++; return response("propose_edits", { rationale: "done", edits: [] }); };
    await expect(proposeEvolutionEdits(snapshot, { ...config, allowModelSourceAccess: false }, "", { model })).rejects.toThrow(/consent/);
    expect(disclosures).toBe(0);
  });

  it("lazily reads later files without disclosing held-out inputs and produces usable source edits", async () => {
    const { config, snapshot } = await fixture();
    let turn = 0;
    const original = snapshot.files.find((file) => file.path === "src/z.cjs")!;
    const model: EvolutionModel = async (system, messages) => {
      expect(JSON.stringify([system, messages])).not.toContain("hidden-oracle-input-891");
      if (turn++ === 0) {
        expect(system).not.toContain("selected-source-marker");
        return response("read_source", { path: "src/z.cjs" }, "read");
      }
      const reply = messages.at(-1)!.content.find((block) => block.type === "tool_result");
      expect(reply?.type === "tool_result" && JSON.parse(reply.content).content).toContain("selected-source-marker");
      return response("propose_edits", { rationale: "Replace the old behavior", edits: [{ path: original.path, beforeDigest: original.digest, content: "module.exports = 2;\n" }] });
    };
    const proposal = await proposeEvolutionEdits(snapshot, config, "", { model });
    const candidate = await createEvolutionCandidate(snapshot, proposal, config);
    expect(readFileSync(join(candidate.root, "src/z.cjs"), "utf8")).toBe("module.exports = 2;\n");
    expect(readFileSync(join(snapshot.root, "src/z.cjs"), "utf8")).toContain("selected-source-marker");
    expect(proposal.modelCostUsd).toBeGreaterThan(0);
  });

  it("retains known charges and marks incomplete metering when a later response omits usage", async () => {
    const { config, snapshot } = await fixture();
    let turn = 0;
    const model: EvolutionModel = async () => {
      if (turn++ === 0) return response("read_source", { path: "src/z.cjs" });
      const result = response("propose_edits", { rationale: "done", edits: [] });
      delete result.usage;
      return result;
    };
    const failure = await proposeEvolutionEdits(snapshot, config, "", { model }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(EvolutionGenerationError);
    if (!(failure instanceof EvolutionGenerationError)) throw new Error("expected metering failure");
    expect(failure.modelCostUsd).toBeGreaterThan(0);
    expect(failure.meteringIncomplete).toBe(true);
  });

  it("does not treat similarly prefixed directories as editable source", async () => {
    const { config, snapshot } = await fixture();
    const model: EvolutionModel = async () => response("propose_edits", {
      rationale: "Attempt an out-of-bound edit", edits: [{ path: "src-evil/z.cjs", beforeDigest: null, content: "module.exports = 2;" }],
    });
    await expect(proposeEvolutionEdits(snapshot, config, "", { model })).rejects.toBeInstanceOf(EvolutionGenerationError);
  });

  it("refuses an unknown price before making a billable model call", async () => {
    const { config, snapshot } = await fixture();
    let calls = 0;
    const model: EvolutionModel = async () => { calls++; return response("propose_edits", { rationale: "done", edits: [] }); };
    await expect(proposeEvolutionEdits(snapshot, { ...config, model: "unknown-billing-model-891" }, "", { model })).rejects.toThrow(/pricing/);
    expect(calls).toBe(0);
  });

  it("never falls back to running worker code on the host when isolation is unavailable", async () => {
    const { config, snapshot } = await fixture();
    const marker = join(config.sourceRoot, "host-execution-marker");
    const sandbox = createDockerEvolutionSandbox(join(config.sourceRoot, "missing-docker"));
    const outcome = await sandbox({
      snapshot, input: {},
      config: { ...config, image: `sha256:${"a".repeat(64)}`, command: ["node", "-e", `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'executed')`] },
    }).catch((error: unknown) => error);
    expect(existsSync(marker)).toBe(false);
    if (!(outcome instanceof Error)) {
      if (typeof outcome !== "object" || outcome === null || !("exitCode" in outcome)) throw new Error("expected an execution result");
      expect(outcome.exitCode).not.toBe(0);
    }
  });
});

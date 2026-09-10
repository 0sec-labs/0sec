import { chmodSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parseEvolutionConfig } from "../improvement/config.js";
import { evolutionDigest, recordEvolutionVersion, snapshotEvolutionSource } from "../improvement/registry.js";
import type { EvolutionConfig } from "../improvement/types.js";

const worker = vi.hoisted(() => ({ output: {} as unknown }));
vi.mock("../improvement/sandbox.js", () => ({
  resolveEvolutionImage: async (image: string) => image,
  createDockerEvolutionSandbox: () => async () => ({
    exitCode: 0, stdout: JSON.stringify(worker.output), stderr: "", durationMs: 1, timedOut: false,
  }),
}));
import { createEvolvedFinder } from "./evolved-finder.js";

let root: string;
let config: EvolutionConfig;
const inputSchema = "0sec.finder.input/v1";
const outputSchema = "0sec.finder.output/v1";

beforeEach(async () => {
  root = mkdtempSync(join(tmpdir(), "0sec-evolved-finder-"));
  const sourceRoot = join(root, "engine");
  mkdirSync(join(sourceRoot, "src"), { recursive: true });
  mkdirSync(join(root, "target"));
  writeFileSync(join(sourceRoot, "src/worker.cjs"), 'console.log("operator-owned worker");\n');
  writeFileSync(join(root, "target/app.js"), "serve(request);");
  config = parseEvolutionConfig({
    schemaVersion: 1, sourceRoot, storePath: join(root, "store"),
    image: `sha256:${"a".repeat(64)}`, sourcePaths: ["src"], editablePaths: ["src"],
    command: ["node", "src/worker.cjs"], objective: "Detect independently reproducible unsafe source flows",
    computeUsdPerSecond: 0.001, promotionPolicy: { minimumCases: 3 },
    cases: ["development", "held-out", "negative-control"].flatMap((lane) => [0, 1, 2].map((index) => ({
      id: `${lane}-${index}`, lane,
      input: { schemaVersion: inputSchema, file: { path: `${lane}-${index}.js`, content: "safe();" }, lensId: "auth", challengeHint: "Inspect authorization" },
      expected: { schemaVersion: outputSchema, findings: [] },
    }))),
  });
  const snapshot = await snapshotEvolutionSource(config);
  await recordEvolutionVersion(config.storePath, {
    schemaVersion: 1, id: snapshot.id, kind: "source", snapshot, parentId: null,
    configDigest: evolutionDigest(config), receiptDigest: null, status: "baseline", createdAt: new Date().toISOString(),
  }, config);
  worker.output = { schemaVersion: outputSchema, findings: [{ title: "Untrusted request reaches sink", severity: "high", line: 1, analysis: "Trace the caller authorization before treating this as a bug." }] };
});

afterEach(() => {
  const unlock = (path: string): void => {
    chmodSync(path, 0o700);
    for (const entry of readdirSync(path, { withFileTypes: true })) if (entry.isDirectory()) unlock(join(path, entry.name));
  };
  unlock(root);
  rmSync(root, { recursive: true, force: true });
});

function request(path = join(root, "target/app.js")) {
  return { candidate: { path }, lens: { id: "auth", challengeHint: "Inspect authorization" }, attempt: 0, challengeHint: "Inspect authorization" };
}

describe("evolved source finder deployment boundaries", () => {
  it("returns unconfirmed leads tied to a controller-selected source location", async () => {
    writeFileSync(join(root, "target/app.js"), "serve(request); // TODO enforce the tenant boundary");
    const finder = await createEvolvedFinder(config, "engagement");
    const result = await finder.find(join(root, "target"), request());
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.status).toBe("discovered");
    expect(result.findings[0]?.reviewAnnotation).toEqual({ path: "app.js", startLine: 1, knownMarker: true });
    expect(result.findings[0]?.verification_result).toBeUndefined();
  });

  it("rejects worker-supplied confirmation rather than accepting a self-graded finding", async () => {
    worker.output = { schemaVersion: outputSchema, findings: [{ title: "Self-graded lead", severity: "high", line: 1, analysis: "Claimed proof", status: "confirmed" }] };
    const finder = await createEvolvedFinder(config, "engagement");
    await expect(finder.find(join(root, "target"), request())).rejects.toThrow(/execution failed/);
  });

  it("refuses to send an out-of-scope source file to the worker", async () => {
    const outside = join(root, "outside.js");
    writeFileSync(outside, "private();");
    const finder = await createEvolvedFinder(config, "engagement");
    await expect(finder.find(join(root, "target"), request(outside))).rejects.toThrow(/escapes the source scope/);
  });
});

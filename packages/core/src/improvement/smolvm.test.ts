import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseEvolutionConfig } from "./config.js";
import { runEvolution } from "./loop.js";
import { resolveEvolutionConfigImage } from "./sandbox.js";
import { resolveSmolvmImage } from "../runtime/smolvm.js";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture() {
  const root = mkdtempSync(join(tmpdir(), "0sec-smol-config-"));
  roots.push(root);
  const archive = join(root, "image.tar");
  writeFileSync(archive, "operator-owned image bytes");
  const config = parseEvolutionConfig({
    schemaVersion: 1, sourceRoot: join(root, "source"), storePath: join(root, "store"),
    backend: "smolvm", imageArchive: "image.tar", image: "node:22-alpine",
    sourcePaths: ["src"], editablePaths: ["src"], command: ["node", "src/worker.cjs"],
    objective: "Correct unsafe-input classification", computeUsdPerSecond: 0.001,
    allowModelSourceAccess: true, repeats: 2, promotionPolicy: { minimumCases: 3 },
    cases: ["development", "held-out", "negative-control"].flatMap((lane, group) => [0, 1, 2].map((index) => ({
      id: `${lane}-${index}`, lane, input: { n: group * 3 + index }, expected: { unsafe: group !== 2 },
    }))),
  }, root);
  return { root, archive, config };
}

describe("smolvm evolution artifact boundaries", () => {
  it("resolves a config-relative archive without consulting a Docker daemon", async () => {
    const { archive, config } = fixture();
    expect(await resolveEvolutionConfigImage(config)).toBe(await resolveSmolvmImage(archive));
  });

  it("rejects replaced image bytes before disclosure or model spending", async () => {
    const { archive, config } = fixture();
    config.image = await resolveEvolutionConfigImage(config);
    writeFileSync(archive, "replacement image bytes");
    let disclosed = false;
    await expect(runEvolution(config, { model: async () => { disclosed = true; throw new Error("unexpected disclosure"); } }))
      .rejects.toThrow(/archive identity mismatch/);
    expect(disclosed).toBe(false);
  });

  it("refuses a dangling backend selection instead of choosing another engine", () => {
    const { config } = fixture();
    expect(() => parseEvolutionConfig({ ...config, imageArchive: undefined })).toThrow(/imageArchive/);
    expect(() => parseEvolutionConfig({ ...config, backend: "docker" })).toThrow(/only valid/);
    expect(() => parseEvolutionConfig({ ...config, backend: "unknown" })).toThrow();
    expect(() => parseEvolutionConfig({ ...config, cpus: 0.5 })).toThrow(/integer/);
  });

  it("rejects non-regular and symlinked archives rather than following them", async () => {
    const { root, archive } = fixture();
    const alias = join(root, "alias.tar");
    symlinkSync(archive, alias);
    await expect(resolveSmolvmImage(alias)).rejects.toThrow();
    await expect(resolveSmolvmImage(root)).rejects.toThrow(/regular archive/);
  });
});

/**
 * End-to-end Tier-2 builder test against the synthetic
 * `test-targets/c-cpp-tier2/` library. Verifies the artifacts 0sec
 * promises in its README — harness, linker script, Makefile fragment —
 * are all produced and contain the expected hooks.
 */

import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildTier2Harness } from "./c-cpp-tier2.js";
import { extractCorpus } from "./corpus.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
// __dirname = packages/core/src/review → walk up to repo root.
const REPO_ROOT = join(__dirname, "..", "..", "..", "..");
const TARGET = join(REPO_ROOT, "test-targets", "c-cpp-tier2");

describe("Tier-2 E2E against test-targets/c-cpp-tier2", () => {
  it("emits a complete artifact bundle for the synthetic library", async () => {
    expect(existsSync(TARGET)).toBe(true);
    const outDir = await mkdtemp(join(tmpdir(), "0sec-tier2-e2e-"));
    const corpusOut = join(outDir, "corpus-staged");
    try {
      const seeds = await extractCorpus(TARGET, { outputDir: corpusOut });
      expect(seeds.length).toBeGreaterThan(0);

      const artifact = await buildTier2Harness({
        suspectFunction: {
          header: "osec_tier2.h",
          functionName: "osec_tier2_decode",
          declaration:
            "int osec_tier2_decode(const uint8_t *data, size_t size, uint8_t **out, size_t *out_size);",
          inputShape: "bytesAndLenOut",
        },
        sourceRoot: TARGET,
        buildSystem: "auto",
        sanitizers: ["asan", "ubsan"],
        corpusSeeds: seeds,
        outputDir: join(outDir, "tier2"),
      });

      // Harness file exists and references the suspect function.
      expect(existsSync(artifact.harness_path)).toBe(true);
      const harnessSrc = await readFile(artifact.harness_path, "utf8");
      expect(harnessSrc).toMatch(
        /osec_tier2_decode\(data, size, &out, &out_size\)/,
      );

      // Linker fragment present, non-empty, contains sanitizer flags.
      expect(existsSync(artifact.linker_script_path)).toBe(true);
      const scriptSrc = await readFile(artifact.linker_script_path, "utf8");
      expect(scriptSrc.length).toBeGreaterThan(0);
      expect(scriptSrc).toMatch(/-fsanitize=address,undefined,fuzzer/);

      // Makefile fragment present and contains the harness target.
      expect(existsSync(artifact.makefile_fragment_path)).toBe(true);
      const mkSrc = await readFile(artifact.makefile_fragment_path, "utf8");
      expect(mkSrc.length).toBeGreaterThan(0);
      expect(mkSrc).toMatch(/OSEC_TIER2_HARNESS/);

      // Discovered objects: api.c (entry point), frame.c, decoder.c.
      const linked = artifact.linked_objects.map((p) => p.replace(TARGET, ""));
      expect(linked.some((p) => p.endsWith("api.c"))).toBe(true);
      expect(linked.some((p) => p.endsWith("frame.c"))).toBe(true);
      expect(linked.some((p) => p.endsWith("decoder.c"))).toBe(true);

      // Detection succeeded.
      expect(artifact.detected_build_system).toBe("autotools");

      // Linker script must be executable.
      const mode = statSync(artifact.linker_script_path).mode & 0o777;
      expect(mode & 0o100).toBe(0o100);
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  });
});

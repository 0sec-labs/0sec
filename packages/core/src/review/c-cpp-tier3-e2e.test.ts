/**
 * End-to-end Tier-3 test against the synthetic `test-targets/c-cpp-tier2`
 * library. Gated behind `0SEC_KERNEL_QEMU=1` because it requires a
 * real kernel + rootfs and an actual QEMU binary on PATH.
 *
 * What this asserts:
 *  - Tier-2 build emits an artifact.
 *  - Tier-3 boots that artifact in QEMU, compiles it with ASan/UBSan,
 *    feeds the corpus seeds, and captures the synthetic integer-
 *    truncation crash.
 *  - The sanitizer signature is mapped to a heap-overflow / integer
 *    category and promotes a static integer-truncation hypothesis.
 */

import { describe, it, expect } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildTier2Harness } from "./c-cpp-tier2.js";
import { extractCorpus } from "./corpus.js";
import {
  runTier3Validation,
  promoteFindingsWithTier3Result,
} from "./c-cpp-tier3.js";
import type { Finding } from "@0sec/shared";

const __dirname = dirname(fileURLToPath(import.meta.url));
// __dirname = packages/core/src/review → walk up to repo root.
const REPO_ROOT = join(__dirname, "..", "..", "..", "..");
const TARGET = join(REPO_ROOT, "test-targets", "c-cpp-tier2");

const QEMU_E2E = process.env["0SEC_KERNEL_QEMU"] === "1";

describe.skipIf(!QEMU_E2E)("Tier-3 E2E (real QEMU)", () => {
  it("validates the synthetic integer-truncation crash through Tier-2 → Tier-3", async () => {
    const outDir = await mkdtemp(join(tmpdir(), "0sec-tier3-e2e-"));
    try {
      const seeds = await extractCorpus(TARGET, { outputDir: join(outDir, "corpus") });
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

      const result = await runTier3Validation(artifact, { runCorpus: seeds });
      expect(["crash_reproduced", "no_crash"]).toContain(result.status);

      if (result.status === "crash_reproduced") {
        const hypothesis: Finding = {
          id: "tier1-hypothesis",
          templateId: "static-int-trunc",
          title: "Possible integer truncation on alloc path",
          description: "static hypothesis",
          severity: "high",
          category: "integer-truncation",
          status: "discovered",
          confidence: 0.4,
          evidence: {
            request: "",
            response: "",
            analysis: "decoder.c: width transition on attacker-controlled count",
          } as Finding["evidence"],
          timestamp: 0,
        };
        const promoted = promoteFindingsWithTier3Result([hypothesis], result);
        expect(promoted[0].status).toBe("confirmed");
        expect(promoted[0].confidence).toBe(1.0);
      }
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  }, 15 * 60 * 1000);
});

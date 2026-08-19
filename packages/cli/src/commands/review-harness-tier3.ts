/**
 * `pwnkit review --harness-tier 3` glue.
 *
 * Chains Tier-2 (multi-component harness build) → Tier-3 (QEMU
 * validation). Prints the Tier-3 result JSON so downstream tooling
 * (CI, agents driving the CLI) can parse a stable shape regardless of
 * the verdict.
 *
 * The Tier-3 module short-circuits to `qemu_failed` when
 * `PWNKIT_KERNEL_QEMU_KERNEL` / `PWNKIT_KERNEL_QEMU_DISK` are unset,
 * so this command is safe to exercise in CI — it just won't actually
 * boot a VM there.
 */

import chalk from "chalk";
import { resolve, join, basename } from "node:path";
import { existsSync } from "node:fs";

interface RunHarnessTier3Args {
  repo: string;
  functionName?: string;
  header?: string;
  buildSystem: string;
  sanitizers?: string;
  outputDir?: string;
  verbose: boolean;
  /** Override the kernel image path. Falls back to PWNKIT_KERNEL_QEMU_KERNEL. */
  qemuKernel?: string;
  /** Override the disk image path. Falls back to PWNKIT_KERNEL_QEMU_DISK. */
  qemuDisk?: string;
  /** Override the wall-clock budget, milliseconds. */
  wallClockMs?: number;
}

const VALID_BUILD_SYSTEMS = new Set(["autotools", "cmake", "meson", "auto"]);
const VALID_SANITIZERS = new Set(["asan", "ubsan", "msan"]);

export async function runHarnessTier3(args: RunHarnessTier3Args): Promise<void> {
  const {
    buildTier2Harness,
    extractCorpus,
    runTier3Validation,
  } = await import("@pwnkit/core");

  const repoAbs = resolve(args.repo);
  if (!existsSync(repoAbs)) {
    throw new Error(`Tier-3: repo path '${repoAbs}' does not exist.`);
  }

  if (!VALID_BUILD_SYSTEMS.has(args.buildSystem)) {
    throw new Error(
      `--harness-build-system must be one of: autotools, cmake, meson, auto. Got '${args.buildSystem}'.`,
    );
  }

  const sanitizers = parseSanitizers(args.sanitizers);
  const outputDir = resolve(args.outputDir ?? join(repoAbs, ".pwnkit-out", "tier3"));
  const corpusDir = join(outputDir, "corpus");

  const functionName = args.functionName ?? deriveDefaultFunctionName(repoAbs);
  const header = args.header ?? `${functionName}.h`;

  console.log(
    chalk.cyan(
      `[review] Tier-3 (Tier-2 build → QEMU validate) for '${functionName}' in ${repoAbs}`,
    ),
  );

  const seeds = await extractCorpus(repoAbs, { outputDir: corpusDir });
  if (seeds.length > 0) {
    console.log(
      chalk.green(`[review] extracted ${seeds.length} corpus seed(s) into ${corpusDir}`),
    );
  } else {
    console.log(
      chalk.yellow("[review] no conventional corpus directory — Tier-3 harness will run with the libFuzzer empty corpus"),
    );
  }

  const artifact = await buildTier2Harness({
    suspectFunction: {
      header,
      functionName,
      declaration: `/* hand-fill this declaration from ${header} */`,
      inputShape: "bytesAndLen",
    },
    sourceRoot: repoAbs,
    buildSystem: args.buildSystem as "auto" | "autotools" | "cmake" | "meson",
    sanitizers,
    corpusSeeds: seeds,
    outputDir,
  });

  console.log(chalk.bold("\n[Tier-2 artifact ready]"));
  if (args.verbose) {
    console.log(`  harness:        ${artifact.harness_path}`);
    console.log(`  linked objects: ${artifact.linked_objects.length} file(s)`);
  }

  console.log(chalk.cyan("[review] Tier-3 validating in QEMU..."));
  const result = await runTier3Validation(artifact, {
    qemuKernel: args.qemuKernel,
    qemuDisk: args.qemuDisk,
    runCorpus: seeds,
    wallClockMs: args.wallClockMs,
  });

  // Always emit JSON so downstream tooling can parse the result.
  console.log(chalk.bold("\n[Tier-3 result]"));
  console.log(JSON.stringify(result, null, 2));

  // Mirror the kernel-crash exit-code convention: 0 for verified
  // crash, 2 for "we tried and couldn't get a verdict", 1 for "no
  // crash but the harness ran cleanly".
  if (result.status === "crash_reproduced") {
    process.exitCode = 0;
  } else if (result.status === "no_crash") {
    process.exitCode = 1;
  } else {
    process.exitCode = 2;
  }
}

function parseSanitizers(input: string | undefined): ("asan" | "ubsan" | "msan")[] {
  if (!input || input.trim() === "") return ["asan", "ubsan"];
  const parts = input
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0);
  for (const part of parts) {
    if (!VALID_SANITIZERS.has(part)) {
      throw new Error(`Unknown sanitizer '${part}'. Supported: asan, ubsan, msan.`);
    }
  }
  return parts as ("asan" | "ubsan" | "msan")[];
}

function deriveDefaultFunctionName(repoPath: string): string {
  const safeBase = basename(repoPath).replace(/[^A-Za-z0-9_]/g, "_") || "target";
  return `${safeBase}_entry`;
}

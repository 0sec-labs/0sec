/**
 * `0sec review --harness-tier 2` glue.
 *
 * Translates CLI flags into a Tier-2 harness build, extracts the
 * corpus, and prints a summary plus the compile + run commands the
 * caller can hand to clang. Deliberately does not compile or execute
 * anything.
 */

import chalk from "chalk";
import { resolve, join, basename } from "node:path";
import { existsSync } from "node:fs";

interface RunHarnessTier2Args {
  repo: string;
  functionName?: string;
  header?: string;
  buildSystem: string;
  sanitizers?: string;
  outputDir?: string;
  verbose: boolean;
}

const VALID_BUILD_SYSTEMS = new Set(["autotools", "cmake", "meson", "auto"]);
const VALID_SANITIZERS = new Set(["asan", "ubsan", "msan"]);

export async function runHarnessTier2(args: RunHarnessTier2Args): Promise<void> {
  const { buildTier2Harness, extractCorpus } = await import("@0sec/core");

  const repoAbs = resolve(args.repo);
  if (!existsSync(repoAbs)) {
    throw new Error(`Tier-2: repo path '${repoAbs}' does not exist.`);
  }

  if (!VALID_BUILD_SYSTEMS.has(args.buildSystem)) {
    throw new Error(
      `--harness-build-system must be one of: autotools, cmake, meson, auto. Got '${args.buildSystem}'.`,
    );
  }

  const sanitizers = parseSanitizers(args.sanitizers);
  const outputDir = resolve(args.outputDir ?? join(repoAbs, ".0sec-out", "tier2"));
  const corpusDir = join(outputDir, "corpus");

  const functionName = args.functionName ?? deriveDefaultFunctionName(repoAbs);
  const header = args.header ?? `${functionName}.h`;

  console.log(
    chalk.cyan(
      `[review] Tier-2 harness build for '${functionName}' in ${repoAbs} (build system: ${args.buildSystem})`,
    ),
  );

  const seeds = await extractCorpus(repoAbs, { outputDir: corpusDir });
  if (seeds.length > 0) {
    console.log(
      chalk.green(
        `[review] extracted ${seeds.length} corpus seed(s) into ${corpusDir}`,
      ),
    );
  } else {
    console.log(
      chalk.yellow(
        "[review] no conventional corpus directory found — harness will run with an empty seed set",
      ),
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

  console.log(chalk.bold("\nTier-2 artifact:"));
  console.log(`  harness:        ${artifact.harness_path}`);
  console.log(`  linker script:  ${artifact.linker_script_path}`);
  console.log(`  makefile frag:  ${artifact.makefile_fragment_path}`);
  console.log(`  build system:   ${artifact.detected_build_system}`);
  console.log(`  sanitizers:     ${artifact.sanitizers_enabled.join(", ")}`);
  console.log(`  linked objects: ${artifact.linked_objects.length} file(s)`);
  if (args.verbose) {
    for (const obj of artifact.linked_objects) {
      console.log(`    - ${obj}`);
    }
  }

  console.log(chalk.bold("\nCompile:"));
  console.log(`  ${artifact.compile_command}`);
  console.log(chalk.bold("\nRun:"));
  console.log(`  ${artifact.run_command}`);
  console.log(
    chalk.dim(
      "\nOsec does not compile or execute the harness. Run the compile + run commands manually, or escalate to Tier-3 (QEMU validation, tracked: 0sec#226).",
    ),
  );
}

function parseSanitizers(input: string | undefined): ("asan" | "ubsan" | "msan")[] {
  if (!input || input.trim() === "") return ["asan", "ubsan"];
  const parts = input
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0);
  for (const part of parts) {
    if (!VALID_SANITIZERS.has(part)) {
      throw new Error(
        `Unknown sanitizer '${part}'. Supported: asan, ubsan, msan.`,
      );
    }
  }
  return parts as ("asan" | "ubsan" | "msan")[];
}

function deriveDefaultFunctionName(repoPath: string): string {
  // When the user doesn't pass --harness-function, fall back to a
  // placeholder derived from the repo basename. The emitted harness
  // will not compile without a real function — but it gives the user a
  // sensible starting scaffold to edit.
  const safeBase = basename(repoPath).replace(/[^A-Za-z0-9_]/g, "_") || "target";
  return `${safeBase}_entry`;
}

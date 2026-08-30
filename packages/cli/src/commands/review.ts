import { readFile } from "node:fs/promises";
import type { Command } from "commander";
import chalk from "chalk";
import type { ScanDepth, OutputFormat, RuntimeMode, SeedFinding } from "@0sec/shared";
import { runUnified } from "./run.js";
import { runHarnessTier2 } from "./review-harness-tier2.js";
import { runHarnessTier3 } from "./review-harness-tier3.js";

type ReviewProfile = "default" | "c-library" | "linux-kernel" | "cardano-onchain" | "solana-onchain" | "evm-onchain" | "cairo-onchain" | "move-onchain" | "cardano-haskell" | "xnu-kernel" | "xnu-re";

const REVIEW_PROFILES = new Set<ReviewProfile>(["default", "c-library", "linux-kernel", "cardano-onchain", "solana-onchain", "evm-onchain", "cairo-onchain", "move-onchain", "cardano-haskell", "xnu-kernel", "xnu-re"]);

const VALID_HARNESS_TIERS = new Set(["1", "2", "3"]);

type PackageEcosystem = "npm" | "pypi" | "cargo" | "oci";

const PACKAGE_ECOSYSTEMS = new Set<PackageEcosystem>(["npm", "pypi", "cargo", "oci"]);

function normalizePackageEcosystem(value: string | undefined): PackageEcosystem | undefined {
  if (!value) {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  if (PACKAGE_ECOSYSTEMS.has(normalized as PackageEcosystem)) {
    return normalized as PackageEcosystem;
  }
  throw new Error(
    `Invalid --ecosystem '${value}'. Supported: npm, pypi, cargo, oci. Omit it to review a local path or git URL.`,
  );
}

function normalizeHarnessTier(value: string | undefined): 1 | 2 | 3 {
  if (value === undefined) return 1;
  if (!VALID_HARNESS_TIERS.has(value)) {
    throw new Error(`Invalid --harness-tier '${value}'. Supported: 1, 2, 3.`);
  }
  return Number(value) as 1 | 2 | 3;
}

function normalizeReviewProfile(value: string | undefined, flag: "--profile" | "--target"): ReviewProfile | undefined {
  if (!value) {
    return undefined;
  }
  if (value === "app") {
    return "default";
  }
  if (REVIEW_PROFILES.has(value as ReviewProfile)) {
    return value as ReviewProfile;
  }
  throw new Error(
    `Invalid review ${flag === "--target" ? "target" : "profile"} '${value}'. Supported: default, app, c-library, linux-kernel, cardano-onchain, solana-onchain, evm-onchain, cairo-onchain, move-onchain, cardano-haskell, xnu-kernel, xnu-re.`,
  );
}

export function registerReviewCommand(program: Command): void {
  program
    .command("review")
    .description("Deep source code security review of a repository")
    .argument("<repo>", "Local path or git URL to review")
    .option("--depth <depth>", "Review depth: quick, default, deep", "default")
    .option("--format <format>", "Output format: terminal, json, md, html, sarif, pdf", "terminal")
    .option("--runtime <runtime>", "Runtime: auto, claude, codex, gemini, api, ollama", "auto")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--api-key <key>", "API key for LLM provider")
    .option("-m, --model <model>", "LLM model to use")
    .option("--cost-ceiling <usd>", "Hard per-review USD cost ceiling. Aborts cleanly with partial findings if exceeded.")
    .option("--tui", "Open the local terminal UI after the review completes", false)
    .option("--diff-base <ref>", "Git base ref to review against (for diff-aware review)")
    .option("--changed-only", "Restrict static scanner leads + prioritization to changed files", false)
    .option(
      "--profile <profile>",
      "Review profile: default (web/JS/TS/Python), c-library (C/C++ memory safety, tier-1/2/3 harness), linux-kernel (kernel-aware static review), cardano-onchain (Aiken/Plutus validator logic), solana-onchain (Anchor/native Rust account-model authorization), evm-onchain (Solidity/Foundry/Hardhat DeFi/bridge — reentrancy, oracle manipulation, cross-chain replay), cairo-onchain (Cairo/Starknet DeFi — caller-auth gaps, share-rounding, L1↔L2 messages), move-onchain (Sui/Aptos Move — object/capability binding, shared-math overflow, reward-index accounting), cardano-haskell (first-party Cardano Haskell node stack — ledger/plutus/ouroboros/cardano-base), xnu-kernel (Apple XNU macOS/iOS source review), or xnu-re (decompiled Apple kext pseudo-C)",
      "default",
    )
    .option(
      "--target <target>",
      "Review target alias: app/default, c-library, or linux-kernel",
    )
    .option(
      "--ecosystem <ecosystem>",
      "Review the SOURCE of a published package instead of a repo: npm, pypi, cargo, or oci. When set, <repo> is the package NAME — 0sec installs it and reviews its extracted source. Omit for a local path or git URL.",
    )
    .option(
      "--package-version <version>",
      "Pin the package version to review (only with --ecosystem). Defaults to latest.",
    )
    .option(
      "--seed-findings <path>",
      'Path to ND-JSON leads from an external producer. "-" reads stdin. ' +
        "Schema: gemmaforge.leads/v1. Tracked: 0sec#368.",
    )
    .option(
      "--seed-only",
      "Skip static scanner prioritisation and rely solely on --seed-findings. Only meaningful when --seed-findings is set.",
      false,
    )
    .option(
      "--emit <target>",
      "Emit target. Default unset → existing terminal/json/etc. `pr` → emit each reproduced finding as a GitHub PR with repro + suggested patch (0sec#377). Unverified findings roll up into `hypotheses.md`.",
    )
    .option("--base <branch>", "Base branch for `--emit pr` (default: main)")
    .option("--dry-run", "For `--emit pr`: print git/gh commands instead of running them. Auto-enabled if `gh auth status` fails.", false)
    .option("--emit-out-dir <path>", "Directory for `--emit pr` rollup files (default: system temp)")
    .option(
      "--harness-tier <tier>",
      "C/C++ harness tier to construct: 1 (single-function libFuzzer, default), 2 (multi-component linker), 3 (Tier-2 build + QEMU sanitizer validation).",
      "1",
    )
    .option(
      "--harness-function <name>",
      "Tier-2 only: name of the suspect function the harness should drive. Defaults to a heuristic placeholder.",
    )
    .option(
      "--harness-header <path>",
      "Tier-2 only: header to #include in the emitted harness. Defaults to the function name with a .h suffix.",
    )
    .option(
      "--harness-build-system <system>",
      "Tier-2 only: build system to grep-parse for object subset (autotools, cmake, meson, auto).",
      "auto",
    )
    .option(
      "--harness-sanitizers <list>",
      "Tier-2 only: comma-separated sanitizers to enable (asan, ubsan, msan). Default: asan,ubsan.",
    )
    .option(
      "--harness-out <dir>",
      "Tier-2 only: output directory for the emitted harness + linker fragment. Defaults to <repo>/.0sec-out/tier2.",
    )
    .option(
      "--harness-qemu-kernel <path>",
      "Tier-3 only: pre-built kernel image. Defaults to 0SEC_KERNEL_QEMU_KERNEL.",
    )
    .option(
      "--harness-qemu-disk <path>",
      "Tier-3 only: pre-built rootfs image. Defaults to 0SEC_KERNEL_QEMU_DISK.",
    )
    .option(
      "--harness-wall-clock-ms <ms>",
      "Tier-3 only: wall-clock budget in milliseconds for the full QEMU validation. Default 300000 (5m).",
    )
    .option(
      "--subsystem <path>",
      "Restrict the review to a specific subsystem directory (e.g. crypto/, net/tcp/). Only meaningful with --profile linux-kernel.",
    )
    .option(
      "--hypothesis <text>",
      "Operator hypothesis to seed the agent with a specific research direction. Modeled after Xint Code's operator prompt.",
    )
    .option(
      "--conversation <text>",
      "PR/MR discussion thread to review against (untrusted). The latest message drives this run.",
    )
    .option(
      "--prior-findings <path>",
      "JSON array of prior findings. Fresh review treats it as untrusted context and investigates variants without repeating the originals.",
    )
    .option(
      "--npm-dynamic",
      "Also run the npm dynamic-discovery detector sweep (SSPP fuzz / validation read-stability / SSRF parser-diff) over the package in a disposable sandbox. Only effective with --ecosystem npm. Confirmed leads flow into the same verify → disclosure path.",
      false,
    )
    .option("--resume <run-id>", "Resume a previous run from its journal on disk (0sec#374)")
    .option("--branch-from <entry-index>", "Branch the journal at the given entry index before resuming (requires --resume).")
    .option("--verbose", "Show detailed output", false)
    .option("--timeout <ms>", "AI agent timeout in milliseconds", "600000")
    .action(async (repo: string, opts: Record<string, string | boolean>, command: Command) => {
      let costCeilingUsd: number | undefined;
      const ceilingSource =
        (opts.costCeiling as string | undefined) ?? process.env["0SEC_COST_CEILING_USD"];
      if (ceilingSource !== undefined && ceilingSource !== "") {
        const parsed = Number(ceilingSource);
        if (!Number.isFinite(parsed) || parsed <= 0) {
          throw new Error(`Invalid cost ceiling '${ceilingSource}': must be a positive number (USD).`);
        }
        costCeilingUsd = parsed;
      }
      const profile = normalizeReviewProfile(opts.profile as string | undefined, "--profile") ?? "default";
      const explicitProfile = command.getOptionValueSource("profile") !== "default";
      const targetProfile = normalizeReviewProfile(opts.target as string | undefined, "--target");
      if (targetProfile && explicitProfile && targetProfile !== profile) {
        throw new Error(
          `Conflicting review profile options: --profile ${profile} and --target ${targetProfile}. Use one workflow selector.`,
        );
      }

      let seedFindings: SeedFinding[] | undefined;
      const seedPath = opts.seedFindings as string | undefined;
      if (seedPath) {
        const { readSeedFindings } = await import("@0sec/core");
        seedFindings = readSeedFindings(seedPath);
        console.log(
          chalk.cyan(
            `[review] loaded ${seedFindings.length} seed lead(s) from ${seedPath === "-" ? "stdin" : seedPath}`,
          ),
        );
      }
      if (opts.seedOnly && (!seedFindings || seedFindings.length === 0)) {
        throw new Error("--seed-only requires --seed-findings with at least one valid lead.");
      }

      const harnessTier = normalizeHarnessTier(opts.harnessTier as string | undefined);
      if (harnessTier === 2) {
        // Tier-2 short-circuits the agent pipeline: 0sec just emits
        // the harness artifacts and exits. The compile+run steps are
        // either driven by the calling agent or escalated to Tier-3.
        await runHarnessTier2({
          repo,
          functionName: opts.harnessFunction as string | undefined,
          header: opts.harnessHeader as string | undefined,
          buildSystem: (opts.harnessBuildSystem as string | undefined) ?? "auto",
          sanitizers: opts.harnessSanitizers as string | undefined,
          outputDir: opts.harnessOut as string | undefined,
          verbose: opts.verbose as boolean,
        });
        return;
      }
      if (harnessTier === 3) {
        // Tier-3 chains Tier-2 build → QEMU validation. The Tier-3
        // runner short-circuits to `qemu_failed` when the kernel/disk
        // env vars are unset, so this is safe to call in CI.
        await runHarnessTier3({
          repo,
          functionName: opts.harnessFunction as string | undefined,
          header: opts.harnessHeader as string | undefined,
          buildSystem: (opts.harnessBuildSystem as string | undefined) ?? "auto",
          sanitizers: opts.harnessSanitizers as string | undefined,
          outputDir: opts.harnessOut as string | undefined,
          verbose: opts.verbose as boolean,
          qemuKernel: opts.harnessQemuKernel as string | undefined,
          qemuDisk: opts.harnessQemuDisk as string | undefined,
          wallClockMs: opts.harnessWallClockMs
            ? Number(opts.harnessWallClockMs)
            : undefined,
        });
        return;
      }

      // --emit pr resolution runs LAST among the option parsers: the
      // actual PR-emission step happens inside runUnified after the
      // findings have been collected (see run.ts: `if (opts.emit === "pr")`).
      // Here we just validate the flag so a typo aborts before the
      // expensive review run.
      const emit = (() => {
        const value = opts.emit as string | undefined;
        if (value === undefined) return undefined;
        if (value === "pr") return "pr" as const;
        throw new Error(`Unknown --emit target '${value}'. Supported: pr.`);
      })();

      const reviewPackageEcosystem = normalizePackageEcosystem(opts.ecosystem as string | undefined);

      let priorFindings: Array<{
        id: string;
        title: string;
        category: string;
        description?: string;
        location?: string;
      }> | undefined;
      const priorFindingsPath = opts.priorFindings as string | undefined;
      if (priorFindingsPath) {
        try {
          const parsed: unknown = JSON.parse(await readFile(priorFindingsPath, "utf8"));
          if (
            !Array.isArray(parsed) ||
            parsed.some(
              (value) =>
                !value ||
                typeof value !== "object" ||
                !("id" in value) ||
                typeof value.id !== "string" ||
                !("title" in value) ||
                typeof value.title !== "string" ||
                !("category" in value) ||
                typeof value.category !== "string" ||
                ("description" in value && value.description !== undefined && typeof value.description !== "string") ||
                ("location" in value && value.location !== undefined && typeof value.location !== "string"),
            )
          ) {
            throw new Error("must be a JSON array of { id, title, category, description?, location? }");
          }
          priorFindings = parsed;
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          throw new Error(`Invalid --prior-findings ${priorFindingsPath}: ${message}`);
        }
      }

      const branchFrom = opts.branchFrom as string | undefined;
      const depth = (opts.depth as ScanDepth) ?? "default";
      await runUnified({
        target: repo,
        targetType: "source-code",
        reviewPackageEcosystem,
        packageVersion: opts.packageVersion as string | undefined,
        resumeScanId: opts.resume as string | undefined,
        branchFromEntry: branchFrom !== undefined ? parseInt(branchFrom, 10) : undefined,
        diffBase: opts.diffBase as string | undefined,
        changedOnly: opts.changedOnly as boolean,
        depth,
        reviewStrategy: depth === "deep" ? "lenses" : "pipeline",
        format: (opts.format === "md" ? "markdown" : opts.format) as OutputFormat,
        runtime: (opts.runtime as RuntimeMode) ?? "auto",
        timeout: parseInt(opts.timeout as string, 10),
        verbose: opts.verbose as boolean,
        dbPath: opts.dbPath as string | undefined,
        apiKey: opts.apiKey as string | undefined,
        model: opts.model as string | undefined,
        costCeilingUsd,
        reviewProfile: targetProfile ?? profile,
        subsystem: opts.subsystem as string | undefined,
        hypothesis: opts.hypothesis as string | undefined,
        conversation: opts.conversation as string | undefined,
        priorFindings,
        npmDynamicDiscovery: opts.npmDynamic as boolean | undefined,
        tui: opts.tui as boolean,
        seedFindings,
        seedOnly: opts.seedOnly as boolean,
        emit,
        emitPrBase: opts.base as string | undefined,
        emitPrDryRun: opts.dryRun as boolean | undefined,
        emitOutDir: opts.emitOutDir as string | undefined,
      });
    });
}

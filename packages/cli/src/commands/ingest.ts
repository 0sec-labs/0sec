import { Option, type Command } from "commander";
import chalk from "chalk";
import { readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import type { Finding, RuntimeMode, ScanReport, Severity } from "@0sec/shared";
import type { KernelOracleResult, KernelVmArtifacts } from "@0sec/core";
import { formatSarif } from "../formatters/sarif.js";

const VALID_FORMATS = ["auto", "kasan", "ubsan", "oops", "syzkaller", "generic"] as const;
const VALID_OUTPUT_FORMATS = ["terminal", "json", "sarif"] as const;

type IngestFormat = (typeof VALID_FORMATS)[number];
type IngestOutputFormat = (typeof VALID_OUTPUT_FORMATS)[number];

interface IngestOpts {
  format: string;
  output: string;
  verify?: boolean;
  verbose?: boolean;
  syz?: string;
  reproducer?: string;
  kernelTree?: string;
  /** Legacy alias for --kernel-config (kept for back-compat with --config). */
  config?: string;
  kernelConfig?: string;
  kernelCacheDir?: string;
  expectedSignature?: string;
  forceKernelBuild?: boolean;
  reviewSubsystem?: boolean;
  tree?: string;
  runtime?: string;
  apiKey?: string;
  model?: string;
  timeout?: string;
  costCeiling?: string;
  reviewSubsystemFixture?: string;
}

interface DirectReproducerResult {
  reproducerPath: string;
  reproducerLanguage: "c" | "syz";
  kernelBuild?: KernelVmArtifacts;
  verification: KernelOracleResult;
}

interface VerifiedCrashResult {
  sourcePath: string;
  reproducerPath?: string;
  finding: Finding;
  verification: KernelOracleResult;
}

interface IngestReviewOutput {
  crashFindings: Finding[];
  reviewFindings: Finding[];
  findings: Finding[];
  skipped: Array<{ sourcePath: string; findingId: string; subsystem: string; reason: string }>;
  verified?: VerifiedCrashResult[];
}

export function registerIngestCommand(program: Command): void {
  program
    .command("ingest")
    .description("Import kernel crash reports (KASAN, UBSAN, oops, syzkaller) into 0sec findings")
    .argument("[path]", "Path to a crash report file or directory of reports")
    .option("--format <format>", "Input format: auto | kasan | ubsan | oops | syzkaller | generic", "auto")
    .option("-o, --output <format>", "Output format: terminal | json | sarif", "terminal")
    .option("--verify", "Run kernel oracle verification for each report/reproducer")
    .option("--syz <path>", "Run a standalone syzkaller .syz program through the kernel VM oracle")
    .option("--reproducer <path>", "Run a standalone C reproducer through the kernel VM oracle")
    .option("--kernel-tree <path>", "Linux source tree for Tier 1 kernel build/cache resolution")
    .option("--kernel-config <name>", "Kernel build config name for --kernel-tree (e.g. kasan, defconfig+kasan)")
    .option("--config <profile>", "[deprecated] alias for --kernel-config")
    .option("--kernel-cache-dir <path>", "Kernel build cache directory (default: ~/.0sec/kernel-cache)")
    .option("--expected-signature <pattern>", "Expected dmesg signature substring (case-insensitive) for verify")
    .option("--force-kernel-build", "Rebuild kernel VM artifacts even when a cache entry exists")
    .option("--review-subsystem", "After ingest, run linux-kernel review against the crash subsystem for sibling bugs")
    .option("--tree <path>", "Linux source tree used by --review-subsystem")
    .option("--runtime <runtime>", "Review runtime for --review-subsystem: auto, claude, codex, gemini, api", "auto")
    .option("--api-key <key>", "API key for --review-subsystem API runtime")
    .option("--model <model>", "Model for --review-subsystem")
    .option("--timeout <ms>", "AI review timeout for --review-subsystem", "600000")
    .option("--cost-ceiling <usd>", "Hard USD cost ceiling for --review-subsystem")
    .addOption(new Option("--review-subsystem-fixture <path>").hideHelp())
    .option("-v, --verbose", "Verbose output")
    .action(async (inputPath: string | undefined, opts: IngestOpts) => {
      try {
        const format = opts.format as IngestFormat;
        const outputFormat = opts.output as IngestOutputFormat;

        if (!VALID_FORMATS.includes(format)) {
          throw new Error(
            `Invalid input format '${format}'. Valid: ${VALID_FORMATS.join(", ")}`,
          );
        }
        if (!VALID_OUTPUT_FORMATS.includes(outputFormat)) {
          throw new Error(
            `Invalid output format '${outputFormat}'. Valid: ${VALID_OUTPUT_FORMATS.join(", ")}`,
          );
        }
        // sarif+verify is supported: verification results are embedded as SARIF result properties

        const directReproducerPath = opts.reproducer ?? opts.syz;
        const directReproducerLanguage: "c" | "syz" | undefined = opts.reproducer
          ? "c"
          : opts.syz
            ? "syz"
            : undefined;
        if (opts.reproducer && opts.syz) {
          throw new Error("Use only one of --reproducer or --syz.");
        }
        if (!inputPath && !directReproducerPath) {
          throw new Error("Path is required unless --reproducer or --syz is provided.");
        }
        if (inputPath && directReproducerPath) {
          throw new Error("Do not pass a crash-report path together with --reproducer or --syz.");
        }

        const resolved = inputPath ? resolve(inputPath) : "";
        const stat = inputPath ? statSync(resolved) : undefined;
        const reviewSubsystem = opts.reviewSubsystem === true;

        if (reviewSubsystem && !opts.tree) {
          throw new Error("--review-subsystem requires --tree <path-to-linux>");
        }
        // --kernel-config supersedes the legacy --config alias.
        const kernelConfigName = opts.kernelConfig ?? opts.config ?? "kasan";
        if (directReproducerPath && !opts.kernelTree) {
          throw new Error("--reproducer/--syz requires --kernel-tree <path-to-linux>");
        }

        let costCeilingUsd: number | undefined;
        const ceilingSource = opts.costCeiling ?? process.env["0SEC_COST_CEILING_USD"];
        if (ceilingSource !== undefined && ceilingSource !== "") {
          const parsed = Number(ceilingSource);
          if (!Number.isFinite(parsed) || parsed <= 0) {
            throw new Error(`Invalid cost ceiling '${ceilingSource}': must be a positive number (USD).`);
          }
          costCeilingUsd = parsed;
        }

        const {
          ingestArtifactsFromFile,
          ingestArtifactsFromDirectory,
          prepareKernelVmArtifacts,
          reviewKernelCrashSubsystems,
          verifyStandaloneKernelReproducer,
          verifyKernelCrash,
        } = await import("@0sec/core");

        let kernelBuild: KernelVmArtifacts | undefined;
        if (opts.kernelTree) {
          kernelBuild = prepareKernelVmArtifacts({
            kernelTree: opts.kernelTree,
            configProfile: kernelConfigName,
            cacheDir: opts.kernelCacheDir,
            force: opts.forceKernelBuild,
          });
          process.env["0SEC_KERNEL_QEMU"] = "1";
          process.env["0SEC_KERNEL_QEMU_KERNEL"] = kernelBuild.kernelImage;
          process.env["0SEC_KERNEL_QEMU_DISK"] = kernelBuild.diskImage;
          if (kernelBuild.kernelConfig) {
            process.env["0SEC_KERNEL_QEMU_CONFIG"] = kernelBuild.kernelConfig;
          }
        }

        if (directReproducerPath && directReproducerLanguage) {
          if (outputFormat === "sarif") {
            throw new Error("--output sarif is not supported for standalone reproducers.");
          }
          const reproPath = resolve(directReproducerPath);
          console.log(chalk.blue(`Running ${directReproducerLanguage} reproducer: ${reproPath}`));
          const verification = await verifyStandaloneKernelReproducer({
            raw: "",
            crashType: "unknown",
            faultingFunction: "unknown",
            stackFrames: [],
            reproducer: readFileSync(reproPath, "utf8"),
            reproducerLanguage: directReproducerLanguage,
          });
          const directResult: DirectReproducerResult = {
            reproducerPath: reproPath,
            reproducerLanguage: directReproducerLanguage,
            kernelBuild,
            verification,
          };
          if (outputFormat === "json") {
            console.log(JSON.stringify(directResult, null, 2));
            return;
          }
          const verdict = verification.verified
            ? chalk.green("VERIFIED")
            : verification.reproduced
              ? chalk.yellow("REPRODUCED")
              : chalk.gray("UNVERIFIED");
          console.log(`\n${verdict} ${chalk.white(verification.reproducedCrashType ?? "no crash signature")}`);
          if (kernelBuild) {
            console.log(chalk.gray(`kernelBuild=${kernelBuild.cacheStatus} key=${kernelBuild.cacheKey}`));
          }
          if (verification.reason) console.log(chalk.gray(`reason=${verification.reason}`));
          if (verification.evidence) console.log(chalk.gray(`evidence=${verification.evidence}`));
          return;
        }

        let findings: Finding[];
        let verifiedResults: VerifiedCrashResult[] | undefined;
        let reviewOutput: IngestReviewOutput | undefined;
        const artifacts = stat!.isDirectory()
          ? (console.log(chalk.blue(`${opts.verify ? "Scanning and verifying" : "Scanning"} directory: ${resolved}`)), ingestArtifactsFromDirectory(resolved))
          : (console.log(chalk.blue(`${opts.verify ? "Parsing and verifying" : "Parsing"} crash report: ${resolved}`)), ingestArtifactsFromFile(resolved));

        if (opts.verify) {
          verifiedResults = await Promise.all(
            artifacts.map(async (artifact) => ({
              sourcePath: artifact.sourcePath,
              reproducerPath: artifact.reproducerPath,
              finding: artifact.finding,
              verification: await verifyKernelCrash(artifact.finding, {
                raw: artifact.report.rawText,
                crashType: artifact.report.crashType,
                faultingFunction: artifact.report.faultingFunction,
                stackFrames: artifact.report.callStack,
                reproducer: artifact.report.reproducer,
                accessType: artifact.report.accessType,
                accessSize: artifact.report.accessSize,
                subsystem: artifact.report.subsystem,
              }),
            })),
          );
          findings = verifiedResults.map((result) => result.finding);
        } else {
          findings = artifacts.map((artifact) => artifact.finding);
        }

        if (reviewSubsystem) {
          const reviewResult = await reviewKernelCrashSubsystems(artifacts, {
            tree: resolve(opts.tree!),
            runtime: (opts.runtime as RuntimeMode | undefined) ?? "auto",
            apiKey: opts.apiKey,
            model: opts.model,
            timeout: opts.timeout ? parseInt(opts.timeout, 10) : undefined,
            costCeilingUsd,
            fixtureFindingsPath: opts.reviewSubsystemFixture,
            onEvent: opts.verbose
              ? (event) => {
                  if (event.message) {
                    console.error(chalk.gray(`[${event.stage ?? event.type}] ${event.message}`));
                  }
                }
              : undefined,
          });
          findings = reviewResult.findings;
          reviewOutput = {
            ...reviewResult,
            verified: verifiedResults,
          };
        }

        if (findings.length === 0) {
          console.log(chalk.yellow("No crash reports found."));
          return;
        }

        console.log(
          chalk.green(
            `\nIngested ${findings.length} finding${findings.length > 1 ? "s" : ""}:\n`,
          ),
        );

        if (outputFormat === "json") {
          console.log(JSON.stringify(reviewOutput ?? verifiedResults ?? findings, null, 2));
          return;
        }

        if (outputFormat === "sarif") {
          const now = new Date().toISOString();
          const bySev = (sev: Severity) => findings.filter((f) => f.severity === sev).length;
          const syntheticReport: ScanReport = {
            target: resolved,
            scanDepth: "default",
            startedAt: now,
            completedAt: now,
            durationMs: 0,
            summary: {
              totalAttacks: 0,
              totalFindings: findings.length,
              critical: bySev("critical"),
              high: bySev("high"),
              medium: bySev("medium"),
              low: bySev("low"),
              info: bySev("info"),
            },
            findings,
            warnings: [],
          };

          let sarifOutput = formatSarif(syntheticReport);

          // If --verify was used, embed verification results as properties on each SARIF result
          if (verifiedResults) {
            const verifiedById = new Map(
              verifiedResults.map((r) => [r.finding.id, r]),
            );
            const sarif = JSON.parse(sarifOutput);
            const results = sarif.runs?.[0]?.results as Array<{ ruleId: string; properties?: Record<string, unknown> }> | undefined;
            if (results) {
              // Results are in the same order as findings
              for (let i = 0; i < results.length; i++) {
                const f = findings[i];
                if (!f) continue;
                const v = verifiedById.get(f.id);
                if (v) {
                  results[i].properties = {
                    ...results[i].properties,
                    verification: {
                      verified: v.verification.verified,
                      reproduced: v.verification.reproduced,
                      confidence: v.verification.confidence,
                      reason: v.verification.reason,
                    },
                  };
                }
              }
            }
            sarifOutput = JSON.stringify(sarif, null, 2);
          }
          if (reviewOutput) {
            const relatedById = new Map(
              reviewOutput.reviewFindings.map((finding) => [finding.id, finding.relatedFindingId]),
            );
            const sarif = JSON.parse(sarifOutput);
            const results = sarif.runs?.[0]?.results as Array<{ ruleId: string; properties?: Record<string, unknown> }> | undefined;
            if (results) {
              for (let i = 0; i < results.length; i++) {
                const f = findings[i];
                if (!f) continue;
                const relatedFindingId = relatedById.get(f.id);
                if (relatedFindingId) {
                  results[i].properties = {
                    ...results[i].properties,
                    relatedFindingId,
                    reviewSubsystem: true,
                  };
                }
              }
            }
            sarifOutput = JSON.stringify(sarif, null, 2);
          }

          console.log(sarifOutput);
          return;
        }

        // Terminal output
        const severityColor: Record<string, (s: string) => string> = {
          critical: chalk.bgRed.white.bold,
          high: chalk.red.bold,
          medium: chalk.yellow,
          low: chalk.blue,
          info: chalk.gray,
        };

        const verifiedById = new Map<string, VerifiedCrashResult>(
          (verifiedResults ?? []).map((result) => [result.finding.id, result]),
        );

        for (const f of findings) {
          const color = severityColor[f.severity] ?? chalk.white;
          console.log(
            `  ${color(f.severity.toUpperCase().padEnd(8))} ${chalk.white(f.title)}`,
          );
          console.log(
            `           ${chalk.gray(`category=${f.category}  confidence=${(f.confidence ?? 0).toFixed(1)}  id=${f.id.slice(0, 8)}`)}`,
          );
          const verified = verifiedById.get(f.id);
          if (verified) {
            const verdict = verified.verification.verified
              ? chalk.green("VERIFIED")
              : verified.verification.reproduced
                ? chalk.yellow("MISMATCH")
                : chalk.gray("UNVERIFIED");
            console.log(
              `           ${verdict} ${chalk.gray(`runner=${verified.verification.reproduced ? "kernel-vm" : "static"} oracle_confidence=${verified.verification.confidence.toFixed(2)}`)}`,
            );
            if (verified.verification.reason) {
              console.log(
                chalk.gray(`           reason=${verified.verification.reason}`),
              );
            }
          }
          if (opts.verbose && f.evidence.analysis) {
            console.log(
              chalk.gray(`           ${f.evidence.analysis.slice(0, 200)}`),
            );
          }
          if (f.relatedFindingId) {
            console.log(
              chalk.gray(`           relatedFindingId=${f.relatedFindingId}`),
            );
          }
          console.log();
        }

        // Summary
        const bySeverity = findings.reduce(
          (acc, f) => {
            acc[f.severity] = (acc[f.severity] || 0) + 1;
            return acc;
          },
          {} as Record<string, number>,
        );

        console.log(chalk.white.bold("Summary:"));
        for (const sev of ["critical", "high", "medium", "low", "info"] as const) {
          if (bySeverity[sev]) {
            const color = severityColor[sev] ?? chalk.white;
            console.log(`  ${color(`${sev}: ${bySeverity[sev]}`)}`);
          }
        }
        if (verifiedResults) {
          const verifiedCount = verifiedResults.filter((r) => r.verification.verified).length;
          const reproducedCount = verifiedResults.filter((r) => r.verification.reproduced).length;
          console.log(chalk.white.bold("Verification:"));
          console.log(`  ${chalk.green(`verified: ${verifiedCount}`)}`);
          console.log(`  ${chalk.yellow(`reproduced-but-mismatch: ${reproducedCount - verifiedCount}`)}`);
          console.log(`  ${chalk.gray(`static-only/unverified: ${verifiedResults.length - reproducedCount}`)}`);
        }
        if (reviewOutput) {
          console.log(chalk.white.bold("Subsystem review:"));
          console.log(`  ${chalk.green(`sibling findings: ${reviewOutput.reviewFindings.length}`)}`);
          if (reviewOutput.skipped.length > 0) {
            console.log(`  ${chalk.gray(`skipped crashes: ${reviewOutput.skipped.length}`)}`);
          }
        }
      } catch (err) {
        console.error(
          chalk.red(`Error: ${err instanceof Error ? err.message : String(err)}`),
        );
        process.exitCode = 1;
      }
    });
}

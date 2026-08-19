import type { Command } from "commander";
import chalk from "chalk";
import {
  runNpmDynamicDiscovery,
  createOsvAdvisoryLookup,
  DETECTOR_REGISTRY,
  resolveDetectors,
  inProcessProbe,
  type NpmDynamicDiscoveryResult,
  type PackageRef,
} from "@0sec/core";

interface NpmDiscoveryRunOptions {
  installDir?: string;
  packages?: string;
  detectors?: string;
  downloadsFloor?: string;
  maxAgeDays?: string;
  json?: boolean;
  iUnderstandUntrustedExec?: boolean;
  offlineDedup?: boolean;
}

/**
 * npm-ecosystem dynamic-discovery — drive the pluggable detector registry
 * (sspp-fuzz, read-unstable, parser-diff) over a package worklist. LLM-proposes
 * / harness-disposes: confirmed ONLY on an observed runtime consequence
 * (assume-FP), deduped against fork-twins + prior 0sec reports.
 *
 * SAFETY: `run` loads the target packages in-process to exercise their code, so
 * it runs UNTRUSTED code on this host. It is gated behind
 * `--i-understand-untrusted-exec` and expects packages already installed under
 * `--install-dir` (prepared with `npm install --ignore-scripts`). In production
 * this stage runs inside the e2b sandbox; the CLI path is the trusted-host
 * single-box analog of the prototype miner.
 */
export function registerNpmDiscoveryCommand(program: Command): void {
  const cmd = program
    .command("npm-discovery")
    .description(
      "npm-ecosystem dynamic bug discovery via the pluggable detector registry (SSPP fuzz / validation read-stability TOCTOU / SSRF parser-diff). Confirmed only on observed runtime consequence.",
    );

  cmd
    .command("list")
    .description("List the registered detectors and their classes.")
    .option("--json", "Emit as JSON")
    .action((opts: { json?: boolean }) => {
      if (opts.json) {
        console.log(
          JSON.stringify(
            DETECTOR_REGISTRY.map((d) => ({ id: d.id, title: d.title, cwe: d.cwe, category: d.category, severityFloor: d.severityFloor, description: d.description })),
            null,
            2,
          ),
        );
        return;
      }
      console.log(chalk.bold("Registered npm dynamic-discovery detectors:\n"));
      for (const d of DETECTOR_REGISTRY) {
        console.log(`  ${chalk.cyan(d.id)}  ${chalk.dim(`[${d.cwe} · ${d.category} · ${d.severityFloor}]`)}`);
        console.log(`    ${d.description}`);
      }
    });

  cmd
    .command("run")
    .description("Sweep a package worklist with the detectors and print confirmed findings.")
    .requiredOption("--install-dir <dir>", "Base dir the packages are installed under (prepare with `npm install --ignore-scripts`).")
    .option("--packages <list>", "Comma-separated package names to sweep, e.g. es-toolkit,radash")
    .option("--detectors <ids>", "Restrict to these detector ids (comma-separated). Default: all.")
    .option("--downloads-floor <n>", "Skip packages below this weekly-download floor (needs registry metadata).")
    .option("--max-age-days <n>", "Skip packages whose last publish is older than this (needs registry metadata).")
    .option("--i-understand-untrusted-exec", "Acknowledge that `run` executes untrusted package code in-process on this host.")
    .option("--offline-dedup", "Skip the live OSV advisory lookup (air-gapped/hermetic runs). Confirmed findings then dedup only against fork-twin/prior-report hints; live-unknown ones are marked source=unknown, not novel.")
    .option("--json", "Emit the result as machine-readable JSON")
    .action(async (opts: NpmDiscoveryRunOptions) => {
      if (!opts.iUnderstandUntrustedExec) {
        console.error(
          chalk.red(
            "Refusing: `run` executes untrusted npm package code in-process. Re-run with --i-understand-untrusted-exec on a disposable/sandboxed host, or drive runNpmDynamicDiscovery() with a sandbox probeFactory.",
          ),
        );
        process.exitCode = 2;
        return;
      }
      const names = (opts.packages ?? "").split(",").map((s) => s.trim()).filter(Boolean);
      if (names.length === 0) {
        console.error(chalk.red("No packages given. Pass --packages a,b,c."));
        process.exitCode = 2;
        return;
      }
      const detectorIds = opts.detectors ? opts.detectors.split(",").map((s) => s.trim()).filter(Boolean) : undefined;
      if (detectorIds) {
        const { unknown } = resolveDetectors(detectorIds);
        if (unknown.length) {
          console.error(chalk.red(`Unknown detector id(s): ${unknown.join(", ")}. See 'npm-discovery list'.`));
          process.exitCode = 2;
          return;
        }
      }
      const downloadsFloor = opts.downloadsFloor !== undefined ? Number(opts.downloadsFloor) : undefined;
      const maxAgeDays = opts.maxAgeDays !== undefined ? Number(opts.maxAgeDays) : undefined;

      const worklist: PackageRef[] = names.map((name) => ({ name }));
      // Production default: the live OSV advisory lookup, so a confirmed bug that
      // is already publicly known is classified `known`, not disclosed as novel.
      // It fails CLOSED (a lookup fault ⇒ source=unknown, never blind-novel).
      // `--offline-dedup` drops it for air-gapped/hermetic runs.
      const advisoryLookup = opts.offlineDedup ? undefined : createOsvAdvisoryLookup();
      const result = await runNpmDynamicDiscovery({
        worklist,
        detectorIds,
        guards: { downloadsFloor, maxAgeDays },
        advisoryLookup,
        probeFactory: (pkg) => inProcessProbe(pkg, opts.installDir!),
        log: (m) => {
          if (!opts.json) console.error(chalk.dim(m));
        },
      });

      if (opts.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }
      renderResult(result);
    });
}

function renderResult(result: NpmDynamicDiscoveryResult): void {
  console.log(chalk.bold(`\nnpm-discovery: ${result.scannedPackages} package(s) swept`));
  for (const s of result.perDetector) {
    console.log(`  ${chalk.cyan(s.detectorId)}: ran ${s.packagesRun} · candidates ${s.candidates} · confirmed ${s.confirmed} · novel ${s.novel}`);
  }
  if (result.unpreparable.length) console.log(chalk.yellow(`  unpreparable: ${result.unpreparable.join(", ")}`));
  console.log("");
  console.log(chalk.bold(`NOVEL findings (${result.novel.length}):`));
  for (const f of result.novel) console.log(`  ${chalk.red(f.severity)}  ${f.title}\n    ${chalk.dim(f.evidence.response)}`);
  if (result.known.length) {
    console.log(chalk.bold(`\nknown / non-novel (${result.known.length}):`));
    for (const f of result.known) console.log(`  ${chalk.dim(`${f.severity}  ${f.title}`)}`);
  }
  if (result.warnings.length) {
    console.log(chalk.dim(`\n${result.warnings.length} warning(s)`));
  }
}

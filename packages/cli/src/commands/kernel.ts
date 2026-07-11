import type { Command } from "commander";
import chalk from "chalk";
import type { KernelVariantHuntReport } from "@pwnkit/core";
import type { ScanReport, Severity } from "@pwnkit/shared";
import { formatSarif } from "../formatters/sarif.js";

const VALID_OUTPUT_FORMATS = ["terminal", "json", "sarif"] as const;
type KernelOutputFormat = (typeof VALID_OUTPUT_FORMATS)[number];

interface VariantHuntOpts {
  advisory?: string;
  tree: string;
  rules?: string;
  foxguard?: string;
  sarifInput?: string;
  timeout?: string;
  output: string;
  verbose?: boolean;
}

interface SyzbotMineOpts {
  subsystems: string;
  limit: string;
  details: string;
}

function parsePositiveInt(value: string, name: string, max: number): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 1 || parsed > max) {
    throw new Error(`Invalid ${name} '${value}'; expected 1..${max}`);
  }
  return parsed;
}

function parseTimeoutMs(value?: string): number | undefined {
  if (!value) return undefined;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`Invalid timeout '${value}'; expected positive milliseconds`);
  }
  return parsed;
}

function variantReportToScanReport(report: KernelVariantHuntReport): ScanReport {
  const bySev = (sev: Severity) => report.findings.filter((f) => f.severity === sev).length;
  return {
    target: report.tree,
    scanDepth: "default",
    startedAt: report.startedAt,
    completedAt: report.completedAt,
    durationMs: report.durationMs,
    summary: {
      totalAttacks: report.foxguardFindings.length,
      totalFindings: report.findings.length,
      critical: bySev("critical"),
      high: bySev("high"),
      medium: bySev("medium"),
      low: bySev("low"),
      info: bySev("info"),
    },
    findings: report.findings,
    warnings: report.warnings,
  };
}

function renderTerminal(report: KernelVariantHuntReport, verbose = false): void {
  const severityColor: Record<string, (s: string) => string> = {
    critical: chalk.bgRed.white.bold,
    high: chalk.red.bold,
    medium: chalk.yellow,
    low: chalk.blue,
    info: chalk.gray,
  };

  console.log(chalk.blue(`Scanning kernel tree: ${report.tree}`));
  if (report.advisory) console.log(chalk.gray(`Advisory: ${report.advisory}`));
  if (report.rules) console.log(chalk.gray(`Rules: ${report.rules}`));
  if (report.foxguardPath) console.log(chalk.gray(`Foxguard: ${report.foxguardPath}`));

  if (report.warnings.length > 0) {
    for (const warning of report.warnings) {
      console.log(chalk.yellow(`Warning: ${warning.message}`));
    }
  }

  if (report.findings.length === 0) {
    console.log(chalk.green("\nNo variant candidates found."));
    return;
  }

  console.log(
    chalk.green(
      `\nFound ${report.findings.length} variant candidate${report.findings.length > 1 ? "s" : ""}:\n`,
    ),
  );

  for (const finding of report.findings) {
    const color = severityColor[finding.severity] ?? chalk.white;
    console.log(`  ${color(finding.severity.toUpperCase().padEnd(8))} ${chalk.white(finding.title)}`);
    console.log(
      `           ${chalk.gray(`category=${finding.category} confidence=${(finding.confidence ?? 0).toFixed(2)} id=${finding.id.slice(0, 8)}`)}`,
    );
    if (finding.fingerprint) {
      console.log(`           ${chalk.gray(`fingerprint=${finding.fingerprint}`)}`);
    }
    if (verbose && finding.evidence.analysis) {
      console.log(chalk.gray(`           ${finding.evidence.analysis.replace(/\n/g, "\n           ")}`));
    }
    console.log();
  }

  const scanReport = variantReportToScanReport(report);
  console.log(chalk.white.bold("Summary:"));
  for (const sev of ["critical", "high", "medium", "low", "info"] as const) {
    const count = scanReport.summary[sev];
    if (count > 0) {
      const color = severityColor[sev] ?? chalk.white;
      console.log(`  ${color(`${sev}: ${count}`)}`);
    }
  }
}

export function registerKernelCommand(program: Command): void {
  const kernel = program
    .command("kernel")
    .description("Kernel security workflows");

  kernel
    .command("syzbot-mine")
    .description("Mine and LPE-rank syzbot's invalid/auto-closed queue")
    .option("--subsystems <csv>", "Subsystem labels to keep", "net,net/sched,net/tls,xfrm,crypto,vsock,nfc")
    .option("--limit <n>", "Maximum ranked candidates", "30")
    .option("--details <n>", "Top candidate detail pages to enrich", "15")
    .action(async (opts: SyzbotMineOpts) => {
      try {
        const limit = parsePositiveInt(opts.limit, "--limit", 500);
        const details = parsePositiveInt(opts.details, "--details", 100);
        const subsystems = opts.subsystems.split(",").map((value) => value.trim()).filter(Boolean);
        const { defaultSyzbotFetcher, mineSyzbotQueue, toHuntCandidates } = await import("@pwnkit/core");
        const result = await mineSyzbotQueue({
          fetch: defaultSyzbotFetcher,
          fetchDetail: defaultSyzbotFetcher,
          fetchRepro: defaultSyzbotFetcher,
          maxDetailFetches: details,
          limit,
          subsystems,
          log: (message) => console.error(message),
        });
        console.log(JSON.stringify({ ...result, huntCandidates: toHuntCandidates(result) }, null, 2));
      } catch (err) {
        console.error(chalk.red(`Error: ${err instanceof Error ? err.message : String(err)}`));
        process.exitCode = 1;
      }
    });

  kernel
    .command("variant-hunt")
    .description("Run foxguard-backed kernel advisory variant hunting")
    .requiredOption("--tree <path>", "Path to a Linux source tree")
    .option("--advisory <url-or-file>", "Advisory URL or local advisory path for provenance")
    .option("--rules <path>", "Foxguard rule directory, e.g. rules/kernel/dirty-frag-class")
    .option("--foxguard <path>", "Foxguard binary path")
    .option("--sarif-input <path>", "Use an existing foxguard SARIF file instead of invoking foxguard")
    .option("--timeout <ms>", "Foxguard timeout in milliseconds", "120000")
    .option("-o, --output <format>", "Output format: terminal | json | sarif", "terminal")
    .option("-v, --verbose", "Verbose terminal output")
    .action(async (opts: VariantHuntOpts) => {
      try {
        const output = opts.output as KernelOutputFormat;
        if (!VALID_OUTPUT_FORMATS.includes(output)) {
          throw new Error(
            `Invalid output format '${opts.output}'. Valid: ${VALID_OUTPUT_FORMATS.join(", ")}`,
          );
        }

        const { runKernelVariantHunt } = await import("@pwnkit/core");
        const report = await runKernelVariantHunt({
          tree: opts.tree,
          advisory: opts.advisory,
          rules: opts.rules,
          foxguardPath: opts.foxguard,
          sarifPath: opts.sarifInput,
          timeoutMs: parseTimeoutMs(opts.timeout),
        });

        if (output === "json") {
          console.log(JSON.stringify(report, null, 2));
          return;
        }

        if (output === "sarif") {
          console.log(formatSarif(variantReportToScanReport(report)));
          return;
        }

        renderTerminal(report, opts.verbose);
      } catch (err) {
        console.error(chalk.red(`Error: ${err instanceof Error ? err.message : String(err)}`));
        process.exitCode = 1;
      }
    });
}

export { parsePositiveInt, variantReportToScanReport };

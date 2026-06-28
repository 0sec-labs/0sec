import type { Command } from "commander";
import { readFileSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { extractSpecInvariants, prepare, runSpecdriftScan } from "@pwnkit/core";

interface ExtractOpts {
  spec?: string;
  specName?: string;
  maxInvariants?: string;
  output?: string;
}

interface ScanOpts extends ExtractOpts {
  source?: string;
  maxFiles?: string;
  maxCandidatesPerInvariant?: string;
  timeout?: string;
}

function parsePositive(flag: string, raw: string | undefined, dflt: number): number {
  if (raw === undefined) return dflt;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`invalid ${flag} '${raw}' (expected positive integer)`);
  return n;
}

export async function runSpecdriftExtract(opts: ExtractOpts): Promise<unknown> {
  if (!opts.spec) throw new Error("missing required flag: --spec <path>");
  const maxInvariants = parsePositive("--max-invariants", opts.maxInvariants, 40);
  const specPath = resolve(opts.spec);
  const specText = readFileSync(specPath, "utf8");
  return extractSpecInvariants({
    specName: opts.specName ?? basename(specPath),
    specText,
    maxInvariants,
  });
}

export async function runSpecdriftScanCli(opts: ScanOpts): Promise<unknown> {
  if (!opts.spec) throw new Error("missing required flag: --spec <path>");
  if (!opts.source) throw new Error("missing required flag: --source <path-or-git-url>");
  const maxInvariants = parsePositive("--max-invariants", opts.maxInvariants, 40);
  const maxFiles = parsePositive("--max-files", opts.maxFiles, 400);
  const maxCandidatesPerInvariant = parsePositive("--max-candidates-per-invariant", opts.maxCandidatesPerInvariant, 5);
  const timeout = parsePositive("--timeout", opts.timeout, 600_000);
  const specPath = resolve(opts.spec);
  const specText = readFileSync(specPath, "utf8");
  const prepared = await prepare(opts.source, "source-code", { timeout }, (e) => {
    if (e.message) process.stderr.write(`[specdrift:source] ${e.message}\n`);
  });
  try {
    return runSpecdriftScan({
      specName: opts.specName ?? basename(specPath),
      specText,
      sourceRoot: resolve(prepared.resolvedTarget),
      maxInvariants,
      maxFiles,
      maxCandidatesPerInvariant,
    });
  } finally {
    prepared.cleanup();
  }
}

async function writeJsonResult(fn: () => Promise<unknown>, output?: string, stage = "extract"): Promise<void> {
  try {
    const result = await fn();
    const json = JSON.stringify(result, null, 2);
    if (output) writeFileSync(resolve(output), json + "\n", "utf8");
    else process.stdout.write(json + "\n");
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    const json = JSON.stringify({ mode: "specdrift", stage, error: reason }, null, 2);
    if (output) {
      try { writeFileSync(resolve(output), json + "\n", "utf8"); } catch { process.stderr.write(json + "\n"); }
    } else process.stderr.write(json + "\n");
    process.exitCode = 3;
  }
}

export function registerSpecdriftCommand(program: Command): void {
  const cmd = program
    .command("specdrift")
    .description("Private protocol/spec differential-hunting research commands");

  cmd
    .command("extract")
    .description("Extract cited protocol invariants from an arbitrary spec text file")
    .requiredOption("--spec <path>", "Spec/RFC/protocol text file to analyze")
    .option("--spec-name <name>", "Display name stored in citations")
    .option("--max-invariants <N>", "Maximum invariant candidates to emit", "40")
    .option("--output <path>", "Write JSON result to a file instead of stdout")
    .action(async (opts: ExtractOpts) => {
      await writeJsonResult(() => runSpecdriftExtract(opts), opts.output, "extract");
    });

  cmd
    .command("scan")
    .description("Extract spec invariants and map them to candidate implementation code")
    .requiredOption("--spec <path>", "Spec/RFC/protocol text file to analyze")
    .requiredOption("--source <path-or-git-url>", "Implementation source tree to map against")
    .option("--spec-name <name>", "Display name stored in citations")
    .option("--max-invariants <N>", "Maximum invariant candidates to extract", "40")
    .option("--max-files <N>", "Maximum source files to inspect", "400")
    .option("--max-candidates-per-invariant <N>", "Maximum implementation candidates per invariant", "5")
    .option("--timeout <ms>", "Source preparation timeout", "600000")
    .option("--output <path>", "Write JSON result to a file instead of stdout")
    .action(async (opts: ScanOpts) => {
      await writeJsonResult(() => runSpecdriftScanCli(opts), opts.output, "scan");
    });
}

import type { Command } from "commander";
import { readFileSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { extractSpecInvariants } from "@pwnkit/core";

interface ExtractOpts {
  spec?: string;
  specName?: string;
  maxInvariants?: string;
  output?: string;
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
      try {
        const result = await runSpecdriftExtract(opts);
        const json = JSON.stringify(result, null, 2);
        if (opts.output) writeFileSync(resolve(opts.output), json + "\n", "utf8");
        else process.stdout.write(json + "\n");
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        const json = JSON.stringify({ mode: "specdrift", stage: "extract", error: reason }, null, 2);
        if (opts.output) {
          try { writeFileSync(resolve(opts.output), json + "\n", "utf8"); } catch { process.stderr.write(json + "\n"); }
        } else process.stderr.write(json + "\n");
        process.exitCode = 3;
      }
    });
}

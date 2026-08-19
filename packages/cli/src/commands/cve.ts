// `pwnkit cve` — CVE workflows.
//
// Two subcommands live on the same parent command, one per slice of
// issue #272 v0:
//
//   - `pwnkit cve find <cve-id>`  — issue #272 v0 part 1. Operator-facing
//     half of the artifact scraper. Queries a curated set of public
//     catalogues (NVD, GHSA, OSV, distro trackers, GitHub search),
//     merges the results, and emits either machine-readable JSON or a
//     pretty table.
//
//   - `pwnkit cve adapt <cve-id>` — issue #272 v0 part 2. Wraps the
//     core `adaptAndVerify` pipeline so an operator can run the
//     discover → confirm → port → reproduce loop end-to-end against a
//     target kernel tree without writing TypeScript.
//
// The two subcommands share nothing at runtime today; they're grouped
// under the same parent so the user-facing surface (`pwnkit cve …`)
// stays coherent.
//
// Exit codes:
//
//   `cve find`:
//     0 — ok (artifacts found and printed)
//     1 — user / input error (bad CVE id, malformed flag)
//     2 — no artifacts at all (every source returned empty/miss)
//     3 — network / source error (every source failed)
//
//   `cve adapt` (issue spec):
//     0 — confirmed
//     1 — unreproduced
//     2 — no_artifact
//     3 — budget_exhausted
//     4 — setup error (bad flags, unreadable file, etc.)

import type { Command } from "commander";
import chalk from "chalk";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  findCveArtifacts,
  normaliseCveId,
  adaptAndVerify,
} from "@pwnkit/core";
import type {
  ScrapedCveArtifacts,
  AdaptationResult,
  AdaptationStatus,
  CveArtifactProvider,
  CveArtifacts,
} from "@pwnkit/core";

// ── `cve find` (scraper) ────────────────────────────────────────────

const VALID_FORMATS = ["json", "table"] as const;
type CveFindFormat = (typeof VALID_FORMATS)[number];

interface CveFindOpts {
  format?: string;
  cacheDir?: string;
  cache?: boolean;
  timeout?: string;
  retries?: string;
  skipGithubPocSearch?: boolean;
}

const EXIT_OK = 0;
const EXIT_USER_ERROR = 1;
const EXIT_NO_ARTIFACTS = 2;
const EXIT_NET = 3;

// ── `cve adapt` (adapt loop) ────────────────────────────────────────

export const CVE_EXIT_CODES: Record<AdaptationStatus | "setup_error", number> = {
  confirmed: 0,
  unreproduced: 1,
  no_artifact: 2,
  budget_exhausted: 3,
  setup_error: 4,
};

interface CveAdaptCliOpts {
  kernelTree: string;
  kernelConfig?: string;
  attempts?: string;
  wallClock?: string;
  artifacts?: string;
  format?: string;
}

/**
 * Parse "30m", "90s", "1500ms" into milliseconds. Bare numbers are ms.
 * Exposed for tests.
 */
export function parseDurationToMs(input: string): number {
  const trimmed = input.trim().toLowerCase();
  if (!trimmed) throw new Error("empty duration");
  const match = /^(\d+(?:\.\d+)?)(ms|s|m|h)?$/.exec(trimmed);
  if (!match) throw new Error(`invalid duration '${input}', expected e.g. '30m', '90s', '500ms'`);
  const value = parseFloat(match[1]);
  const unit = match[2] ?? "ms";
  const multiplier =
    unit === "ms" ? 1
      : unit === "s" ? 1_000
      : unit === "m" ? 60_000
      : 3_600_000;
  return Math.trunc(value * multiplier);
}

export function parseAttempts(input: string | undefined, fallback = 5): number {
  if (input === undefined) return fallback;
  const parsed = parseInt(input, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`invalid --attempts '${input}', expected positive integer`);
  }
  return parsed;
}

export function loadArtifactsFile(path: string): CveArtifacts {
  const abs = resolve(path);
  let raw: string;
  try {
    raw = readFileSync(abs, "utf-8");
  } catch (err) {
    throw new Error(`failed to read --artifacts ${abs}: ${err instanceof Error ? err.message : String(err)}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`failed to parse --artifacts as JSON (${abs}): ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!parsed || typeof parsed !== "object" || !("pocCandidates" in (parsed as object))) {
    throw new Error(`--artifacts JSON is missing required field 'pocCandidates'`);
  }
  return parsed as CveArtifacts;
}

export function renderAdaptTable(result: AdaptationResult): string {
  const lines: string[] = [];
  lines.push(chalk.bold(`CVE: ${result.cveId}`));
  lines.push(`Status: ${chalk.cyan(result.status)}`);
  if (result.signature) lines.push(`Signature: ${result.signature}`);
  if (result.final_poc_path) lines.push(`Final PoC: ${result.final_poc_path}`);
  lines.push(`Total: ${result.total_ms} ms — ${result.attempts.length} attempt(s)`);
  lines.push("");
  lines.push(chalk.bold("Attempts:"));
  for (const a of result.attempts) {
    const verdict = a.verification?.status ?? (a.error ? "fetch-error" : "n/a");
    lines.push(
      `  #${a.attemptIndex + 1}  candidate=${a.candidate.url}  ` +
        `lang=${a.candidate.language}  verdict=${verdict}` +
        (a.diffApplied ? "  [diff applied]" : "") +
        (a.error ? `  error=${a.error}` : ""),
    );
  }
  return lines.join("\n");
}

// Back-compat alias for the adapt-loop's renderTable name (used in tests).
export const renderTable = renderAdaptTable;

export interface RunCveAdaptArgs {
  cveId: string;
  opts: CveAdaptCliOpts;
  /**
   * Injection point for tests. In production the scraper provides
   * artifacts; today the CLI also accepts `--artifacts <path>` for
   * end-to-end runs without going through the network.
   */
  providerOverride?: CveArtifactProvider;
}

export interface CveAdaptOutcome {
  result: AdaptationResult;
  exitCode: number;
}

export async function runCveAdapt(args: RunCveAdaptArgs): Promise<CveAdaptOutcome> {
  const { cveId, opts } = args;
  if (!cveId) throw new Error("missing CVE id positional argument");
  if (!opts.kernelTree) throw new Error("missing required flag: --kernel-tree <path>");
  const attempts = parseAttempts(opts.attempts);
  const wallClockMs = opts.wallClock ? parseDurationToMs(opts.wallClock) : undefined;

  let provider: CveArtifactProvider;
  if (args.providerOverride) {
    provider = args.providerOverride;
  } else if (opts.artifacts) {
    const data = loadArtifactsFile(opts.artifacts);
    provider = async () => data;
  } else {
    throw new Error(
      "no artifact provider available. Pass --artifacts <path.json> until the scraper from feat/272-cve-artifact-scraper merges.",
    );
  }

  const result = await adaptAndVerify(cveId, {
    kernelTree: opts.kernelTree,
    kernelConfig: opts.kernelConfig,
    attempts,
    wallClockMs,
    artifactProvider: provider,
  });
  return { result, exitCode: CVE_EXIT_CODES[result.status] };
}

// ── Command registration ────────────────────────────────────────────

export function registerCveCommand(program: Command): void {
  const cve = program
    .command("cve")
    .description(
      "CVE workflows: artifact lookup (`find`) and autonomous PoC adaptation (`adapt`).",
    );

  cve
    .command("find")
    .description("Find public PoC + write-up artifacts for a CVE id")
    .argument("<cve-id>", "CVE identifier, e.g. CVE-2024-1086")
    .option("--format <fmt>", `Output format: ${VALID_FORMATS.join(" | ")}`, "json")
    .option("--cache-dir <path>", "Override cache directory (default ~/.pwnkit/cve-cache)")
    .option("--no-cache", "Bypass on-disk cache and re-fetch every source")
    .option("--timeout <ms>", "Per-source timeout in milliseconds", "10000")
    .option("--retries <n>", "Retry count per source on 5xx", "2")
    .option("--skip-github-poc-search", "Skip the GitHub repository / code search step")
    .action(async (rawCveId: string, opts: CveFindOpts) => {
      let cveId: string;
      try {
        cveId = normaliseCveId(rawCveId);
      } catch (err) {
        console.error(
          chalk.red(`Error: ${err instanceof Error ? err.message : String(err)}`),
        );
        process.exitCode = EXIT_USER_ERROR;
        return;
      }

      const format = (opts.format ?? "json") as CveFindFormat;
      if (!VALID_FORMATS.includes(format)) {
        console.error(
          chalk.red(
            `Error: invalid --format ${JSON.stringify(opts.format)}. Valid: ${VALID_FORMATS.join(", ")}`,
          ),
        );
        process.exitCode = EXIT_USER_ERROR;
        return;
      }

      const timeoutMs = parsePositiveInt(opts.timeout, "--timeout", 10_000);
      if (timeoutMs === null) return;
      const retries = parsePositiveInt(opts.retries, "--retries", 2, 10);
      if (retries === null) return;

      let result: ScrapedCveArtifacts;
      try {
        result = await findCveArtifacts(cveId, {
          cacheDir: opts.cacheDir,
          // Commander negates `--no-cache` into `opts.cache = false`.
          cache: opts.cache !== false,
          timeoutMs,
          retries,
          skipGithubPocSearch: opts.skipGithubPocSearch === true,
        });
      } catch (err) {
        console.error(
          chalk.red(
            `Error: ${err instanceof Error ? err.message : String(err)}`,
          ),
        );
        process.exitCode = EXIT_NET;
        return;
      }

      if (format === "json") {
        console.log(JSON.stringify(result, null, 2));
      } else {
        renderFindTable(result);
      }

      // Exit code policy:
      //   - any PoC OR any write-up OR any affected row → EXIT_OK
      //   - sources all reported error and nothing collected → EXIT_NET
      //   - sources reported only miss + nothing collected → EXIT_NO_ARTIFACTS
      const haveAnything =
        result.poc_urls.length > 0 ||
        result.writeup_urls.length > 0 ||
        result.affected.length > 0 ||
        !!result.description;
      if (haveAnything) {
        process.exitCode = EXIT_OK;
        return;
      }
      const allError = result.sources.every(
        (s) => s.status === "error" || s.status === "rate-limited",
      );
      process.exitCode = allError ? EXIT_NET : EXIT_NO_ARTIFACTS;
    });

  cve
    .command("adapt <cve-id>")
    .description("Adapt a public PoC for <cve-id> until it reproduces on the target kernel.")
    .requiredOption("--kernel-tree <path>", "Linux source tree to build against")
    .option("--kernel-config <profile>", "Kernel build profile (default: kasan)")
    .option("--attempts <n>", "Max verify-run attempts across all candidates", "5")
    .option("--wall-clock <duration>", "Total wall-clock budget (e.g. 30m, 90s, 500ms)", "30m")
    .option(
      "--artifacts <path>",
      "Path to a CveArtifacts JSON file (temporary; replaced by the scraper once it merges).",
    )
    .option("--format <fmt>", "Output format: json | table", "json")
    .action(async (cveId: string, opts: CveAdaptCliOpts) => {
      try {
        const outcome = await runCveAdapt({ cveId, opts });
        if ((opts.format ?? "json") === "table") {
          process.stdout.write(renderAdaptTable(outcome.result) + "\n");
        } else {
          process.stdout.write(JSON.stringify(outcome.result, null, 2) + "\n");
        }
        process.exitCode = outcome.exitCode;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        process.stderr.write(chalk.red(`error: ${message}\n`));
        process.exitCode = CVE_EXIT_CODES.setup_error;
      }
    });
}

function parsePositiveInt(
  input: string | undefined,
  flag: string,
  def: number,
  max?: number,
): number | null {
  if (input === undefined) return def;
  const n = Number.parseInt(input, 10);
  if (!Number.isFinite(n) || n < 0) {
    console.error(
      chalk.red(
        `Error: ${flag} must be a non-negative integer (got ${JSON.stringify(input)}).`,
      ),
    );
    process.exitCode = EXIT_USER_ERROR;
    return null;
  }
  if (max !== undefined && n > max) {
    console.error(
      chalk.red(`Error: ${flag} cannot exceed ${max} (got ${n}).`),
    );
    process.exitCode = EXIT_USER_ERROR;
    return null;
  }
  return n;
}

function renderFindTable(result: ScrapedCveArtifacts): void {
  console.log("");
  console.log(chalk.bold(result.cve_id));
  if (result.published) {
    console.log(chalk.gray(`  published: ${result.published}`));
  }
  if (result.description) {
    const wrapped = wrapText(result.description, 80);
    console.log("");
    console.log("  " + wrapped.split("\n").join("\n  "));
  }

  if (result.affected.length > 0) {
    console.log("");
    console.log(chalk.bold("  Affected versions"));
    for (const a of result.affected.slice(0, 12)) {
      const product = a.product ?? "?";
      const vendor = a.vendor ? `${a.vendor}/` : "";
      console.log(
        `    ${chalk.gray(a.source.padEnd(7))} ${vendor}${product} ${chalk.dim(a.range)}`,
      );
    }
    if (result.affected.length > 12) {
      console.log(chalk.dim(`    …and ${result.affected.length - 12} more`));
    }
  }

  if (result.poc_urls.length > 0) {
    console.log("");
    console.log(chalk.bold(`  PoC candidates (${result.poc_urls.length})`));
    for (const p of result.poc_urls.slice(0, 10)) {
      const stars = p.stars !== undefined ? ` ★${p.stars}` : "";
      const lang = p.language ? ` [${p.language}]` : "";
      const conf = `(${p.confidence.toFixed(2)})`;
      console.log(
        `    ${chalk.yellow(conf)} ${chalk.gray(p.source.padEnd(14))} ${p.url}${lang}${stars}`,
      );
    }
    if (result.poc_urls.length > 10) {
      console.log(chalk.dim(`    …and ${result.poc_urls.length - 10} more`));
    }
  } else {
    console.log("");
    console.log(chalk.gray("  No PoC candidates found."));
  }

  if (result.writeup_urls.length > 0) {
    console.log("");
    console.log(chalk.bold(`  Write-ups / advisories (${result.writeup_urls.length})`));
    for (const u of result.writeup_urls.slice(0, 10)) {
      console.log(`    ${u}`);
    }
    if (result.writeup_urls.length > 10) {
      console.log(chalk.dim(`    …and ${result.writeup_urls.length - 10} more`));
    }
  }

  console.log("");
  console.log(chalk.bold("  Sources"));
  for (const s of result.sources) {
    const colour =
      s.status === "ok" || s.status === "cached"
        ? chalk.green
        : s.status === "miss" || s.status === "skipped"
          ? chalk.gray
          : chalk.red;
    const detail = s.error ? ` — ${s.error}` : "";
    console.log(
      `    ${colour(s.status.padEnd(13))} ${chalk.gray(s.source.padEnd(15))} ${chalk.dim(`${s.durationMs}ms`)}${detail}`,
    );
  }
  console.log("");
}

function wrapText(input: string, width: number): string {
  const words = input.split(/\s+/);
  const lines: string[] = [];
  let line = "";
  for (const w of words) {
    if ((line + " " + w).length > width) {
      lines.push(line);
      line = w;
    } else {
      line = line ? `${line} ${w}` : w;
    }
  }
  if (line) lines.push(line);
  return lines.join("\n");
}

import type { Command } from "commander";
import chalk from "chalk";
import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import {
  buildEntraGraphFromAzureHound,
  runEntraPathAnalysis,
  type EntraPathAnalysis,
  type EntraPathFinding,
  type IdentitySeverity,
} from "@0sec/core";

const DEFAULT_TIMEOUT_MS = "120000";

const SEVERITY_ORDER: IdentitySeverity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_COLOR: Record<IdentitySeverity, (s: string) => string> = {
  critical: chalk.red.bold,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.cyan,
  info: chalk.dim,
};

interface EntraGraphOptions {
  input: string;
  json?: boolean;
  timeout?: string;
  maxDepth?: string;
  owned?: string;
}

export function registerEntraGraphCommand(program: Command): void {
  program
    .command("entragraph")
    .description(
      "Offline Microsoft Entra ID attack-path analysis over an AzureHound export already on disk — paths to Global Administrator, service-principal escalation, consent-grant abuse, owner chains, and guest escalation. Reads files only: never collects, never authenticates, never touches the network.",
    )
    .requiredOption(
      "--input <path>",
      "A single AzureHound JSON file, or a directory of AzureHound JSON files (non-recursive, *.json)",
    )
    .option("--json", "Emit the analysis as machine-readable JSON")
    .option("--timeout <ms>", "Wall-clock bound on ingest + analysis in milliseconds", DEFAULT_TIMEOUT_MS)
    .option("--max-depth <n>", "Hop ceiling for path traversal")
    .option(
      "--owned <ids>",
      "Comma-separated object ids already under operator control. These become the path sources; omit to treat every enabled non-privileged principal as a candidate.",
    )
    .action(async (opts: EntraGraphOptions) => {
      const input = opts.input?.trim();
      if (!input) {
        console.error(chalk.red("Invalid --input: expected a path to a file or directory."));
        process.exitCode = 2;
        return;
      }

      let timeout = Number(DEFAULT_TIMEOUT_MS);
      if (opts.timeout !== undefined) {
        const parsed = Number(opts.timeout);
        if (!Number.isFinite(parsed) || parsed <= 0) {
          console.error(chalk.red(`Invalid --timeout '${opts.timeout}': must be a positive number (ms).`));
          process.exitCode = 2;
          return;
        }
        timeout = parsed;
      }

      let maxDepth: number | undefined;
      if (opts.maxDepth !== undefined) {
        const parsed = Number(opts.maxDepth);
        if (!Number.isInteger(parsed) || parsed <= 0) {
          console.error(chalk.red(`Invalid --max-depth '${opts.maxDepth}': must be a positive integer.`));
          process.exitCode = 2;
          return;
        }
        maxDepth = parsed;
      }

      const owned = opts.owned
        ?.split(",")
        .map((s) => s.trim().toLowerCase())
        .filter((s) => s.length > 0);

      let timer: ReturnType<typeof setTimeout> | undefined;
      const deadline = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`Analysis exceeded --timeout ${timeout}ms.`)), timeout);
      });

      let analysis: EntraPathAnalysis;
      let warnings: string[];
      try {
        ({ analysis, warnings } = await Promise.race([analyze(input, { maxDepth, owned }), deadline]));
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exitCode = 2;
        return;
      } finally {
        if (timer) clearTimeout(timer);
      }

      if (opts.json) {
        console.log(JSON.stringify({ ...analysis, ingestWarnings: warnings }, null, 2));
        return;
      }

      renderEntraGraph(analysis, warnings);
    });
}

async function analyze(
  input: string,
  opts: { maxDepth?: number; owned?: string[] },
): Promise<{ analysis: EntraPathAnalysis; warnings: string[] }> {
  const files = await resolveInputFiles(input);

  const parsed: unknown[] = [];
  const parseErrors: string[] = [];
  for (const file of files) {
    let text: string;
    try {
      text = await readFile(file, "utf8");
    } catch (err) {
      parseErrors.push(`${file}: unreadable (${err instanceof Error ? err.message : String(err)})`);
      continue;
    }
    try {
      parsed.push(JSON.parse(text));
    } catch (err) {
      parseErrors.push(`${file}: invalid JSON (${err instanceof Error ? err.message : String(err)})`);
    }
  }

  if (parsed.length === 0) {
    throw new Error(
      `No usable AzureHound JSON in --input '${input}':\n${parseErrors.map((e) => `  - ${e}`).join("\n")}`,
    );
  }

  const { graph, ingest } = buildEntraGraphFromAzureHound(parsed);
  if (graph.nodes.size === 0) {
    throw new Error(
      `--input '${input}' parsed as JSON but contained no Entra objects. Expected AzureHound output ({data:[{kind,data}],meta:{type}}).`,
    );
  }

  const analysis = runEntraPathAnalysis(graph, {
    ...(opts.maxDepth !== undefined ? { maxDepth: opts.maxDepth } : {}),
    ...(opts.owned && opts.owned.length > 0 ? { ownedPrincipalIds: opts.owned } : {}),
  });

  return { analysis, warnings: [...parseErrors, ...ingest.warnings] };
}

async function resolveInputFiles(input: string): Promise<string[]> {
  let info: Awaited<ReturnType<typeof stat>>;
  try {
    info = await stat(input);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") throw new Error(`--input '${input}' does not exist.`);
    if (code === "EACCES") throw new Error(`--input '${input}' is not readable (permission denied).`);
    throw new Error(`--input '${input}' could not be read: ${err instanceof Error ? err.message : String(err)}`);
  }

  if (!info.isDirectory()) return [input];

  let entries: string[];
  try {
    entries = await readdir(input);
  } catch (err) {
    throw new Error(
      `--input directory '${input}' could not be listed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const files = entries
    .filter((name) => name.toLowerCase().endsWith(".json"))
    .sort()
    .map((name) => join(input, name));
  if (files.length === 0) {
    throw new Error(
      `--input directory '${input}' contains no *.json files. Point it at an unzipped AzureHound collection.`,
    );
  }
  return files;
}

function renderEntraGraph(analysis: EntraPathAnalysis, warnings: string[]): void {
  const { graph, summary, findings } = analysis;

  console.log("");
  console.log(chalk.bold(`Entra ID attack paths — tenant ${graph.tenantDisplayName ?? graph.tenantId}`));
  console.log(
    chalk.dim(
      `  ${graph.nodeCount} objects, ${graph.edgeCount} edges, from ${graph.origin} — ` +
        `${graph.counts.users} users, ${graph.counts.groups} groups, ` +
        `${graph.counts.servicePrincipals} service principals, ${graph.counts.roles} roles`,
    ),
  );

  // The single most important caveat in the whole report: an empty result on an
  // export that never collected relationships is a collection gap, not a clean
  // tenant, and saying so is the difference between a useful report and a
  // misleading one.
  if (!graph.relationshipsCollected) {
    console.log("");
    console.log(
      chalk.yellow(
        "  ! No membership or ownership data in this export. Paths that depend on it cannot be computed,\n" +
          "    and their absence is NOT evidence that none exist. Re-run AzureHound with those collections.",
      ),
    );
  }

  console.log("");
  if (findings.length === 0) {
    console.log(chalk.green("  No attack paths found with the current inputs."));
  } else {
    const counts = SEVERITY_ORDER.filter((s) => (summary.bySeverity[s] ?? 0) > 0)
      .map((s) => SEVERITY_COLOR[s](`${summary.bySeverity[s]} ${s}`))
      .join(chalk.dim(" · "));
    console.log(
      `  ${chalk.bold(String(summary.findingCount))} finding(s)  ${counts}` +
        chalk.dim(
          `  ·  ${summary.pathCount} path(s), ${summary.affectedPrincipalCount} principal(s)` +
            (summary.shortestPathLength !== undefined ? `, shortest ${summary.shortestPathLength} hop(s)` : ""),
        ),
    );
    console.log("");
    for (const f of findings) renderFinding(f);
  }

  if (warnings.length > 0) {
    console.log("");
    console.log(chalk.dim(`  Notes (${warnings.length}):`));
    for (const w of warnings) console.log(chalk.dim(`    - ${w}`));
  }
  console.log("");
}

function renderFinding(f: EntraPathFinding): void {
  const tag = SEVERITY_COLOR[f.severity](f.severity.toUpperCase().padEnd(8));
  console.log(`  ${tag} ${chalk.bold(f.title)}`);
  console.log(chalk.dim(`           ${f.description}`));

  const shown = f.paths.slice(0, 3);
  for (const p of shown) {
    console.log(chalk.dim(`           ↳ ${p.length} hop(s): ${p.technique}`));
  }
  if (f.paths.length > shown.length) {
    console.log(chalk.dim(`           ↳ …and ${f.paths.length - shown.length} more path(s)`));
  }
  console.log("");
}

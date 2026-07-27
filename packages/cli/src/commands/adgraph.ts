import type { Command } from "commander";
import chalk from "chalk";
import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import {
  buildAdGraph,
  ingestBloodHoundFiles,
  runAdGraphAnalysis,
  type AdEdge,
  type AdFinding,
  type AdGraph,
  type AdGraphAnalysis,
  type AdNode,
  type AdSeverity,
} from "@pwnkit/core";

const DEFAULT_TIMEOUT_MS = "120000";

const SEVERITY_ORDER: AdSeverity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_COLOR: Record<AdSeverity, (s: string) => string> = {
  critical: chalk.red.bold,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.cyan,
  info: chalk.dim,
};

interface AdGraphOptions {
  input: string;
  json?: boolean;
  timeout?: string;
  domain?: string;
}

export function registerAdGraphCommand(program: Command): void {
  program
    .command("adgraph")
    .description(
      "Offline Active Directory attack-path analysis over BloodHound CE / SharpHound JSON already on disk — paths to Domain Admin, kerberoastable principals, unconstrained delegation, DCSync rights, ACL abuse chains, and ADCS escalation. Reads files only: never collects, never authenticates, never touches the network.",
    )
    .requiredOption(
      "--input <path>",
      "A single BloodHound CE JSON file, or a directory of collector JSON files (non-recursive, *.json)",
    )
    .option("--json", "Emit the analysis as machine-readable JSON")
    .option("--timeout <ms>", "Wall-clock bound on ingest + analysis in milliseconds", DEFAULT_TIMEOUT_MS)
    .option("--domain <fqdn>", "Restrict the analysis to objects belonging to this AD domain, e.g. corp.example.com")
    .action(async (opts: AdGraphOptions) => {
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

      let timer: ReturnType<typeof setTimeout> | undefined;
      const deadline = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`Analysis exceeded --timeout ${timeout}ms.`)), timeout);
      });

      let analysis: AdGraphAnalysis;
      let warnings: string[];
      try {
        ({ analysis, warnings } = await Promise.race([analyze(input, opts.domain), deadline]));
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exitCode = 2;
        return;
      } finally {
        if (timer) clearTimeout(timer);
      }

      if (opts.json) {
        console.log(JSON.stringify(analysis, null, 2));
        return;
      }

      renderAdGraph(analysis, warnings);
    });
}

/**
 * Read, ingest and analyze. Every failure mode here is an operator mistake with
 * a specific fix, so each throws its own message rather than bubbling a raw
 * ENOENT or `SyntaxError` up as a stack trace.
 */
async function analyze(
  input: string,
  domain: string | undefined,
): Promise<{ analysis: AdGraphAnalysis; warnings: string[] }> {
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

  // A single truncated file inside a collection is a warning; nothing readable
  // at all is a failed run.
  if (parsed.length === 0) {
    throw new Error(
      `No usable BloodHound JSON in --input '${input}':\n${parseErrors.map((e) => `  - ${e}`).join("\n")}`,
    );
  }

  let graph = ingestBloodHoundFiles(parsed);
  if (graph.nodes.size === 0) {
    throw new Error(
      `--input '${input}' parsed as JSON but contained no AD objects. Expected BloodHound CE collector output ({meta:{type},data:[...]}) or a graph export ({data:{nodes,edges}}).`,
    );
  }

  if (domain) {
    graph = filterGraphToDomain(graph, domain);
  }

  return { analysis: runAdGraphAnalysis(graph), warnings: parseErrors };
}

/** `--input` accepts one file or a flat directory of collector files. */
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
    throw new Error(`--input directory '${input}' could not be listed: ${err instanceof Error ? err.message : String(err)}`);
  }
  const files = entries
    .filter((name) => name.toLowerCase().endsWith(".json"))
    .sort()
    .map((name) => join(input, name));
  if (files.length === 0) {
    throw new Error(`--input directory '${input}' contains no *.json files. Point it at an unzipped BloodHound collection.`);
  }
  return files;
}

/**
 * Keep objects that belong to `fqdn`, plus objects that never declared a domain
 * at all — those are stubs synthesised from a reference (a group member, an ACE
 * principal) and dropping them would sever traversal mid-path. Objects that
 * explicitly name a *different* domain are the only ones removed.
 */
function filterGraphToDomain(graph: AdGraph, fqdn: string): AdGraph {
  const want = fqdn.trim().toUpperCase();
  const declaredDomains = new Set<string>();
  const kept: AdNode[] = [];
  let matched = 0;

  for (const node of graph.nodes.values()) {
    const raw = node.properties.domain;
    const declared = typeof raw === "string" && raw.trim().length > 0 ? raw.trim().toUpperCase() : undefined;
    if (declared) declaredDomains.add(declared);
    if (declared === undefined) {
      kept.push(node);
      continue;
    }
    if (declared === want) {
      kept.push(node);
      matched += 1;
    }
  }

  if (matched === 0) {
    const available = [...declaredDomains].sort();
    throw new Error(
      `No objects in the collection belong to --domain '${fqdn}'. ` +
        (available.length > 0
          ? `Domains present: ${available.join(", ")}.`
          : `The collection declares no domain on any object, so --domain cannot be applied.`),
    );
  }

  const keptIds = new Set(kept.map((node) => node.objectId));
  const edges: AdEdge[] = graph.edges.filter((edge) => keptIds.has(edge.source) && keptIds.has(edge.target));
  return buildAdGraph(kept, edges, {
    sourceTypes: graph.meta.sourceTypes,
    collectorVersion: graph.meta.collectorVersion,
    warnings: [...graph.meta.warnings, `filtered to domain ${want}: ${matched} object(s) matched`],
    ingestedAt: graph.meta.ingestedAt,
  });
}

function renderAdGraph(analysis: AdGraphAnalysis, readWarnings: string[]): void {
  const { graph, summary } = analysis;
  console.log(chalk.bold("adgraph"));
  console.log(`  graph: ${graph.nodeCount} nodes, ${graph.edgeCount} edges`);
  if (graph.sourceTypes.length > 0) console.log(`  sources: ${graph.sourceTypes.join(", ")}`);
  console.log(`  findings: ${summary.findingCount} (top severity ${summary.topSeverity})`);
  console.log(`  affected principals: ${summary.affectedPrincipalCount}`);
  console.log("");

  for (const warning of readWarnings) console.log(chalk.yellow(`  ! ${warning}`));
  if (readWarnings.length > 0) console.log("");

  const bySeverity: Record<string, AdFinding[]> = {};
  for (const finding of analysis.findings) (bySeverity[finding.severity] ??= []).push(finding);

  for (const severity of SEVERITY_ORDER) {
    const findings = bySeverity[severity];
    if (!findings?.length) continue;
    console.log(SEVERITY_COLOR[severity](chalk.bold(severity.toUpperCase())));
    for (const finding of findings) {
      console.log(`  ${chalk.bold(finding.title)} ${chalk.dim(`[${finding.analyzer}]`)}`);
      console.log(`    ${finding.description}`);
      const shortest = finding.paths[0];
      if (shortest) {
        console.log(
          chalk.dim(
            `    shortest path (${shortest.length} hop${shortest.length === 1 ? "" : "s"}): ${shortest.technique}`,
          ),
        );
      }
      if (finding.affectedPrincipals.length > 0) {
        console.log(chalk.dim(`    principals: ${finding.affectedPrincipals.length}`));
      }
      console.log(chalk.dim(`    fix: ${finding.remediation}`));
    }
    console.log("");
  }

  if (graph.warnings.length > 0) {
    console.log(chalk.yellow(`ingest warnings (${graph.warnings.length}):`));
    for (const warning of graph.warnings.slice(0, 20)) console.log(chalk.dim(`  - ${warning}`));
    if (graph.warnings.length > 20) console.log(chalk.dim(`  ... ${graph.warnings.length - 20} more`));
  }
}

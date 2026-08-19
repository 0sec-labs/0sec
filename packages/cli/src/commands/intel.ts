import type { Command } from "commander";
import chalk from "chalk";
import {
  buildIntelDossier,
  lookupCve,
  searchAdvisories,
  searchSimilar,
  searchTargetHistory,
  type IntelDossier,
  type IntelTargetHistory,
  type VulnerabilityIntel,
} from "@pwnkit/core";

interface SearchOptions {
  ecosystem?: string;
  packageVersion?: string;
  ver?: string;
  json?: boolean;
  enrich?: boolean;
  offline?: boolean;
  cacheDir?: string;
}

interface CveOptions {
  json?: boolean;
  offline?: boolean;
  cacheDir?: string;
}

interface SimilarOptions {
  cwe?: string;
  ecosystem?: string;
  keywords?: string;
  limit?: string;
  json?: boolean;
  offline?: boolean;
  cacheDir?: string;
}

interface DossierOptions {
  ecosystem?: string;
  packageVersion?: string;
  ver?: string;
  keywords?: string;
  similarLimit?: string;
  json?: boolean;
  offline?: boolean;
  cacheDir?: string;
  similar?: boolean;
}

interface TargetHistoryOptions {
  repoPath?: string;
  repository?: string;
  ecosystem?: string;
  package?: string;
  product?: string;
  vendor?: string;
  keywords?: string;
  limit?: string;
  json?: boolean;
  offline?: boolean;
  cacheDir?: string;
}

export function registerIntelCommand(program: Command): void {
  const intel = program
    .command("intel")
    .description("Live vulnerability intelligence lookup helpers");

  intel
    .command("dossier")
    .description("Build a package-level intel dossier with risk summary, prior-vuln playbooks, and variant leads")
    .argument("<package>", "Package name")
    .option("--ecosystem <ecosystem>", "Package ecosystem: npm, pypi, cargo, Go, Maven", "npm")
    .option("--package-version <version>", "Resolved package version")
    .option("--ver <version>", "Alias for --package-version")
    .option("--keywords <list>", "Comma-separated variant-hunt keywords")
    .option("--similar-limit <n>", "Maximum similar advisory leads", "10")
    .option("--no-similar", "Skip similar-advisory search")
    .option("--offline", "Use cache only")
    .option("--cache-dir <path>", "Override intel cache directory")
    .option("--json", "Emit machine-readable JSON")
    .action(async (packageName: string, opts: DossierOptions) => {
      try {
        const dossier = await buildIntelDossier({
          ecosystem: opts.ecosystem ?? "npm",
          packageName,
          version: opts.packageVersion ?? opts.ver,
          keywords: opts.keywords?.split(",").map((item) => item.trim()).filter(Boolean),
          similarLimit: parseLimit(opts.similarLimit),
          includeSimilar: opts.similar === false ? false : true,
          offline: opts.offline,
          cacheDir: opts.cacheDir,
        });
        renderDossier(dossier, opts.json);
      } catch (err) {
        fail(err);
      }
    });

  intel
    .command("target-history")
    .description("Search prior CVEs/GHSAs already reported against this target, repo, package, or product")
    .argument("[target]", "Target URL/name or GitHub repository")
    .option("--repo-path <path>", "Infer target hints from a local repository/package path")
    .option("--repository <owner/repo-or-url>", "GitHub repository hint, e.g. expressjs/express")
    .option("--ecosystem <ecosystem>", "Optional package ecosystem: npm, pypi, cargo, Go, Maven")
    .option("--package <package>", "Optional package name")
    .option("--product <product>", "Optional product/project name")
    .option("--vendor <vendor>", "Optional vendor/organization name")
    .option("--keywords <list>", "Comma-separated target aliases or extra search terms")
    .option("--limit <n>", "Maximum results per live source query", "20")
    .option("--offline", "Use cache only")
    .option("--cache-dir <path>", "Override intel cache directory")
    .option("--json", "Emit machine-readable JSON")
    .action(async (target: string | undefined, opts: TargetHistoryOptions) => {
      try {
        const result = await searchTargetHistory({
          target,
          repoPath: opts.repoPath,
          repository: opts.repository,
          ecosystem: opts.ecosystem,
          packageName: opts.package,
          product: opts.product,
          vendor: opts.vendor,
          keywords: opts.keywords?.split(",").map((item) => item.trim()).filter(Boolean),
          limit: parseLimit(opts.limit),
          offline: opts.offline,
          cacheDir: opts.cacheDir,
        });
        renderTargetHistory(result, opts.json);
      } catch (err) {
        fail(err);
      }
    });

  intel
    .command("search")
    .description("Search advisories for a package/version")
    .argument("<package>", "Package name")
    .option("--ecosystem <ecosystem>", "Package ecosystem: npm, pypi, cargo, Go, Maven", "npm")
    .option("--package-version <version>", "Resolved package version")
    .option("--ver <version>", "Alias for --package-version")
    .option("--no-enrich", "Skip CVE enrichment via NVD/CISA KEV")
    .option("--offline", "Use cache only")
    .option("--cache-dir <path>", "Override intel cache directory")
    .option("--json", "Emit machine-readable JSON")
    .action(async (packageName: string, opts: SearchOptions) => {
      try {
        const result = await searchAdvisories({
          ecosystem: opts.ecosystem ?? "npm",
          packageName,
          version: opts.packageVersion ?? opts.ver,
          enrich: opts.enrich === false ? false : true,
          offline: opts.offline,
          cacheDir: opts.cacheDir,
        });
        renderIntelList(result.advisories, opts.json);
      } catch (err) {
        fail(err);
      }
    });

  intel
    .command("cve")
    .description("Look up a CVE from NVD and CISA KEV")
    .argument("<cve-id>", "CVE identifier, e.g. CVE-2024-1086")
    .option("--offline", "Use cache only")
    .option("--cache-dir <path>", "Override intel cache directory")
    .option("--json", "Emit machine-readable JSON")
    .action(async (cveId: string, opts: CveOptions) => {
      try {
        const result = await lookupCve({
          cveId,
          offline: opts.offline,
          cacheDir: opts.cacheDir,
        });
        if (opts.json) {
          console.log(JSON.stringify(result, null, 2));
          return;
        }
        if (!result) {
          console.log(chalk.yellow(`No CVE intel found for ${cveId.toUpperCase()}`));
          return;
        }
        renderIntelList([result], false);
      } catch (err) {
        fail(err);
      }
    });

  intel
    .command("similar")
    .description("Search related CVEs/advisories by CWE and keywords")
    .option("--cwe <cwe>", "CWE id, e.g. CWE-22")
    .option("--ecosystem <ecosystem>", "Optional ecosystem hint")
    .option("--keywords <list>", "Comma-separated keywords")
    .option("--limit <n>", "Maximum results", "10")
    .option("--offline", "Use cache only")
    .option("--cache-dir <path>", "Override intel cache directory")
    .option("--json", "Emit machine-readable JSON")
    .action(async (opts: SimilarOptions) => {
      try {
        const limit = parseLimit(opts.limit);
        const keywords = opts.keywords?.split(",").map((item) => item.trim()).filter(Boolean);
        const result = await searchSimilar({
          cwe: opts.cwe,
          ecosystem: opts.ecosystem,
          keywords,
          limit,
          offline: opts.offline,
          cacheDir: opts.cacheDir,
        });
        renderIntelList(result.advisories, opts.json);
      } catch (err) {
        fail(err);
      }
    });
}

function renderTargetHistory(history: IntelTargetHistory, json?: boolean): void {
  if (json) {
    console.log(JSON.stringify(history, null, 2));
    return;
  }
  const label = history.target.repository
    ?? history.target.packageName
    ?? history.target.product
    ?? history.target.target
    ?? "target";
  console.log(chalk.bold(`prior vulnerability history: ${label}`));
  console.log(`  advisories: ${history.summary.advisoryCount} (${history.summary.criticalCount} critical, ${history.summary.highCount} high, ${history.summary.kevCount} KEV)`);
  console.log(`  playbooks: ${history.summary.playbookCount}`);
  console.log(`  audit graph: ${history.auditGraph.nodes.length} nodes, ${history.auditGraph.edges.length} edges`);
  if (history.summary.matchedHints.length > 0) console.log(`  matched hints: ${history.summary.matchedHints.join(", ")}`);
  if (history.advisories.length > 0) {
    console.log("");
    console.log(chalk.bold("Previously reported advisories"));
    renderIntelList(history.advisories.slice(0, 8), false);
  }
  if (history.playbooks.length > 0) {
    console.log(chalk.bold("Target-history playbooks"));
    for (const playbook of history.playbooks.slice(0, 4)) {
      console.log(`${playbook.bugClass} ${playbook.cwes.join(", ")}`);
      console.log(chalk.dim(`  prior: ${playbook.priorVulnerabilityIds.slice(0, 6).join(", ")}`));
      for (const step of playbook.steps.slice(0, 3)) {
        console.log(`  - ${step.title}`);
      }
    }
  }
}

function renderDossier(dossier: IntelDossier, json?: boolean): void {
  if (json) {
    console.log(JSON.stringify(dossier, null, 2));
    return;
  }
  console.log(`${chalk.bold(`${dossier.package.ecosystem}:${dossier.package.name}`)}${dossier.version ? `@${dossier.version}` : ""}`);
  console.log(`  risk: ${riskBadge(dossier.summary.riskLevel)} score=${dossier.summary.riskScore}`);
  console.log(`  advisories: ${dossier.summary.advisoryCount} (${dossier.summary.criticalCount} critical, ${dossier.summary.highCount} high, ${dossier.summary.kevCount} KEV)`);
  console.log(`  variant leads: ${dossier.summary.variantLeadCount}`);
  console.log(`  playbooks: ${dossier.summary.playbookCount}`);
  console.log(`  audit graph: ${dossier.auditGraph.nodes.length} nodes, ${dossier.auditGraph.edges.length} edges`);
  if (dossier.summary.recommendedFocus.length > 0) {
    console.log(`  focus: ${dossier.summary.recommendedFocus.join(", ")}`);
  }
  if (dossier.advisories.length > 0) {
    console.log("");
    console.log(chalk.bold("Top advisories"));
    renderIntelList(dossier.advisories.slice(0, 5), false);
  }
  if (dossier.variantLeads.length > 0) {
    console.log(chalk.bold("Variant leads"));
    for (const lead of dossier.variantLeads.slice(0, 5)) {
      console.log(`${lead.id} ${severityBadge(lead.severity)} ${lead.cwes.join(", ")}`);
      if (lead.summary) console.log(`  ${lead.summary}`);
      console.log(chalk.dim(`  ${lead.reason}`));
    }
  }
  if (dossier.playbooks.length > 0) {
    console.log(chalk.bold("Prior-vulnerability playbooks"));
    for (const playbook of dossier.playbooks.slice(0, 3)) {
      console.log(`${playbook.bugClass} ${playbook.cwes.join(", ")}`);
      console.log(chalk.dim(`  prior: ${playbook.priorVulnerabilityIds.slice(0, 5).join(", ")}`));
      for (const step of playbook.steps.slice(0, 3)) {
        console.log(`  - ${step.title}`);
      }
    }
  }
}

function renderIntelList(items: VulnerabilityIntel[], json?: boolean): void {
  if (json) {
    console.log(JSON.stringify(items, null, 2));
    return;
  }
  if (items.length === 0) {
    console.log(chalk.dim("No vulnerability intel found."));
    return;
  }
  for (const item of items) {
    const kev = item.kev?.knownExploited ? chalk.red(" KEV") : "";
    console.log(`${chalk.bold(item.id)} ${severityBadge(item.severity)}${kev}`);
    if (item.summary) console.log(`  ${item.summary}`);
    if (item.aliases.length > 1) console.log(`  aliases: ${item.aliases.join(", ")}`);
    if (item.package) console.log(`  package: ${item.package.ecosystem}:${item.package.name}`);
    if (item.affectedRanges.length > 0) console.log(`  affected: ${item.affectedRanges.slice(0, 3).join(" | ")}`);
    if (item.fixedVersions.length > 0) console.log(`  fixed: ${item.fixedVersions.join(", ")}`);
    if (item.cwes.length > 0) console.log(`  cwe: ${item.cwes.join(", ")}`);
    if (item.cvss?.score !== undefined) console.log(`  cvss: ${item.cvss.score}${item.cvss.vector ? ` ${item.cvss.vector}` : ""}`);
    if (item.references.length > 0) console.log(`  ref: ${item.references[0]!.url}`);
    console.log(chalk.dim(`  sources: ${item.sources.join(", ")} fetched_at=${item.fetchedAt}`));
    console.log("");
  }
}

function severityBadge(severity: string): string {
  if (severity === "critical") return chalk.bgRed.white(" critical ");
  if (severity === "high") return chalk.red("high");
  if (severity === "medium") return chalk.yellow("medium");
  if (severity === "low") return chalk.blue("low");
  return chalk.dim("info");
}

function riskBadge(risk: IntelDossier["summary"]["riskLevel"]): string {
  if (risk === "critical") return chalk.bgRed.white(" critical ");
  if (risk === "high") return chalk.red("high");
  if (risk === "medium") return chalk.yellow("medium");
  if (risk === "low") return chalk.blue("low");
  return chalk.dim("none");
}

function parseLimit(input: string | undefined): number {
  const parsed = Number.parseInt(input ?? "10", 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`invalid --limit: ${input}`);
  }
  return Math.min(parsed, 50);
}

function fail(err: unknown): void {
  console.error(chalk.red(err instanceof Error ? err.message : String(err)));
  process.exitCode = 1;
}

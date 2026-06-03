import type { Command } from "commander";
import chalk from "chalk";
import { runRecon, type ReconAsset, type ReconResult } from "@pwnkit/core";

interface ReconOptions {
  json?: boolean;
  timeout?: string;
}

export function registerReconCommand(program: Command): void {
  program
    .command("recon")
    .description(
      "Enumerate a domain's attack surface — subdomains (stubbed), endpoints, OpenAPI/Swagger docs, and MCP servers — and emit a deduped asset inventory consumable as discovered_assets. Partial #769.",
    )
    .argument("<domain>", "Target domain or origin, e.g. example.com or https://api.example.com")
    .option("--json", "Emit the asset inventory as machine-readable JSON")
    .option("--timeout <ms>", "Per-request probe timeout in milliseconds", "10000")
    .action(async (domain: string, opts: ReconOptions) => {
      let timeout = 10_000;
      if (opts.timeout !== undefined) {
        const parsed = Number(opts.timeout);
        if (!Number.isFinite(parsed) || parsed <= 0) {
          console.error(chalk.red(`Invalid --timeout '${opts.timeout}': must be a positive number (ms).`));
          process.exit(2);
        }
        timeout = parsed;
      }

      let result: ReconResult;
      try {
        result = await runRecon(domain, { timeout });
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exit(2);
        return;
      }

      if (opts.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      renderRecon(result);
    });
}

function renderRecon(result: ReconResult): void {
  console.log(chalk.bold(`recon: ${result.domain}`));
  console.log(`  assets: ${result.summary.total}`);
  for (const [kind, count] of Object.entries(result.summary.byKind)) {
    console.log(`    ${kind}: ${count}`);
  }
  console.log("");

  const groups: Record<string, ReconAsset[]> = {};
  for (const asset of result.assets) {
    (groups[asset.kind] ??= []).push(asset);
  }
  for (const [kind, assets] of Object.entries(groups)) {
    console.log(chalk.bold(kind));
    for (const asset of assets) {
      const meta = asset.metadata
        ? chalk.dim(
            ` (${Object.entries(asset.metadata)
              .map(([k, v]) => `${k}=${v}`)
              .join(", ")})`,
          )
        : "";
      console.log(`  ${asset.value}${meta}`);
    }
    console.log("");
  }

  if (result.warnings.length > 0) {
    console.log(chalk.yellow(`warnings (${result.warnings.length}):`));
    for (const w of result.warnings) console.log(chalk.dim(`  - ${w}`));
  }
}

import type { Command } from "commander";
import chalk from "chalk";
import { runRecon, ScopePolicy, type ReconAsset, type ReconResult } from "@0sec/core";

interface ReconOptions {
  json?: boolean;
  timeout?: string;
  active?: boolean;
  scope?: string;
}

export function registerReconCommand(program: Command): void {
  program
    .command("recon")
    .description(
      "Enumerate a domain's attack surface — subdomains (passive CT/DNS, plus active DNS brute-force with --active), endpoints, OpenAPI/Swagger docs, and MCP servers — and emit a deduped asset inventory consumable as discovered_assets. Partial #769.",
    )
    .argument("<domain>", "Target domain or origin, e.g. example.com or https://api.example.com")
    .option("--json", "Emit the asset inventory as machine-readable JSON")
    .option("--timeout <ms>", "Per-request probe timeout in milliseconds", "10000")
    .option(
      "--active",
      "Enable active subdomain enumeration (DNS brute-force). Touches the target's DNS, so it is deny-by-default: REQUIRES --scope <file> authorizing the targets.",
    )
    .option(
      "--scope <file>",
      "Path to a JSON scope file ({in_scope, out_of_scope}). Required for --active; every candidate host is checked against it before any DNS query.",
    )
    .action(async (domain: string, opts: ReconOptions) => {
      let timeout = 10_000;
      if (opts.timeout !== undefined) {
        const parsed = Number(opts.timeout);
        if (!Number.isFinite(parsed) || parsed <= 0) {
          console.error(chalk.red(`Invalid --timeout '${opts.timeout}': must be a positive number (ms).`));
          process.exitCode = 2;
          return;
        }
        timeout = parsed;
      }

      // Deny-by-default: active subdomain enumeration touches the target's DNS,
      // so the library gates it behind a ScopePolicy and resolves nothing
      // without one. Refuse at the CLI with a clear message rather than
      // silently no-op'ing, so the operator knows why nothing was enumerated.
      let scope: ScopePolicy | undefined;
      if (opts.scope) {
        try {
          scope = ScopePolicy.fromJsonFile(opts.scope);
        } catch (err) {
          console.error(chalk.red(`Failed to load --scope '${opts.scope}': ${err instanceof Error ? err.message : String(err)}`));
          process.exitCode = 2;
          return;
        }
      }
      if (opts.active && !scope) {
        console.error(
          chalk.red(
            "--active requires --scope <file>: active subdomain enumeration is deny-by-default (it issues DNS queries against the target). Pass an authorized scope file.",
          ),
        );
        process.exitCode = 2;
        return;
      }

      let result: ReconResult;
      try {
        result = await runRecon(domain, {
          timeout,
          ...(opts.active && scope ? { activeSubdomains: { enabled: true, scope } } : {}),
        });
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exitCode = 2;
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

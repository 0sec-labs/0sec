import type { Command } from "commander";
import type { ScanDepth, OutputFormat, RuntimeMode } from "@0sec/shared";
import { runUnified } from "./run.js";

const SUPPORTED_AUDIT_ECOSYSTEMS = new Set(["npm", "pypi", "cargo", "oci"]);

export function registerAuditCommand(program: Command): void {
  program
    .command("audit")
    .description("Audit a package for security vulnerabilities")
    .argument("<package>", "package name (e.g. lodash, express, requests)")
    .option("--ecosystem <ecosystem>", "Package ecosystem: npm, pypi, cargo, oci", "npm")
    // `--package-version` rather than `--version` because Commander reserves
    // `-V, --version` as the global "show CLI version" flag — if we declare
    // `--version <ver>` here, Commander's root parser eats `--version` first
    // and prints the CLI version instead of routing it into the audit
    // subcommand. Aliasing a less-conflicting name (with `--pkg-version` and
    // `--ver` shortcuts) avoids the collision.
    .option(
      "--package-version <version>",
      "Specific package version to audit (default: latest)",
    )
    .option("--pkg-version <version>", "Alias for --package-version")
    .option("--ver <version>", "Alias for --package-version")
    .option("--depth <depth>", "Audit depth: quick, default, deep", "default")
    .option("--format <format>", "Output format: terminal, json, md, html, sarif, pdf", "terminal")
    .option("--runtime <runtime>", "Runtime: auto, claude, codex, gemini, api", "auto")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--api-key <key>", "API key for LLM provider")
    .option("--model <model>", "LLM model to use")
    .option("--cost-ceiling <usd>", "Hard per-audit USD cost ceiling. Aborts cleanly with partial findings if exceeded.")
    .option("--tui", "Open the local terminal UI after the audit completes", false)
    .option("--resume <run-id>", "Resume a previous run from its journal on disk (0sec#374)")
    .option("--branch-from <entry-index>", "Branch the journal at the given entry index before resuming (requires --resume).")
    .option("--verbose", "Show detailed output", false)
    .option("--timeout <ms>", "AI agent timeout in milliseconds", "600000")
    .action(async (packageName: string, opts: Record<string, string | boolean>) => {
      const ecosystem = ((opts.ecosystem as string | undefined) ?? "npm").trim().toLowerCase();
      if (
        !SUPPORTED_AUDIT_ECOSYSTEMS.has(ecosystem)
      ) {
        throw new Error(`Unsupported ecosystem '${ecosystem}'. Valid: npm, pypi, cargo, oci.`);
      }
      let costCeilingUsd: number | undefined;
      const ceilingSource =
        (opts.costCeiling as string | undefined) ?? process.env["0SEC_COST_CEILING_USD"];
      if (ceilingSource !== undefined && ceilingSource !== "") {
        const parsed = Number(ceilingSource);
        if (!Number.isFinite(parsed) || parsed <= 0) {
          throw new Error(`Invalid cost ceiling '${ceilingSource}': must be a positive number (USD).`);
        }
        costCeilingUsd = parsed;
      }
      await runUnified({
        target: packageName,
        targetType:
          ecosystem === "pypi"
            ? "pypi-package"
            : ecosystem === "cargo"
              ? "cargo-package"
              : ecosystem === "oci"
                ? "oci-image"
                : "npm-package",
        resumeScanId: opts.resume as string | undefined,
        branchFromEntry: opts.branchFrom !== undefined ? parseInt(opts.branchFrom as string, 10) : undefined,
        depth: (opts.depth as ScanDepth) ?? "default",
        format: (opts.format === "md" ? "markdown" : opts.format) as OutputFormat,
        runtime: (opts.runtime as RuntimeMode) ?? "auto",
        timeout: parseInt(opts.timeout as string, 10),
        verbose: opts.verbose as boolean,
        dbPath: opts.dbPath as string | undefined,
        apiKey: opts.apiKey as string | undefined,
        model: opts.model as string | undefined,
        // Read in priority: --package-version, --pkg-version, --ver.
        packageVersion:
          (opts.packageVersion as string | undefined) ??
          (opts.pkgVersion as string | undefined) ??
          (opts.ver as string | undefined),
        costCeilingUsd,
        tui: opts.tui as boolean,
      });
    });
}

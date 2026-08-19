import type { Command } from "commander";
import chalk from "chalk";
import type { OutputFormat, RuntimeMode, ScanDepth, ScanMode } from "@pwnkit/shared";
import { pwnkitDB } from "@pwnkit/db";
import { runUnified } from "./run.js";

function parseScanTarget(target: string): {
  target: string;
  targetType: "npm-package" | "source-code" | "url" | "web-app";
  packageVersion?: string;
  mode?: ScanMode;
  sourceDescription: string;
} {
  if (target.startsWith("http://") || target.startsWith("https://")) {
    return {
      target,
      targetType: "url",
      sourceDescription: "url",
    };
  }

  if (target.startsWith("web:")) {
    return {
      target: target.slice("web:".length),
      targetType: "web-app",
      mode: "web",
      sourceDescription: "web-app",
    };
  }
  if (target.startsWith("mcp://")) {
    return {
      target,
      targetType: "url",
      mode: "mcp",
      sourceDescription: "mcp target",
    };
  }
  if (target.startsWith("scan:")) {
    return {
      target: target.slice("scan:".length),
      targetType: "url",
      sourceDescription: "url",
    };
  }
  if (target.startsWith("repo:")) {
    return {
      target: target.slice("repo:".length),
      targetType: "source-code",
      sourceDescription: "repository",
    };
  }

  if (target.startsWith("npm:")) {
    const spec = target.slice("npm:".length);
    const atIndex = spec.lastIndexOf("@");
    if (atIndex > 0) {
      return {
        target: spec.slice(0, atIndex),
        targetType: "npm-package",
        packageVersion: spec.slice(atIndex + 1),
        sourceDescription: "npm package",
      };
    }

    return {
      target: spec,
      targetType: "npm-package",
      sourceDescription: "npm package",
    };
  }

  throw new Error(
    `Resume does not know how to route this persisted target yet: ${target}`,
  );
}

export function registerResumeCommand(program: Command): void {
  program
    .command("resume")
    .description("Resume a previous scan from persisted state")
    .argument("<scanId>", "Scan ID to resume")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--format <format>", "Output format override: terminal, json, md, html, sarif, pdf")
    .option("--runtime <runtime>", "Runtime override: auto, claude, codex, gemini, api")
    .option("--timeout <ms>", "AI agent timeout override in milliseconds")
    .option("--api-key <key>", "API key for LLM provider")
    .option("--model <model>", "LLM model to use")
    .option("--branch-from <entry-index>", "Branch the journal at the given entry index before resuming. Copies entries 0..N into a new run and resumes from there.")
    .action(async (scanId: string, opts: Record<string, string | boolean>) => {
      let scan: ReturnType<pwnkitDB["getScan"]> | null = null;
      try {
        const db = new pwnkitDB(opts.dbPath as string | undefined);
        scan =
          db.getScan(scanId) ??
          (() => {
            const matches = db.listScans(200).filter((entry) => entry.id.startsWith(scanId));
            if (matches.length === 1) return matches[0];
            if (matches.length > 1) {
              throw new Error(`Scan prefix '${scanId}' is ambiguous.`);
            }
            return null;
          })();
        db.close();
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exit(2);
      }

      if (!scan) {
        console.error(chalk.red(`Scan ${scanId} not found.`));
        process.exit(2);
      }

      const parsed = parseScanTarget(scan.target);
      const inferredTargetType =
        scan.mode === "web"
          ? "web-app"
          : parsed.targetType;
      const inferredMode =
        parsed.mode
        ?? ((scan.mode as ScanMode | undefined) ?? (inferredTargetType === "web-app" ? "web" : "deep"));

      const branchFrom = opts.branchFrom as string | undefined;
      await runUnified({
        target: parsed.target,
        targetType: inferredTargetType,
        resumeScanId: scanId,
        branchFromEntry: branchFrom !== undefined ? parseInt(branchFrom, 10) : undefined,
        packageVersion: parsed.packageVersion,
        depth: scan.depth as ScanDepth,
        format: ((opts.format as string | undefined) === "md" ? "markdown" : (opts.format as OutputFormat | undefined)) ?? "terminal",
        runtime: (opts.runtime as RuntimeMode | undefined) ?? (scan.runtime as RuntimeMode) ?? "auto",
        mode: inferredMode,
        timeout: parseInt((opts.timeout as string | undefined) ?? "600000", 10),
        verbose: false,
        dbPath: opts.dbPath as string | undefined,
        apiKey: opts.apiKey as string | undefined,
        model: opts.model as string | undefined,
      });
    });
}

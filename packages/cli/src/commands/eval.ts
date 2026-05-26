import { readFileSync, existsSync } from "node:fs";
import type { Command } from "commander";
import chalk from "chalk";
import type { AuthConfig, OutputFormat } from "@pwnkit/shared";
import { runEval, getEvalCategories } from "@pwnkit/core";
import type { EvalScorecard, EvalCategoryResult, EvalVerdict } from "@pwnkit/core";

/**
 * Parse the --auth flag value into an AuthConfig object.
 * (Same logic as scan command.)
 */
function parseAuthFlag(value: string): AuthConfig {
  let raw: string;
  if (!value.trimStart().startsWith("{") && existsSync(value)) {
    raw = readFileSync(value, "utf-8");
  } else {
    raw = value;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(
      `Invalid --auth value: must be a JSON string or path to a JSON file.`,
    );
  }

  const obj = parsed as Record<string, unknown>;
  const validTypes = new Set(["bearer", "cookie", "basic", "header"]);
  if (!obj || typeof obj !== "object" || !validTypes.has(obj.type as string)) {
    throw new Error(
      `Invalid auth config: "type" must be one of: bearer, cookie, basic, header.`,
    );
  }

  return obj as unknown as AuthConfig;
}

// ── Terminal formatting ──

function verdictColor(v: EvalVerdict): (s: string) => string {
  if (v === "fail") return chalk.red;
  if (v === "pass") return chalk.green;
  return chalk.yellow;
}

function verdictIcon(v: EvalVerdict): string {
  if (v === "fail") return chalk.red("FAIL");
  if (v === "pass") return chalk.green("PASS");
  return chalk.yellow("ERR ");
}

function formatTerminalScorecard(scorecard: EvalScorecard): string {
  const lines: string[] = [];

  lines.push("");
  lines.push(chalk.red.bold("  pwnkit adversarial eval"));
  lines.push(chalk.dim(`  target: ${scorecard.target}`));
  lines.push(chalk.dim(`  duration: ${(scorecard.durationMs / 1000).toFixed(1)}s`));
  lines.push("");

  // Category results table
  lines.push("  " + chalk.bold("Category".padEnd(30)) + chalk.bold("Result".padEnd(8)) + chalk.bold("Turns".padEnd(8)) + chalk.bold("Time".padEnd(10)) + chalk.bold("Details"));
  lines.push("  " + "─".repeat(90));

  for (const cat of scorecard.categories) {
    const icon = verdictIcon(cat.verdict);
    const turns = String(cat.turnCount).padEnd(8);
    const time = `${(cat.durationMs / 1000).toFixed(1)}s`.padEnd(10);
    const name = cat.categoryName.padEnd(30);
    const reason = cat.reason.length > 40 ? cat.reason.slice(0, 37) + "..." : cat.reason;
    lines.push(`  ${name}${icon}    ${turns}${time}${chalk.dim(reason)}`);
  }

  lines.push("  " + "─".repeat(90));
  lines.push("");

  // Summary
  const { passed, failed, errored, total, score } = scorecard.summary;
  const pct = total > 0 ? ((passed / total) * 100).toFixed(0) : "0";
  const color = failed > 0 ? chalk.red : chalk.green;

  lines.push(`  ${chalk.bold("Score:")} ${color.bold(`${score} categories passed`)} (${pct}%)`);
  if (failed > 0) {
    lines.push(`  ${chalk.red(`${failed} failed`)} — target is vulnerable to these attack categories`);
  }
  if (errored > 0) {
    lines.push(`  ${chalk.yellow(`${errored} errored`)} — could not evaluate`);
  }
  if (passed === total) {
    lines.push(`  ${chalk.green("All categories passed")} — target resisted all probes`);
  }

  // Finding summary
  const allFindings = scorecard.categories.flatMap((c) => c.findings);
  if (allFindings.length > 0) {
    lines.push("");
    lines.push(`  ${chalk.bold("Findings:")} ${allFindings.length} total`);
    const bySev: Record<string, number> = {};
    for (const f of allFindings) {
      bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;
    }
    const sevOrder = ["critical", "high", "medium", "low", "info"];
    const sevColors: Record<string, (s: string) => string> = {
      critical: chalk.red.bold,
      high: chalk.red,
      medium: chalk.yellow,
      low: chalk.blue,
      info: chalk.dim,
    };
    for (const sev of sevOrder) {
      if (bySev[sev]) {
        lines.push(`    ${sevColors[sev]?.(sev) ?? sev}: ${bySev[sev]}`);
      }
    }
  }

  lines.push("");
  return lines.join("\n");
}

// ── Command registration ──

export function registerEvalCommand(program: Command): void {
  program
    .command("eval")
    .description("Run adversarial safety eval against an AI/LLM endpoint and produce a scorecard")
    .requiredOption("--target <url>", "Target AI/LLM endpoint URL")
    .option("--format <format>", "Output format: terminal, json", "terminal")
    .option("--timeout <ms>", "Request timeout in milliseconds", "30000")
    .option("--api-key <key>", "API key for LLM provider")
    .option("--model <model>", "LLM model to use for evaluation")
    .option("--auth <json>", "Auth credentials for the target (JSON string or path)")
    .option(
      "--categories <list>",
      "Comma-separated category IDs to run (default: all). Use --list-categories to see available.",
    )
    .option("--list-categories", "List available eval categories and exit", false)
    .option("--verbose", "Show detailed output", false)
    .action(async (opts) => {
      // ── List categories ──
      if (opts.listCategories) {
        const cats = getEvalCategories();
        console.log(chalk.bold("\nAvailable eval categories:\n"));
        for (const cat of cats) {
          console.log(`  ${chalk.cyan(cat.id.padEnd(28))} ${cat.name}`);
          console.log(`  ${"".padEnd(28)} ${chalk.dim(cat.description)}`);
          console.log(`  ${"".padEnd(28)} ${chalk.dim(`max turns: ${cat.maxTurns}`)}`);
          console.log("");
        }
        return;
      }

      // Parse --auth
      let authConfig: AuthConfig | undefined;
      if (opts.auth) {
        try {
          authConfig = parseAuthFlag(opts.auth as string);
        } catch (err) {
          console.error(chalk.red(err instanceof Error ? err.message : String(err)));
          process.exit(2);
        }
      }

      // Parse --categories
      let categoryFilter: string[] | undefined;
      if (opts.categories) {
        categoryFilter = String(opts.categories)
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
      }

      const format = opts.format as string;
      const isJson = format === "json";

      if (!isJson) {
        console.log("");
        console.log(chalk.red.bold("  pwnkit adversarial eval"));
        console.log(chalk.dim(`  target: ${opts.target}`));
        console.log(chalk.dim(`  categories: ${categoryFilter ? categoryFilter.join(", ") : "all"}`));
        console.log("");
      }

      try {
        const scorecard = await runEval({
          target: opts.target as string,
          auth: authConfig,
          apiKey: opts.apiKey as string | undefined,
          model: opts.model as string | undefined,
          timeout: parseInt(opts.timeout as string, 10),
          categories: categoryFilter,
          onEvent: isJson
            ? undefined
            : (event) => {
                if (event.message) {
                  console.log(chalk.dim(`  ${event.message}`));
                }
              },
        });

        if (isJson) {
          console.log(JSON.stringify(scorecard, null, 2));
        } else {
          console.log(formatTerminalScorecard(scorecard));
        }

        // Exit code: 1 if any category failed, 0 if all passed
        if (scorecard.summary.failed > 0) {
          process.exit(1);
        }
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exit(2);
      }
    });
}

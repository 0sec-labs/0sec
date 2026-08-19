import { createInterface } from "node:readline";
import { stdin, stdout } from "node:process";

import type { Command } from "commander";
import chalk from "chalk";
import {
  createConsoleRuntime,
  createConsoleSession,
  type ConsoleSession,
  type ToolCall,
  type ToolResult,
} from "@0sec/core";

interface ConsoleOptions {
  target?: string;
  model?: string;
  role?: string;
  maxToolCalls?: string;
  allowScanners?: boolean;
}

/**
 * `0sec console` — the unified interactive chat cockpit.
 *
 * A single conversational surface where the operator talks to the engine and it
 * can invoke every 0sec tool (recon, web pentest, source/package scan,
 * variant hunt, verify, patch-gen) in one place. Thin REPL over the engine-side
 * driver in `@0sec/core` (`createConsoleSession`) — the tool registry and LLM
 * runtime are the real ones the autonomous scanner uses; this command only owns
 * terminal I/O and rendering.
 */
export function registerConsoleCommand(program: Command): void {
  program
    .command("console")
    .description(
      "Interactive chat console — talk to the engine and drive the full tool registry (recon, web, source-scan, variant-hunt, verify, patch-gen) from one prompt.",
    )
    .option("--target <url>", "Engagement target the tools operate against (optional; can be named in-chat)")
    .option("--model <id>", "Override the LLM model id (else provider default)")
    .option("--role <role>", "Tool set to expose: audit|review|discovery|attack|verify (default audit = every tool)")
    .option("--max-tool-calls <n>", "Safety cap on tool-call rounds per operator message", "20")
    .option("--allow-scanners", "Expose generic-scanner tool wrappers (sqlmap/nikto/…); default off")
    .action(async (opts: ConsoleOptions) => {
      let maxToolIterations = 20;
      if (opts.maxToolCalls !== undefined) {
        const parsed = Number(opts.maxToolCalls);
        if (!Number.isFinite(parsed) || parsed <= 0) {
          console.error(chalk.red(`Invalid --max-tool-calls '${opts.maxToolCalls}': must be a positive number.`));
          process.exitCode = 2;
          return;
        }
        maxToolIterations = parsed;
      }

      const VALID_ROLES = ["discovery", "attack", "verify", "report", "audit", "review"] as const;
      type ConsoleRole = (typeof VALID_ROLES)[number];
      let role: ConsoleRole = "audit";
      if (opts.role !== undefined) {
        if (!VALID_ROLES.includes(opts.role as ConsoleRole)) {
          console.error(chalk.red(`Invalid --role '${opts.role}': expected one of ${VALID_ROLES.join(", ")}.`));
          process.exitCode = 2;
          return;
        }
        role = opts.role as ConsoleRole;
      }

      let session: ConsoleSession;
      try {
        const runtime = createConsoleRuntime({ model: opts.model });
        session = createConsoleSession({
          runtime,
          target: opts.target,
          role,
          maxToolIterations,
          allowScanners: opts.allowScanners,
        });
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        console.error(
          chalk.dim(
            "The console needs an LLM provider. Set ANTHROPIC_API_KEY (or another supported provider key) and retry.",
          ),
        );
        process.exitCode = 2;
        return;
      }

      printBanner(session, opts.target);

      const rl = createInterface({ input: stdin, output: stdout });
      const prompt = () => rl.setPrompt(chalk.bold.cyan("operator › "));
      prompt();
      rl.prompt();

      rl.on("line", async (line) => {
        const text = line.trim();
        if (text === "") {
          rl.prompt();
          return;
        }
        if (text === "/exit" || text === "/quit") {
          rl.close();
          return;
        }
        if (text === "/tools") {
          printTools(session);
          rl.prompt();
          return;
        }
        if (text === "/help") {
          printHelp();
          rl.prompt();
          return;
        }

        rl.pause();
        try {
          await runTurn(session, text);
        } catch (err) {
          console.error(chalk.red(`\nturn failed: ${err instanceof Error ? err.message : String(err)}`));
        }
        rl.resume();
        rl.prompt();
      });

      rl.on("close", async () => {
        await session.cleanup().catch(() => {});
        console.log(chalk.dim("\nconsole session ended."));
      });
    });
}

async function runTurn(session: ConsoleSession, text: string): Promise<void> {
  let streamedAny = false;
  process.stdout.write("\n" + chalk.bold.green("engine › "));

  const outcome = await session.send(text, {
    onAssistantDelta: (chunk) => {
      streamedAny = true;
      process.stdout.write(chunk);
    },
    onToolStart: (call: ToolCall) => {
      process.stdout.write("\n" + chalk.yellow(`  ⚙ ${call.name}`) + chalk.dim(` ${previewArgs(call.arguments)}`));
    },
    onToolResult: (_call: ToolCall, result: ToolResult) => {
      const mark = result.success ? chalk.green("✓") : chalk.red("✗");
      process.stdout.write(chalk.dim(` → ${mark} ${previewResult(result)}`));
    },
    onNotice: (msg) => {
      process.stdout.write("\n" + chalk.dim(`  (${msg})`));
    },
  });

  // If nothing streamed token-by-token (provider without delta support), print
  // the collected assistant text now.
  if (!streamedAny && outcome.assistantText) {
    process.stdout.write("\n" + outcome.assistantText);
  }

  const usage = outcome.usage;
  const footer = `${outcome.toolCalls.length} tool call${outcome.toolCalls.length === 1 ? "" : "s"} · ${usage.inputTokens}→${usage.outputTokens} tok`;
  process.stdout.write("\n" + chalk.dim(`  [${footer}]`) + "\n");

  if (outcome.stopReason === "error") {
    console.error(chalk.red(`\nengine error: ${outcome.error ?? "unknown"}`));
  }
}

function previewArgs(args: Record<string, unknown>): string {
  const json = JSON.stringify(args);
  return json.length > 120 ? json.slice(0, 117) + "…" : json;
}

function previewResult(result: ToolResult): string {
  const raw = result.success
    ? typeof result.output === "string"
      ? result.output
      : JSON.stringify(result.output)
    : result.error ?? "failed";
  const flat = raw.replace(/\s+/g, " ").trim();
  return flat.length > 100 ? flat.slice(0, 97) + "…" : flat;
}

function printBanner(session: ConsoleSession, target?: string): void {
  console.log("");
  console.log(chalk.bold("0sec console") + chalk.dim(" — interactive operator cockpit"));
  console.log(chalk.dim(`  session ${session.scanId}`));
  console.log(chalk.dim(`  ${session.tools.length} tools available${target ? ` · target ${target}` : " · no target set"}`));
  console.log(chalk.dim("  /tools list · /help commands · /exit quit"));
  console.log("");
}

function printTools(session: ConsoleSession): void {
  console.log(chalk.bold(`\n${session.tools.length} tools:`));
  for (const tool of session.tools) {
    console.log(`  ${chalk.cyan(tool.name)} ${chalk.dim("- " + firstSentence(tool.description))}`);
  }
  console.log("");
}

function printHelp(): void {
  console.log(chalk.bold("\nconsole commands:"));
  console.log(`  ${chalk.cyan("/tools")}  list available tools`);
  console.log(`  ${chalk.cyan("/help")}   show this help`);
  console.log(`  ${chalk.cyan("/exit")}   end the session`);
  console.log(chalk.dim("  anything else is sent to the engine as an operator message.\n"));
}

function firstSentence(text: string): string {
  const end = text.indexOf(". ");
  const s = end > 0 ? text.slice(0, end) : text;
  return s.length > 90 ? s.slice(0, 87) + "…" : s;
}

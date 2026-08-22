import { createInterface } from "node:readline";
import { stdin, stdout } from "node:process";

import type { Command } from "commander";
import chalk from "chalk";
import {
  createConsoleRuntime,
  createConsoleSession,
  loadScope,
} from "@0sec/core";
import type {
  ConsoleAutonomyMode,
  ConsoleSession,
  ToolCall,
  ToolResult,
} from "@0sec/core";
import { canUseOpenTui, isBunRuntime } from "../tui/runtime.js";
import {
  findCommand,
  getCommandByName,
  SLASH_COMMANDS,
} from "../tui/slash-commands.js";

interface ConsoleOptions {
  target?: string;
  scope?: string;
  model?: string;
  role?: string;
  autonomy?: string;
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
    .option("--scope <file>", "Initial authorization scope; required for the Node fallback (optional otherwise)")
    .option("--model <id>", "Override the LLM model id (else provider default)")
    .option("--role <role>", "Tool set to expose: audit|review|discovery|attack|verify (default audit = every tool)")
    .option("--autonomy <mode>", "Execution policy: standard|copilot|yolo|recon (default standard)", "standard")
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

      let autonomyMode: ConsoleAutonomyMode = "standard";
      if (opts.autonomy !== undefined) {
        if (opts.autonomy !== "standard" && opts.autonomy !== "copilot" && opts.autonomy !== "yolo" && opts.autonomy !== "recon") {
          console.error(chalk.red(`Invalid --autonomy '${opts.autonomy}': expected standard, copilot, yolo, or recon.`));
          process.exitCode = 2;
          return;
        }
        autonomyMode = opts.autonomy;
      }

      let scope;
      if (opts.scope) {
        try {
          scope = loadScope(opts.scope);
        } catch (err) {
          console.error(chalk.red(`Failed to load --scope '${opts.scope}': ${err instanceof Error ? err.message : String(err)}`));
          process.exitCode = 2;
          return;
        }
      }

      if (autonomyMode === "yolo" && !hasConfiguredScope(scope)) {
        console.error(chalk.red("YOLO mode requires --scope <file> with at least one in_scope entry."));
        process.exitCode = 2;
        return;
      }

      if (isBunRuntime() && canUseOpenTui()) {
        // `run.tsx` imports Bun-only OpenTUI dependencies, so Node must not
        // resolve it before falling back to the readline console.
        const { showOpenTuiConsole } = await import("../tui/run.js");
        await showOpenTuiConsole({
          target: opts.target,
          scope,
          model: opts.model,
          role,
          maxToolIterations,
          allowScanners: opts.allowScanners,
          autonomyMode,
        });
        return;
      }

      if (!scope) {
        console.error(chalk.red("0sec console under Node requires --scope <file>."));
        console.error(chalk.dim("The readline fallback cannot approve session-only scope extensions; use the Bun TUI for scope-on-demand."));
        process.exitCode = 2;
        return;
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
          scope,
          autonomyMode,
          // Readline has no approval surface, so session-only scope extensions are denied.
          requestScope: async () => null,
          approveTool: autonomyMode === "copilot" ? async () => false : undefined,
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

        const parsed = findCommand(text);

        // Non-slash input → normal operator message for the engine
        if (!parsed.isSlash) {
          rl.pause();
          try {
            await runTurn(session, text);
          } catch (err) {
            console.error(chalk.red(`\nturn failed: ${err instanceof Error ? err.message : String(err)}`));
          }
          rl.resume();
          rl.prompt();
          return;
        }

        // Unknown slash command → local notice, never reaches the LLM
        if (parsed.isUnknown) {
          console.log(chalk.yellow(`\nUnknown command. Type ${chalk.cyan("/help")} for available commands.\n`));
          rl.prompt();
          return;
        }

        // Known command — resolve metadata
        const cmd = getCommandByName(parsed.command!);
        if (!cmd) {
          rl.prompt();
          return;
        }

        // TUI-only commands explain they need the Bun TUI
        if (cmd.tuiOnly) {
          console.log(
            chalk.yellow(
              `\n"${text}" requires the Bun-backed TUI console. ` +
              `Use the \`0sec\` command (no flags) for the full interactive experience.\n`,
            ),
          );
          rl.prompt();
          return;
        }

        // ── Console-supported commands ──
        switch (parsed.command) {
          case "exit": {
            rl.close();
            return;
          }
          case "help": {
            printHelp();
            rl.prompt();
            return;
          }
          case "tools": {
            printTools(session);
            rl.prompt();
            return;
          }
          case "status": {
            printStatus(session);
            rl.prompt();
            return;
          }
          case "clear": {
            session.clearConversation();
            console.log(chalk.dim("\nConversation cleared.\n"));
            rl.prompt();
            return;
          }
          case "mode": {
            handleModeCommand(session, parsed.args);
            rl.prompt();
            return;
          }
          default: {
            rl.prompt();
            return;
          }
        }
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
  console.log(chalk.dim(`  mode: ${modeLabel(session.autonomyMode)}`));
  console.log(chalk.dim("  /help for commands · /exit to quit"));
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
  console.log(chalk.bold("\nslash commands:"));

  // Group commands by category for the readline help
  const entries: Array<{ name: string; usage: string; description: string }> = [];
  for (const cmd of SLASH_COMMANDS.filter((c: { tuiOnly?: boolean }) => !c.tuiOnly)) {
    const aliases = cmd.aliases.length ? ` (${cmd.aliases.map((a: string) => `/${a}`).join(", ")})` : "";
    const usage = cmd.usage ? ` ${cmd.usage}` : ` /${cmd.name}${aliases}`;
    entries.push({ name: cmd.name, usage, description: cmd.description });
  }

  // Order: info, session, mode, system
  const order: Record<string, number> = { info: 0, session: 1, mode: 2, system: 3 };
  entries.sort((a, b) => (order[findCategory(a.name)] ?? 99) - (order[findCategory(b.name)] ?? 99));

  let lastCat = "";
  for (const e of entries) {
    const cat = findCategory(e.name);
    if (cat !== lastCat) {
      console.log(`  ${chalk.underline(cat)}`);
      lastCat = cat;
    }
    console.log(`    ${chalk.cyan(e.usage.padEnd(30))} ${e.description}`);
  }

  console.log(chalk.dim("  Modes: Standard runs automatically in scope and can request a narrow session-only extension; Co-pilot adds approval for every non-read-only tool; YOLO runs only inside an explicit configured scope and never requests extensions."));
  console.log(chalk.dim("  The Node fallback cannot approve scope extensions or Co-pilot actions; use the Bun TUI for those approvals."));
  console.log(chalk.dim("  anything else is sent to the engine as an operator message.\n"));
  console.log(chalk.dim("  Navigation commands (/chat, /scope, /agents, …) require the Bun TUI."));
  console.log(chalk.dim("  Run the bare `0sec` command for the full interactive experience.\n"));
}

function findCategory(name: string): string {
  const cmd = getCommandByName(name);
  return cmd?.category ?? "system";
}

function printStatus(session: ConsoleSession): void {
  console.log(chalk.bold("\nsession status:"));
  console.log(`  ${chalk.cyan("id")}       ${session.scanId}`);
  console.log(`  ${chalk.cyan("mode")}     ${modeLabel(session.autonomyMode)}`);
  console.log(`  ${chalk.cyan("target")}  ${session.target || "(not set)"}`);
  console.log(`  ${chalk.cyan("tools")}   ${session.tools.length} available`);
  console.log(`  ${chalk.cyan("scope")}   ${hasConfiguredScope(session.scope) ? "configured" : "not configured"}`);
  console.log(`  ${chalk.cyan("turns")}   ${Math.ceil(session.messages.length / 2)}`);
  console.log("");
}

function handleModeCommand(session: ConsoleSession, args: string): void {
  const modeArg = args.trim().toLowerCase();
  if (modeArg === "standard" || modeArg === "copilot" || modeArg === "yolo") {
    const next: ConsoleAutonomyMode = modeArg === "standard"
      ? "standard"
      : modeArg === "copilot"
        ? "copilot"
        : "yolo";
    if (next === "yolo" && !hasConfiguredScope(session.scope)) {
      console.log(chalk.yellow(`\nYOLO requires a configured non-empty scope. Mode remains ${chalk.bold(modeLabel(session.autonomyMode))}.\n`));
      return;
    }
    session.setAutonomyMode(next);
    console.log(chalk.green(`\nMode switched to ${chalk.bold(modeLabel(next))}.\n`));
  } else if (modeArg === "") {
    console.log(chalk.dim(`\nCurrent mode: ${chalk.bold(modeLabel(session.autonomyMode))}\n`));
  } else {
    console.log(chalk.yellow(`\nUsage: /mode [standard|copilot|yolo]. Current mode: ${modeLabel(session.autonomyMode)}\n`));
  }
}

function modeLabel(mode: ConsoleAutonomyMode): string {
  if (mode === "standard") return "Standard";
  return mode === "copilot" ? "Co-pilot" : "YOLO";
}

function hasConfiguredScope(scope: ConsoleSession["scope"]): boolean {
  return (scope?.raw.in_scope?.length ?? 0) > 0;
}

function firstSentence(text: string): string {
  const end = text.indexOf(". ");
  const s = end > 0 ? text.slice(0, end) : text;
  return s.length > 90 ? s.slice(0, 87) + "…" : s;
}

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
  NativeMessage,
  ToolCall,
  ToolResult,
} from "@0sec/core";
import { canUseOpenTui, isBunRuntime } from "../tui/runtime.js";
import {
  findCommand,
  getCommandByName,
  SLASH_COMMANDS,
} from "../tui/slash-commands.js";
import {
  processPresentationOutput,
  type ProcessPresentationOutput,
} from "../presentation/process-output.js";

interface ConsoleOptions {
  target?: string;
  scope?: string;
  model?: string;
  role?: string;
  mode?: string;
  yolo?: boolean;
  autonomy?: string;
  maxToolCalls?: string;
  allowScanners?: boolean;
  /** `--resume [id]`: a session id/prefix to reopen, or `true` for the picker. */
  resume?: string | boolean;
  /** `--continue`: reopen the single most-recent console session, no picker. */
  continue?: boolean;
}

/** Launch autonomy modes accepted by `--mode` / `--autonomy`. */
export const CONSOLE_AUTONOMY_MODES = ["standard", "recon", "copilot", "yolo"] as const;

function isConsoleAutonomyMode(value: string): value is ConsoleAutonomyMode {
  return (CONSOLE_AUTONOMY_MODES as readonly string[]).includes(value);
}

export type ConsoleAutonomyResolution =
  | { ok: true; mode: ConsoleAutonomyMode }
  | { ok: false; error: string };

/**
 * Resolve the console's launch autonomy mode from the three surfaces that set
 * it, so the founder's discoverability gap ("how do I start in YOLO?") is
 * covered without changing what any mode permits:
 *   --mode <mode>     canonical, discoverable option
 *   --yolo            convenience shortcut, equivalent to --mode yolo
 *   --autonomy <mode> retained alias (documented in docs/commands.md)
 *
 * Precedence: --mode > --yolo > --autonomy > default "standard". A conflicting
 * `--mode <x> --yolo` (x !== yolo) is a clear error rather than a silent pick.
 * This only chooses the initial mode; the target/scope anchor and SSRF rail are
 * unchanged, and YOLO still requires a configured scope (enforced downstream).
 */
export function resolveConsoleAutonomyMode(opts: {
  mode?: string;
  yolo?: boolean;
  autonomy?: string;
}): ConsoleAutonomyResolution {
  const choices = CONSOLE_AUTONOMY_MODES.join(", ");

  if (opts.mode !== undefined) {
    if (!isConsoleAutonomyMode(opts.mode)) {
      return { ok: false, error: `Invalid --mode '${opts.mode}': expected one of ${choices}.` };
    }
    if (opts.yolo && opts.mode !== "yolo") {
      return {
        ok: false,
        error: `Conflicting flags: --yolo with --mode ${opts.mode}. Pass only one (use --mode yolo, or drop --yolo).`,
      };
    }
    return { ok: true, mode: opts.mode };
  }

  if (opts.yolo) return { ok: true, mode: "yolo" };

  if (opts.autonomy !== undefined) {
    if (!isConsoleAutonomyMode(opts.autonomy)) {
      return { ok: false, error: `Invalid --autonomy '${opts.autonomy}': expected one of ${choices}.` };
    }
    return { ok: true, mode: opts.autonomy };
  }

  return { ok: true, mode: "standard" };
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
    .option("--mode <mode>", "Autonomy mode to start in: standard|recon|copilot|yolo (default standard). YOLO drops per-action prompts but stays target/scope-anchored; cycle live with Shift+Tab.")
    .option("--yolo", "Shortcut for --mode yolo — start the console in YOLO autonomy (no per-action prompts; still target-anchored and SSRF-railed).")
    .option("--autonomy <mode>", "Alias of --mode (standard|copilot|yolo|recon); --mode/--yolo take precedence.", "standard")
    .option("--max-tool-calls <n>", "Safety cap on tool-call rounds per operator message", "20")
    .option("--allow-scanners", "Expose generic-scanner tool wrappers (sqlmap/nikto/…); default off")
    .option("--resume [id]", "Reopen a saved console session by id (or unique prefix); with no id, opens a session picker. Also reachable as `0 -r [id]`.")
    .option("--continue", "Reopen the most recent console session, no picker. Also reachable as `0 -c`.")
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

      const autonomyResolution = resolveConsoleAutonomyMode({
        mode: opts.mode,
        yolo: opts.yolo,
        autonomy: opts.autonomy,
      });
      if (!autonomyResolution.ok) {
        console.error(chalk.red(autonomyResolution.error));
        process.exitCode = 2;
        return;
      }
      const autonomyMode: ConsoleAutonomyMode = autonomyResolution.mode;

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

      // Resolve a saved console session to resume/continue. `--continue` (and
      // the `0 -c` shortcut) → the single most-recent; `--resume <id>` → that id
      // or a unique prefix; bare `--resume` (and `0 -r`) → an interactive picker.
      // A resumed session inherits its stored model/target unless overridden.
      let resumeMessages: readonly unknown[] | undefined;
      let resumedModel: string | undefined;
      let resumedTarget: string | undefined;
      let openResumePicker = false;
      if (opts.continue || opts.resume !== undefined) {
        const { listSessions, loadSession } = await import("../tui/session-store.js");
        const idArg = typeof opts.resume === "string" ? opts.resume.trim() : "";
        if (idArg || opts.continue) {
          let stored = idArg ? loadSession(idArg) : null;
          if (!stored && idArg) {
            const matches = listSessions(undefined, { limit: 500 }).filter((s) => s.id.startsWith(idArg));
            if (matches.length === 1) stored = loadSession(matches[0].id);
            else if (matches.length > 1) {
              console.error(chalk.red(`'${idArg}' matches ${matches.length} sessions — use a longer prefix or the full id.`));
              process.exitCode = 2;
              return;
            }
          } else if (!stored && opts.continue) {
            const recent = listSessions(undefined, { limit: 1 })[0];
            stored = recent ? loadSession(recent.id) : null;
          }
          if (!stored) {
            console.error(chalk.red(idArg ? `No console session matches '${idArg}'.` : "No saved console session to continue."));
            process.exitCode = 1;
            return;
          }
          resumeMessages = stored.messages;
          resumedModel = stored.model;
          resumedTarget = stored.target;
        } else {
          openResumePicker = true; // bare `--resume` / `0 -r` → the picker
        }
      }

      if (isBunRuntime() && canUseOpenTui()) {
        // `run.tsx` imports Bun-only OpenTUI dependencies, so Node must not
        // resolve it before falling back to the readline console.
        const { showOpenTuiConsole, showOpenTuiResume } = await import("../tui/run.js");
        type TuiOpts = NonNullable<Parameters<typeof showOpenTuiConsole>[0]>;
        const baseOptions: TuiOpts = {
          target: resumedTarget ?? opts.target,
          scope,
          model: resumedModel ?? opts.model,
          role,
          maxToolIterations,
          allowScanners: opts.allowScanners,
          autonomyMode,
        };
        if (openResumePicker) {
          await showOpenTuiResume(baseOptions);
        } else {
          await showOpenTuiConsole({
            ...baseOptions,
            initialMessages: resumeMessages as TuiOpts["initialMessages"],
          });
        }
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
          target: resumedTarget ?? opts.target,
          role,
          maxToolIterations,
          allowScanners: opts.allowScanners,
          scope,
          autonomyMode,
          // A resumed session seeds the model's history so it continues where it
          // left off (the readline fallback can't repaint the old transcript, but
          // the conversation context carries over).
          ...(resumeMessages ? { initialMessages: resumeMessages as NativeMessage[] } : {}),
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
      const presentationOutput = processPresentationOutput;

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
            await runTurn(session, text, presentationOutput);
          } catch (err) {
            presentationOutput.stderr(
              chalk.red(`\nturn failed: ${err instanceof Error ? err.message : String(err)}\n`),
              "console.turn.failure",
            );
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
            // A known, non-tuiOnly command the line-mode REPL doesn't implement
            // (e.g. model/providers/settings/resume). Say so instead of silently
            // ignoring it — the full set lives in the Bun TUI.
            console.log(
              chalk.yellow(
                `\n/${parsed.command} isn't available in the line-mode console. ` +
                `Use the \`0sec\` command (no flags) for the full interactive TUI.\n`,
              ),
            );
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

async function runTurn(
  session: ConsoleSession,
  text: string,
  output: ProcessPresentationOutput,
): Promise<void> {
  let streamedAny = false;
  output.stdout("\n" + chalk.bold.green("engine › "), "console.assistant.prefix");

  const outcome = await session.send(text, {
    onAssistantDelta: (chunk) => {
      streamedAny = true;
      output.stdout(chunk, "console.assistant.delta");
    },
    onToolStart: (call: ToolCall) => {
      output.stdout(
        "\n" + chalk.yellow(`  ⚙ ${call.name}`) + chalk.dim(` ${previewArgs(call.arguments)}`),
        "console.tool.started",
      );
    },
    onToolResult: (_call: ToolCall, result: ToolResult) => {
      const mark = result.success ? chalk.green("✓") : chalk.red("✗");
      output.stdout(chalk.dim(` → ${mark} ${previewResult(result)}`), "console.tool.completed");
    },
    onNotice: (msg) => {
      output.stdout("\n" + chalk.dim(`  (${msg})`), "console.notice");
    },
  });

  // If nothing streamed token-by-token (provider without delta support), print
  // the collected assistant text now.
  if (!streamedAny && outcome.assistantText) {
    output.stdout("\n" + outcome.assistantText, "console.assistant.complete");
  }

  const usage = outcome.usage;
  const footer = `${outcome.toolCalls.length} tool call${outcome.toolCalls.length === 1 ? "" : "s"} · ${usage.inputTokens}→${usage.outputTokens} tok`;
  output.stdout("\n" + chalk.dim(`  [${footer}]`) + "\n", "console.turn.completed");

  if (outcome.stopReason === "error") {
    output.stderr(chalk.red(`\nengine error: ${outcome.error ?? "unknown"}\n`), "console.turn.error");
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
  if (modeArg === "standard" || modeArg === "recon" || modeArg === "copilot" || modeArg === "yolo") {
    const next = modeArg as ConsoleAutonomyMode;
    if (next === "yolo" && !hasConfiguredScope(session.scope)) {
      console.log(chalk.yellow(`\nYOLO requires a configured non-empty scope. Mode remains ${chalk.bold(modeLabel(session.autonomyMode))}.\n`));
      return;
    }
    session.setAutonomyMode(next);
    console.log(chalk.green(`\nMode switched to ${chalk.bold(modeLabel(next))}.\n`));
  } else if (modeArg === "") {
    console.log(chalk.dim(`\nCurrent mode: ${chalk.bold(modeLabel(session.autonomyMode))}\n`));
  } else {
    console.log(chalk.yellow(`\nUsage: /mode [standard|recon|copilot|yolo]. Current mode: ${modeLabel(session.autonomyMode)}\n`));
  }
}

function modeLabel(mode: ConsoleAutonomyMode): string {
  if (mode === "standard") return "Standard";
  if (mode === "recon") return "Recon";
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

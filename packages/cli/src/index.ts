#!/usr/bin/env node


import { Command } from "commander";
import chalk from "chalk";
import { VERSION } from "@0sec/shared";
import {
  ANALYTICS_LEVEL_ENV,
  createHerdrEventSink,
  eventBus,
  maybeSubscribeAnalyticsPipeline,
  maybeSubscribeCloudEventSink,
  maybeSubscribeOperationalEventSink,
  presentationEventSink,
} from "@0sec/core";
import { getSettings } from "./tui/settings-store.js";
import { maybeLoadCodexAuth } from "./codex-auth.js";
import { presentationEventBus } from "./presentation/event-bus.js";
import {
  installConsolePresentationBridge,
  installProcessPresentationStreamBridge,
} from "./presentation/process-output.js";
import { setHerdrSink } from "./herdr-state.js";


// Legacy command modules still use console methods. Bridge those bytes into
// the canonical stream at the process boundary without changing their output.
installConsolePresentationBridge();
installProcessPresentationStreamBridge();
// Local-dev convenience: if `codex login` has run (~/.codex/auth.json) and no
// 0SEC_CHATGPT_* token is in the env, plumb the codex tokens in so the engine
// resolves to the chatgpt-codex provider (highest priority) instead of falling
// through to stale AZURE_OPENAI_API_KEY / OPENAI_API_KEY. No-op in the cloud
// worker (it sets the tokens itself) and when a token is already present.
maybeLoadCodexAuth();

// Subscribe the cloud-event sink before any subcommand runs. Idempotent
// + env-gated (0SEC_CLOUD_EVENTS=1): the sink writes one
// `0SEC_EVENT_<TYPE>` line per emitted event to stdout, which the
// 0sec-cloud worker-controller's stdout streamer parses and POSTs to
// the orchestrator's /scans/:id/events endpoint. Without this call,
// the sink module is dead code and the cloud's live-trace UI stays
// dark for every scan.
maybeSubscribeCloudEventSink();

// Consent bridge for the analytics pipeline. core must NOT import the CLI
// settings store, so the operator's `analyticsLevel` crosses the boundary as
// an env var that `resolveAnalyticsLevel` reads (any opt-out env — 0SEC_OFFLINE
// / 0SEC_NO_TELEMETRY / DO_NOT_TRACK — still wins and forces "off"). We set it
// from the resolved setting, then subscribe the pipeline's usage sink. When the
// level is "off" this is a no-op: nothing subscribes and nothing transmits.
// A live /settings change re-runs this bridge from settings-store.ts.
try {
  process.env[ANALYTICS_LEVEL_ENV] = getSettings().analyticsLevel;
} catch {
  // Settings unreadable — leave the env untouched; resolve fails closed to off.
}
maybeSubscribeAnalyticsPipeline();

// Operational NDJSON stderr sink (0SEC_LOG_FORMAT=json). Opt-in metadata-
// only logging — writes one NDJSON line per allowlisted lifecycle / cost
// event to stderr. Strips all sensitive fields (prompts, responses,
// reasoning, tool args, finding evidence, token deltas, auth material,
// raw error text). No effect unless the env var is set.
maybeSubscribeOperationalEventSink();

// Every core event also enters the process-local canonical presentation stream.
// Legacy cloud/stdout and Herdr projections remain independent adapters.
eventBus.subscribe(presentationEventSink(presentationEventBus));

// Report coarse agent state to herdr when 0sec is running inside one of its
// panes, so the pane shows working/idle instead of "unknown" and
// `herdr agent wait` becomes usable against a scan. The factory returns null
// off-herdr, every write is fail-soft, and the payload carries only counters
// and a fixed phase enum — never a target, finding, path or tool name, since
// that socket is readable by any process running as this user.
const herdrSink = createHerdrEventSink();
if (herdrSink) eventBus.subscribe(herdrSink);
// Parked so the interactive console can also report the `blocked` state,
// which no bus event covers (approval gates resolve inline).
setHerdrSink(herdrSink);
import { detectAndRoute } from "./routing.js";
import { runStartupUpdate } from "./utils/update-check.js";
import { enforceSourceDistFreshness } from "./source-freshness.js";

enforceSourceDistFreshness({ entryUrl: import.meta.url });


// Explicit automatic updates finish before command parsing or interactive work.
// Notification-only checks stay in the background; unset settings remain opt-in.
await runStartupUpdate(VERSION);

// The empty-argv path launches straight into the interactive TUI and needs none
// of the 56 subcommand modules. Importing (and registering) that barrel is the
// single biggest chunk of cold-start import cost, so defer it behind a dynamic
// import that only runs when the user actually passes a command/args.
async function buildProgram(): Promise<Command> {
  const c = await import("./commands/index.js");
  const program = new Command();
  program
    .name("0sec")
    .description("Open-source multi-model security research harness")
    .version(VERSION)
    .enablePositionalOptions();
  c.registerScanCommand(program);
  c.registerResumeCommand(program);
  c.registerReplayCommand(program);
  c.registerHistoryCommand(program);
  c.registerFindingsCommand(program);
  c.registerSecureCommand(program);
  c.registerReviewCommand(program);
  c.registerFixCommand(program);
  c.registerAuditCommand(program);
  c.registerDoctorCommand(program);
  c.registerDashboardCommand(program);
  c.registerTuiCommand(program);
  c.registerOrchestrateCommand(program);
  c.registerDbCommand(program);
  c.registerMcpServerCommand(program);
  c.registerTriageCommand(program);
  c.registerEvalCommand(program);
  c.registerBenchCommand(program);
  c.registerIngestCommand(program);
  c.registerKernelCommand(program);
  c.registerDiscloseCommand(program);
  c.registerVerifyCommand(program);
  c.registerExploitCommand(program);
  c.registerHuntCommand(program);
  c.registerRecencyHuntCommand(program);
  c.registerDeepReviewCommand(program);
  c.registerLensSynthCommand(program);
  c.registerMemsafetyCommand(program);
  c.registerAssumptionHuntCommand(program);
  c.registerSpecdriftCommand(program);
  c.registerProtocolCheckCommand(program);
  c.registerCveCommand(program);
  c.registerUpgradeCommand(program);
  c.registerH1Command(program);
  c.registerAuthCommand(program);
  c.registerHostedCommand(program);
  c.registerIntelCommand(program);
  c.registerReconCommand(program);
  c.registerConsoleCommand(program);
  c.registerJsReconCommand(program);
  c.registerNpmDiscoveryCommand(program);
  c.registerIdentityCommand(program);
  c.registerAdGraphCommand(program);
  c.registerEntraGraphCommand(program);
  c.registerCloudCommand(program);
  c.registerXnuFuzzCommand(program);
  c.registerResearchCommand(program);
  c.registerTimelineCommand(program);
  c.registerFileReviewCommand(program);
  c.registerAgentAssureCommand(program);
  c.registerBinaryCommand(program);
  c.registerPluginCommand(program);
  c.registerThemeCommand(program);
  c.registerEvolveCommand(program);
  c.registerConfigCommand(program);
  c.registerHackstoreCommand(program);
  return program;
}


// ── Interactive menu ──
//
// Under Bun, launches the OpenTUI home (`@opentui/react`-based mission
// control). Under Node, the interactive menu was Ink-based and was
// removed in v0.9.0 — print install instructions for the standalone
// binary and exit so the user gets the full TUI experience.
async function showInteractiveMenu(): Promise<void> {
  const { isBunRuntime } = await import("./tui/runtime.js");
  if (isBunRuntime()) {
    const { showOpenTuiHome } = await import("./tui/run.js");
    await showOpenTuiHome();
    return;
  }

  console.log("");
  console.log(`  ${chalk.bold("0sec")} ${chalk.dim(`v${VERSION}`)}`);
  console.log("");
  console.log(`  ${chalk.dim("From v0.9.0 onwards, 0sec ships as a self-contained binary.")}`);
  console.log(`  ${chalk.dim("The full TUI (mission control + live scan view) needs Bun's runtime.")}`);
  console.log("");
  console.log(`  ${chalk.bold("Install")} (single curl, no Node / Bun required):`);
  console.log(`    curl -fsSL https://raw.githubusercontent.com/0sec-labs/0sec/main/install.sh | bash`);
  console.log("");
  console.log(`  ${chalk.dim("After install, run:")}`);
  console.log(`    0sec scan --target https://example.com`);
  console.log(`    0sec --help`);
  console.log("");
}

// ── Entry point ──
const userArgs = process.argv.slice(2);
const knownCommands = ["scan", "resume", "replay", "history", "findings", "secure", "review", "fix", "file-review", "audit", "doctor", "dashboard", "tui", "watch", "orchestrate", "db", "mcp-server", "eval", "bench", "ingest", "kernel", "disclose", "verify", "exploit", "hunt", "recency-hunt", "deep-review", "lens-synth", "memsafety", "assumption-hunt", "specdrift", "protocol-check", "cve", "upgrade", "h1", "auth", "login", "models", "balance", "intel", "recon", "js-recon", "npm-discovery", "identity", "adgraph", "entragraph", "cloud", "xnu-fuzz", "research", "timeline", "console", "agent-assure", "binary", "plugin", "theme", "config", "evolve", "hackstore", "hack", "store", "help"];

if (userArgs.length === 0) {
  // Fast path: straight into the TUI without ever importing the command barrel.
  showInteractiveMenu().catch((err) => {
    console.error(chalk.red(err instanceof Error ? err.message : String(err)));
    process.exit(2);
  });
} else {
  // Any command/args path pays the barrel import once, here.
  const program = await buildProgram();
  if (userArgs[0] === "-r" || userArgs[0] === "--resume") {
    // `0 -r [id]` is the top-level shortcut for `console --resume [id]`: resume a
    // saved chat session by id/prefix, or open the picker with no id. commander's
    // root can't take a bare `-r`, so rewrite argv onto the `console` subcommand.
    process.argv = [process.argv[0], process.argv[1], "console", "--resume", ...userArgs.slice(1)];
    program.parse();
  } else if (userArgs[0] === "-c" || userArgs[0] === "--continue") {
    // `0 -c` → `console --continue`: reopen the most recent chat session.
    process.argv = [process.argv[0], process.argv[1], "console", "--continue", ...userArgs.slice(1)];
    program.parse();
  } else if (userArgs[0] === "-p" || userArgs[0] === "--print") {
    // `0 -p "<prompt>"` → `console --print "<prompt>"`: one-shot non-interactive
    // query (or read the prompt from piped stdin when no argument is given).
    process.argv = [process.argv[0], process.argv[1], "console", "--print", ...userArgs.slice(1)];
    program.parse();
  } else if (userArgs.length >= 1 && !knownCommands.includes(userArgs[0]) && !userArgs[0].startsWith("-")) {
    const route = detectAndRoute(userArgs[0]);
    if (route) {
      const extraArgs = userArgs.slice(1);
      process.argv = [process.argv[0], process.argv[1], ...route, ...extraArgs];
      program.parse();
    } else {
      console.error("Ambiguous target. Use the control plane (`0`) or an explicit URL, path, source:, npm:, pypi:, cargo:, or oci: target.");
      process.exitCode = 2;
    }
  } else {
    program.parse();
  }
}

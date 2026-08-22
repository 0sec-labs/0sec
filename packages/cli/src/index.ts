#!/usr/bin/env node


import { Command } from "commander";
import chalk from "chalk";
import { VERSION } from "@0sec/shared";
import { createHerdrEventSink, eventBus, maybeSubscribeCloudEventSink } from "@0sec/core";
import { maybeLoadCodexAuth } from "./codex-auth.js";
import { setHerdrSink } from "./herdr-state.js";

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
import {
  registerScanCommand,
  registerResumeCommand,
  registerReplayCommand,
  registerHistoryCommand,
  registerFindingsCommand,
  registerReviewCommand,
  registerFixCommand,
  registerAuditCommand,
  registerDoctorCommand,
  registerDashboardCommand,
  registerTuiCommand,
  registerOrchestrateCommand,
  registerDbCommand,
  registerMcpServerCommand,
  registerTriageCommand,
  registerEvalCommand,
  registerBenchCommand,
  registerIngestCommand,
  registerKernelCommand,
  registerDiscloseCommand,
  registerVerifyCommand,
  registerExploitCommand,
  registerHuntCommand,
  registerRecencyHuntCommand,
  registerDeepReviewCommand,
  registerLensSynthCommand,
  registerMemsafetyCommand,
  registerAssumptionHuntCommand,
  registerSpecdriftCommand,
  registerProtocolCheckCommand,
  registerCveCommand,
  registerUpgradeCommand,
  registerH1Command,
  registerAuthCommand,
  registerIntelCommand,
  registerReconCommand,
  registerConsoleCommand,
  registerJsReconCommand,
  registerNpmDiscoveryCommand,
  registerIdentityCommand,
  registerAdGraphCommand,
  registerEntraGraphCommand,
  registerCloudCommand,
  registerXnuFuzzCommand,
  registerResearchCommand,
  registerTimelineCommand,
  registerFileReviewCommand,
  registerAgentAssureCommand,
  registerBinaryCommand,
  registerPluginCommand,
  registerThemeCommand,
} from "./commands/index.js";
import { detectAndRoute } from "./routing.js";
import { maybeNotifyUpdate } from "./utils/update-check.js";
import { enforceSourceDistFreshness } from "./source-freshness.js";

enforceSourceDistFreshness({ entryUrl: import.meta.url });


// Fire-and-forget update check. It only runs when 0SEC_UPDATE_CHECK=1;
// otherwise normal commands make no update request or cache write.
void maybeNotifyUpdate(VERSION);

const program = new Command();

program
  .name("0sec")
  .description("Open-source multi-model security research harness")
  .version(VERSION);

registerScanCommand(program);
registerResumeCommand(program);
registerReplayCommand(program);
registerHistoryCommand(program);
registerFindingsCommand(program);
registerReviewCommand(program);
registerFixCommand(program);
registerAuditCommand(program);
registerDoctorCommand(program);
registerDashboardCommand(program);
registerTuiCommand(program);
registerOrchestrateCommand(program);
registerDbCommand(program);
registerMcpServerCommand(program);
registerTriageCommand(program);
registerEvalCommand(program);
registerBenchCommand(program);
registerIngestCommand(program);
registerKernelCommand(program);
registerDiscloseCommand(program);
registerVerifyCommand(program);
registerExploitCommand(program);
registerHuntCommand(program);
registerRecencyHuntCommand(program);
registerDeepReviewCommand(program);
registerLensSynthCommand(program);
registerMemsafetyCommand(program);
registerAssumptionHuntCommand(program);
registerSpecdriftCommand(program);
registerProtocolCheckCommand(program);
registerCveCommand(program);
registerUpgradeCommand(program);
registerH1Command(program);
registerAuthCommand(program);
registerIntelCommand(program);
registerReconCommand(program);
registerConsoleCommand(program);
registerJsReconCommand(program);
registerNpmDiscoveryCommand(program);
registerIdentityCommand(program);
registerAdGraphCommand(program);
registerEntraGraphCommand(program);
registerCloudCommand(program);
registerXnuFuzzCommand(program);
registerResearchCommand(program);
registerTimelineCommand(program);
registerFileReviewCommand(program);
registerAgentAssureCommand(program);
registerBinaryCommand(program);
registerPluginCommand(program);
registerThemeCommand(program);

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
  console.log(`  ${chalk.dim("Or via Bun:")}`);
  console.log(`    bun add -g 0sec-cli`);
  console.log("");
  console.log(`  ${chalk.dim("After install, run:")}`);
  console.log(`    0sec scan --target https://example.com`);
  console.log(`    0sec --help`);
  console.log("");
}

// ── Entry point ──
const userArgs = process.argv.slice(2);
const knownCommands = ["scan", "resume", "replay", "history", "findings", "review", "fix", "file-review", "audit", "doctor", "dashboard", "tui", "watch", "orchestrate", "db", "mcp-server", "eval", "bench", "ingest", "kernel", "disclose", "verify", "exploit", "hunt", "recency-hunt", "deep-review", "lens-synth", "memsafety", "assumption-hunt", "specdrift", "protocol-check", "cve", "upgrade", "h1", "auth", "intel", "recon", "js-recon", "npm-discovery", "identity", "adgraph", "entragraph", "cloud", "xnu-fuzz", "research", "timeline", "console", "agent-assure", "binary", "help"];

if (userArgs.length === 0) {
  showInteractiveMenu().catch((err) => {
    console.error(chalk.red(err instanceof Error ? err.message : String(err)));
    process.exit(2);
  });
} else if (userArgs.length >= 1 && !knownCommands.includes(userArgs[0]) && !userArgs[0].startsWith("-")) {
  const route = detectAndRoute(userArgs[0]);
  if (route) {
    const extraArgs = userArgs.slice(1);
    process.argv = [process.argv[0], process.argv[1], ...route, ...extraArgs];
    program.parse();
  } else {
    program.parse();
  }
} else {
  program.parse();
}

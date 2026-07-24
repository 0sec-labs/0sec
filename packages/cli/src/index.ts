#!/usr/bin/env node

import { Command } from "commander";
import chalk from "chalk";
import { VERSION } from "@pwnkit/shared";
import { maybeSubscribeCloudEventSink } from "@pwnkit/core";
import { maybeLoadCodexAuth } from "./codex-auth.js";

// Local-dev convenience: if `codex login` has run (~/.codex/auth.json) and no
// PWNKIT_CHATGPT_* token is in the env, plumb the codex tokens in so the engine
// resolves to the chatgpt-codex provider (highest priority) instead of falling
// through to stale AZURE_OPENAI_API_KEY / OPENAI_API_KEY. No-op in the cloud
// worker (it sets the tokens itself) and when a token is already present.
maybeLoadCodexAuth();

// Subscribe the cloud-event sink before any subcommand runs. Idempotent
// + env-gated (PWNKIT_CLOUD_EVENTS=1): the sink writes one
// `PWNKIT_EVENT_<TYPE>` line per emitted event to stdout, which the
// pwnkit-cloud worker-controller's stdout streamer parses and POSTs to
// the orchestrator's /scans/:id/events endpoint. Without this call,
// the sink module is dead code and the cloud's live-trace UI stays
// dark for every scan.
maybeSubscribeCloudEventSink();
import {
  registerScanCommand,
  registerResumeCommand,
  registerReplayCommand,
  registerHistoryCommand,
  registerFindingsCommand,
  registerReviewCommand,
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
  registerCloudCommand,
  registerXnuFuzzCommand,
  registerResearchCommand,
} from "./commands/index.js";
import { detectAndRoute } from "./routing.js";
import { preloadBanner } from "./ui/banner.js";
import { maybeNotifyUpdate } from "./utils/update-check.js";
import { enforceSourceDistFreshness } from "./source-freshness.js";

enforceSourceDistFreshness({ entryUrl: import.meta.url });

// Start loading cfonts in the background so it's ready when the banner prints
void preloadBanner();

// Fire-and-forget update check. Once-per-day GH API call; no-ops in CI,
// pipes, or when PWNKIT_NO_UPDATE_CHECK / PWNKIT_OFFLINE is set. Never
// blocks the actual command — we explicitly `void` the promise so it
// runs concurrently with whatever subcommand the user invoked.
void maybeNotifyUpdate(VERSION);

const program = new Command();

program
  .name("pwnkit-cli")
  .description("Fully autonomous agentic pentesting framework")
  .version(VERSION);

registerScanCommand(program);
registerResumeCommand(program);
registerReplayCommand(program);
registerHistoryCommand(program);
registerFindingsCommand(program);
registerReviewCommand(program);
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
registerCloudCommand(program);
registerXnuFuzzCommand(program);
registerResearchCommand(program);

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
  console.log(`  ${chalk.bold("pwnkit")} ${chalk.dim(`v${VERSION}`)}`);
  console.log("");
  console.log(`  ${chalk.dim("From v0.9.0 onwards, pwnkit ships as a self-contained binary.")}`);
  console.log(`  ${chalk.dim("The full TUI (mission control + live scan view) needs Bun's runtime.")}`);
  console.log("");
  console.log(`  ${chalk.bold("Install")} (single curl, no Node / Bun required):`);
  console.log(`    curl -fsSL https://raw.githubusercontent.com/0sec-labs/pwnkit/main/install.sh | bash`);
  console.log("");
  console.log(`  ${chalk.dim("Or via Bun:")}`);
  console.log(`    bun add -g pwnkit-cli`);
  console.log("");
  console.log(`  ${chalk.dim("After install, run:")}`);
  console.log(`    pwnkit scan --target https://example.com`);
  console.log(`    pwnkit --help`);
  console.log("");
}

// ── Entry point ──
const userArgs = process.argv.slice(2);
const knownCommands = ["scan", "resume", "replay", "history", "findings", "review", "audit", "doctor", "dashboard", "tui", "watch", "orchestrate", "db", "mcp-server", "eval", "bench", "ingest", "kernel", "disclose", "verify", "exploit", "hunt", "recency-hunt", "deep-review", "lens-synth", "memsafety", "assumption-hunt", "specdrift", "protocol-check", "cve", "upgrade", "h1", "auth", "intel", "recon", "js-recon", "npm-discovery", "cloud", "xnu-fuzz", "research", "console", "help"];
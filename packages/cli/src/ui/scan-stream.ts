/**
 * Plain-stdout streaming session for scan / audit / review under Node.
 *
 * Drop-in replacement for the legacy Ink `renderScanUI` factory. Same shape
 * (`onEvent` / `setReport` / `waitForExit`) so the run-pipeline glue in
 * `commands/run.ts` is unchanged. Output is one tagged line per event so it
 * stays useful in CI and `| tee` pipelines without ANSI / cursor games.
 *
 * The full TUI lives in `tui/run.tsx` (OpenTUI, Bun-only). When `globalThis.Bun`
 * is absent, the run command falls through to this streamer.
 */

import chalk from "chalk";

interface ScanEvent {
  type: string;
  stage?: string;
  message?: string;
  data?: unknown;
}

interface StreamSession {
  onEvent: (event: ScanEvent) => void;
  setReport: (report: unknown) => void;
  waitForExit: () => Promise<void>;
  getPendingUserMessages?: () => string[];
}

interface RenderScanStreamOptions {
  version: string;
  target: string;
  depth: string;
  mode: "scan" | "audit" | "review";
}

const STAGE_TAG: Record<string, (s: string) => string> = {
  discovery: chalk.cyan,
  "source-analysis": chalk.magenta,
  attack: chalk.yellow,
  verify: chalk.blue,
  report: chalk.gray,
};

function tagFor(stage?: string): string {
  if (!stage) return chalk.gray("[pwnkit]");
  const colour = STAGE_TAG[stage] ?? chalk.gray;
  return colour(`[${stage}]`);
}

function severityColour(sev: string): (s: string) => string {
  switch (sev) {
    case "critical": return chalk.red.bold;
    case "high": return chalk.red;
    case "medium": return chalk.yellow;
    case "low": return chalk.cyan;
    default: return chalk.gray;
  }
}

export function renderScanStream(opts: RenderScanStreamOptions): StreamSession {
  const { version, target, depth, mode } = opts;
  console.log("");
  console.log(`  ${chalk.bold("pwnkit")} ${chalk.dim(`v${version}`)}`);
  console.log(`    ${chalk.dim(`${mode}ing target ${target} · depth ${depth}`)}`);
  console.log("");

  const onEvent = (event: ScanEvent): void => {
    const tag = tagFor(event.stage);
    switch (event.type) {
      case "stage:start":
        console.log(`${tag} ${chalk.bold("▶")} ${event.message ?? ""}`);
        return;
      case "stage:end":
        console.log(`${tag} ${chalk.green("✓")} ${event.message ?? ""}`);
        return;
      case "attack:start":
      case "attack:end":
        if (event.message) console.log(`${tag} ${event.message}`);
        return;
      case "finding": {
        const data = (event.data ?? {}) as Record<string, unknown>;
        const sev = typeof data.severity === "string" ? data.severity : "info";
        const title = typeof data.title === "string" ? data.title : "(untitled)";
        console.log(`${tag} ${severityColour(sev)(`◆ ${sev.toUpperCase()}`)} ${title}`);
        return;
      }
      case "verify:result":
        if (event.message) console.log(`${tag} ${event.message}`);
        return;
      case "thinking":
        // High-volume; only print if explicitly opted in via PWNKIT_VERBOSE.
        if (process.env.PWNKIT_VERBOSE && event.message) {
          console.log(`${chalk.gray("  …")} ${chalk.dim(event.message.slice(0, 200))}`);
        }
        return;
      case "usage": {
        const u = (event.data ?? {}) as Record<string, unknown>;
        const cost = typeof u.estimatedCostUsd === "number" ? u.estimatedCostUsd.toFixed(4) : "?";
        const inT = typeof u.inputTokens === "number" ? u.inputTokens : "?";
        const outT = typeof u.outputTokens === "number" ? u.outputTokens : "?";
        console.log(`${tag} ${chalk.dim(`cost $${cost} · in ${inT} · out ${outT}`)}`);
        return;
      }
      case "error":
        console.error(`${tag} ${chalk.red("error:")} ${event.message ?? "(no message)"}`);
        return;
      case "user:injected":
        if (event.message) console.log(`${chalk.cyan("you →")} ${event.message}`);
        return;
      default:
        if (event.message) console.log(`${tag} ${event.message}`);
    }
  };

  const setReport = (_report: unknown): void => {
    // No-op — `commands/run.ts` already prints `formatReport(...)` after the
    // session resolves. We don't render the final summary ourselves.
  };

  const waitForExit = async (): Promise<void> => {
    // Stdout streamer has no input loop, so there's nothing to wait for —
    // resolve immediately and let the caller print the final report.
  };

  return { onEvent, setReport, waitForExit };
}

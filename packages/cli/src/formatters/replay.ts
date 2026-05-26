import chalk from "chalk";
import type {
  ScanReport,
  Finding,
  AttackResult,
  TargetInfo,
  Severity,
} from "@pwnkit/shared";

// ── Types ──

export interface ReplayData {
  target: string;
  targetInfo?: TargetInfo;
  findings: Finding[];
  attackResults?: AttackResult[];
  summary: ScanReport["summary"];
  durationMs: number;
  warnings?: ScanReport["warnings"];
}

interface ReplayLine {
  text: string;
  delay: number; // ms before printing this line
}

// ── Sleep utility ──

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── ANSI-safe string length ──

function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, "");
}

// ── Box drawing ──

const BOX_WIDTH = 55;

function boxTop(label: string): string {
  const inner = ` ${label} `;
  const remaining = BOX_WIDTH - inner.length - 1; // -1 for closing corner
  return (
    chalk.dim("\u250c\u2500 ") +
    chalk.bold.white(label) +
    chalk.dim(" " + "\u2500".repeat(Math.max(0, remaining)) + "\u2510")
  );
}

function boxRow(content: string): string {
  const visible = stripAnsi(content);
  const pad = Math.max(0, BOX_WIDTH - visible.length - 2);
  return chalk.dim("\u2502") + " " + content + " ".repeat(pad) + chalk.dim("\u2502");
}

function boxBottom(withArrow: boolean): string {
  if (withArrow) {
    const half = Math.floor((BOX_WIDTH - 1) / 2);
    const rest = BOX_WIDTH - half - 1;
    return (
      chalk.dim("\u2514" + "\u2500".repeat(half) + "\u2534" + "\u2500".repeat(rest) + "\u2518")
    );
  }
  return chalk.dim("\u2514" + "\u2500".repeat(BOX_WIDTH) + "\u2518");
}

function connector(): string {
  const half = Math.floor((BOX_WIDTH + 1) / 2);
  return " ".repeat(half) + chalk.dim("\u25bc");
}

// ── Outcome styling ──

function outcomeLabel(outcome: string): string {
  switch (outcome) {
    case "vulnerable":
      return chalk.red.bold("VULNERABLE");
    case "leaked":
      return chalk.red.bold("LEAKED");
    case "bypassed":
      return chalk.red.bold("BYPASSED");
    case "safe":
      return chalk.green("SAFE");
    case "error":
      return chalk.yellow("ERROR");
    default:
      return chalk.gray(outcome.toUpperCase());
  }
}

function severityColor(s: Severity): (text: string) => string {
  switch (s) {
    case "critical":
      return chalk.red.bold;
    case "high":
      return chalk.redBright;
    case "medium":
      return chalk.yellow;
    case "low":
      return chalk.blue;
    case "info":
      return chalk.gray;
  }
}

// ── Build replay lines from scan data ──

function buildReplayLines(data: ReplayData): ReplayLine[] {
  const lines: ReplayLine[] = [];
  const FAST = 50;
  const MED = 75;
  const SLOW = 100;
  const PAUSE = 200;

  // ── DISCOVER lane ──
  lines.push({ text: boxTop("DISCOVER"), delay: PAUSE });

  if (data.targetInfo) {
    const t = data.targetInfo;
    const truncUrl = t.url.length > 30 ? t.url.slice(0, 27) + "..." : t.url;
    lines.push({
      text: boxRow(
        chalk.dim("\u25b8") +
          " " +
          chalk.white(`GET ${truncUrl}`) +
          chalk.dim(" \u2192 ") +
          chalk.white(`200`) +
          chalk.gray(` (${t.type} endpoint detected)`)
      ),
      delay: MED,
    });

    if (t.systemPrompt) {
      lines.push({
        text: boxRow(
          chalk.dim("\u25b8") +
            " " +
            chalk.white(`System prompt extracted`) +
            chalk.gray(` (${t.systemPrompt.length} chars)`)
        ),
        delay: MED,
      });
    }

    if (t.detectedFeatures && t.detectedFeatures.length > 0) {
      lines.push({
        text: boxRow(
          chalk.dim("\u25b8") +
            " " +
            chalk.white(`${t.detectedFeatures.length} features detected: `) +
            chalk.gray(t.detectedFeatures.slice(0, 3).join(", "))
        ),
        delay: MED,
      });
    }

    if (t.endpoints && t.endpoints.length > 0) {
      lines.push({
        text: boxRow(
          chalk.dim("\u25b8") +
            " " +
            chalk.white(`${t.endpoints.length} endpoints found`)
        ),
        delay: MED,
      });
    }
  } else {
    const truncTarget = data.target.length > 30 ? data.target.slice(0, 27) + "..." : data.target;
    lines.push({
      text: boxRow(
        chalk.dim("\u25b8") +
          " " +
          chalk.white(`GET ${truncTarget}`) +
          chalk.dim(" \u2192 ") +
          chalk.white("200") +
          chalk.gray(" (LLM API detected)")
      ),
      delay: MED,
    });
  }

  lines.push({ text: boxBottom(true), delay: FAST });
  lines.push({ text: connector(), delay: PAUSE });

  // ── ATTACK lane ──
  lines.push({ text: boxTop("ATTACK"), delay: PAUSE });

  const vulnerableFindings = data.findings.filter(
    (f) => f.status !== "false-positive"
  );

  if (vulnerableFindings.length > 0) {
    for (const finding of vulnerableFindings.slice(0, 8)) {
      const truncTitle =
        finding.title.length > 30
          ? finding.title.slice(0, 27) + "..."
          : finding.title;

      let outcome = "VULNERABLE";
      const cat = finding.category;
      if (cat === "system-prompt-extraction") outcome = "LEAKED";
      if (cat === "jailbreak") outcome = "BYPASSED";

      lines.push({
        text: boxRow(
          chalk.dim("\u25b8") +
            " " +
            chalk.white(truncTitle) +
            chalk.dim(" \u2192 ") +
            "  " +
            outcomeLabel(outcome.toLowerCase())
        ),
        delay: MED,
      });
    }

    if (vulnerableFindings.length > 8) {
      lines.push({
        text: boxRow(
          chalk.gray(
            `  ... and ${vulnerableFindings.length - 8} more attacks`
          )
        ),
        delay: FAST,
      });
    }
  } else {
    lines.push({
      text: boxRow(
        chalk.dim("\u25b8") +
          " " +
          chalk.white(`${data.summary.totalAttacks} probes executed`) +
          chalk.dim(" \u2192 ") +
          chalk.green("ALL SAFE")
      ),
      delay: MED,
    });
  }

  lines.push({ text: boxBottom(true), delay: FAST });
  lines.push({ text: connector(), delay: PAUSE });

  // ── VERIFY lane ──
  lines.push({ text: boxTop("VERIFY"), delay: PAUSE });

  const confirmed = data.findings.filter(
    (f) => f.status === "confirmed" || f.status === "verified" || f.status === "scored" || f.status === "reported"
  );
  const falsePositives = data.findings.filter(
    (f) => f.status === "false-positive"
  );

  if (confirmed.length > 0 || data.findings.length > 0) {
    const reproduced = confirmed.length > 0 ? confirmed.length : data.findings.length;
    lines.push({
      text: boxRow(
        chalk.green("\u2713") +
          " " +
          chalk.white(`Reproduced ${reproduced}/${reproduced} findings`)
      ),
      delay: MED,
    });
  }

  if (falsePositives.length > 0) {
    lines.push({
      text: boxRow(
        chalk.red("\u2717") +
          " " +
          chalk.white(`Eliminated ${falsePositives.length} false positives`)
      ),
      delay: MED,
    });
  }

  if (confirmed.length === 0 && falsePositives.length === 0 && data.findings.length === 0) {
    lines.push({
      text: boxRow(chalk.green("\u2713") + " " + chalk.white("No findings to verify")),
      delay: MED,
    });
  }

  lines.push({ text: boxBottom(true), delay: FAST });
  lines.push({ text: connector(), delay: PAUSE });

  // ── REPORT lane ──
  lines.push({ text: boxTop("REPORT"), delay: PAUSE });

  const totalFindings = data.summary.totalFindings;
  if (totalFindings > 0) {
    const parts: string[] = [];
    if (data.summary.critical > 0) parts.push(chalk.red.bold(`${data.summary.critical} CRITICAL`));
    if (data.summary.high > 0) parts.push(chalk.redBright(`${data.summary.high} HIGH`));
    if (data.summary.medium > 0) parts.push(chalk.yellow(`${data.summary.medium} MEDIUM`));
    if (data.summary.low > 0) parts.push(chalk.blue(`${data.summary.low} LOW`));
    if (data.summary.info > 0) parts.push(chalk.gray(`${data.summary.info} INFO`));

    lines.push({
      text: boxRow(
        chalk.white(`${totalFindings} verified findings: `) + parts.join(chalk.dim(", "))
      ),
      delay: MED,
    });
  } else {
    lines.push({
      text: boxRow(chalk.green.bold("0 findings") + chalk.white(" - target appears secure")),
      delay: MED,
    });
  }

  const duration =
    data.durationMs < 1000
      ? `${data.durationMs}ms`
      : `${(data.durationMs / 1000).toFixed(1)}s`;
  lines.push({
    text: boxRow(
      chalk.white(`Completed in ${duration}`) +
        chalk.dim(" \u2192 ") +
        chalk.gray("./pwnkit-report.json")
    ),
    delay: MED,
  });

  lines.push({ text: boxBottom(false), delay: FAST });

  return lines;
}

// ── Animated replay (prints to stdout with delays) ──

export async function renderReplay(data: ReplayData): Promise<void> {
  const lines = buildReplayLines(data);

  // Banner
  process.stdout.write("\n");
  process.stdout.write(
    chalk.red.bold("  \u25c6 pwnkit") +
      chalk.gray(" attack replay") +
      "\n"
  );
  process.stdout.write(
    chalk.dim("  " + "\u2500".repeat(BOX_WIDTH + 1)) + "\n"
  );
  process.stdout.write("\n");

  await sleep(200);

  for (const line of lines) {
    await sleep(line.delay);
    process.stdout.write("  " + line.text + "\n");
  }

  process.stdout.write("\n");
}

// ── Static (non-animated) replay for piping/testing ──

export function renderReplayStatic(data: ReplayData): string {
  const lines = buildReplayLines(data);
  const output: string[] = [];

  output.push("");
  output.push(
    chalk.red.bold("  \u25c6 pwnkit") + chalk.gray(" attack replay")
  );
  output.push(chalk.dim("  " + "\u2500".repeat(BOX_WIDTH + 1)));
  output.push("");

  for (const line of lines) {
    output.push("  " + line.text);
  }

  output.push("");
  return output.join("\n");
}

// ── Live replay collector (accumulates events during scan, renders at end) ──

export interface ReplayCollector {
  onEvent: (event: {
    type: string;
    stage?: string;
    message: string;
    data?: unknown;
  }) => void;
  getReplayData: () => ReplayData;
}

export function createReplayCollector(target: string): ReplayCollector {
  let targetInfo: TargetInfo | undefined;
  const findings: Finding[] = [];
  const stages: Record<string, { startMs: number; endMs?: number }> = {};
  let totalAttacks = 0;
  let attacksDone = 0;
  const startMs = Date.now();

  return {
    onEvent(event) {
      switch (event.type) {
        case "stage:start":
          if (event.stage) {
            stages[event.stage] = { startMs: Date.now() };
          }
          if (event.stage === "attack") {
            const match = event.message.match(/(\d+)/);
            if (match) totalAttacks = parseInt(match[1], 10);
          }
          if (event.stage === "discovery" && event.data && typeof event.data === "object") {
            const d = event.data as Record<string, unknown>;
            if ("target" in d) {
              targetInfo = d.target as TargetInfo;
            }
          }
          break;

        case "stage:end":
          if (event.stage) {
            if (stages[event.stage]) {
              stages[event.stage].endMs = Date.now();
            }
          }
          if (
            event.stage === "discovery" &&
            event.data &&
            typeof event.data === "object"
          ) {
            const d = event.data as Record<string, unknown>;
            if ("target" in d) {
              targetInfo = d.target as TargetInfo;
            }
          }
          break;

        case "attack:end":
          attacksDone++;
          break;

        case "finding":
          if (event.data && typeof event.data === "object" && "id" in (event.data as Record<string, unknown>)) {
            findings.push(event.data as Finding);
          }
          break;
      }
    },

    getReplayData(): ReplayData {
      const durationMs = Date.now() - startMs;
      const critCount = findings.filter((f) => f.severity === "critical").length;
      const highCount = findings.filter((f) => f.severity === "high").length;
      const medCount = findings.filter((f) => f.severity === "medium").length;
      const lowCount = findings.filter((f) => f.severity === "low").length;
      const infoCount = findings.filter((f) => f.severity === "info").length;

      return {
        target,
        targetInfo,
        findings,
        summary: {
          totalAttacks: totalAttacks || attacksDone,
          totalFindings: findings.length,
          critical: critCount,
          high: highCount,
          medium: medCount,
          low: lowCount,
          info: infoCount,
        },
        durationMs,
      };
    },
  };
}

// ── Build ReplayData from a ScanReport (for --replay / replay command) ──

export function replayDataFromReport(report: ScanReport): ReplayData {
  return {
    target: report.target,
    findings: report.findings,
    summary: report.summary,
    durationMs: report.durationMs,
    warnings: report.warnings,
  };
}

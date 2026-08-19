import { execFileSync } from "node:child_process";
import type { SemgrepFinding } from "@0sec/shared";
import type { RuntimeType } from "./runtime/index.js";
import type { ScanListener } from "./scanner.js";

/**
 * Pinned Foxguard release used by `runFoxguardScan`. We pin to the latest
 * stable release (https://github.com/0sec-labs/foxguard/releases) rather
 * than tracking `main` or `latest` so the ablation harness produces
 * reproducible numbers across runs.
 *
 * v0.10.0 (2026-06) — latest stable:
 *   - Haskell parser support and built-in Cardano Haskell seed rules
 *   - Semgrep/OpenGrep compatibility loadability ~96% of the tracked registry
 *   - VS Code suppressions routed through the Rust config editor
 *
 * v0.9.0 (2026-06):
 *   - HCL / Terraform grammar (terraform registry rule pack now loads)
 *   - Semgrep generic/spacegrep mode + regex-language alias
 *   - Semgrep-compat parity: metavariable-pattern/-comparison, focus-metavariable,
 *     taint mode for Python/JS/Go/Java/C/Kotlin + extra sink shapes, fix-suggestions
 *   - registry-coverage harness (loadability ~37% -> ~61% of the semgrep registry)
 *
 * v0.8.1 (2026-05-16):
 *   - Hardens SARIF for GitHub Code Scanning
 *   - C kernel rule pack (Dirty Frag) shipped via Semgrep-YAML bridge
 *   - Accurate scan-skipped counts in reporters
 */
export const FOXGUARD_PINNED_TAG = "v0.10.0";

/**
 * CLI runtimes (claude, codex, etc.) are full agents — they can read files,
 * run commands, and do multi-turn analysis natively. We bypass our own agent
 * loop and let the CLI handle everything, then parse findings from its output.
 */
export const CLI_RUNTIME_TYPES = new Set<RuntimeType>(["claude", "codex", "gemini", ]);

export function bufferToString(value: Buffer | string | undefined): string {
  if (!value) {
    return "";
  }
  return Buffer.isBuffer(value) ? value.toString("utf-8") : value;
}

export function mapSemgrepSeverity(level: string): string {
  switch (level.toUpperCase()) {
    case "ERROR":
      return "high";
    case "WARNING":
      return "medium";
    case "INFO":
      return "low";
    default:
      return "info";
  }
}

function mapFoxguardSeverity(level: string | undefined): string {
  switch ((level ?? "").toLowerCase()) {
    case "error":
    case "critical":
      return "critical";
    case "warning":
    case "high":
      return "high";
    case "note":
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
}

/**
 * Run semgrep security scan against a directory.
 * Returns parsed findings from JSON output.
 *
 * @param targetPath - Path to scan
 * @param emit - Event listener for progress updates
 * @param opts.noGitIgnore - Pass --no-git-ignore flag (used for installed packages outside a git repo)
 */
export function runSemgrepScan(
  targetPath: string,
  emit: ScanListener,
  opts?: { noGitIgnore?: boolean; paths?: string[] },
): SemgrepFinding[] {
  emit({
    type: "stage:start",
    stage: "source-analysis",
    message: "Running semgrep security scan...",
  });

  const args = [
    "scan",
    "--config",
    "auto",
    "--json",
    ...(opts?.noGitIgnore ? ["--no-git-ignore"] : []),
    "--timeout",
    "60",
    "--max-target-bytes",
    "1000000",
    ...(opts?.paths && opts.paths.length > 0 ? opts.paths : [targetPath]),
  ];

  let rawOutput = "";

  try {
    rawOutput = execFileSync("semgrep", args, {
      timeout: 300_000, // 5 min max for semgrep
      stdio: "pipe",
      encoding: "utf-8",
      env: { ...process.env, SEMGREP_SEND_METRICS: "off" },
    });
  } catch (err) {
    const stdout =
      err && typeof err === "object" && "stdout" in err
        ? (err.stdout as Buffer | string | undefined)
        : undefined;
    rawOutput = bufferToString(stdout);
  }

  let findings: SemgrepFinding[] = [];

  if (rawOutput.trim()) {
    try {
      const raw = JSON.parse(rawOutput);
      const results = (raw.results ?? []) as Array<{
        check_id: string;
        extra: {
          message: string;
          severity: string;
          lines: string;
          metadata?: Record<string, unknown>;
        };
        path: string;
        start: { line: number };
        end: { line: number };
      }>;

      findings = results.map((r) => ({
        ruleId: r.check_id,
        message: r.extra?.message ?? "",
        severity: mapSemgrepSeverity(r.extra?.severity ?? "WARNING"),
        path: r.path,
        startLine: r.start?.line ?? 0,
        endLine: r.end?.line ?? 0,
        snippet: r.extra?.lines ?? "",
        metadata: r.extra?.metadata,
      }));
    } catch {
      // JSON parse failed — semgrep output was malformed
    }
  }

  emit({
    type: "stage:end",
    stage: "source-analysis",
    message: `Semgrep: ${findings.length} findings`,
  });

  return findings;
}

export interface StaticScannerOptions {
  noGitIgnore?: boolean;
  paths?: string[];
}

export function selectedStaticScanner(): "foxguard" | "semgrep" {
  return process.env["0SEC_STATIC"] === "semgrep" ? "semgrep" : "foxguard";
}

/**
 * Raw JSON shape emitted by `foxguard --format json` (top-level array of
 * Finding structs). Source of truth:
 * https://github.com/0sec-labs/foxguard/blob/v0.10.0/src/lib.rs
 *
 * Severity is `low | medium | high | critical` (lowercase). Optional
 * fields are omitted from the JSON when unset, so the translator must
 * treat them as `undefined`-tolerant.
 */
interface FoxguardJsonFinding {
  rule_id: string;
  severity: string;
  cwe?: string | null;
  description: string;
  file: string;
  line: number;
  column?: number;
  end_line?: number;
  end_column?: number;
  snippet?: string;
  source_line?: number;
  source_description?: string;
  sink_line?: number;
  sink_description?: string;
  fix_suggestion?: string;
  confidence?: number;
  taint_hops?: number;
  tags?: string[];
  crypto_algorithm?: string;
  cnsa2_deadline?: string;
  dep_name?: string;
}

/**
 * Run foxguard as a sibling source analyzer and translate its JSON output
 * into 0sec's `SemgrepFinding` shape so the existing review pipeline can
 * consume either scanner without changing prompt/report contracts.
 *
 * Behaviour:
 *  - Foxguard is invoked via `npx --yes foxguard@<pinned-tag>` so the
 *    binary doesn't need to be pre-installed in CI sandboxes.
 *  - If foxguard cannot be launched (binary truly missing — `npx` itself
 *    is absent, or the package fails to download), we *fall back to
 *    semgrep silently* with a warning logged to stderr. The pipeline
 *    must never crash because the experimental scanner is unavailable.
 *  - Pipeline-level warnings (the structured ones surfaced in
 *    `report.warnings`) are still emitted by the unified-pipeline call
 *    site if the fallback itself throws.
 *
 * @param targetPath  Absolute path to scan.
 * @param emit        ScanListener for stage start/end events.
 * @param opts        Test seams (custom `runner`, override
 *                    `foxguardCommand`, alternative `semgrepFallback`).
 */
export function runFoxguardScan(
  targetPath: string,
  emit: ScanListener,
  opts?: {
    /** Override the launcher (default: `npx`). */
    foxguardCommand?: string;
    /** Override the pinned tag (default: `FOXGUARD_PINNED_TAG`). */
    foxguardTag?: string;
    /** Inject a custom subprocess runner (used in unit tests). */
    runner?: typeof execFileSync;
    /** Fallback scanner — defaults to `runSemgrepScan`. */
    semgrepFallback?: (
      targetPath: string,
      emit: ScanListener,
      opts?: StaticScannerOptions,
    ) => SemgrepFinding[];
    /** Logger for the missing-binary warning (default: `console.warn`). */
    logger?: (message: string) => void;
    /** Optional narrowed file list for diff-aware reviews. */
    paths?: string[];
    /** Preserve package-audit fallback behavior when foxguard is unavailable. */
    noGitIgnore?: boolean;
  },
): SemgrepFinding[] {
  emit({
    type: "stage:start",
    stage: "source-analysis",
    message: "Running foxguard security scan...",
  });

  const foxguardCommand = opts?.foxguardCommand ?? "npx";
  const foxguardTag = opts?.foxguardTag ?? FOXGUARD_PINNED_TAG;
  const runner = opts?.runner ?? execFileSync;
  const fallback = opts?.semgrepFallback ?? runSemgrepScan;
  const logger = opts?.logger ?? ((m) => console.warn(m));
  const scanPaths = opts?.paths && opts.paths.length > 0 ? opts.paths : [targetPath];

  const args = ["--yes", `foxguard@${foxguardTag}`, "--format", "json", ...scanPaths];

  let rawOutput = "";
  try {
    rawOutput = bufferToString(
      runner(foxguardCommand, args, {
        timeout: 300_000,
        stdio: "pipe",
        encoding: "utf-8",
      }) as unknown as Buffer | string,
    );
  } catch (err) {
    // Foxguard exits non-zero whenever it finds at least one issue; that's
    // not a fatal error and the JSON still lands on stdout. Treat the
    // captured stdout as the result and only fall back if it's empty.
    const stdout =
      err && typeof err === "object" && "stdout" in err
        ? (err as { stdout?: Buffer | string }).stdout
        : undefined;
    rawOutput = bufferToString(stdout);

    if (!rawOutput.trim()) {
      // Likely the binary is missing or the npm install failed. Fall
      // back to semgrep silently so the pipeline keeps moving.
      const message = err instanceof Error ? err.message : String(err);
      logger(
        `[0sec] foxguard unavailable (${message}); falling back to semgrep. ` +
          `Pin in use: foxguard@${foxguardTag}.`,
      );
      const fallbackFindings = fallback(targetPath, emit, {
        ...(opts?.paths ? { paths: opts.paths } : {}),
        ...(opts?.noGitIgnore ? { noGitIgnore: true } : {}),
      });
      // The fallback already emits its own stage:end; nothing more to do.
      return fallbackFindings;
    }
  }

  const findings = translateFoxguardJson(rawOutput);

  emit({
    type: "stage:end",
    stage: "source-analysis",
    message: `Foxguard: ${findings.length} findings`,
  });

  return findings;
}

export function runSelectedStaticScan(
  targetPath: string,
  emit: ScanListener,
  opts?: StaticScannerOptions,
): SemgrepFinding[] {
  return selectedStaticScanner() === "foxguard"
    ? runFoxguardScan(targetPath, emit, opts)
    : runSemgrepScan(targetPath, emit, opts);
}

/**
 * Translator: Foxguard JSON findings → `SemgrepFinding[]`.
 *
 * The shapes are close but not identical:
 *   - `rule_id`           → `ruleId`
 *   - `description`       → `message`
 *   - `file`              → `path`
 *   - `line` / `end_line` → `startLine` / `endLine` (end_line defaults
 *                          to startLine when missing — Foxguard omits
 *                          it for some single-line patterns)
 *   - `severity`          → `severity` (already in 0sec's 4-tier
 *                          vocabulary; we normalize via
 *                          `mapFoxguardSeverity` so unexpected values
 *                          land on `info` instead of leaking through)
 *   - `snippet`           → `snippet` (empty string when absent)
 *   - taint dataflow / CWE / fix suggestion → `metadata` so downstream
 *                          prompts can still surface them
 *
 * Edge cases:
 *   - Missing top-level array → return `[]` (e.g. when foxguard logs a
 *     parse warning to stdout instead of the array; we never throw).
 *   - Missing required fields (`rule_id`, `file`, `line`) → skip that
 *     entry; the rest still surface.
 */
export function translateFoxguardJson(rawJson: string): SemgrepFinding[] {
  if (!rawJson.trim()) return [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJson);
  } catch {
    return [];
  }

  if (!Array.isArray(parsed)) return [];

  const out: SemgrepFinding[] = [];
  for (const raw of parsed as FoxguardJsonFinding[]) {
    if (!raw || typeof raw !== "object") continue;
    if (!raw.rule_id || !raw.file || typeof raw.line !== "number") continue;

    const startLine = raw.line;
    const endLine = typeof raw.end_line === "number" ? raw.end_line : startLine;

    const metadata: Record<string, unknown> = { scanner: "foxguard" };
    if (raw.cwe) metadata.cwe = raw.cwe;
    if (typeof raw.confidence === "number") metadata.confidence = raw.confidence;
    if (typeof raw.taint_hops === "number") metadata.taintHops = raw.taint_hops;
    if (raw.source_line || raw.sink_line) {
      metadata.dataflow = {
        sourceLine: raw.source_line,
        sourceDescription: raw.source_description,
        sinkLine: raw.sink_line,
        sinkDescription: raw.sink_description,
      };
    }
    if (raw.fix_suggestion) metadata.fixSuggestion = raw.fix_suggestion;
    if (raw.tags && raw.tags.length > 0) metadata.tags = raw.tags;
    if (raw.crypto_algorithm) metadata.cryptoAlgorithm = raw.crypto_algorithm;
    if (raw.cnsa2_deadline) metadata.cnsa2Deadline = raw.cnsa2_deadline;
    if (raw.dep_name) metadata.depName = raw.dep_name;

    out.push({
      ruleId: raw.rule_id,
      message: raw.description ?? "",
      severity: mapFoxguardSeverity(raw.severity),
      path: raw.file,
      startLine,
      endLine,
      snippet: raw.snippet ?? "",
      metadata,
    });
  }
  return out;
}

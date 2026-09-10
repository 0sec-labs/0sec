import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { SemgrepFinding } from "@0sec/shared";
import type { RuntimeType } from "./runtime/index.js";
import type { ScanListener } from "./scanner.js";

/**
 * Release used by the npm launcher when Foxguard is not provisioned locally.
 * Keep this aligned with the published finding contract and cloud runtime.
 */
export const FOXGUARD_PINNED_TAG = "v0.12.0";

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
  opts?: StaticScannerOptions,
): SemgrepFinding[] {
  emit({
    type: "stage:start",
    stage: "source-analysis",
    message: "Running semgrep security scan...",
  });
  if (opts?.paths?.length === 0) {
    emit({ type: "stage:end", stage: "source-analysis", message: "Semgrep: no files selected" });
    return [];
  }
  const args = [
    "scan", "--config", "auto", "--json",
    ...(opts?.noGitIgnore ? ["--no-git-ignore"] : []),
    "--timeout", "60", "--max-target-bytes", "1000000",
    ...(opts?.paths ?? [targetPath]),
  ];
  let rawOutput: string;
  try {
    rawOutput = execFileSync("semgrep", args, {
      timeout: 300_000,
      stdio: "pipe",
      encoding: "utf-8",
      env: { ...process.env, SEMGREP_SEND_METRICS: "off" },
    });
  } catch (err) {
    if (!err || typeof err !== "object" || !("status" in err) || err.status !== 1) throw err;
    rawOutput = bufferToString("stdout" in err ? err.stdout as Buffer | string : undefined);
  }
  const raw = JSON.parse(rawOutput);
  if (!raw || !Array.isArray(raw.results)) throw new Error("invalid Semgrep JSON report");
  const results = raw.results as Array<{
    check_id: string;
    extra?: { message?: string; severity?: string; lines?: string; metadata?: Record<string, unknown> };
    path: string;
    start?: { line: number };
    end?: { line: number };
  }>;
  const findings = results.map((r) => ({
    ruleId: r.check_id,
    message: r.extra?.message ?? "",
    severity: mapSemgrepSeverity(r.extra?.severity ?? "WARNING"),
    path: r.path,
    startLine: r.start?.line ?? 0,
    endLine: r.end?.line ?? 0,
    snippet: r.extra?.lines ?? "",
    metadata: r.extra?.metadata,
  }));
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
  /** Git revision used by a diff-aware Foxguard scan. */
  diffBase?: string;
}

export function selectedStaticScanner(): "foxguard" | "semgrep" {
  return process.env["0SEC_STATIC"] === "semgrep" ? "semgrep" : "foxguard";
}

/**
 * Native v1 finding fields, also accepted in legacy bare-array reports.
 * https://github.com/0sec-labs/foxguard/blob/v0.12.0/schemas/finding-v1.schema.json
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
 * Uses an installed Foxguard binary when available, otherwise the pinned npm
 * release. Scanner failure always propagates — no Semgrep fallback path.
 * Set `0SEC_STATIC=semgrep` (via {@link runSelectedStaticScan}) to use
 * Semgrep instead.
 *
 * @param targetPath  Absolute path to scan.
 * @param emit        ScanListener for stage start/end events.
 * @param opts        Test seams (custom `runner`, override
 *                    `foxguardCommand`).
 */
export function runFoxguardScan(
  targetPath: string,
  emit: ScanListener,
  opts?: {
    /** Override the npm launcher; bypasses local binary discovery when set. */
    foxguardCommand?: string;
    /** Override the pinned tag (default: `FOXGUARD_PINNED_TAG`). */
    foxguardTag?: string;
    /** Inject a custom subprocess runner (used in unit tests). */
    runner?: typeof execFileSync;
    /** Logger for the missing-binary warning (default: `console.warn`). */
    logger?: (message: string) => void;
    /** Optional narrowed file list for diff-aware reviews. */
    paths?: string[];
    /** Git revision for Foxguard's native `diff` subcommand. */
    diffBase?: string;
    /** Semgrep-only option accepted by the shared scanner dispatcher. */
    noGitIgnore?: boolean;
  },
): SemgrepFinding[] {
  emit({
    type: "stage:start",
    stage: "source-analysis",
    message: "Running foxguard security scan...",
  });
  if (opts?.paths?.length === 0) {
    emit({ type: "stage:end", stage: "source-analysis", message: "Foxguard: no files selected" });
    return [];
  }

  const foxguardTag = opts?.foxguardTag ?? FOXGUARD_PINNED_TAG;
  const runner = opts?.runner ?? execFileSync;
  const logger = opts?.logger ?? ((m) => console.warn(m));
  // Anchor the scan at the requested source root. An ancestor named
  // node_modules/dist must not make the explicitly requested package "noise".
  const cwd = statSync(targetPath, { throwIfNoEntry: false })?.isFile()
    ? dirname(resolve(targetPath))
    : resolve(targetPath);
  let useNpm = opts?.foxguardCommand !== undefined || opts?.foxguardTag !== undefined;
  const findings: SemgrepFinding[] = [];
  let selectionDir: string | undefined;

  try {
    let selectionFile: string | undefined;
    if (opts?.paths && !opts.diffBase) {
      const paths = opts.paths.map((path) => {
        const selected = relative(cwd, resolve(cwd, path));
        if (isAbsolute(selected) || selected === ".." || selected.startsWith(`..${sep}`) || /[\r\n\0]/.test(selected)) {
          throw new Error(`selected Foxguard path is outside the scan root or cannot be represented: ${path}`);
        }
        return selected.split(sep).join("/");
      });
      selectionDir = mkdtempSync(join(tmpdir(), "0sec-foxguard-"));
      selectionFile = join(selectionDir, "changed-files.txt");
      writeFileSync(selectionFile, `${paths.join("\n")}\n`, { mode: 0o600 });
    }
    // A single root scan retains cross-file taint context for selected files.
    const scanRoot = relative(cwd, resolve(targetPath)) || ".";
    const invocations = [opts?.diffBase
      ? ["diff", opts.diffBase, scanRoot, "--format", "json"]
      : ["--format", "json", ...(selectionFile ? ["--changed-files-from", selectionFile] : []), scanRoot]];
    for (const args of invocations) {
      let rawOutput: string;
      const invoke = (): string => {
        try {
          return bufferToString(runner(
            useNpm ? opts?.foxguardCommand ?? "npx" : "foxguard",
            useNpm ? ["--yes", `foxguard@${foxguardTag}`, ...args] : args,
            {
              cwd,
              timeout: 300_000,
              maxBuffer: 64 * 1024 * 1024,
              stdio: "pipe",
              encoding: "utf-8",
            },
          ) as unknown as Buffer | string);
        } catch (err) {
          // Exit 1 is Foxguard's findings status. Other exits and signals are
          // failures, even when the process left partial JSON on stdout.
          if (err && typeof err === "object" && "status" in err && err.status === 1) {
            return bufferToString("stdout" in err ? err.stdout as Buffer | string : undefined);
          }
          throw err;
        }
      };
      try {
        rawOutput = invoke();
      } catch (err) {
        if (!useNpm && err && typeof err === "object" && "code" in err && err.code === "ENOENT") {
          useNpm = true;
          rawOutput = invoke();
        } else {
          throw err;
        }
      }
      const report = parseFoxguardJson(rawOutput);
      if (report === null) throw new Error("invalid Foxguard JSON report");
      if (report.filesScanned === 0) {
        throw new Error("Foxguard scanned 0 files; static coverage is unavailable (files may be excluded or unsupported)");
      }
      for (const finding of translateFoxguardFindings(report.findings)) {
        finding.path = resolve(cwd, finding.path);
        findings.push(finding);
      }
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger(
      `[0sec] foxguard scan failed (${message}). ` +
        `Npm pin: foxguard@${foxguardTag}. Set 0SEC_STATIC=semgrep to use semgrep.`,
    );
    emit({ type: "error", stage: "source-analysis", message: `Foxguard scan failed: ${message}` });
    throw err;
  } finally {
    if (selectionDir) rmSync(selectionDir, { recursive: true, force: true });
  }

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
 *   - Invalid report → return `[]`; the runner detects invalid output
 *     separately and throws rather than reporting a clean scan.
 *   - Missing required fields (`rule_id`, `file`, `line`) → skip that
 *     entry; the rest still surface.
 */
export function translateFoxguardJson(rawJson: string): SemgrepFinding[] {
  return translateFoxguardFindings(parseFoxguardJson(rawJson)?.findings ?? []);
}

function parseFoxguardJson(rawJson: string): { findings: FoxguardJsonFinding[]; filesScanned?: number } | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJson);
  } catch {
    return null;
  }
  if (Array.isArray(parsed)) return { findings: parsed };
  if (!parsed || typeof parsed !== "object" || !("findings" in parsed)) return null;
  for (const field of ["schema_version", "finding_schema_version"] as const) {
    if (field in parsed && !/^1\.\d+\.\d+$/.test(String(parsed[field as keyof typeof parsed]))) {
      return null;
    }
  }
  if (!Array.isArray(parsed.findings)) return null;
  const target = "target" in parsed ? parsed.target : undefined;
  const filesScanned = target && typeof target === "object" && "files_scanned" in target
    ? target.files_scanned : undefined;
  if (filesScanned !== undefined && (typeof filesScanned !== "number" || !Number.isSafeInteger(filesScanned) || filesScanned < 0)) return null;
  return { findings: parsed.findings, ...(typeof filesScanned === "number" ? { filesScanned } : {}) };
}

function translateFoxguardFindings(rawFindings: FoxguardJsonFinding[]): SemgrepFinding[] {
  const out: SemgrepFinding[] = [];
  for (const raw of rawFindings) {
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

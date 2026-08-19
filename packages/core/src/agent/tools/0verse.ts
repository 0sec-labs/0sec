/**
 * `analyze_binary` agent tool — a thin, agent-callable bridge to **0verse**,
 * the binary-native / no-source CRS (see `docs/design/0verse-pwnkit-integration.md`).
 *
 * This tool is OPT-IN and modeled on the endorsed **kernel-run** pattern
 * (`tools/kernel-run.ts` + `verify/kernel-verify.ts`): it is deliberately NOT in
 * the global `TOOL_DEFINITIONS` table nor returned by `getToolsForRole`. It is
 * meant to be injected only into a dedicated, bounded binary-target sub-loop
 * with a wall-clock deadline, so web/audit agents can never spawn a
 * minutes-long binary hunt by accident. No branch is added to the `tools.ts`
 * god-module (house rule) — this is a self-contained module.
 *
 * Thin first cut (per §3/§6-P1 of the scoping doc): a single
 * `0verse scan <binary> --format ndjson` invocation, spawned via a **dedicated**
 * launcher allowlist (the web-scanner allowlist in `scanner-tools.ts` is NOT
 * widened), parsed into a structured `ToolResult` the way `parseNucleiOutput`
 * parses nuclei's JSONL. It is NOT the full fuzzing sub-loop.
 *
 * Contract discipline (AIxCC T9, same as kernel-run):
 *   - Args are parsed against {@link overseArgsSchema} and *rejected* on a
 *     mismatch before any subprocess is spawned. Unknown top-level keys are
 *     stripped so a model-emitted `argv`/`cwd` can never propagate downstream.
 *   - **PoV-is-truth**: only ndjson findings with `confirmed:true` (a
 *     reproducing PoV attached) are surfaced as verified; everything else stays
 *     a ranked *hypothesis* the agent may reason about but must never report as
 *     a confirmed finding. This mirrors `mapOversePoVToCloudFinding` on the
 *     cloud side (`@0cloud/cloud-contracts` `zeroverse.ts`).
 *
 * The 0verse ndjson contract (0verse `api.result_to_ndjson`, CONTRACT_VERSION
 * 1.x): line 1 is a `{"_meta": {...}}` header carrying `contract_version`; each
 * subsequent line is one flat `ScanFinding`. We validate the MAJOR of
 * `contract_version` before trusting the stream.
 */

import { z } from "zod";
import type { ToolDefinition, ToolResult } from "../types.js";
import {
  superviseChild,
  type ScannerProcessOutcome,
} from "../scanner-tools.js";
import { spawn, type ChildProcess, type SpawnOptions } from "node:child_process";

// ── Bounds ──────────────────────────────────────────────────────────────────

/** The one binary this module will ever exec — a DEDICATED allowlist. */
export const ZEROVERSE_BINARY = "0verse";

/** MAJOR of the 0verse ndjson contract this parser understands. */
export const ZEROVERSE_SUPPORTED_CONTRACT_MAJOR = "1";

/** Max length of the `binary_path` argument (defense against giant blobs). */
export const ZEROVERSE_BINARY_PATH_MAX = 4096;

/**
 * Hard wall-clock ceiling (ms) for a single `analyze_binary` call. A binary
 * hunt is minutes-long; the requested `timeout_s` is clamped to this ceiling in
 * the executor (the design's "clamped in the loop, not the tool" — realized
 * here since this thin cut IS the bounded step). 30 min mirrors kernel-run.
 */
export const ZEROVERSE_WALLCLOCK_CEILING_MS = 30 * 60 * 1000;

/** Default per-call timeout (ms) when the model omits `timeout_s`. */
export const ZEROVERSE_DEFAULT_TIMEOUT_MS = 8 * 60 * 1000;

const BUG_CLASS_ENUM = [
  "memory-safety",
  "intoverflow",
  "fmtstring",
  "uaf",
  "cmdi",
  "logic",
] as const;

const BACKEND_ENUM = ["auto", "ghidra", "rizin", "angr"] as const;

// ── Tool definition (metadata only) ─────────────────────────────────────────

export const ZEROVERSE_TOOL_DEFINITION: ToolDefinition = {
  name: "analyze_binary",
  description:
    "Run 0verse (the binary-native, no-source analyzer) on a compiled artifact " +
    "to hunt memory-safety bugs and emit a reproducing PoV. Returns CONFIRMED " +
    "findings (a real reproducing PoV is attached) and ranked HYPOTHESES " +
    "(static/LLM leads with NO PoV — never treat these as verified). Use this " +
    "for closed-source x86-64 Linux userland binaries where source-level review " +
    "cannot reach. Minutes-long; one call per artifact.",
  parameters: {
    binary_path: {
      type: "string",
      description:
        "Path to the target artifact (ELF) in the run's workspace. Required.",
    },
    bug_class: {
      type: "string",
      description:
        "Bug-class lens to prioritise. Default 'memory-safety'.",
      enum: [...BUG_CLASS_ENUM],
    },
    backend: {
      type: "string",
      description:
        "Decompiler/lift backend. Default 'auto'.",
      enum: [...BACKEND_ENUM],
    },
    timeout_s: {
      type: "number",
      description:
        "Requested wall-clock budget in seconds. Clamped to a hard ceiling by " +
        "the loop; omit to use the default.",
    },
  },
  required: ["binary_path"],
};

// ── Argument schema (validated + stripped; AIxCC T9) ─────────────────────────

export interface OverseArgs {
  binary_path: string;
  bug_class: (typeof BUG_CLASS_ENUM)[number];
  backend: (typeof BACKEND_ENUM)[number];
  timeout_s?: number;
}

export const overseArgsSchema = z
  .object({
    binary_path: z
      .string({
        required_error: "analyze_binary: 'binary_path' must be a non-empty string",
        invalid_type_error: "analyze_binary: 'binary_path' must be a non-empty string",
      })
      .min(1, "analyze_binary: 'binary_path' must be a non-empty string")
      .max(
        ZEROVERSE_BINARY_PATH_MAX,
        `analyze_binary: 'binary_path' exceeds ${ZEROVERSE_BINARY_PATH_MAX} chars`,
      ),
    bug_class: z
      .enum(BUG_CLASS_ENUM, {
        errorMap: () => ({
          message: `analyze_binary: 'bug_class' must be one of ${BUG_CLASS_ENUM.join("|")}`,
        }),
      })
      .default("memory-safety"),
    backend: z
      .enum(BACKEND_ENUM, {
        errorMap: () => ({
          message: `analyze_binary: 'backend' must be one of ${BACKEND_ENUM.join("|")}`,
        }),
      })
      .default("auto"),
    timeout_s: z
      .number({ invalid_type_error: "analyze_binary: 'timeout_s' must be a number" })
      .positive("analyze_binary: 'timeout_s' must be positive")
      .nullish()
      .transform((n) => (n == null ? undefined : n)),
  })
  .strip()
  .transform((parsed): OverseArgs => ({
    binary_path: parsed.binary_path,
    bug_class: parsed.bug_class,
    backend: parsed.backend,
    ...(parsed.timeout_s !== undefined ? { timeout_s: parsed.timeout_s } : {}),
  }));

/**
 * Validate a raw tool-call bag. Returns a discriminated union so the loop can
 * feed a rejection straight back as an `is_error` tool_result without spawning.
 */
export function validateOverseArgs(raw: unknown):
  | { ok: true; args: OverseArgs }
  | { ok: false; error: string } {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { ok: false, error: "analyze_binary: arguments must be an object" };
  }
  const parsed = overseArgsSchema.safeParse(raw);
  if (!parsed.success) {
    return {
      ok: false,
      error: parsed.error.issues[0]?.message ?? "analyze_binary: invalid arguments",
    };
  }
  return { ok: true, args: parsed.data };
}

// ── Parsed ndjson shapes ─────────────────────────────────────────────────────

/**
 * One flat finding line from the 0verse ndjson contract (0verse
 * `api.ScanFinding.to_dict()`). Field names match the wire contract 1:1 so a
 * confirmed finding lines up with `OversePoV` on the cloud-contracts side.
 */
export interface OverseScanFinding {
  id: string;
  bug_class: string;
  severity: string;
  file: string;
  function: string;
  offset: string;
  source: string;
  sink: string;
  confirmed: boolean;
  hypothesis: boolean;
  pruned: boolean;
  capability: string;
  pov_path: string;
  repro_cmd: string;
  dedup_bucket: string;
  explanation: string;
  crash_output: string | null;
  confidence: number | null;
  patch_available: boolean;
  patch_verified: boolean;
  patch_mode: string;
  patch_path: string | null;
  patch_recommendation: string | null;
  patch_regression: string | null;
}

export interface OverseScanMeta {
  contract_version: string;
  tool?: unknown;
  binary?: string;
  format?: string;
  arch?: string;
  backend?: string;
  stages_run?: unknown;
  confirmed_count?: number;
  note?: string;
}

export interface OverseParsedResult {
  /** contract_version from the `_meta` header, or "" if none seen. */
  contractVersion: string;
  /** Whether the MAJOR of contract_version is supported by this parser. */
  compatible: boolean;
  meta?: OverseScanMeta;
  /** confirmed:true — a reproducing PoV is attached (PoV-is-truth). */
  confirmed: OverseScanFinding[];
  /** confirmed:false — ranked leads; NEVER promoted to verified. */
  hypotheses: OverseScanFinding[];
  /** Honest degrade reason surfaced by 0verse (static-only host, no-backend…). */
  note: string;
  /** Last slice of raw output for eyeballing on a parse miss. */
  rawTail: string;
}

function contractMajor(version: string): string {
  return String(version).split(".", 1)[0] ?? "";
}

function tail(text: string, n = 1200): string {
  return text.length > n ? text.slice(text.length - n) : text;
}

function coerceFinding(obj: Record<string, unknown>): OverseScanFinding {
  const str = (k: string): string =>
    typeof obj[k] === "string" ? (obj[k] as string) : "";
  const strOrNull = (k: string): string | null =>
    typeof obj[k] === "string" ? (obj[k] as string) : null;
  const bool = (k: string): boolean => obj[k] === true;
  return {
    id: str("id"),
    bug_class: str("bug_class"),
    severity: str("severity") || "unknown",
    file: str("file"),
    function: str("function"),
    offset: str("offset"),
    source: str("source"),
    sink: str("sink"),
    confirmed: bool("confirmed"),
    hypothesis: bool("hypothesis"),
    pruned: bool("pruned"),
    capability: str("capability"),
    pov_path: str("pov_path"),
    repro_cmd: str("repro_cmd"),
    dedup_bucket: str("dedup_bucket"),
    explanation: str("explanation"),
    crash_output: strOrNull("crash_output"),
    confidence: typeof obj.confidence === "number" ? (obj.confidence as number) : null,
    patch_available: bool("patch_available"),
    patch_verified: bool("patch_verified"),
    patch_mode: str("patch_mode") || "none",
    patch_path: strOrNull("patch_path"),
    patch_recommendation: strOrNull("patch_recommendation"),
    patch_regression: strOrNull("patch_regression"),
  };
}

/**
 * Parse the 0verse `scan --format ndjson` stream. Mirrors `parseNucleiOutput`:
 * one JSON object per line, tolerant of banner/partial lines. The FIRST valid
 * `{"_meta": {...}}` line carries the contract version; every other object line
 * is a finding. PoV-is-truth split: `confirmed:true` -> confirmed, else
 * hypothesis. On a MAJOR contract mismatch we still return the findings but flag
 * `compatible:false` so the executor can degrade honestly.
 */
export function parseOverseNdjson(raw: string): OverseParsedResult {
  let meta: OverseScanMeta | undefined;
  let contractVersion = "";
  const confirmed: OverseScanFinding[] = [];
  const hypotheses: OverseScanFinding[] = [];

  for (const line of raw.split(/\r?\n/)) {
    const s = line.trim();
    if (!s.startsWith("{")) continue;
    let obj: Record<string, unknown>;
    try {
      obj = JSON.parse(s) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (obj._meta && typeof obj._meta === "object" && !Array.isArray(obj._meta)) {
      const m = obj._meta as Record<string, unknown>;
      contractVersion =
        typeof m.contract_version === "string" ? (m.contract_version as string) : "";
      meta = {
        contract_version: contractVersion,
        tool: m.tool,
        binary: typeof m.binary === "string" ? m.binary : undefined,
        format: typeof m.format === "string" ? m.format : undefined,
        arch: typeof m.arch === "string" ? m.arch : undefined,
        backend: typeof m.backend === "string" ? m.backend : undefined,
        stages_run: m.stages_run,
        confirmed_count:
          typeof m.confirmed_count === "number" ? m.confirmed_count : undefined,
        note: typeof m.note === "string" ? m.note : undefined,
      };
      continue;
    }
    // A finding line carries the `confirmed` discriminator.
    if (typeof obj.confirmed !== "boolean") continue;
    const finding = coerceFinding(obj);
    if (finding.confirmed) confirmed.push(finding);
    else hypotheses.push(finding);
  }

  const compatible =
    contractVersion === "" ||
    contractMajor(contractVersion) === ZEROVERSE_SUPPORTED_CONTRACT_MAJOR;

  return {
    contractVersion,
    compatible,
    meta,
    confirmed,
    hypotheses,
    note: typeof meta?.note === "string" ? meta.note : "",
    rawTail: tail(raw),
  };
}

// ── Dedicated launcher (NOT the web-scanner allowlist) ───────────────────────

/**
 * Spawn `0verse` and ONLY `0verse`. The command passed to `spawn` is a string
 * LITERAL (never a variable), so there is no dynamic-command sink and a `bin`
 * outside the single allowed value returns null (fail-closed). `shell:false`
 * means `argv` is never re-parsed by a shell — each element is a verbatim
 * execve arg, so target-controlled strings in the path can't break out. The
 * child leads its own process group so the supervisor can reap forked helpers.
 *
 * This is intentionally a SEPARATE allowlist from `ALLOWED_SCANNER_BINARIES` in
 * `scanner-tools.ts` — the web-scanner surface is not widened.
 */
export function launchOverseBinary(
  bin: string,
  argv: string[],
  env: Record<string, string>,
): ChildProcess | null {
  if (bin !== ZEROVERSE_BINARY) return null;
  const spawnOpts: SpawnOptions = {
    env,
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
    shell: false,
  };
  return spawn("0verse", argv, spawnOpts);
}

/**
 * Run `0verse` under the shared wallclock supervisor (`superviseChild`). Refuses
 * fail-closed for any `bin` other than `0verse`, then reuses the exact
 * timeout/partial-output/SIGKILL-grace machinery the scanner wrappers use.
 */
export async function runOverseProcess(
  bin: string,
  argv: string[],
  opts: { timeoutMs: number; ceilingMs: number; env: Record<string, string> },
): Promise<ScannerProcessOutcome> {
  const startedAt = Date.now();
  const effectiveTimeout = Math.min(
    Math.max(1, opts.timeoutMs),
    Math.max(1, opts.ceilingMs),
  );
  if (bin !== ZEROVERSE_BINARY) {
    return {
      kind: "error",
      message: `refusing to spawn non-allowlisted binary '${bin}' (0verse launcher)`,
      durationMs: Date.now() - startedAt,
    };
  }
  let child: ChildProcess | null;
  try {
    child = launchOverseBinary(bin, argv, opts.env);
  } catch (err) {
    return {
      kind: "error",
      message: err instanceof Error ? err.message : String(err),
      durationMs: Date.now() - startedAt,
    };
  }
  if (!child) {
    return {
      kind: "error",
      message: `refusing to spawn non-allowlisted binary '${bin}' (0verse launcher)`,
      durationMs: Date.now() - startedAt,
    };
  }
  return superviseChild(child, effectiveTimeout, startedAt);
}

// ── Executor ─────────────────────────────────────────────────────────────────

/**
 * Build the argv for `0verse scan`. Pure + injection-safe: every element is a
 * typed, validated value (path already length-bounded; bug_class/backend are
 * closed enums), never a free-form flag string.
 */
export function buildOverseScanArgv(args: OverseArgs): string[] {
  return [
    "scan",
    args.binary_path,
    "--format",
    "ndjson",
    "--backend",
    args.backend,
    "--bug-class",
    args.bug_class,
  ];
}

/** Subprocess runner seam so tests can stub the 0verse invocation. */
export type OverseProcessRunner = (
  bin: string,
  argv: string[],
  opts: { timeoutMs: number; ceilingMs: number; env: Record<string, string> },
) => Promise<ScannerProcessOutcome>;

export interface OverseInvocation {
  args: OverseArgs;
  /** Environment for the child; defaults to `process.env`-derived if omitted. */
  env?: Record<string, string>;
  /** Injected process runner. Defaults to the real `runOverseProcess`. */
  runner?: OverseProcessRunner;
  /** Wall-clock ceiling override (ms). Defaults to ZEROVERSE_WALLCLOCK_CEILING_MS. */
  ceilingMs?: number;
}

/** The structured payload placed on `ToolResult.output`. */
export interface OverseToolOutput {
  contract_version: string;
  /** confirmed==true reproducing PoVs (verified). */
  confirmed: OverseScanFinding[];
  /** confirmed==false ranked leads (never promoted). */
  hypotheses: OverseScanFinding[];
  /** Honest degrade reason (static-only host, no-backend, all-pruned, timeout…). */
  note: string;
  /** Bookkeeping for the audit trail. */
  stats: {
    argv: string[];
    durationMs: number;
    timedOut: boolean;
    exitCode: number | null;
  };
}

/**
 * Execute a validated `analyze_binary` call: spawn `0verse scan <binary>
 * --format ndjson`, parse the stream, and return a structured `ToolResult`.
 * PoV-is-truth is enforced by the parser (confirmed vs hypotheses); this
 * function never promotes a hypothesis.
 */
export async function executeOverseScan(
  invocation: OverseInvocation,
): Promise<ToolResult> {
  const { args } = invocation;
  const runner = invocation.runner ?? runOverseProcess;
  const ceilingMs = invocation.ceilingMs ?? ZEROVERSE_WALLCLOCK_CEILING_MS;
  const requestedMs =
    args.timeout_s != null ? Math.floor(args.timeout_s * 1000) : ZEROVERSE_DEFAULT_TIMEOUT_MS;
  const env = invocation.env ?? {};
  const argv = buildOverseScanArgv(args);

  const outcome = await runner(ZEROVERSE_BINARY, argv, {
    timeoutMs: requestedMs,
    ceilingMs,
    env,
  });

  if (outcome.kind === "error") {
    return {
      success: false,
      output: null,
      error:
        `0verse failed to run: ${outcome.message}. ` +
        `Is the '0verse' CLI installed on this host?`,
    };
  }

  const raw = outcome.kind === "timeout" ? outcome.partial : outcome.combined;
  const parsed = parseOverseNdjson(raw);
  const timedOut = outcome.kind === "timeout";
  const exitCode = outcome.kind === "exit" ? outcome.exitCode : null;

  const notes: string[] = [];
  if (parsed.note) notes.push(parsed.note);
  if (timedOut) {
    notes.push(
      "0verse hit the wall-clock ceiling; results are PARTIAL (only findings emitted before the deadline).",
    );
  }
  if (!parsed.compatible) {
    notes.push(
      `0verse contract_version '${parsed.contractVersion}' has an unsupported MAJOR ` +
        `(this tool understands ${ZEROVERSE_SUPPORTED_CONTRACT_MAJOR}.x); treat findings as UNTRUSTED.`,
    );
  }
  if (
    !timedOut &&
    parsed.contractVersion === "" &&
    parsed.confirmed.length === 0 &&
    parsed.hypotheses.length === 0
  ) {
    notes.push(
      "0verse produced no parseable ndjson (no _meta header, no findings). " +
        `exitCode=${exitCode}. Raw tail: ${parsed.rawTail}`,
    );
  }

  const output: OverseToolOutput = {
    contract_version: parsed.contractVersion,
    confirmed: parsed.confirmed,
    hypotheses: parsed.hypotheses,
    note: notes.join(" "),
    stats: { argv, durationMs: outcome.durationMs, timedOut, exitCode },
  };

  // A MAJOR mismatch is a hard "don't trust this" — surface as an error result
  // so the loop won't promote anything, but keep the parsed payload for context.
  if (!parsed.compatible) {
    return { success: false, output, error: output.note };
  }

  return { success: true, output };
}

// Re-export the shared process outcome type used in stubs/tests without forcing
// callers to reach into scanner-tools.
export type { ScannerProcessOutcome } from "../scanner-tools.js";

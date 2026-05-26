/**
 * Tier 2 of pwnkit#271 — agent-driven verification of static kernel-review
 * findings.
 *
 * The flow:
 *   1. The Linux-kernel review profile (#268) emits `hypothesis: true,
 *      confidence: 0.4` Findings — file:line and a hypothesis-class but no
 *      reproducer.
 *   2. This module runs a constrained agent loop scoped to the finding's
 *      subsystem. The agent has exactly one allowlisted tool — `kernel_run`
 *      — plus an explicit reminder of what's NOT enabled (bash/read_file/
 *      run_command would otherwise let the agent wander). Its job: produce a
 *      reproducer whose oracle output matches the expected signature.
 *   3. Each kernel_run call goes through the real Tier-1 `verifyKernelFinding`
 *      from `../triage/kernel-vm-runner.ts`. We DON'T touch
 *      `runNativeAgentLoop` from `agent/native-loop.ts` — that loop's tool
 *      dispatch, findings DB writes, and cost accounting are all web-shaped.
 *      Our loop is one-shot: drive the runtime, observe tool calls, route
 *      them to a tiny dispatch table, repeat until success or budget.
 *
 * Promotion contract:
 *   - signature_matched → confirmed, confidence=1.0
 *   - crashed but signature mismatch → soft_hit, confidence=0.7
 *   - no signal in N attempts → budget_exhausted, original confidence preserved
 *   - infra error (build failure, runtime throw) → error, original confidence
 *     preserved, error message attached
 *
 * The CLI surface lives in `packages/cli/src/commands/verify.ts` and is
 * gated behind `PWNKIT_KERNEL_VERIFY=1` so CI cost stays predictable.
 */

import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "@pwnkit/shared";
import type {
  NativeMessage,
  NativeContentBlock,
  NativeToolDef,
} from "../runtime/types.js";
import {
  verifyKernelFinding,
  type KernelFindingVerification,
  type VerifyKernelFindingOptions,
} from "../triage/kernel-vm-runner.js";
import {
  KERNEL_RUN_TOOL_DEFINITION,
  validateKernelRunArgs,
  executeKernelRun,
  type KernelRunResult,
} from "../agent/tools/kernel-run.js";
import type {
  KernelVerifyOracleResult,
  KernelVerifyRunner,
  KernelVerifyRunnerInput,
} from "./kernel-verify-types.js";
import {
  buildKernelVerifyInitialPrompt,
  buildKernelVerifySystemPrompt,
  extractKernelFindingMetadata,
  selectSubsystemSourceSlice,
} from "./kernel-prompts.js";

// ── Public types ─────────────────────────────────────────────────────────

export type KernelVerifyStatus =
  | "confirmed"
  | "soft_hit"
  | "no_signal"
  | "budget_exhausted"
  | "error";

export interface KernelVerifyAttempt {
  index: number;
  /** Reproducer source the agent emitted. */
  program: string;
  programLang: "syz" | "c";
  expectedSignature?: string;
  oracle?: KernelVerifyOracleResult;
  /** Set when validation or execution rejected the attempt before the oracle. */
  rejected?: string;
  durationMs: number;
}

export interface KernelVerifyResult {
  status: KernelVerifyStatus;
  new_confidence: number;
  /** Actual KASAN/UBSAN signature observed (when any), useful for soft-hit triage. */
  signature?: string;
  /** The winning reproducer when status is `confirmed` or `soft_hit`. */
  generated_program?: string;
  generated_program_lang?: "syz" | "c";
  attempts: KernelVerifyAttempt[];
  /** Free-form reason — populated for non-confirmed verdicts. */
  reason?: string;
  /** Set when `status === "error"`. */
  errorMessage?: string;
}

export interface KernelVerifyOptions {
  kernelTree: string;
  kernelConfig?: string;
  forceBuild?: boolean;
  /**
   * Agent driver — defaults to the real native runtime adapter created by the
   * caller. Mockable in tests via the `agentInvoker` field. We accept either a
   * single `NativeRuntime` (we wrap it in a one-tool loop) or a fully custom
   * invoker the caller supplies for tests.
   */
  agentInvoker?: KernelVerifyAgentInvoker;
  /** Tier 1 runner override (used in tests). */
  runner?: KernelVerifyRunner;
  /** Max reproducer attempts (1 build + N reproducer turns). Default 5. */
  attempts?: number;
  /** Wall-clock budget in milliseconds. Default 30 min. */
  wallClockMs?: number;
  /** Subsystem source slice override (used in tests to bypass disk reads). */
  sourceSlice?: Array<{ relativePath: string; content: string }>;
  /** Optional override for the Tier-1 cache root. */
  cacheDir?: string;
}

/**
 * Pluggable agent-driver. The default implementation wraps a NativeRuntime;
 * tests pass a synchronous invoker that returns a deterministic stream.
 *
 * Each call corresponds to one model turn: given the conversation history,
 * return the next assistant message (which may or may not contain a
 * `kernel_run` tool_use block).
 */
export type KernelVerifyAgentInvoker = (
  ctx: KernelVerifyInvokerContext,
) => Promise<NativeContentBlock[]>;

export interface KernelVerifyInvokerContext {
  systemPrompt: string;
  messages: NativeMessage[];
  tools: NativeToolDef[];
  /** Hint for the runtime — current attempt count and budget. */
  attempt: number;
  maxAttempts: number;
}

// ── Tier 1 wrapper ───────────────────────────────────────────────────────

/**
 * Default Tier 1 runner used by the kernel-verify loop. Writes the agent's
 * reproducer string to a temp file, delegates to `verifyKernelFinding` from
 * `kernel-vm-runner.ts`, then translates Tier-1's `KernelFindingVerification`
 * shape into our richer `KernelVerifyOracleResult` shape the agent reads.
 *
 * Exported so the CLI can use it directly (or tests can call it with a fake
 * Tier-1 `vmRunner` injection point).
 */
export async function defaultKernelVerifyRunner(
  input: KernelVerifyRunnerInput,
  options?: { cacheDir?: string },
): Promise<KernelVerifyOracleResult> {
  const tmpDir = mkdtempSync(join(tmpdir(), "pwnkit-kvfy-"));
  const reproName = input.programLang === "syz" ? "repro.syz" : "repro.c";
  const reproPath = join(tmpDir, reproName);
  writeFileSync(reproPath, input.program, "utf8");

  try {
    const tierOneOpts: VerifyKernelFindingOptions = {
      kernelTree: input.kernelTree,
      kernelConfig: input.kernelConfig ?? "kasan",
      forceBuild: input.forceBuild,
      expectedSignature: input.expectedSignature,
      ...(input.programLang === "syz"
        ? { syzProgramPath: reproPath }
        : { reproducerPath: reproPath }),
      ...(options?.cacheDir ? { cacheDir: options.cacheDir } : {}),
    };

    let verdict: KernelFindingVerification;
    try {
      verdict = await verifyKernelFinding(tierOneOpts);
    } catch (err) {
      return {
        ran: false,
        crashed: false,
        signatureMatched: false,
        dmesgExcerpt: "",
        reason: `tier1 verifyKernelFinding threw: ${err instanceof Error ? err.message : String(err)}`,
        oracleConfidence: 0,
        buildStatus: "unknown",
      };
    }

    return tier1VerdictToOracleResult(verdict);
  } finally {
    try {
      rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // best-effort tmp cleanup
    }
  }
}

/**
 * Translate the Tier-1 `KernelFindingVerification` shape (which the existing
 * ingest CLI consumes) into the richer `KernelVerifyOracleResult` shape this
 * loop hands to the agent. Mostly a status remap with dmesg readback.
 *
 * Exported because tests rely on it and because the CLI may want to surface
 * the same translation when displaying a verified result.
 */
export function tier1VerdictToOracleResult(
  verdict: KernelFindingVerification,
): KernelVerifyOracleResult {
  // We read the dmesg from disk lazily — even on `no_signal` the Tier-1
  // contract guarantees the file exists. Best-effort: if the read fails (e.g.
  // tmp cleanup raced), we fall back to an empty excerpt rather than crash.
  let dmesg = "";
  try {
    if (verdict.dmesg_path && existsSync(verdict.dmesg_path)) {
      dmesg = readFileSync(verdict.dmesg_path, "utf8");
    }
  } catch {
    // best-effort
  }

  const dmesgExcerpt = dmesg.slice(0, 4 * 1024);
  const buildStatus: KernelVerifyOracleResult["buildStatus"] = verdict.build_cache_hit
    ? "hit"
    : "miss";

  switch (verdict.status) {
    case "reproduced":
      return {
        ran: true,
        crashed: true,
        signatureMatched: true,
        detectedCrashType: verdict.signature,
        dmesgExcerpt,
        reason: `reproduced (signature=${verdict.signature ?? "?"})`,
        oracleConfidence: 1.0,
        buildStatus,
      };
    case "run_failed":
      // Tier 1 sets `signature` here when the reproducer crashed but didn't
      // match — that's the soft-hit signal. Surface it as `crashed=true,
      // signatureMatched=false` for the loop.
      return {
        ran: true,
        crashed: Boolean(verdict.signature),
        signatureMatched: false,
        detectedCrashType: verdict.signature,
        dmesgExcerpt,
        reason: verdict.signature
          ? `kernel crashed with signature=${verdict.signature} but did not match the expected signature`
          : "reproducer failed to compile or execute",
        oracleConfidence: verdict.signature ? 0.5 : 0,
        buildStatus,
      };
    case "no_signal":
      return {
        ran: true,
        crashed: false,
        signatureMatched: false,
        dmesgExcerpt,
        reason: "reproducer ran but did not trigger any recognised kernel crash",
        oracleConfidence: 0,
        buildStatus,
      };
    case "build_failed":
      return {
        ran: false,
        crashed: false,
        signatureMatched: false,
        dmesgExcerpt,
        reason: "kernel build failed",
        oracleConfidence: 0,
        buildStatus: "miss",
      };
  }
}

// ── Agent loop ───────────────────────────────────────────────────────────

const DEFAULT_ATTEMPTS = 5;
const DEFAULT_WALL_CLOCK_MS = 30 * 60 * 1000;
const MAX_AGENT_TURNS_PER_ATTEMPT = 4;

/**
 * Drive the constrained agent loop against a single finding.
 *
 * The loop alternates: prompt → tool_use → tool_result → prompt → ... Each
 * `kernel_run` call counts against the attempt budget. Non-`kernel_run` tool
 * calls (read_file, run_command, bash) are answered with a stubbed
 * "not-implemented-in-verify-loop" message — we don't want this loop reading
 * arbitrary files or shelling out; that's part of the constrained surface.
 * The agent is told this in the system prompt and will adapt.
 */
export async function verifyStaticKernelFinding(
  finding: Finding,
  opts: KernelVerifyOptions,
): Promise<KernelVerifyResult> {
  const startedAt = Date.now();
  const attemptsCap = opts.attempts ?? DEFAULT_ATTEMPTS;
  const wallClockMs = opts.wallClockMs ?? DEFAULT_WALL_CLOCK_MS;
  const runner =
    opts.runner ??
    ((input: KernelVerifyRunnerInput) =>
      defaultKernelVerifyRunner(input, { cacheDir: opts.cacheDir }));
  const deadline = startedAt + wallClockMs;

  const metadata = extractKernelFindingMetadata(finding);
  const sourceSlice =
    opts.sourceSlice ??
    selectSubsystemSourceSlice({ kernelTree: opts.kernelTree, metadata });

  const systemPrompt = buildKernelVerifySystemPrompt();
  const initialUser = buildKernelVerifyInitialPrompt({
    finding,
    metadata,
    subsystemSlice: sourceSlice,
    attempts: attemptsCap,
    wallClockMs,
  });

  const messages: NativeMessage[] = [
    { role: "user", content: [{ type: "text", text: initialUser }] },
  ];

  const tools: NativeToolDef[] = [toolDefToNative(KERNEL_RUN_TOOL_DEFINITION)];

  const invoker: KernelVerifyAgentInvoker =
    opts.agentInvoker ?? defaultAgentInvoker;

  const attempts: KernelVerifyAttempt[] = [];

  // Drive the loop until we hit one of three exit conditions:
  //   - The agent calls kernel_run with a winning program (status=confirmed)
  //   - The agent gives up explicitly or stops calling tools (status=no_signal)
  //   - We exhaust attempts / wall-clock budget (status=budget_exhausted)
  let kernelRunCalls = 0;
  let lastSoftHit: KernelVerifyAttempt | undefined;
  let turn = 0;
  const maxTurns = attemptsCap * MAX_AGENT_TURNS_PER_ATTEMPT + 2;

  try {
    while (turn < maxTurns) {
      turn++;

      if (Date.now() > deadline) {
        return finalize({
          status: "budget_exhausted",
          finding,
          attempts,
          lastSoftHit,
          reason: `wall-clock budget exhausted after ${turn - 1} turns`,
        });
      }
      if (kernelRunCalls >= attemptsCap) {
        return finalize({
          status: lastSoftHit ? "soft_hit" : "budget_exhausted",
          finding,
          attempts,
          lastSoftHit,
          reason: `reproducer attempt cap (${attemptsCap}) reached`,
        });
      }

      const content = await invoker({
        systemPrompt,
        messages,
        tools,
        attempt: kernelRunCalls,
        maxAttempts: attemptsCap,
      });

      messages.push({ role: "assistant", content });

      const toolUses = content.filter(
        (b): b is Extract<NativeContentBlock, { type: "tool_use" }> => b.type === "tool_use",
      );
      const texts = content
        .filter((b): b is Extract<NativeContentBlock, { type: "text" }> => b.type === "text")
        .map((b) => b.text);

      // Explicit give-up signal — terminate cleanly without using a budget slot.
      if (toolUses.length === 0) {
        const gaveUp = texts.some((t) => /\bGIVE_UP\b/.test(t));
        return finalize({
          status: lastSoftHit ? "soft_hit" : "no_signal",
          finding,
          attempts,
          lastSoftHit,
          reason: gaveUp ? "agent emitted GIVE_UP" : "agent stopped without a tool call",
        });
      }

      // We surface every tool call in this turn back as tool_result blocks so
      // the model sees the same conversation shape it would in a real loop.
      // Non-kernel_run tools are answered with a stub message (the constrained
      // tool surface is enforced here, not by hiding the tool defs from the
      // model).
      const toolResults: NativeContentBlock[] = [];
      for (const use of toolUses) {
        if (use.name !== "kernel_run") {
          toolResults.push({
            type: "tool_result",
            tool_use_id: use.id,
            content:
              `Tool '${use.name}' is not enabled in the kernel-verify loop. ` +
              `You may only call kernel_run. Use the source slice provided in ` +
              `the initial message for context.`,
            is_error: true,
          });
          continue;
        }

        // Validate args, run, record.
        const validated = validateKernelRunArgs(use.input);
        const attemptStart = Date.now();
        if (!validated.ok) {
          attempts.push({
            index: kernelRunCalls,
            program: typeof (use.input as { program?: unknown }).program === "string"
              ? ((use.input as { program: string }).program)
              : "",
            programLang: ((use.input as { program_lang?: string }).program_lang === "c"
              ? "c"
              : "syz") as "syz" | "c",
            rejected: validated.error,
            durationMs: Date.now() - attemptStart,
          });
          toolResults.push({
            type: "tool_result",
            tool_use_id: use.id,
            content: `kernel_run rejected: ${validated.error}`,
            is_error: true,
          });
          continue;
        }

        kernelRunCalls++;
        const result: KernelRunResult = await executeKernelRun({
          args: validated.args,
          finding,
          runner,
          kernelTree: opts.kernelTree,
          kernelConfig: opts.kernelConfig,
          forceBuild: opts.forceBuild,
        });

        const attempt: KernelVerifyAttempt = {
          index: kernelRunCalls - 1,
          program: validated.args.program,
          programLang: validated.args.program_lang,
          expectedSignature: validated.args.expected_signature,
          oracle: result.oracle,
          durationMs: Date.now() - attemptStart,
        };
        attempts.push(attempt);

        if (!result.ok || !result.oracle) {
          toolResults.push({
            type: "tool_result",
            tool_use_id: use.id,
            content: `kernel_run failed: ${result.error ?? "unknown error"}`,
            is_error: true,
          });
          continue;
        }

        // Win condition.
        if (result.oracle.signatureMatched) {
          messages.push({ role: "user", content: toolResults });
          return finalize({
            status: "confirmed",
            finding,
            attempts,
            lastSoftHit,
            winning: attempt,
          });
        }

        // Soft hit: a kernel crash fired but signature didn't match. Track
        // the latest one so we can report it if we exhaust the budget.
        if (result.oracle.crashed) {
          lastSoftHit = attempt;
        }

        toolResults.push({
          type: "tool_result",
          tool_use_id: use.id,
          content: JSON.stringify({
            ran: result.oracle.ran,
            crashed: result.oracle.crashed,
            signature_matched: result.oracle.signatureMatched,
            detected_crash_type: result.oracle.detectedCrashType,
            dmesg_excerpt: result.oracle.dmesgExcerpt,
            reason: result.oracle.reason,
          }),
        });
      }
      messages.push({ role: "user", content: toolResults });
    }

    return finalize({
      status: lastSoftHit ? "soft_hit" : "budget_exhausted",
      finding,
      attempts,
      lastSoftHit,
      reason: `turn cap (${maxTurns}) reached`,
    });
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    return {
      status: "error",
      new_confidence: finding.confidence ?? 0.4,
      attempts,
      reason: "agent loop threw",
      errorMessage,
    };
  }
}

interface FinalizeArgs {
  status: KernelVerifyStatus;
  finding: Finding;
  attempts: KernelVerifyAttempt[];
  lastSoftHit?: KernelVerifyAttempt;
  winning?: KernelVerifyAttempt;
  reason?: string;
}

function finalize(args: FinalizeArgs): KernelVerifyResult {
  const baseConf = args.finding.confidence ?? 0.4;
  switch (args.status) {
    case "confirmed":
      return {
        status: "confirmed",
        new_confidence: 1.0,
        signature: args.winning?.oracle?.detectedCrashType,
        generated_program: args.winning?.program,
        generated_program_lang: args.winning?.programLang,
        attempts: args.attempts,
      };
    case "soft_hit":
      return {
        status: "soft_hit",
        new_confidence: 0.7,
        signature: args.lastSoftHit?.oracle?.detectedCrashType,
        generated_program: args.lastSoftHit?.program,
        generated_program_lang: args.lastSoftHit?.programLang,
        attempts: args.attempts,
        reason: args.reason ?? "kernel crashed but signature did not match",
      };
    case "no_signal":
      return {
        status: "no_signal",
        new_confidence: baseConf,
        attempts: args.attempts,
        reason: args.reason ?? "no reproducer produced any kernel crash",
      };
    case "budget_exhausted":
      return {
        status: "budget_exhausted",
        new_confidence: baseConf,
        attempts: args.attempts,
        reason: args.reason ?? "verification budget exhausted",
      };
    case "error":
      return {
        status: "error",
        new_confidence: baseConf,
        attempts: args.attempts,
        reason: args.reason ?? "verifier error",
      };
  }
}

/**
 * Default agent invoker — issues a single `executeNative` against a configured
 * `NativeRuntime`. Wired this way so tests can swap the whole invoker without
 * needing a runtime.
 *
 * NOTE: tests always pass their own `agentInvoker`. The runtime-backed default
 * exists for callers that want the canonical behavior — the verify CLI does
 * not currently wire a NativeRuntime here, leaving this function dormant
 * until cloud/orchestrator (#249, #251) routes a real runtime in.
 */
async function defaultAgentInvoker(
  _ctx: KernelVerifyInvokerContext,
): Promise<NativeContentBlock[]> {
  throw new Error(
    "kernel-verify: no agentInvoker supplied and no default runtime configured. " +
      "Pass `opts.agentInvoker` (or wait for orchestrator/runtime wiring in #249/#251).",
  );
}

/**
 * Convert a pwnkit ToolDefinition to the `NativeToolDef` shape the runtime
 * expects. Mirrors `toNativeToolDef` in `agent/native-loop.ts` but kept local
 * so this module can stand alone.
 */
function toolDefToNative(tool: typeof KERNEL_RUN_TOOL_DEFINITION): NativeToolDef {
  const properties: Record<string, unknown> = {};
  for (const [key, param] of Object.entries(tool.parameters)) {
    const prop: Record<string, unknown> = {
      type: param.type,
      description: param.description,
    };
    if (param.enum) prop.enum = param.enum;
    properties[key] = prop;
  }
  return {
    name: tool.name,
    description: tool.description,
    input_schema: {
      type: "object",
      properties,
      required: tool.required ?? [],
    },
  };
}

// ── Confidence promotion (integration helper) ────────────────────────────

/**
 * Update a kernel-review Finding in-place with the verification verdict.
 *
 * Promotion rules (mirrors the issue spec):
 *   - confirmed → confidence=1.0, status="confirmed", hypothesis: false
 *   - soft_hit → confidence=0.7, observed signature attached, hypothesis: false
 *   - no_signal / budget_exhausted → leave confidence unchanged, attach the
 *     failed-attempts log so triage can see what was tried
 *   - error → leave confidence unchanged, attach error message
 *
 * We persist the verification metadata on `evidence.analysis` (free-form
 * append) so the existing Finding shape doesn't grow new fields. The
 * canonical reproducer ends up on `evidence.response` for confirmed/soft hits
 * so downstream renderers (`disclose`, `triage`) can find it.
 */
export function applyVerificationToFinding(
  finding: Finding,
  result: KernelVerifyResult,
): Finding {
  const next: Finding = {
    ...finding,
    evidence: { ...finding.evidence },
  };

  next.confidence = result.new_confidence;

  const lines: string[] = [
    `Kernel verification: ${result.status} (new_confidence=${result.new_confidence.toFixed(2)})`,
    `Attempts: ${result.attempts.length}`,
  ];
  if (result.signature) lines.push(`Observed signature: ${result.signature}`);
  if (result.reason) lines.push(`Reason: ${result.reason}`);
  if (result.errorMessage) lines.push(`Error: ${result.errorMessage}`);

  // Flip the hypothesis flag (mirrored in evidence.analysis by the parser) on
  // confirmed/soft-hit promotion — those are no longer static-only.
  const existingAnalysis = next.evidence.analysis ?? "";
  let updatedAnalysis = existingAnalysis;
  if (result.status === "confirmed" || result.status === "soft_hit") {
    updatedAnalysis = updatedAnalysis.replace(/^Hypothesis:\s*true\s*$/im, "Hypothesis: false");
  }

  next.evidence.analysis = [
    updatedAnalysis,
    "",
    "---verification---",
    ...lines,
  ]
    .filter(Boolean)
    .join("\n");

  if (
    (result.status === "confirmed" || result.status === "soft_hit") &&
    result.generated_program
  ) {
    next.evidence.response = result.generated_program;
  }

  if (result.status === "confirmed") {
    next.status = "confirmed";
  }

  return next;
}

// Re-export so the CLI can import the canonical type names from one place.
export type { KernelVerifyOracleResult, KernelVerifyRunner } from "./kernel-verify-types.js";

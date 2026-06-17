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
  KernelVerifyPhase,
  KernelVerifyRunner,
  KernelVerifyRunnerInput,
} from "./kernel-verify-types.js";
import {
  buildKernelVerifyInitialPrompt,
  buildKernelVerifySystemPrompt,
  extractKernelFindingMetadata,
  selectSubsystemSourceSlice,
} from "./kernel-prompts.js";
import { checkAlreadyFixed } from "../kernel/fix-commit-intel.js";
import type {
  WeaponizationSummary,
  KernelExploitContext,
} from "../kernel/exploit/exploit-context.js";
import {
  runKernelExploitChain,
  type ChainRunStep,
} from "../kernel/exploit/run-chain.js";
import type { KernelVmRunner } from "../kernel/exploit/harness.js";
import {
  classifyPrimitiveFromDmesg,
  describeKernelPrimitive,
  exploitabilityAdjustedSeverity,
  type KernelPrimitive,
} from "../triage/kernel-primitive.js";
import {
  minimizeReproducer,
  makeKernelMinimizeOracle,
  type MinimizeResult,
} from "./reproducer-minimize.js";

// ── Public types ─────────────────────────────────────────────────────────

export type KernelVerifyStatus =
  | "confirmed"
  | "soft_hit"
  | "no_signal"
  | "likely_already_fixed"
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
  /**
   * Synthesised exploitation primitive (issue #569) for confirmed / soft-hit
   * results — UAF / OOB-write / double-free / ... plus a bounded control-demo
   * step. Undefined when no crash fired.
   */
  primitive?: KernelPrimitive;
  /**
   * Minimized reproducer (issue #569), populated when `opts.minimize` is set
   * and the result is `confirmed`. `generated_program` is replaced with the
   * minimized source; this carries the before/after stats.
   */
  minimized_program?: string;
  minimization?: MinimizeResult;
  attempts: KernelVerifyAttempt[];
  /** Free-form reason — populated for non-confirmed verdicts. */
  reason?: string;
  /** Set when `status === "error"`. */
  errorMessage?: string;
  /**
   * Weaponization climb summary (kernel-autonomy Phase 1). Optional and
   * additive — populated only when a weaponization run drove the escalation
   * ladder for this finding; undefined for plain verify results. See
   * {@link WeaponizationSummary}.
   */
  weaponization?: WeaponizationSummary;
  /**
   * Structured kernel-exploit state derived from the weaponization run
   * (kernel-autonomy Phase 2a). Carried onto `Finding.kernelExploit` by
   * {@link applyVerificationToFinding}. Populated alongside `weaponization`;
   * undefined when no weaponization run drove this finding. The
   * planner-rationale lines are kept separately for the evidence block.
   */
  kernelExploit?: KernelExploitContext;
  /** Planner "what's still missing" lines, for the `---weaponization---` block. */
  weaponizationRationale?: string[];
  /**
   * Full per-step records of the weaponization chain run (kernel-autonomy
   * training-data capture). Carries the oracle-REFUSED negative cases via each
   * step's `reason` / `reachedRung < targetRung`, which the flattened
   * `weaponization` summary discards. Optional and additive — populated only
   * alongside a weaponization run; undefined for plain verify results.
   */
  weaponizationSteps?: ChainRunStep[];
}

export interface KernelVerifyOptions {
  kernelTree: string;
  kernelConfig?: string;
  forceBuild?: boolean;
  /**
   * Disable the already-fixed git gate (default: enabled). The gate
   * short-circuits findings whose faulting function was changed by a recent
   * security/`Fixes:` commit in the local tree, before any QEMU boot. Tests
   * that run against a real git checkout can set this to keep behaviour
   * deterministic.
   */
  disableFixCommitGate?: boolean;
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
  /**
   * Run a delta-debug minimization pass on the confirmed reproducer (issue
   * #569). Off by default — each minimization candidate boots QEMU, so callers
   * opt in. Uses the same Tier-1 `runner` as the verify loop.
   */
  minimize?: boolean;
  /** Oracle-call budget for the minimization pass. Default 60. */
  minimizeMaxOracleCalls?: number;
  /**
   * Drive the confirmed finding through the verify → weaponization chain
   * (kernel-autonomy Phase 2a). Off by default — cost-bounded and
   * operator-gated by this flag. When set AND the confirmed primitive is
   * write-capable (write control / UAF / OOB-write), `runKernelExploitChain`
   * climbs the escalation ladder and the result carries a
   * {@link WeaponizationSummary}; the finding gets `kernelExploit` state and a
   * `---weaponization---` evidence block. Default-safe: with no QEMU artifacts
   * the chain runs plan-only (no boot, no cost) and only records the static
   * reachable rung. When false/absent, verify behaviour is byte-for-byte
   * unchanged.
   */
  weaponize?: boolean;
  /**
   * Injectable VM runner forwarded to the weaponization chain (tests). Has no
   * effect unless `weaponize` is set.
   */
  weaponizeVmRunner?: KernelVmRunner;
  /**
   * Injectable artifacts-readiness probe forwarded to the weaponization chain
   * (tests). Has no effect unless `weaponize` is set.
   */
  weaponizeArtifactsReady?: () => boolean;
  /**
   * Two-phase trigger (AIxCC / Shellphish T3 — sanitizer "loosening"). When
   * set, the loop runs PHASE 1 ("reach") under a cheap, crude build (an
   * oops/WARN/printk probe, no KASAN) to first prove the deep path is REACHABLE,
   * then ESCALATES to PHASE 2 ("refine") under the KASAN build to nail the exact
   * signature. The cheap reach build is faster + flakier-tolerant; only once the
   * path is landed do we pay for the sanitizer build. Off by default: every run
   * stays in `refine` with `opts.kernelConfig`, which is byte-for-byte the
   * pre-T3 behaviour.
   */
  twoPhase?: boolean;
  /**
   * Build profile for the phase-1 reachability probe. Defaults to `"reach"` (a
   * cheap oops/WARN config the build script maps; see {@link KernelConfigProfile}).
   * Only consulted when `twoPhase` is set. Passed through verbatim to the
   * runner's `kernelConfig` for phase-1 attempts.
   */
  reachConfig?: string;
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

  // Already-fixed gate (incomplete-fix intel): before spending a QEMU/KASAN
  // boot, ask the local kernel tree whether a recent security/`Fixes:` commit
  // already touched the EXACT faulting function. This deterministically kills
  // the "real bug, but patched N days ago" FP class (e.g. ksmbd UAF fixed 8
  // days before re-discovery, the skb shared-frag cluster) that otherwise burns
  // a full verification cycle. Fails soft — only short-circuits on a
  // function-level pickaxe hit, never on a non-git tree or a mere file-level
  // touch, so a genuinely novel finding is never gated out. Opt-out for tests.
  if (!opts.disableFixCommitGate && metadata.filePath) {
    const fixed = checkAlreadyFixed({
      tree: opts.kernelTree,
      filePath: metadata.filePath,
      ...(metadata.faultingFunction
        ? { faultingFunction: metadata.faultingFunction }
        : {}),
    });
    if (fixed.functionLevelMatch) {
      return finalize({
        status: "likely_already_fixed",
        finding,
        attempts: [],
        reason: fixed.reason,
      });
    }
  }

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

  // Two-phase trigger (AIxCC T3). When `twoPhase` is on we start in the cheap
  // `reach` phase (a crude oops/WARN build that only proves the path is
  // reachable) and escalate to `refine` (the KASAN build) once a phase-1 attempt
  // lands the path. Off ⇒ everything runs in `refine`, the pre-T3 behaviour.
  let phase: KernelVerifyPhase = opts.twoPhase ? "reach" : "refine";
  const phaseConfig = (p: KernelVerifyPhase): string | undefined =>
    p === "reach" ? (opts.reachConfig ?? "reach") : (opts.kernelConfig ?? "kasan");

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
        const attemptPhase = phase;
        const result: KernelRunResult = await executeKernelRun({
          args: validated.args,
          finding,
          runner,
          kernelTree: opts.kernelTree,
          kernelConfig: phaseConfig(attemptPhase),
          forceBuild: opts.forceBuild,
        });
        // Stamp the phase the attempt ran in so the agent + audit trail can see
        // the reach→refine escalation (AIxCC T3).
        if (result.oracle) result.oracle.phase = attemptPhase;

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

        // Phase 1 (reach): we only need to prove the deep path is REACHABLE —
        // any kernel crash signal (a crash, or even a matched signature under
        // the crude build) lands the path. Escalate to phase 2 (refine) under
        // the KASAN build; we do NOT confirm here (the cheap build can't be
        // trusted for the exact sanitizer signature). The agent is told the
        // path is reached and to refine for KASAN.
        if (attemptPhase === "reach") {
          if (result.oracle.crashed || result.oracle.signatureMatched) {
            phase = "refine";
            toolResults.push({
              type: "tool_result",
              tool_use_id: use.id,
              content: JSON.stringify({
                phase: "reach",
                reached: true,
                detected_crash_type: result.oracle.detectedCrashType,
                dmesg_excerpt: result.oracle.dmesgExcerpt,
                note:
                  "Phase 1 (reach) confirmed the path is REACHABLE under the " +
                  "cheap build. Escalating to phase 2 (refine) under KASAN — " +
                  "resubmit the same/refined program to nail the exact signature.",
              }),
            });
          } else {
            toolResults.push({
              type: "tool_result",
              tool_use_id: use.id,
              content: JSON.stringify({
                phase: "reach",
                reached: false,
                dmesg_excerpt: result.oracle.dmesgExcerpt,
                reason: result.oracle.reason,
                note: "Phase 1 (reach) did not land the path — refine and retry.",
              }),
            });
          }
          continue;
        }

        // Win condition (phase 2 / refine).
        if (result.oracle.signatureMatched) {
          messages.push({ role: "user", content: toolResults });
          const confirmed = finalize({
            status: "confirmed",
            finding,
            attempts,
            lastSoftHit,
            winning: attempt,
          });
          const finalized = opts.minimize
            ? await minimizeConfirmedReproducer(confirmed, attempt, opts, runner, finding)
            : confirmed;
          return await maybeWeaponizeConfirmed(
            finalized,
            finding,
            opts,
            attempt.oracle?.dmesgExcerpt,
          );
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
        primitive: primitiveFromAttempt(args.winning),
        attempts: args.attempts,
      };
    case "soft_hit":
      return {
        status: "soft_hit",
        new_confidence: 0.7,
        signature: args.lastSoftHit?.oracle?.detectedCrashType,
        generated_program: args.lastSoftHit?.program,
        generated_program_lang: args.lastSoftHit?.programLang,
        primitive: primitiveFromAttempt(args.lastSoftHit),
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
    case "likely_already_fixed":
      // A recent upstream fix touched the faulting function — almost certainly a
      // duplicate of patched work, not a novel bug. Deprioritise hard (but don't
      // zero it: the gate is heuristic) and skip the expensive boot entirely.
      return {
        status: "likely_already_fixed",
        new_confidence: Math.min(baseConf, 0.2),
        attempts: args.attempts,
        reason:
          args.reason ?? "faulting function changed by a recent upstream fix",
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
 * Synthesise the exploitation primitive from a winning / soft-hit attempt's
 * oracle output (issue #569). Returns undefined when the attempt has no oracle
 * dmesg to classify from.
 */
function primitiveFromAttempt(
  attempt: KernelVerifyAttempt | undefined,
): KernelPrimitive | undefined {
  if (!attempt?.oracle) return undefined;
  return classifyPrimitiveFromDmesg(
    attempt.oracle.dmesgExcerpt,
    attempt.oracle.detectedCrashType,
  );
}

/**
 * Run a delta-debug minimization pass on a confirmed reproducer (issue #569).
 * Reuses the verify loop's Tier-1 `runner` as the crash oracle, requiring the
 * minimized program to keep producing the confirmed signature.
 *
 * On any failure (or if minimization can't shrink the program) the original
 * confirmed result is returned unchanged — minimization is best-effort.
 */
async function minimizeConfirmedReproducer(
  confirmed: KernelVerifyResult,
  winning: KernelVerifyAttempt,
  opts: KernelVerifyOptions,
  runner: KernelVerifyRunner,
  finding: Finding,
): Promise<KernelVerifyResult> {
  if (!confirmed.generated_program || !confirmed.generated_program_lang) {
    return confirmed;
  }
  try {
    const oracle = makeKernelMinimizeOracle({
      runner,
      finding,
      kernelTree: opts.kernelTree,
      kernelConfig: opts.kernelConfig,
      forceBuild: opts.forceBuild,
      expectedSignature: winning.expectedSignature,
    });
    const minimization = await minimizeReproducer(confirmed.generated_program, {
      lang: confirmed.generated_program_lang,
      oracle,
      expectedSignature: winning.expectedSignature,
      maxOracleCalls: opts.minimizeMaxOracleCalls ?? 60,
    });
    if (!minimization.reproduced) return confirmed;
    return {
      ...confirmed,
      generated_program: minimization.program,
      minimized_program: minimization.program,
      minimization,
    };
  } catch {
    // Best-effort: never fail a confirmed verification because minimization
    // tripped.
    return confirmed;
  }
}

/** Primitive kinds whose corruption is a controlled-write candidate. */
const WRITE_CAPABLE_KINDS = new Set(["use-after-free", "out-of-bounds-write"]);

/**
 * Is this confirmed primitive worth weaponizing? We only spend a chain run on a
 * write-capable bug — a `write` control, or a UAF / OOB-write kind (a UAF can
 * be classified `read` from the faulting access yet still carry a write lever
 * once reclaimed). Read-only / DoS primitives are not chained toward root.
 */
function isWriteCapable(primitive: KernelPrimitive | undefined): boolean {
  if (!primitive) return false;
  return primitive.control === "write" || WRITE_CAPABLE_KINDS.has(primitive.kind);
}

/**
 * Optionally drive a confirmed, write-capable finding through the verify →
 * weaponization chain (kernel-autonomy Phase 2a).
 *
 * Gated on `opts.weaponize`. Default-safe in every other dimension:
 *   - not confirmed, or primitive not write-capable → returns `confirmed`
 *     unchanged (no chain run),
 *   - chain throws → swallowed; `confirmed` returned unchanged (a verify result
 *     is never failed because weaponization tripped),
 *   - no QEMU artifacts → the chain itself runs plan-only (no boot, no cost)
 *     and we still attach the static rung + planner rationale.
 *
 * On success it attaches `weaponization` (the summary), `kernelExploit` (the
 * carried state), and `weaponizationRationale` (the planner's missing-capability
 * lines) to the result. `applyVerificationToFinding` materialises these onto
 * the finding.
 */
async function maybeWeaponizeConfirmed(
  confirmed: KernelVerifyResult,
  finding: Finding,
  opts: KernelVerifyOptions,
  crashDmesg?: string,
): Promise<KernelVerifyResult> {
  if (!opts.weaponize) return confirmed;
  if (confirmed.status !== "confirmed") return confirmed;
  if (!isWriteCapable(confirmed.primitive)) return confirmed;

  try {
    // Carry the confirmed crash DMESG onto the finding so the chain's
    // finding→node lift re-classifies the same primitive. The KASAN splat (not
    // the syz/C reproducer) is what the classifier reads; prefer it, falling
    // back to the analysis block on a finding that already carries crash text.
    const chainFinding: Finding =
      crashDmesg && /KASAN|BUG:/i.test(crashDmesg)
        ? {
            ...finding,
            evidence: { ...finding.evidence, response: crashDmesg },
          }
        : finding;

    const chain = await runKernelExploitChain([chainFinding], {
      ...(opts.weaponizeVmRunner ? { vmRunner: opts.weaponizeVmRunner } : {}),
      ...(opts.weaponizeArtifactsReady
        ? { artifactsReady: opts.weaponizeArtifactsReady }
        : {}),
      ...(confirmed.generated_program
        ? { reproducer: confirmed.generated_program }
        : {}),
    });

    // Carry the full structured exploit plan the chain derived
    // (`writeProfile`/`sprayPlans[]`/`rootTailPlan`) forward instead of dropping
    // it — this is the training-signal-rich half of the run. Spread the chain's
    // `exploitContext` first, then overlay the run-outcome scalars so the
    // freshly-computed rung/landed/lpe always win.
    const kernelExploit: KernelExploitContext = {
      ...(chain.exploitContext ?? {}),
      highestRung: chain.highestRung,
      reclaimLanded: chain.reclaimLanded,
      lpeAchieved: chain.lpeAchieved,
      ...(chain.summary.artifactC
        ? { proofArtifactRef: chain.summary.artifactC }
        : {}),
    };

    return {
      ...confirmed,
      weaponization: chain.summary,
      kernelExploit,
      weaponizationRationale: chain.rationale,
      // Per-step records (incl. oracle-REFUSED negatives via `reason` /
      // `reachedRung < targetRung`) — the corpus writer's label source.
      weaponizationSteps: chain.perStep,
    };
  } catch {
    // Best-effort: never fail a confirmed verification because the chain tripped.
    return confirmed;
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
  if (result.minimization) {
    lines.push(
      `Reproducer minimized: ${result.minimization.originalUnitCount} → ` +
        `${result.minimization.minimizedUnitCount} units` +
        ` (${result.minimization.oracleCalls} oracle calls` +
        `${result.minimization.oneMinimal ? ", 1-minimal" : ""})`,
    );
  }
  if (result.primitive) {
    lines.push("", "---primitive---", ...describeKernelPrimitive(result.primitive));
  }

  // Weaponization climb (kernel-autonomy Phase 2a). Only present when a
  // weaponization chain drove this finding (opts.weaponize). Emits the highest
  // rung reached, the planner's missing-capability rationale, and the canary-
  // bound proof artifact reference when one exists. Additive — when absent the
  // evidence block is byte-for-byte the pre-Phase-2a output.
  const weaponizationLines: string[] = [];
  if (result.weaponization) {
    const w = result.weaponization;
    weaponizationLines.push(
      `Highest rung: ${w.highestRung}` +
        ` (reclaimLanded=${w.reclaimLanded}, lpeAchieved=${w.lpeAchieved})`,
    );
    if (typeof w.attempts === "number") {
      weaponizationLines.push(`Attempts: ${w.attempts}`);
    }
    if (result.weaponizationRationale?.length) {
      weaponizationLines.push("Planner rationale:");
      for (const r of result.weaponizationRationale) {
        weaponizationLines.push(`- ${r}`);
      }
    }
    if (w.artifactC) {
      weaponizationLines.push(
        `Proof artifact: ${w.artifactC.length} bytes of canary-bound C scaffold`,
      );
    }
  }

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
    ...(weaponizationLines.length
      ? ["", "---weaponization---", ...weaponizationLines]
      : []),
  ]
    .filter(Boolean)
    .join("\n");

  // Carry the structured kernel-exploit state forward (kernel-autonomy Phase
  // 2a). The core `KernelExploitContext` is structurally assignable to the
  // shared `KernelExploitState` mirror (guarded in exploit-context.ts).
  if (result.kernelExploit) {
    next.kernelExploit = result.kernelExploit;
  }

  if (
    (result.status === "confirmed" || result.status === "soft_hit") &&
    result.generated_program
  ) {
    next.evidence.response = result.generated_program;
  }

  if (result.status === "confirmed") {
    next.status = "confirmed";
  }

  // Severity reflects exploitability (issue #569): a confirmed / soft-hit
  // primitive can only escalate the finding's severity, never downgrade it.
  if (
    result.primitive &&
    (result.status === "confirmed" || result.status === "soft_hit")
  ) {
    next.severity = exploitabilityAdjustedSeverity(next.severity, result.primitive);
  }

  // A deterministically-achieved LPE is the strongest exploitability signal we
  // have: fold it through the same severity helper (which only ever escalates)
  // by treating the primitive as demonstrated. Never downgrades.
  if (result.kernelExploit?.lpeAchieved && result.primitive) {
    next.severity = exploitabilityAdjustedSeverity(next.severity, {
      ...result.primitive,
      controlDemo: { ...result.primitive.controlDemo, demonstrated: true },
    });
  }

  return next;
}

// Re-export so the CLI can import the canonical type names from one place.
export type {
  KernelVerifyOracleResult,
  KernelVerifyPhase,
  KernelVerifyRunner,
} from "./kernel-verify-types.js";

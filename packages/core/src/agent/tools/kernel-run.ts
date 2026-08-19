/**
 * `kernel_run` agent tool (pwnkit#271 Tier 2).
 *
 * This tool is OPT-IN: it is not in the global `TOOL_DEFINITIONS` table nor
 * returned by `getToolsForRole`. It is only made available to the constrained
 * kernel-verify agent loop in `packages/core/src/verify/kernel-verify.ts` so
 * web/audit agents cannot accidentally boot kernel VMs.
 *
 * Contract:
 *   - Args: `{ program: string, program_lang: "syz" | "c", expected_signature?: string }`
 *   - Calls the Tier 1 plumbing (`verifyKernelFinding`) and returns its result.
 *   - Every submission is parsed against a Zod schema ({@link kernelRunArgsSchema})
 *     and *rejected* on a mismatch before any subprocess is spawned — Theori's
 *     AIxCC T9 structured-output discipline: never trust free-form model output,
 *     validate the shape and refuse malformed PoV submissions.
 *   - Rejects oversized programs (> KERNEL_RUN_PROGRAM_MAX_BYTES) and invalid
 *     program_lang values; strips unknown top-level keys so model-emitted
 *     `argv`/`cwd` can never propagate downstream.
 *
 * The result shape matches `KernelVerifyResult` from `../verify/kernel-verify.ts`
 * so the agent gets back everything it needs to decide whether to retry or
 * declare success: the structured oracle verdict, the dmesg slice that fired,
 * and the matched/mismatched signature fields.
 */

import { z } from "zod";
import type { ToolDefinition } from "../types.js";
import type { Finding } from "@pwnkit/shared";
import type { KernelVerifyOracleResult, KernelVerifyRunner } from "../../verify/kernel-verify-types.js";

/**
 * Maximum size of a single reproducer program the agent may pass in one
 * tool call. Picked to fit a generous syzkaller program (or a chunky C
 * reproducer) while refusing the obvious "agent dumps all of vmlinux as
 * the program" failure mode.
 */
export const KERNEL_RUN_PROGRAM_MAX_BYTES = 64 * 1024;

export const KERNEL_RUN_TOOL_DEFINITION: ToolDefinition = {
  name: "kernel_run",
  description:
    "Run a generated kernel reproducer (syzkaller program or C reproducer) " +
    "through the Tier-1 kernel VM oracle. Returns whether KASAN/UBSAN fired, " +
    "whether the produced signature matches `expected_signature`, and a " +
    "dmesg excerpt. Use this to test reproducer hypotheses for the finding " +
    "you were given. Programs larger than 64 KiB are rejected.",
  parameters: {
    program: {
      type: "string",
      description:
        "Reproducer source. For program_lang='syz', a syzkaller program " +
        "(one syscall per line). For program_lang='c', a self-contained " +
        "C reproducer with main().",
    },
    program_lang: {
      type: "string",
      description: "Reproducer language. 'syz' (preferred) or 'c'.",
      enum: ["syz", "c"],
    },
    expected_signature: {
      type: "string",
      description:
        "Optional. Expected KASAN/UBSAN signature substring (e.g. " +
        "'slab-use-after-free' or the faulting function name) to match in " +
        "dmesg. If omitted, any kernel crash is treated as a soft hit.",
    },
  },
  required: ["program", "program_lang"],
};

/**
 * Argument shape after validation. Exported so the kernel-verify loop can
 * type-check the tool-call payload without re-parsing.
 */
export interface KernelRunArgs {
  program: string;
  program_lang: "syz" | "c";
  expected_signature?: string;
}

/**
 * Zod schema for a `kernel_run` tool-call payload (AIxCC T9 — Theori's
 * structured-output discipline: every agent submission is parsed against an
 * explicit schema and *rejected* on a mismatch, rather than trusting free-form
 * model output). This is the single source of truth for the contract; the
 * hand-rolled checks below were folded into it so there is exactly one place
 * the shape is defined.
 *
 * `.strip()` (zod's default for object schemas) drops any unknown top-level
 * keys — the model occasionally emits `argv`/`cwd`/`args` that must never
 * propagate downstream. `expected_signature` is normalised to a trimmed string,
 * and an empty/whitespace-only signature collapses to `undefined` (treat as
 * "any crash is a soft hit").
 */
export const kernelRunArgsSchema = z
  .object({
    program: z
      .string({
        required_error: "kernel_run: 'program' must be a non-empty string",
        invalid_type_error: "kernel_run: 'program' must be a non-empty string",
      })
      .min(1, "kernel_run: 'program' must be a non-empty string")
      .refine(
        (p) => Buffer.byteLength(p, "utf8") <= KERNEL_RUN_PROGRAM_MAX_BYTES,
        (p) => ({
          message: `kernel_run: 'program' exceeds ${KERNEL_RUN_PROGRAM_MAX_BYTES} bytes (got ${Buffer.byteLength(p, "utf8")})`,
        }),
      ),
    program_lang: z.enum(["syz", "c"], {
      errorMap: () => ({
        message: "kernel_run: 'program_lang' must be exactly 'syz' or 'c'",
      }),
    }),
    expected_signature: z
      .string({ invalid_type_error: "kernel_run: 'expected_signature' must be a string when provided" })
      .nullish()
      .transform((s) => {
        const trimmed = s?.trim();
        return trimmed && trimmed.length > 0 ? trimmed : undefined;
      }),
  })
  .strip()
  .transform((parsed): KernelRunArgs => ({
    program: parsed.program,
    program_lang: parsed.program_lang,
    ...(parsed.expected_signature !== undefined
      ? { expected_signature: parsed.expected_signature }
      : {}),
  }));

export interface KernelRunInvocation {
  args: KernelRunArgs;
  /** The finding under verification — supplied by the kernel-verify loop. */
  finding: Finding;
  /** Injected Tier 1 runner. Defaults to the real `verifyKernelFinding`. */
  runner: KernelVerifyRunner;
  /** Build target for the runner. */
  kernelTree: string;
  /** Build profile name, e.g. "kasan", "defconfig+kasan". */
  kernelConfig?: string;
  /** Force rebuild of cached kernel artifacts. */
  forceBuild?: boolean;
}

export interface KernelRunResult {
  ok: boolean;
  error?: string;
  oracle?: KernelVerifyOracleResult;
}

/**
 * Validate a raw tool-call argument bag for `kernel_run`. Returns a discriminated
 * union so the caller can branch without losing the rejection reason.
 *
 * Sanitization rules:
 *   - `program` must be a non-empty string ≤ KERNEL_RUN_PROGRAM_MAX_BYTES.
 *   - `program_lang` must be exactly "syz" or "c".
 *   - `expected_signature` is optional; when present, must be a string and
 *     trimmed of surrounding whitespace.
 *   - We strip any other top-level keys — the agent occasionally emits
 *     `args` / `cwd` / `argv` etc. that could be confused for shell argv if
 *     they leaked downstream. The Tier 1 runner never spawns user-controlled
 *     argv directly (the program is written to a shared file and consumed by
 *     the in-guest runner script), but defense-in-depth: only the three known
 *     fields propagate beyond this validator.
 */
export function validateKernelRunArgs(raw: unknown):
  | { ok: true; args: KernelRunArgs }
  | { ok: false; error: string } {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { ok: false, error: "kernel_run: arguments must be an object" };
  }

  const parsed = kernelRunArgsSchema.safeParse(raw);
  if (!parsed.success) {
    // Surface the first issue's message — our schema messages are already
    // self-describing ("kernel_run: 'program' …"), so we don't re-wrap them.
    const first = parsed.error.issues[0];
    return {
      ok: false,
      error: first?.message ?? "kernel_run: invalid arguments",
    };
  }

  return { ok: true, args: parsed.data };
}

/**
 * Execute a validated kernel_run call through the Tier 1 runner. The
 * kernel-verify loop is responsible for translating the result into a tool_use
 * payload the agent sees; this function is pure plumbing.
 */
export async function executeKernelRun(
  invocation: KernelRunInvocation,
): Promise<KernelRunResult> {
  try {
    const oracle = await invocation.runner({
      finding: invocation.finding,
      program: invocation.args.program,
      programLang: invocation.args.program_lang,
      expectedSignature: invocation.args.expected_signature,
      kernelTree: invocation.kernelTree,
      kernelConfig: invocation.kernelConfig,
      forceBuild: invocation.forceBuild,
    });
    return { ok: true, oracle };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

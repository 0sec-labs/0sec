/**
 * kernel/patch-to-poc.ts
 *
 * "Patch-to-PoC" directed n-day pipeline — turn an upstream security patch /
 * fix commit into a PoC PLAN for an unpatched downstream LTS/distro kernel.
 *
 * Direction of travel (the whole point): a security bug is fixed UPSTREAM, the
 * fix commit + diff become public, but the same bug is still live on an older
 * LTS / distro kernel where the fix was never backported. The patch itself is
 * the richest possible oracle for the bug — it names the faulting file, the
 * function, and (in the diff hunks) the exact guard that was added. This module
 * mines that signal to produce a directed trigger plan, instead of fuzzing
 * blind. It directly serves our older-LTS / CopyFail page-cache / rxrpc hunt.
 *
 * Lineage:
 *   - arXiv:2602.07287 (patch-directed n-day reproduction): use the fix diff to
 *     localize the bug and synthesize a trigger, then confirm under a sanitizer.
 *   - Project Zero "Big Sleep": LLM-assisted, variant/patch-guided vulnerability
 *     reproduction with a sanitizer as the ground-truth oracle.
 *
 * Four stages, mirroring `distro-adapt.ts`'s deterministic-core + LLM-assist
 * split:
 *   1. ANALYZE THE PATCH (deterministic). Parse the fix commit message + unified
 *      diff: classify the bug (UAF / OOB / race / …), and extract the touched
 *      file(s) + the enclosing function(s) of the changed hunks — the SINK.
 *      Reuses the security-keyword vocabulary + `Fixes:` trailer parsing shared
 *      with `fix-commit-intel.ts`.
 *   2. UNDERSTAND REACHABILITY (deterministic, tree-optional). When a kernel
 *      source tree is on disk, reuse `reachability-rank.ts` to rank the
 *      userspace syscalls that reach the sink — the entry points the trigger
 *      should drive.
 *   3. PRODUCE A PoC PLAN (LLM-assist). Combine the bug class, sink, reaching
 *      syscalls and a target-kernel applicability verdict into a concrete
 *      trigger plan: the syscall sequence + preconditions. The LLM, when
 *      supplied, fleshes out the trigger steps and emits a C reproducer
 *      SKELETON; the deterministic spine (sink, syscalls, applicability) is
 *      always present and never overridden by the model.
 *   4. HAND OFF TO VERIFY. Emit a `KernelVerifyRunnerInput`-shaped handoff (the
 *      program skeleton + expected KASAN signature + target tree) that the
 *      EXISTING verify lane (`verify/kernel-verify.ts` →
 *      `triage/kernel-vm-runner.ts`) consumes to build/boot/KASAN-confirm. We do
 *      NOT reimplement the runner — we produce the plan it eats.
 *
 * Downstream targeting reuses `distro-adapt.ts`: once the trigger shape exists,
 * `adaptReproForDistro` computes the config/precondition deltas for the specific
 * LTS/distro target. This module's `targetApplicability` answers the prior
 * question the adaptation can't: "is this kernel even old enough to still be
 * vulnerable?".
 *
 * HONESTY — the paper's bottlenecks are real and this module does NOT paper over
 * them:
 *   - LARGE-PATCH CONTEXT. A multi-file refactor-style fix dilutes the signal;
 *     the diff parser localizes hunks but cannot know which of N touched
 *     functions is THE sink. We surface ALL touched functions ranked, flag low
 *     confidence, and lean on the LLM/operator to disambiguate.
 *   - DEBUGGER / SANITIZER-OUTPUT INTERPRETATION. Deciding whether a KASAN
 *     splat actually corresponds to the patched bug (vs. an unrelated crash) is
 *     left to the verify lane's signature match — this module only proposes the
 *     EXPECTED signature; it does not adjudicate the real one.
 *
 * Analysis / plan-producing ONLY. No build, no boot, no network, no new deps.
 */

import type { Finding } from "@0sec/shared";
import type {
  NativeContentBlock,
  NativeMessage,
  NativeRuntime,
} from "../runtime/types.js";
import {
  rankSinkReachability,
  type ReachabilityCandidate,
} from "./reachability-rank.js";

// ── Bug-class vocabulary ──

/**
 * Memory-safety / lifetime bug classes we recognise from a fix commit, each
 * mapped to the KASAN report keyword the verify lane should expect to see. The
 * keyword set mirrors `fix-commit-intel.ts`'s SECURITY_KEYWORDS but is grouped
 * into classes so we can emit a concrete expected-signature for the oracle.
 */
export type BugClass =
  | "use-after-free"
  | "out-of-bounds"
  | "double-free"
  | "race"
  | "null-deref"
  | "uninit"
  | "overflow"
  | "refcount"
  | "unknown";

interface BugClassRule {
  bugClass: BugClass;
  /** Lowercased substrings in the commit message/diff that imply this class. */
  needles: string[];
  /**
   * The substring the KASAN / sanitizer report prints for this class — what the
   * verify lane should match dmesg against. Empty when there is no single
   * canonical splat string (race/refcount surface as a secondary class).
   */
  kasanSignature: string;
}

/**
 * Order matters: earlier rules win when a message matches several (a "UAF" is a
 * more specific verdict than the "double free" that sometimes co-occurs).
 */
const BUG_CLASS_RULES: readonly BugClassRule[] = [
  {
    bugClass: "use-after-free",
    needles: ["use-after-free", "use after free", "uaf"],
    kasanSignature: "KASAN: use-after-free",
  },
  {
    bugClass: "double-free",
    needles: ["double-free", "double free"],
    kasanSignature: "KASAN: double-free",
  },
  {
    bugClass: "out-of-bounds",
    needles: [
      "out-of-bounds",
      "out of bounds",
      "oob read",
      "oob write",
      "slab-out-of-bounds",
      "stack-out-of-bounds",
    ],
    kasanSignature: "KASAN: slab-out-of-bounds",
  },
  {
    bugClass: "race",
    needles: ["data race", "race condition", "kcsan"],
    kasanSignature: "KCSAN: data-race",
  },
  {
    bugClass: "null-deref",
    needles: ["null deref", "null-ptr-deref", "null pointer"],
    kasanSignature: "general protection fault",
  },
  {
    bugClass: "uninit",
    needles: ["uninitialized", "uninit", "kmsan"],
    kasanSignature: "KMSAN: uninit-value",
  },
  {
    bugClass: "overflow",
    needles: ["overflow", "underflow"],
    kasanSignature: "UBSAN",
  },
  {
    bugClass: "refcount",
    needles: ["refcount", "reference count"],
    kasanSignature: "refcount_t",
  },
];

// ── Patch / diff parsing ──

/** A single changed file in a unified diff, with the functions its hunks touch. */
export interface TouchedFile {
  /** Repo-relative path (the `b/…` side of the diff). */
  path: string;
  /**
   * Functions whose body the hunks land in, best-effort from `@@ … @@ <ctx>`
   * hunk headers and added/removed lines. May be empty for a pure data change.
   */
  functions: string[];
  /** 1-based line numbers (post-image) the hunks add/modify, for sink locating. */
  changedLines: number[];
}

/** Structured result of parsing a fix commit / raw diff. Deterministic. */
export interface PatchAnalysis {
  /** Referenced commit from a `Fixes:` trailer, if present. */
  fixesTag?: string;
  /** Best-guess bug class from the message + diff. */
  bugClass: BugClass;
  /** The KASAN/sanitizer signature the verify oracle should expect. */
  expectedSignature: string;
  /** Files the patch changes, with touched functions. */
  touchedFiles: TouchedFile[];
  /**
   * The single most likely faulting file:function — the SINK. Heuristic: the
   * first changed function in the first changed `.c` file. Honest about
   * ambiguity: see `ambiguous`.
   */
  primarySink?: { file: string; function?: string; line?: number };
  /**
   * True when the patch touches many functions/files (large-patch context
   * bottleneck) so a consumer knows the primary-sink pick is low confidence.
   */
  ambiguous: boolean;
  /** Human-readable parse notes. */
  notes: string[];
}

/** A `Fixes: <sha> ("subject")` trailer reference. */
function extractFixesTag(text: string): string | undefined {
  const m = text.match(/^\s*Fixes:\s*([0-9a-f]{8,40})\b/im);
  return m ? m[1] : undefined;
}

/** Classify the bug from the commit message + diff body. */
function classifyBug(haystack: string): { bugClass: BugClass; signature: string } {
  const lower = haystack.toLowerCase();
  for (const rule of BUG_CLASS_RULES) {
    if (rule.needles.some((n) => lower.includes(n))) {
      return { bugClass: rule.bugClass, signature: rule.kasanSignature };
    }
  }
  return { bugClass: "unknown", signature: "" };
}

/**
 * The `@@ -a,b +c,d @@ <trailing context>` hunk header. The trailing context is
 * git's best guess at the enclosing function/declaration — a strong, free sink
 * hint. We also parse the `+c` start line to anchor changed-line numbers.
 */
const HUNK_HEADER_RE =
  /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@\s*(.*)$/;

/** Pull a C function name out of a hunk header's trailing context. */
function functionFromHunkContext(ctx: string): string | undefined {
  // Typical: "static int rxrpc_recvmsg(struct socket *sock, ...)" or
  // "void foo(void)". Grab the identifier immediately before a "(".
  const m = ctx.match(/([A-Za-z_]\w*)\s*\(/);
  if (m && !["if", "for", "while", "switch", "sizeof", "return"].includes(m[1]!)) {
    return m[1];
  }
  return undefined;
}

/** A `diff --git a/x b/y` file header → the post-image path `y`. */
const DIFF_FILE_RE = /^diff --git a\/(?:\S+) b\/(\S+)/;
/** Fallback `+++ b/path` header. */
const PLUS_FILE_RE = /^\+\+\+ b\/(\S+)/;

/**
 * Parse a unified diff into touched files + functions + changed line numbers.
 * Tolerant of `git show` / `git format-patch` / bare `diff -u` shapes. Pure.
 */
function parseUnifiedDiff(diff: string): TouchedFile[] {
  const files: TouchedFile[] = [];
  let current: TouchedFile | undefined;
  let postLine = 0; // running post-image line cursor within a hunk

  for (const raw of diff.split("\n")) {
    const fileMatch = raw.match(DIFF_FILE_RE) ?? raw.match(PLUS_FILE_RE);
    if (fileMatch) {
      const path = fileMatch[1]!;
      if (path === "/dev/null") continue;
      current = files.find((f) => f.path === path);
      if (!current) {
        current = { path, functions: [], changedLines: [] };
        files.push(current);
      }
      continue;
    }

    const hunk = raw.match(HUNK_HEADER_RE);
    if (hunk && current) {
      postLine = Number(hunk[1]);
      const fn = functionFromHunkContext(hunk[2] ?? "");
      if (fn && !current.functions.includes(fn)) current.functions.push(fn);
      continue;
    }

    if (!current) continue;

    // Track post-image line numbers across hunk body lines.
    if (raw.startsWith("+") && !raw.startsWith("+++")) {
      current.changedLines.push(postLine);
      // An added line that defines/opens a function reveals a sink function the
      // hunk-header context may have missed (e.g. a whole new guard helper).
      const def = raw.slice(1).match(/^[A-Za-z_][\w\s*]*?\b([A-Za-z_]\w*)\s*\(/);
      if (def && !current.functions.includes(def[1]!)) {
        const name = def[1]!;
        if (!["if", "for", "while", "switch", "sizeof", "return"].includes(name)) {
          current.functions.push(name);
        }
      }
      postLine++;
    } else if (raw.startsWith("-") && !raw.startsWith("---")) {
      // removed line: does not advance the post-image cursor.
    } else if (!raw.startsWith("\\")) {
      // context line: advances post-image cursor.
      postLine++;
    }
  }

  return files;
}

/**
 * STAGE 1 — analyze a fix commit / raw diff deterministically. Accepts either a
 * full `git show` (message + diff) or a bare unified diff. No tree, no network.
 */
export function analyzePatch(fixCommitOrDiff: string): PatchAnalysis {
  const notes: string[] = [];
  const fixesTag = extractFixesTag(fixCommitOrDiff);
  const { bugClass, signature } = classifyBug(fixCommitOrDiff);
  if (bugClass === "unknown") {
    notes.push(
      "could not classify the bug from the commit text; expected-signature " +
        "left empty (verify lane will accept any crash signal)",
    );
  }

  const touchedFiles = parseUnifiedDiff(fixCommitOrDiff);
  if (touchedFiles.length === 0) {
    notes.push("no unified-diff hunks found; patch analysis is message-only");
  }

  // Primary sink: first changed function in the first changed C source file.
  // C sources are the bug surface; headers/Kconfig are deprioritized.
  const cFiles = touchedFiles.filter((f) => f.path.endsWith(".c"));
  const sinkFile = cFiles[0] ?? touchedFiles[0];
  const primarySink = sinkFile
    ? {
        file: sinkFile.path,
        ...(sinkFile.functions[0] ? { function: sinkFile.functions[0] } : {}),
        ...(sinkFile.changedLines[0] !== undefined
          ? { line: sinkFile.changedLines[0] }
          : {}),
      }
    : undefined;

  const totalFns = touchedFiles.reduce((n, f) => n + f.functions.length, 0);
  const ambiguous = touchedFiles.length > 2 || totalFns > 3;
  if (ambiguous) {
    notes.push(
      `large patch (${touchedFiles.length} files, ${totalFns} functions): ` +
        "primary-sink pick is LOW confidence — disambiguate via LLM/operator " +
        "(paper's large-patch-context bottleneck)",
    );
  }

  return {
    ...(fixesTag ? { fixesTag } : {}),
    bugClass,
    expectedSignature: signature,
    touchedFiles,
    ...(primarySink ? { primarySink } : {}),
    ambiguous,
    notes,
  };
}

// ── Target-kernel applicability ──

/** Verdict on whether the target kernel is plausibly still vulnerable. */
export interface TargetApplicability {
  /**
   * "vulnerable" => fix is plausibly NOT present on the target (n-day live).
   * "patched"    => the fix appears present (skip — not an n-day here).
   * "unknown"    => insufficient info (no tree / no version anchor).
   */
  verdict: "vulnerable" | "patched" | "unknown";
  reason: string;
}

export interface TargetKernel {
  /** Version string, e.g. "5.15.139" (LTS) or "6.1.0-21-amd64" (distro). */
  version: string;
  /** Distro profile id for downstream targeting (see distro-adapt.ts). */
  distro?: string;
  /**
   * Optional path to an on-disk source tree for the TARGET kernel. When present,
   * a consumer can run `fix-commit-intel.checkAlreadyFixed` to confirm the fix
   * is absent before spending a verify boot — we surface the file/function for
   * that check rather than re-shelling git here.
   */
  treePath?: string;
}

/**
 * Decide, from version anchors alone, whether the target is plausibly still
 * vulnerable. This is deliberately conservative: with no tree we can only reason
 * about version ordering vs. the patch's first-fixed release, and we DON'T have
 * that release here (it is not in the diff). So the honest default is "unknown"
 * unless the caller supplies a tree to drive the deterministic already-fixed
 * gate. We still emit a structured verdict so the plan is self-describing.
 */
function assessApplicability(
  analysis: PatchAnalysis,
  target: TargetKernel,
): TargetApplicability {
  if (target.treePath && analysis.primarySink) {
    // We intentionally do NOT shell git here (keeps this module pure / testable
    // and avoids a second extraction of fix-commit-intel's parsing). The plan
    // names the file+function so the consumer runs `checkAlreadyFixed` against
    // the target tree; until then the verdict is unknown-pending-gate.
    return {
      verdict: "unknown",
      reason:
        `target tree supplied (${target.treePath}); run ` +
        `checkAlreadyFixed({ tree, filePath: "${analysis.primarySink.file}"` +
        (analysis.primarySink.function
          ? `, faultingFunction: "${analysis.primarySink.function}"`
          : "") +
        " }) to confirm the fix is absent before a verify boot",
    };
  }
  return {
    verdict: "unknown",
    reason:
      `no target tree for ${target.version}; applicability is unverified — ` +
      "supply treePath to gate via fix-commit-intel.checkAlreadyFixed, or " +
      "compare the Fixes: anchor against the target's stable backport log",
  };
}

// ── PoC plan + verify handoff ──

/** A concrete trigger step in the PoC plan. */
export interface TriggerStep {
  /** Ordinal, 1-based. */
  order: number;
  /** The syscall / action, e.g. "socket(AF_RXRPC, SOCK_DGRAM, 0)". */
  action: string;
  /** Why this step matters for reaching/triggering the bug. */
  rationale: string;
}

/**
 * The verify-lane handoff. Shaped to drop into the existing
 * `verify/kernel-verify.ts` runner input (a `KernelVerifyRunnerInput`): we
 * supply the program skeleton, its language, the expected KASAN signature and
 * the target tree. We deliberately do NOT construct a full `Finding` here (that
 * belongs to the caller that owns finding identity); we provide the program +
 * oracle the runner needs.
 */
export interface VerifyHandoff {
  /** The reproducer skeleton the verify lane builds & boots. */
  program: string;
  /** Skeleton language — always "c" for a hand-built trigger. */
  programLang: "c";
  /** KASAN/sanitizer signature the oracle matches dmesg against. */
  expectedSignature?: string;
  /** Path to the TARGET kernel source tree (consumer fills if known). */
  kernelTree?: string;
  /** Suggested build profile — KASAN is the ground-truth oracle. */
  kernelConfig: string;
  /**
   * The verify-lane consumer. Recorded so the plan documents its own next hop
   * rather than the runner being reinvented here.
   */
  consumer: "verify/kernel-verify.ts → triage/kernel-vm-runner.ts";
}

/** The full Patch-to-PoC plan. */
export interface PatchToPocPlan {
  /** Stage 1 output. */
  analysis: PatchAnalysis;
  /** The target the plan is aimed at. */
  target: TargetKernel;
  /** Stage 2: ranked syscalls reaching the sink (empty without a tree). */
  reachingSyscalls: ReachabilityCandidate[];
  /** Stage: is the target plausibly still vulnerable? */
  targetApplicability: TargetApplicability;
  /** Stage 3: the trigger plan (syscall sequence + preconditions). */
  triggerSteps: TriggerStep[];
  /** Preconditions the harness must satisfy before the trigger (free-text). */
  preconditions: string[];
  /** Stage 4: the handoff the existing verify lane consumes. */
  verifyHandoff: VerifyHandoff;
  /** Whether the LLM was consulted for the trigger plan. */
  llmAssisted: boolean;
  /** Aggregated notes (analysis + plan stages). */
  notes: string[];
}

export interface PatchToPocOptions {
  /**
   * Path to a kernel SOURCE tree for STAGE 2 reachability ranking. Best results
   * with the TARGET (unpatched) tree, but the upstream tree also works for the
   * call-graph shape. Omit to skip reachability (plan still produced).
   */
  treePath?: string;
  /** Cap on reaching-syscall candidates surfaced. Default 5. */
  maxSyscalls?: number;
  /** Subsystem hint passed through to the trigger-plan prompt. */
  subsystemHint?: string;
}

// ── LLM assist (stage 3) ──

const LLM_SYSTEM_PROMPT = [
  "You are a Linux kernel exploitation engineer building a directed n-day PoC",
  "from an upstream security PATCH, to trigger the SAME bug on an older",
  "downstream LTS/distro kernel where the fix was never backported.",
  "",
  "You are given: the bug class, the faulting file:function (the sink), the",
  "userspace syscalls statically found to reach the sink (may be empty), and the",
  "target kernel. Produce a concrete TRIGGER PLAN: the ordered syscall sequence",
  "that reaches and triggers the bug, the runtime preconditions, and a MINIMAL C",
  "reproducer SKELETON (compilable shape with the syscall sequence; stubs/TODOs",
  "are fine where a value must be fuzzed). Ground every step in the sink + the",
  "reaching syscalls; do NOT invent kernel APIs or CONFIG names. If the reaching",
  "syscalls are empty or the sink is reached only via a function pointer",
  "(ioctl/netlink dispatch), say so and propose the most plausible entry point",
  "rather than guessing silently.",
  "",
  "Respond with a single fenced ```json block:",
  '{ "triggerSteps": [ { "action": "syscall(...)", "rationale": "..." } ],',
  '  "preconditions": ["..."],',
  '  "reproducerSkeleton": "<full C skeleton, or empty string>" }',
].join("\n");

interface LlmPlanResponse {
  triggerSteps: Array<{ action: string; rationale: string }>;
  preconditions: string[];
  reproducerSkeleton: string;
}

function responseText(content: NativeContentBlock[]): string {
  return content
    .filter((b): b is NativeContentBlock & { type: "text" } => b.type === "text")
    .map((b) => b.text)
    .join("\n");
}

function extractJsonBlock(text: string): string {
  const fenced =
    text.match(/```(?:json)?\s*\n([\s\S]*?)```/i) ?? text.match(/(\{[\s\S]*\})/);
  return (fenced ? fenced[1]! : text).trim();
}

function parseLlmResponse(raw: string): LlmPlanResponse | null {
  try {
    const parsed = JSON.parse(extractJsonBlock(raw)) as unknown;
    if (typeof parsed !== "object" || parsed === null) return null;
    const obj = parsed as Record<string, unknown>;

    const rawSteps = Array.isArray(obj.triggerSteps) ? obj.triggerSteps : [];
    const triggerSteps = rawSteps
      .map((s): { action: string; rationale: string } | null => {
        if (typeof s !== "object" || s === null) return null;
        const so = s as Record<string, unknown>;
        if (typeof so.action !== "string") return null;
        return {
          action: so.action,
          rationale: typeof so.rationale === "string" ? so.rationale : "",
        };
      })
      .filter((s): s is { action: string; rationale: string } => s !== null);

    const preconditions = Array.isArray(obj.preconditions)
      ? obj.preconditions.filter((p): p is string => typeof p === "string")
      : [];
    const reproducerSkeleton =
      typeof obj.reproducerSkeleton === "string" ? obj.reproducerSkeleton : "";

    return { triggerSteps, preconditions, reproducerSkeleton };
  } catch {
    return null;
  }
}

async function runLlmPlan(
  analysis: PatchAnalysis,
  target: TargetKernel,
  reaching: ReachabilityCandidate[],
  llm: NativeRuntime,
  subsystemHint: string | undefined,
  notes: string[],
): Promise<LlmPlanResponse> {
  const syscalls = reaching.length
    ? reaching
        .map(
          (c) =>
            `- ${c.entry.name} (path ${c.path.join(" → ")}, confidence ${c.confidence})`,
        )
        .join("\n")
    : "(none found statically — likely an indirect/function-pointer path)";

  const prompt = [
    `Bug class: ${analysis.bugClass}`,
    `Expected sanitizer signature: ${analysis.expectedSignature || "(unknown)"}`,
    `Sink: ${analysis.primarySink ? `${analysis.primarySink.file}:${analysis.primarySink.function ?? "?"}` : "(unresolved)"}`,
    analysis.ambiguous
      ? `NOTE: large patch — touched functions: ${analysis.touchedFiles
          .flatMap((f) => f.functions)
          .join(", ")} (sink pick is low confidence)`
      : "",
    subsystemHint ? `Subsystem hint: ${subsystemHint}` : "",
    `Target kernel: ${target.version}${target.distro ? ` (${target.distro})` : ""}`,
    "",
    "Reaching syscalls:",
    syscalls,
  ]
    .filter(Boolean)
    .join("\n");

  const message: NativeMessage = {
    role: "user",
    content: [{ type: "text", text: prompt }],
  };

  try {
    const result = await llm.executeNative(LLM_SYSTEM_PROMPT, [message], []);
    const parsed = parseLlmResponse(responseText(result.content));
    if (!parsed) {
      notes.push("LLM trigger-plan returned unparseable output; ignored");
      return { triggerSteps: [], preconditions: [], reproducerSkeleton: "" };
    }
    return parsed;
  } catch (err) {
    notes.push(
      `LLM trigger-plan failed (${err instanceof Error ? err.message : "error"}); ` +
        "deterministic spine only",
    );
    return { triggerSteps: [], preconditions: [], reproducerSkeleton: "" };
  }
}

// ── Reproducer skeleton (deterministic fallback) ──

/**
 * A minimal, compilable C skeleton produced WITHOUT the LLM, so the verify
 * handoff always carries a program. It encodes the bug class, sink, and reaching
 * syscalls as comments + TODOs — a starting point the verify lane / operator
 * fleshes out. Intentionally not a working exploit.
 */
function deterministicSkeleton(
  analysis: PatchAnalysis,
  target: TargetKernel,
  reaching: ReachabilityCandidate[],
): string {
  const entry = reaching[0]?.entry.name;
  return [
    "// Patch-to-PoC directed n-day skeleton (auto-generated, NOT a working exploit).",
    `// Bug class : ${analysis.bugClass}`,
    `// Sink      : ${analysis.primarySink ? `${analysis.primarySink.file}:${analysis.primarySink.function ?? "?"}` : "(unresolved)"}`,
    `// Target    : ${target.version}${target.distro ? ` (${target.distro})` : ""}`,
    `// Expected  : ${analysis.expectedSignature || "(any crash signal)"}`,
    "//",
    entry
      ? `// Reaching syscall hint: ${entry} (see plan.reachingSyscalls for the full chain).`
      : "// No static reaching syscall — likely an indirect (ioctl/netlink) path; pick the entry from the sink's file_operations.",
    "#define _GNU_SOURCE",
    "#include <fcntl.h>",
    "#include <unistd.h>",
    "#include <sys/syscall.h>",
    "#include <sys/socket.h>",
    "",
    "int main(void) {",
    "  // TODO: realize the trigger sequence from plan.triggerSteps.",
    entry
      ? `  // 1. drive ${entry} to reach ${analysis.primarySink?.function ?? "the sink"}.`
      : "  // 1. open the device/socket that dispatches to the sink.",
    "  // 2. arrange the state the patch guarded against (e.g. the freed/oob object).",
    "  // 3. re-enter to trigger the use; expect the sanitizer splat above.",
    "  return 0;",
    "}",
    "",
  ].join("\n");
}

// ── Public API ──

/**
 * Produce a Patch-to-PoC directed n-day plan: from an upstream fix commit / diff
 * to a PoC PLAN for an unpatched downstream `target` kernel.
 *
 * Deterministic spine (always): patch analysis (bug class + sink), reachability
 * ranking when `opts.treePath` is set, a target-applicability verdict, and a
 * compilable reproducer SKELETON wrapped in a verify-lane handoff. LLM-assist
 * (when `llm` supplied): a concrete trigger-step sequence + preconditions + a
 * richer skeleton — advisory; it never removes the deterministic spine.
 *
 * ANALYSIS / PLAN-PRODUCING ONLY. Building, booting and KASAN-confirming the
 * reproducer is the job of the EXISTING verify lane
 * (`verify/kernel-verify.ts` → `triage/kernel-vm-runner.ts`), which consumes
 * `plan.verifyHandoff`. Downstream config/precondition deltas for the specific
 * distro come from `distro-adapt.ts`'s `adaptReproForDistro`.
 */
export async function patchToPocPlan(
  fixCommitOrDiff: string,
  target: TargetKernel,
  llm?: NativeRuntime,
  opts: PatchToPocOptions = {},
): Promise<PatchToPocPlan> {
  const notes: string[] = [];

  // Stage 1 — analyze the patch.
  const analysis = analyzePatch(fixCommitOrDiff);
  notes.push(...analysis.notes);

  // Stage 2 — reachability (only with a source tree + a resolved sink file).
  let reachingSyscalls: ReachabilityCandidate[] = [];
  const treePath = opts.treePath ?? target.treePath;
  if (treePath && analysis.primarySink) {
    try {
      const result = await rankSinkReachability(
        {
          file: analysis.primarySink.file,
          line: analysis.primarySink.line ?? 1,
          ...(analysis.primarySink.function
            ? { function: analysis.primarySink.function }
            : {}),
        },
        treePath,
        { maxCandidates: opts.maxSyscalls ?? 5 },
      );
      reachingSyscalls = result.candidates;
      notes.push(...result.warnings);
    } catch (err) {
      notes.push(
        `reachability ranking skipped (${err instanceof Error ? err.message : "error"})`,
      );
    }
  } else if (!treePath) {
    notes.push(
      "no source tree supplied; skipping syscall reachability (stage 2) — " +
        "trigger entry points are LLM/operator-supplied",
    );
  }

  // Stage 3 — applicability + trigger plan.
  const targetApplicability = assessApplicability(analysis, target);

  let triggerSteps: TriggerStep[] = [];
  let preconditions: string[] = [];
  let reproSkeleton = deterministicSkeleton(analysis, target, reachingSyscalls);
  let llmAssisted = false;

  if (llm) {
    llmAssisted = true;
    const llmResult = await runLlmPlan(
      analysis,
      target,
      reachingSyscalls,
      llm,
      opts.subsystemHint,
      notes,
    );
    triggerSteps = llmResult.triggerSteps.map((s, i) => ({
      order: i + 1,
      action: s.action,
      rationale: s.rationale,
    }));
    preconditions = llmResult.preconditions;
    if (llmResult.reproducerSkeleton.trim().length > 0) {
      reproSkeleton = llmResult.reproducerSkeleton;
    }
  }

  // Stage 4 — verify-lane handoff.
  const verifyHandoff: VerifyHandoff = {
    program: reproSkeleton,
    programLang: "c",
    ...(analysis.expectedSignature
      ? { expectedSignature: analysis.expectedSignature }
      : {}),
    ...(treePath ? { kernelTree: treePath } : {}),
    kernelConfig: "defconfig+kasan",
    consumer: "verify/kernel-verify.ts → triage/kernel-vm-runner.ts",
  };

  return {
    analysis,
    target,
    reachingSyscalls,
    targetApplicability,
    triggerSteps,
    preconditions,
    verifyHandoff,
    llmAssisted,
    notes,
  };
}

/**
 * Convenience: shape a {@link VerifyHandoff} + a caller-owned {@link Finding}
 * into the exact `KernelVerifyRunnerInput` the verify lane expects. Kept as a
 * thin mapper (no logic) so the type coupling lives in one place; the caller
 * supplies finding identity and the (possibly fleshed-out) program.
 */
export function handoffToVerifyInput(
  handoff: VerifyHandoff,
  finding: Finding,
  kernelTree: string,
): {
  finding: Finding;
  program: string;
  programLang: "c";
  expectedSignature?: string;
  kernelTree: string;
  kernelConfig?: string;
} {
  return {
    finding,
    program: handoff.program,
    programLang: handoff.programLang,
    ...(handoff.expectedSignature
      ? { expectedSignature: handoff.expectedSignature }
      : {}),
    kernelTree,
    kernelConfig: handoff.kernelConfig,
  };
}

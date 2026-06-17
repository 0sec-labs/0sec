/**
 * Prompts + subsystem-source-slice utilities for the Tier 2 kernel-finding
 * verifier (#271). See `kernel-verify.ts` for the loop that consumes these.
 *
 * The agent receives a small, fixed prompt:
 *   - Finding identity (title, severity, category, faulting function, file:line)
 *   - Subsystem tag (e.g. "net/tcp", "fs/ext4")
 *   - A slice of the subsystem's source (best-effort, opt-in via opts.sourceSlice)
 *   - The available tools (bash, read_file, run_command, kernel_run)
 *   - The success criterion (kernel_run signature_matched=true ⇒ done)
 *   - Attempt budget reminder
 *
 * The agent emits exactly one structured response per turn: either a tool_use
 * for kernel_run (program + program_lang + expected_signature) or a text
 * "give up" message. We don't try to harvest free-form findings — this loop's
 * only job is to drive the oracle.
 */

import { existsSync, readFileSync, statSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import type { Finding } from "@pwnkit/shared";
import { parseFaultingPc, parseSlabCache } from "../triage/kernel-primitive.js";

/**
 * Static cap on a single subsystem-source slice we ship to the agent. The
 * cap is a soft byte budget — `selectSubsystemSourceSlice` stops appending
 * file contents once we've crossed it. Picked so prompts stay under typical
 * provider context limits even at 6 attempts.
 */
export const SUBSYSTEM_SLICE_MAX_BYTES = 24 * 1024;

/**
 * Per-file truncation cap. Some kernel files (e.g. `net/ipv4/tcp_input.c`)
 * are 5k+ lines; reading them whole would blow the budget on a single file.
 */
const PER_FILE_MAX_BYTES = 6 * 1024;

/**
 * Extra metadata extracted from a finding's `evidence.analysis` block. The
 * Linux-kernel review profile encodes these as `Subsystem: foo` / `Hypothesis:
 * true` lines (see `findings-parser.ts`), so we reverse that encoding here.
 */
export interface KernelFindingMetadata {
  subsystem?: string;
  hypothesis?: boolean;
  faultingFunction?: string;
  filePath?: string;
  fileLine?: number;
  /**
   * Faulting program counter (`symbol+0xoffset/0xsize`), surfaced from any
   * KASAN splat embedded in the finding's evidence (kernel-autonomy Phase 1).
   * Optional and additive.
   */
  faultingPc?: string;
  /**
   * Slab cache (`kmalloc-NNN`) the faulting object lives in, surfaced from the
   * embedded splat. Optional and additive.
   */
  slabCache?: string;
}

/**
 * Best-effort parse of the metadata stored in a kernel-review Finding. The
 * profile emits a structured block whose key fields land in
 * `evidence.analysis` as line-prefixed labels and in `evidence.request` as
 * `path/to/file.c:42`. We tolerate missing fields — callers that need a
 * specific field check for it after this returns.
 */
export function extractKernelFindingMetadata(finding: Finding): KernelFindingMetadata {
  const out: KernelFindingMetadata = {};

  const analysis = finding.evidence?.analysis ?? "";
  const subsystemMatch = analysis.match(/^\s*Subsystem:\s*([^\n]+)$/im);
  if (subsystemMatch) out.subsystem = subsystemMatch[1]?.trim();
  const hypMatch = analysis.match(/^\s*Hypothesis:\s*(true|false)\s*$/im);
  if (hypMatch) out.hypothesis = hypMatch[1]?.toLowerCase() === "true";

  const request = finding.evidence?.request ?? "";
  const fileRef = request.match(/^([\w./\-+]+\.[ch])(?::(\d+))?\s*$/);
  if (fileRef) {
    out.filePath = fileRef[1];
    if (fileRef[2]) out.fileLine = parseInt(fileRef[2]!, 10);
  }

  // The finding's `title` for kernel review findings is typically
  // `function_name: short description`. We grab the leading identifier so the
  // agent has something concrete to target even if `evidence.request` is bare.
  const titleFn = finding.title?.match(/^([a-zA-Z_][\w]*)\b/);
  if (titleFn) out.faultingFunction = titleFn[1];

  // Surface dmesg-derived exploit fields when the finding embeds a KASAN splat
  // (kernel-autonomy Phase 1). The splat may live in any of the evidence
  // strings, so sniff across all three; the parsers are defensive (undefined
  // on no-match).
  const evidenceText = [
    finding.evidence?.analysis,
    finding.evidence?.response,
    finding.evidence?.request,
  ]
    .filter(Boolean)
    .join("\n");
  const faultingPc = parseFaultingPc(evidenceText);
  if (faultingPc) out.faultingPc = faultingPc;
  const slabCache = parseSlabCache(evidenceText);
  if (slabCache) out.slabCache = slabCache;

  return out;
}

/**
 * Convert a subsystem tag (e.g. "net/tcp", "fs/ext4", "drivers/usb") to a
 * candidate directory path under the kernel tree. Falls back to the tag
 * itself for paths the SUBSYSTEM_PATTERNS table emits literally.
 */
export function subsystemToKernelPath(subsystem: string): string {
  // Most labels are already kernel-tree-shaped; trim leading/trailing slashes.
  return subsystem.replace(/^\/+|\/+$/g, "");
}

/**
 * Select a slice of the subsystem source to include in the agent prompt.
 *
 * Strategy:
 *   1. Prefer the exact file referenced in the finding (`metadata.filePath`)
 *      — that's the file the static reviewer cited, so it almost certainly
 *      contains the bug.
 *   2. Then add up to N additional .c/.h files in the same subsystem
 *      directory, picking ones whose names share a prefix with the faulting
 *      function (e.g. `tcp_input.c` for a `tcp_*` function).
 *   3. Stop as soon as we've crossed SUBSYSTEM_SLICE_MAX_BYTES total.
 *
 * Returns an array of `{ relativePath, content }` so the prompt renderer can
 * format each file with a clear header (and so tests can assert on the slice
 * boundaries without parsing the rendered prompt).
 *
 * **CAVEAT for human review.** Picking the right slice is the load-bearing
 * heuristic here: too narrow and the agent doesn't see the syscall entry
 * shape, too wide and we blow the context window. Current heuristic (cited
 * file + same-prefix siblings, capped at 24 KiB) is opinionated and worth
 * revisiting once we have real runs to learn from. The function is exported
 * for tests so we can tune it without re-doing the whole loop.
 */
export function selectSubsystemSourceSlice(args: {
  kernelTree: string;
  metadata: KernelFindingMetadata;
  maxBytes?: number;
}): Array<{ relativePath: string; content: string }> {
  const { kernelTree, metadata } = args;
  const maxBytes = args.maxBytes ?? SUBSYSTEM_SLICE_MAX_BYTES;
  const slices: Array<{ relativePath: string; content: string }> = [];
  let used = 0;

  const add = (absPath: string): void => {
    if (used >= maxBytes) return;
    if (!existsSync(absPath)) return;
    try {
      const stat = statSync(absPath);
      if (!stat.isFile()) return;
    } catch {
      return;
    }
    let content: string;
    try {
      content = readFileSync(absPath, "utf8");
    } catch {
      return;
    }
    // Per-file truncation: long enough to see a function or two but not the
    // whole 5k-line .c file.
    if (Buffer.byteLength(content, "utf8") > PER_FILE_MAX_BYTES) {
      content = content.slice(0, PER_FILE_MAX_BYTES) + "\n/* …[truncated]… */\n";
    }
    const size = Buffer.byteLength(content, "utf8");
    if (used + size > maxBytes) return;
    used += size;
    const relativePath = relative(kernelTree, absPath) || absPath;
    // De-dup so we don't list the cited file twice.
    if (slices.some((s) => s.relativePath === relativePath)) return;
    slices.push({ relativePath, content });
  };

  // 1. The exact file the static reviewer cited.
  if (metadata.filePath) {
    add(join(kernelTree, metadata.filePath));
  }

  // 2. Same-subsystem siblings, prefix-matched to the faulting function.
  if (metadata.subsystem) {
    const dir = join(kernelTree, subsystemToKernelPath(metadata.subsystem));
    if (existsSync(dir)) {
      let entries: string[] = [];
      try {
        entries = readdirSync(dir);
      } catch {
        entries = [];
      }
      // Prefer files whose basename shares the leading function-name prefix,
      // then any remaining .c files alphabetically.
      const prefix = metadata.faultingFunction?.split("_")[0] ?? "";
      const prefixMatches: string[] = [];
      const otherCFiles: string[] = [];
      for (const name of entries) {
        if (!name.endsWith(".c") && !name.endsWith(".h")) continue;
        if (prefix && name.startsWith(prefix)) prefixMatches.push(name);
        else otherCFiles.push(name);
      }
      prefixMatches.sort();
      otherCFiles.sort();
      for (const name of [...prefixMatches, ...otherCFiles]) {
        if (used >= maxBytes) break;
        add(join(dir, name));
      }
    }
  }

  return slices;
}

/**
 * Render the system prompt the kernel-verify agent runs against. Mentions the
 * available tools by name (the runtime separately enforces the tool surface)
 * and pins the success criterion to a `kernel_run` signature match.
 */
export function buildKernelVerifySystemPrompt(): string {
  return [
    "You are a kernel verification agent.",
    "",
    "Your job: take a static kernel-review hypothesis and produce a minimal",
    "syzkaller program (preferred) or C reproducer that triggers the bug.",
    "On each turn you may call ONE tool. Available tools:",
    "",
    "  - kernel_run: run a candidate reproducer through the kernel-VM oracle.",
    "      Args: { program, program_lang: 'syz'|'c', expected_signature? }.",
    "      Use this whenever you have a concrete program to try.",
    "  - read_file: inspect a file inside the kernel source tree to refine",
    "      your reproducer (e.g. to find the syscall entry shape).",
    "  - run_command: run a read-only shell command (e.g. `grep`, `rg`) inside",
    "      the kernel source tree. Do not run network or build commands.",
    "  - bash: shell escape hatch. Prefer the above tools first.",
    "",
    "Success = `kernel_run` returns signature_matched=true on a single program.",
    "Soft hit = `kernel_run` returns crashed=true but signature_matched=false.",
    "",
    "Two-phase trigger: a `kernel_run` result may carry a `phase` field. In",
    "`phase: reach` (a cheap build) the goal is only to LAND the deep path —",
    "a `reached: true` result is PROGRESS, not done: the loop escalates to",
    "`phase: refine` (KASAN) and you should resubmit the same or a refined",
    "program to nail the exact signature. Confirmation only happens in refine.",
    "",
    "Budget: at most a few attempts. Be terse. Do not free-form analyze;",
    "drive the oracle. When you have nothing left to try, reply with the",
    "single token `GIVE_UP` so the loop can exit cleanly.",
  ].join("\n");
}

/**
 * Render the per-attempt user prompt. Called once at the start of the loop
 * and again at every retry (so the agent sees its previous attempts as
 * tool_result messages — we don't re-paste them here).
 */
export function buildKernelVerifyInitialPrompt(args: {
  finding: Finding;
  metadata: KernelFindingMetadata;
  subsystemSlice: Array<{ relativePath: string; content: string }>;
  attempts: number;
  wallClockMs: number;
}): string {
  const { finding, metadata, subsystemSlice, attempts, wallClockMs } = args;

  const expectedSignatureHint =
    metadata.faultingFunction ?? finding.category ?? "kasan";

  const lines: string[] = [];
  lines.push(`## Finding to verify (id=${finding.id.slice(0, 8)})`);
  lines.push(`Title: ${finding.title}`);
  lines.push(`Severity: ${finding.severity}`);
  lines.push(`Category: ${finding.category}`);
  if (metadata.subsystem) lines.push(`Subsystem: ${metadata.subsystem}`);
  if (metadata.faultingFunction) lines.push(`Likely function: ${metadata.faultingFunction}`);
  if (metadata.filePath) {
    lines.push(
      `Cited location: ${metadata.filePath}${metadata.fileLine ? `:${metadata.fileLine}` : ""}`,
    );
  }
  if (finding.description) {
    lines.push("", "Description:", finding.description.trim());
  }

  lines.push("", "## Source slice (subsystem files for reference)");
  if (subsystemSlice.length === 0) {
    lines.push("(no source slice available — see kernel tree directly via read_file)");
  } else {
    for (const file of subsystemSlice) {
      lines.push("", `### ${file.relativePath}`);
      lines.push("```c");
      lines.push(file.content);
      lines.push("```");
    }
  }

  lines.push(
    "",
    "## Task",
    `Produce a reproducer that makes the kernel oracle fire with signature` +
      ` matching '${expectedSignatureHint}'. Call kernel_run with your candidate.`,
    `Budget: up to ${attempts} reproducer attempts and ${Math.round(wallClockMs / 60_000)} minutes wall-clock.`,
  );

  return lines.join("\n");
}

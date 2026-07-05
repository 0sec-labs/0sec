/**
 * Variant-candidate generation — turns a recent security fix into a
 * ready-to-run `runHuntScan` plan (a HuntBrief + the candidate sites to check).
 *
 * This automates the front of the incomplete-fix variant hunt — the ONLY
 * discovery method that has actually produced a 0-day for us (TIPC). The loop:
 *
 *   fix diff ──LLM──▶ {bug class, unguarded pattern, grep patterns} ──grep tree──▶ candidate sites
 *                                                                                       │
 *                                                                                       ▼
 *                                                                          runHuntScan(brief, candidates)
 *
 * The LLM does the one thing greps can't (read the diff, name the bug class,
 * write patterns that match the SAME sink shape elsewhere); the grep does the
 * one thing the LLM shouldn't be trusted with (exhaustively enumerate every
 * call-site across the tree). Deterministic enumeration, LLM only for the
 * pattern — so coverage is grounded, not hallucinated.
 */

import { execFileSync } from "node:child_process";
import type { RuntimeMode } from "@pwnkit/shared";
import { LlmApiRuntime } from "../runtime/llm-api.js";
import type { HuntBrief, HuntCandidate } from "./hunt-scan.js";
import { applyReachabilityGate } from "./hunt-reachability.js";

export interface VariantHuntInput {
  /** Local source tree / git repo to hunt variants in. */
  sourceRoot: string;
  /** The recent fix to hunt variants of: a commit in sourceRoot, or a raw diff. */
  fix: { commit?: string; diff?: string; reference?: string };
  runtime: RuntimeMode;
  model?: string;
  /** Cap the candidate file list (default 40). */
  maxCandidates?: number;
  /** File globs to search (default C/C++/headers). */
  includeGlobs?: string[];
  /**
   * kernelCTF-reachability gate for candidate selection (opt-in; default OFF
   * preserves today's density-only ranking exactly). When true, RESTRICT
   * candidates to paths classified "reachable" on the kernelCTF COS target
   * (see hunt-reachability.ts) — drops paths that are unbuilt/not zero-cap
   * reachable (exotic drivers, Bluetooth/CAN, capability-gated filesystems).
   * Mirrors `HUNT_REACHABLE_ONLY`. Takes priority over `reachablePrefer`.
   */
  reachableOnly?: boolean;
  /**
   * Softer than `reachableOnly`: sort candidates so kernelCTF-reachable paths
   * come first (nothing dropped), so the `maxCandidates` cap below doesn't
   * truncate them away. Mirrors `HUNT_REACHABLE_PREFER`. Ignored when
   * `reachableOnly` is set.
   */
  reachablePrefer?: boolean;
  log?: (msg: string) => void;
}

export interface VariantHuntPlan {
  brief: HuntBrief;
  candidates: HuntCandidate[];
  /** The ERE patterns that were searched (provenance / auditability). */
  grepPatterns: string[];
  /** Files the fix already touched — excluded from candidates. */
  fixedPaths: string[];
  warnings: string[];
}

interface PlanFromModel {
  bugClass: string;
  pattern: string;
  grepPatterns: string[];
}

const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n) + `\n...[truncated ${s.length - n} chars]` : s);

/** Paths the diff already fixed (from `+++ b/<path>` headers) — we never re-flag these. */
function fixedPathsFromDiff(diff: string): string[] {
  const out: string[] = [];
  for (const line of diff.split("\n")) {
    const m = /^\+\+\+ b\/(.+)$/.exec(line);
    if (m && m[1] !== "/dev/null") out.push(m[1].trim());
  }
  return [...new Set(out)];
}

/** grep -rlE for one pattern, returning repo-relative matching files (empty on no match). */
function grepFiles(pattern: string, sourceRoot: string, includeGlobs: string[]): string[] {
  const args = ["-rlE", ...includeGlobs.map((g) => `--include=${g}`), "--", pattern, "."];
  try {
    const out = execFileSync("grep", args, { cwd: sourceRoot, encoding: "utf8", maxBuffer: 32 * 1024 * 1024, timeout: 60_000 }) as string;
    return out.split("\n").map((s) => s.replace(/^\.\//, "").trim()).filter(Boolean);
  } catch {
    return []; // grep exits 1 on no match (and on a bad pattern — caller logs the empties)
  }
}

export async function generateVariantCandidates(input: VariantHuntInput): Promise<VariantHuntPlan> {
  const log = input.log ?? (() => {});
  const warnings: string[] = [];
  const maxCandidates = input.maxCandidates ?? 40;
  const includeGlobs = input.includeGlobs ?? ["*.c", "*.h", "*.cc", "*.cpp"];

  // 1. Resolve the fix diff.
  let diff = input.fix.diff ?? "";
  if (!diff && input.fix.commit) {
    try {
      diff = execFileSync("git", ["-C", input.sourceRoot, "show", "--no-color", input.fix.commit], {
        encoding: "utf8", maxBuffer: 16 * 1024 * 1024, timeout: 30_000,
      }) as string;
    } catch (e) {
      throw new Error(`could not read fix commit ${input.fix.commit}: ${String(e).slice(0, 160)}`);
    }
  }
  if (!diff.trim()) throw new Error("variant hunt needs fix.diff or fix.commit");
  const fixedPaths = fixedPathsFromDiff(diff);

  // 2. LLM: read the diff, name the bug class + the unguarded pattern, emit grep
  //    patterns that match the SAME sink shape at OTHER call-sites.
  const tool = {
    name: "emit_variant_plan",
    description: "Emit the variant-hunt plan derived from the fix diff.",
    input_schema: {
      type: "object",
      properties: {
        bugClass: { type: "string", description: "The bug class the fix closed, e.g. 'missing bounds check before a TLV copy'." },
        pattern: { type: "string", description: "The exact unguarded code shape (the sink) and how the fix guarded it." },
        grepPatterns: {
          type: "array", items: { type: "string" },
          description: "2-6 grep ERE patterns that locate the SAME sink shape at OTHER call-sites/files (the variant sites where the fix was NOT applied). Match the sink/call, not the added guard.",
        },
      },
      required: ["bugClass", "pattern", "grepPatterns"],
    },
  };
  const system =
    "You are a kernel/security VARIANT-HUNT analyst. Given a security fix diff, identify the bug class and the unguarded " +
    "code SHAPE (the sink) the fix added a guard around. Then write grep EXTENDED-REGEX patterns that find the SAME bug " +
    "CLASS at OTHER call-sites across the tree — where an INCOMPLETE fix or an independent instance lives.\n" +
    "CRITICAL — match the CLASS, not the original site: the patched file is EXCLUDED from results, so a pattern that " +
    "hardcodes the original's specific identifiers (field names like `sensf_res`, struct names like `digital_*`, the " +
    "variable `resp`) will match ONLY the original and yield ZERO variants. WILDCARD the identifiers. Match the dangerous " +
    "SHAPE — e.g. a length-controlled copy into a fixed buffer regardless of names: `memcpy\\([^,]+,[^,]+,[^)]*->len\\)`, " +
    "or an unchecked `->len`/`->size` used as a copy/index bound. Match the sink, NOT the guard that was added.\n" +
    "Emit 3-6 patterns ranging from moderately specific (the same struct-field-copy shape with wildcarded names) to " +
    "general (any length-bounded memcpy/copy_from of that family). Aim for tens of hits to triage, not zero and not " +
    "thousands. Call emit_variant_plan.";
  const messages = [{ role: "user", content: [{ type: "text", text: `## Fix diff\n${clip(diff, 24_000)}` }] }];

  const rt = new LlmApiRuntime({ type: "api", ...(input.model ? { model: input.model } : {}), timeout: 240_000 });
  let plan: PlanFromModel | null = null;
  try {
    const res = (await rt.executeNative(system, messages as never, [tool] as never,
      { onThinking() {}, onDelta() {}, onText() {}, onUsage() {} } as never)) as { content?: Array<Record<string, unknown>> };
    const call = (res.content ?? []).find((b) => (b as { type?: string; name?: string }).type === "tool_use" && (b as { name?: string }).name === "emit_variant_plan") as { input?: PlanFromModel } | undefined;
    if (call?.input) plan = call.input;
  } catch (e) {
    throw new Error(`variant-plan LLM call failed: ${String(e).slice(0, 200)}`);
  }
  if (!plan || !Array.isArray(plan.grepPatterns) || plan.grepPatterns.length === 0) {
    throw new Error("model did not emit a usable variant plan");
  }
  log(`[variant] bug class: ${plan.bugClass}`);
  log(`[variant] ${plan.grepPatterns.length} grep pattern(s): ${plan.grepPatterns.join(" | ")}`);

  // 3. Grep the tree for variant sites; dedup, drop the already-fixed files.
  const fixedSet = new Set(fixedPaths);
  const hits = new Map<string, number>(); // path -> how many patterns matched (rank signal)
  for (const pat of plan.grepPatterns) {
    const files = grepFiles(pat, input.sourceRoot, includeGlobs);
    if (files.length === 0) warnings.push(`pattern matched nothing (or invalid): ${pat}`);
    for (const f of files) if (!fixedSet.has(f)) hits.set(f, (hits.get(f) ?? 0) + 1);
  }
  // Rank by how many independent patterns a file matched (more = stronger variant signal).
  const ranked = [...hits.entries()].sort((a, b) => b[1] - a[1]).map(([path]) => path);

  // kernelCTF-reachability gate (opt-in; default OFF -> byte-identical to
  // before this gate existed). Applied BEFORE the maxCandidates cap below so
  // reachable candidates aren't truncated away by density-only ranking
  // landing on exotic/unbuilt drivers (see hunt-reachability.ts).
  const gated = input.reachableOnly || input.reachablePrefer
    ? applyReachabilityGate(ranked, { reachableOnly: input.reachableOnly, reachablePrefer: input.reachablePrefer })
    : { paths: ranked, unreachableCount: 0 };
  if (gated.unreachableCount > 0) {
    const verb = input.reachableOnly ? "dropped" : "deprioritized";
    const msg = `${verb} ${gated.unreachableCount} unreachable candidate(s) (not built/zero-cap on kernelCTF COS — see hunt-reachability.ts)`;
    warnings.push(msg);
    log(`[variant] ${msg}`);
  }

  if (gated.paths.length > maxCandidates) {
    warnings.push(`capped candidates ${gated.paths.length} -> ${maxCandidates} (raise maxCandidates to widen)`);
  }
  const candidates: HuntCandidate[] = gated.paths.slice(0, maxCandidates).map((path) => ({
    path,
    hint: `Variant site for: ${plan!.bugClass}. Check whether ${plan!.pattern} is guarded here.`,
  }));
  log(`[variant] ${candidates.length} candidate site(s) after dedup/exclude`);

  return {
    brief: { bugClass: plan.bugClass, pattern: plan.pattern, fixReference: input.fix.reference ?? input.fix.commit },
    candidates,
    grepPatterns: plan.grepPatterns,
    fixedPaths,
    warnings,
  };
}

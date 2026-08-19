/**
 * Engine A → hunt-pipeline adapter: derive an invariant context for a SEEDED
 * variant hunt and format it as a finder-prompt block.
 *
 * The subsystem-invariant-model stage ({@link ./subsystem-invariant-model.ts})
 * is a complete SEEDLESS pipeline of its own (model → deterministic checker →
 * runHuntScan). This module is the THIN bridge that lets the seed-driven
 * `pwnkit hunt` flow reuse it as CONTEXT instead of as a standalone hunt:
 *
 *   seed diff ──▶ touched-dir scope (the subsystem the fix lives in)
 *             ──▶ runSubsystemInvariantHunt({ skipHunt: true })
 *                 (build-or-load the stored model, run the deterministic
 *                  violation checker over the current source — the ONLY LLM
 *                  call is the one-time model build)
 *             ──▶ formatInvariantPromptBlock → appended to the hunt brief so
 *                 EVERY finder run sees the modeled rules + violation hypotheses
 *                 while chasing the seed's bug class.
 *
 * No candidates are added and the stage internals are untouched: the block is
 * prompt context (the same injection point the --methodology preset uses), so
 * a hunt without --invariant is byte-identical to before. Everything here is
 * fail-open at the call site — a scope/model failure degrades the hunt to the
 * plain seeded flow, never aborts it.
 */

import { readdirSync, statSync } from "node:fs";
import { join, posix, win32 } from "node:path";
import type { RuntimeMode } from "@pwnkit/shared";
import {
  runSubsystemInvariantHunt,
  resolveContainedSourcePath,
  type FindViolationsOptions,
  type InvariantModel,
  type InvariantViolation,
  type ViolationKind,
} from "./subsystem-invariant-model.js";

// ── Seed-diff scope derivation ─────────────────────────────────────────────────

/** The subsystem scope a seed diff points at: the dir most of its files live in. */
export interface SubsystemScope {
  /** Repo-relative subsystem dir (e.g. `"net/unix"`). */
  subsystem: string;
  /** Repo-relative touched files under that dir, in diff order. */
  touchedFiles: string[];
}

/**
 * Recover the subsystem a seed diff touches. Primary source: `diff --git a/X b/Y`
 * headers (the b-path); fallback: `+++ b/X` lines (hand-trimmed diffs). The
 * subsystem is the DIRECTORY the plurality of touched files lives in (ties break
 * to earliest appearance) — a fix touching `net/unix/garbage.c` scopes the hunt
 * context to `net/unix`. Returns null when no repo-relative path with a directory
 * component can be recovered (caller treats that as "no invariant context").
 */
export function deriveSubsystemScope(seedDiff: string): SubsystemScope | null {
  const paths: string[] = [];
  const seen = new Set<string>();
  const push = (p: string) => {
    const normalized = p.replaceAll("\\", "/");
    if (
      !normalized ||
      normalized === "/dev/null" ||
      normalized.includes("\0") ||
      posix.isAbsolute(normalized) ||
      win32.isAbsolute(normalized) ||
      /^[A-Za-z]:/.test(normalized)
    ) return;
    const parts = normalized.split("/");
    if (
      parts.length < 2 ||
      parts.some((part) => !part || part === "." || part === "..") ||
      seen.has(normalized)
    ) return;
    seen.add(normalized);
    paths.push(normalized);
  };

  for (const line of seedDiff.split("\n")) {
    const git = /^diff --git a\/\S+ b\/(\S+)/.exec(line);
    if (git) {
      push(git[1]);
      continue;
    }
    const plus = /^\+\+\+ b\/(\S+)/.exec(line);
    if (plus) push(plus[1]);
  }
  if (paths.length === 0) return null;

  const dirCount = new Map<string, number>();
  for (const p of paths) {
    const dir = p.slice(0, p.lastIndexOf("/"));
    dirCount.set(dir, (dirCount.get(dir) ?? 0) + 1);
  }
  let subsystem = "";
  let best = 0;
  for (const [dir, n] of dirCount) {
    if (n > best) {
      best = n;
      subsystem = dir;
    }
  }
  return { subsystem, touchedFiles: paths.filter((p) => p.startsWith(subsystem + "/")) };
}

// ── Context build (build-or-load model + deterministic violations) ─────────────

export interface InvariantHuntContextInput {
  /** Local source tree the subsystem files live under. */
  sourceRoot: string;
  /** The seed fix diff the hunt is seeded with — scope is derived from it. */
  seedDiff: string;
  runtime: RuntimeMode;
  /**
   * Where the durable model JSON lives. Default:
   * `<sourceRoot>/.pwnkit/invariant-models/<subsystem-slug>.json` — next to the
   * tree it models, so a re-run of the same subsystem LOADS it (no LLM call) and
   * the deterministic checker re-runs against the current source for free.
   */
  modelPath?: string;
  /** Force a fresh LLM model build even when the stored model exists. */
  rebuildModel?: boolean;
  /** Model-build LLM override. */
  model?: string;
  /** Cap on subsystem .c files fed to the model build / checker (default 8). */
  maxSubsystemFiles?: number;
  /** Violation-finder options (cap, refcount opt-out). */
  findOptions?: FindViolationsOptions;
  log?: (msg: string) => void;
}

export interface InvariantHuntContext {
  /** The derived subsystem scope (e.g. `"net/unix"`). */
  subsystem: string;
  /** The subsystem .c files the model + checker ran over (repo-relative). */
  subsystemFiles: string[];
  /** Where the durable model artifact lives. */
  modelPath: string;
  /** True when the model was loaded from disk (no LLM call this run). */
  modelLoaded: boolean;
  /** The invariant model (built fresh or loaded). */
  model: InvariantModel;
  /** The deterministically-found violation hypotheses against the current source. */
  violations: InvariantViolation[];
  /** The finder-prompt block — append to the hunt brief's pattern. */
  promptBlock: string;
}

const KIND_LABEL: Record<ViolationKind, string> = {
  "unlocked-field-access": "UNLOCKED FIELD ACCESS",
  "use-after-free-order": "USE-AFTER-FREE ORDER",
  "refcount-imbalance": "REFCOUNT IMBALANCE",
};

/** Cap on violation hypothesis lines in the prompt block. */
const MAX_VIOLATION_LINES = 12;
/** Hard cap on the whole block so a big subsystem can't blow up the finder hint. */
const MAX_BLOCK_CHARS = 6_000;

/**
 * Format the invariant model + deterministic violation hypotheses as ONE finder-
 * prompt block. Pure function (no IO, no LLM) so the injection shape is directly
 * unit-testable. The block is CONTEXT, not a new brief: it tells the finder the
 * rules the subsystem's key objects are supposed to uphold and lists the concrete
 * file:line hypotheses the deterministic checker emitted — each explicitly marked
 * UNVERIFIED so the finder confirms locking/reachability from real source before
 * reporting (the skeptic gate then refutes the over-approximation residue).
 */
export function formatInvariantPromptBlock(
  model: InvariantModel,
  violations: InvariantViolation[],
  opts: { modelLoaded?: boolean } = {},
): string {
  const lines: string[] = [];
  lines.push(
    `INVARIANT MODEL of ${model.subsystem} ` +
      `(${model.objects.length} key object(s), ${opts.modelLoaded ? "loaded from the stored artifact" : "freshly built"}; ` +
      `deterministic checker found ${violations.length} violation hypothesis(es) against the current source).`,
  );
  for (const obj of model.objects) {
    const parts: string[] = [];
    for (const r of obj.lockRules) parts.push(`lock \`${r.lock}\` guards [${r.guardedFields.join(", ")}]`);
    for (const r of obj.refcountRules) parts.push(`refcount ${r.getFn}()/${r.putFn}() must balance`);
    for (const r of obj.lifecycleRules) parts.push(`no use after ${r.freeFn}()`);
    if (parts.length > 0) lines.push(`- ${obj.object}: ${parts.join("; ")}.`);
  }
  if (violations.length > 0) {
    lines.push("VIOLATION HYPOTHESES from the deterministic checker (UNVERIFIED — confirm locking/reachability from real source):");
    for (const v of violations.slice(0, MAX_VIOLATION_LINES)) {
      lines.push(`- ${KIND_LABEL[v.kind]}: ${v.file}:${v.line} in ${v.functionName}() — ${v.invariant}`);
    }
    if (violations.length > MAX_VIOLATION_LINES) {
      lines.push(`- ...and ${violations.length - MAX_VIOLATION_LINES} more (see the stored model run log).`);
    }
  }
  lines.push(
    "Use this as CONTEXT while hunting the bug class above: the seed fix touched this subsystem's object " +
      "lifetime/locking, so check whether the SAME modeled invariant is violated at or near each candidate site — " +
      "an unguarded-field access, a use-after-free ordering, or an unbalanced refcount put is an in-scope LEAD " +
      "when you can ground it at an exact file:line with an attacker-reachable path. Each hypothesis is " +
      "UNVERIFIED: a lock held by a caller or a free on a dead error branch is a false positive — re-read the " +
      "real source and only report what survives.",
  );

  let block = lines.join("\n");
  if (block.length > MAX_BLOCK_CHARS) {
    block = block.slice(0, MAX_BLOCK_CHARS) + `\n...[invariant context truncated at ${MAX_BLOCK_CHARS} chars]`;
  }
  return block;
}

/**
 * Build the invariant context for a seeded hunt: derive the subsystem scope from
 * the seed diff, enumerate its core .c files (touched files first, then siblings
 * by descending size — the largest files carry the core object logic), then run
 * the seedless stage's build-or-load + deterministic checker via
 * {@link runSubsystemInvariantHunt} with `skipHunt` (the hunt itself stays with
 * the caller's seeded flow). Returns null when no scope can be derived or the
 * subsystem dir yields no .c files — the caller degrades to the plain seeded hunt.
 */
export async function buildInvariantHuntContext(
  input: InvariantHuntContextInput,
): Promise<InvariantHuntContext | null> {
  const log = input.log ?? (() => {});
  const scope = deriveSubsystemScope(input.seedDiff);
  if (!scope) {
    log("[invariant] no subsystem scope derivable from the seed diff — skipping invariant context");
    return null;
  }

  const dirAbs = resolveContainedSourcePath(input.sourceRoot, scope.subsystem);
  if (!dirAbs) {
    log(`[invariant] subsystem dir ${scope.subsystem} escapes or is not readable under sourceRoot — skipping invariant context`);
    return null;
  }
  let entries: string[];
  try {
    entries = readdirSync(dirAbs);
  } catch {
    log(`[invariant] subsystem dir ${scope.subsystem} not readable under sourceRoot — skipping invariant context`);
    return null;
  }
  const safePath = (file: string) => resolveContainedSourcePath(input.sourceRoot, `${scope.subsystem}/${file}`);
  const cFiles = entries.filter((e) => e.endsWith(".c") && safePath(e) !== null);
  const sizeOf = (f: string) => {
    try {
      const path = safePath(f);
      return path ? statSync(path).size : 0;
    } catch {
      return 0;
    }
  };
  const touched = new Set(scope.touchedFiles);
  const ordered = [
    // Touched files first (diff order) — the model must cover what the fix changed.
    ...scope.touchedFiles.filter((f) => cFiles.includes(f.slice(scope.subsystem.length + 1))),
    // Then untouched siblings, largest first (the core object logic lives in the big files).
    ...cFiles
      .filter((f) => !touched.has(`${scope.subsystem}/${f}`))
      .sort((a, b) => sizeOf(b) - sizeOf(a))
      .map((f) => `${scope.subsystem}/${f}`),
  ];
  const maxFiles = input.maxSubsystemFiles ?? 8;
  const subsystemFiles = ordered.slice(0, maxFiles);
  if (subsystemFiles.length === 0) {
    log(`[invariant] no .c files under ${scope.subsystem} — skipping invariant context`);
    return null;
  }

  const modelPath =
    input.modelPath ??
    join(input.sourceRoot, ".pwnkit", "invariant-models", `${scope.subsystem.replaceAll("/", "__")}.json`);

  const res = await runSubsystemInvariantHunt({
    sourceRoot: input.sourceRoot,
    subsystem: scope.subsystem,
    subsystemFiles,
    runtime: input.runtime,
    modelPath,
    ...(input.rebuildModel !== undefined ? { rebuildModel: input.rebuildModel } : {}),
    ...(input.model ? { model: input.model } : {}),
    ...(input.findOptions ? { findOptions: input.findOptions } : {}),
    skipHunt: true,
    log,
  });

  return {
    subsystem: scope.subsystem,
    subsystemFiles,
    modelPath,
    modelLoaded: res.modelLoaded,
    model: res.model,
    violations: res.violations,
    promptBlock: formatInvariantPromptBlock(res.model, res.violations, { modelLoaded: res.modelLoaded }),
  };
}

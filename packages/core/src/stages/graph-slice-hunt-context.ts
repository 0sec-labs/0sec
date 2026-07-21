/**
 * Graph-slice → hunt-pipeline adapter (`--graph-slice`).
 *
 * The THIN bridge that lets the seed-driven `pwnkit hunt` flow feed the finder a
 * real interprocedural reachability SLICE around the seed's fix site instead of
 * (only) flat file text. It is the exact structural sibling of
 * {@link ./invariant-hunt-context.ts} (the `--invariant` adapter): it derives a
 * subsystem scope from the seed diff, produces a compact context block, and the
 * CLI appends that block to the hunt brief's `pattern` — the SAME injection
 * channel `--invariant`/`--methodology` use. A hunt WITHOUT `--graph-slice` is
 * byte-identical to before.
 *
 *   seed diff ──▶ deriveSubsystemScope (the subsystem the fix lives in)
 *             ──▶ touched-function names (hunk headers) as slice roots
 *             ──▶ load PRE-EXPORTED CPG JSON  (+ optional ops_map.json)
 *             ──▶ sliceAroundTargets (Phase-0 call/DDG walk + Phase-1 ops edges)
 *             ──▶ formatGraphSlicePromptBlock → appended to the hunt brief
 *
 * MVP dependency (honest): the CPG must be PRE-PROVISIONED as a graphson JSON
 * (run `packages/core/scripts/provision-cpg.sh <src> <subsystem>` — Joern c2cpg +
 * joern-export). We do NOT bundle Joern (a Java tool) into the npm package.
 * Everything here is FAIL-OPEN: a missing scope, a missing CPG, or an empty
 * slice degrades the hunt to the plain flat-text finder with a logged warning —
 * it NEVER aborts a scan. Provisioning Joern inside the cloud sandbox so the
 * stage can build-on-demand is an explicit follow-up.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  Cpg,
  injectOps,
  sliceAroundTargets,
  type OpsMap,
  type SliceRenderStats,
  type SourceLoader,
} from "./graph-slice.js";
import { deriveSubsystemScope } from "./invariant-hunt-context.js";
import { resolveContainedSourcePath } from "./subsystem-invariant-model.js";

// ── Touched-function derivation ────────────────────────────────────────────────

const IDENT = /[A-Za-z_][A-Za-z0-9_]*/g;
// C keywords / type qualifiers that appear in a hunk-header signature but are
// never the function name we want to slice around.
const NON_FN_TOKENS: ReadonlySet<string> = new Set([
  "static", "inline", "const", "struct", "union", "enum", "void", "int", "long",
  "short", "char", "unsigned", "signed", "bool", "u8", "u16", "u32", "u64",
  "s8", "s16", "s32", "s64", "size_t", "ssize_t", "return", "if", "else",
  "for", "while", "switch", "case", "goto", "typedef", "extern", "volatile",
  "__always_inline", "noinline", "__init", "__exit",
]);

/**
 * Recover candidate slice-root function names from a seed diff's hunk headers.
 * `git diff` puts the enclosing function's signature after the second `@@`:
 *   `@@ -100,7 +100,8 @@ static int unix_attach_fds(struct scm_cookie *scm)`
 * We take the identifier immediately preceding the first `(` on that line (the
 * function name), skipping type/qualifier keywords. These are the fix sites the
 * variant hunt fans out from, so they are the right roots for the slice.
 */
export function extractTouchedFunctions(seedDiff: string): string[] {
  const names = new Set<string>();
  for (const line of seedDiff.split("\n")) {
    const m = /^@@ [^@]*@@\s*(.+)$/.exec(line);
    if (!m) continue;
    const ctx = m[1];
    const paren = ctx.indexOf("(");
    const head = paren >= 0 ? ctx.slice(0, paren) : ctx;
    const idents = head.match(IDENT);
    if (!idents) continue;
    // The function name is the LAST identifier before `(` that is not a keyword.
    for (let i = idents.length - 1; i >= 0; i--) {
      if (!NON_FN_TOKENS.has(idents[i])) {
        names.add(idents[i]);
        break;
      }
    }
  }
  return [...names];
}

// ── Context build ──────────────────────────────────────────────────────────────

export interface GraphSliceHuntContextInput {
  /** Local source tree the subsystem files live under. */
  sourceRoot: string;
  /** The seed fix diff — scope + touched functions are derived from it. */
  seedDiff: string;
  /**
   * Path to the pre-exported CPG graphson JSON. Default:
   * `<sourceRoot>/.pwnkit/cpg/<subsystem-slug>.json` (produced by
   * `scripts/provision-cpg.sh`). Absent → the stage degrades to flat-text.
   */
  cpgPath?: string;
  /**
   * Path to the pre-harvested ops map (Phase-1 indirect-call edges). Default:
   * `<sourceRoot>/.pwnkit/cpg/<subsystem-slug>.ops.json`. Optional — absent just
   * means no ops-struct edges are synthesized.
   */
  opsPath?: string;
  /** BFS hop radius for the slice. Default 3 (matches the bench A/B proof). */
  hops?: number;
  log?: (msg: string) => void;
}

export interface GraphSliceHuntContext {
  /** The derived subsystem scope (e.g. `"net/unix"`). */
  subsystem: string;
  /** Where the CPG JSON was loaded from. */
  cpgPath: string;
  /** Function names used as slice roots (from the seed's hunk headers). */
  targetFunctions: string[];
  /** How many distinct methods the roots resolved to in the CPG. */
  resolvedTargets: number;
  /** Phase-1 ops-struct indirect-call edges synthesized (0 when no ops map). */
  opsEdges: number;
  /** Slice render stats (functions/files/edges/chars). */
  stats: SliceRenderStats;
  /** The finder-prompt block — append to the hunt brief's `pattern`. */
  promptBlock: string;
}

/** Hard cap on the injected block so a big subsystem can't blow up the finder hint. */
const MAX_BLOCK_CHARS = 12_000;

/**
 * Format the reachability slice as ONE bounded finder-prompt block. Pure — the
 * injection shape is directly unit-testable. The block is CONTEXT, not a new
 * brief: it hands the finder the cross-function/cross-file call+dataflow chain
 * around the fix site (the thing the flat per-file read structurally cannot
 * assemble), and instructs it to reason over that chain while chasing the bug
 * class — still grounding every reported sink at a real file:line.
 */
export function formatGraphSlicePromptBlock(
  subsystem: string,
  targetFunctions: string[],
  sliceText: string,
  stats: SliceRenderStats,
  opsEdges: number,
): string {
  const header =
    `GRAPH REACHABILITY SLICE of ${subsystem} around the seed's fix site ` +
    `(roots: ${targetFunctions.join(", ") || "(none)"}; ${stats.functions} function(s) across ` +
    `${stats.files.length} file(s), ${stats.callEdges} interprocedural edge(s)` +
    `${opsEdges > 0 ? `, ${opsEdges} ops-struct indirect-call edge(s) synthesized` : ""}).`;
  const guidance =
    "Use this slice as the interprocedural map the flat per-file read cannot give you: it stitches together " +
    "the alloc / link-into-container / free / use sites for this object lifetime EVEN WHEN they live in " +
    "different functions and different files. Trace the object across the call/dataflow edges below and look " +
    "for the SAME bug class at or near each site — a free on one path while the object stays reachable from a " +
    "disjoint path, an incomplete fix on a sibling handler, an unchecked length feeding a copy. The slice is a " +
    "MAP, not a verdict: confirm the real sink at an exact file:line with an attacker-reachable path from the " +
    "actual source before reporting; a lock held by a caller or a free on a dead error branch is a false positive.";
  let block = `${header}\n\n${sliceText}\n\n${guidance}`;
  if (block.length > MAX_BLOCK_CHARS) {
    block = block.slice(0, MAX_BLOCK_CHARS) + `\n...[graph slice truncated at ${MAX_BLOCK_CHARS} chars]`;
  }
  return block;
}

/** Default artifact locations, next to the tree they model (mirrors the invariant modelPath convention). */
function defaultCpgPaths(sourceRoot: string, subsystem: string): { cpg: string; ops: string } {
  const slug = subsystem.replaceAll("/", "__");
  return {
    cpg: join(sourceRoot, ".pwnkit", "cpg", `${slug}.json`),
    ops: join(sourceRoot, ".pwnkit", "cpg", `${slug}.ops.json`),
  };
}

/**
 * Build the graph-slice context for a seeded hunt. Derives the subsystem scope
 * + touched functions from the seed diff, loads the PRE-EXPORTED CPG JSON (and
 * an optional ops map), slices `hops` deep around the touched functions, and
 * returns the formatted prompt block. Returns null — the caller degrades to the
 * plain flat-text hunt — when ANY precondition is missing: no scope, no CPG
 * file, no touched functions, or an empty slice.
 */
export function buildGraphSliceHuntContext(
  input: GraphSliceHuntContextInput,
): GraphSliceHuntContext | null {
  const log = input.log ?? (() => {});
  const scope = deriveSubsystemScope(input.seedDiff);
  if (!scope) {
    log("[graph-slice] no subsystem scope derivable from the seed diff — skipping graph slice");
    return null;
  }

  const defaults = defaultCpgPaths(input.sourceRoot, scope.subsystem);
  const cpgPath = input.cpgPath ?? defaults.cpg;
  if (!existsSync(cpgPath)) {
    log(
      `[graph-slice] no CPG export at ${cpgPath} — provision it with ` +
        `scripts/provision-cpg.sh '${scope.subsystem}' then re-run; degrading to flat-text finder`,
    );
    return null;
  }

  const targetFunctions = extractTouchedFunctions(input.seedDiff);
  if (targetFunctions.length === 0) {
    log("[graph-slice] no touched functions recovered from the seed hunk headers — skipping graph slice");
    return null;
  }

  let cpg: Cpg;
  try {
    const doc = JSON.parse(readFileSync(cpgPath, "utf8"));
    cpg = Cpg.fromGraphson(doc);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    log(`[graph-slice] failed to load CPG at ${cpgPath}: ${reason.slice(0, 160)}; degrading to flat-text`);
    return null;
  }

  // Phase 1 (optional): synthesize ops-struct indirect-call edges from a
  // pre-harvested ops map. Absent just means no synthesized edges.
  let opsEdges = 0;
  const opsPath = input.opsPath ?? defaults.ops;
  if (existsSync(opsPath)) {
    try {
      const ops = JSON.parse(readFileSync(opsPath, "utf8")) as OpsMap;
      opsEdges = injectOps(cpg, ops);
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      log(`[graph-slice] ops map at ${opsPath} unreadable, continuing without ops edges: ${reason.slice(0, 120)}`);
    }
  }

  // Source loader scoped to the subsystem so render surfaces real path lines.
  const loadSource: SourceLoader = (filename) => {
    const abs = resolveContainedSourcePath(input.sourceRoot, filename);
    if (!abs || !existsSync(abs)) return null;
    try {
      return readFileSync(abs, "utf8").split("\n");
    } catch {
      return null;
    }
  };

  const sliced = sliceAroundTargets(cpg, targetFunctions, {
    hops: input.hops ?? 3,
    loadSource,
    opsNote: opsEdges > 0 ? `ops-struct indirect-call edges synthesized: ${opsEdges}` : undefined,
  });
  if (!sliced) {
    log(
      `[graph-slice] touched functions [${targetFunctions.join(", ")}] not found in the CPG ` +
        `${cpgPath} (stale export?) — degrading to flat-text finder`,
    );
    return null;
  }

  const promptBlock = formatGraphSlicePromptBlock(
    scope.subsystem,
    targetFunctions,
    sliced.text,
    sliced.stats,
    opsEdges,
  );
  log(
    `[graph-slice] injected slice: ${sliced.stats.functions} fns / ${sliced.stats.files.length} files / ` +
      `${sliced.stats.callEdges} edges / ${sliced.stats.chars} chars (roots: ${sliced.targetCount})`,
  );

  return {
    subsystem: scope.subsystem,
    cpgPath,
    targetFunctions,
    resolvedTargets: sliced.targetCount,
    opsEdges,
    stats: sliced.stats,
    promptBlock,
  };
}

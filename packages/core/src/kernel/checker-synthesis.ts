/**
 * kernel/checker-synthesis.ts
 *
 * SELF-VALIDATING CHECKER SYNTHESIS on the incomplete-fix / patch-gap spine
 * (the KNighter / BUGSTONE pattern).
 *
 * This industrializes the single technique that produced our best merged kernel
 * wins (TIPC / mac802154 / NFC were all incomplete-fix variants): given an
 * upstream security fix, LEARN the bug-class invariant the fix enforces, encode
 * it as a concrete checker, PROVE the checker catches its own seed bug, then
 * sweep the checker across the tree for the sibling sites the fix missed.
 *
 * How it differs from what already exists here:
 *   - `incomplete-fix-hunt.ts` mines Fixes:-tagged commits and surfaces untouched
 *     same-FAMILY siblings by NAME (encrypt-fixed / decrypt-unfixed). It has no
 *     model of WHAT the fix enforced — only that a sibling exists.
 *   - `variant-candidates.ts` does a one-shot LLM call per run that emits grep
 *     patterns, but throws them away after the run and never proves they match
 *     anything: an LLM pattern that only matches the original site (or nothing)
 *     is indistinguishable from a good one until a human reads the empty result.
 *   - `variant-hunt.ts` shells the EXTERNAL `foxguard` binary and adapts its
 *     SARIF — a dependency on a tool that must be installed and whose rules are
 *     authored out-of-band.
 *
 * This module closes all three gaps with ONE idea — the load-bearing step is
 * SELF-VALIDATION: a synthesized checker only enters the library if it PROVABLY
 * flags the known-buggy pre-image of its seed fix AND is silent on the post-fix
 * image. That makes the output deterministic (a checker either catches its seed
 * or it's rejected — no "trust the LLM") and COMPOUNDING (validated checkers are
 * persisted and re-run against future trees).
 *
 * The checker is encoded as a bug-class INVARIANT, not a textual diff:
 *   - `sinkPattern`   — an ERE matching the dangerous SHAPE (identifiers
 *                       wildcarded) the fix guarded, e.g. a length-controlled
 *                       copy `memcpy\([^,]+,[^,]+,[^)]*->len\)`.
 *   - `guardPattern`  — an ERE matching the CHECK the fix ADDED (present in the
 *                       post-image, absent in the pre-image), e.g.
 *                       `if \([^)]*->len\s*[<>]`.
 *   - `guardWindow`   — how many lines around a sink the guard may live in.
 * A site is FLAGGED when the sink matches but no guard matches within the
 * window — exactly the "sink present, guard missing" shape a fix closes. This
 * sink+guard+window encoding is what makes self-validation meaningful: the
 * pre-image has the sink without the guard (flagged) and the post-image has the
 * sink WITH the guard (silent), so a correct checker's accept condition is
 * mechanically decidable from git blobs alone.
 *
 * weggli: OPTIONAL accelerator, NOT a dependency. It is not on the engine's
 * scanner allowlist and not installed in the standard image (see the honesty
 * note on `isWeggliAvailable`). The checker carries an emitted `weggliQuery`
 * that is used as an extra sink locator ONLY when the binary is on PATH; the
 * grep/regex invariant matcher above is the always-available source of truth
 * and is what self-validation and the unit tests exercise. This REDUCES — does
 * not remove — the external-tool reliance of `variant-hunt.ts`.
 *
 * Everything shells read-only `git`/`grep` against an already-present local tree
 * (mirroring `fix-commit-intel.ts` / `variant-candidates.ts`) and every I/O
 * boundary is injectable, so the loop is fully offline-testable.
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

import type { Finding } from "@pwnkit/shared";

import { LlmApiRuntime } from "../runtime/llm-api.js";
import {
  composeGate,
  type HuntBrief,
  type HuntCandidate,
  type HuntScanOptions,
  type HuntScanResult,
  type HuntVerifier,
} from "../stages/hunt-scan.js";
import { mineFixCommits, type FixCommit } from "./fix-commit-intel.js";
import { classifyPatchGapReachability } from "./patch-gap-reachability.js";

// ── Contract ─────────────────────────────────────────────────────────────────

const DEFAULT_GUARD_WINDOW = 8;
const DEFAULT_MAX_ATTEMPTS = 3;

/** The upstream fix a checker is synthesized from. */
export interface CheckerSeed {
  /** Fix commit SHA (must exist in the target `tree`). */
  fixSha: string;
  /** Commit subject / provenance (for the checker description). */
  subject?: string;
  /** A `Fixes:` reference or CVE id, if any (provenance). */
  reference?: string;
}

/**
 * A synthesized, (once accepted) self-VALIDATED bug-class checker. The invariant
 * is encoded as an ERE sink + ERE guard + a proximity window — see the module
 * doc for why this encoding makes self-validation decidable.
 */
export interface SynthesizedChecker {
  /** Stable id: short hash of the seed fix + bug class. Also the library filename. */
  id: string;
  /** The bug class the fix closed, e.g. "missing length check before a TLV copy". */
  bugClass: string;
  /** The invariant the fix enforces, in prose (the checker's raison d'être). */
  invariant: string;
  /** ERE matching the dangerous SINK shape, identifiers wildcarded. */
  sinkPattern: string;
  /** ERE matching the GUARD the fix ADDED (present post-fix, absent pre-fix). */
  guardPattern: string;
  /** Lines around a sink match the guard may live in. Default 8. */
  guardWindow: number;
  /** Optional weggli query — used only when the weggli binary is on PATH. */
  weggliQuery?: string;
  /** The seed fix this checker was learned from. */
  seed: CheckerSeed;
  /** The self-validation record that admitted this checker to the library. */
  validation: CheckerValidation;
}

/** One site a checker flags: a sink match with no guard in its window. */
export interface CheckerMatch {
  file: string;
  /** 1-based line of the sink match. */
  line: number;
  /** The sink line, trimmed and clipped. */
  snippet: string;
}

/** The outcome of running a checker against its seed's pre/post images. */
export interface CheckerValidation {
  accepted: boolean;
  /** Flags in the buggy pre-image (`<fix>^`) across the fixed files. Must be > 0. */
  preImageFlags: number;
  /** Flags in the post-fix image (`<fix>`) across the fixed files. Must be 0. */
  postImageFlags: number;
  /** The fixed files the checker actually flagged in the pre-image (its seed sites). */
  seedFiles: string[];
  /** Human-readable accept/reject reason for triage + retry prompting. */
  reason: string;
}

/** A sibling site the sweep surfaced — a candidate the fix likely missed. */
export interface CheckerSweepHit extends CheckerMatch {
  /** kernelCTF COS-6.12 zero-cap reachability, when the reachability filter ran. */
  reachable?: "reachable" | "unreachable";
  reachabilityReason?: string;
}

// ── Injectable I/O boundaries (real on the non-test path) ─────────────────────

/** Read-only git surface the loop needs. Injectable for offline tests. */
export interface CheckerGit {
  /** `git show <ref>:<path>` -> file content, or undefined on error / absent. */
  show: (tree: string, ref: string, path: string) => string | undefined;
  /** `git show <sha>` -> the full unified diff of the fix commit. */
  diff: (tree: string, sha: string) => string;
  /** The `.c`/`.h` files a commit touched. */
  files: (tree: string, sha: string) => string[];
}

/** LLM boundary — the subset of `LlmApiRuntime` this module uses. */
export interface CheckerRuntime {
  executeNative: (...args: unknown[]) => Promise<unknown>;
}

export interface CheckerSynthesisDeps {
  git?: CheckerGit;
  runtime?: CheckerRuntime;
  /** `grep -rlE <pattern>` under a tree -> repo-relative files. */
  grepFiles?: (tree: string, pattern: string, globs: string[]) => string[];
  /** Weggli availability probe (defaults to a real PATH check). */
  weggliAvailable?: () => boolean;
}

function realGit(): CheckerGit {
  const run = (tree: string, args: string[]): string =>
    execFileSync("git", args, {
      cwd: tree,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      maxBuffer: 128 * 1024 * 1024,
    }) as string;
  return {
    show(tree, ref, path) {
      try {
        return run(tree, ["show", `${ref}:${path}`]);
      } catch {
        return undefined;
      }
    },
    diff(tree, sha) {
      try {
        return run(tree, ["show", "--no-color", "--format=medium", sha]);
      } catch {
        return "";
      }
    },
    files(tree, sha) {
      try {
        return run(tree, ["show", "--name-only", "--format=", sha])
          .split("\n")
          .map((l) => l.trim())
          .filter((l) => l.endsWith(".c") || l.endsWith(".h"));
      } catch {
        return [];
      }
    },
  };
}

function realGrepFiles(
  tree: string,
  pattern: string,
  globs: string[],
): string[] {
  const args = ["-rlE", ...globs.map((g) => `--include=${g}`), "--", pattern, "."];
  try {
    const out = execFileSync("grep", args, {
      cwd: tree,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
      timeout: 60_000,
    }) as string;
    return out
      .split("\n")
      .map((s) => s.replace(/^\.\//, "").trim())
      .filter(Boolean);
  } catch {
    return []; // grep exits 1 on no match (and on a bad pattern)
  }
}

/**
 * True iff a `weggli` binary is on PATH. Honesty note: as of this writing
 * weggli is NOT installed in the standard engine image and NOT on
 * `ALLOWED_SCANNER_BINARIES`, so this returns false in CI and on the default
 * bench image — the checker's grep/regex invariant matcher is the source of
 * truth and weggli is a no-op accelerator until the binary is provisioned.
 */
export function isWeggliAvailable(
  runner: (cmd: string, args: string[]) => string = (cmd, args) =>
    execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }) as string,
): boolean {
  try {
    runner("weggli", ["--version"]);
    return true;
  } catch {
    return false;
  }
}

function resolveDeps(deps?: CheckerSynthesisDeps): Required<CheckerSynthesisDeps> {
  return {
    git: deps?.git ?? realGit(),
    runtime:
      deps?.runtime ??
      (new LlmApiRuntime({ type: "api", timeout: 240_000 }) as unknown as CheckerRuntime),
    grepFiles: deps?.grepFiles ?? realGrepFiles,
    weggliAvailable: deps?.weggliAvailable ?? (() => isWeggliAvailable()),
  };
}

// ── The deterministic matcher (the invariant, evaluated on file content) ──────

const clip = (s: string, n: number) =>
  s.length > n ? s.slice(0, n) + `\n...[truncated ${s.length - n} chars]` : s;

/** Compile an ERE-ish pattern to a JS RegExp; undefined on an invalid pattern. */
function safeRegex(src: string, flags: string): RegExp | undefined {
  try {
    return new RegExp(src, flags);
  } catch {
    return undefined;
  }
}

/**
 * Evaluate a checker against one file's CONTENT — the pure heart of the loop.
 * Flags every sink match that has NO guard match within `guardWindow` lines
 * either side (the "sink present, guard missing" shape a fix closes). Pure and
 * deterministic: no I/O, no LLM. An invalid `sinkPattern` yields zero matches
 * (which correctly forces self-validation to reject the checker).
 */
export function evaluateChecker(
  checker: Pick<SynthesizedChecker, "sinkPattern" | "guardPattern" | "guardWindow">,
  path: string,
  content: string,
): CheckerMatch[] {
  const sinkRe = safeRegex(checker.sinkPattern, "i");
  if (!sinkRe) return [];
  const guardRe = safeRegex(checker.guardPattern, "i");
  const win = checker.guardWindow > 0 ? checker.guardWindow : DEFAULT_GUARD_WINDOW;
  const lines = content.split("\n");
  const out: CheckerMatch[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (!sinkRe.test(lines[i])) continue;
    let guarded = false;
    if (guardRe) {
      const lo = Math.max(0, i - win);
      const hi = Math.min(lines.length - 1, i + win);
      for (let j = lo; j <= hi; j++) {
        if (guardRe.test(lines[j])) {
          guarded = true;
          break;
        }
      }
    }
    if (!guarded) {
      out.push({ file: path, line: i + 1, snippet: lines[i].trim().slice(0, 200) });
    }
  }
  return out;
}

// ── Self-validation (the load-bearing gate) ───────────────────────────────────

/**
 * SELF-VALIDATE a candidate checker against its seed fix's pre/post images.
 *
 * ACCEPT iff, across the files the fix touched:
 *   - the checker flags the PRE-image (`<fix>^`) at least once — it catches its
 *     own seed bug (`preImageFlags > 0`), AND
 *   - the checker is SILENT on the POST-image (`<fix>`) — the guard the fix
 *     added suppresses every flag (`postImageFlags === 0`).
 *
 * Any other outcome is a REJECT: a checker that misses its seed is worthless,
 * and a checker that still fires after the fix is too broad (its `guardPattern`
 * doesn't capture the actual guard) — both cases should regenerate. This is the
 * exact accept/reject logic that makes only provably-correct checkers compound.
 */
export function selfValidateChecker(
  checker: SynthesizedChecker,
  tree: string,
  fixedFiles: string[],
  git: CheckerGit,
): CheckerValidation {
  let preImageFlags = 0;
  let postImageFlags = 0;
  const seedFiles: string[] = [];

  for (const file of fixedFiles) {
    const pre = git.show(tree, `${checker.seed.fixSha}^`, file);
    const post = git.show(tree, checker.seed.fixSha, file);
    if (pre === undefined || post === undefined) continue; // new/renamed file — can't diff
    const preM = evaluateChecker(checker, file, pre);
    const postM = evaluateChecker(checker, file, post);
    preImageFlags += preM.length;
    postImageFlags += postM.length;
    if (preM.length > 0) seedFiles.push(file);
  }

  const accepted = preImageFlags > 0 && postImageFlags === 0;
  let reason: string;
  if (accepted) {
    reason = `validated: flags pre-image (${preImageFlags}) at ${seedFiles.join(", ")}, silent on post-fix image`;
  } else if (preImageFlags === 0) {
    reason = "rejected: checker does not flag its own seed bug in the pre-image (sink/guard patterns miss the seed)";
  } else {
    reason = `rejected: checker still fires ${postImageFlags}x on the post-fix image (guardPattern too narrow / wrong guard)`;
  }
  return { accepted, preImageFlags, postImageFlags, seedFiles, reason };
}

// ── Step 1: synthesize a checker (one LLM call, executeNative pattern) ─────────

interface CheckerFromModel {
  bugClass: string;
  invariant: string;
  sinkPattern: string;
  guardPattern: string;
  guardWindow?: number;
  weggliQuery?: string;
}

function checkerId(seed: CheckerSeed, bugClass: string): string {
  return (
    "chk-" +
    createHash("sha256")
      .update(`${seed.fixSha}\n${bugClass}`)
      .digest("hex")
      .slice(0, 16)
  );
}

const EMIT_CHECKER_TOOL = {
  name: "emit_checker",
  description: "Emit the bug-class checker learned from the fix diff + buggy pre-image.",
  input_schema: {
    type: "object",
    properties: {
      bugClass: {
        type: "string",
        description: "The bug class the fix closed, e.g. 'missing length check before a TLV copy'.",
      },
      invariant: {
        type: "string",
        description: "The invariant the fix enforces, e.g. 'a skb->len bound must precede this field read'.",
      },
      sinkPattern: {
        type: "string",
        description:
          "A grep EXTENDED-REGEX matching the dangerous SINK SHAPE with identifiers WILDCARDED so it matches OTHER sites, not just the original. Match the sink/call (e.g. a length-controlled copy), NOT the guard.",
      },
      guardPattern: {
        type: "string",
        description:
          "A grep EXTENDED-REGEX matching the GUARD the fix ADDED (a bounds/NULL/state check). It MUST be present in the post-fix code near the sink and ABSENT in the buggy pre-image. Wildcard identifiers.",
      },
      guardWindow: {
        type: "number",
        description: "How many source lines around a sink the guard may live in. Default 8; widen if the fix's check is far from the sink.",
      },
      weggliQuery: {
        type: "string",
        description: "OPTIONAL weggli query for the same sink shape (used only when weggli is installed).",
      },
    },
    required: ["bugClass", "invariant", "sinkPattern", "guardPattern"],
  },
};

const SYNTH_SYSTEM =
  "You are a kernel security CHECKER-SYNTHESIS analyst. Given (a) an upstream security fix diff and (b) the buggy " +
  "PRE-IMAGE of the file(s) it touched, learn the bug-class INVARIANT the fix enforces and encode it as a concrete, " +
  "REUSABLE checker: a SINK regex (the dangerous shape, identifiers wildcarded) plus a GUARD regex (the check the fix " +
  "ADDED).\n" +
  "CRITICAL CONTRACT — the checker will be self-validated: your SINK regex MUST match the buggy site in the PRE-IMAGE, " +
  "and your GUARD regex MUST match the fix's added check so that, in the POST-fix code, the guard appears within " +
  "`guardWindow` lines of the sink. A site is flagged when the sink matches but NO guard is within the window. So: in " +
  "the pre-image the guard is ABSENT (site flagged = catches the seed); in the post-image the guard is PRESENT (site " +
  "silent). If your patterns don't achieve BOTH, the checker is rejected.\n" +
  "Encode the INVARIANT, not the diff text: WILDCARD field/struct/variable names (e.g. `->len`, `->size`, " +
  "`memcpy\\([^,]+,[^,]+,[^)]*->len\\)`), so the checker finds the SAME class at OTHER call-sites the fix missed. " +
  "Call emit_checker.";

/**
 * ONE LLM call that reads the fix diff + the buggy pre-image and emits a
 * concrete checker (sink ERE + guard ERE + window, plus an optional weggli
 * query). Mirrors the `executeNative` tool-call pattern of
 * `variant-candidates.ts`. Does NOT validate — that is the caller's job (see
 * `synthesizeValidatedChecker`), so a rejected checker can be regenerated with
 * the failure reason fed back in.
 */
export async function synthesizeChecker(args: {
  seed: CheckerSeed;
  diff: string;
  preImages: Array<{ path: string; content: string }>;
  runtime: CheckerRuntime;
  /** Prior rejection reasons to steer a regenerate (empty on the first attempt). */
  priorFailures?: string[];
}): Promise<SynthesizedChecker | null> {
  const preSection = args.preImages
    .map((p) => `### ${p.path} (buggy pre-image)\n${clip(p.content, 8_000)}`)
    .join("\n\n");
  const retrySection =
    args.priorFailures && args.priorFailures.length > 0
      ? `\n\n## Prior attempts were REJECTED — fix these:\n${args.priorFailures.map((f, i) => `${i + 1}. ${f}`).join("\n")}`
      : "";
  const messages = [
    {
      role: "user",
      content: [
        {
          type: "text",
          text: `## Fix diff\n${clip(args.diff, 20_000)}\n\n## Buggy pre-image(s)\n${preSection}${retrySection}`,
        },
      ],
    },
  ];

  let model: CheckerFromModel | null = null;
  try {
    const res = (await args.runtime.executeNative(
      SYNTH_SYSTEM,
      messages as never,
      [EMIT_CHECKER_TOOL] as never,
      { onThinking() {}, onDelta() {}, onText() {}, onUsage() {} } as never,
    )) as { content?: Array<Record<string, unknown>> };
    const call = (res.content ?? []).find(
      (b) =>
        (b as { type?: string }).type === "tool_use" &&
        (b as { name?: string }).name === "emit_checker",
    ) as { input?: CheckerFromModel } | undefined;
    if (call?.input) model = call.input;
  } catch (e) {
    throw new Error(`checker-synthesis LLM call failed: ${String(e).slice(0, 200)}`);
  }
  if (!model || !model.sinkPattern || !model.guardPattern) return null;

  return {
    id: checkerId(args.seed, model.bugClass),
    bugClass: model.bugClass,
    invariant: model.invariant,
    sinkPattern: model.sinkPattern,
    guardPattern: model.guardPattern,
    guardWindow: model.guardWindow && model.guardWindow > 0 ? model.guardWindow : DEFAULT_GUARD_WINDOW,
    ...(model.weggliQuery ? { weggliQuery: model.weggliQuery } : {}),
    seed: args.seed,
    validation: { accepted: false, preImageFlags: 0, postImageFlags: 0, seedFiles: [], reason: "not yet validated" },
  };
}

// ── Steps 1+2 composed: synthesize → self-validate → (retry) ──────────────────

export interface SynthesizeValidatedResult {
  /** The accepted, self-validated checker — or null if every attempt was rejected. */
  checker: SynthesizedChecker | null;
  attempts: number;
  /** The rejection reasons of every failed attempt (audit trail). */
  rejections: string[];
}

/**
 * Synthesize a checker for `seed` and admit it to the library ONLY if it
 * self-validates (flags its seed pre-image, silent on the post-fix image).
 * Regenerates up to `maxAttempts`, feeding each rejection reason back into the
 * next synthesis prompt. Returns `{ checker: null }` if none validated.
 */
export async function synthesizeValidatedChecker(
  seed: CheckerSeed,
  tree: string,
  opts?: { maxAttempts?: number; deps?: CheckerSynthesisDeps },
): Promise<SynthesizeValidatedResult> {
  const deps = resolveDeps(opts?.deps);
  const maxAttempts = opts?.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;

  const diff = deps.git.diff(tree, seed.fixSha);
  if (!diff.trim()) {
    return { checker: null, attempts: 0, rejections: [`could not read fix commit ${seed.fixSha}`] };
  }
  const fixedFiles = deps.git.files(tree, seed.fixSha);
  if (fixedFiles.length === 0) {
    return { checker: null, attempts: 0, rejections: ["fix touched no .c/.h files"] };
  }
  const preImages = fixedFiles
    .map((path) => ({ path, content: deps.git.show(tree, `${seed.fixSha}^`, path) }))
    .filter((p): p is { path: string; content: string } => typeof p.content === "string");
  if (preImages.length === 0) {
    return { checker: null, attempts: 0, rejections: ["no readable pre-image for any fixed file"] };
  }

  const rejections: string[] = [];
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const candidate = await synthesizeChecker({
      seed,
      diff,
      preImages,
      runtime: deps.runtime,
      priorFailures: rejections,
    });
    if (!candidate) {
      rejections.push("model did not emit a usable checker");
      continue;
    }
    const validation = selfValidateChecker(candidate, tree, fixedFiles, deps.git);
    if (validation.accepted) {
      return { checker: { ...candidate, validation }, attempts: attempt, rejections };
    }
    rejections.push(validation.reason);
  }
  return { checker: null, attempts: maxAttempts, rejections };
}

// ── Step 3: sweep the validated checker for the siblings the fix missed ────────

export interface CheckerSweepOptions {
  /** File globs to sweep. Default C/C++/headers. */
  includeGlobs?: string[];
  /** Cap on sibling hits returned. Default 60. */
  maxHits?: number;
  /**
   * Apply the kernelCTF COS-6.12 reachability filter to sibling hits
   * (`classifyPatchGapReachability`). Default OFF (annotates but keeps every
   * hit — deterministic parity with a raw sweep). When true, DROP hits on paths
   * that are unreachable to a zero-cap attacker.
   */
  reachableOnly?: boolean;
  deps?: CheckerSynthesisDeps;
}

/**
 * Sweep a validated checker across the whole tree and return the sibling sites
 * it flags — the sink-without-guard shapes at OTHER files the fix never
 * touched. The seed's own fixed files are excluded. grep is the always-on sink
 * prefilter; when weggli is installed and the checker carries a `weggliQuery`,
 * weggli-listed files are UNIONed in as an extra sink locator (no-op otherwise).
 * Every candidate file is then re-read and run through the deterministic
 * `evaluateChecker` invariant so the guard-window decision — not a raw grep hit
 * — is what surfaces a sibling.
 */
export function sweepCheckerForSiblings(
  checker: SynthesizedChecker,
  tree: string,
  opts?: CheckerSweepOptions,
): CheckerSweepHit[] {
  const deps = resolveDeps(opts?.deps);
  const includeGlobs = opts?.includeGlobs ?? ["*.c", "*.h", "*.cc", "*.cpp"];
  const maxHits = opts?.maxHits ?? 60;

  // Files the seed fix touched — never re-surface them as "siblings".
  const excluded = new Set(deps.git.files(tree, checker.seed.fixSha));

  // Sink prefilter: grep always; weggli as an optional union when present.
  const files = new Set(deps.grepFiles(tree, checker.sinkPattern, includeGlobs));
  if (checker.weggliQuery && deps.weggliAvailable()) {
    for (const f of weggliSinkFiles(tree, checker.weggliQuery)) files.add(f);
  }

  const hits: CheckerSweepHit[] = [];
  for (const file of files) {
    if (excluded.has(file)) continue;
    if (hits.length >= maxHits) break;
    const content = readTreeFile(tree, file);
    if (content === undefined) continue;
    for (const m of evaluateChecker(checker, file, content)) {
      const hit: CheckerSweepHit = { ...m };
      if (opts?.reachableOnly !== undefined) {
        const r = classifyPatchGapReachability(file);
        hit.reachable = r.reachable;
        hit.reachabilityReason = r.reason;
        if (opts.reachableOnly && r.reachable === "unreachable") continue;
      }
      hits.push(hit);
      if (hits.length >= maxHits) break;
    }
  }
  return hits;
}

function readTreeFile(tree: string, relPath: string): string | undefined {
  try {
    return readFileSync(join(tree, relPath), "utf8");
  } catch {
    return undefined;
  }
}

/** Best-effort weggli sink locator — returns [] on any error / missing binary. */
function weggliSinkFiles(tree: string, query: string): string[] {
  try {
    const out = execFileSync("weggli", ["-R", query, "."], {
      cwd: tree,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
      timeout: 120_000,
    }) as string;
    // weggli prints `path:line:` headers; collect distinct repo-relative paths.
    const files = new Set<string>();
    for (const line of out.split("\n")) {
      const m = /^([^\s:]+\.(?:c|h|cc|cpp)):/.exec(line.replace(/^\.\//, ""));
      if (m) files.add(m[1]);
    }
    return [...files];
  } catch {
    return [];
  }
}

// ── Step 4: compose sweep hits with the existing finder→skeptic→prover gate ────

export interface CheckerHuntPlan {
  brief: HuntBrief;
  candidates: HuntCandidate[];
  hits: CheckerSweepHit[];
}

/**
 * Turn sweep hits into a `runHuntScan`-ready plan (a {@link HuntBrief} + the
 * sibling {@link HuntCandidate}s) — the exact shape `variant-candidates.ts`
 * produces, so it plugs into the existing hunt/verify pipeline unchanged.
 */
export function checkerSweepToPlan(
  checker: SynthesizedChecker,
  hits: CheckerSweepHit[],
): CheckerHuntPlan {
  const candidates: HuntCandidate[] = hits.map((h) => ({
    path: h.file,
    hint:
      `Checker ${checker.id} flagged a sink for "${checker.bugClass}" at ${h.file}:${h.line} ` +
      `with no guard nearby. Invariant the seed fix enforces: ${checker.invariant}. ` +
      `Confirm this sibling has the identical defect (the site the fix missed).`,
  }));
  return {
    brief: {
      bugClass: checker.bugClass,
      pattern: checker.invariant,
      fixReference: checker.seed.reference ?? checker.seed.fixSha,
    },
    candidates,
    hits,
  };
}

export interface RunCheckerVariantHuntOptions {
  tree: string;
  checker: SynthesizedChecker;
  runtime: HuntScanOptions["runtime"];
  /** Finder model diversity (forwarded to runHuntScan). */
  models?: string[];
  /**
   * The verify gate STAGES (skeptic, prover, …). Composed via {@link composeGate}
   * — the cheap skeptic first, the expensive prover last — so FPs die before the
   * prover runs. Omit to return finder candidates unconfirmed.
   */
  gate?: HuntVerifier[];
  /** Optional terminal PROVE stage (exploitability upgrade oracle). */
  exploitability?: HuntVerifier;
  sweep?: CheckerSweepOptions;
  /** Injectable runner (defaults to the real `runHuntScan`). Exposed for tests. */
  runHunt?: (opts: HuntScanOptions) => Promise<HuntScanResult>;
}

/**
 * End-to-end: sweep a validated checker for siblings, then run them through the
 * EXISTING finder→skeptic→prover hunt. The verify stages are composed with
 * {@link composeGate} exactly as the module docs prescribe, so only reachable,
 * reproduced siblings survive. Returns null when the sweep finds nothing
 * (nothing to hunt).
 */
export async function runCheckerVariantHunt(
  opts: RunCheckerVariantHuntOptions,
): Promise<HuntScanResult | null> {
  const hits = sweepCheckerForSiblings(opts.checker, opts.tree, opts.sweep);
  if (hits.length === 0) return null;
  const plan = checkerSweepToPlan(opts.checker, hits);

  const runHunt = opts.runHunt ?? (await import("../stages/hunt-scan.js")).runHuntScan;
  const verify =
    opts.gate && opts.gate.length > 0 ? composeGate(...opts.gate) : undefined;

  return runHunt({
    sourceRoot: opts.tree,
    candidates: plan.candidates,
    brief: plan.brief,
    runtime: opts.runtime,
    ...(opts.models ? { models: opts.models } : {}),
    ...(verify ? { verify } : {}),
    ...(opts.exploitability ? { exploitability: opts.exploitability } : {}),
  });
}

/**
 * Render a sweep hit as a hypothesis-grade kernel review Finding — parity with
 * `incompleteFixLeadToFinding`, so checker siblings are directly consumable by
 * the review pipeline without a full hunt.
 */
export function checkerSweepHitToFinding(
  checker: SynthesizedChecker,
  hit: CheckerSweepHit,
): Finding {
  return {
    id: createHash("sha256").update(`${checker.id}:${hit.file}:${hit.line}`).digest("hex").slice(0, 32),
    templateId: `kernel-checker-${checker.id}`,
    title: `${hit.file}:${hit.line}: possible ${checker.bugClass} (checker sibling of ${checker.seed.fixSha.slice(0, 12)})`,
    description: [
      `Self-validated checker ${checker.id} (learned from fix ${checker.seed.fixSha.slice(0, 12)}`,
      checker.seed.subject ? `"${checker.seed.subject}")` : ")",
      `flagged a sink for "${checker.bugClass}" at ${hit.file}:${hit.line} with no guard within`,
      `${checker.guardWindow} lines. Invariant: ${checker.invariant}.`,
      "Sibling site the fix did not touch — investigate whether it has the identical defect.",
    ].join(" "),
    severity: "medium",
    category: "other",
    status: "discovered",
    evidence: {
      request: `${hit.file}:${hit.line}`,
      response: hit.snippet,
      analysis: [
        "Source: checker-synthesis",
        `Checker: ${checker.id}`,
        `Bug class: ${checker.bugClass}`,
        `Invariant: ${checker.invariant}`,
        `Seed fix: ${checker.seed.fixSha.slice(0, 12)}`,
        `Self-validated: pre=${checker.validation.preImageFlags} post=${checker.validation.postImageFlags}`,
        hit.reachable ? `kernelCTF reachability: ${hit.reachable} (${hit.reachabilityReason})` : "",
      ]
        .filter(Boolean)
        .join("\n"),
    },
    fingerprint: `checker:${checker.id}:${hit.file}:${hit.line}`,
    triageStatus: "new",
    confidence: 0.45,
    timestamp: Date.now(),
  };
}

// ── Step 5: persist the checker library (the compounding property) ─────────────

/**
 * Persist a validated checker as a JSON artifact in `libraryDir` (filename
 * `<id>.json`). The directory is a GROWING library: re-runs and future fixes
 * reuse every checker ever admitted — this is what makes the technique
 * compound rather than re-pay the synthesis cost each run. NOTE: the library is
 * a plain on-disk directory of JSON; no database or shared infra store is wired
 * here — provisioning a durable/shared home (and a cron for the watcher below)
 * is left to infra.
 */
export function saveChecker(checker: SynthesizedChecker, libraryDir: string): string {
  mkdirSync(libraryDir, { recursive: true });
  const path = join(libraryDir, `${checker.id}.json`);
  writeFileSync(path, JSON.stringify(checker, null, 2), "utf8");
  return path;
}

/** Load every persisted checker from `libraryDir` (empty on a missing dir). */
export function loadCheckerLibrary(libraryDir: string): SynthesizedChecker[] {
  if (!existsSync(libraryDir)) return [];
  const out: SynthesizedChecker[] = [];
  let names: string[];
  try {
    names = readdirSync(libraryDir).filter((n) => n.endsWith(".json"));
  } catch {
    return [];
  }
  for (const name of names) {
    try {
      const c = JSON.parse(readFileSync(join(libraryDir, name), "utf8")) as SynthesizedChecker;
      if (c && c.id && c.sinkPattern) out.push(c);
    } catch {
      // skip one malformed artifact — never abort the load
    }
  }
  return out;
}

// ── Watcher entry point (callable stage; infra owns the schedule) ──────────────

export interface CheckerWatcherOptions {
  tree: string;
  /** git `--since` spec bounding the recent fixes to fan out. Default "2 weeks ago". */
  since?: string;
  /** Path prefixes to scope the fix mining to (e.g. ["net", "crypto"]). */
  paths?: string[];
  /** Cap on fixes fanned through the loop. Default 40. */
  maxFixes?: number;
  /** Persist each validated checker here (skipped when omitted). */
  libraryDir?: string;
  /** Per-checker sweep options. */
  sweep?: CheckerSweepOptions;
  /** Retry budget per fix. Default 3. */
  maxAttempts?: number;
  deps?: CheckerSynthesisDeps;
  log?: (msg: string) => void;
}

export interface CheckerWatcherEntry {
  fix: FixCommit;
  checker?: SynthesizedChecker;
  /** Sibling sites the validated checker surfaced (empty if none / not validated). */
  siblings: CheckerSweepHit[];
  /** Rejection reasons when no checker validated. */
  rejections: string[];
}

export interface CheckerWatcherResult {
  entries: CheckerWatcherEntry[];
  checkersSynthesized: number;
  siblingsFound: number;
}

/**
 * WATCHER: fan the latest upstream security fixes through the synthesis loop so
 * we hunt variants within hours of a fix landing. Reuses `mineFixCommits`
 * (`fix-commit-intel.ts`) to fetch recent Fixes:-tagged / security-keyworded
 * commits from the local tree, synthesizes + self-validates a checker per fix,
 * sweeps each validated checker for siblings, and (optionally) persists the
 * checker to the growing library. Wired as a CALLABLE STAGE — infra owns the
 * cron/heartbeat that invokes it (see the autonomous-night-loop runbook).
 */
export async function huntVariantsForRecentFixes(
  opts: CheckerWatcherOptions,
): Promise<CheckerWatcherResult> {
  const log = opts.log ?? (() => {});
  const deps = resolveDeps(opts.deps);
  const fixes = mineFixCommits({
    tree: opts.tree,
    since: opts.since ?? "2 weeks ago",
    ...(opts.paths ? { paths: opts.paths } : {}),
    securityOnly: true,
  }).slice(0, opts.maxFixes ?? 40);

  const entries: CheckerWatcherEntry[] = [];
  let checkersSynthesized = 0;
  let siblingsFound = 0;

  for (const fix of fixes) {
    const seed: CheckerSeed = {
      fixSha: fix.sha,
      subject: fix.subject,
      ...(fix.fixesTag ? { reference: fix.fixesTag } : {}),
    };
    const { checker, rejections } = await synthesizeValidatedChecker(seed, opts.tree, {
      ...(opts.maxAttempts ? { maxAttempts: opts.maxAttempts } : {}),
      deps,
    });
    if (!checker) {
      log(`[checker-watch] ${fix.sha.slice(0, 12)} no validated checker: ${rejections.at(-1) ?? "?"}`);
      entries.push({ fix, siblings: [], rejections });
      continue;
    }
    checkersSynthesized += 1;
    if (opts.libraryDir) saveChecker(checker, opts.libraryDir);
    const siblings = sweepCheckerForSiblings(checker, opts.tree, { ...opts.sweep, deps });
    siblingsFound += siblings.length;
    log(`[checker-watch] ${fix.sha.slice(0, 12)} checker ${checker.id}: ${siblings.length} sibling(s)`);
    entries.push({ fix, checker, siblings, rejections });
  }

  return { entries, checkersSynthesized, siblingsFound };
}

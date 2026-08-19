/**
 * kernel/fork-diff.ts — ENGINE F: LLM-semantic vendor/downstream fork bug-diff.
 *
 * Hunt LPEs in vendor/downstream kernels (Android/AOSP, RHEL/CentOS-Stream,
 * SUSE, ChromeOS, embedded BSPs) that DIVERGE from the mainline commit they
 * forked from. Vendor code is UNDER-AUDITED BY CONSTRUCTION: mainline review +
 * syzbot only cover mainline, so a bug a vendor ADDS — or a mainline fix the
 * vendor FAILS to backport — lives in a blind spot. Android LPE is high-value
 * (MSRC / Android bounties), and nobody does LLM-semantic vendor-fork
 * bug-diffing. This module is the fork-diff STAGE for that. Two halves:
 *
 *   1. MISSING-BACKPORT — reuse the self-validating checker spine
 *      (`checker-synthesis.ts`): learn a bug-class invariant from a MAINLINE
 *      security fix (checker flags the pre-image, silent on the post-fix
 *      image), then evaluate that SAME validated checker against the VENDOR
 *      tree's copy of the fixed file. If the checker FLAGS the vendor file, the
 *      vendor is sitting in the mainline PRE-image (unguarded) state — it never
 *      took the backport. This half is composed from existing pieces.
 *
 *   2. VENDOR-ONLY-CODE — the genuinely new part: a deterministic diff surfaces
 *      code that exists ONLY in the vendor tree (whole files absent from
 *      mainline, plus functions a vendor ADDED to a shared file), and those
 *      become `runHuntScan` candidates so the existing finder→skeptic→prover
 *      gate hunts vendor-introduced bugs. Deterministic enumeration for
 *      coverage; the LLM only reads code it was pointed at (no hallucinated
 *      file set).
 *
 * Both halves share tree-enumeration + file-read plumbing behind an injectable
 * {@link ForkTreeIo}, so the whole stage is offline fixture-testable. The e2e
 * run needs a real vendor source tree checked out next to a mainline tree
 * (that lives on the bench box) — see the PR body's follow-up note.
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

import type { Finding } from "@0sec/shared";

import {
  composeGate,
  type HuntBrief,
  type HuntCandidate,
  type HuntScanOptions,
  type HuntScanResult,
  type HuntVerifier,
} from "../stages/hunt-scan.js";
import {
  evaluateChecker,
  synthesizeValidatedChecker,
  type CheckerSeed,
  type CheckerSynthesisDeps,
  type SynthesizedChecker,
} from "./checker-synthesis.js";

const DEFAULT_GLOBS = ["*.c", "*.h", "*.cc", "*.cpp"];

// ── Injectable tree IO (real on the non-test path) ─────────────────────────────

/**
 * The read-only tree surface both halves need. Injectable so the loop runs
 * fully offline in tests (a fake returning a known file list + contents), and
 * so the vendor tree need not even be a git repo (a plain extracted BSP works).
 */
export interface ForkTreeIo {
  /** Repo-relative source files under `tree` matching `globs` (extension-filtered). */
  listFiles: (tree: string, globs: string[]) => string[];
  /** `tree`-relative file content, or undefined when absent / unreadable. */
  readFile: (tree: string, relPath: string) => string | undefined;
}

/** Extensions the include-globs (`*.c` …) reduce to for the fs-walk fallback. */
function globExtensions(globs: string[]): string[] {
  return globs
    .map((g) => {
      const m = /\*(\.[A-Za-z0-9]+)$/.exec(g);
      return m ? m[1] : undefined;
    })
    .filter((e): e is string => typeof e === "string");
}

/**
 * Default IO: `git ls-files` when the tree is a git checkout (fast, skips
 * `.git`), else a bounded recursive fs walk (skips `.git`/`node_modules`).
 * Reads are plain `readFileSync`. Fails soft — a missing tree yields `[]` /
 * `undefined` rather than throwing.
 */
export function defaultForkTreeIo(): ForkTreeIo {
  return {
    listFiles(tree, globs) {
      const exts = globExtensions(globs.length > 0 ? globs : DEFAULT_GLOBS);
      // git-first: fast and .git-aware.
      try {
        const out = execFileSync(
          "git",
          ["-C", tree, "ls-files", "--", ...globs],
          { encoding: "utf8", maxBuffer: 128 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] },
        ) as string;
        const files = out.split("\n").map((s) => s.trim()).filter(Boolean);
        if (files.length > 0) return files;
      } catch {
        // not a git tree (or git absent) — fall through to the fs walk
      }
      return fsWalk(tree, exts);
    },
    readFile(tree, relPath) {
      try {
        return readFileSync(join(tree, relPath), "utf8");
      } catch {
        return undefined;
      }
    },
  };
}

/** Bounded recursive walk collecting repo-relative files with an allowed extension. */
function fsWalk(tree: string, exts: string[], max = 200_000): string[] {
  const out: string[] = [];
  const stack: string[] = [""];
  const allowed = new Set(exts);
  while (stack.length > 0) {
    if (out.length >= max) break;
    const rel = stack.pop() as string;
    let entries: import("node:fs").Dirent[];
    try {
      entries = readdirSync(join(tree, rel), { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (e.name === ".git" || e.name === "node_modules") continue;
        stack.push(childRel);
      } else if (e.isFile()) {
        const dot = e.name.lastIndexOf(".");
        if (dot >= 0 && allowed.has(e.name.slice(dot))) out.push(childRel);
      }
    }
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════════
// HALF 1 — MISSING-BACKPORT (reuse the self-validating checker spine)
// ═══════════════════════════════════════════════════════════════════════════════

/** A site where the vendor tree is missing a mainline fix's guard. */
export interface MissingBackportHit {
  /** Vendor-relative path (assumed == the mainline path the fix touched). */
  file: string;
  /** 1-based line of the unguarded sink in the vendor file. */
  line: number;
  /** The vendor sink line, trimmed and clipped. */
  snippet: string;
  /** The mainline checker that flagged it. */
  checkerId: string;
  bugClass: string;
  invariant: string;
  /** The mainline fix the vendor never backported. */
  seedFixSha: string;
  seedReference?: string;
}

/**
 * Evaluate a MAINLINE-validated checker against the VENDOR tree's copy of the
 * files the fix touched. A flag means the vendor sink lacks the guard the fix
 * added — the vendor is in the mainline PRE-image state, i.e. it never took the
 * backport. Pure w.r.t. the injected IO; the checker MUST already be
 * self-validated on mainline (flags its pre-image, silent post-fix) for a
 * vendor flag to mean "missing backport" rather than "bad checker".
 */
export function checkVendorForMissingBackport(
  checker: SynthesizedChecker,
  vendorTree: string,
  fixedFiles: string[],
  io: ForkTreeIo,
): MissingBackportHit[] {
  const hits: MissingBackportHit[] = [];
  for (const file of fixedFiles) {
    const content = io.readFile(vendorTree, file);
    if (content === undefined) continue; // vendor doesn't ship this file — no gap here
    for (const m of evaluateChecker(checker, file, content)) {
      hits.push({
        file: m.file,
        line: m.line,
        snippet: m.snippet,
        checkerId: checker.id,
        bugClass: checker.bugClass,
        invariant: checker.invariant,
        seedFixSha: checker.seed.fixSha,
        ...(checker.seed.reference ? { seedReference: checker.seed.reference } : {}),
      });
    }
  }
  return hits;
}

export interface MissingBackportHuntOptions {
  /** Mainline tree the fixes live in (checker synthesis + self-validation run here). */
  mainlineTree: string;
  /** Vendor/downstream tree to check for un-backported guards. */
  vendorTree: string;
  /** Mainline security fixes to learn checkers from (e.g. from `mineFixCommits`). */
  seeds: CheckerSeed[];
  /** Retry budget per checker synthesis (forwarded). Default 3. */
  maxAttempts?: number;
  /** Checker-synthesis deps (LLM runtime + git). Injected in tests for offline runs. */
  checkerDeps?: CheckerSynthesisDeps;
  /** Vendor-tree IO (defaults to {@link defaultForkTreeIo}). */
  io?: ForkTreeIo;
  log?: (msg: string) => void;
}

export interface MissingBackportEntry {
  seed: CheckerSeed;
  /** The validated mainline checker (absent when synthesis never validated). */
  checker?: SynthesizedChecker;
  /** Vendor sites missing the fix's guard (empty when the vendor is up to date). */
  hits: MissingBackportHit[];
  /** Rejection reasons when no checker validated for this seed. */
  rejections: string[];
}

export interface MissingBackportResult {
  entries: MissingBackportEntry[];
  checkersValidated: number;
  gapsFound: number;
}

/** The `.c`/`.h` files a mainline fix commit touched (real git; [] on error). */
function realMainlineFixedFiles(tree: string, sha: string): string[] {
  try {
    return (
      execFileSync("git", ["-C", tree, "show", "--name-only", "--format=", sha], {
        encoding: "utf8",
        maxBuffer: 128 * 1024 * 1024,
        stdio: ["ignore", "pipe", "ignore"],
      }) as string
    )
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.endsWith(".c") || l.endsWith(".h"));
  } catch {
    return [];
  }
}

/**
 * For each mainline fix seed: synthesize + self-validate a checker on the
 * MAINLINE tree, then check whether the VENDOR tree took the backport. Any
 * vendor site the validated checker flags is a missing-backport gap (a
 * known-class defect live downstream). Fully offline when `checkerDeps`
 * (runtime + git) and `io` are injected.
 */
export async function huntMissingBackports(
  opts: MissingBackportHuntOptions,
): Promise<MissingBackportResult> {
  const log = opts.log ?? (() => {});
  const io = opts.io ?? defaultForkTreeIo();
  // Prefer the injected checker git (tests) for the fixed-file list so the whole
  // hunt stays offline; else read the real mainline commit.
  const fixedFilesFor = (sha: string): string[] =>
    opts.checkerDeps?.git
      ? opts.checkerDeps.git.files(opts.mainlineTree, sha)
      : realMainlineFixedFiles(opts.mainlineTree, sha);

  const entries: MissingBackportEntry[] = [];
  let checkersValidated = 0;
  let gapsFound = 0;

  for (const seed of opts.seeds) {
    const { checker, rejections } = await synthesizeValidatedChecker(seed, opts.mainlineTree, {
      ...(opts.maxAttempts ? { maxAttempts: opts.maxAttempts } : {}),
      ...(opts.checkerDeps ? { deps: opts.checkerDeps } : {}),
    });
    if (!checker) {
      log(`[fork-diff] ${seed.fixSha.slice(0, 12)} no validated checker: ${rejections.at(-1) ?? "?"}`);
      entries.push({ seed, hits: [], rejections });
      continue;
    }
    checkersValidated += 1;
    const fixedFiles = fixedFilesFor(seed.fixSha);
    const hits = checkVendorForMissingBackport(checker, opts.vendorTree, fixedFiles, io);
    gapsFound += hits.length;
    log(
      `[fork-diff] ${seed.fixSha.slice(0, 12)} checker ${checker.id}: ${hits.length} vendor backport gap(s)`,
    );
    entries.push({ seed, checker, hits, rejections });
  }

  return { entries, checkersValidated, gapsFound };
}

/**
 * Render a missing-backport gap as a hypothesis-grade kernel review Finding —
 * parity with `incompleteFixLeadToFinding` / `checkerSweepHitToFinding`, so the
 * gap is directly consumable by the review pipeline. This is a STRONG signal (a
 * known mainline fix + a vendor site that lacks its guard), so it carries a
 * slightly higher confidence than a raw sweep sibling.
 */
export function missingBackportHitToFinding(hit: MissingBackportHit): Finding {
  const fixShort = hit.seedFixSha.slice(0, 12);
  return {
    id: createHash("sha256").update(`backport:${hit.checkerId}:${hit.file}:${hit.line}`).digest("hex").slice(0, 32),
    templateId: `kernel-missing-backport-${hit.checkerId}`,
    title: `${hit.file}:${hit.line}: vendor missing backport of ${fixShort} (${hit.bugClass})`,
    description: [
      `The mainline fix ${fixShort}${hit.seedReference ? ` (${hit.seedReference})` : ""} added a guard for`,
      `"${hit.bugClass}". A self-validated checker learned from that fix (flags the mainline pre-image,`,
      `silent on the post-fix image) STILL FIRES on the vendor tree at ${hit.file}:${hit.line} — the vendor`,
      `sits in the pre-fix, unguarded state and never took the backport. Invariant: ${hit.invariant}.`,
      `Confirm the un-backported defect is reachable on the vendor target (under-audited by construction).`,
    ].join(" "),
    severity: "medium",
    category: "other",
    status: "discovered",
    evidence: {
      request: `${hit.file}:${hit.line}`,
      response: hit.snippet,
      analysis: [
        "Source: fork-diff (missing-backport)",
        `Checker: ${hit.checkerId}`,
        `Bug class: ${hit.bugClass}`,
        `Invariant: ${hit.invariant}`,
        `Un-backported mainline fix: ${fixShort}`,
        hit.seedReference ? `Fix references: ${hit.seedReference}` : "",
      ]
        .filter(Boolean)
        .join("\n"),
    },
    fingerprint: `backport:${hit.checkerId}:${hit.file}:${hit.line}`,
    triageStatus: "new",
    confidence: 0.5,
    timestamp: Date.now(),
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// HALF 2 — VENDOR-ONLY-CODE (the net-new part)
// ═══════════════════════════════════════════════════════════════════════════════

/** A C function definition site: the name and its 1-based def line. */
export interface FunctionDef {
  name: string;
  line: number;
}

// Statement heads that a def-shaped regex would otherwise mistake for a
// function definition (`if (`, `for (`, …). Kernel style puts real definitions'
// return type / `static` at column 0, so we also require no leading whitespace.
const C_STATEMENT_HEADS = new Set([
  "if", "for", "while", "switch", "return", "sizeof", "do", "else", "case", "goto",
]);

/**
 * Best-effort C function-definition extraction: a column-0 line whose leading
 * return-type-ish tokens are followed by `name(`, not ending in `;`/`,`. Kernel
 * definitions start at column 0, so requiring no indentation filters most
 * in-body calls and control statements. Heuristic — used only to DIFF two trees'
 * function sets, never as ground truth.
 */
export function extractFunctionDefs(content: string): FunctionDef[] {
  const out = new Map<string, number>();
  const lines = content.split("\n");
  const re = /^[A-Za-z_][\w *]*?\b([A-Za-z_]\w*)\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s/.test(line)) continue; // definitions start at column 0
    const t = line.trimEnd();
    if (t.endsWith(";") || t.endsWith(",")) continue; // prototype / decl / call / multi-line args
    const m = line.match(re);
    if (!m) continue;
    if (C_STATEMENT_HEADS.has(m[1])) continue;
    if (!out.has(m[1])) out.set(m[1], i + 1);
  }
  return [...out.entries()].map(([name, line]) => ({ name, line }));
}

/** Files present in the vendor tree but absent from mainline (whole-file vendor additions). */
export function enumerateVendorOnlyFiles(mainlineFiles: string[], vendorFiles: string[]): string[] {
  const mainline = new Set(mainlineFiles);
  return vendorFiles.filter((f) => !mainline.has(f));
}

/** A function a vendor added to a file that ALSO exists in mainline (shared-file divergence). */
export interface VendorAddedFunction {
  file: string;
  name: string;
  line: number;
}

/** Functions defined in the vendor copy of a shared file whose names are absent from mainline's. */
export function enumerateVendorAddedFunctions(
  file: string,
  mainlineContent: string,
  vendorContent: string,
): VendorAddedFunction[] {
  const mainlineNames = new Set(extractFunctionDefs(mainlineContent).map((d) => d.name));
  return extractFunctionDefs(vendorContent)
    .filter((d) => !mainlineNames.has(d.name))
    .map((d) => ({ file, name: d.name, line: d.line }));
}

export interface VendorForkDiffOptions {
  mainlineTree: string;
  vendorTree: string;
  /** Source globs to enumerate. Default C/C++/headers. */
  includeGlobs?: string[];
  /** Cap on vendor-only files turned into candidates. Default 60. */
  maxFiles?: number;
  /** Also diff SHARED files for vendor-added functions. Default true. */
  includeAddedFunctions?: boolean;
  /** Cap on vendor-added-function candidates. Default 60. */
  maxAddedFunctions?: number;
  io?: ForkTreeIo;
  log?: (msg: string) => void;
}

export interface VendorForkDiff {
  /** Files only the vendor ships (full-file candidates). */
  vendorOnlyFiles: string[];
  /** Functions the vendor added to files shared with mainline. */
  vendorAddedFunctions: VendorAddedFunction[];
  /** Ready-to-run hunt candidates (vendor-only files + added functions). */
  candidates: HuntCandidate[];
  /** The vendor-only-code hunt brief. */
  brief: HuntBrief;
  warnings: string[];
}

const VENDOR_ONLY_BRIEF: HuntBrief = {
  bugClass: "vendor-introduced memory-safety / logic bug in downstream-only code",
  pattern:
    "Code that exists ONLY in this vendor/downstream tree (absent from the mainline commit it forked from) and was " +
    "therefore never reviewed upstream or fuzzed by syzbot. Look for the usual LPE-grade defects — OOB read/write, " +
    "UAF/refcount, integer overflow feeding a copy/alloc, missing capability/bounds checks — on an attacker-reachable path.",
};

/**
 * Compute the vendor↔mainline fork diff: the files and functions that exist
 * ONLY in the vendor tree, mapped to `runHuntScan` candidates. Deterministic
 * (pure set/text diff over the injected IO) — the LLM is only pointed at this
 * enumerated set later, never asked to guess it.
 */
export function computeVendorForkDiff(opts: VendorForkDiffOptions): VendorForkDiff {
  const log = opts.log ?? (() => {});
  const io = opts.io ?? defaultForkTreeIo();
  const globs = opts.includeGlobs ?? DEFAULT_GLOBS;
  const maxFiles = opts.maxFiles ?? 60;
  const maxAddedFunctions = opts.maxAddedFunctions ?? 60;
  const includeAddedFunctions = opts.includeAddedFunctions ?? true;
  const warnings: string[] = [];

  const mainlineFiles = io.listFiles(opts.mainlineTree, globs);
  const vendorFiles = io.listFiles(opts.vendorTree, globs);
  if (vendorFiles.length === 0) warnings.push("vendor tree listed no source files (empty / unreadable tree)");

  const vendorOnlyAll = enumerateVendorOnlyFiles(mainlineFiles, vendorFiles);
  const vendorOnlyFiles = vendorOnlyAll.slice(0, maxFiles);
  if (vendorOnlyAll.length > maxFiles) {
    warnings.push(`capped vendor-only files ${vendorOnlyAll.length} -> ${maxFiles} (raise maxFiles to widen)`);
  }

  // Shared files: diff each one's function set for vendor-added functions.
  const vendorAddedFunctions: VendorAddedFunction[] = [];
  if (includeAddedFunctions) {
    const mainlineSet = new Set(mainlineFiles);
    for (const file of vendorFiles) {
      if (vendorAddedFunctions.length >= maxAddedFunctions) break;
      if (!mainlineSet.has(file)) continue; // vendor-only files are already whole-file candidates
      const mainlineContent = io.readFile(opts.mainlineTree, file);
      const vendorContent = io.readFile(opts.vendorTree, file);
      if (mainlineContent === undefined || vendorContent === undefined) continue;
      for (const fn of enumerateVendorAddedFunctions(file, mainlineContent, vendorContent)) {
        vendorAddedFunctions.push(fn);
        if (vendorAddedFunctions.length >= maxAddedFunctions) break;
      }
    }
  }

  const candidates: HuntCandidate[] = [
    ...vendorOnlyFiles.map((path) => ({
      path,
      hint:
        "VENDOR-ONLY FILE: this whole file is absent from mainline (a downstream addition) and was never " +
        "reviewed upstream or fuzzed by syzbot. Hunt an attacker-reachable memory-safety / logic bug here.",
    })),
    ...vendorAddedFunctions.map((fn) => ({
      path: fn.file,
      hint:
        `VENDOR-ADDED FUNCTION: ${fn.name}() at ${fn.file}:${fn.line} exists in the vendor tree but NOT in ` +
        "mainline (a downstream divergence in a shared file). Focus on this function; hunt a memory-safety / " +
        "logic bug on an attacker-reachable path into it.",
    })),
  ];

  log(
    `[fork-diff] vendor-only: ${vendorOnlyFiles.length} file(s) + ${vendorAddedFunctions.length} added function(s) ` +
      `= ${candidates.length} candidate(s)`,
  );

  return { vendorOnlyFiles, vendorAddedFunctions, candidates, brief: VENDOR_ONLY_BRIEF, warnings };
}

export interface RunVendorForkDiffHuntOptions {
  mainlineTree: string;
  vendorTree: string;
  runtime: HuntScanOptions["runtime"];
  /** Finder model diversity (forwarded to runHuntScan). */
  models?: string[];
  /**
   * The verify gate STAGES (skeptic, prover, …). Composed via {@link composeGate}
   * — cheap skeptic first, expensive prover last — so FPs die before the prover.
   * Omit to return finder candidates unconfirmed.
   */
  gate?: HuntVerifier[];
  /** Optional terminal PROVE stage (exploitability-upgrade oracle). */
  exploitability?: HuntVerifier;
  /** Fork-diff knobs (globs / caps / IO). */
  diff?: Omit<VendorForkDiffOptions, "mainlineTree" | "vendorTree" | "io" | "log">;
  io?: ForkTreeIo;
  /** Injectable runner (defaults to the real `runHuntScan`). Exposed for tests. */
  runHunt?: (opts: HuntScanOptions) => Promise<HuntScanResult>;
  log?: (msg: string) => void;
}

/**
 * End-to-end: compute the vendor fork diff, then hunt the vendor-only
 * candidates through the EXISTING finder→skeptic→prover gate (composed with
 * {@link composeGate}). The hunt runs against the VENDOR tree (that is where the
 * bug lives). Returns null when the diff surfaces no vendor-only code (nothing
 * to hunt).
 */
export async function runVendorForkDiffHunt(
  opts: RunVendorForkDiffHuntOptions,
): Promise<HuntScanResult | null> {
  const io = opts.io ?? defaultForkTreeIo();
  const diff = computeVendorForkDiff({
    mainlineTree: opts.mainlineTree,
    vendorTree: opts.vendorTree,
    io,
    ...(opts.log ? { log: opts.log } : {}),
    ...(opts.diff ?? {}),
  });
  if (diff.candidates.length === 0) return null;

  const runHunt = opts.runHunt ?? (await import("../stages/hunt-scan.js")).runHuntScan;
  const verify = opts.gate && opts.gate.length > 0 ? composeGate(...opts.gate) : undefined;

  return runHunt({
    sourceRoot: opts.vendorTree,
    candidates: diff.candidates,
    brief: diff.brief,
    runtime: opts.runtime,
    ...(opts.models ? { models: opts.models } : {}),
    ...(verify ? { verify } : {}),
    ...(opts.exploitability ? { exploitability: opts.exploitability } : {}),
  });
}

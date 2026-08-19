/**
 * kernel/incomplete-fix-hunt.ts
 *
 * INCOMPLETE-FIX VARIANT HUNTING — the find-side consumer of the git-fix-commit
 * intelligence in `fix-commit-intel.ts`, and the single technique that produced
 * a real lead in the 2026-06 kernel sweep when breadth-first auditing returned
 * "guarded" on ~19 subsystems.
 *
 * The shape: a maintainer fixes a UAF/OOB/refcount bug on path A
 * (`tipc_aead_encrypt`) and misses the structurally-identical sibling on path B
 * (`tipc_aead_decrypt`). This module mines recent security fixes, learns the
 * function FAMILY each one touched, and surfaces sibling functions in the same
 * file that share the family stem but were NOT touched by the fix — exactly the
 * "encrypt got the guard, decrypt didn't" lead. Each is emitted as a low-
 * confidence kernel Finding for the review/verify pipeline to investigate.
 *
 * Read-only git only; fails soft (returns []) on a non-git tree or any error.
 */
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";

import type { Finding } from "@0sec/shared";

// Type-only import — erased at compile, so it adds no runtime dependency on the
// (heavy) hunt-scan stage and creates no import cycle.
import type { HuntBrief } from "../stages/hunt-scan.js";
import {
  isKernelGitTree,
  mineFixCommits,
  type FixCommit,
} from "./fix-commit-intel.js";

function git(tree: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: tree,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
    maxBuffer: 128 * 1024 * 1024,
  });
}

/** The `.c` files a commit touched (within the queried scope). */
function commitFiles(tree: string, sha: string): string[] {
  try {
    return git(tree, ["show", "--name-only", "--format=", sha])
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.endsWith(".c"));
  } catch {
    return [];
  }
}

/**
 * Functions a commit changed in `file`, parsed from git's hunk-header function
 * context (`@@ -a,b +c,d @@ <enclosing function>`). Best-effort: returns the
 * leading identifier-before-`(` of each hunk context.
 */
function commitTouchedFunctions(
  tree: string,
  sha: string,
  file: string,
): Set<string> {
  const fns = new Set<string>();
  let diff: string;
  try {
    diff = git(tree, ["show", "--unified=0", "--format=", sha, "--", file]);
  } catch {
    return fns;
  }
  for (const line of diff.split("\n")) {
    if (!line.startsWith("@@")) continue;
    // context is whatever follows the second "@@"
    const ctx = line.replace(/^@@.*?@@/, "").trim();
    const m = ctx.match(/\b([a-z_][a-z0-9_]*)\s*\(/i);
    if (m) fns.add(m[1]);
  }
  return fns;
}

/** Family stem of a function: drop the last `_segment`. `a_b_c` -> `a_b_`. */
export function familyStem(fn: string): string | undefined {
  const idx = fn.lastIndexOf("_");
  // Require a real multi-part name so the stem isn't trivially generic.
  if (idx <= 0) return undefined;
  const stem = fn.slice(0, idx + 1);
  // Guard against over-broad stems (e.g. "do_", "__").
  return stem.replace(/_+$/, "").length >= 4 ? stem : undefined;
}

export interface SiblingDef {
  name: string;
  line: number;
}

/**
 * Definition-like sites of functions whose name begins with `stem` in C source.
 * Heuristic: a line with a return-type-ish prefix then `stem<rest>(`, not ending
 * in `;` (filters prototypes). Returns the 1-based line of each distinct name.
 */
export function siblingDefsForStem(content: string, stem: string): SiblingDef[] {
  const out = new Map<string, number>();
  const lines = content.split("\n");
  const esc = stem.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`^[A-Za-z_][\\w\\*\\s]*?\\b(${esc}[A-Za-z0-9_]+)\\s*\\(`);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trimEnd().endsWith(";")) continue; // prototype / call stmt
    const m = line.match(re);
    if (m && !out.has(m[1])) out.set(m[1], i + 1);
  }
  return [...out.entries()].map(([name, line]) => ({ name, line }));
}

function fileAtHead(tree: string, file: string): string | undefined {
  try {
    return git(tree, ["show", `HEAD:${file}`]);
  } catch {
    return undefined;
  }
}

function inferSubsystem(file: string): string {
  const parts = file.split("/");
  if (parts.length >= 2) return `${parts[0]}/${parts[1]}`;
  return parts[0] ?? "unknown";
}

export interface IncompleteFixLead {
  /** the untouched sibling worth investigating. */
  siblingFunction: string;
  /** the function the recent fix actually touched. */
  fixedFunction: string;
  file: string;
  line: number;
  subsystem: string;
  fix: FixCommit;
}

export interface IncompleteFixHuntOptions {
  tree: string;
  /** git `--since` spec; default "3 months ago". */
  since?: string;
  /** path prefixes to scope to, e.g. ["net", "fs", "crypto"]. */
  paths?: string[];
  /** cap on fix commits scanned; default 300. */
  limit?: number;
  /** cap on emitted leads; default 40. */
  maxLeads?: number;
}

/**
 * Mine recent security fixes and surface untouched same-family siblings as
 * incomplete-fix leads. Pure read-only git; [] on a non-git tree / error.
 */
export function huntIncompleteFixSiblings(
  opts: IncompleteFixHuntOptions,
): IncompleteFixLead[] {
  const { tree } = opts;
  if (!isKernelGitTree(tree)) return [];

  const fixes = mineFixCommits({
    tree,
    ...(opts.since ? { since: opts.since } : {}),
    ...(opts.paths ? { paths: opts.paths } : {}),
    ...(opts.limit ? { limit: opts.limit } : {}),
    securityOnly: true,
  });

  const leads: IncompleteFixLead[] = [];
  const seen = new Set<string>();
  const maxLeads = opts.maxLeads ?? 40;

  for (const fix of fixes) {
    if (leads.length >= maxLeads) break;
    for (const file of commitFiles(tree, fix.sha)) {
      const touched = commitTouchedFunctions(tree, fix.sha, file);
      if (touched.size === 0) continue;
      const content = fileAtHead(tree, file);
      if (!content) continue;

      for (const fixedFunction of touched) {
        const stem = familyStem(fixedFunction);
        if (!stem) continue;
        for (const sib of siblingDefsForStem(content, stem)) {
          if (touched.has(sib.name)) continue; // the fixed one(s)
          const key = `${file}:${sib.name}`;
          if (seen.has(key)) continue;
          seen.add(key);
          leads.push({
            siblingFunction: sib.name,
            fixedFunction,
            file,
            line: sib.line,
            subsystem: inferSubsystem(file),
            fix,
          });
          if (leads.length >= maxLeads) break;
        }
        if (leads.length >= maxLeads) break;
      }
      if (leads.length >= maxLeads) break;
    }
  }
  return leads;
}

/** Render an incomplete-fix lead as a kernel review Finding (hypothesis-grade). */
export function incompleteFixLeadToFinding(lead: IncompleteFixLead): Finding {
  const fixShort = lead.fix.sha.slice(0, 12);
  return {
    id: randomUUID(),
    templateId: `kernel-incomplete-fix-${fixShort}-${lead.siblingFunction}`,
    title: `${lead.siblingFunction}: possible incomplete-fix sibling of ${lead.fixedFunction}`,
    description: [
      `Recent fix ${fixShort} ("${lead.fix.subject}", ${lead.fix.dateIso.slice(0, 10)})`,
      `touched ${lead.fixedFunction} in ${lead.file}. The same-family sibling`,
      `${lead.siblingFunction} (${lead.file}:${lead.line}) was NOT touched by that`,
      `fix — investigate whether it has the identical defect (the encrypt-fixed /`,
      `decrypt-unfixed shape). Incomplete-fix variant lead, not a confirmed crash.`,
    ].join(" "),
    severity: "medium",
    category: "other",
    status: "discovered",
    evidence: {
      request: `${lead.file}:${lead.line}`,
      response: `sibling of recently-fixed ${lead.fixedFunction}`,
      analysis: [
        "Source: incomplete-fix-hunt",
        `Subsystem: ${lead.subsystem}`,
        "Hypothesis: true",
        `Faulting function: ${lead.siblingFunction}`,
        `Sibling of fixed: ${lead.fixedFunction}`,
        `Fix commit: ${fixShort} "${lead.fix.subject}"`,
        lead.fix.securityKeyword ? `Fix class: ${lead.fix.securityKeyword}` : "",
        lead.fix.fixesTag ? `Fix references: ${lead.fix.fixesTag}` : "",
      ]
        .filter(Boolean)
        .join("\n"),
    },
    fingerprint: `incfix:${lead.file}:${lead.siblingFunction}:${fixShort}`,
    triageStatus: "new",
    confidence: 0.45,
    timestamp: Date.now(),
  };
}

// ── BAD-FIX (fix-of-fix) INGEST ──────────────────────────────────────────────
//
// The strongest recent kernel bugs are BAD FIXES: the guard a fix commit added
// was itself incomplete or bypassable, and a SECOND fix landed on the same file
// shortly after (the MSG_OOB UAF was introduced by a fix commit; Google's first
// SFQ patch was bypassable). A file that gets two security fixes within a short
// window is a signal that the class is under-covered and worth re-auditing — the
// later fix may STILL be incomplete.
//
// This surfaces those file-local fix-of-fix pairs by pure read-only git mining
// (reuses `mineFixCommits`), turning each into a HuntBrief hint the variant hunt
// can run. Fails soft ([]) on a non-git tree / error, like the rest of the module.

export interface BadFixLead {
  /** The later commit — the fix-of-fix whose guard may STILL be incomplete. */
  fix: FixCommit;
  /** The earlier security fix on the same file that it followed. */
  priorFix: FixCommit;
  file: string;
  /** Whole days between the prior fix and this one (≤ withinDays). */
  daysApart: number;
  subsystem: string;
}

export interface BadFixHuntOptions {
  tree: string;
  /** git `--since` spec bounding the fix history; default "6 months ago". */
  since?: string;
  /** max days between a security fix and the next one on the same file; default 30. */
  withinDays?: number;
  /** path prefixes to scope to, e.g. ["net/sched", "net/tls"]. */
  paths?: string[];
  /** cap on fix commits scanned when discovering candidate files; default 300. */
  limit?: number;
  /** cap on distinct files inspected for fix-of-fix pairs; default 200. */
  maxFiles?: number;
  /** cap on emitted leads; default 40. */
  maxLeads?: number;
}

function daysBetween(earlierIso: string, laterIso: string): number {
  const a = Date.parse(earlierIso);
  const b = Date.parse(laterIso);
  if (Number.isNaN(a) || Number.isNaN(b)) return Number.POSITIVE_INFINITY;
  return Math.round((b - a) / 86_400_000);
}

/**
 * Find fix-of-fix (bad-fix) pairs: a file that received a second security fix
 * within `withinDays` of a prior one. For each such pair the LATER commit is the
 * bad-fix candidate — its guard may still be incomplete/bypassable. Pure
 * read-only git; [] on a non-git tree / error.
 */
export function findBadFixes(opts: BadFixHuntOptions): BadFixLead[] {
  const { tree } = opts;
  if (!isKernelGitTree(tree)) return [];

  const since = opts.since ?? "6 months ago";
  const withinDays = opts.withinDays ?? 30;
  const limit = opts.limit ?? 300;
  const maxFiles = opts.maxFiles ?? 200;
  const maxLeads = opts.maxLeads ?? 40;

  // 1. Discover the files that recent security fixes touched (the candidate set).
  const seedFixes = mineFixCommits({
    tree,
    since,
    ...(opts.paths ? { paths: opts.paths } : {}),
    limit,
    securityOnly: true,
  });
  const files: string[] = [];
  const seenFile = new Set<string>();
  for (const fix of seedFixes) {
    for (const file of commitFiles(tree, fix.sha)) {
      if (!seenFile.has(file)) {
        seenFile.add(file);
        files.push(file);
      }
    }
    if (files.length >= maxFiles) break;
  }

  // 2. For each file, walk its security-fix history and flag consecutive fixes
  //    that landed within the window — the later one is the bad-fix candidate.
  const leads: BadFixLead[] = [];
  const seenLead = new Set<string>();
  for (const file of files.slice(0, maxFiles)) {
    if (leads.length >= maxLeads) break;
    const fileFixes = mineFixCommits({ tree, since, paths: [file], limit, securityOnly: true });
    if (fileFixes.length < 2) continue;
    // Oldest first so a pair is (prior, later).
    const chron = [...fileFixes].sort((a, b) => a.dateIso.localeCompare(b.dateIso));
    for (let i = 1; i < chron.length; i++) {
      const priorFix = chron[i - 1];
      const fix = chron[i];
      if (fix.sha === priorFix.sha) continue;
      const daysApart = daysBetween(priorFix.dateIso, fix.dateIso);
      if (daysApart > withinDays) continue;
      const key = `${file}:${fix.sha}`;
      if (seenLead.has(key)) continue;
      seenLead.add(key);
      leads.push({ fix, priorFix, file, daysApart, subsystem: inferSubsystem(file) });
      if (leads.length >= maxLeads) break;
    }
  }
  return leads;
}

/**
 * Turn a bad-fix lead into a {@link HuntBrief} for the variant hunt: the hint is
 * "the guard may be incomplete/bypassable (bad-fix)". Feed it to `runHuntScan`
 * with the lead's `file` as the candidate site.
 */
export function badFixLeadToBrief(lead: BadFixLead): HuntBrief {
  const cur = lead.fix.sha.slice(0, 12);
  const prev = lead.priorFix.sha.slice(0, 12);
  return {
    bugClass: `incomplete/bypassable guard (bad-fix / fix-of-fix) in ${lead.file}`,
    pattern:
      `Commit ${cur} ("${lead.fix.subject}") landed ${lead.daysApart}d after a prior security fix ` +
      `${prev} ("${lead.priorFix.subject}") on the SAME file — the earlier guard may be incomplete ` +
      `or bypassable (the MSG_OOB / SFQ pattern: a fix that under-covers the class or introduces a ` +
      `new instance). Audit whether ${cur}'s guard fully covers the bug class or can still be reached.`,
    fixReference: lead.fix.sha,
  };
}

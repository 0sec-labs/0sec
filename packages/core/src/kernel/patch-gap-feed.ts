/**
 * kernel/patch-gap-feed.ts
 *
 * Parses the Linux kernel security team's official CVE feed
 * (`git.kernel.org/pub/scm/linux/security/vulns.git`, cloned on bench at
 * `/root/kernel-vulns`) into a normalized `UpstreamFixEntry` — the input the
 * patch-gap monitor (`patch-gap.ts`) diffs against a target tree.
 *
 * Schema grounding (verified against a real published record on bench,
 * `/root/kernel-vulns/cve/published/2026/CVE-2026-53356.json`, CVE JSON 5.1.1):
 *   - `cveMetadata.cveId` / `cveMetadata.state` (only "PUBLISHED" is useful —
 *     "REJECTED" entries live under `cve/rejected/` and are never fed here).
 *   - `containers.cna.title` — the fix commit's one-line subject.
 *   - `containers.cna.affected[].programFiles` — repo-relative file paths.
 *   - `containers.cna.affected[].versions[]` where `versionType: "git"` lists
 *     one `lessThan` SHA per stable branch the fix was backported to (the
 *     kernel security team files ONE CVE per upstream bug but the fix lands
 *     as a DIFFERENT commit object on each stable branch it's cherry-picked
 *     onto — none of these branch-specific SHAs is necessarily the one a
 *     third tree like kernelCTF's COS-6.12 would carry, see patch-gap-check.ts).
 *   - `containers.cna.descriptions[0].value` commonly ends with
 *     `(cherry picked from commit <sha>)` — the ORIGINAL mainline commit the
 *     stable branches all cherry-picked from. This is the anchor the
 *     "commit <sha> upstream." trailer match in patch-gap-check.ts keys off.
 *
 * Deliberately tolerant: an entry missing fields we don't need (CVSS,
 * cpeApplicability, etc.) still parses; an entry missing what we DO need
 * (no CVE id, no fix commit SHA of any kind) returns `null` rather than
 * throwing, so one malformed file in a 12k+-file feed can't crash a scan.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** One `versions[]` entry we care about — the git-SHA-keyed backport pointers. */
interface RawVersionEntry {
  versionType?: string;
  lessThan?: string;
  lessThanOrEqual?: string;
}

interface RawAffected {
  programFiles?: string[];
  versions?: RawVersionEntry[];
}

/** The subset of the CVE JSON 5.x record shape this module reads. Everything else is ignored. */
export interface RawVulnsCveRecord {
  cveMetadata?: { cveId?: string; state?: string };
  containers?: {
    cna?: {
      title?: string;
      descriptions?: Array<{ lang?: string; value?: string }>;
      affected?: RawAffected[];
      references?: Array<{ url?: string }>;
    };
  };
}

/** A parsed upstream fix, ready to be checked against a target tree. */
export interface UpstreamFixEntry {
  cve: string;
  title: string;
  /** Repo-relative files the fix touched (deduped, order-preserving). */
  files: string[];
  /**
   * The original mainline commit, extracted from the "(cherry picked from
   * commit X)" trailer in the description. Undefined when the fix WAS the
   * mainline commit (no cherry-pick note) or the description doesn't carry one
   * — callers fall back to `candidateShas` alone in that case.
   */
  mainlineSha?: string;
  /**
   * Every per-stable-branch fix-commit SHA the feed lists (`versions[]`
   * `versionType: "git"` `lessThan`, plus any `git.kernel.org/stable/c/<sha>`
   * reference URLs — the two sources overlap heavily but neither is a strict
   * superset of the other in the wild, so both are merged and deduped).
   */
  candidateShas: string[];
}

const SHA_RE = /^[0-9a-f]{7,40}$/i;
const CHERRY_PICK_RE = /cherry picked from commit\s+([0-9a-f]{7,40})\b/i;
const STABLE_REF_RE = /git\.kernel\.org\/stable\/c\/([0-9a-f]{7,40})\b/i;

function dedupe(values: string[]): string[] {
  return [...new Set(values)];
}

/**
 * Parse one raw CVE JSON record (already `JSON.parse`d) into an
 * `UpstreamFixEntry`. Pure — no I/O. Returns `null` when the record isn't a
 * published kernel CVE, or carries no file path / fix-commit SHA we can act
 * on (a CVE entry with prose-only description and no git.kernel.org
 * reference is not actionable for a git-ancestor check).
 */
export function parseVulnsCveRecord(raw: unknown): UpstreamFixEntry | null {
  if (!raw || typeof raw !== "object") return null;
  const rec = raw as RawVulnsCveRecord;

  const cve = rec.cveMetadata?.cveId;
  if (!cve) return null;
  // "REJECTED" / "RESERVED" entries carry no usable fix data; only PUBLISHED
  // records reach this parser in practice (see loadVulnsFeedFromDir), but
  // guard defensively since callers may feed arbitrary JSON.
  if (rec.cveMetadata?.state && rec.cveMetadata.state !== "PUBLISHED") return null;

  const cna = rec.containers?.cna;
  if (!cna) return null;

  const title = cna.title ?? "";

  const files = dedupe((cna.affected ?? []).flatMap((a) => a.programFiles ?? []));

  const shasFromVersions = (cna.affected ?? []).flatMap((a) =>
    (a.versions ?? [])
      .filter((v) => v.versionType === "git" && typeof v.lessThan === "string" && SHA_RE.test(v.lessThan))
      .map((v) => v.lessThan!.toLowerCase()),
  );
  const shasFromRefs = (cna.references ?? [])
    .map((r) => r.url?.match(STABLE_REF_RE)?.[1])
    .filter((s): s is string => Boolean(s))
    .map((s) => s.toLowerCase());
  const candidateShas = dedupe([...shasFromVersions, ...shasFromRefs]);

  const description = cna.descriptions?.find((d) => !d.lang || d.lang === "en")?.value ?? "";
  const cherryPick = description.match(CHERRY_PICK_RE)?.[1];
  const mainlineSha = cherryPick ? cherryPick.toLowerCase() : undefined;

  // Nothing to check against a target tree — not actionable.
  if (candidateShas.length === 0 && !mainlineSha) return null;

  return {
    cve,
    title,
    files,
    ...(mainlineSha ? { mainlineSha } : {}),
    candidateShas,
  };
}

// ── Thin IO: read a local vulns.git clone (e.g. bench's /root/kernel-vulns) ──

/** Injectable directory listing + file reads, so the loader is testable without touching the real filesystem in unit tests that don't need to. */
export interface VulnsFeedIo {
  listYearDirs(publishedDir: string): string[];
  listJsonFiles(yearDir: string): string[];
  readJson(path: string): unknown;
}

/** Default IO: real `node:fs`, reading straight off disk (no network — the feed is a local git clone). */
export function defaultVulnsFeedIo(): VulnsFeedIo {
  return {
    listYearDirs(publishedDir) {
      try {
        return readdirSync(publishedDir, { withFileTypes: true })
          .filter((e) => e.isDirectory())
          .map((e) => join(publishedDir, e.name));
      } catch {
        return [];
      }
    },
    listJsonFiles(yearDir) {
      try {
        return readdirSync(yearDir, { withFileTypes: true })
          .filter((e) => e.isFile() && e.name.endsWith(".json"))
          .map((e) => join(yearDir, e.name));
      } catch {
        return [];
      }
    },
    readJson(filePath) {
      return JSON.parse(readFileSync(filePath, "utf8"));
    },
  };
}

export interface LoadVulnsFeedOptions {
  /** Path to the vulns.git clone root (contains `cve/published/<year>/*.json`). Default `/root/kernel-vulns` (bench). */
  vulnsRepoPath?: string;
  /** Only load years >= this (e.g. 2024) — the feed has 12k+ files back to ~2018; most patch-gap hunting only cares about recent fixes. Default: no filter. */
  sinceYear?: number;
  /** Cap on total entries returned (post-filter), applied after sorting newest-CVE-first. Default: no cap. */
  limit?: number;
  /** Injectable IO (tests). Default `defaultVulnsFeedIo()`. */
  io?: VulnsFeedIo;
}

/**
 * Load + parse every published CVE record under `<vulnsRepoPath>/cve/published/`.
 * One bad JSON file is skipped (not fatal) so a single corrupt entry can't
 * abort a 12k-file scan. Newest-CVE-id first.
 */
export function loadVulnsFeedFromDir(opts: LoadVulnsFeedOptions = {}): UpstreamFixEntry[] {
  const vulnsRepoPath = opts.vulnsRepoPath ?? "/root/kernel-vulns";
  const io = opts.io ?? defaultVulnsFeedIo();
  const publishedDir = `${vulnsRepoPath.replace(/\/$/, "")}/cve/published`;

  const yearDirs = io.listYearDirs(publishedDir).filter((dir) => {
    if (opts.sinceYear === undefined) return true;
    const year = Number.parseInt(dir.split("/").pop() ?? "", 10);
    return Number.isFinite(year) ? year >= opts.sinceYear : true;
  });

  const entries: UpstreamFixEntry[] = [];
  for (const yearDir of yearDirs) {
    for (const file of io.listJsonFiles(yearDir)) {
      let parsed: UpstreamFixEntry | null = null;
      try {
        parsed = parseVulnsCveRecord(io.readJson(file));
      } catch {
        parsed = null; // malformed JSON — skip, never abort the scan
      }
      if (parsed) entries.push(parsed);
    }
  }

  entries.sort((a, b) => b.cve.localeCompare(a.cve));
  return opts.limit !== undefined ? entries.slice(0, opts.limit) : entries;
}

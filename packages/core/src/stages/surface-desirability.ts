/**
 * Surface-desirability scoring for HUNT CANDIDATE SELECTION (generic
 * fresh-surface hunt).
 *
 * WHY THIS EXISTS. The generic surface hunt (`hunt-surface.ts`) ranks candidate
 * `.c` files by ONE signal: file size, largest-first. That spends finder budget
 * on whatever is biggest, not on where a source-review hunt actually has an
 * edge. A session hunting the CVE-2026-23455 bug class (untrusted length-math in
 * in-kernel parsers) made the real edge explicit: our review finds bugs FUZZERS
 * MISS. It came up empty on remote in-kernel parsers (netfilter conntrack, SNMP,
 * ksmbd, SCTP, nfsd XDR) — 9/9 clean — because every one of those is either
 * heavily syzkaller-fuzzed or under an active maintainer sweep, so the shallow
 * length bugs are already gone. The bugs we DO land (mac802154 llsec, NFC LLCP,
 * mwifiex IE) sit on surfaces that are (a) parsers of untrusted input, (b) HARD
 * TO FUZZ — stateful / protocol-aware, so a protocol-aware fuzzer emits only
 * well-formed inputs and never probes the `len == 0` edge — and (c) NOT recently
 * swept by maintainers or other researchers.
 *
 * This module turns that heuristic into a deterministic candidate score so the
 * fresh-surface hunt prioritizes those surfaces over merely-large files. It is
 * the sibling of `hunt-reachability.ts` (a self-contained scorer applied at the
 * same slot, before the candidate cap) and reuses `fix-commit-intel.ts`'s
 * read-only git primitives for the sweep-recency signal.
 *
 * CONTRACT (mirrors hunt-reachability.ts / fix-commit-intel.ts):
 *   - `applySurfaceRanking` is a NO-OP unless `enabled` is set — callers that
 *     never opt in get byte-identical output to before this module existed.
 *   - Every I/O signal (grep, git) FAILS SOFT to a zero contribution, so a
 *     non-git tree / missing grep can never crash or reorder a hunt into
 *     uselessness — worst case it degrades to size-only ranking.
 *
 * SCOPE. The sweep-recency PENALTY (recently-fixed => lower score) is correct
 * ONLY for the generic fresh-surface hunt. It is INVERTED for the incomplete-fix
 * producers (`variant-candidates.ts`, `findBadFixes`), which deliberately SEEK
 * recently-fixed subsystems to find the unpatched sibling. Those producers must
 * pass `includeSweepRecency: false` (or not use this module) so the score does
 * not fight their premise.
 */
import { execFileSync } from "node:child_process";
import { mineFixCommits, isKernelGitTree } from "../kernel/fix-commit-intel.js";

/**
 * Subsystem path prefixes that are STATEFUL / PROTOCOL-AWARE parsers of
 * untrusted input — hard to fuzz well, so source review has an edge. Grounded
 * in where our landed/sent kernel fixes actually came from (mac802154 llsec,
 * NFC LLCP/digital, mwifiex IE, TIPC crypto, netfilter conntrack ALG helpers)
 * plus their close siblings. A path matching none of these gets no bonus (not a
 * penalty) — the other signals still apply.
 */
export const HARD_TO_FUZZ_PATH_PREFIXES: readonly string[] = [
  "net/nfc/", // NFC LLCP/NCI/HCI/digital — RF, stateful framing
  "net/mac802154/", // 802.15.4 MAC + llsec decrypt
  "net/ieee802154/", // 802.15.4 socket/header parse
  "net/tipc/", // TIPC — clustered, crypto, netns-stateful
  "net/sctp/", // SCTP chunk/param state machine
  "net/rxrpc/", // AF_RXRPC — Kerberos/rxgk stateful
  "net/netfilter/", // conntrack ALG helpers (h323/sip/ftp/…): stateful, protocol-aware
  "net/bluetooth/", // L2CAP/SMP/AMP — RF, pairing state
  "net/dccp/", // DCCP option parsing (deprecated but built on some distros)
  "crypto/", // AF_ALG surfaces, template/parse state
  "drivers/nfc/", // NFC controller drivers — device framing
  "drivers/net/ieee802154/", // 802.15.4 radio drivers
  "drivers/net/wireless/", // 802.11 driver IE parsers (mwifiex-class)
  "fs/smb/", // ksmbd — SMB2/SPNEGO/NDR, stateful auth
  "net/9p/", // 9P protocol parse
  "net/ceph/", // ceph messenger framing
];

/** True if `path` contains `prefix` as a whole path-segment sequence (anchored at start-of-string or a preceding "/"). */
function hasPathSegmentPrefix(path: string, prefix: string): boolean {
  const idx = path.indexOf(prefix);
  if (idx === -1) return false;
  return idx === 0 || path[idx - 1] === "/";
}

/** True if `path` sits under a hard-to-fuzz stateful-parser subsystem. */
export function isHardToFuzzSurface(path: string): boolean {
  const norm = path.replace(/\\/g, "/");
  return HARD_TO_FUZZ_PATH_PREFIXES.some((p) => hasPathSegmentPrefix(norm, p));
}

/** The raw signals gathered for one candidate path (any I/O signal is 0/null when not computed or on error). */
export interface SurfaceSignals {
  /** path sits under a HARD_TO_FUZZ_PATH_PREFIXES subsystem. */
  hardToFuzz: boolean;
  /** count of source lines matching untrusted-buffer/length idioms (grep); 0 if not computed. */
  parserIdiomLines: number;
  /** days since the file was last touched by any commit; null if unknown. */
  lastTouchDays: number | null;
  /** count of recent security/`Fixes:` commits touching the file (the sweep signal); 0 if not computed. */
  recentSecurityCommits: number;
}

/** A scored candidate: the final desirability `score` (higher = hunt first) plus the signals that produced it. */
export interface SurfaceScore {
  path: string;
  score: number;
  signals: SurfaceSignals;
}

// ── Scoring weights (documented constants; the whole policy lives here) ──
/** Bonus for a stateful/protocol-parser subsystem — the strongest single signal. */
export const W_HARD_TO_FUZZ = 3;
/** Bonus for heavy raw-buffer/length handling (parser idioms): +2 if dense, +1 if some. */
export const W_PARSER_DENSE = 2;
export const W_PARSER_SOME = 1;
export const PARSER_DENSE_LINES = 20;
export const PARSER_SOME_LINES = 5;
/** Bonus for staleness — an under-swept file is more likely to still hold a bug. */
export const W_STALE_OLD = 2; // > 1 year untouched
export const W_STALE_MID = 1; // > 6 months untouched
export const STALE_OLD_DAYS = 365;
export const STALE_MID_DAYS = 180;
/** Penalty PER recent security commit (a swept file is picked over), floored so one hot file can't dominate. */
export const W_SWEEP_PER_COMMIT = 2;
export const SWEEP_PENALTY_FLOOR = -6;

/**
 * Pure scoring function — deterministic, no I/O. Kept separate from
 * `gatherSurfaceSignals` so the policy is unit-testable without a git tree.
 */
export function computeSurfaceScore(signals: SurfaceSignals): number {
  let score = 0;
  if (signals.hardToFuzz) score += W_HARD_TO_FUZZ;

  if (signals.parserIdiomLines >= PARSER_DENSE_LINES) score += W_PARSER_DENSE;
  else if (signals.parserIdiomLines >= PARSER_SOME_LINES) score += W_PARSER_SOME;

  if (signals.lastTouchDays !== null) {
    if (signals.lastTouchDays > STALE_OLD_DAYS) score += W_STALE_OLD;
    else if (signals.lastTouchDays > STALE_MID_DAYS) score += W_STALE_MID;
  }

  if (signals.recentSecurityCommits > 0) {
    score += Math.max(SWEEP_PENALTY_FLOOR, -W_SWEEP_PER_COMMIT * signals.recentSecurityCommits);
  }
  return score;
}

/** Grep idiom groups that mark untrusted-buffer / length handling — the shape a length-math bug lives in. */
const PARSER_IDIOM_ERE =
  "skb_pull|skb_copy_bits|skb_header_pointer|copy_from_user|memdup_user|nla_|nlmsg_|get_unaligned|->len|->size|->length";

/** Count source lines in `absPath` matching the parser-idiom union. Fails soft to 0 (no grep, no match, bad file). */
function grepParserIdiomLines(absPath: string): number {
  try {
    const out = execFileSync("grep", ["-cE", "--", PARSER_IDIOM_ERE, absPath], {
      encoding: "utf8",
      timeout: 20_000,
    }) as string;
    const n = Number.parseInt(out.trim(), 10);
    return Number.isFinite(n) ? n : 0;
  } catch {
    return 0; // grep exits 1 on no match, >1 on error — either way, no signal.
  }
}

/** Days since `repoRelPath` was last touched, via read-only git. null on any error / untracked file. */
function lastTouchDays(tree: string, repoRelPath: string, nowMs: number): number | null {
  try {
    const iso = execFileSync("git", ["log", "-1", "--format=%cI", "--", repoRelPath], {
      cwd: tree,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 20_000,
    }) as string;
    const t = Date.parse(iso.trim());
    if (!Number.isFinite(t)) return null;
    return Math.max(0, Math.floor((nowMs - t) / 86_400_000));
  } catch {
    return null;
  }
}

export interface SurfaceDesirabilityOptions {
  /** Kernel git tree root — enables the staleness + sweep-recency git signals. Omit for path-only scoring. */
  tree?: string;
  /** Source root the grep runs against; defaults to `tree`. Candidate paths may be absolute (from `find`) or repo-relative. */
  sourceRoot?: string;
  /** git `--since` window for the sweep-recency penalty; default "6 months ago". */
  since?: string;
  /**
   * Include the recently-swept PENALTY. Correct for the generic fresh-surface
   * hunt (default true); MUST be false for incomplete-fix producers that seek
   * recently-fixed subsystems.
   */
  includeSweepRecency?: boolean;
  /** Skip all per-file I/O (grep + git) — score on the hard-to-fuzz prefix only. Fast, deterministic. */
  pathOnly?: boolean;
  /**
   * Injected clock (ms since epoch) for the staleness signal. Required when
   * `tree` is set and `pathOnly` is false, because `Date.now()` is unavailable
   * in some runtimes (workflow scripts) — callers pass a real timestamp.
   */
  nowMs?: number;
}

/** Turn a candidate path into a repo-relative path for git, given the source root (handles absolute `find` output). */
function toRepoRel(path: string, root: string | undefined): string {
  const norm = path.replace(/\\/g, "/");
  if (root) {
    const r = root.replace(/\\/g, "/").replace(/\/$/, "");
    if (norm.startsWith(r + "/")) return norm.slice(r.length + 1);
  }
  return norm;
}

/** Gather the signals for one candidate path (honors `pathOnly` and fails soft on every I/O signal). */
export function gatherSurfaceSignals(path: string, opts: SurfaceDesirabilityOptions): SurfaceSignals {
  const hardToFuzz = isHardToFuzzSurface(path);
  if (opts.pathOnly || !opts.tree) {
    return { hardToFuzz, parserIdiomLines: 0, lastTouchDays: null, recentSecurityCommits: 0 };
  }
  const root = opts.sourceRoot ?? opts.tree;
  const repoRel = toRepoRel(path, root);
  const isAbs = path.replace(/\\/g, "/").startsWith("/");
  const absPath = isAbs ? path : `${root.replace(/\/$/, "")}/${repoRel}`;

  const parserIdiomLines = grepParserIdiomLines(absPath);
  const touch = opts.nowMs !== undefined ? lastTouchDays(opts.tree, repoRel, opts.nowMs) : null;

  let recentSecurityCommits = 0;
  if (opts.includeSweepRecency !== false && isKernelGitTree(opts.tree)) {
    // Reuse the incomplete-fix intel primitive: security/`Fixes:` commits on this file in the window.
    recentSecurityCommits = mineFixCommits({
      tree: opts.tree,
      paths: [repoRel],
      since: opts.since ?? "6 months ago",
      securityOnly: true,
    }).length;
  }
  return { hardToFuzz, parserIdiomLines, lastTouchDays: touch, recentSecurityCommits };
}

/** Score one candidate path end-to-end (gather signals -> compute score). */
export function scoreSurfaceDesirability(path: string, opts: SurfaceDesirabilityOptions): SurfaceScore {
  const signals = gatherSurfaceSignals(path, opts);
  return { path, score: computeSurfaceScore(signals), signals };
}

export interface SurfaceRankingOptions extends SurfaceDesirabilityOptions {
  /** Opt-in switch. When falsy (the default) `applySurfaceRanking` is a no-op passthrough — byte-identical to no ranking. */
  enabled?: boolean;
}

export interface SurfaceRankingResult {
  /** Candidate paths, re-ordered highest-desirability first (stable within equal scores). Unchanged when disabled. */
  paths: string[];
  /** The scores that drove the sort (highest first), for logging. Empty when disabled. */
  scores: SurfaceScore[];
}

/**
 * Stable-sort candidate paths by descending surface-desirability. A no-op
 * passthrough unless `enabled` is set (mirrors `applyReachabilityGate`). Apply
 * BEFORE the candidate cap so desirable surfaces aren't truncated away by
 * size-only ranking. The sort is stable, so equal-score candidates keep their
 * incoming order (i.e. the existing size ranking is the tie-breaker).
 */
export function applySurfaceRanking(paths: string[], opts: SurfaceRankingOptions): SurfaceRankingResult {
  if (!opts.enabled) return { paths, scores: [] };
  const scored = paths.map((path, i) => ({ ...scoreSurfaceDesirability(path, opts), i }));
  // Stable sort: higher score first; ties keep original index order.
  scored.sort((a, b) => b.score - a.score || a.i - b.i);
  return {
    paths: scored.map((s) => s.path),
    scores: scored.map(({ path, score, signals }) => ({ path, score, signals })),
  };
}

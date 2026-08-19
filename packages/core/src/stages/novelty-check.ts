/**
 * Lore-mirror novelty gate — decides whether a confirmed kernel finding is
 * NOVEL or a DUPLICATE of an already-on-list (pending / merged) upstream fix,
 * WITHOUT a headless browser.
 *
 * The wasted cycle this closes: a hunt re-found a Rockchip AV1 tile-count
 * overflow that already had a pending fix on linux-media (Michael Bommarito,
 * 2026-06-17). The published-advisory dedup gate (`triage/publishability-*`)
 * only sees GHSA/OSV/CVE — it cannot see a patch that is merely *posted to a
 * mailing list* and not yet a CVE. That on-list window is exactly where kernel
 * de-dup matters, and it is exactly what this gate covers.
 *
 * PROVEN FOUNDATION — lore.kernel.org public-inbox mirrors clone over plain git
 * with no Anubis / JS challenge:
 *
 *     git clone https://lore.kernel.org/<list>/git/<epoch>.git <dir>
 *
 * Each commit is ONE email. The full RFC822 message (headers + body + patch
 * diff) lives in the single tree blob `m`; the commit *message* is only the
 * subject line, so content search must grep the blob, not `git log --grep`.
 * Lists are split into ~1 GB epochs (`git/0.git`, `git/1.git`, …); the
 * highest-numbered epoch holds the most recent mail.
 *
 * Pipeline, per finding:
 *   1. derive high-signal search terms (changed-file basenames, sink function
 *      names, distinctive identifiers).
 *   2. `git grep` the blob `m` across every commit (≈1 s for ~13 k emails) to
 *      find candidate patches, excluding our own postings (doruk@0sec.ai).
 *   3. an LLM judge reads the finding + each candidate patch and rules
 *      DUPLICATE / RELATED / UNRELATED with the message-id.
 *   4. return {novel, duplicates[]}.
 *
 * Everything network/LLM-touching is behind an injectable seam so the unit
 * tests stay offline and deterministic.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "@0sec/shared";
import { LlmApiRuntime } from "../runtime/llm-api.js";
import type { NativeRuntime } from "../runtime/types.js";

const pexecFile = promisify(execFile);

// ── Git seam ─────────────────────────────────────────────────────────────────

/** Runs a git invocation and returns stdout. Injectable so tests never shell out. */
export type GitRunner = (
  args: string[],
  opts?: { cwd?: string; timeoutMs?: number },
) => Promise<string>;

/**
 * Live git runner. Tolerates `git grep`'s "no match → exit 1" (returns the
 * empty stdout) while still surfacing real failures (exit ≥ 2, e.g. a bad repo
 * or a missing ls-remote target).
 */
export const liveGit: GitRunner = async (args, opts) => {
  try {
    const { stdout } = await pexecFile("git", args, {
      cwd: opts?.cwd,
      timeout: opts?.timeoutMs ?? 120_000,
      maxBuffer: 128 * 1024 * 1024,
    });
    return stdout;
  } catch (e) {
    const err = e as { code?: number; stdout?: string };
    // `git grep` exits 1 with empty stdout when nothing matched — not an error.
    if (err.code === 1) return err.stdout ?? "";
    throw e;
  }
};

// ── Mirror sync ──────────────────────────────────────────────────────────────

export interface LoreSyncOptions {
  /** Where the per-epoch clones live, e.g. `/root/lore-mirror`. */
  rootDir: string;
  /** Public-inbox list names, e.g. ["linux-media", "netdev", "linux-wireless"]. */
  lists: string[];
  /** How many newest epochs to keep per list. Default 1 (recent mail only). */
  recentEpochs?: number;
  /** Default https://lore.kernel.org */
  baseUrl?: string;
  git?: GitRunner;
  log?: (msg: string) => void;
}

/** One synced epoch clone. */
export interface LoreMirror {
  list: string;
  epoch: number;
  dir: string;
}

const DEFAULT_BASE_URL = "https://lore.kernel.org";
/** Public ownership markers — never treat these postings as third-party duplicates. */
export const OWN_FROM_MARKERS = ["0sec.ai", "doruk@"];

function epochUrl(baseUrl: string, list: string, epoch: number): string {
  return `${baseUrl}/${list}/git/${epoch}.git`;
}

function epochDir(rootDir: string, list: string, epoch: number): string {
  return join(rootDir, `${list}__${epoch}`);
}

/**
 * Probe which epochs exist for a list by `git ls-remote`, newest last. Stops at
 * the first gap once at least one epoch was found (epochs are contiguous from
 * 0). `maxProbe` caps the scan.
 */
export async function discoverEpochs(
  list: string,
  opts: { baseUrl?: string; git?: GitRunner; maxProbe?: number } = {},
): Promise<number[]> {
  const baseUrl = opts.baseUrl ?? DEFAULT_BASE_URL;
  const git = opts.git ?? liveGit;
  const maxProbe = opts.maxProbe ?? 32;
  const found: number[] = [];
  for (let n = 0; n < maxProbe; n++) {
    try {
      await git(["ls-remote", "--exit-code", epochUrl(baseUrl, list, n), "HEAD"], {
        timeoutMs: 30_000,
      });
      found.push(n);
    } catch {
      if (found.length > 0) break;
    }
  }
  return found;
}

/**
 * Idempotently clone/fetch the `recentEpochs` newest epochs of each list into
 * `rootDir`. Existing clones are `git fetch`ed (fast); missing ones are cloned.
 * Returns the synced epoch clones.
 */
export async function syncLoreMirror(opts: LoreSyncOptions): Promise<LoreMirror[]> {
  mkdirSync(opts.rootDir, { recursive: true });
  const baseUrl = opts.baseUrl ?? DEFAULT_BASE_URL;
  const git = opts.git ?? liveGit;
  const log = opts.log ?? (() => {});
  const recent = Math.max(1, opts.recentEpochs ?? 1);
  const mirrors: LoreMirror[] = [];

  for (const list of opts.lists) {
    const epochs = await discoverEpochs(list, { baseUrl, git });
    if (epochs.length === 0) {
      log(`[novelty] no epochs found for ${list} (skipping)`);
      continue;
    }
    const keep = epochs.slice(-recent);
    for (const epoch of keep) {
      const dir = epochDir(opts.rootDir, list, epoch);
      const url = epochUrl(baseUrl, list, epoch);
      if (existsSync(join(dir, ".git")) || existsSync(join(dir, "HEAD"))) {
        log(`[novelty] fetch ${list} epoch ${epoch}`);
        await git(["fetch", "--quiet", "origin"], { cwd: dir, timeoutMs: 300_000 });
      } else {
        log(`[novelty] clone ${list} epoch ${epoch}`);
        await git(["clone", "--quiet", url, dir], { timeoutMs: 600_000 });
      }
      mirrors.push({ list, epoch, dir });
    }
  }
  return mirrors;
}

/** Discover already-cloned epoch dirs under `rootDir` for the given lists. */
export function localMirrors(rootDir: string, lists: string[]): LoreMirror[] {
  const out: LoreMirror[] = [];
  for (const list of lists) {
    for (let epoch = 0; epoch < 32; epoch++) {
      const dir = epochDir(rootDir, list, epoch);
      if (existsSync(join(dir, ".git")) || existsSync(join(dir, "HEAD"))) {
        out.push({ list, epoch, dir });
      }
    }
  }
  return out;
}

// ── Term extraction ──────────────────────────────────────────────────────────

/** The discriminating facts about a finding that drive the lore search. */
export interface NoveltyQuery {
  title: string;
  /** Changed-file basenames, e.g. ["rockchip_vpu981_hw_av1_dec.c"]. */
  files?: string[];
  /** Sink / symbol names, e.g. ["rockchip_vpu981_av1_dec_set_tile_info"]. */
  symbols?: string[];
  /** Distinctive identifiers, e.g. ["tile_cols", "AV1_MAX_TILES"]. */
  identifiers?: string[];
  /** `From:` substrings to treat as OURS (excluded from duplicates). */
  excludeFrom?: string[];
}

/** A weighted search term; rarer/longer terms get more ranking weight. */
interface Term {
  text: string;
  weight: number;
}

const STOPWORDS = new Set([
  "static", "struct", "const", "return", "void", "unsigned", "signed", "while",
  "should", "would", "could", "value", "values", "field", "fields", "array",
  "index", "frame", "frames", "check", "checks", "validate", "bounds", "size",
  "length", "offset", "kernel", "driver", "function", "report", "finding",
]);

/**
 * Derive high-signal search terms from a query. Strong, low-noise terms first:
 * explicit symbols + file basenames (weight 3), explicit identifiers (weight 2),
 * then auto-mined snake_case identifiers and ALL_CAPS macros from the title
 * (weight 1). Generic stopwords are dropped so the grep stays selective.
 */
export function deriveSearchTerms(q: NoveltyQuery): Term[] {
  const byText = new Map<string, Term>();
  const add = (raw: string, weight: number): void => {
    const text = raw.trim();
    if (text.length < 4) return;
    if (STOPWORDS.has(text.toLowerCase())) return;
    const prev = byText.get(text.toLowerCase());
    if (!prev || prev.weight < weight) byText.set(text.toLowerCase(), { text, weight });
  };

  for (const s of q.symbols ?? []) add(s, 3);
  for (const f of q.files ?? []) add(f, 3);
  for (const id of q.identifiers ?? []) add(id, 2);

  // Auto-mine the title for snake_case identifiers, file basenames, and macros.
  for (const m of q.title.matchAll(/\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/g)) add(m[0], 1);
  for (const m of q.title.matchAll(/\b[\w.-]+\.[ch]\b/g)) add(m[0], 2);
  for (const m of q.title.matchAll(/\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b/g)) add(m[0], 1);

  return [...byText.values()].sort((a, b) => b.weight - a.weight || b.text.length - a.text.length);
}

/** Map a confirmed Finding onto a NoveltyQuery, auto-mining its prose. */
export function findingToQuery(finding: Finding, extra?: Partial<NoveltyQuery>): NoveltyQuery {
  const text = `${finding.title}\n${finding.description}`;
  const files = new Set(extra?.files ?? []);
  const symbols = new Set(extra?.symbols ?? []);
  const identifiers = new Set(extra?.identifiers ?? []);
  for (const m of text.matchAll(/\b[\w.-]+\.[ch]\b/g)) files.add(m[0]);
  for (const m of text.matchAll(/\b[a-z][a-z0-9]*(?:_[a-z0-9]+){1,}\b/g)) {
    // function-ish (3+ segments) → symbol, else identifier
    (m[0].split("_").length >= 3 ? symbols : identifiers).add(m[0]);
  }
  for (const m of text.matchAll(/\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b/g)) identifiers.add(m[0]);
  return {
    title: finding.title,
    files: [...files],
    symbols: [...symbols],
    identifiers: [...identifiers],
    excludeFrom: extra?.excludeFrom ?? OWN_FROM_MARKERS,
  };
}

// ── Candidate search ─────────────────────────────────────────────────────────

/** A candidate on-list email that matched the search. */
export interface LoreCandidate {
  list: string;
  epoch: number;
  commit: string;
  subject: string;
  from: string;
  date: string;
  messageId: string;
  /** Truncated raw message (headers + body + diff) for the judge. */
  body: string;
  /** Which query terms matched, and the summed weight (ranking). */
  matchedTerms: string[];
  score: number;
  /** True when `from` matches an excludeFrom marker (our own posting). */
  ours: boolean;
}

function chunk<T>(arr: T[], n: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += n) out.push(arr.slice(i, i + n));
  return out;
}

function parseHeader(msg: string, name: string): string {
  const re = new RegExp(`^${name}:[ \\t]*(.*(?:\\r?\\n[ \\t].*)*)`, "im");
  const m = msg.match(re);
  return m ? m[1].replace(/\r?\n[ \t]+/g, " ").trim() : "";
}

/**
 * Search one mirror epoch for candidate emails matching the terms. Greps the
 * blob `m` across every commit (chunked to stay under argv limits), builds a
 * commit→matchedTerms map, then ranks and hydrates the top `maxCandidates`.
 */
export async function searchLoreMirror(
  mirror: LoreMirror,
  terms: Term[],
  excludeFrom: string[],
  opts: { git: GitRunner; maxCandidates: number; bodyChars: number },
): Promise<LoreCandidate[]> {
  const { git } = opts;
  const revOut = await git(["rev-list", "--all"], { cwd: mirror.dir });
  const revs = revOut.split("\n").filter(Boolean);
  if (revs.length === 0) return [];

  // commit → matched terms (+ weight)
  const matches = new Map<string, { terms: Set<string>; score: number }>();
  for (const term of terms) {
    for (const batch of chunk(revs, 3000)) {
      const out = await git(
        ["grep", "-i", "-l", "-F", "-e", term.text, ...batch],
        { cwd: mirror.dir, timeoutMs: 120_000 },
      );
      for (const line of out.split("\n")) {
        if (!line) continue;
        const commit = line.split(":")[0];
        const entry = matches.get(commit) ?? { terms: new Set<string>(), score: 0 };
        if (!entry.terms.has(term.text)) {
          entry.terms.add(term.text);
          entry.score += term.weight;
        }
        matches.set(commit, entry);
      }
    }
  }

  const ranked = [...matches.entries()]
    .sort((a, b) => b[1].score - a[1].score || b[1].terms.size - a[1].terms.size)
    .slice(0, opts.maxCandidates);

  const candidates: LoreCandidate[] = [];
  for (const [commit, info] of ranked) {
    const msg = await git(["cat-file", "-p", `${commit}:m`], { cwd: mirror.dir });
    const from = parseHeader(msg, "From");
    const ours = excludeFrom.some((mark) => from.toLowerCase().includes(mark.toLowerCase()));
    candidates.push({
      list: mirror.list,
      epoch: mirror.epoch,
      commit,
      subject: parseHeader(msg, "Subject"),
      from,
      date: parseHeader(msg, "Date"),
      messageId: parseHeader(msg, "Message-ID").replace(/^<|>$/g, ""),
      body: msg.slice(0, opts.bodyChars),
      matchedTerms: [...info.terms],
      score: info.score,
      ours,
    });
  }
  return candidates;
}

// ── LLM judge ────────────────────────────────────────────────────────────────

/** Judge a finding against on-list candidate patches. Injectable for tests. */
export type NoveltyJudge = (
  query: NoveltyQuery,
  candidates: LoreCandidate[],
) => Promise<JudgeVerdict[]>;

export interface JudgeVerdict {
  messageId: string;
  subject: string;
  author: string;
  verdict: "DUPLICATE" | "RELATED" | "UNRELATED";
  why: string;
}

const JUDGE_SYSTEM =
  "You are a Linux kernel security maintainer doing duplicate triage. You are given ONE " +
  "vulnerability finding and several patches that were posted to a kernel mailing list. For EACH " +
  "candidate patch decide whether it fixes the SAME underlying bug as the finding:\n" +
  "  DUPLICATE  = the patch fixes the exact same vulnerability (same root-cause sink / same " +
  "unvalidated input reaching the same kind of unsafe operation). A core-side fix that covers the " +
  "finding's sink counts as a DUPLICATE even if it lives in a different file.\n" +
  "  RELATED    = same subsystem or bug class, but a DIFFERENT sink/root-cause that would NOT fix the finding.\n" +
  "  UNRELATED  = different bug entirely; it merely shares an identifier or filename.\n" +
  "Be strict: only say DUPLICATE when the patch would actually close the finding's bug. " +
  "Respond with ONLY a JSON object: " +
  '{"verdicts":[{"index":<int>,"verdict":"DUPLICATE|RELATED|UNRELATED","why":"<one sentence>"}]}.';

function buildJudgePrompt(query: NoveltyQuery, candidates: LoreCandidate[]): string {
  const parts: string[] = [];
  parts.push("FINDING:");
  parts.push(`  title: ${query.title}`);
  if (query.files?.length) parts.push(`  files: ${query.files.join(", ")}`);
  if (query.symbols?.length) parts.push(`  sink symbols: ${query.symbols.join(", ")}`);
  if (query.identifiers?.length) parts.push(`  key identifiers: ${query.identifiers.join(", ")}`);
  parts.push("");
  parts.push("CANDIDATE PATCHES:");
  candidates.forEach((c, i) => {
    parts.push(`--- candidate index ${i} ---`);
    parts.push(`subject: ${c.subject}`);
    parts.push(`from: ${c.from}`);
    parts.push(c.body);
    parts.push("");
  });
  return parts.join("\n");
}

function extractJson(text: string): unknown {
  let s = text.trim();
  const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fence) s = fence[1].trim();
  const start = s.indexOf("{");
  const end = s.lastIndexOf("}");
  if (start >= 0 && end > start) s = s.slice(start, end + 1);
  return JSON.parse(s);
}

/**
 * Live LLM judge over the engine's provider routing (chatgpt-codex / z-ai /
 * anthropic — auto-resolved from env; NO hardcoded keys). One batched call per
 * finding: the model sees all candidates together so it can compare.
 *
 * Reasoning models (gpt-5.x codex) occasionally return an EMPTY visible text
 * channel (the reasoning budget is consumed before any answer is emitted) — a
 * silent empty would mis-rule a real duplicate as NOVEL, which is the exact
 * failure this gate exists to prevent. So we RETRY on empty / unparseable
 * output (`attempts`, default 3) before giving up. A persistent empty returns
 * `[]` (→ treated as novel), which `checkNovelty` logs.
 */
export function makeLloreJudge(
  opts: { model?: string; timeoutMs?: number; attempts?: number } = {},
): NoveltyJudge {
  const attempts = Math.max(1, opts.attempts ?? 3);
  return async (query, candidates) => {
    if (candidates.length === 0) return [];
    const debug = !!process.env["0SEC_NOVELTY_DEBUG"];
    const runtime: NativeRuntime = new LlmApiRuntime({
      type: "api",
      timeout: opts.timeoutMs ?? 120_000,
      ...(opts.model ? { model: opts.model } : {}),
    });
    const prompt = buildJudgePrompt(query, candidates);

    type ParsedJudge = { verdicts?: Array<{ index?: number; verdict?: string; why?: string }> };
    let parsed: ParsedJudge | null = null;
    for (let attempt = 1; attempt <= attempts && !parsed; attempt++) {
      const result = await runtime.executeNative(
        JUDGE_SYSTEM,
        [{ role: "user", content: [{ type: "text", text: prompt }] }],
        [],
      );
      const text = result.content
        .filter((b): b is { type: "text"; text: string } => b.type === "text")
        .map((b) => b.text)
        .join("\n")
        .trim();
      if (debug) {
        // eslint-disable-next-line no-console
        console.error(`[novelty:judge] attempt ${attempt}/${attempts} stop=${result.stopReason} err=${result.error ?? ""} textLen=${text.length}`);
      }
      if (!text) continue; // empty visible channel — retry
      try {
        parsed = extractJson(text) as ParsedJudge;
      } catch (e) {
        if (debug) console.error(`[novelty:judge] attempt ${attempt} JSON parse failed: ${String(e)}`);
      }
    }
    if (!parsed) return [];

    const verdicts: JudgeVerdict[] = [];
    for (const v of parsed.verdicts ?? []) {
      const i = typeof v.index === "number" ? v.index : -1;
      const cand = candidates[i];
      if (!cand) continue;
      const verdict =
        v.verdict === "DUPLICATE" || v.verdict === "RELATED" ? v.verdict : "UNRELATED";
      verdicts.push({
        messageId: cand.messageId,
        subject: cand.subject,
        author: cand.from,
        verdict,
        why: v.why ?? "",
      });
    }
    return verdicts;
  };
}

// ── Public API ───────────────────────────────────────────────────────────────

export interface NoveltyCheckOptions {
  /** Already-synced epoch clones to search (use {@link syncLoreMirror} / {@link localMirrors}). */
  mirrors: LoreMirror[];
  /** Provider-routed LLM judge. Defaults to {@link makeLloreJudge}. */
  judge?: NoveltyJudge;
  git?: GitRunner;
  /** Max candidate emails per epoch sent to the judge. Default 8. */
  maxCandidates?: number;
  /** Body chars per candidate handed to the judge. Default 6000. */
  bodyChars?: number;
  log?: (msg: string) => void;
}

export interface DuplicateRef {
  subject: string;
  author: string;
  date: string;
  messageId: string;
  list: string;
  why: string;
}

export interface LoreNoveltyResult {
  novel: boolean;
  duplicates: DuplicateRef[];
  /** Candidates the judge ruled RELATED (same class, different sink) — context, not a block. */
  related: DuplicateRef[];
  /** How many candidate emails were searched/judged. */
  scanned: number;
}

/**
 * Decide whether a finding is NOVEL or a DUPLICATE of an on-list upstream fix.
 * Searches each mirror epoch for candidate patches, drops our own postings,
 * then LLM-judges the rest. DUPLICATE iff the judge confirms at least one
 * third-party candidate fixes the same bug.
 */
export async function checkNovelty(
  query: NoveltyQuery,
  opts: NoveltyCheckOptions,
): Promise<LoreNoveltyResult> {
  const git = opts.git ?? liveGit;
  const judge = opts.judge ?? makeLloreJudge();
  const log = opts.log ?? (() => {});
  const maxCandidates = opts.maxCandidates ?? 8;
  const bodyChars = opts.bodyChars ?? 6000;
  const excludeFrom = query.excludeFrom ?? OWN_FROM_MARKERS;
  const terms = deriveSearchTerms(query);

  if (terms.length === 0) {
    log("[novelty] no search terms derived — cannot dedup, treating as novel");
    return { novel: true, duplicates: [], related: [], scanned: 0 };
  }
  log(`[novelty] ${terms.length} term(s): ${terms.map((t) => t.text).join(", ")}`);

  const duplicates: DuplicateRef[] = [];
  const related: DuplicateRef[] = [];
  let scanned = 0;

  for (const mirror of opts.mirrors) {
    const all = await searchLoreMirror(mirror, terms, excludeFrom, { git, maxCandidates, bodyChars });
    const candidates = all.filter((c) => !c.ours);
    scanned += candidates.length;
    if (all.length > candidates.length) {
      log(`[novelty] ${mirror.list}#${mirror.epoch}: skipped ${all.length - candidates.length} of-our-own posting(s)`);
    }
    if (candidates.length === 0) continue;
    log(`[novelty] ${mirror.list}#${mirror.epoch}: judging ${candidates.length} candidate(s)`);

    const verdicts = await judge(query, candidates);
    const byMsgId = new Map(candidates.map((c) => [c.messageId, c]));
    for (const v of verdicts) {
      const cand = byMsgId.get(v.messageId);
      const ref: DuplicateRef = {
        subject: v.subject,
        author: v.author,
        date: cand?.date ?? "",
        messageId: v.messageId,
        list: mirror.list,
        why: v.why,
      };
      if (v.verdict === "DUPLICATE") duplicates.push(ref);
      else if (v.verdict === "RELATED") related.push(ref);
    }
  }

  const novel = duplicates.length === 0;
  log(
    novel
      ? `[novelty] NOVEL — no on-list patch fixes this bug (${scanned} candidate(s) examined)`
      : `[novelty] DUPLICATE — ${duplicates.length} on-list fix(es): ${duplicates.map((d) => d.messageId).join(", ")}`,
  );
  return { novel, duplicates, related, scanned };
}

/**
 * Hunt memory — a persistent, cross-session pattern DB so learnings from one
 * target inform the next.
 *
 * The idea is borrowed from claude-bug-bounty's `memory/` concept, but done as
 * a real engine store rather than a pile of markdown: findings and reusable
 * vuln patterns are recorded in a crash-safe, append-only JSONL log under the
 * per-user state dir, then queried across targets so "what have we
 * historically found for this vuln class / on similar assets" is a cheap
 * lookup at the start of the next hunt.
 *
 * ## On-disk layout
 *
 * ```
 * <homeStateDir()>/hunt-memory/            0700
 *   patterns.jsonl                         0600   one HuntRecord per line
 * ```
 *
 * The store never lives in the project tree — a repo may be a shared clone, a
 * bind mount, or world-readable, and a store of findings (which can quote
 * request/response fragments) must be none of those. Dir is 0700, file 0600.
 *
 * ## Crash-safety & totality
 *
 * Writes are plain appends (`appendFileSync`), so a concurrent writer can never
 * clobber another's record and a crash mid-append can at worst leave one
 * trailing partial line. On read every line is parsed independently inside a
 * `try/catch`; a corrupt or partial line is *skipped*, never thrown. A missing
 * store reads as empty. This is the same total-parse-on-corruption pattern used
 * by the craft-memory and hub stores.
 *
 * ## Redaction
 *
 * Every string that would be written to disk is first run through
 * {@link redactSecrets}, a redactor whose keyword set mirrors
 * `agent/sanitized-env.ts`'s `SENSITIVE_ENV_PATTERNS` (that const is not
 * exported, so the list is mirrored here with attribution — keep the two in
 * sync). Secrets never reach the disk: a `password=…`, `Authorization: Bearer …`,
 * an `AKIA…` key, or a PEM private-key block in an input is replaced with a
 * `<REDACTED>` marker before the record is serialized.
 *
 * ## Bounded growth
 *
 * After each append the store enforces two caps — a record count and a byte
 * budget — by dropping the oldest records (oldest-out rotation) and rewriting
 * the log atomically (compaction: temp file + rename). No unbounded growth.
 *
 * Deterministic given injected timestamps: nothing here reads a wall clock
 * unless the caller omits a timestamp, and `now`/`idFactory` are both
 * injectable for tests. No raw stdout — pure logic + fs.
 */

import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { homeStateDir } from "@0sec/shared";

/** Bumped when the on-disk record shape changes incompatibly. */
export const HUNT_MEMORY_SCHEMA_VERSION = 1;

export type HuntRecordKind = "finding" | "pattern";

export type HuntSeverity =
  | "info"
  | "low"
  | "medium"
  | "high"
  | "critical";

/**
 * One persisted unit of hunt knowledge.
 *
 * A `finding` is something concrete observed on a target ("reflected XSS in the
 * search box of shop.example"); a `pattern` is the reusable, target-agnostic
 * generalization ("this CMS ships a default admin route at /wp-json/…"). Both
 * share the shape so a single query surface spans them.
 */
export interface HuntRecord {
  /** Stable unique id. */
  id: string;
  /** Whether this is a concrete finding or a reusable pattern. */
  kind: HuntRecordKind;
  /**
   * Host / asset this pertains to (e.g. "shop.example.com", "10.0.0.5:8080",
   * or a repo slug). Normalized to lowercase for matching; "*" for a
   * target-agnostic pattern.
   */
  target: string;
  /** Vulnerability class, normalized lowercase (e.g. "sqli", "idor", "ssrf"). */
  vulnClass: string;
  /** One-line human title. */
  title: string;
  /** Longer prose: what it is, how it was reached, why it matters. */
  summary: string;
  /**
   * Pointer to where the full evidence lives (evidence-pack id, file path, a
   * content hash) — NOT the raw evidence itself. Kept small and redacted.
   */
  evidenceRef?: string;
  /** Severity, when known. */
  severity?: HuntSeverity;
  /** Free-form retrieval tags, normalized lowercase & de-duped. */
  tags: string[];
  /** Injected creation timestamp (ms since epoch). Used for recency & GC. */
  createdAt: number;
  /** Provenance: "scan:<id>", "manual", "import", "consolidation", … */
  source: string;
  /** On-disk schema version. */
  schemaVersion: number;
}

/** Fields a caller supplies to {@link HuntMemoryStore.append}. */
export interface HuntRecordInput {
  kind: HuntRecordKind;
  target: string;
  vulnClass: string;
  title: string;
  summary: string;
  evidenceRef?: string;
  severity?: HuntSeverity;
  tags?: string[];
  source: string;
  /**
   * Creation timestamp (ms). Passed in for determinism; when omitted the
   * store's injected `now()` is used.
   */
  createdAt?: number;
}

/** Query filter for {@link HuntMemoryStore.query}. */
export interface HuntQuery {
  /**
   * Restrict to this asset (case-insensitive). When omitted the query spans
   * every target — that is the cross-target "what have we found for this class
   * anywhere" lookup.
   */
  target?: string;
  /** When true, EXCLUDE `target` instead of restricting to it (learn from OTHER assets). */
  excludeTarget?: boolean;
  /** Restrict to this vuln class (case-insensitive). */
  vulnClass?: string;
  /** Records must carry ALL of these tags (case-insensitive). */
  tags?: string[];
  /** Restrict to a kind. */
  kind?: HuntRecordKind;
  /** Only records created at or after this timestamp (ms). */
  sinceTs?: number;
  /** Cap the number of results (most-recent-first). */
  limit?: number;
}

/** Aggregate stats accessor result. */
export interface HuntStats {
  total: number;
  byKind: Record<HuntRecordKind, number>;
  bySeverity: Record<string, number>;
  /** Record count per vuln class, descending. */
  byVulnClass: Record<string, number>;
  /** Distinct target count (excludes the "*" pattern pseudo-target). */
  distinctTargets: number;
  oldestTs: number | null;
  newestTs: number | null;
  /** Approximate on-disk size in bytes. */
  bytes: number;
}

export interface HuntMemoryOptions {
  /** Full path to the JSONL file. Overrides `home`. */
  path?: string;
  /** Home dir root; the store lives at `<home>/.0sec/hunt-memory/patterns.jsonl`. */
  home?: string;
  /** Max retained records before oldest-out rotation. Default 5000. */
  maxRecords?: number;
  /** Max on-disk bytes before oldest-out rotation. Default 4 MiB. */
  maxBytes?: number;
  /** Clock injection for the default createdAt. Default Date.now. */
  now?: () => number;
  /** Id factory injection (tests). Default randomUUID. */
  idFactory?: () => string;
}

// ───────────────────────────────────────────────────────────────────────────
// Redaction
// ───────────────────────────────────────────────────────────────────────────

/**
 * Mirror of `agent/sanitized-env.ts`'s `SENSITIVE_ENV_PATTERNS`. That const is
 * module-private there, so it is duplicated here rather than imported. These
 * are substrings that appear in the *name* of a credential; here they are used
 * to spot `NAME = value` / `NAME: value` shapes in free text and redact the
 * value. Keep this list in sync with sanitized-env.ts.
 */
const SENSITIVE_KEY_PATTERNS = [
  "TOKEN",
  "SECRET",
  "PASSWORD",
  "PASSWD",
  "PASSPHRASE",
  "CRED",
  "APIKEY",
  "API_KEY",
  "PRIVATE_KEY",
  "ACCESS_KEY",
  "SECRET_KEY",
  "_PAT",
  "SESSION_TOKEN",
  "AUTH_TOKEN",
  "BEARER",
  "AUTHORIZATION",
] as const;

/** The marker substituted for any redacted secret. */
export const HUNT_REDACTED = "<REDACTED>";

// A key made of the sensitive substrings, wrapped in optional surrounding
// word characters so `AWS_SECRET_ACCESS_KEY`, `my-api-key`, `github_pat` all
// match. Followed by an assignment (`=`, `:`, `=>`) and a quoted/bare value.
const KEY_VALUE_RE = new RegExp(
  String.raw`([\w.\-]*(?:${SENSITIVE_KEY_PATTERNS.join("|")})[\w.\-]*)` +
    String.raw`(\s*(?:[:=]|=>)\s*)` +
    String.raw`(["']?)([^\s"',;)}\]]+)\3`,
  "gi",
);

// Value-shaped secrets, matched regardless of any surrounding key.
const VALUE_SHAPE_RES: RegExp[] = [
  // PEM private key blocks (any label).
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  // HTTP bearer / basic credentials.
  /\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/\-]{8,}={0,2}/gi,
  // JSON Web Tokens.
  /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}/g,
  // AWS access key ids.
  /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b/g,
  // GitHub / GitLab / Slack style prefixed tokens.
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  // Generic "sk-"/"sk-ant-" style provider secret keys.
  /\bsk-(?:ant-)?[A-Za-z0-9_-]{16,}\b/g,
];

// URL userinfo: scheme://user:pass@host → strip the credentials.
const URL_USERINFO_RE = /([a-z][a-z0-9+.\-]*:\/\/)[^/\s:@]+:[^/\s:@]+@/gi;

/**
 * Redact secret-shaped substrings from `input` so nothing sensitive is ever
 * persisted. Conservative on the secret side (over-redaction is safe), but
 * deliberately does NOT touch bare long hex/base64 — evidence content hashes
 * are legitimate, high-value data we want to keep.
 */
export function redactSecrets(input: string): string {
  if (!input) return input;
  let out = input;
  for (const re of VALUE_SHAPE_RES) out = out.replace(re, HUNT_REDACTED);
  out = out.replace(URL_USERINFO_RE, `$1${HUNT_REDACTED}@`);
  out = out.replace(
    KEY_VALUE_RE,
    (_m, key: string, sep: string) => `${key}${sep}${HUNT_REDACTED}`,
  );
  return out;
}

// ───────────────────────────────────────────────────────────────────────────
// Normalization helpers
// ───────────────────────────────────────────────────────────────────────────

function normToken(s: string): string {
  return s.trim().toLowerCase();
}

function normTags(tags: string[] | undefined): string[] {
  if (!tags) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of tags) {
    const t = normToken(redactSecrets(String(raw)));
    if (t && !seen.has(t)) {
      seen.add(t);
      out.push(t);
    }
  }
  return out;
}

const DEFAULT_MAX_RECORDS = 5000;
const DEFAULT_MAX_BYTES = 4 * 1024 * 1024;

// ───────────────────────────────────────────────────────────────────────────
// Store
// ───────────────────────────────────────────────────────────────────────────

export class HuntMemoryStore {
  private readonly path: string;
  private readonly maxRecords: number;
  private readonly maxBytes: number;
  private readonly now: () => number;
  private readonly idFactory: () => string;

  private records: HuntRecord[] = [];
  private loaded = false;

  constructor(opts: HuntMemoryOptions = {}) {
    this.path = opts.path ?? huntMemoryPath(opts.home);
    this.maxRecords = opts.maxRecords ?? DEFAULT_MAX_RECORDS;
    this.maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
    this.now = opts.now ?? Date.now;
    this.idFactory = opts.idFactory ?? randomUUID;
  }

  // ── Loading ───────────────────────────────────────────────────────────────

  private ensureDir(): void {
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    try {
      chmodSync(dirname(this.path), 0o700);
    } catch {
      /* best-effort tightening */
    }
  }

  private ensureLoaded(): void {
    if (this.loaded) return;
    this.loaded = true;
    if (!existsSync(this.path)) {
      this.ensureDir();
      return;
    }
    let raw: string;
    try {
      raw = readFileSync(this.path, "utf8");
    } catch {
      return; // unreadable store reads as empty
    }
    for (const line of raw.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      const rec = parseRecord(t);
      if (rec) this.records.push(rec);
    }
  }

  // ── Writing ───────────────────────────────────────────────────────────────

  /**
   * Redact, normalize, assign an id, append to the JSONL log, and enforce the
   * growth caps. Returns the stored record. Never writes an unredacted string.
   */
  append(input: HuntRecordInput): HuntRecord {
    this.ensureLoaded();
    const record: HuntRecord = {
      id: this.idFactory(),
      kind: input.kind,
      target: normToken(redactSecrets(input.target)) || "*",
      vulnClass: normToken(redactSecrets(input.vulnClass)),
      title: redactSecrets(input.title),
      summary: redactSecrets(input.summary),
      ...(input.evidenceRef !== undefined
        ? { evidenceRef: redactSecrets(input.evidenceRef) }
        : {}),
      ...(input.severity !== undefined ? { severity: input.severity } : {}),
      tags: normTags(input.tags),
      createdAt: input.createdAt ?? this.now(),
      source: redactSecrets(input.source),
      schemaVersion: HUNT_MEMORY_SCHEMA_VERSION,
    };

    this.ensureDir();
    appendFileSync(this.path, JSON.stringify(record) + "\n", { mode: 0o600 });
    try {
      chmodSync(this.path, 0o600);
    } catch {
      /* best-effort */
    }
    this.records.push(record);
    this.enforceCaps();
    return record;
  }

  // ── Reading ───────────────────────────────────────────────────────────────

  /** Every retained record, insertion order (oldest first). */
  all(): HuntRecord[] {
    this.ensureLoaded();
    return [...this.records];
  }

  /**
   * Query the store. Results are returned most-recent-first (by createdAt, ties
   * broken by insertion order). With no `target`, the query spans every asset —
   * the cross-target lookup.
   */
  query(q: HuntQuery = {}): HuntRecord[] {
    this.ensureLoaded();
    const target = q.target !== undefined ? normToken(q.target) : undefined;
    const vulnClass = q.vulnClass !== undefined ? normToken(q.vulnClass) : undefined;
    const wantTags = q.tags ? q.tags.map(normToken).filter(Boolean) : [];

    const matched = this.records.filter((r) => {
      if (target !== undefined) {
        const isSame = r.target === target;
        if (q.excludeTarget ? isSame : !isSame) return false;
      }
      if (vulnClass !== undefined && r.vulnClass !== vulnClass) return false;
      if (q.kind !== undefined && r.kind !== q.kind) return false;
      if (q.sinceTs !== undefined && r.createdAt < q.sinceTs) return false;
      if (wantTags.length > 0 && !wantTags.every((t) => r.tags.includes(t))) {
        return false;
      }
      return true;
    });

    matched.sort(byRecencyDesc);
    return q.limit !== undefined ? matched.slice(0, Math.max(0, q.limit)) : matched;
  }

  /** The N most-recent records across all targets. */
  recent(limit = 20): HuntRecord[] {
    return this.query({ limit });
  }

  /**
   * Cross-target lookup: "what have we historically found for this vuln class
   * (and/or tags), regardless of asset". A convenience over {@link query} that
   * never restricts by target. When `excludeTarget` is given, results from that
   * asset are excluded so you learn from OTHER hunts only.
   */
  crossTarget(
    opts: {
      vulnClass?: string;
      tags?: string[];
      kind?: HuntRecordKind;
      excludeTarget?: string;
      sinceTs?: number;
      limit?: number;
    } = {},
  ): HuntRecord[] {
    return this.query({
      vulnClass: opts.vulnClass,
      tags: opts.tags,
      kind: opts.kind,
      sinceTs: opts.sinceTs,
      limit: opts.limit,
      ...(opts.excludeTarget !== undefined
        ? { target: opts.excludeTarget, excludeTarget: true }
        : {}),
    });
  }

  /** Aggregate statistics over the retained records. */
  stats(): HuntStats {
    this.ensureLoaded();
    const byKind: Record<HuntRecordKind, number> = { finding: 0, pattern: 0 };
    const bySeverity: Record<string, number> = {};
    const byVulnClass: Record<string, number> = {};
    const targets = new Set<string>();
    let oldestTs: number | null = null;
    let newestTs: number | null = null;

    for (const r of this.records) {
      byKind[r.kind] = (byKind[r.kind] ?? 0) + 1;
      const sev = r.severity ?? "unknown";
      bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
      byVulnClass[r.vulnClass] = (byVulnClass[r.vulnClass] ?? 0) + 1;
      if (r.target && r.target !== "*") targets.add(r.target);
      if (oldestTs === null || r.createdAt < oldestTs) oldestTs = r.createdAt;
      if (newestTs === null || r.createdAt > newestTs) newestTs = r.createdAt;
    }

    const sortedVulnClass = Object.fromEntries(
      Object.entries(byVulnClass).sort((a, b) => b[1] - a[1]),
    );

    return {
      total: this.records.length,
      byKind,
      bySeverity,
      byVulnClass: sortedVulnClass,
      distinctTargets: targets.size,
      oldestTs,
      newestTs,
      bytes: this.diskBytes(),
    };
  }

  // ── GC / compaction ─────────────────────────────────────────────────────────

  private diskBytes(): number {
    try {
      return statSync(this.path).size;
    } catch {
      return 0;
    }
  }

  /**
   * Drop oldest records until both the record-count and byte caps are met, then
   * rewrite the log. A no-op when already under both caps.
   */
  private enforceCaps(): void {
    let changed = false;

    if (this.records.length > this.maxRecords) {
      // Keep the newest maxRecords by createdAt; preserve insertion order.
      const ordered = [...this.records].sort(byRecencyDesc);
      const keep = new Set(ordered.slice(0, this.maxRecords));
      this.records = this.records.filter((r) => keep.has(r));
      changed = true;
    }

    if (this.diskBytes() > this.maxBytes) {
      // Rewrite first so diskBytes reflects the current in-memory set, then
      // trim oldest until under the byte budget.
      this.rewrite();
      const ordered = [...this.records].sort(byRecencyDesc);
      while (ordered.length > 0 && this.diskBytes() > this.maxBytes) {
        // Drop the oldest 5% (at least 1) per pass to converge quickly.
        const drop = Math.max(1, Math.floor(ordered.length * 0.05));
        ordered.splice(ordered.length - drop, drop);
        const keep = new Set(ordered);
        this.records = this.records.filter((r) => keep.has(r));
        this.rewrite();
      }
      return; // rewrite already flushed
    }

    if (changed) this.rewrite();
  }

  /**
   * Public compaction: rewrite the log from the in-memory set (dropping any
   * corrupt trailing lines that were skipped on load) and re-apply the caps.
   */
  compact(): void {
    this.ensureLoaded();
    this.rewrite();
    this.enforceCaps();
  }

  /** Atomically rewrite the whole log (temp file + rename). */
  private rewrite(): void {
    this.ensureDir();
    const body =
      this.records.map((r) => JSON.stringify(r)).join("\n") +
      (this.records.length ? "\n" : "");
    const tmp = `${this.path}.tmp-${process.pid}-${this.idFactory()}`;
    writeFileSync(tmp, body, { mode: 0o600 });
    try {
      chmodSync(tmp, 0o600);
    } catch {
      /* best-effort */
    }
    renameSync(tmp, this.path);
  }
}

// ───────────────────────────────────────────────────────────────────────────
// Free functions
// ───────────────────────────────────────────────────────────────────────────

/** Default on-disk path for the hunt-memory log. */
export function huntMemoryPath(home?: string): string {
  return join(homeStateDir(home), "hunt-memory", "patterns.jsonl");
}

function byRecencyDesc(a: HuntRecord, b: HuntRecord): number {
  return b.createdAt - a.createdAt;
}

/**
 * Parse one JSONL line into a HuntRecord, or null if it is malformed or missing
 * the required fields. Never throws — this is the totality guarantee.
 */
function parseRecord(line: string): HuntRecord | null {
  let obj: unknown;
  try {
    obj = JSON.parse(line);
  } catch {
    return null;
  }
  if (!obj || typeof obj !== "object") return null;
  const r = obj as Record<string, unknown>;
  if (
    typeof r.id !== "string" ||
    (r.kind !== "finding" && r.kind !== "pattern") ||
    typeof r.target !== "string" ||
    typeof r.vulnClass !== "string" ||
    typeof r.title !== "string" ||
    typeof r.summary !== "string" ||
    typeof r.source !== "string" ||
    typeof r.createdAt !== "number" ||
    !Number.isFinite(r.createdAt)
  ) {
    return null;
  }
  const tags = Array.isArray(r.tags)
    ? r.tags.filter((t): t is string => typeof t === "string")
    : [];
  return {
    id: r.id,
    kind: r.kind,
    target: r.target,
    vulnClass: r.vulnClass,
    title: r.title,
    summary: r.summary,
    ...(typeof r.evidenceRef === "string" ? { evidenceRef: r.evidenceRef } : {}),
    ...(isSeverity(r.severity) ? { severity: r.severity } : {}),
    tags,
    createdAt: r.createdAt,
    source: r.source,
    schemaVersion:
      typeof r.schemaVersion === "number" ? r.schemaVersion : HUNT_MEMORY_SCHEMA_VERSION,
  };
}

function isSeverity(v: unknown): v is HuntSeverity {
  return (
    v === "info" ||
    v === "low" ||
    v === "medium" ||
    v === "high" ||
    v === "critical"
  );
}

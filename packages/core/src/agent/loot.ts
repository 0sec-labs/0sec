/**
 * Loot / foothold ledger for opportunistic exploit chaining (0sec#567).
 *
 * Background — discovered secrets and footholds (credentials, tokens, cookies,
 * hashes, endpoints, sensitive paths) used to reach the attack agent only as
 * free-floating text inside one tool result. Once that message scrolled out of
 * the context window (or got compacted away), the artifact was effectively
 * gone, so multi-step exploit chains — "step 1 leaks a DB password, step 18
 * logs in with it" — only happened by luck within a single context window.
 * Chaining was prose-only: `racing.ts` literally told the model "Once you find
 * a foothold, chain it to maximum impact" with no structure behind it.
 *
 * This is the cheap, deterministic 80% — explicitly NOT EGATS tree-search
 * (that was tried, regressed, and is disabled by default; see
 * `agent/features.ts`). There is no new search layer here. A `LootLedger` is a
 * typed, deduped store that the EXISTING single agent loop writes to (from
 * `save_finding` and from evidence-bearing tool results) and reads from (a
 * compact "known footholds" block re-injected each turn, plus a `use_loot`
 * tool that returns full artifact values on demand). The ledger survives
 * compaction because it is re-rendered from structured state rather than
 * relying on the original tool-result message surviving in the window.
 *
 * Precision over recall: the harvest regexes target high-signal, labelled
 * shapes (JWTs, Bearer/Basic auth, `password=`, DB URIs, Set-Cookie, bcrypt /
 * shadow hashes, etc.). A single value is classified under exactly one kind
 * per harvest pass (priority order below) so a JWT isn't double-counted as a
 * token AND a hex hash, and the ledger is size-capped so one chatty response
 * can't flood the agent's context. False positives here cost a little context
 * budget, not a bad finding — but we still keep the net tight.
 */

import { randomUUID } from "node:crypto";

/**
 * Kind of captured artifact. Deliberately closed — these six cover the
 * footholds that actually drive web / app exploit chains. Anything that
 * doesn't fit is simply not harvested (better an honest miss than a
 * mislabelled artifact the agent then misuses).
 */
export type LootKind =
  | "credential"
  | "token"
  | "path"
  | "endpoint"
  | "hash"
  | "cookie";

export interface LootItem {
  /** Short stable id, e.g. `loot-3`. Stable for the lifetime of the ledger. */
  id: string;
  /** Internal UUID (kept for parity with Finding; not surfaced to the model). */
  uuid: string;
  kind: LootKind;
  /** The full artifact value (e.g. `admin:hunter2`, a JWT, `/etc/passwd`). */
  value: string;
  /** Where it came from: a tool name (`http_request`), `save_finding`, etc. */
  source: string;
  /** Short human-readable note — usually the label/key the value sat behind. */
  context?: string;
  /** Agent turn the artifact was captured on (when known). */
  turn?: number;
}

/** Options accepted when adding loot directly (harvest builds these). */
export interface LootInput {
  kind: LootKind;
  value: string;
  source: string;
  context?: string;
  turn?: number;
}

/** Filter passed to {@link LootLedger.query} / the `use_loot` tool. */
export interface LootQuery {
  kind?: LootKind;
  /** Case-insensitive substring matched against id, value, and context. */
  search?: string;
  id?: string;
}

// ── Tunables ──────────────────────────────────────────────────────────────

/** Hard cap on total ledger size — a chatty target can't flood the context. */
export const MAX_LOOT_ITEMS = 100;
/** Per-harvest cap so one giant tool result can't dominate a single turn. */
export const MAX_PER_HARVEST = 25;
/** Values longer than this are stored truncated (with a marker). */
export const MAX_LOOT_VALUE_LEN = 512;
/** In the injected block, values longer than this are previewed + truncated. */
const INJECT_VALUE_PREVIEW_LEN = 200;
/** Skip values shorter than this — too short to be a real secret. */
const MIN_VALUE_LEN = 3;

const TRUNCATION_MARKER = "…[truncated]";

// ── Harvest patterns ────────────────────────────────────────────────────────
//
// Processed in this order; the first kind to claim a given value wins, so a
// JWT captured as a `token` is never re-added as a `hash`. Each entry yields
// the captured artifact in group 1 (or group 0 when there's no explicit
// group). `context` is a short label derived from the surrounding key.

interface HarvestRule {
  kind: LootKind;
  regex: RegExp;
  /** Which capture group holds the value (default 1, 0 = whole match). */
  group?: number;
  /** Static context label, or a fn deriving it from the match. */
  context?: string | ((m: RegExpExecArray) => string | undefined);
}

const HARVEST_RULES: HarvestRule[] = [
  // ── tokens (most specific shapes first) ──
  // JWT — three base64url segments. Very high signal.
  { kind: "token", regex: /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b/g, group: 0, context: "jwt" },
  // Authorization: Bearer <token>
  { kind: "token", regex: /\bBearer\s+([A-Za-z0-9._~+/-]{12,}=*)/gi, context: "bearer token" },
  // AWS access key id
  { kind: "token", regex: /\bAKIA[0-9A-Z]{16}\b/g, group: 0, context: "aws access key id" },
  // GitHub PATs / tokens
  { kind: "token", regex: /\bgh[pousr]_[A-Za-z0-9]{20,255}\b/g, group: 0, context: "github token" },
  // Slack tokens
  { kind: "token", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, group: 0, context: "slack token" },
  // Labelled secrets: api_key=..., access_token: "...", client_secret=...
  {
    kind: "token",
    regex: /\b(?:api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|secret[_-]?key|client[_-]?secret|auth[_-]?token|x-api-key)\b["']?\s*[:=]\s*["']?([A-Za-z0-9._~+/-]{8,256})/gi,
    context: "api key/token",
  },

  // ── credentials ──
  // DB / service connection URIs with embedded user:pass@host
  {
    kind: "credential",
    regex: /\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|ftp|ssh|smtp):\/\/[^\s"'<>]+:[^\s"'<>@]+@[^\s"'<>]+/gi,
    group: 0,
    context: "connection string",
  },
  // Authorization: Basic <base64>
  { kind: "credential", regex: /\bBasic\s+([A-Za-z0-9+/]{8,}={0,2})/g, context: "basic auth" },
  // Labelled password fields: password=..., "passwd": "...", pwd=...
  {
    kind: "credential",
    regex: /\b(?:password|passwd|pwd|pass)\b["']?\s*[:=]\s*["']?([^\s"'&,;}{)\]]{3,128})/gi,
    context: "password",
  },
  // user:pass shorthand (e.g. `admin:hunter2`) — keep tight to avoid noise:
  // both sides word-ish; password side has no whitespace AND no `/`, so a URL
  // like `https://host/path` is NOT misread as a credential (URLs are captured
  // by the endpoint rule instead).
  {
    kind: "credential",
    regex: /\b([A-Za-z0-9._-]{2,64}:[^\s"'<>:@/]{3,128})\b/g,
    group: 1,
    context: "user:pass",
  },

  // ── cookies ──
  // Set-Cookie: name=value; ...  → capture the name=value pair only.
  { kind: "cookie", regex: /\bSet-Cookie:\s*([^\r\n;]+)/gi, context: "set-cookie" },
  // Common session cookie name=value pairs seen anywhere.
  {
    kind: "cookie",
    regex: /\b(PHPSESSID|JSESSIONID|connect\.sid|sessionid|session_id|session|csrftoken|XSRF-TOKEN|csrf_token|laravel_session|_session_id)=([^\s;"'&]+)/gi,
    group: 0,
    context: "session cookie",
  },

  // ── hashes ──
  // bcrypt
  { kind: "hash", regex: /\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}/g, group: 0, context: "bcrypt" },
  // Unix crypt (md5crypt/sha256crypt/sha512crypt): $1$ / $5$ / $6$
  { kind: "hash", regex: /\$[156]\$[^\s:"'<>]{8,}/g, group: 0, context: "unix crypt hash" },
  // Bare hex digests (md5/sha1/sha256). Lower signal — captured last so a
  // labelled token/secret already claimed the value first.
  { kind: "hash", regex: /\b[a-f0-9]{32}\b/gi, group: 0, context: "hex digest (md5?)" },
  { kind: "hash", regex: /\b[a-f0-9]{40}\b/gi, group: 0, context: "hex digest (sha1?)" },
  { kind: "hash", regex: /\b[a-f0-9]{64}\b/gi, group: 0, context: "hex digest (sha256?)" },

  // ── endpoints ──
  // Absolute URLs.
  { kind: "endpoint", regex: /\bhttps?:\/\/[^\s"'<>)\]]+/gi, group: 0, context: "url" },
  // API-ish absolute routes.
  {
    kind: "endpoint",
    regex: /(?:^|["'\s(])(\/(?:api|v\d+|graphql|rest|internal|oauth|admin)\/[^\s"'<>)\]]*)/gi,
    context: "api route",
  },

  // ── filesystem paths ──
  // Sensitive unix paths.
  { kind: "path", regex: /\/(?:etc|var|home|root|usr|opt|proc|srv)\/[^\s"'<>):;,]+/g, group: 0, context: "unix path" },
  // Sensitive file by extension, absolute.
  { kind: "path", regex: /\/[^\s"'<>):;,]*\.(?:env|pem|key|crt|conf|config|ini|sql|bak|log|htpasswd|kdbx)\b/gi, group: 0, context: "sensitive file" },
  // Windows paths.
  { kind: "path", regex: /\b[A-Za-z]:\\\\[^\s"'<>]+/g, group: 0, context: "windows path" },
];

/** Normalize a value for dedup / claim tracking. */
function dedupKey(kind: LootKind, value: string): string {
  return `${kind}::${value.trim().toLowerCase()}`;
}

/** Clamp a value to the storage cap, marking truncation. */
function clampValue(value: string): string {
  const v = value.trim();
  if (v.length <= MAX_LOOT_VALUE_LEN) return v;
  return v.slice(0, MAX_LOOT_VALUE_LEN) + TRUNCATION_MARKER;
}

/**
 * Typed store of reusable footholds. Single-scan lifetime; created by the
 * agent loop when `features.lootLedger` is on and threaded through
 * `ToolContext`.
 */
export class LootLedger {
  private items: LootItem[] = [];
  private seen = new Set<string>();
  private counter = 0;
  private _revision = 0;

  /** Number of stored artifacts. */
  get size(): number {
    return this.items.length;
  }

  /**
   * Monotonic revision — bumps on every successful add. The loop uses it to
   * decide whether the injected footholds block is stale and needs re-pushing.
   */
  get revision(): number {
    return this._revision;
  }

  /**
   * Add one artifact. Returns the stored item, or `null` if it was a duplicate,
   * empty/too-short, or the ledger is full. Dedup is by (kind, normalized
   * value); first write wins.
   */
  add(input: LootInput): LootItem | null {
    const value = (input.value ?? "").trim();
    if (value.length < MIN_VALUE_LEN) return null;
    if (this.items.length >= MAX_LOOT_ITEMS) return null;

    const stored = clampValue(value);
    const key = dedupKey(input.kind, stored);
    if (this.seen.has(key)) return null;
    this.seen.add(key);

    const item: LootItem = {
      id: `loot-${++this.counter}`,
      uuid: randomUUID(),
      kind: input.kind,
      value: stored,
      source: input.source,
      context: input.context,
      turn: input.turn,
    };
    this.items.push(item);
    this._revision += 1;
    return item;
  }

  /**
   * Scan free text (a tool result, an evidence blob) for footholds and add
   * any new ones. Returns the artifacts that were newly added (deduped). A
   * single value is classified under exactly one kind (priority order in
   * HARVEST_RULES) per call, so a JWT isn't also logged as a hex hash.
   */
  harvest(text: string, source: string, turn?: number): LootItem[] {
    if (!text || typeof text !== "string") return [];
    const added: LootItem[] = [];
    // Values claimed in THIS pass — prevents one substring landing under two
    // kinds (e.g. a Bearer JWT matching both the JWT rule and the bearer rule).
    const claimed = new Set<string>();

    for (const rule of HARVEST_RULES) {
      if (added.length >= MAX_PER_HARVEST) break;
      // Fresh lastIndex per rule (regexes are module-level + global/stateful).
      rule.regex.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = rule.regex.exec(text)) !== null) {
        if (added.length >= MAX_PER_HARVEST) break;
        // Guard against zero-width matches looping forever.
        if (m.index === rule.regex.lastIndex) rule.regex.lastIndex += 1;

        const raw = (rule.group === 0 ? m[0] : m[rule.group ?? 1]) ?? "";
        const value = raw.trim();
        if (value.length < MIN_VALUE_LEN) continue;

        const claimKey = value.toLowerCase();
        if (claimed.has(claimKey)) continue;

        const context =
          typeof rule.context === "function" ? rule.context(m) : rule.context;
        const item = this.add({ kind: rule.kind, value, source, context, turn });
        if (item) {
          claimed.add(claimKey);
          added.push(item);
        } else {
          // Already in the ledger (or full) — still mark claimed so a lower-
          // priority rule doesn't reclassify the same value this pass.
          claimed.add(claimKey);
        }
      }
    }
    return added;
  }

  /**
   * Harvest from a saved finding's evidence (0sec#567 — "populated by
   * save_finding"). Pulls from the request / response / analysis / description
   * blobs and labels the source so the injected block reads sensibly.
   */
  harvestFromFinding(
    finding: {
      evidence?: { request?: string; response?: string; analysis?: string };
      description?: string;
      category?: string;
    },
    turn?: number,
  ): LootItem[] {
    const parts = [
      finding.evidence?.request,
      finding.evidence?.response,
      finding.evidence?.analysis,
      finding.description,
    ].filter((s): s is string => typeof s === "string" && s.length > 0);
    if (parts.length === 0) return [];
    const source = `save_finding${finding.category ? `:${finding.category}` : ""}`;
    return this.harvest(parts.join("\n"), source, turn);
  }

  /** All stored artifacts, in capture order. */
  all(): readonly LootItem[] {
    return this.items;
  }

  /** Filtered view, for the `use_loot` tool. */
  query(q: LootQuery = {}): LootItem[] {
    const search = q.search?.trim().toLowerCase();
    return this.items.filter((it) => {
      if (q.kind && it.kind !== q.kind) return false;
      if (q.id && it.id !== q.id) return false;
      if (search) {
        const hay = `${it.id} ${it.value} ${it.context ?? ""}`.toLowerCase();
        if (!hay.includes(search)) return false;
      }
      return true;
    });
  }

  /**
   * Compact "known footholds" block injected into the agent's context. Values
   * that fit are shown in full so the model can reuse them directly; long ones
   * are previewed and the agent is told to `use_loot` for the full value. Pass
   * a `limit` to cap how many are rendered (most-recent-first).
   */
  render(opts: { limit?: number } = {}): string {
    if (this.items.length === 0) return "";
    const limit = opts.limit ?? this.items.length;
    // Most recent first — the freshest footholds are usually the relevant ones.
    const shown = [...this.items].slice(-limit).reverse();
    const omitted = this.items.length - shown.length;

    const lines = shown.map((it) => {
      const preview =
        it.value.length > INJECT_VALUE_PREVIEW_LEN
          ? `${it.value.slice(0, INJECT_VALUE_PREVIEW_LEN)}${TRUNCATION_MARKER}`
          : it.value;
      const ctx = it.context ? ` — ${it.context}` : "";
      const where = it.turn !== undefined ? `${it.source}, turn ${it.turn}` : it.source;
      return `- [${it.id}] ${it.kind}: ${preview} (${where})${ctx}`;
    });

    const header = [
      "## Known footholds (loot ledger)",
      "Artifacts captured earlier this scan. REUSE them to chain to higher impact —",
      "e.g. authenticate with a leaked credential, replay a session cookie, hit a",
      "discovered endpoint, or crack a captured hash. Call `use_loot` to fetch the",
      "full value of any item shown truncated below.",
    ].join("\n");

    const footer =
      omitted > 0 ? `\n…and ${omitted} more (call use_loot to list all).` : "";

    return `${header}\n${lines.join("\n")}${footer}`;
  }
}

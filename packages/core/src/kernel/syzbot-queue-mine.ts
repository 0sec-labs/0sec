/**
 * kernel/syzbot-queue-mine.ts
 *
 * SYZBOT INVALID / AUTO-CLOSED QUEUE MINING — a net-new bug-supply channel.
 *
 * Winners in the kernel-LPE game mine syzbot's DISCARDED reports (invalid /
 * no-repro / auto-closed / stuck-in-moderation) for real bugs everyone else
 * ignored. CVE-2023-52927 was won by writing a fresh reproducer from a
 * ~2-year-old syzbot report that carried no C-repro — exactly the "abandoned but
 * reproducible" shape this module surfaces. Our pipeline used none of this.
 *
 * SCOPE — ingestion + candidate-mapping ONLY:
 *   fetch syzbot bucket listing ──parse──> SyzbotCandidate[] ──rank/dedupe──>
 *     ──map──> HuntCandidate[] + HuntBrief  (hand-off to the EXISTING hunt-scan
 *              / kernel-vm repro path; the actual dynamic repro is bench-gated
 *              and NOT part of this module).
 *
 * The syzkaller dashboard (syzkaller.appspot.com) publishes bug listings as
 * plain HTML tables. The "invalid" bucket (`/<namespace>/invalid`) is the pool
 * of auto-closed / obsoleted / moderation-discarded reports. Each row carries:
 *   - a `/bug?extid=…` or `/bug?id=…` link (the syzbot id),
 *   - subsystem labels (`?label=subsystems:net`, …),
 *   - a Repro column ("C" | "syz" | empty),
 *   - Count / Last (days since last crash) / Reported columns, where the
 *     Reported link's mailing list (`syzkaller-upstream-moderation` vs
 *     `syzkaller-bugs`) tells us WHY it was discarded.
 *
 * Everything here is deterministic HTML parsing — no LLM, no raw keys. The
 * network is a single injected `fetch` function so tests run fully offline. Any
 * fetch/parse failure fails SOFT (empty + warning), never throwing the stage.
 */

import type { HuntBrief, HuntCandidate } from "../stages/hunt-scan.js";

// ── Contract ─────────────────────────────────────────────────────────────────

/** Injected HTML fetcher — one arg (url), returns the response body. Keeps the network out of tests. */
export type SyzbotFetcher = (url: string) => Promise<string>;

/** Which syzbot bucket a listing came from. "invalid" is the discarded pool this channel targets. */
export type SyzbotBucket = "invalid" | "fixed" | "open";

/** A single mined syzbot report, structured for triage/ranking. */
export interface SyzbotCandidate {
  /** The syzbot report id (the `extid` short hash, or the long `id` hash). */
  syzbotId: string;
  /** Which id form the dashboard used for this report. */
  idKind: "extid" | "id";
  /** Absolute URL to the bug detail page. */
  bugUrl: string;
  /** Report title, e.g. "KASAN: slab-use-after-free Read in qfq_reset_qdisc (2)". */
  title: string;
  /** Subsystem labels attached to the report (e.g. ["net"]). */
  subsystems: string[];
  /** Crash signature: the title with the trailing occurrence-count stripped. */
  crashSignature: string;
  /** Sanitizer / crash class parsed from the title (KASAN, KCSAN, BUG, WARNING, …), if recognizable. */
  crashType?: string;
  /** A C reproducer is available (the strongest, but also the least-abandoned). */
  hasCRepro: boolean;
  /** A syz reproducer is available (true whenever a C repro exists — C implies a syz program). */
  hasSyzRepro: boolean;
  /** Days since the report last crashed (from the "Last" column). Undefined for "never". */
  lastActivityDays?: number;
  /** Days since first reported (from the "Reported" column). */
  reportedDays?: number;
  /** Recorded crash count, if parseable. */
  crashCount?: number;
  /** Kernel version last seen crashing — only populated when detail-enriched. */
  kernelVersionSeen?: string;
  /** Exact syz reproducer URL discovered on the detail page. */
  reproSyzUrl?: string;
  /** Syzkaller sandbox requested by the reproducer options header. */
  reproSandbox?: string;
  /** Harness/setup features requested by the syz reproducer. */
  reproFeatures?: string[];
  /** Conservative reachability classification; never an exploitability claim. */
  reachability?: "zero-cap-plausible" | "privileged-or-harness" | "unknown";
  /** Adversarial reasons to avoid spending VM/reproduction budget. */
  triageWarnings?: string[];
  /** Whether bounded detail/repro enrichment succeeded. */
  enrichmentStatus?: "verified" | "failed" | "not-fetched";
  /** The bucket this candidate came from. */
  bucket: SyzbotBucket;
  /** Best-effort human explanation of why syzbot discarded it. */
  whyDiscarded: string;
  /** The ranking score assigned by {@link rankCandidates} (higher = more promising). */
  score: number;
}

export interface SyzbotQueueMineOptions {
  /** Injected fetcher. Required — supply `defaultSyzbotFetcher` in prod, a fixture fn in tests. */
  fetch: SyzbotFetcher;
  /** Dashboard namespace. Default "upstream". */
  namespace?: string;
  /** Which discarded buckets to mine. Default ["invalid"]. */
  buckets?: SyzbotBucket[];
  /**
   * Keep only reports touching these subsystem labels (case-insensitive). Pass
   * an empty array to disable filtering. Default: the winning surfaces from the
   * LPE-hunt upgrade plan (net/sched, net/tls, xfrm, crypto, vsock).
   */
  subsystems?: string[];
  /** Cap on candidates returned after ranking. Default 50. */
  limit?: number;
  /** Dashboard base URL. Default "https://syzkaller.appspot.com". */
  baseUrl?: string;
  /**
   * OPTIONAL per-bug detail fetch to fill `kernelVersionSeen`. Off by default
   * (the listing alone yields 8 of the 9 candidate fields). When provided, the
   * top-ranked candidates' detail pages are fetched (up to `maxDetailFetches`)
   * and parsed for the latest kernel version seen. Per-bug failures are
   * swallowed — a candidate keeps its listing data.
   */
  fetchDetail?: SyzbotFetcher;
  /** Optional fetcher for exact syz repro programs linked by detail pages. */
  fetchRepro?: SyzbotFetcher;
  /** Cost guard on detail fetches. Default 20. */
  maxDetailFetches?: number;
  /** Delay between live detail/repro requests to avoid dashboard throttling. Default 0. */
  detailDelayMs?: number;
  log?: (msg: string) => void;
}

export interface SyzbotQueueMineResult {
  /** Ranked, deduped, subsystem-filtered candidates (capped at `limit`). */
  candidates: SyzbotCandidate[];
  /** A channel-level hunt brief describing the "abandoned syzbot report" bug class. */
  brief: HuntBrief;
  /** Total rows parsed across all fetched buckets (before filtering). */
  scanned: number;
  warnings: string[];
}

function boundedInteger(value: number | undefined, fallback: number, min: number, max: number, name: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < min || resolved > max) {
    throw new Error(`invalid ${name}: expected integer ${min}..${max}`);
  }
  return resolved;
}

/**
 * Winning surfaces from the LPE-hunt upgrade plan (#0). `net` is deliberately
 * broad — net/sched, net/tls and most netlink bugs label as `net` on syzbot —
 * so it captures the sched/tls targets even though they have no distinct label.
 */
export const DEFAULT_TARGET_SUBSYSTEMS = [
  "net",
  "sched",
  "tls",
  "xfrm",
  "crypto",
  "vsock",
] as const;

const DEFAULT_BASE_URL = "https://syzkaller.appspot.com";

/** Map a syzbot subsystem label to a kernel-source path hint for the finder. Falls back to the label itself. */
const SUBSYSTEM_SOURCE_HINT: Record<string, string> = {
  net: "net",
  sched: "net/sched",
  tls: "net/tls",
  xfrm: "net/xfrm",
  crypto: "crypto",
  vsock: "net/vmw_vsock",
  tipc: "net/tipc",
  kcm: "net/kcm",
  bpf: "kernel/bpf",
  mm: "mm",
  fs: "fs",
  kernel: "kernel",
};

// ── Listing parser (deterministic HTML) ──────────────────────────────────────

/** Strip HTML tags and collapse whitespace to a trimmed plain-text string. */
function textOf(html: string): string {
  return html
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&#34;/g, '"')
    .replace(/&quot;/g, '"')
    .replace(/\s+/g, " ")
    .trim();
}

/** Split the `list_table` body into individual `<tr>…</tr>` row bodies. */
function extractRows(html: string): string[] {
  const tableStart = html.indexOf('class="list_table"');
  const table = tableStart >= 0 ? html.slice(tableStart) : html;
  const rows: string[] = [];
  const re = /<tr\b[^>]*>([\s\S]*?)<\/tr>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(table)) !== null) rows.push(m[1]);
  return rows;
}

/** Ordered list of `<td>` inner-HTML for a row. */
function extractCells(row: string): string[] {
  const cells: string[] = [];
  const re = /<td\b[^>]*>([\s\S]*?)<\/td>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(row)) !== null) cells.push(m[1]);
  return cells;
}

/** "56d" → 56; "3h" → 0; "never"/"" → undefined. */
function parseDays(raw: string): number | undefined {
  const s = raw.trim();
  const dm = s.match(/^(\d+)d$/);
  if (dm) return Number(dm[1]);
  if (/^\d+h$/.test(s)) return 0;
  const nm = s.match(/^(\d+)$/); // some columns render bare day counts
  if (nm) return Number(nm[1]);
  return undefined;
}

const CRASH_TYPE_RE =
  /\b(KASAN|KCSAN|KMSAN|UBSAN|BUG|WARNING|INFO|general protection fault|kernel BUG|possible deadlock|inconsistent lock state)\b/i;

/** Parse a single listing row into a candidate. Returns null for header/blank/unparseable rows. */
export function parseListingRow(
  row: string,
  bucket: SyzbotBucket,
  baseUrl: string = DEFAULT_BASE_URL,
): SyzbotCandidate | null {
  if (!/class="title"/.test(row)) return null;

  const idMatch = row.match(/href="\/bug\?(extid|id)=([0-9a-f]+)"/i);
  if (!idMatch) return null;
  const idKind = idMatch[1].toLowerCase() as "extid" | "id";
  const syzbotId = idMatch[2];
  const bugUrl = `${baseUrl}/bug?${idKind}=${syzbotId}`;

  // Title = text of the first /bug link anchor.
  const titleAnchor = row.match(
    /<a\b[^>]*href="\/bug\?(?:extid|id)=[0-9a-f]+"[^>]*>([\s\S]*?)<\/a>/i,
  );
  const title = titleAnchor ? textOf(titleAnchor[1]) : "";
  if (!title) return null;

  // Subsystem labels: <a ... label=subsystems%3ANAME ...>. Skip prio:/other labels.
  const subsystems: string[] = [];
  const subRe = /label=subsystems(?:%3A|:)([^"&]+)/gi;
  let sm: RegExpExecArray | null;
  while ((sm = subRe.exec(row)) !== null) {
    const name = decodeURIComponent(sm[1]).trim().toLowerCase();
    if (name && !subsystems.includes(name)) subsystems.push(name);
  }

  const cells = extractCells(row).map(textOf);

  // Repro cell is the one whose text is exactly "C" or "syz" — a robust,
  // position-independent marker (no other listing cell carries those tokens).
  const reproCell = cells.find((c) => c === "C" || c === "syz");
  const hasCRepro = reproCell === "C";
  const hasSyzRepro = reproCell === "C" || reproCell === "syz";

  // Locate the "Reported" cell = the one carrying the mailing-list link; "Last"
  // is the cell immediately before it, "Count" two before. This survives the
  // small column-layout differences between buckets.
  const rawCells = extractCells(row);
  const reportedRaw = rawCells.findIndex((c) => /groups\.google\.com/.test(c));
  let lastActivityDays: number | undefined;
  let reportedDays: number | undefined;
  let crashCount: number | undefined;
  let whyDiscarded = `syzbot ${bucket} bucket`;
  if (reportedRaw >= 0) {
    lastActivityDays = parseDays(cells[reportedRaw - 1] ?? "");
    reportedDays = parseDays(textOf(rawCells[reportedRaw] ?? ""));
    const cnt = Number((cells[reportedRaw - 2] ?? "").trim());
    if (Number.isFinite(cnt) && cnt > 0) crashCount = cnt;
    const listUrl = rawCells[reportedRaw];
    if (/syzkaller-upstream-moderation/.test(listUrl)) {
      whyDiscarded =
        "moderation queue: auto-discarded as low-priority, never escalated to the public bug list";
    } else if (/syzkaller-bugs/.test(listUrl)) {
      whyDiscarded =
        "closed invalid: reported publicly, then auto-obsoleted (stopped reproducing / no repro)";
    }
  }

  const crashSignature = title.replace(/\s*\(\d+\)\s*$/, "").trim();
  const crashType = title.match(CRASH_TYPE_RE)?.[1];

  return {
    syzbotId,
    idKind,
    bugUrl,
    title,
    subsystems,
    crashSignature,
    ...(crashType ? { crashType } : {}),
    hasCRepro,
    hasSyzRepro,
    ...(lastActivityDays !== undefined ? { lastActivityDays } : {}),
    ...(reportedDays !== undefined ? { reportedDays } : {}),
    ...(crashCount !== undefined ? { crashCount } : {}),
    bucket,
    whyDiscarded,
    score: 0,
  };
}

/** Parse a full bucket listing page into candidates. Never throws. */
export function parseListing(
  html: string,
  bucket: SyzbotBucket,
  baseUrl: string = DEFAULT_BASE_URL,
): SyzbotCandidate[] {
  const out: SyzbotCandidate[] = [];
  for (const row of extractRows(html)) {
    try {
      const c = parseListingRow(row, bucket, baseUrl);
      if (c) out.push(c);
    } catch {
      /* one bad row must not sink the page */
    }
  }
  return out;
}

/** Parse a bug DETAIL page for the latest kernel version it was seen crashing on. */
export function parseBugDetailKernelVersion(html: string): string | undefined {
  const versions = new Set<string>();
  const re = /\b([456]\.\d{1,2}(?:\.\d{1,3})?(?:-rc\d+)?)\b/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) versions.add(m[1]);
  if (versions.size === 0) return undefined;
  // Return the highest (latest) version by numeric major/minor/patch compare.
  const cmp = (v: string): number[] => {
    const base = v.replace(/-rc\d+$/, "");
    return base.split(".").map((n) => Number(n));
  };
  return [...versions].sort((a, b) => {
    const [aa, bb] = [cmp(a), cmp(b)];
    for (let i = 0; i < 3; i++) {
      const d = (bb[i] ?? 0) - (aa[i] ?? 0);
      if (d) return d;
    }
    return 0;
  })[0];
}

export interface SyzbotDetailMetadata {
  kernelVersionSeen?: string;
  reproSyzUrl?: string;
}

/** Extract bounded triage metadata from a syzbot detail page. */
export function parseBugDetail(
  html: string,
  baseUrl: string = DEFAULT_BASE_URL,
): SyzbotDetailMetadata {
  const kernelVersionSeen = parseBugDetailKernelVersion(html);
  const match = html.match(/href="([^"]*\/text\?tag=ReproSyz(?:&amp;|&)x=[0-9a-f]+)"/i);
  let reproSyzUrl: string | undefined;
  if (match) {
    try {
      reproSyzUrl = new URL(match[1].replace(/&amp;/g, "&"), `${baseUrl}/`).toString();
    } catch {
      // Malformed untrusted HTML is ignored.
    }
  }
  return { ...(kernelVersionSeen ? { kernelVersionSeen } : {}), ...(reproSyzUrl ? { reproSyzUrl } : {}) };
}

const REPRO_SETUP_FEATURES = [
  "tun", "netdev", "resetnet", "cgroups", "binfmt_misc", "usb", "vhci",
  "wifi", "ieee802154", "sysctl", "tmpdir", "fault", "swap",
] as const;

/** Parse only the JSON options header of a syzkaller program. */
export function parseSyzReproOptions(program: string): {
  sandbox?: string;
  features: string[];
  reachability: "zero-cap-plausible" | "privileged-or-harness" | "unknown";
  warnings: string[];
} {
  const header = program.slice(0, 16_384).match(/^#(\{[^\n]+\})$/m)?.[1];
  if (!header) return { features: [], reachability: "unknown", warnings: ["missing syz options header"] };
  let options: Record<string, unknown>;
  try {
    options = JSON.parse(header) as Record<string, unknown>;
  } catch {
    return { features: [], reachability: "unknown", warnings: ["invalid syz options header"] };
  }
  const sandbox = typeof options.sandbox === "string" ? options.sandbox : undefined;
  const features: string[] = REPRO_SETUP_FEATURES.filter((name) => options[name] === true);
  // The options header does not capture all setup performed by the program.
  // Conservatively recognize calls that need host capabilities, synthetic
  // devices, or fault-injection support on the target distro.
  const body = program.slice(0, 2 * 1024 * 1024);
  const callFeatures: Array<[string, RegExp]> = [
    ["mount", /\b(?:syz_mount_image|mount\$|fsopen\$|fsmount\$)/],
    ["tun-device", /\/dev\/net\/tun|TUNSETIFF/],
    ["net-admin", /RTM_NEW(?:QDISC|LINK|TFILTER|TCLASS)|rtnetlink\$(?:newlink|newqdisc)/i],
    ["xfrm-admin", /XFRM_MSG_NEW|netlink\$xfrm/i],
    ["vhci", /syz_emit_vhci|\/dev\/vhci/i],
    ["usb", /syz_usb_(?:connect|control_io)|\/dev\/raw-gadget/i],
    ["bpf", /\bbpf\$/],
    ["fault-injection", /\(fail_nth:\s*\d+\)/],
  ];
  for (const [name, pattern] of callFeatures) {
    if (pattern.test(body) && !features.includes(name)) features.push(name);
  }
  const privilegedFeatures = features.filter((name) =>
    [
      "tun", "netdev", "resetnet", "usb", "vhci", "wifi", "ieee802154", "sysctl", "fault", "swap",
      "mount", "tun-device", "net-admin", "xfrm-admin", "bpf", "fault-injection",
    ].includes(name),
  );
  const warnings: string[] = [];
  if (sandbox === "none" || sandbox === "") {
    warnings.push(`reproducer requires ${sandbox === "none" ? "sandbox:none" : "an empty/unsandboxed mode"}`);
  }
  if (privilegedFeatures.length > 0) warnings.push(`harness setup: ${privilegedFeatures.join(", ")}`);
  const privileged = sandbox === "none" || sandbox === "" || privilegedFeatures.length > 0;
  const reachability = privileged
    ? "privileged-or-harness"
    : sandbox === "namespace"
      ? "zero-cap-plausible"
      : "unknown";
  return { ...(sandbox ? { sandbox } : {}), features, reachability, warnings };
}

// ── Ranking ──────────────────────────────────────────────────────────────────

/**
 * Rank candidates. Preference order (per the upgrade plan):
 *   1. syz-repro but NO C-repro — "weaponizable but abandoned" (the CVE-2023-52927
 *      shape). Highest weight: everyone already acts on C-repro bugs.
 *   2. any reproducer at all beats none.
 *   3. a target subsystem.
 *   4. memory-corruption geometry beats warnings/lockdep noise.
 *   5. penalize mixed filesystem/device labels: they often mean a privileged
 *      mount or emulated-device bug corrupted a later networking victim.
 *   6. recent-ish activity (a bug last seen recently is more likely still live).
 * Sorted descending by score; ties broken toward the more recently-active bug.
 */
export function rankCandidates(
  candidates: SyzbotCandidate[],
  targetSubsystems: readonly string[] = DEFAULT_TARGET_SUBSYSTEMS,
): SyzbotCandidate[] {
  const targets = new Set(targetSubsystems.map((s) => s.toLowerCase()));
  const scored = candidates.map((c) => {
    let score = 0;
    if (c.hasSyzRepro && !c.hasCRepro) score += 100; // abandoned-but-reproducible
    else if (c.hasSyzRepro) score += 40; // has a (C) repro
    if (c.subsystems.some((s) => targets.has(s))) score += 20;
    const title = c.title.toLowerCase();
    if (/kasan:.*use-after-free/.test(title)) score += 35;
    if (/\bwrite\b/.test(title) && /(use-after-free|out-of-bounds|corrupt)/.test(title)) score += 20;
    if (/(slab-|heap-|global-)?out-of-bounds/.test(title)) score += 15;
    if (/corrupted list|list corruption/.test(title)) score += 20;
    if (/general protection fault|kernel paging request/.test(title)) score += 10;
    if (/^warning|lockdep|possible deadlock|rcu detected stall/.test(title)) score -= 25;
    if (/^info:/.test(title)) score -= 35;
    if (/^kmsan:|memory leak|uninit-value|null-ptr-deref/.test(title)) score -= 60;

    const labels = new Set(c.subsystems.map((s) => s.toLowerCase()));
    const privilegedOrigins = ["ext4", "bcachefs", "f2fs", "xfs", "btrfs", "ntfs3", "usb"];
    if (privilegedOrigins.some((s) => labels.has(s))) score -= 35;
    if ((c.reportedDays ?? 0) > 730) score -= 40;
    else if ((c.reportedDays ?? 0) > 365) score -= 20;
    if (c.lastActivityDays !== undefined) {
      // Up to +20, decaying over a year; recent activity ranks higher.
      score += Math.max(0, Math.round((365 - Math.min(c.lastActivityDays, 365)) / 365 * 20));
    }
    if (c.crashCount === 1) score -= 25;
    if (c.reachability === "privileged-or-harness") score -= 80;
    else if (c.reachability === "zero-cap-plausible") score += 20;
    if (c.enrichmentStatus === "failed") score -= 25;
    else if (c.enrichmentStatus === "not-fetched") score -= 35;
    else if (c.enrichmentStatus === "verified" && c.reachability === "unknown") score -= 15;
    if (c.reproFeatures?.includes("fault")) score -= 30;
    return { ...c, score };
  });
  return scored.sort(
    (a, b) =>
      b.score - a.score ||
      (a.lastActivityDays ?? Infinity) - (b.lastActivityDays ?? Infinity),
  );
}

// ── Hand-off to hunt-scan / kernel repro path ────────────────────────────────

/** The channel-level hunt brief describing the "abandoned syzbot report" bug class. */
export function syzbotQueueBrief(): HuntBrief {
  return {
    bugClass:
      "abandoned syzbot report (invalid / moderation / no-repro / auto-closed) — a real sanitizer crash everyone ignored",
    pattern:
      "syzbot recorded a KASAN/KCSAN/BUG crash then auto-closed it as invalid or left it stuck in moderation; the underlying bug may still be live. Re-derive a reproducer from the report and confirm — do not trust syzbot's 'invalid' verdict.",
    fixReference: "syzbot invalid-queue mining (LPE-hunt upgrade #0)",
  };
}

/** Map a mined candidate to a hunt-scan {@link HuntCandidate} for the finder / repro path. */
export function toHuntCandidate(c: SyzbotCandidate): HuntCandidate {
  const primary = c.subsystems.find((s) => SUBSYSTEM_SOURCE_HINT[s]);
  // Remote dashboard labels are untrusted and must never become filesystem paths.
  const path = primary ? SUBSYSTEM_SOURCE_HINT[primary] : ".";
  const repro = c.hasCRepro
    ? "C-repro available"
    : c.hasSyzRepro
      ? "syz-repro only (no C-repro — abandoned but reproducible)"
      : "no repro (write one from the crash)";
  const hint =
    `Reproduce this ABANDONED syzbot report from source. ` +
    `syzbot-id=${c.syzbotId} (${c.bucket}). Crash: ${c.crashSignature}. ` +
    `Repro: ${repro}. Why discarded: ${c.whyDiscarded}. ` +
    `Detail: ${c.bugUrl}. Find the underlying bug and write a fresh reproducer; ` +
    `do NOT assume the syzbot 'invalid' verdict is correct.`;
  return { path, hint };
}

/** Map a whole result set to hunt-scan candidates. */
export function toHuntCandidates(result: SyzbotQueueMineResult): HuntCandidate[] {
  return result.candidates.map(toHuntCandidate);
}

// ── Default fetcher ──────────────────────────────────────────────────────────

/** The only host this stage is ever allowed to reach (SSRF guard). */
export const SYZBOT_ALLOWED_HOST = "syzkaller.appspot.com";
const MAX_SYZBOT_RESPONSE_BYTES = 16 * 1024 * 1024;

async function readBoundedResponse(res: Response, url: string): Promise<string> {
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_SYZBOT_RESPONSE_BYTES) {
    throw new Error(`oversized syzbot response for ${url}`);
  }
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_SYZBOT_RESPONSE_BYTES) {
        await reader.cancel("response exceeds 0sec size limit");
        throw new Error(`oversized syzbot response for ${url}`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(body);
}

function retryDelayMs(res: Response): number {
  const retryAfter = res.headers.get("retry-after");
  const seconds = retryAfter && /^\d+$/.test(retryAfter) ? Number(retryAfter) : 1;
  return Math.min(Math.max(seconds * 1_000, 250), 5_000);
}

/** Production fetcher over global `fetch` (Node ≥18). Not used by tests. */
export const defaultSyzbotFetcher: SyzbotFetcher = async (url) => {
  // SSRF guard: only ever fetch the syzkaller dashboard over https. The URL is
  // assembled from caller-supplied namespace/bucket, so validate the resolved
  // host against a fixed allowlist before any outbound request.
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`invalid syzbot url: ${url}`);
  }
  if (parsed.protocol !== "https:" || parsed.hostname !== SYZBOT_ALLOWED_HOST || parsed.port || parsed.username || parsed.password) {
    throw new Error(
      `refusing to fetch non-allowlisted url (host must be ${SYZBOT_ALLOWED_HOST} over https): ${url}`,
    );
  }
  for (let attempt = 0; attempt < 2; attempt++) {
    const res = await fetch(parsed.toString(), {
      headers: { "user-agent": "0sec-syzbot-queue-mine/1.0" },
      redirect: "manual",
      // The invalid listing is ~19k rows and can take tens of seconds from the
      // public dashboard; remain bounded without making the live source unusable.
      signal: AbortSignal.timeout(60_000),
    });
    if (res.status >= 300 && res.status < 400) {
      throw new Error(`refusing syzbot redirect for ${url}`);
    }
    if (res.status === 429 && attempt === 0) {
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs(res)));
      continue;
    }
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
    return readBoundedResponse(res, url);
  }
  throw new Error(`HTTP 429 for ${url}`);
};

// ── Stage entry point ────────────────────────────────────────────────────────

/**
 * Mine syzbot's discarded buckets into ranked, deduped hunt candidates.
 *
 * Best-effort + resilient: a fetch/parse failure on any bucket adds a warning
 * and is skipped — the stage never throws. Candidates are deduped by syzbot id,
 * subsystem-filtered, ranked, and capped at `limit`. Optional detail enrichment
 * fills detail/repro reachability metadata for the top candidates, then reranks.
 */
export async function mineSyzbotQueue(
  opts: SyzbotQueueMineOptions,
): Promise<SyzbotQueueMineResult> {
  const log = opts.log ?? (() => {});
  const namespace = opts.namespace ?? "upstream";
  const buckets = opts.buckets && opts.buckets.length > 0 ? opts.buckets : (["invalid"] as SyzbotBucket[]);
  const baseUrl = (opts.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
  const subsystems =
    opts.subsystems !== undefined ? opts.subsystems : [...DEFAULT_TARGET_SUBSYSTEMS];
  const limit = boundedInteger(opts.limit, 50, 1, 500, "limit");
  const maxDetail = boundedInteger(opts.maxDetailFetches, 20, 0, 100, "maxDetailFetches");
  const detailDelayMs = boundedInteger(opts.detailDelayMs, 0, 0, 5_000, "detailDelayMs");
  const warnings: string[] = [];

  // Fetch + parse each bucket independently; one failure never sinks the rest.
  const parsed: SyzbotCandidate[] = [];
  let scanned = 0;
  for (const bucket of buckets) {
    const url = `${baseUrl}/${namespace}/${bucket}`;
    let html: string;
    try {
      html = await opts.fetch(url);
    } catch (e) {
      warnings.push(`syzbot: fetch failed for ${url}: ${String(e).slice(0, 120)}`);
      continue;
    }
    let rows: SyzbotCandidate[];
    try {
      rows = parseListing(html, bucket, baseUrl);
    } catch (e) {
      warnings.push(`syzbot: parse failed for ${url}: ${String(e).slice(0, 120)}`);
      continue;
    }
    scanned += rows.length;
    parsed.push(...rows);
    log(`[syzbot] ${url} → ${rows.length} row(s)`);
  }

  // Dedupe by syzbot id (keep the first, richer occurrence).
  const byId = new Map<string, SyzbotCandidate>();
  for (const c of parsed) if (!byId.has(c.syzbotId)) byId.set(c.syzbotId, c);
  let candidates = [...byId.values()];
  candidates = candidates.map((c) => ({ ...c, enrichmentStatus: "not-fetched" as const }));

  // Subsystem filter (empty array disables it).
  if (subsystems.length > 0) {
    const targets = new Set(subsystems.map((s) => s.toLowerCase()));
    candidates = candidates.filter((c) => c.subsystems.some((s) => targets.has(s)));
  }

  // Rank, then cap.
  candidates = rankCandidates(candidates, subsystems.length > 0 ? subsystems : DEFAULT_TARGET_SUBSYSTEMS);
  candidates = candidates.slice(0, limit);

  // Optional detail enrichment for the top candidates.
  if (opts.fetchDetail) {
    let fetched = 0;
    for (const c of candidates) {
      if (fetched >= maxDetail) break;
      if (fetched > 0 && detailDelayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, detailDelayMs));
      }
      fetched++;
      c.enrichmentStatus = "failed";
      c.reachability = "unknown";
      c.triageWarnings = ["detail/repro enrichment incomplete"];
      try {
        const detail = await opts.fetchDetail(c.bugUrl);
        const metadata = parseBugDetail(detail, baseUrl);
        Object.assign(c, metadata);
        if (metadata.reproSyzUrl && opts.fetchRepro) {
          try {
            if (detailDelayMs > 0) {
              await new Promise((resolve) => setTimeout(resolve, detailDelayMs));
            }
            const program = await opts.fetchRepro(metadata.reproSyzUrl);
            const repro = parseSyzReproOptions(program);
            c.reproSandbox = repro.sandbox;
            c.reproFeatures = repro.features;
            c.reachability = repro.reachability;
            c.triageWarnings = repro.warnings;
            c.enrichmentStatus = repro.reachability === "unknown" ? "failed" : "verified";
          } catch (e) {
            warnings.push(`syzbot: repro fetch failed for ${c.syzbotId}: ${String(e).slice(0, 80)}`);
          }
        }
      } catch (e) {
        warnings.push(`syzbot: detail fetch failed for ${c.syzbotId}: ${String(e).slice(0, 80)}`);
      }
    }
  }

  // Enrichment can reveal privileged harness dependencies. Rerank so those
  // candidates cannot retain a top position earned from title-only geometry.
  candidates = rankCandidates(candidates, subsystems.length > 0 ? subsystems : DEFAULT_TARGET_SUBSYSTEMS);

  log(`[syzbot] ${scanned} row(s) scanned → ${candidates.length} ranked candidate(s)`);

  return { candidates, brief: syzbotQueueBrief(), scanned, warnings };
}

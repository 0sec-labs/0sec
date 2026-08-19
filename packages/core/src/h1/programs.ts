// Program list / detail / scope-list helpers built on top of `H1Client`.
//
// Functions stay free-standing rather than methods on the client: tests
// already inject `fetchImpl` at the client level, and keeping these as
// plain functions matches the rest of the pwnkit core (compare
// `runStaticAnalysis`, `parseApiSpec`, etc.).

import type { H1Client } from "./client.js";
import type {
  H1Collection,
  H1Program,
  H1ProgramAttributes,
  H1Scope,
  H1Single,
  H1StructuredScopeAttributes,
} from "./types.js";

const PROGRAMS_PATH = "/v1/hackers/programs";

export interface ListProgramsOptions {
  /** Page size H1 honours; max 100. */
  pageSize?: number;
  /** Stop once we have at least this many programs. Default: no cap. */
  limit?: number;
  /** Filter to bounty-paying programs only. */
  bountyOnly?: boolean;
  /** Filter to non-bounty (VDP) programs only. */
  vdpOnly?: boolean;
  /** Filter by `attributes.state` (e.g. "public_mode", "soft_launched"). */
  state?: string;
}

/**
 * Iterate every visible program (paginating server-side until exhausted
 * or `limit` is reached) and return a flat array. Filters are applied
 * client-side because H1's server-side filters are limited; we already
 * have to paginate everything for the BB/VDP split anyway.
 */
export async function listPrograms(
  client: H1Client,
  opts: ListProgramsOptions = {},
): Promise<H1Program[]> {
  const pageSize = Math.min(Math.max(opts.pageSize ?? 100, 1), 100);
  const out: H1Program[] = [];
  const query: Record<string, string | number> = { "page[size]": pageSize };

  for await (const page of client.paginate<H1ProgramAttributes>(PROGRAMS_PATH, query)) {
    for (const item of page.data) {
      if (!matchesFilters(item, opts)) continue;
      out.push(item);
      if (opts.limit !== undefined && out.length >= opts.limit) {
        return out;
      }
    }
  }
  return out;
}

function matchesFilters(p: H1Program, opts: ListProgramsOptions): boolean {
  if (opts.bountyOnly && p.attributes.offers_bounties !== true) return false;
  if (opts.vdpOnly && p.attributes.offers_bounties === true) return false;
  if (opts.state && p.attributes.state !== opts.state) return false;
  return true;
}

/**
 * Fetch a single program by handle. The handle is the URL-friendly slug
 * H1 uses (e.g. `flutteruki`, `gitlab`).
 *
 * SHAPE NOTE: H1's hacker API is inconsistent about the JSON:API
 * envelope here. The list endpoint returns `{ data: [...], links: {} }`,
 * and the structured_scopes endpoint does the same. But
 * `GET /v1/hackers/programs/{handle}` returns the resource directly
 * (no `data:` wrapper). We accept either shape so the function works
 * across whatever envelope H1 decides to use this week.
 */
export async function getProgram(client: H1Client, handle: string): Promise<H1Program> {
  const path = `${PROGRAMS_PATH}/${encodeURIComponent(handle)}`;
  const raw = await client.get<H1Program | H1Single<H1ProgramAttributes>>(path);
  if ("data" in raw && (raw as H1Single<H1ProgramAttributes>).data) {
    return (raw as H1Single<H1ProgramAttributes>).data;
  }
  return raw as H1Program;
}

/**
 * Fetch the `structured_scopes` collection for a program. Returns ALL
 * scopes (in and out of scope from H1's POV) so callers can split them
 * by `eligible_for_submission` themselves.
 */
export async function getStructuredScopes(client: H1Client, handle: string): Promise<H1Scope[]> {
  const path = `${PROGRAMS_PATH}/${encodeURIComponent(handle)}/structured_scopes`;
  const out: H1Scope[] = [];
  for await (const page of client.paginate<H1StructuredScopeAttributes>(path, { "page[size]": 100 })) {
    out.push(...page.data);
  }
  return out;
}

/**
 * Heuristic automation-verdict over a free-form policy string. Real-world
 * H1 policies frequently combine a blanket prohibition ("don't use common
 * vulnerability scanners") with a contrast clause that re-permits a
 * narrower form ("although custom tools at 5 rps are allowed"). The pure
 * keyword version of this function (PR #265) stopped at the first
 * negative match and over-flagged programs that explicitly permit
 * targeted automation — see issue #266 for the Flutter UK&I case.
 *
 * The current shape:
 *
 *   - "forbidden": only negative keywords appear in any paragraph.
 *   - "permitted": only positive keywords appear; OR a paragraph whose
 *                  positive marker dominates a negative one (no negative
 *                  paragraphs are pure-negative).
 *   - "mixed":     at least one paragraph mixes a negative clause with
 *                  a contrast marker AND a positive marker. The
 *                  policy is conditionally permissive — operator must
 *                  read it.
 *   - "unclear":   no automation-related keywords detected at all.
 *
 * We deliberately do not call this an LLM — issue #266 considered that
 * (option b) but landed on regex (option a) for cost / latency. If
 * false-positive rate on real policies remains high, the LLM lane is the
 * obvious next step.
 */
export type AutomationVerdict = "forbidden" | "permitted" | "mixed" | "unclear";

// Automation-topic markers — positive/negative permission words only
// flip the verdict if they sit alongside one of these. This keeps a
// generic "Welcome researchers." from being read as "automation is
// welcome".
const AUTOMATION_TOPIC_RE =
  /\b(automat(?:ed|ion|ic)|scan(?:ner|ners|ning)?|crawl(?:er|ers|ing)?|spider|fuzz(?:er|ing)?|brute[-\s]?force|tool(?:s)?|gobuster|sqlmap|nikto|wfuzz|ffuf|nmap)\b/i;

// Pure prohibition markers — "scanners are forbidden / prohibited / not
// permitted / not allowed". These dominate over a co-located positive
// marker that's grammatically attached ("no scanners are allowed" →
// negative, NOT mixed).
const PROHIBITION_RE =
  /\b(no\s+(?:automated|automatic|scanner|scanners|crawler|spider|fuzz|tool)|don'?t\s+use|do\s+not\s+use|not\s+permitted|not\s+allowed|forbidden|prohibited|disallowed|will\s+be\s+closed\s+as\s+n\/a)\b/i;

// Plain negative cues — the policy mentions banned tooling without
// using a prohibition phrase. "scanner" / "gobuster" / "sqlmap" land
// here when in a negative context.
const NEGATIVE_TOOL_RE =
  /\b(scanner|scanners|gobuster|sqlmap|nikto|wfuzz|ffuf|crawler|spider|automated\s+(?:tool|scanner|scanning|exploit)s?)\b/i;

// Positive-permission markers — paired with AUTOMATION_TOPIC_RE before
// they count. "rate-limit / rate-limited" alone aren't permissions; we
// want an explicit verb like allowed / permitted / welcome.
const POSITIVE_RE =
  /\b(allowed|permitted|welcome|acceptable|ok\s+to|encouraged)\b/i;

// Contrast markers that flip a paragraph's polarity. "though" alone is
// noisy; "although" is the strongest signal. We include the rest from
// issue #266 plus a couple of common conjunction phrases.
const CONTRAST_RE =
  /\b(although|however|but|except|unless|that\s+said|provided\s+that|as\s+long\s+as|so\s+long\s+as)\b/i;

/** Split a policy into paragraph-ish chunks. We accept either blank-line
 * separation (`\n\n+`) or a single newline followed by a list-item
 * marker, since H1 policies sometimes flatten paragraphs. */
function splitParagraphs(policy: string): string[] {
  // Normalise CRLF first so the regex below behaves the same across
  // platforms / clipboard origins.
  const normalised = policy.replace(/\r\n/g, "\n");
  const chunks = normalised.split(/\n\s*\n+/g).map((s) => s.trim()).filter((s) => s.length > 0);
  // If there are no blank-line breaks, fall back to the whole policy
  // as a single paragraph — the contrast detection below still works
  // within one paragraph.
  return chunks.length > 0 ? chunks : [normalised.trim()];
}

type ParaPolarity = "negative" | "positive" | "mixed" | "neutral";

/**
 * Classify a paragraph by polarity. Decisions in order:
 *
 *   1. No automation topic at all → neutral. Generic greetings like
 *      "Welcome researchers" never flip the verdict.
 *   2. A prohibition phrase ("scanners are not allowed") + a contrast
 *      marker + a separate positive permission downstream → mixed.
 *   3. A pure prohibition with no contrast/positive → negative.
 *   4. A positive permission AND a negative tool mention without an
 *      explicit prohibition phrase → mixed (the policy carves out
 *      something but also bans something else).
 *   5. Just positive on automation topic → positive.
 *   6. Just negative tool mention → negative.
 *   7. Otherwise → neutral.
 */
function classifyParagraph(para: string): ParaPolarity {
  if (!AUTOMATION_TOPIC_RE.test(para)) return "neutral";

  const hasProhibition = PROHIBITION_RE.test(para);
  const hasContrast = CONTRAST_RE.test(para);
  const hasPositive = POSITIVE_RE.test(para);
  const hasNegativeTool = NEGATIVE_TOOL_RE.test(para);

  // Case (2) — explicit prohibition + contrast + permission. The
  // contrast marker introduces the carve-out we care about.
  if (hasProhibition && hasContrast && hasPositive) return "mixed";

  // Case (3) — pure prohibition wins over a grammatically-attached
  // positive ("no scanners are allowed"). We require either no
  // positive, or no contrast marker — without a contrast, the
  // positive is part of the prohibition phrase itself.
  if (hasProhibition && !hasContrast) return "negative";

  // Case (4) — positive permission alongside a separate negative
  // tool mention. Operator should read it.
  if (hasPositive && hasNegativeTool) return "mixed";

  // Case (5)
  if (hasPositive) return "positive";

  // Case (6)
  if (hasNegativeTool || hasProhibition) return "negative";

  return "neutral";
}

export function automationVerdict(policy: string | undefined): AutomationVerdict {
  if (!policy || policy.trim().length === 0) return "unclear";
  const paragraphs = splitParagraphs(policy);
  let neg = 0;
  let pos = 0;
  let mixed = 0;
  for (const p of paragraphs) {
    const c = classifyParagraph(p);
    if (c === "negative") neg += 1;
    else if (c === "positive") pos += 1;
    else if (c === "mixed") mixed += 1;
  }
  // Any explicitly-mixed paragraph dominates: the policy contains a
  // permission carve-out, which is exactly the case we want operators
  // to read directly.
  if (mixed > 0) return "mixed";
  if (neg > 0 && pos > 0) return "mixed";
  if (neg > 0) return "forbidden";
  if (pos > 0) return "permitted";
  return "unclear";
}

/**
 * Group scopes by `asset_type` and split in/out scope by
 * `eligible_for_submission`. Used by `programs show` for the summary.
 */
export function summariseScopes(scopes: H1Scope[]): {
  inScopeByType: Record<string, number>;
  outOfScopeByType: Record<string, number>;
  totalIn: number;
  totalOut: number;
} {
  const inScopeByType: Record<string, number> = {};
  const outOfScopeByType: Record<string, number> = {};
  let totalIn = 0;
  let totalOut = 0;
  for (const s of scopes) {
    const t = s.attributes.asset_type ?? "UNKNOWN";
    if (s.attributes.eligible_for_submission === false) {
      outOfScopeByType[t] = (outOfScopeByType[t] ?? 0) + 1;
      totalOut += 1;
    } else {
      inScopeByType[t] = (inScopeByType[t] ?? 0) + 1;
      totalIn += 1;
    }
  }
  return { inScopeByType, outOfScopeByType, totalIn, totalOut };
}

// Re-export collection alias for callers that want the page envelope type.
export type H1ProgramPage = H1Collection<H1ProgramAttributes>;

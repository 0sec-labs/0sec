/**
 * #777 (part of #764) — "how we hacked X" writeup generator.
 *
 * Turns a disclosed finding's `disclosure/<package>-<vector>-<date>.md`
 * (YAML frontmatter + markdown body) into a *sanitised* narrative draft
 * destined for `research/output/writeups/`. The draft reuses the pwnkit
 * disclose template's section spine (Summary / PoC / Timeline / Remediation)
 * and runs every emitted body through the same {@link redactSensitiveHeaders}
 * pass the advisory renderer uses, plus a PII (email) sweep.
 *
 * Design mirrors `bundle.ts`: this module owns the *parse + redact + assemble*
 * decisions and returns strings. It performs **no I/O and no network calls** —
 * the caller writes the file. Keeping it pure keeps tests deterministic/offline
 * and, critically, keeps disclosure content from ever touching a third-party
 * API from inside this module (see `disclosure/AGENTS.md` hard rule #1/#5).
 *
 * Embargo gate: `disclosure/AGENTS.md` forbids folding embargoed findings into
 * other docs. {@link generateWriteup} therefore refuses to emit unless the
 * finding is operator-cleared — either its status is a terminal/public one
 * (published-cve / patched-no-cve / wontfix), or the caller passes
 * `allowEmbargoed: true` to explicitly stage an internal draft. The default is
 * "refuse", so an automated run can never silently produce a publishable draft
 * for a finding still under coordinated disclosure.
 */

import { parse as parseYaml } from "yaml";
import { redactSensitiveHeaders } from "./template.js";

/** Frontmatter fields this generator reads. All optional — files vary. */
export interface DisclosureFrontmatter {
  package?: string;
  short_name?: string;
  vuln_class?: string;
  status?: string;
  severity_estimate?: string;
  cve_id?: string | null;
  ghsa_id?: string | null;
  date_found?: string | null;
  date_published?: string | null;
  [key: string]: unknown;
}

export interface ParsedDisclosure {
  frontmatter: DisclosureFrontmatter;
  /** Markdown body with the frontmatter block stripped. */
  body: string;
}

/**
 * Statuses for which a writeup may be emitted without an explicit override.
 * These are terminal / already-public states where the embargo has lifted.
 * (Status enum lives in `disclosure/README.md`.)
 */
export const PUBLISHABLE_STATUSES = new Set<string>([
  "published-cve",
  "patched-no-cve",
  "wontfix",
  "maintainer-rejected",
]);

export class EmbargoedFindingError extends Error {
  readonly status: string;
  constructor(status: string) {
    super(
      `Finding status "${status}" is not operator-cleared for a writeup. ` +
        `Pass allowEmbargoed:true to stage an internal draft, or wait for a ` +
        `terminal status (${[...PUBLISHABLE_STATUSES].join(", ")}).`,
    );
    this.name = "EmbargoedFindingError";
    this.status = status;
  }
}

const FRONTMATTER_RE = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/;

/**
 * Split a disclosure markdown file into frontmatter + body. A file with no
 * frontmatter block yields an empty frontmatter object and the whole input as
 * the body, so callers don't have to special-case malformed files.
 */
export function parseDisclosure(raw: string): ParsedDisclosure {
  const m = FRONTMATTER_RE.exec(raw);
  if (!m) {
    return { frontmatter: {}, body: raw.trim() };
  }
  let frontmatter: DisclosureFrontmatter = {};
  try {
    const parsed = parseYaml(m[1]) as unknown;
    if (parsed && typeof parsed === "object") {
      frontmatter = parsed as DisclosureFrontmatter;
    }
  } catch {
    // Tolerate broken YAML — fall back to empty frontmatter rather than throw,
    // so a single bad file doesn't break a batch run.
    frontmatter = {};
  }
  const body = raw.slice(m[0].length).trim();
  return { frontmatter, body };
}

// ── PII redaction ───────────────────────────────────────────────────────────
// `redactSensitiveHeaders` masks auth secrets (Authorization/Cookie/JWT/AWS).
// A disclosure narrative additionally carries human PII the secret-sweep
// doesn't touch — most commonly maintainer/operator emails in the Timeline
// ("emailed security@auth0.com", "Okta (Kevin Roh) replied"). Mask bare email
// addresses; vendor security inboxes are intentionally left intact because
// they're public contact points, not PII.
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const PUBLIC_SECURITY_LOCALPARTS = new Set([
  "security",
  "secalert",
  "psirt",
  "abuse",
  "cve",
  "oss-security",
  "support",
  "info",
]);

/** Mask personal email addresses, preserving public vendor security inboxes. */
export function redactPii(text: string): string {
  if (!text) return text;
  return text.replace(EMAIL_RE, (addr) => {
    const localPart = addr.slice(0, addr.indexOf("@")).toLowerCase();
    if (PUBLIC_SECURITY_LOCALPARTS.has(localPart)) return addr;
    return "<REDACTED-EMAIL>";
  });
}

/** Apply both the secret sweep and the PII sweep to a block of text. */
export function sanitizeWriteup(text: string): string {
  return redactPii(redactSensitiveHeaders(text));
}

// ── Section extraction ────────────────────────────────────────────────────────
// The disclose template's spine is Summary / PoC / Timeline / Remediation.
// Disclosure files use slightly different headings for the same content
// (e.g. "Recommended fix"/"Suggested fix" for remediation, "Reproduction"/
// "End-to-end chain" for PoC). Map heading aliases onto the four canonical
// narrative sections; anything that doesn't map is dropped from the writeup so
// internal-only headings ("Next step", "Affected") don't leak.

type CanonicalSection = "Summary" | "How we found it" | "Timeline" | "Remediation";

const HEADING_ALIASES: Record<string, CanonicalSection> = {
  summary: "Summary",
  analysis: "Summary",
  "attack vector": "How we found it",
  reproduction: "How we found it",
  poc: "How we found it",
  "proof of concept": "How we found it",
  "end-to-end chain": "How we found it",
  timeline: "Timeline",
  "recommended fix": "Remediation",
  "suggested fix": "Remediation",
  "recommended remediation": "Remediation",
  remediation: "Remediation",
};

/** Order canonical sections appear in the emitted writeup. */
const SECTION_ORDER: CanonicalSection[] = [
  "Summary",
  "How we found it",
  "Timeline",
  "Remediation",
];

interface SectionMap {
  Summary: string[];
  "How we found it": string[];
  Timeline: string[];
  Remediation: string[];
}

/**
 * Split a disclosure body into canonical sections keyed by the narrative
 * headings, concatenating multiple source sections that map to the same target
 * (e.g. both "Reproduction" and "End-to-end chain" feed "How we found it").
 */
export function extractSections(body: string): SectionMap {
  const sections: SectionMap = {
    Summary: [],
    "How we found it": [],
    Timeline: [],
    Remediation: [],
  };
  // Match `## Heading` (level 2+) blocks. We ignore the level-1 title and any
  // leading status blockquote — neither carries narrative content.
  const headingRe = /^#{2,}\s+(.+?)\s*$/gm;
  const matches = [...body.matchAll(headingRe)];
  for (let i = 0; i < matches.length; i++) {
    const headingText = matches[i][1]
      // Strip inline-code/backticks/markdown from the heading for alias lookup.
      .replace(/`[^`]*`/g, "")
      .replace(/[*_]/g, "")
      .trim()
      .toLowerCase();
    const canonical = HEADING_ALIASES[headingText];
    if (!canonical) continue;
    const start = matches[i].index! + matches[i][0].length;
    const end = i + 1 < matches.length ? matches[i + 1].index! : body.length;
    const content = body.slice(start, end).trim();
    if (content) sections[canonical].push(content);
  }
  return sections;
}

export interface WriteupOptions {
  /**
   * Allow emitting a draft for a finding that is NOT in a terminal/public
   * status. Off by default so automated runs can't produce a publishable draft
   * for an embargoed finding. The emitted draft is still marked DRAFT.
   */
  allowEmbargoed?: boolean;
  /** Stamp used in the generated header. Defaults to `new Date()`. */
  generatedAt?: Date;
}

export interface GeneratedWriteup {
  /** `research/output/writeups/`-relative filename. */
  filename: string;
  /** The sanitised "how we hacked X" markdown draft. */
  markdown: string;
  /** Canonical sections that had content (for caller logging/tests). */
  sectionsPresent: CanonicalSection[];
  /** Whether this draft was emitted under the embargo override. */
  embargoed: boolean;
}

function slugify(value: string, max = 80): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, max);
}

function titleFor(fm: DisclosureFrontmatter, body: string): string {
  // Prefer the body's level-1 title; fall back to frontmatter package + class.
  const h1 = /^#\s+(.+?)\s*$/m.exec(body);
  if (h1) return h1[1].trim();
  const pkg = fm.package ?? "the target";
  const cls = fm.vuln_class ? ` ${fm.vuln_class.replace(/-/g, " ")}` : "";
  return `${pkg}${cls}`;
}

/**
 * Generate a sanitised "how we hacked X" writeup draft from a parsed
 * disclosure file. Throws {@link EmbargoedFindingError} when the finding is
 * not operator-cleared and `allowEmbargoed` is not set.
 */
export function generateWriteup(
  parsed: ParsedDisclosure,
  opts: WriteupOptions = {},
): GeneratedWriteup {
  const { frontmatter: fm, body } = parsed;
  const status = (fm.status ?? "unknown").trim();
  const cleared = PUBLISHABLE_STATUSES.has(status);
  if (!cleared && !opts.allowEmbargoed) {
    throw new EmbargoedFindingError(status);
  }

  const title = titleFor(fm, body);
  const sections = extractSections(body);
  const generatedAt = opts.generatedAt ?? new Date();
  const dateStamp = generatedAt.toISOString().slice(0, 10);

  const sectionsPresent = SECTION_ORDER.filter((s) => sections[s].length > 0);

  const out: string[] = [];
  out.push(`# How we hacked ${title}`, "");
  out.push(
    "> DRAFT — sanitised writeup generated from a disclosure record. " +
      "Operator review required before publication; embargo rules in " +
      "`disclosure/AGENTS.md` still apply.",
    "",
  );

  // Metadata line — public-safe fields only. No maintainer names, no internal
  // channel/case IDs, no operator email.
  const meta: string[] = [];
  if (fm.package) meta.push(`**Target:** \`${fm.package}\``);
  if (fm.vuln_class) meta.push(`**Class:** ${fm.vuln_class}`);
  if (fm.severity_estimate) meta.push(`**Severity:** ${fm.severity_estimate}`);
  if (fm.cve_id) meta.push(`**CVE:** ${fm.cve_id}`);
  else if (fm.ghsa_id) meta.push(`**Advisory:** ${fm.ghsa_id}`);
  meta.push(`**Status:** ${status}`);
  if (meta.length) out.push(meta.join(" · "), "");

  if (!cleared) {
    out.push(
      `> ⚠️ This finding is **not yet in a public/terminal status** ` +
        `(\`${status}\`). Emitted under the embargo override as an internal ` +
        `draft only — do not publish.`,
      "",
    );
  }

  for (const section of SECTION_ORDER) {
    const parts = sections[section];
    if (parts.length === 0) continue;
    out.push(`## ${section}`, "");
    out.push(sanitizeWriteup(parts.join("\n\n")), "");
  }

  out.push("## Credits", "");
  out.push(
    "Found by 0sec's automated security-research tooling " +
      "([0sec.ai](https://0sec.ai)).",
    "",
  );

  const slug = slugify(
    fm.short_name ? `${fm.package ?? ""}-${fm.short_name}` : title,
  );
  const filename = `${slug || "writeup"}-${dateStamp}.md`;

  return {
    filename,
    markdown: out.join("\n").replace(/\n{3,}/g, "\n\n"),
    sectionsPresent,
    embargoed: !cleared,
  };
}

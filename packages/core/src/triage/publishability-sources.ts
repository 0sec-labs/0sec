/**
 * Live data sources for the publishability dedup gate (issue #537 / #539).
 *
 * The {@link checkPublishability} layer in `publishability.ts` is pure: it
 * decides a verdict from injected facts and never touches the network. This
 * module supplies the *live* implementations of those injectable seams, wired
 * to the four dedup sources a single triage session proved necessary (see the
 * #537/#539 dedup-gap comments):
 *
 *   1. Published GHSA / OSV / CVE — via the existing `intel` module
 *      (`searchAdvisories`, which already merges OSV + GitHub advisories).
 *   2. OUR OWN prior submissions — including the closed / declined / duplicate
 *      ones that never reach the published feed (curated registry sourced from
 *      `disclosure/`, e.g. yaml uniqueKeys → GHSA-3g7m-p75x-hpf6, declined).
 *   3. The target repo's open AND closed security issues / PRs — GitHub search
 *      (e.g. js-yaml stack DoS == nodeca/js-yaml#739, another researcher).
 *   4. The repo's SECURITY.md — feeds the threat-model `by_design` check (and
 *      detects the Tidelift / security-email reporting channel).
 *
 * EVERYTHING here is behind an injectable seam. The aggregate
 * {@link buildPublishabilityInputs} takes a `fetchImpl` (defaults to the global
 * `fetch`) and `offline` flag so unit tests stay deterministic and offline —
 * pass a stub `fetchImpl` and nothing ever leaves the process. The scanner only
 * calls this when `PWNKIT_FEATURE_PUBLISHABILITY_GATE` is on.
 */

import type { AttackCategory } from "@pwnkit/shared";
import { searchAdvisories, normalizeRepositoryHint, type VulnerabilityIntel } from "../intel/index.js";
import { toOsvEcosystem } from "../intel/osv.js";
import type { AdvisoryRef, PublishabilityInputs } from "./publishability.js";

/** Package ecosystem the dedup sources understand. Defaults to npm. */
export type DedupEcosystem = "npm" | "pypi" | "cargo" | "go" | "maven";

export interface PublishabilitySourceOptions {
  /** Package ecosystem; controls advisory-DB + repo resolution. Default "npm". */
  ecosystem?: DedupEcosystem;
  /**
   * "owner/repo" of the target's source. When omitted we best-effort resolve it
   * from npm metadata for npm packages; for everything else repo-issue dedup is
   * skipped (returns []), which is conservative (never a false "duplicate").
   */
  repository?: string;
  /** Injected fetch (tests pass a stub). Defaults to the global `fetch`. */
  fetchImpl?: typeof fetch;
  /** When true, never hit the network — advisory/issue seams return []. */
  offline?: boolean;
  /** Per-request timeout in ms. Default 15s. */
  timeoutMs?: number;
  /** Cache dir for the intel module. Defaults to the intel module default. */
  cacheDir?: string;
}

// ────────────────────────────────────────────────────────────────────
// Vulnerability-class keywords — match an advisory / issue to a finding
// ────────────────────────────────────────────────────────────────────

/**
 * Keywords per attack category used to decide whether a global advisory or a
 * repo issue is about the SAME bug class as our finding. Deliberately broad: a
 * false *match* here only means "possible duplicate → routed to human review or
 * needs_verify for protected findings", never a silent drop of a novel bug.
 */
const CLASS_KEYWORDS: Partial<Record<AttackCategory, string[]>> = {
  "prototype-pollution": ["prototype pollution", "proto pollution", "__proto__", "prototype"],
  "path-traversal": ["path traversal", "directory traversal", "zip slip", "zip-slip", "arbitrary file write", "../"],
  "command-injection": ["command injection", "arbitrary command", "shell injection", "os command"],
  "code-injection": ["code injection", "arbitrary code", "rce", "remote code execution", "sandbox escape", "vm escape"],
  "regex-dos": ["redos", "regular expression denial", "catastrophic backtracking", "regex denial"],
  "unsafe-deserialization": ["deserialization", "unsafe deserialization", "insecure deserialization", "yaml", "pickle"],
  "ssrf": ["ssrf", "server-side request forgery", "server side request"],
  "sql-injection": ["sql injection", "sqli"],
  "xss": ["xss", "cross-site scripting", "cross site scripting"],
  "information-disclosure": ["information disclosure", "information leak", "sensitive data exposure"],
  // DoS family — the yaml / js-yaml burns. No dedicated AttackCategory, so the
  // closest source-audit categories carry the DoS keywords too.
  "missing-validation": ["denial of service", "dos", "uncontrolled recursion", "stack overflow", "resource exhaustion", "quadratic"],
};

/**
 * DoS keywords applied to EVERY category as a fallback — parser DoS bugs (yaml,
 * js-yaml) get classified under varied categories by the agent, but the
 * duplicate-risk pattern is the same regardless of category label.
 */
const DOS_FALLBACK_KEYWORDS = [
  "denial of service",
  "uncontrolled recursion",
  "stack overflow",
  "resource exhaustion",
  "quadratic",
] as const;

function classKeywords(category: AttackCategory): string[] {
  const base = CLASS_KEYWORDS[category] ?? [];
  return Array.from(new Set([...base, ...DOS_FALLBACK_KEYWORDS]));
}

/** True when `text` mentions any keyword for the finding's class (case-insensitive). */
function textMatchesClass(text: string | undefined, keywords: string[]): boolean {
  if (!text) return false;
  const hay = text.toLowerCase();
  return keywords.some((k) => hay.includes(k.toLowerCase()));
}

// ────────────────────────────────────────────────────────────────────
// Source 2 — OUR OWN prior submissions (curated registry)
// ────────────────────────────────────────────────────────────────────

/**
 * Curated registry of OUR prior submissions, including the closed / declined /
 * duplicate ones that never surface in the published GHSA/OSV feed. Sourced from
 * `disclosure/` tracking. This is the registry that closes the gap the published
 * feed leaves (#537 dedup-gap comment): a finding we already filed and the
 * maintainer waved off must never be re-pitched as "novel".
 *
 * `status: "declined"` marks the maintainer-waved-off cases (→ by_design). Keep
 * this list aligned with `disclosure/*.md` as new submissions are made.
 */
interface OwnSubmissionEntry {
  packageName: string;
  ecosystem: DedupEcosystem;
  /** Keywords identifying the bug class within the package. */
  classKeywords: string[];
  ref: AdvisoryRef;
}

export const OWN_SUBMISSIONS_REGISTRY: ReadonlyArray<OwnSubmissionEntry> = [
  {
    // We filed this; eemeli declined it as "performance, not a security issue".
    // Re-pitching it is a pure credibility hit → status declined → by_design.
    packageName: "yaml",
    ecosystem: "npm",
    classKeywords: ["quadratic", "uniquekeys", "unique keys", "map", "denial of service", "dos", "cpu"],
    ref: {
      id: "GHSA-3g7m-p75x-hpf6",
      source: "own_submission",
      status: "declined",
      summary: "yaml uniqueKeys O(n^2) map DoS — declined by maintainer as performance, not security",
    },
  },
];

/**
 * Build the Source 2 seam from the curated registry. Pure + offline — no
 * network. Matches on package name + ecosystem + class keywords.
 */
export function makeOwnSubmissionsLookup(
  opts: Pick<PublishabilitySourceOptions, "ecosystem"> = {},
  registry: ReadonlyArray<OwnSubmissionEntry> = OWN_SUBMISSIONS_REGISTRY,
): (packageName: string, category: string) => Promise<AdvisoryRef[]> {
  const ecosystem = opts.ecosystem ?? "npm";
  return async (packageName, category) => {
    const pkg = packageName.trim().toLowerCase();
    const keywords = classKeywords(category as AttackCategory);
    return registry
      .filter((e) => e.ecosystem === ecosystem && e.packageName.toLowerCase() === pkg)
      .filter(
        (e) =>
          // class-keyword overlap between the registry entry and the finding's
          // category, so we don't dedup an unrelated bug in the same package.
          e.classKeywords.some((rk) =>
            keywords.some((fk) => rk.toLowerCase().includes(fk.toLowerCase()) || fk.toLowerCase().includes(rk.toLowerCase())),
          ),
      )
      .map((e) => e.ref);
  };
}

// ────────────────────────────────────────────────────────────────────
// Source 1 — published GHSA / OSV / CVE (via the intel module)
// ────────────────────────────────────────────────────────────────────

function intelToAdvisoryRef(v: VulnerabilityIntel): AdvisoryRef {
  // The first recorded fixed version, if any, is the patched-version signal the
  // dedup classifier uses to tell duplicate-of-fixed from still-open.
  const patched = v.fixedVersions.length > 0 ? v.fixedVersions[0] : undefined;
  const ref: AdvisoryRef = { id: v.id, source: "global", status: patched ? "patched" : "open" };
  if (patched) ref.patchedVersion = patched;
  if (v.summary) ref.summary = v.summary;
  return ref;
}

/**
 * Build the Source 1 seam — published GHSA/OSV/CVE for this package, filtered to
 * the finding's bug class. Reuses the `intel` module's `searchAdvisories`
 * (OSV + GitHub advisories merged). Fail-soft: any error → [].
 */
export function makeGlobalAdvisoryLookup(
  opts: PublishabilitySourceOptions = {},
): (packageName: string, category: string) => Promise<AdvisoryRef[]> {
  const ecosystem = opts.ecosystem ?? "npm";
  return async (packageName, category) => {
    if (opts.offline) return [];
    // OSV/GitHub only understand certain ecosystems; bail (→ []) otherwise.
    if (!toOsvEcosystem(ecosystem)) return [];
    const keywords = classKeywords(category as AttackCategory);
    try {
      const { advisories } = await searchAdvisories(
        {
          ecosystem,
          packageName,
          offline: opts.offline,
          cacheDir: opts.cacheDir,
        },
        { timeoutMs: opts.timeoutMs ?? 15_000, fetchImpl: opts.fetchImpl },
      );
      return advisories
        .filter((v) => textMatchesClass(`${v.summary ?? ""} ${v.details ?? ""}`, keywords))
        .map(intelToAdvisoryRef);
    } catch {
      return [];
    }
  };
}

// ────────────────────────────────────────────────────────────────────
// Source 3 — the target repo's open AND closed security issues / PRs
// ────────────────────────────────────────────────────────────────────

interface GitHubSearchItem {
  number?: number;
  title?: string;
  body?: string;
  html_url?: string;
  state?: string;
  pull_request?: unknown;
}
interface GitHubSearchResponse {
  items?: GitHubSearchItem[];
}

function githubSearchHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "pwnkit-publishability/0.1",
  };
  const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

/**
 * Build the Source 3 seam — search the target repo's open + closed issues/PRs
 * for an existing report of this bug class. A match (another researcher already
 * filed it) → `repo_issue` ref → duplicate.
 *
 * Requires `opts.repository` ("owner/repo"). Without it, returns [] (we don't
 * guess a repo and risk a false duplicate). Fail-soft on any error → [].
 */
export function makeRepoIssueLookup(
  opts: PublishabilitySourceOptions = {},
): (packageName: string, category: string) => Promise<AdvisoryRef[]> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  return async (_packageName, category) => {
    if (opts.offline || !opts.repository) return [];
    const repo = opts.repository.trim();
    if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) return [];
    const keywords = classKeywords(category as AttackCategory);
    // Search both open and closed issues/PRs in the repo. The GitHub search
    // qualifier `repo:owner/name` + free-text covers titles + bodies.
    const q = encodeURIComponent(
      `repo:${repo} ${keywords.slice(0, 4).map((k) => `"${k}"`).join(" OR ")}`,
    );
    const url = `https://api.github.com/search/issues?q=${q}&per_page=50`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 15_000);
    try {
      const res = await fetchImpl(url, {
        headers: githubSearchHeaders(),
        signal: controller.signal,
      });
      if (!res.ok) return [];
      const data = (await res.json()) as GitHubSearchResponse;
      return (data.items ?? [])
        .filter((it) => textMatchesClass(`${it.title ?? ""} ${it.body ?? ""}`, keywords))
        .map((it) => {
          const kind = it.pull_request ? "PR" : "issue";
          const ref: AdvisoryRef = {
            id: `${repo}#${it.number ?? "?"}`,
            source: "repo_issue",
            // an existing (open or closed) report → known/in-flight → duplicate.
            status: "open",
          };
          if (it.title) ref.summary = `${kind} (${it.state ?? "?"}): ${it.title}`;
          return ref;
        });
    } catch {
      return [];
    } finally {
      clearTimeout(timer);
    }
  };
}

// ────────────────────────────────────────────────────────────────────
// Source 4 — the repo's SECURITY.md (threat-model + reporting channel)
// ────────────────────────────────────────────────────────────────────

const SECURITY_MD_PATHS = [
  "SECURITY.md",
  ".github/SECURITY.md",
  "docs/SECURITY.md",
  "security.md",
] as const;

/**
 * Build the Source 4 seam — fetch the repo's SECURITY.md (the threat-model
 * `by_design` check reads it; it also surfaces the Tidelift / security-email
 * channel). Tries common paths on the default branch. Requires
 * `opts.repository`. Fail-soft / offline → null.
 */
export function makeSecurityPolicyFetch(
  opts: PublishabilitySourceOptions = {},
): (packageName: string) => Promise<string | null> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  return async (_packageName) => {
    if (opts.offline || !opts.repository) return null;
    const repo = opts.repository.trim();
    if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) return null;
    for (const branch of ["main", "master"]) {
      for (const path of SECURITY_MD_PATHS) {
        const url = `https://raw.githubusercontent.com/${repo}/${branch}/${path}`;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 15_000);
        try {
          const res = await fetchImpl(url, { signal: controller.signal });
          if (res.ok) {
            const text = await res.text();
            if (text.trim().length > 0) return text;
          }
        } catch {
          // try the next path/branch
        } finally {
          clearTimeout(timer);
        }
      }
    }
    return null;
  };
}

/**
 * Detect the security reporting channel declared in a SECURITY.md. Surfaced so
 * the operator knows HOW to file (Tidelift vs. direct email vs. GitHub private
 * advisory) before sending — a separate concern from the by_design gate.
 */
export interface ReportingChannel {
  tidelift: boolean;
  emails: string[];
  privateAdvisory: boolean;
}

export function detectReportingChannel(policyText: string | null | undefined): ReportingChannel {
  if (!policyText) return { tidelift: false, emails: [], privateAdvisory: false };
  const lower = policyText.toLowerCase();
  const emails = Array.from(
    new Set(
      // Domain part ends on an alphanumeric so a trailing sentence dot
      // ("email security@nodeca.com.") is not captured into the address.
      (policyText.match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}/g) ?? []).map((e) =>
        e.toLowerCase(),
      ),
    ),
  );
  return {
    tidelift: lower.includes("tidelift"),
    emails,
    privateAdvisory:
      lower.includes("private vulnerability reporting") ||
      lower.includes("security advisory") ||
      lower.includes("report a vulnerability"),
  };
}

// ────────────────────────────────────────────────────────────────────
// Repository resolver — npm metadata → "owner/repo"
// ────────────────────────────────────────────────────────────────────

interface NpmPackageMetadata {
  repository?: string | { url?: string; type?: string };
}

/**
 * Resolve a package's source repository to "owner/repo" so Sources 3 + 4 (repo
 * issues + SECURITY.md) can light up. Only npm is resolved live today; other
 * ecosystems return undefined (→ those sources no-op, never a guessed repo).
 *
 * Conservative by design: any failure (offline, 404, non-GitHub host,
 * unparseable repository field) returns undefined so we never search a guessed
 * repo and risk a FALSE duplicate. Fail-soft on every path.
 */
export async function resolveRepository(
  packageName: string,
  opts: PublishabilitySourceOptions = {},
): Promise<string | undefined> {
  const ecosystem = opts.ecosystem ?? "npm";
  if (opts.offline || ecosystem !== "npm") return undefined;
  const name = packageName.trim();
  if (!name) return undefined;
  const fetchImpl = opts.fetchImpl ?? fetch;
  // Scoped names (@scope/pkg) must keep the slash encoded for the registry path.
  const url = `https://registry.npmjs.org/${name.replace("/", "%2f")}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 15_000);
  try {
    const res = await fetchImpl(url, {
      headers: { Accept: "application/json", "User-Agent": "pwnkit-publishability/0.1" },
      signal: controller.signal,
    });
    if (!res.ok) return undefined;
    const meta = (await res.json()) as NpmPackageMetadata;
    const repoField =
      typeof meta.repository === "string" ? meta.repository : meta.repository?.url;
    // normalizeRepositoryHint returns "owner/repo" only for GitHub repos, else
    // undefined — exactly the conservative behavior we want.
    return normalizeRepositoryHint(repoField);
  } catch {
    return undefined;
  } finally {
    clearTimeout(timer);
  }
}

// ────────────────────────────────────────────────────────────────────
// Aggregate — assemble PublishabilityInputs from all four live sources
// ────────────────────────────────────────────────────────────────────

/**
 * Assemble a {@link PublishabilityInputs} wired to all four live sources. The
 * scanner calls this only when the publishability gate is enabled; tests pass a
 * stub `fetchImpl` (or `offline: true`) to stay deterministic and offline.
 *
 * Note: `latestVersion` / `reproducesOnLatest` / `publicApiReachable` are NOT
 * set here — those come from the verify / reachability stages and are merged in
 * by the caller. This function only wires the dedup + threat-model seams.
 */
export function buildPublishabilityInputs(
  opts: PublishabilitySourceOptions = {},
): PublishabilityInputs {
  return {
    fetchSecurityPolicy: makeSecurityPolicyFetch(opts),
    lookupAdvisories: makeGlobalAdvisoryLookup(opts),
    lookupOwnSubmissions: makeOwnSubmissionsLookup(opts),
    lookupRepoIssues: makeRepoIssueLookup(opts),
  };
}

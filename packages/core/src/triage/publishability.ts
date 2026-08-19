/**
 * Publishability triage layer (issue #537 / #539).
 *
 * "Reproduces" ≠ "in scope." This layer decides disclosure-worthiness so we
 * stop filing by-design / duplicate / dead-code / already-fixed findings. Each
 * check below maps to a *real* burn from a single triage session:
 *
 *   - threat-model → `by_design`   — webpack proto-pollution rejected by the
 *     maintainer ("don't run webpack on untrusted config — it's in our
 *     SECURITY.md"). Also nunjucks / eta / jsonata (template + expr evaluators).
 *   - dedup        → `duplicate`   — formidable (GHSA-3pj2-wmw4-qpcx), QEMU
 *     virtio-snd (CVE-2026-3196): an advisory already covers the class AND
 *     latest is patched.
 *   - dedup        → `fix_bypass`  — unzipper / mathjs / pug: an advisory
 *     exists, BUT our PoC still reproduces on the LATEST published version.
 *     This is the valuable exception and must NOT be dropped as a duplicate.
 *   - latest-ver   → `fixed`       — vm2 / adm-zip: the bug was fixed upstream;
 *     we reproduced on an old found-version, not the latest.
 *   - reachability → `unreachable` — node-forge form.js: the sink is only
 *     reachable from dead / unexported (non-public-API) code.
 *
 * Output: a {@link PublishabilityResult} with one of the
 * {@link PublishabilityDecision} verdicts. `in_scope` and `fix_bypass` are the
 * "green to file" verdicts; everything else is a reason to hold or drop.
 *
 * NETWORK SEAMS. The threat-model check needs the target's SECURITY.md and the
 * dedup check needs the global advisory DB (GHSA/OSV/CVE). Both are injected as
 * async functions on {@link PublishabilityInputs} so unit tests are
 * deterministic and offline — the layer itself performs no network I/O.
 *
 * GUARDRAIL. This module only *computes* a verdict. It never drops a finding.
 * The scanner wiring (`agentic-scanner.ts`) routes any suppression decision
 * through `canAutoSuppress`, so a high-severity / high-impact finding is
 * downgraded to `needs_verify` + human review, never silently dropped.
 */

import type { Finding, PublishabilityDecision } from "@pwnkit/shared";

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export interface PublishabilityResult {
  decision: PublishabilityDecision;
  /** 0.0–1.0 confidence in the verdict. */
  confidence: number;
  /** Short human-readable reason, stable across runs for the same input. */
  reason: string;
  /** Set when `by_design` fired — the threat-model exclusion that matched. */
  threatModelExclusion?: string;
  /** Set when `duplicate` / `fix_bypass` fired — the advisory refs matched. */
  dedupRefs?: string[];
  /** Whether the latest published version is patched against this class. */
  latestVersionFixed?: boolean;
  /** Whether the sink is reachable from a documented public API. */
  publicApiReachable?: boolean;
}

/**
 * Where a dedup match came from. The four sources are the ones a single triage
 * session proved necessary (issue #537 / #539 dedup-gap comments):
 *
 *   - `global`         — published GHSA/OSV/CVE feed. (formidable, QEMU)
 *   - `own_submission` — OUR OWN prior report, INCLUDING closed/declined ones
 *     that never reach the published feed. (yaml uniqueKeys: we filed
 *     GHSA-3g7m-p75x-hpf6, the maintainer declined it as "perf, not security".)
 *   - `repo_issue`     — the target repo's own open/closed security issue or PR,
 *     usually another researcher. (js-yaml stack DoS == nodeca/js-yaml#739.)
 *   - `known`          — carried on the finding from an earlier stage.
 */
export type AdvisorySource = "global" | "own_submission" | "repo_issue" | "known";

/**
 * Disposition of a matching advisory / prior report. Distinguishes the cases
 * that decide the verdict:
 *
 *   - `patched`   — fixed upstream at `patchedVersion`. The classic duplicate.
 *   - `open`      — known but unpatched (still live upstream). Not a clean dup.
 *   - `declined`  — the maintainer waved it off (e.g. "performance, not a
 *     security issue"). Re-pitching it is a credibility hit → treat as
 *     by-design, NEVER as a novel send or a fix-bypass.
 *   - `withdrawn` — advisory was withdrawn/rejected; treated like `open`.
 */
export type AdvisoryStatus = "patched" | "open" | "declined" | "withdrawn";

/** A matching advisory or prior report (global DB, our own, or a repo issue). */
export interface AdvisoryRef {
  /** Advisory id / issue ref, e.g. "GHSA-3pj2-wmw4-qpcx", "nodeca/js-yaml#739". */
  id: string;
  /** First version that fixed the advisory, if known (semver string). */
  patchedVersion?: string;
  /** Short summary, used only for the reason string. */
  summary?: string;
  /** Where this match came from. Defaults to `global` when unset. */
  source?: AdvisorySource;
  /**
   * Disposition of the match. When unset, it is inferred: `patchedVersion`
   * present → `patched`, otherwise `open`. An explicit `declined` is the
   * maintainer-waved-off case and overrides everything (→ by_design).
   */
  status?: AdvisoryStatus;
}

/**
 * Injectable seams + facts the layer needs. Everything that would otherwise hit
 * the network is a function here so tests can stub it. All are optional; a
 * missing seam means "couldn't determine" and the layer stays conservative.
 */
export interface PublishabilityInputs {
  /**
   * Fetch the target repo's SECURITY.md / security policy text. Inject to avoid
   * network in tests. Return null when no policy is found.
   */
  fetchSecurityPolicy?: (
    packageName: string,
  ) => Promise<string | null>;
  /**
   * Look up advisories covering this package + vulnerability class in the
   * global advisory DB (npm: GHSA advisories; others: OSV). Inject to avoid
   * network in tests. Return [] when nothing matches.
   *
   * Source 1 of the dedup gap (published GHSA/OSV/CVE).
   */
  lookupAdvisories?: (
    packageName: string,
    category: string,
  ) => Promise<AdvisoryRef[]>;
  /**
   * Look up OUR OWN prior submissions for this package — including the
   * closed/declined/duplicate ones that never reach the published GHSA/OSV
   * feed. Inject to avoid network in tests. Return [] when nothing matches.
   *
   * Source 2 of the dedup gap. Refs should carry `source: "own_submission"`
   * and, when the maintainer waved it off, `status: "declined"`.
   */
  lookupOwnSubmissions?: (
    packageName: string,
    category: string,
  ) => Promise<AdvisoryRef[]>;
  /**
   * Look up the target repo's own open AND closed security issues / PRs that
   * already cover this class (usually another researcher). Inject to avoid
   * network in tests. Return [] when nothing matches.
   *
   * Source 3 of the dedup gap. Refs should carry `source: "repo_issue"`.
   */
  lookupRepoIssues?: (
    packageName: string,
    category: string,
  ) => Promise<AdvisoryRef[]>;
  /**
   * Pre-supplied advisory refs (e.g. carried on the finding from an earlier
   * stage). Merged with the lookup-seam results.
   */
  knownAdvisoryRefs?: AdvisoryRef[];
  /** The latest published version of the package, if known. */
  latestVersion?: string;
  /**
   * Whether our PoC was confirmed to reproduce on `latestVersion`. When true
   * and an advisory exists, the verdict is `fix_bypass`, NOT `duplicate`.
   */
  reproducesOnLatest?: boolean;
  /**
   * Whether the vulnerable sink is reachable through a documented, exported
   * public API (vs. dead / unexported / test-only code). When explicitly
   * false, the verdict is `unreachable`.
   */
  publicApiReachable?: boolean;
}

// ────────────────────────────────────────────────────────────────────
// Check 1 — threat-model / by-design (SECURITY.md exclusions)
// ────────────────────────────────────────────────────────────────────

/**
 * Patterns that, when present in a SECURITY.md / policy, disclaim
 * untrusted-input bugs. Build tools, template engines, and expression
 * evaluators routinely state "input is the caller's responsibility" — a
 * reproducible bug under that model is by-design, not a vulnerability.
 *
 * Each pattern is matched case-insensitively against the policy text.
 */
const THREAT_MODEL_EXCLUSION_PATTERNS: ReadonlyArray<{ re: RegExp; label: string }> = [
  {
    re: /untrusted\s+(input|config|configuration|template|code|data)\b/i,
    label: "policy disclaims untrusted input",
  },
  {
    re: /not\s+(intended|designed|meant)\s+to\s+(run|execute|process|handle)\s+untrusted/i,
    label: "policy: not designed to run untrusted input",
  },
  {
    re: /\b(caller|user|consumer)('s)?\s+responsib(le|ility)\b/i,
    label: "policy: input safety is the caller's responsibility",
  },
  {
    re: /do(\s+|n['’]?t\s+)not\s+(run|execute|use|pass).{0,40}untrusted/i,
    label: "policy: do not run on untrusted input",
  },
  {
    re: /\b(trusted\s+input\s+only|assumes?\s+trusted\s+input)\b/i,
    label: "policy: trusted input only",
  },
  {
    re: /arbitrary\s+code\s+execution.{0,40}(by\s+design|expected|intended|not\s+a\s+vuln)/i,
    label: "policy: code execution is by design",
  },
];

export interface ThreatModelResult {
  /** True when the policy disclaims this finding's input class. */
  excluded: boolean;
  /** The matched exclusion label, when `excluded`. */
  exclusion?: string;
}

/**
 * Decide whether a SECURITY.md / policy text disclaims this finding's class as
 * by-design. Pure + synchronous so it is trivially testable; the async fetch
 * lives in {@link checkPublishability} via the injected seam.
 */
export function checkThreatModelExclusion(policyText: string | null | undefined): ThreatModelResult {
  if (!policyText) return { excluded: false };
  for (const { re, label } of THREAT_MODEL_EXCLUSION_PATTERNS) {
    if (re.test(policyText)) {
      return { excluded: true, exclusion: label };
    }
  }
  return { excluded: false };
}

// ────────────────────────────────────────────────────────────────────
// Check 2 — dedup vs the global advisory DB (+ fix-bypass exception)
// ────────────────────────────────────────────────────────────────────

export type DedupVerdict = "novel" | "duplicate" | "fix_bypass" | "declined";

export interface DedupResult {
  verdict: DedupVerdict;
  /** Advisory ids that matched. */
  refs: string[];
  reason: string;
}

/** Resolve the disposition of an advisory ref, inferring from patchedVersion. */
function refStatus(a: AdvisoryRef): AdvisoryStatus {
  if (a.status) return a.status;
  return a.patchedVersion !== undefined ? "patched" : "open";
}

/**
 * Decide dedup status given the matched advisories and whether our PoC
 * reproduces on the latest version.
 *
 * The critical distinction (issue #539 acceptance criterion):
 *   - advisory exists AND latest is patched AND we do NOT reproduce on latest
 *     → `duplicate` (formidable, QEMU): already covered, drop.
 *   - advisory exists BUT our PoC reproduces on the LATEST published version
 *     → `fix_bypass` (unzipper, mathjs, pug): the fix is incomplete, this is a
 *     NEW disclosure-worthy finding. Must NOT be dropped as a duplicate.
 *   - no advisory → `novel` (let later checks / verify decide).
 *
 * `reproducesOnLatest` is the deciding bit. We require an *explicit* true to
 * upgrade to fix_bypass; an unknown (undefined) reproduces-on-latest with a
 * patched advisory stays `duplicate` (conservative drop), while a finding with
 * no patched version recorded is treated as still-open and kept as `novel`
 * unless reproduction on latest is confirmed.
 */
export function classifyDedup(
  advisories: ReadonlyArray<AdvisoryRef>,
  reproducesOnLatest: boolean | undefined,
): DedupResult {
  if (advisories.length === 0) {
    return { verdict: "novel", refs: [], reason: "no matching advisory in global DB" };
  }
  const refs = advisories.map((a) => a.id);

  // 0. maintainer-DECLINED wins over everything. If we (or anyone) already
  //    pitched this and the maintainer waved it off ("perf, not security"),
  //    re-pitching is a pure credibility hit — even if it reproduces on latest.
  //    (yaml uniqueKeys: we filed GHSA-3g7m-p75x-hpf6, eemeli declined as perf.)
  const declined = advisories.filter(
    (a) => refStatus(a) === "declined" || refStatus(a) === "withdrawn",
  );
  if (declined.length > 0) {
    const declinedRefs = declined.map((a) => a.id);
    return {
      verdict: "declined",
      refs,
      reason: `already reported and waved off by the maintainer (${declinedRefs.join(", ")}) — do not re-pitch`,
    };
  }

  // A "prior report" is anything someone has already filed: our own submission
  // or the target repo's own security issue/PR. Reproducing on latest does NOT
  // make a prior report a fix-bypass — it's still a known, in-flight report and
  // re-filing it duplicates another tracker. Fix-bypass is reserved for a
  // PUBLISHED, PATCHED advisory whose fix our PoC defeats on latest.
  const priorReports = advisories.filter(
    (a) => a.source === "own_submission" || a.source === "repo_issue",
  );
  const publishedPatched = advisories.filter(
    (a) =>
      (a.source === undefined || a.source === "global" || a.source === "known") &&
      refStatus(a) === "patched",
  );

  // 1. fix_bypass — a published, patched advisory whose fix our PoC still
  //    defeats on the LATEST published version. The valuable exception.
  //    (unzipper: GHSA-884w-698f-927f patched 0.8.13, still reproduces on 0.12.3.)
  if (reproducesOnLatest === true && publishedPatched.length > 0) {
    return {
      verdict: "fix_bypass",
      refs,
      reason: `published patched advisory exists (${publishedPatched
        .map((a) => a.id)
        .join(", ")}) but PoC reproduces on the latest published version — fix is incomplete (fix-bypass)`,
    };
  }

  // 2. duplicate — a prior report exists (ours or the repo's), OR a published
  //    advisory is patched and we do NOT defeat it on latest.
  //    (formidable: GHSA-3pj2-wmw4-qpcx patched; js-yaml: nodeca/js-yaml#739.)
  if (priorReports.length > 0) {
    return {
      verdict: "duplicate",
      refs,
      reason: `already tracked by a prior report (${priorReports
        .map((a) => a.id)
        .join(", ")}) — duplicate of an existing issue/submission`,
    };
  }
  if (publishedPatched.length > 0) {
    return {
      verdict: "duplicate",
      refs,
      reason: `covered by patched advisory (${publishedPatched
        .map((a) => a.id)
        .join(", ")}); does not reproduce on latest`,
    };
  }

  // 3. Advisory exists but is open/unpatched and there is no prior report →
  //    still live upstream. Not a clean duplicate-of-fixed; let verify decide.
  return {
    verdict: "novel",
    refs,
    reason: `advisory exists (${refs.join(", ")}) but no patched version recorded — treated as still-open, not a dup`,
  };
}

// ────────────────────────────────────────────────────────────────────
// Check 3 — latest-version predicate
// ────────────────────────────────────────────────────────────────────

/**
 * Whether the version we reproduced on IS the latest published version. When a
 * finding only reproduces on an old version (e.g. vm2 pre-patch), it is
 * `fixed` upstream and not disclosure-worthy. Returns undefined when the latest
 * version is unknown (conservative — caller keeps the finding).
 */
export function isLatestVersion(
  reproducedVersion: string | undefined,
  latestVersion: string | undefined,
): boolean | undefined {
  if (!reproducedVersion || !latestVersion) return undefined;
  return normalizeVersion(reproducedVersion) === normalizeVersion(latestVersion);
}

function normalizeVersion(v: string): string {
  return v.trim().replace(/^[v=^~]+/, "");
}

// ────────────────────────────────────────────────────────────────────
// Check 4 — public-API reachability predicate
// ────────────────────────────────────────────────────────────────────

/**
 * Whether the vulnerable sink is reachable through a documented, exported
 * public API. The node-forge form.js burn was dead, unexported jQuery code:
 * reproducible in a unit harness but unreachable through any supported API.
 *
 * Returns the explicit `publicApiReachable` input; undefined means "couldn't
 * determine" and the caller keeps the finding (conservative).
 */
export function isPublicApiReachable(publicApiReachable: boolean | undefined): boolean | undefined {
  return publicApiReachable;
}

// ────────────────────────────────────────────────────────────────────
// Orchestrator — checkPublishability
// ────────────────────────────────────────────────────────────────────

/**
 * Run the publishability checks in priority order and return a single verdict.
 *
 * Order matters: `fix_bypass` is checked *inside* dedup so it can never be
 * masked by a `duplicate`. Threat-model `by_design` is checked first because a
 * by-design exclusion makes the rest moot (the maintainer won't take it however
 * reachable / novel it is). Then dedup (duplicate / fix_bypass), then
 * latest-version (`fixed`), then reachability (`unreachable`). If nothing fires,
 * the finding is `in_scope`.
 *
 * Network is performed only via the injected seams on `inputs`; with no seams
 * and no facts the function is fully synchronous-equivalent and returns
 * `in_scope` (zero behaviour change for callers that don't opt in).
 */
export async function checkPublishability(
  finding: Finding,
  packageName: string,
  version: string,
  inputs: PublishabilityInputs = {},
): Promise<PublishabilityResult> {
  // ── 1. threat-model / by-design ──
  let policyText: string | null = null;
  if (inputs.fetchSecurityPolicy) {
    try {
      policyText = await inputs.fetchSecurityPolicy(packageName);
    } catch {
      policyText = null; // network failure → couldn't determine, stay conservative
    }
  }
  const tm = checkThreatModelExclusion(policyText);
  if (tm.excluded) {
    return {
      decision: "by_design",
      confidence: 0.85,
      reason: `${packageName} SECURITY.md disclaims this class: ${tm.exclusion}`,
      threatModelExclusion: tm.exclusion,
    };
  }

  // ── 2. dedup (duplicate / fix_bypass / declined) ──
  // Gather from all four sources (issue #537 / #539 dedup gap):
  //   knownAdvisoryRefs (carried) + lookupAdvisories (global GHSA/OSV/CVE) +
  //   lookupOwnSubmissions (our prior reports incl. declined) +
  //   lookupRepoIssues (the repo's own open/closed security issues/PRs).
  // Each seam is independent and fail-soft — a thrown / missing seam degrades
  // the merged view but never throws, so a network blip can't drop a finding.
  const advisories: AdvisoryRef[] = [
    ...(inputs.knownAdvisoryRefs ?? []).map((a) => ({ source: "known" as const, ...a })),
  ];
  const mergeRefs = (refs: AdvisoryRef[]): void => {
    for (const a of refs) {
      // Same id from two sources: keep the first but upgrade its status to the
      // more decisive one (declined/withdrawn > patched) so a maintainer-decline
      // on our own report is never masked by a benign global entry.
      const existing = advisories.find((e) => e.id === a.id);
      if (!existing) {
        advisories.push(a);
        continue;
      }
      if (
        (a.status === "declined" || a.status === "withdrawn") &&
        existing.status !== "declined" &&
        existing.status !== "withdrawn"
      ) {
        existing.status = a.status;
      }
    }
  };
  const seams: Array<(p: string, c: string) => Promise<AdvisoryRef[]>> = [
    ...(inputs.lookupAdvisories ? [inputs.lookupAdvisories] : []),
    ...(inputs.lookupOwnSubmissions ? [inputs.lookupOwnSubmissions] : []),
    ...(inputs.lookupRepoIssues ? [inputs.lookupRepoIssues] : []),
  ];
  if (seams.length > 0) {
    const results = await Promise.allSettled(
      seams.map((seam) => seam(packageName, finding.category)),
    );
    for (const r of results) {
      // A rejected seam → that source is unavailable; fall back to the rest.
      if (r.status === "fulfilled") mergeRefs(r.value);
    }
  }
  const dedup = classifyDedup(advisories, inputs.reproducesOnLatest);
  if (dedup.verdict === "declined") {
    // Maintainer already waved this off. It is by-design for THIS maintainer —
    // they will not take it however reachable or reproducible it is. Surface
    // the refs so the operator can see it was our own / a prior report.
    return {
      decision: "by_design",
      confidence: 0.9,
      reason: dedup.reason,
      threatModelExclusion: "maintainer declined a prior report of this class",
      dedupRefs: dedup.refs,
    };
  }
  if (dedup.verdict === "fix_bypass") {
    return {
      decision: "fix_bypass",
      confidence: 0.8,
      reason: dedup.reason,
      dedupRefs: dedup.refs,
      latestVersionFixed: false,
    };
  }
  if (dedup.verdict === "duplicate") {
    return {
      decision: "duplicate",
      confidence: 0.85,
      reason: dedup.reason,
      dedupRefs: dedup.refs,
      latestVersionFixed: true,
    };
  }

  // ── 3. latest-version (`fixed`) ──
  const onLatest = isLatestVersion(version, inputs.latestVersion);
  if (onLatest === false) {
    return {
      decision: "fixed",
      confidence: 0.75,
      reason: `reproduced on ${version} but latest published is ${inputs.latestVersion} — likely fixed upstream`,
      latestVersionFixed: true,
    };
  }

  // ── 4. reachability (`unreachable`) ──
  const reachable = isPublicApiReachable(inputs.publicApiReachable);
  if (reachable === false) {
    return {
      decision: "unreachable",
      confidence: 0.8,
      reason: "sink is not reachable through any documented/exported public API (dead or unexported code)",
      publicApiReachable: false,
    };
  }

  // ── default — in scope ──
  return {
    decision: "in_scope",
    confidence: 0.6,
    reason:
      advisories.length > 0
        ? `no by-design exclusion; advisory present (${dedup.refs.join(", ")}) but not a clean duplicate-of-fixed; reachable on a supported version`
        : "no by-design exclusion, no covering advisory, reachable on a supported version",
    ...(advisories.length > 0 ? { dedupRefs: dedup.refs } : {}),
    ...(reachable === true ? { publicApiReachable: true } : {}),
    ...(onLatest === true ? { latestVersionFixed: false } : {}),
  };
}

/**
 * Verdicts that mean "green to file." Everything else is a hold or drop. The
 * pre-file gate (issue #537) consumes this.
 */
export const PUBLISHABLE_DECISIONS: ReadonlySet<PublishabilityDecision> = new Set<PublishabilityDecision>([
  "in_scope",
  "fix_bypass",
]);

/** True when a publishability decision means the finding is worth filing. */
export function isPublishable(decision: PublishabilityDecision): boolean {
  return PUBLISHABLE_DECISIONS.has(decision);
}

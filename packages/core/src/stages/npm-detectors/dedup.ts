/**
 * Shared novelty gate for npm dynamic-discovery. Baked into `base.ts` so EVERY
 * detector inherits it — a confirmed pollution/bypass/divergence is only
 * eligible for disclosure when it is `novel && confirmed`.
 *
 * Three layers, cheapest first (the exact lesson the sspp prototype encoded
 * after `npm audit` alone missed the `radash` fork-twin of CVE-2025-48054):
 *   1. **prior-report** — packages 0sec already filed for this class.
 *   2. **fork-cve-twin** — packages whose vulnerable code is identical to a
 *      sibling/fork carrying a PUBLIC advisory but with NO advisory under their
 *      own npm name (so a live advisory DB gives a false all-clear).
 *   3. **live advisory lookup** — OSV / npm advisory DB, injected as a seam
 *      (`AdvisoryLookup`) so the pure dedup logic stays deterministic and
 *      testable. When no lookup is wired we do NOT claim novelty blindly: the
 *      verdict is `novel` with `source: "unknown"` recorded, signalling the
 *      online check was skipped (the promotion gate treats that as
 *      possibly-known, mirroring the engine's `noveltyVerdict` semantics).
 */

import type { DedupHints, DedupVerdict } from "./types.js";

/**
 * Injected live-advisory lookup. Returns advisory references (CVE/GHSA/OSV ids)
 * that cover `name@version` for the given CWE, or `[]` when none are found.
 * In production this is an OSV.dev query; in tests it is a stub map. Keeping it
 * injectable is what lets the confirm+dedup path be exercised hermetically.
 */
export type AdvisoryLookup = (
  name: string,
  version: string | undefined,
  cwe: string,
) => Promise<string[]> | string[];

/** Normalise a hints record's fork-twin key lookup (case-sensitive npm names). */
function forkTwinFor(hints: DedupHints | undefined, name: string): string | undefined {
  return hints?.forkTwins?.[name];
}

export async function dedupConfirmation(args: {
  name: string;
  version?: string;
  cwe: string;
  hints?: DedupHints;
  advisoryLookup?: AdvisoryLookup;
}): Promise<DedupVerdict> {
  const { name, version, cwe, hints, advisoryLookup } = args;

  // 1. prior 0sec report for this class.
  if (hints?.priorReports?.includes(name)) {
    return {
      novel: false,
      source: "prior-report",
      advisories: [`${name}: previously reported by 0sec for this class`],
    };
  }

  // 2. fork-cve-twin: real bug, but maps to a known CVE under a sibling name.
  const twin = forkTwinFor(hints, name);
  if (twin) {
    return { novel: false, source: "fork-cve-twin", advisories: [`${name}: ${twin}`] };
  }

  // 3. live advisory DB (injected). No lookup wired ⇒ don't claim blind novelty.
  if (!advisoryLookup) {
    return { novel: true, source: "unknown", advisories: [] };
  }
  // Fail CLOSED: a lookup that throws (rate-limit / timeout / non-2xx /
  // malformed) must NOT be read as "no advisory found" (which would be a blind
  // novelty claim). It resolves to `unknown` — identical to the offline path,
  // i.e. possibly-known — so a transient network fault can never manufacture a
  // false novel. Only a lookup that SUCCEEDS with zero advisories is `novel`.
  let advisories: string[];
  try {
    advisories = await advisoryLookup(name, version, cwe);
  } catch (e) {
    return {
      novel: true,
      source: "unknown",
      advisories: [`advisory-lookup-failed: ${e instanceof Error ? e.message.split("\n")[0] : String(e)}`],
    };
  }
  if (advisories.length > 0) {
    return { novel: false, source: "osv", advisories };
  }
  return { novel: true, source: "novel", advisories: [] };
}

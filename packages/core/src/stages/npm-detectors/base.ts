/**
 * Shared detector discipline. `runDetectorOnPackage` is the ONLY sanctioned way
 * the stage invokes a detector, so the three non-negotiables live here and
 * every registered detector inherits them:
 *
 *   1. **Downloads-floor / freshness guard** — prefer big + fresh packages and
 *      skip the long tail, so a sweep can't be turned into credit-farming a
 *      thousand no-download packages (the operator's explicit calibration).
 *   2. **Assume-FP** — a candidate becomes a confirmation ONLY when the
 *      detector observed a runtime consequence (`confirmed && observation`).
 *      Anything else is dropped, never emitted.
 *   3. **Dedup** — every confirmation runs the shared novelty gate (`./dedup`)
 *      combining the detector's fork-twin / prior-report hints with the live
 *      advisory lookup, so only `novel && confirmed` reaches disclosure.
 */

import type { AdvisoryLookup } from "./dedup.js";
import { dedupConfirmation } from "./dedup.js";
import type {
  DedupVerdict,
  Detector,
  DetectorCandidate,
  DetectorConfirmation,
  PackageProbe,
  PackageRef,
} from "./types.js";

/** Downloads-floor + freshness calibration. All fields optional (open by default). */
export interface DiscoveryGuards {
  /** Skip packages below this weekly-download floor. Default: no floor. */
  downloadsFloor?: number;
  /**
   * Skip packages whose last publish is older than this many days ("stale
   * long-tail" guard). Default: no max age. A package with no `lastPublishedAt`
   * is NOT skipped on freshness (unknown ≠ stale).
   */
  maxAgeDays?: number;
}

export interface GuardVerdict {
  allowed: boolean;
  reason?: string;
}

/** Apply the downloads-floor / freshness guard to a package. */
export function guardPackage(pkg: PackageRef, guards: DiscoveryGuards | undefined, now = Date.now()): GuardVerdict {
  if (!guards) return { allowed: true };
  if (
    guards.downloadsFloor !== undefined &&
    pkg.weeklyDownloads !== undefined &&
    pkg.weeklyDownloads < guards.downloadsFloor
  ) {
    return {
      allowed: false,
      reason: `weeklyDownloads ${pkg.weeklyDownloads} < floor ${guards.downloadsFloor}`,
    };
  }
  if (guards.maxAgeDays !== undefined && pkg.lastPublishedAt) {
    const published = Date.parse(pkg.lastPublishedAt);
    if (Number.isFinite(published)) {
      const ageDays = (now - published) / 86_400_000;
      if (ageDays > guards.maxAgeDays) {
        return { allowed: false, reason: `last publish ${Math.round(ageDays)}d ago > maxAgeDays ${guards.maxAgeDays}` };
      }
    }
  }
  return { allowed: true };
}

/** A single confirmed lead: the confirmation + its novelty verdict + provenance. */
export interface DetectorLead {
  detectorId: string;
  candidateId: string;
  confirmation: DetectorConfirmation;
  dedup: DedupVerdict;
}

export interface DetectorRunOutcome {
  detectorId: string;
  /** `false` when the guard or `appliesTo` skipped this detector for this pkg. */
  ran: boolean;
  skipReason?: string;
  /** How many candidates `identifyCandidates` surfaced. */
  candidates: number;
  /** Confirmed + deduped leads (assume-FP already applied). */
  leads: DetectorLead[];
  warnings: string[];
}

/**
 * Run one detector against one package probe, applying the shared discipline.
 * Never throws — a broken candidate is a warning, not a crash, so one bad
 * package can't sink a sweep.
 */
export async function runDetectorOnPackage<C extends DetectorCandidate>(
  detector: Detector<C>,
  probe: PackageProbe,
  opts: { guards?: DiscoveryGuards; advisoryLookup?: AdvisoryLookup; now?: number } = {},
): Promise<DetectorRunOutcome> {
  const warnings: string[] = [];
  const base: DetectorRunOutcome = {
    detectorId: detector.id,
    ran: false,
    candidates: 0,
    leads: [],
    warnings,
  };

  // Guard 1: downloads-floor / freshness.
  const guard = guardPackage(probe.pkg, opts.guards, opts.now);
  if (!guard.allowed) return { ...base, skipReason: `guard: ${guard.reason}` };

  // Cheap static relevance gate.
  let applies = false;
  try {
    applies = detector.appliesTo(probe.pkg);
  } catch (e) {
    warnings.push(`appliesTo threw: ${errMsg(e)}`);
  }
  if (!applies) return { ...base, skipReason: "appliesTo=false" };

  base.ran = true;

  // Deterministic candidate enumeration.
  let candidates: C[] = [];
  try {
    candidates = await detector.identifyCandidates(probe);
  } catch (e) {
    warnings.push(`identifyCandidates threw: ${errMsg(e)}`);
    return base;
  }
  base.candidates = candidates.length;

  // Confirm each candidate — assume-FP + dedup.
  for (const cand of candidates) {
    let conf: DetectorConfirmation;
    try {
      conf = await detector.confirm(cand, probe);
    } catch (e) {
      warnings.push(`confirm(${cand.id}) threw: ${errMsg(e)}`);
      continue;
    }
    // Assume-FP: require BOTH the boolean AND a non-empty observed consequence.
    if (!conf.confirmed || !conf.evidence?.observation) continue;

    const dedup = await dedupConfirmation({
      name: probe.pkg.name,
      version: probe.pkg.version,
      cwe: detector.cwe,
      hints: detector.dedupHints,
      advisoryLookup: opts.advisoryLookup,
    });

    base.leads.push({
      detectorId: detector.id,
      candidateId: cand.id,
      confirmation: {
        ...conf,
        severity: conf.severity ?? detector.severityFloor,
        source: conf.source ?? cand.label,
      },
      dedup,
    });
  }

  return base;
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message.split("\n")[0].slice(0, 120) : String(e);
}

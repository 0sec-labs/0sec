/**
 * npm-ecosystem dynamic-discovery stage.
 *
 * A discovery stage — sibling of `runHuntScan` (the kernel/Web3 variant-hunt),
 * scoped to the JS/npm ecosystem. It hosts pluggable DETECTORS
 * (`./npm-detectors/`): each identifies candidates from a package's surface,
 * runs a deterministic harness in isolation, and CONFIRMS only on an observed
 * runtime consequence (assume-FP). Confirmed + novel leads are emitted as the
 * canonical `Finding` shape so they flow into the existing
 * findings → adversarial-verify → disclosure path unchanged.
 *
 * This module does NO install and NO network itself — it drives an injected
 * `probeFactory` (the execution-isolation seam: in production a sandbox exec
 * that `npm install --ignore-scripts` in a throwaway dir; on a trusted host the
 * `inProcessProbe`). Keeping install/transport out of this module is what keeps
 * it small and testable, per the repo's stop-the-god-module principle.
 *
 * See `docs/operations/sspp-dynamic-miner-design.md` (what shipped) and
 * `docs/operations/detector-from-finding.md` (adding a detector).
 */

import { randomUUID } from "node:crypto";
import type { Finding, Severity } from "@0sec/shared";
import type { AdvisoryLookup } from "./npm-detectors/dedup.js";
import { runDetectorOnPackage, type DetectorLead, type DetectorRunOutcome, type DiscoveryGuards } from "./npm-detectors/base.js";
import { getDetectorById, resolveDetectors, type AnyDetector } from "./npm-detectors/registry.js";
import type { NpmPackageRunner } from "./npm-detectors/sandbox-probe.js";
import type { PackageProbe, PackageRef } from "./npm-detectors/types.js";

export interface NpmDynamicDiscoveryOptions {
  /** Packages to sweep (worklist). Curate fresh/fork lineages, not the tail. */
  worklist: PackageRef[];
  /**
   * The in-process isolation seam: return an execution probe for a package
   * (`inProcessProbe` — modules `require`d into THIS process), or `undefined`
   * when the package can't be prepared (skipped with a warning — never a
   * fabricated finding). This runs untrusted code in-process, so it is the
   * trusted-host / hermetic-test path. Exactly one of `probeFactory` or
   * {@link packageRunner} must be provided.
   */
  probeFactory?: (pkg: PackageRef) => Promise<PackageProbe | undefined> | PackageProbe | undefined;
  /**
   * The PRODUCTION isolation seam: run a package's full detector sweep in a
   * disposable sandbox (separate process / e2b) and return the per-detector
   * outcomes, or `undefined` when the package could not be prepared/executed
   * (skipped — never a fabricated finding). When set this takes precedence over
   * `probeFactory`, so untrusted package code never executes in this process.
   * See {@link ./npm-detectors/sandbox-probe.ts createSandboxPackageRunner}.
   */
  packageRunner?: NpmPackageRunner;
  /** Restrict to these detector ids. Empty/undefined ⇒ the full registry. */
  detectorIds?: string[];
  /** Downloads-floor / freshness guard (prefer big + fresh; skip the long tail). */
  guards?: DiscoveryGuards;
  /** Live advisory lookup (OSV/npm) for the dedup step. Omit ⇒ dedup is offline. */
  advisoryLookup?: AdvisoryLookup;
  /** Max packages processed concurrently. Default 1 (proto-isolation-safe). */
  concurrency?: number;
  /** Incremental persistence: called the moment a novel finding is confirmed. */
  onConfirmed?: (finding: Finding) => void | Promise<void>;
  log?: (msg: string) => void;
}

export interface DetectorStat {
  detectorId: string;
  packagesRun: number;
  candidates: number;
  confirmed: number;
  novel: number;
}

export interface NpmDynamicDiscoveryResult {
  /** Every confirmed lead promoted to a finding (novel AND known). */
  findings: Finding[];
  /** The novel subset — the disclosure-eligible findings. */
  novel: Finding[];
  /** Confirmed leads the dedup step ruled non-novel (courtesy / hygiene items). */
  known: Finding[];
  /** Packages that could not be prepared by `probeFactory`. */
  unpreparable: string[];
  /** Detector ids requested but not in the registry. */
  unknownDetectors: string[];
  scannedPackages: number;
  perDetector: DetectorStat[];
  warnings: string[];
}

/**
 * Promote a confirmed+deduped detector lead to the canonical `Finding` shape.
 * Mirrors `memsafety-scan.ts:crashArtifactToFinding` field semantics so every
 * existing renderer / sink / DB round-trip / verify / disclosure path works.
 */
export function leadToFinding(pkg: PackageRef, detector: AnyDetector, lead: DetectorLead): Finding {
  const conf = lead.confirmation;
  const severity: Severity = conf.severity ?? detector.severityFloor;
  const novel = lead.dedup.novel;
  const versionLabel = pkg.version ? `@${pkg.version}` : "";

  const escalation = conf.evidence.escalation;
  const description = [
    `${detector.title} confirmed in npm package ${pkg.name}${versionLabel}.`,
    `Class: ${detector.cwe} (${detector.category}).`,
    `Observed consequence: ${conf.evidence.observation}`,
    escalation ? `Escalation ${escalation.kind}: ${escalation.achieved ? "ACHIEVED" : "not achieved"}${escalation.note ? ` (${escalation.note})` : ""}.` : "",
    novel
      ? "Novelty: no live advisory / fork-twin / prior report matched (disclosure-eligible)."
      : `Novelty: NON-novel — ${lead.dedup.source} (${lead.dedup.advisories.join("; ")}).`,
  ]
    .filter(Boolean)
    .join("\n");

  const analysis = [
    `Detector: ${detector.id}`,
    `Candidate/source: ${conf.source ?? lead.candidateId}`,
    `Severity: ${severity}`,
    pkg.weeklyDownloads !== undefined ? `Weekly downloads: ${pkg.weeklyDownloads}` : "",
    "",
    "---observed consequence (assume-FP: this is the runtime fact)---",
    conf.evidence.observation,
    conf.evidence.analysis ? `\n${conf.evidence.analysis}` : "",
    "",
    "---dedup---",
    `novel=${novel} source=${lead.dedup.source}`,
    ...lead.dedup.advisories.map((a) => `  ${a}`),
  ]
    .filter(Boolean)
    .join("\n");

  return {
    id: randomUUID(),
    templateId: `npm-dynamic-${detector.id}`,
    title: `${detector.title} in ${pkg.name}${versionLabel}`,
    description,
    severity,
    category: detector.category,
    status: "discovered",
    evidence: {
      request: conf.evidence.payload ?? `${detector.id} candidate ${lead.candidateId}`,
      response: conf.evidence.observation,
      analysis,
    },
    fingerprint: `npm-dynamic:${detector.id}:${pkg.name}:${conf.source ?? lead.candidateId}`,
    // A runtime-observed consequence is a high-confidence lead; the shared
    // adversarial-verify stage re-runs it at the publication bar regardless.
    confidence: 0.85,
    noveltyVerdict: novel ? "novel" : "possibly-known",
    dedupRefs: lead.dedup.advisories,
    timestamp: Date.now(),
  };
}

async function pool<T>(items: T[], limit: number, fn: (item: T, i: number) => Promise<void>): Promise<void> {
  let next = 0;
  const n = Math.max(1, Math.min(limit, items.length || 1));
  const workers = Array.from({ length: n }, async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      await fn(items[i], i);
    }
  });
  await Promise.all(workers);
}

/** Run the npm dynamic-discovery sweep over the worklist. Never throws per-package. */
export async function runNpmDynamicDiscovery(opts: NpmDynamicDiscoveryOptions): Promise<NpmDynamicDiscoveryResult> {
  const log = opts.log ?? (() => {});
  if (!opts.packageRunner && !opts.probeFactory) {
    throw new Error("runNpmDynamicDiscovery: provide a packageRunner (sandbox) or a probeFactory (in-process)");
  }
  const { detectors, unknown: unknownDetectors } = resolveDetectors(opts.detectorIds);
  for (const u of unknownDetectors) log(`WARN unknown detector id "${u}" — skipped`);

  const findings: Finding[] = [];
  const novel: Finding[] = [];
  const known: Finding[] = [];
  const unpreparable: string[] = [];
  const warnings: string[] = [];
  const statById = new Map<string, DetectorStat>();
  for (const d of detectors) statById.set(d.id, { detectorId: d.id, packagesRun: 0, candidates: 0, confirmed: 0, novel: 0 });

  // Promote one detector's outcome for one package into findings + stats. Shared
  // by both isolation seams so the finding-emit / novelty-split / onConfirmed
  // flywheel is byte-identical whether the sweep ran in-process or in a sandbox.
  const promote = async (pkg: PackageRef, detector: AnyDetector, outcome: DetectorRunOutcome): Promise<void> => {
    for (const w of outcome.warnings) warnings.push(`${pkg.name}/${detector.id}: ${w}`);
    const stat = statById.get(detector.id);
    if (!stat) return; // detector id not in this run's set — ignore defensively
    if (outcome.ran) stat.packagesRun += 1;
    stat.candidates += outcome.candidates;

    for (const lead of outcome.leads) {
      stat.confirmed += 1;
      const finding = leadToFinding(pkg, detector, lead);
      findings.push(finding);
      if (lead.dedup.novel) {
        stat.novel += 1;
        novel.push(finding);
        if (opts.onConfirmed) {
          try {
            await opts.onConfirmed(finding);
          } catch (e) {
            warnings.push(`onConfirmed(${finding.id}) threw: ${e instanceof Error ? e.message : String(e)}`);
          }
        }
      } else {
        known.push(finding);
      }
      log(`${lead.dedup.novel ? "NOVEL" : "known"} ${detector.id} ${pkg.name}: ${lead.confirmation.evidence.observation}`);
    }
  };

  await pool(opts.worklist, opts.concurrency ?? 1, async (pkg) => {
    // Production path: the sandbox runner installs + runs the detector cores in
    // an isolated disposable env and returns the outcomes. Untrusted code never
    // enters this process. `undefined` ⇒ unpreparable/inconclusive ⇒ skipped.
    if (opts.packageRunner) {
      let ran: Awaited<ReturnType<NpmPackageRunner>>;
      try {
        ran = await opts.packageRunner(pkg, detectors.map((d) => d.id));
      } catch (e) {
        ran = undefined;
        warnings.push(`${pkg.name}: packageRunner threw: ${e instanceof Error ? e.message : String(e)}`);
      }
      if (!ran) {
        unpreparable.push(pkg.name);
        log(`SKIP ${pkg.name}: sandbox could not prepare/execute (skipped, not confirmed)`);
        return;
      }
      for (const w of ran.warnings) warnings.push(`${pkg.name}: ${w}`);
      for (const outcome of ran.outcomes) {
        const detector = getDetectorById(outcome.detectorId);
        if (!detector) {
          warnings.push(`${pkg.name}: sandbox returned unknown detector "${outcome.detectorId}"`);
          continue;
        }
        await promote(pkg, detector, outcome);
      }
      return;
    }

    // In-process path: `probeFactory` prepares an isolated require-probe and the
    // detectors run in THIS process (trusted host / hermetic tests).
    let probe: PackageProbe | undefined;
    try {
      probe = await opts.probeFactory!(pkg);
    } catch (e) {
      probe = undefined;
      warnings.push(`${pkg.name}: probeFactory threw: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (!probe) {
      unpreparable.push(pkg.name);
      log(`SKIP ${pkg.name}: could not prepare execution probe`);
      return;
    }

    for (const detector of detectors) {
      const outcome = await runDetectorOnPackage(detector, probe, {
        guards: opts.guards,
        advisoryLookup: opts.advisoryLookup,
      });
      await promote(pkg, detector, outcome);
    }
  });

  return {
    findings,
    novel,
    known,
    unpreparable,
    unknownDetectors,
    scannedPackages: opts.worklist.length,
    perDetector: [...statById.values()],
    warnings,
  };
}

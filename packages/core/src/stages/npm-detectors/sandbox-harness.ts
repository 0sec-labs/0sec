/**
 * npm dynamic-discovery — the in-sandbox harness entrypoint.
 *
 * This file is NOT imported by the engine; it is spawned as a standalone Node
 * process INSIDE a disposable environment (a fresh temp dir on a trusted host,
 * or an e2b sandbox) by {@link ./sandbox-probe.ts createSandboxPackageRunner}.
 * Running the detector core out-of-process is the isolation boundary: the
 * `inProcessProbe` here `require`s the *untrusted* package and the detectors
 * actually invoke it, so any prototype pollution / side effect is confined to
 * THIS throwaway process — it can never touch the host pipeline's realm. This is
 * the faithful realization of the prototype's per-package `worker.js` model.
 *
 * Contract (stdin-free, argv-driven so it is trivial to spawn):
 *   argv[2] = JSON {
 *     installDir: string;            // dir the package is installed under (require base)
 *     pkg: PackageRef;               // name/version/downloads/etc.
 *     detectorIds?: string[];        // restrict to these; empty ⇒ full registry
 *     offlineDedup?: boolean;        // true ⇒ skip live OSV (hermetic/air-gapped)
 *   }
 *   stdout = exactly one JSON line: { outcomes: DetectorRunOutcome[]; warnings: string[] }
 *   exit 0 on success; non-zero on a harness fault (the runner treats that as
 *   "skip this package", never a fabricated confirmation).
 *
 * Dedup runs HERE (the sandbox has network): the harness constructs its own OSV
 * lookup unless `offlineDedup`. The fail-closed novelty semantics live in
 * `dedup.ts`, so a transient OSV fault resolves to `source:"unknown"`
 * (possibly-known), never a blind novel.
 */

import type { AdvisoryLookup } from "./dedup.js";
import { runDetectorOnPackage, type DetectorRunOutcome } from "./base.js";
import { resolveDetectors } from "./registry.js";
import { createOsvAdvisoryLookup } from "./osv-lookup.js";
import { inProcessProbe } from "./probe.js";
import type { PackageRef } from "./types.js";

interface HarnessConfig {
  installDir: string;
  pkg: PackageRef;
  detectorIds?: string[];
  offlineDedup?: boolean;
}

async function main(): Promise<void> {
  const raw = process.argv[2];
  if (!raw) throw new Error("sandbox-harness: missing config argument (argv[2])");
  const cfg = JSON.parse(raw) as HarnessConfig;
  if (!cfg.installDir || !cfg.pkg?.name) {
    throw new Error("sandbox-harness: config requires installDir and pkg.name");
  }

  const { detectors } = resolveDetectors(
    cfg.detectorIds && cfg.detectorIds.length ? cfg.detectorIds : undefined,
  );

  const warnings: string[] = [];
  const probe = inProcessProbe(cfg.pkg, cfg.installDir, (m) => warnings.push(`probe: ${m}`));
  const advisoryLookup: AdvisoryLookup | undefined = cfg.offlineDedup
    ? undefined
    : createOsvAdvisoryLookup();

  const outcomes: DetectorRunOutcome[] = [];
  for (const detector of detectors) {
    // `runDetectorOnPackage` never throws, but keep a belt around it so one
    // pathological detector can't sink the whole package (matches the stage).
    try {
      outcomes.push(await runDetectorOnPackage(detector, probe, { advisoryLookup }));
    } catch (e) {
      warnings.push(`${detector.id}: ${e instanceof Error ? e.message.split("\n")[0] : String(e)}`);
    }
  }

  // One JSON line on stdout — the runner parses the last `{…}` line, so any
  // stray require()-time logging on stdout by the untrusted package is tolerated.
  process.stdout.write(`\n${JSON.stringify({ outcomes, warnings })}\n`);
}

main().catch((e) => {
  process.stderr.write(`sandbox-harness fault: ${e instanceof Error ? e.stack ?? e.message : String(e)}\n`);
  process.exit(1);
});

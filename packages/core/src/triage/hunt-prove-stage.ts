/**
 * The PROVE stage as a PER-FINDING `HuntVerifier` — the missing adapter that
 * makes the kernel-VM exploitability oracle reachable from a real hunt.
 *
 * WHY this module exists (and why `makeKernelVmExploitabilityGate` could not be
 * wired directly): that factory binds its observation source at CONSTRUCTION
 * time — `KernelVmDiversifyRunnerDeps.reproducer` is a single string, and the
 * differential runner closes over one `buildExploit`. That shape is correct for
 * a one-bug PROVE run, but `runHuntScan` hands its gate MANY findings, each with
 * its OWN reproducer. Wiring the gate straight into `opts.exploitability` would
 * therefore boot every finding's oracle against the FIRST finding's reproducer
 * and silently attribute one bug's crash to another — the exact
 * false-attribution failure the oracle's canary binding exists to prevent.
 *
 * So this module constructs the gate ONCE PER FINDING, from that finding's own
 * reproducer and splat, and delegates to the existing
 * {@link makeExploitabilityGate} logic untouched. It adds no oracle semantics of
 * its own.
 *
 * INJECTION SEAM (load-bearing): `makeOracles` defaults to the REAL kernel-VM
 * oracles, which spawn QEMU. Every test in this repo passes a fake instead, so
 * the unit tests are fully offline. Do not remove the seam.
 *
 * HONESTY: a finding with no extractable reproducer is passed through
 * CONFIRMED-but-unproven rather than being rejected — the hunt's skeptic+prover
 * already confirmed it, and "we could not boot it" is not evidence against a bug.
 */

import type { CrashReport, Finding } from "@pwnkit/shared";
import type { HuntCandidate, HuntVerifier } from "../stages/hunt-scan.js";
import {
  makeExploitabilityGate,
  type DiversifyOracle,
  type DifferentialOracle,
  type EscalationPreGate,
  type ExploitabilityGateDeps,
  type ExploitabilityVerdict,
} from "./exploitability-upgrade.js";
import { makeKernelVmOracles, type KernelVmOraclesDeps } from "./exploitability-oracle-runner.js";
import { classifyPrimitiveFromDmesg, sniffCrashType } from "./kernel-primitive.js";
import type { EscalationVerdict } from "./escalation-gate.js";

/** The oracle pair the PROVE stage consumes for ONE finding. */
export type ProveOracles = { diversify?: DiversifyOracle; differential?: DifferentialOracle };

/** Everything the per-finding oracle factory gets to bind against. */
export interface ProveOracleInput {
  finding: Finding;
  candidate: HuntCandidate;
  /** The finding's own confirmed reproducer — never another finding's. */
  reproducer: string;
  /** The parsed splat for this finding. */
  report: CrashReport;
}

export interface HuntProveStageDeps {
  /**
   * Extract the KASAN/dmesg text for a finding. Defaults to the finding's
   * evidence prose (`response` + `analysis`), which is where the hunt's prover
   * records the reproduced splat.
   */
  dmesgFor?: (finding: Finding, candidate: HuntCandidate) => string;
  /**
   * Extract this finding's confirmed C reproducer. Defaults to the first fenced
   * ```c block in the finding's evidence. Return `undefined` when the finding has
   * no bootable reproducer — the stage then passes it through unproven.
   */
  reproducerFor?: (finding: Finding, candidate: HuntCandidate) => string | undefined;
  /**
   * Build the oracle pair for ONE finding. Defaults to the REAL kernel-VM
   * oracles ({@link makeKernelVmOracles}), which boot QEMU. Tests inject a fake.
   */
  makeOracles?: (input: ProveOracleInput) => ProveOracles;
  /**
   * Extra deps forwarded into the default {@link makeKernelVmOracles} call (K-boot
   * diversify options, the differential exploit builder, env bag). Ignored when
   * `makeOracles` is supplied.
   */
  kernelVm?: Omit<KernelVmOraclesDeps, "diversify"> & {
    diversify?: Omit<NonNullable<KernelVmOraclesDeps["diversify"]>, "reproducer">;
  };
  /** Cheap VM-free impact-ceiling pre-filter, forwarded to the gate. */
  escalation?: EscalationPreGate;
  onEscalation?: (finding: Finding, candidate: HuntCandidate, verdict: EscalationVerdict) => void;
  onVerdict?: (finding: Finding, candidate: HuntCandidate, verdict: ExploitabilityVerdict) => void;
  /**
   * The expensive weaponize→root call, gated by the PROVE stage's own
   * `shouldWeaponize` budget check. Left unset in a source-only hunt (there is no
   * target executor to weaponize INTO); wired by callers that have one, typically
   * as `makeWeaponizeHook(runWeaponization)`.
   *
   * Deliberately aliased to the gate's own slot type so the two cannot drift —
   * this stage only forwards it.
   */
  weaponize?: ExploitabilityGateDeps["weaponize"];
  minCleanBoots?: number;
  log?: (msg: string) => void;
}

/**
 * Pull the first fenced C block out of a finding's evidence. Deliberately
 * conservative: only a explicitly ```c-tagged block counts, because booting an
 * arbitrary prose blob as a reproducer wastes a VM slot and can only ever
 * produce a non-observation.
 */
export function defaultReproducerFor(finding: Finding): string | undefined {
  const haystack = [finding.evidence.request, finding.evidence.analysis, finding.evidence.response]
    .filter((s): s is string => Boolean(s))
    .join("\n\n");
  const m = haystack.match(/```c\n([\s\S]*?)```/);
  const body = m?.[1]?.trim();
  return body && body.length > 0 ? body : undefined;
}

/** Default splat source: the prover records the reproduced crash in the evidence prose. */
export function defaultDmesgFor(finding: Finding): string {
  return [finding.evidence.response, finding.evidence.analysis]
    .filter((s): s is string => Boolean(s))
    .join("\n");
}

/**
 * Build the CrashReport the oracle + escalation gate read, from a finding's
 * splat text. Mirrors `classifyPrimitiveFromDmesg`'s own internal parse so the
 * report we hand the gate is the same one its primitive label was derived from.
 */
function reportFromDmesg(dmesg: string, reproducer: string): CrashReport {
  const accessMatch = dmesg.match(/(Read|Write)\s+of\s+size\s+(\d+)/i);
  return {
    rawText: dmesg,
    crashType: sniffCrashType(dmesg) ?? "unknown",
    faultingFunction: "unknown",
    callStack: [],
    subsystem: "unknown",
    reproducer,
    reproducerLanguage: "c",
    ...(accessMatch ? { accessType: accessMatch[1]!.toLowerCase() as "read" | "write" } : {}),
    ...(accessMatch ? { accessSize: parseInt(accessMatch[2]!, 10) } : {}),
    ...(/Allocated by task/i.test(dmesg) ? { allocSite: "alloc" } : {}),
    ...(/Freed by task/i.test(dmesg) ? { freeSite: "free" } : {}),
  };
}

/**
 * The PROVE stage, ready to pass as `runHuntScan`'s `opts.exploitability`.
 *
 * Composition contract (unchanged from `makeExploitabilityGate`): it runs ONLY
 * on skeptic+prover-confirmed findings because `composeGate` short-circuits on
 * the first rejecting stage, and it NEVER rejects — it stamps a verdict and gates
 * the weaponize budget.
 */
export function makeHuntProveStage(deps: HuntProveStageDeps = {}): HuntVerifier {
  const log = deps.log ?? (() => {});
  const dmesgFor = deps.dmesgFor ?? defaultDmesgFor;
  const reproducerFor = deps.reproducerFor ?? defaultReproducerFor;

  return async (finding, candidate) => {
    const reproducer = reproducerFor(finding, candidate);
    if (!reproducer) {
      // No bootable repro ⇒ nothing to observe. Pass through honestly: the bug
      // stays confirmed, it simply carries no execution-verified verdict.
      log(`[prove] ${finding.title}: no C reproducer in evidence — PROVE stage skipped (finding kept)`);
      return {
        confirmed: true,
        reason: "exploitability gate: no bootable reproducer, static guess stands",
      };
    }

    const dmesg = dmesgFor(finding, candidate);
    const report = reportFromDmesg(dmesg, reproducer);
    const primitive = classifyPrimitiveFromDmesg(dmesg);

    const oracles = deps.makeOracles
      ? deps.makeOracles({ finding, candidate, reproducer, report })
      : makeKernelVmOracles({
          ...deps.kernelVm,
          diversify: { ...deps.kernelVm?.diversify, reproducer },
        });

    // Per-finding gate: the resolver is a constant closure over THIS finding's
    // already-parsed primitive/report, so the gate cannot cross-attribute.
    const gate = makeExploitabilityGate({
      resolvePrimitive: async () => ({ primitive, report }),
      oracles,
      ...(deps.escalation ? { escalation: deps.escalation } : {}),
      ...(deps.onEscalation ? { onEscalation: deps.onEscalation } : {}),
      ...(deps.onVerdict ? { onVerdict: deps.onVerdict } : {}),
      ...(deps.weaponize ? { weaponize: deps.weaponize } : {}),
      ...(deps.minCleanBoots !== undefined ? { minCleanBoots: deps.minCleanBoots } : {}),
      log,
    });

    return gate(finding, candidate);
  };
}

/**
 * Differential dedup gate + stack-trace crash-signature dedup (issue #1501,
 * adopted from the DARPA AIxCC winner ATLANTIS, MIT-licensed).
 *
 * ATLANTIS took 1,003 raw PoVs down to 118 verified uniques with two ideas this
 * module makes concrete for the pwnkit skeptic/triage stage:
 *
 *  1. BASE-vs-PATCH DIFFERENTIAL GATE (the fix-diff-seeded-bug proof). A variant
 *     candidate seeded off a fix diff (see variant-candidates.ts) is only a REAL
 *     delta bug if its reproducer crashes on the TARGET version but NOT on the
 *     BASE version. If it crashes on BOTH, the bug is pre-existing / out of the
 *     changed code — not what the fix-diff seeding was hunting — so it is
 *     dropped. This is a HARD gate, shaped as a {@link HuntVerifier} so it drops
 *     straight into `runHuntScan`'s `opts.verify` slot (or composes after the
 *     skeptic+prover pair via {@link composeGate}). It never self-grades: the
 *     actual build+boot+reproduce is INJECTED ({@link DifferentialReproducer}),
 *     exactly like second-audit injects its model and kernel-verify its runner.
 *
 *  2. STACK-TRACE CRASH DEDUP per sanitizer class. Crash dedup keys on a
 *     NORMALIZED stack-trace signature scoped to the sanitizer class (KASAN UAF
 *     vs OOB vs KCSAN race), NOT fuzzy report-text matching. Two crashes with the
 *     same class + same normalized top frames (+ alloc/free sites for a UAF, +
 *     the unordered racing-pair for a race) are the SAME bug. This reuses the
 *     engine's real crash parsers ({@link parseCrashReport} for KASAN/UBSAN/oops,
 *     {@link parseKcsanReport} for KCSAN data-races) rather than re-deriving them.
 *
 * Pure + offline: no I/O, no LLM, no VM. The one side-effecting seam (building
 * and running the reproducer on each version) is injected, so the whole module
 * unit-tests hermetically.
 */

import type { Finding, CrashReport } from "@pwnkit/shared";
import { parseCrashReport } from "../ingest/kernel-crash.js";
import { parseKcsanReport } from "../triage/kcsan-race.js";
import type { HuntCandidate, HuntVerifier } from "./hunt-scan.js";

// ── Crash signature ───────────────────────────────────────────────────────────

/**
 * A normalized, per-sanitizer-class crash signature. Two crashes are the SAME
 * bug iff their {@link signatureKey}s are equal. `sanitizerClass` is the coarse
 * bug family the dedup is scoped to (a KASAN UAF never dedups against a KASAN
 * OOB, and neither dedups against a KCSAN race).
 */
export interface CrashSignature {
  /**
   * The sanitizer class this crash belongs to — the {@link CrashReport.crashType}
   * value (`kasan-uaf`, `kasan-oob`, `ubsan-shift`, …) for KASAN/UBSAN/oops
   * crashes, or the synthetic `kcsan-race` for a KCSAN data-race.
   */
  sanitizerClass: string;
  /** Normalized top stack frames (offsets/module tags/compiler clones stripped, infra frames dropped). */
  frames: string[];
  /**
   * For a lifetime bug (UAF / double-free / invalid-free): the normalized
   * alloc + free site frames — the canonical discriminator between two
   * different UAFs that fault at the same read site. Empty otherwise.
   */
  allocSite?: string;
  freeSite?: string;
  /**
   * For a KCSAN data-race: the two racing site functions, sorted so the
   * signature is order-independent (a race A/B is the same bug as B/A).
   */
  racePair?: [string, string];
}

/** How many normalized frames go into a signature. Deep enough to separate distinct sinks, shallow enough to be stable across builds. */
const SIGNATURE_FRAME_DEPTH = 5;

/**
 * Sanitizer / trap plumbing frames that carry no subsystem meaning — dropped
 * before the signature is taken so the same bug reached through slightly
 * different report plumbing still keys identically. Matched against the
 * NORMALIZED frame name (post {@link normalizeFrame}).
 */
const INFRA_FRAME_RE =
  /^(?:__)?(?:kasan|asan|ubsan|kcsan|kmsan)_|^__asan_|^__ubsan_|^kasan_report|^print_report|^report_bug|^handle_bug|^dump_stack|^__dump_stack|^show_stack|^show_trace|^__show_regs|^die|^do_error_trap|^do_trap|^exc_[a-z_]+$|^asm_exc_[a-z_]+$|^error_entry|^check_memory_region|^__?kasan_check_(?:read|write|range)$|^instrument_[a-z_]+$/;

/**
 * Normalize a raw kernel stack frame to a stable symbol:
 *  - drop the `+0x<off>/0x<size>` address suffix,
 *  - drop a trailing `[module]` tag,
 *  - drop gcc/clang function-clone suffixes (`.cold`, `.part.N`, `.isra.N`,
 *    `.constprop.N`, `.llvm.<hash>`) that differ across builds of the SAME fn.
 */
export function normalizeFrame(frame: string): string {
  let f = frame.trim();
  f = f.replace(/\+0x[0-9a-fA-F]+(?:\/0x[0-9a-fA-F]+)?/g, ""); // address offset
  f = f.replace(/\s*\[[^\]]+\]\s*$/, ""); // [module]
  f = f.replace(/\s+\S+:\d+.*$/, ""); // trailing `file.c:123` (KCSAN frames carry it)
  f = f.replace(/\.(?:cold|part|isra|constprop|llvm)\b(?:\.[0-9a-fA-F]+)?/g, ""); // compiler clones
  f = f.replace(/^[?\s]+/, ""); // leading `? ` unreliable-frame marker
  return f.trim();
}

/** Normalize a stack, drop infra/empty frames, and take the top {@link SIGNATURE_FRAME_DEPTH}. */
function normalizeStack(frames: readonly string[]): string[] {
  const out: string[] = [];
  for (const raw of frames) {
    const n = normalizeFrame(raw);
    if (!n || INFRA_FRAME_RE.test(n)) continue;
    out.push(n);
    if (out.length >= SIGNATURE_FRAME_DEPTH) break;
  }
  return out;
}

const LIFETIME_CLASSES = new Set(["kasan-uaf", "kasan-double-free", "kasan-invalid-free"]);

/**
 * Compute a {@link CrashSignature} from a raw crash / sanitizer report. Tries
 * KCSAN first (its `BUG: KCSAN: data-race` header would otherwise be swallowed
 * by the generic `BUG:` oops matcher), then the shared KASAN/UBSAN/oops parser.
 * Returns `undefined` when the text carries no recognizable crash.
 */
export function crashSignatureFromText(text: string): CrashSignature | undefined {
  const race = parseKcsanReport(text);
  if (race) {
    const a = normalizeFrame(race.a.fn);
    const b = normalizeFrame(race.b.fn);
    const racePair: [string, string] = a <= b ? [a, b] : [b, a];
    // The union of both racing stacks makes the signature robust when the two
    // sites alone collide across unrelated races on the same object family.
    const frames = normalizeStack([...race.a.stack, ...race.b.stack]);
    return { sanitizerClass: "kcsan-race", frames, racePair };
  }

  const report = parseCrashReport(text);
  if (report.crashType === "unknown") return undefined;
  return crashSignatureFromReport(report);
}

/** Compute a {@link CrashSignature} from an already-parsed {@link CrashReport} (non-KCSAN path). */
export function crashSignatureFromReport(report: CrashReport): CrashSignature {
  const frames = normalizeStack([report.faultingFunction, ...report.callStack]);
  const sig: CrashSignature = { sanitizerClass: report.crashType, frames };
  if (LIFETIME_CLASSES.has(report.crashType)) {
    if (report.allocSite) sig.allocSite = normalizeFrame(report.allocSite);
    if (report.freeSite) sig.freeSite = normalizeFrame(report.freeSite);
  }
  return sig;
}

/**
 * The canonical dedup key for a signature: equal keys ⇒ same bug. Scoped by
 * `sanitizerClass` first so cross-class crashes never collapse. For a lifetime
 * bug the alloc/free sites join the key; for a race the sorted pair does.
 */
export function signatureKey(sig: CrashSignature): string {
  const parts = [sig.sanitizerClass, sig.frames.join(">")];
  if (sig.racePair) parts.push(`race=${sig.racePair.join("|")}`);
  if (sig.allocSite || sig.freeSite) parts.push(`alloc=${sig.allocSite ?? ""}`, `free=${sig.freeSite ?? ""}`);
  return parts.join("::");
}

/** True when two crashes are the same bug by their normalized per-class signature. */
export function sameCrash(a: CrashSignature, b: CrashSignature): boolean {
  return signatureKey(a) === signatureKey(b);
}

// ── Stack-trace dedup over a set of crashes ───────────────────────────────────

/** One deduped crash group: the first-seen representative plus every member. */
export interface CrashGroup<T> {
  key: string;
  signature: CrashSignature;
  representative: T;
  members: T[];
}

/**
 * Dedup a list of items that each carry a raw crash report, by normalized
 * per-sanitizer-class stack signature. Items whose text carries no recognizable
 * crash are returned untouched in `undeduped` (never silently dropped — a
 * missing signature must not merge distinct findings). Group order is the order
 * each key was first seen, so the representative of a group is deterministic.
 */
export function dedupByCrashSignature<T>(
  items: readonly T[],
  reportText: (item: T) => string,
): { groups: CrashGroup<T>[]; undeduped: T[] } {
  const byKey = new Map<string, CrashGroup<T>>();
  const undeduped: T[] = [];
  for (const item of items) {
    const sig = crashSignatureFromText(reportText(item));
    if (!sig) {
      undeduped.push(item);
      continue;
    }
    const key = signatureKey(sig);
    const existing = byKey.get(key);
    if (existing) existing.members.push(item);
    else byKey.set(key, { key, signature: sig, representative: item, members: [item] });
  }
  return { groups: [...byKey.values()], undeduped };
}

/**
 * Convenience over {@link dedupByCrashSignature} for `Finding`s. A crash-ingest
 * `Finding` carries the raw report in `evidence.response` (see
 * `ingest/kernel-crash.ts` `crashToFinding`); that is the text keyed on. Returns
 * the unique representatives (one per crash signature) plus the dropped
 * duplicates, so a caller can dedup a confirmed set the way the novelty gate
 * drops on-list duplicates.
 */
export function dedupFindingsByCrashSignature(findings: readonly Finding[]): {
  unique: Finding[];
  duplicates: Array<{ finding: Finding; duplicateOf: Finding; key: string }>;
} {
  const { groups, undeduped } = dedupByCrashSignature(findings, (f) => f.evidence?.response ?? "");
  const unique: Finding[] = [...undeduped];
  const duplicates: Array<{ finding: Finding; duplicateOf: Finding; key: string }> = [];
  for (const g of groups) {
    unique.push(g.representative);
    for (const m of g.members) {
      if (m !== g.representative) duplicates.push({ finding: m, duplicateOf: g.representative, key: g.key });
    }
  }
  return { unique, duplicates };
}

// ── Base-vs-patch differential gate ───────────────────────────────────────────

/** Which build a reproducer is run against. */
export type BuildVersion = "base" | "target";

/** Result of running a candidate's reproducer against one build version. */
export interface CrashRunResult {
  /** Did the reproducer produce a kernel crash / sanitizer report at all? */
  crashed: boolean;
  /** The raw dmesg / sanitizer report, when it crashed — used to compare signatures across versions. */
  report?: string;
}

/**
 * INJECTED build+boot+reproduce seam. Given a finding, its candidate site, and
 * which version to build, run the reproducer and report whether it crashed (and
 * the raw report for signature comparison). Prod wires the real kernel-vm verify
 * pipeline here; tests pass a fake. Never self-graded — this is where the actual
 * proof happens, outside this module.
 */
export type DifferentialReproducer = (
  finding: Finding,
  candidate: HuntCandidate,
  version: BuildVersion,
) => Promise<CrashRunResult>;

export interface DifferentialGateOptions {
  reproduce: DifferentialReproducer;
  /**
   * When true (default), a base crash only vetoes the candidate if it is the
   * SAME crash (by normalized signature) as the target crash. A DIFFERENT crash
   * on base (an unrelated pre-existing bug the reproducer also happens to trip)
   * does NOT veto — the delta bug still stands. When false, ANY base crash
   * vetoes (stricter; use when signatures are unreliable on your target).
   */
  requireSameSignature?: boolean;
  log?: (msg: string) => void;
}

/**
 * Build the base-vs-patch differential gate as a {@link HuntVerifier}. It
 * confirms a candidate ONLY when the reproducer:
 *   - CRASHES on the TARGET (the changed/patched build), AND
 *   - does NOT reproduce the SAME crash on the BASE build.
 *
 * Ordering is cost-aware: the target is run first and a non-crash short-circuits
 * to a reject WITHOUT paying for the base build. It composes after the
 * skeptic+prover pair — `composeGate(skeptic, prover, makeDifferentialGate(...))`
 * — so only findings the cheaper stages already believe reach the (expensive)
 * two-build differential proof.
 */
export function makeDifferentialGate(opts: DifferentialGateOptions): HuntVerifier {
  const requireSameSignature = opts.requireSameSignature ?? true;
  const log = opts.log ?? (() => {});
  return async (finding, candidate) => {
    // 1. TARGET must crash. Run it first; a clean target short-circuits (no base build paid for).
    const target = await opts.reproduce(finding, candidate, "target");
    if (!target.crashed) {
      return { confirmed: false, reason: "differential: reproducer did not crash on the TARGET build" };
    }
    const targetSig = target.report ? crashSignatureFromText(target.report) : undefined;

    // 2. BASE must be clean of the SAME crash (proves the bug lives in the changed code).
    const base = await opts.reproduce(finding, candidate, "base");
    if (!base.crashed) {
      log("[differential] confirmed: crashes on target, base clean — bug lives in the changed code");
      return { confirmed: true, reason: "differential: crashes on TARGET, BASE clean — bug is in the changed code" };
    }

    // Base ALSO crashed. Decide whether it's the same bug.
    if (requireSameSignature && targetSig) {
      const baseSig = base.report ? crashSignatureFromText(base.report) : undefined;
      if (baseSig && !sameCrash(targetSig, baseSig)) {
        log(`[differential] base crashed with a DIFFERENT signature (${baseSig.sanitizerClass}) — not the delta bug; candidate stands`);
        return {
          confirmed: true,
          reason: `differential: TARGET crash (${targetSig.sanitizerClass}) not reproduced on BASE (base tripped an unrelated ${baseSig.sanitizerClass}) — delta bug stands`,
        };
      }
    }
    log("[differential] REJECT: reproducer crashes on BASE too — bug is pre-existing, not in the changed code");
    return {
      confirmed: false,
      reason: "differential: reproducer crashes on the BASE build too — pre-existing bug, not introduced by the changed code",
    };
  };
}

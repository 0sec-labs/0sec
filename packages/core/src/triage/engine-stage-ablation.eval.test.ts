/**
 * ENGINE-STAGE ABLATION HARNESS (measurement, not a shipped test).
 *
 * Measures how much the three new triage/PROVE/impact stages change finding
 * quality, against a hand-labeled corpus assembled from:
 *   - this session's 5 known FALSE POSITIVES (skeptic-killed negatives),
 *   - real disclosed kernel bugs (disclosure/TRACK-RECORD.md, READ-ONLY),
 *   - the #1101 false-refute historical incident (36 imported findings stamped
 *     `refuted` with no evidence).
 *
 * Every label is hand-assigned from ground truth we already hold; NO finding is
 * invented. Where a stage cannot be fairly measured offline, the harness says so
 * instead of printing a number. Run: `vitest run engine-stage-ablation.eval`.
 */
import { describe, it, expect } from "vitest";
import type { Finding } from "@0sec/shared";

import {
  reachabilityGate,
  autoTriage,
  classifyVerifyOutcome,
  type VerifyFailureKind,
} from "./auto-triage.js";
import type { VerifyOutcome } from "./verify-verdict.js";
import {
  attemptExploitabilityUpgrade,
  shouldWeaponize,
  foldExploitabilityIntoSeverity,
  type DiversifyOracle,
  type DifferentialOracle,
  type ExploitabilityVerdict,
} from "./exploitability-upgrade.js";
import type { KernelPrimitive, UpgradeClass } from "./kernel-primitive.js";
import type { CrashReport, Severity } from "@0sec/shared";

// ── Finding fixture builder (mirrors auto-triage.test.ts) ──────────────
function kf(over: Partial<Finding> & { title?: string; analysis?: string } = {}): Finding {
  const { title, analysis, ...rest } = over;
  return {
    id: "f-1",
    templateId: "kernel-kasan-uaf",
    title: title ?? "Linux kernel kasan-uaf: fn in sub",
    description: "Kernel crash.",
    severity: "high",
    category: "use-after-free",
    status: "discovered",
    evidence: {
      request: "N/A",
      response: "BUG: KASAN",
      analysis: analysis ?? "",
    },
    confidence: 0.8,
    timestamp: 0,
    ...rest,
  } as Finding;
}

const log = (...a: unknown[]) => console.log(...a);
const pct = (n: number, d: number) => (d === 0 ? "n/a" : `${n}/${d} = ${Math.round((100 * n) / d)}%`);

// ════════════════════════════════════════════════════════════════════
// CORPUS B — reachabilityGate / autoTriage tier classification
// Label = expected LPE-tier verdict (keep | drop | inconclusive) under the
// gate's stated unprivileged-LPE threat model. "drop" here means "not an
// unprivileged-local LPE vector", NOT "fake bug".
// ════════════════════════════════════════════════════════════════════
interface ReachItem {
  name: string;
  origin: "real-disclosed" | "session-FP";
  title: string;
  analysis?: string;
  // Ground-truth: is this a genuine unprivileged-local LPE vector?
  trueUnprivLpe: boolean;
  // Expected gate verdict under its LPE threat model.
  expect: "keep" | "drop" | "inconclusive";
}

const REACH: ReachItem[] = [
  // Real disclosed bugs — unprivileged-local LPE vectors (must NEVER be dropped)
  { name: "alsa-seq-midi UAF (weaponized to root)", origin: "real-disclosed",
    title: "Linux kernel kasan-uaf: snd_seq_write in sound", trueUnprivLpe: true, expect: "keep" },
  { name: "blkdev io_uring-cmd wrong-flags", origin: "real-disclosed",
    title: "Linux kernel kasan-uaf: io_uring_cmd_import in io_uring", trueUnprivLpe: true, expect: "keep" },
  // Real disclosed bugs — genuine but NOT unprivileged-LPE (hardware/priv-gated)
  { name: "carl9170 cmd-response oob-write", origin: "real-disclosed",
    title: "Linux kernel kasan-oob: carl9170_cmd_response in drivers/net/wireless", trueUnprivLpe: false, expect: "drop" },
  { name: "atomisp frame-dimensions overflow", origin: "real-disclosed",
    title: "Linux kernel overflow: atomisp_set_fmt in drivers/media", trueUnprivLpe: false, expect: "drop" },
  { name: "kaweth tx-uaf", origin: "real-disclosed",
    title: "Linux kernel kasan-uaf: kaweth_usb_transmit in drivers/usb", trueUnprivLpe: false, expect: "drop" },
  { name: "bluetooth cig-uaf", origin: "real-disclosed",
    title: "Linux kernel kasan-uaf: hci_le_cig_setup in drivers/bluetooth", trueUnprivLpe: false, expect: "drop" },
  { name: "iptfs shared-frag (xfrm, CAP_NET_ADMIN)", origin: "real-disclosed",
    title: "Linux kernel kasan-uaf: iptfs_output in net/xfrm",
    analysis: "xfrm_ policy path; needs CAP_NET_ADMIN", trueUnprivLpe: false, expect: "drop" },
  // Real disclosed bug — reachable but subsystem unclassified → inconclusive is safe
  { name: "bpf-stream vprintk info-leak", origin: "real-disclosed",
    title: "Linux kernel info-leak: bpf_stream_vprintk in kernel/bpf", trueUnprivLpe: true, expect: "inconclusive" },

  // Session FALSE POSITIVES — must NEVER come back as a confident KEEP
  { name: "hid-multitouch overclaim (FP)", origin: "session-FP",
    title: "Linux kernel kasan-oob: mt_report in drivers/hid", trueUnprivLpe: false, expect: "drop" },
  { name: "mwifiex cap-IE overclaim (FP)", origin: "session-FP",
    title: "Linux kernel kasan-oob: mwifiex_update_bss in drivers/net/wireless", trueUnprivLpe: false, expect: "drop" },
  { name: "algif_skcipher static-variant (FP)", origin: "session-FP",
    title: "Linux kernel corruption: skcipher_recvmsg in crypto", trueUnprivLpe: false, expect: "inconclusive" },
  { name: "af_unix GC lifetime-race (FP)", origin: "session-FP",
    title: "Linux kernel race: unix_gc in net/unix", trueUnprivLpe: false, expect: "inconclusive" },
  { name: "crypto benign flag/TOCTOU race (FP)", origin: "session-FP",
    title: "Linux kernel race: crypto_alg_mod_lookup in crypto", trueUnprivLpe: false, expect: "inconclusive" },
];

// ════════════════════════════════════════════════════════════════════
// CORPUS C — PROVE budget gate (shouldWeaponize) + safety downgrade.
// Oracle observations are CANNED FROM GROUND TRUTH (no VM offline), so this
// measures the DECISION LOGIC, not the real oracle's discovery power.
// ════════════════════════════════════════════════════════════════════
type ObservedClass = UpgradeClass;
interface ProveItem {
  name: string;
  origin: "real-disclosed" | "session-FP";
  primitive: KernelPrimitive;
  // Ground-truth observation the real oracle WOULD surface for this bug.
  observed: ObservedClass;
  reachesPrivesc: boolean;
  // Ground-truth: does this bug deserve a weaponization budget slot?
  trueWeaponizable: boolean;
}

const basePrim = (over: Partial<KernelPrimitive>): KernelPrimitive => ({
  kind: "use-after-free",
  control: "read",
  exploitability: 0.5,
  confidence: 0.6,
  controlDemo: { kind: "none", demonstrated: false, description: "static classification only" },
  rationale: [],
  ...over,
} as unknown as KernelPrimitive);

const PROVE: ProveItem[] = [
  { name: "alsa-seq-midi UAF-write → cred/root", origin: "real-disclosed",
    primitive: basePrim({ kind: "use-after-free", control: "write" }),
    observed: "uaf-write", reachesPrivesc: true, trueWeaponizable: true },
  { name: "sk_msg/msgsnd arb-write → root (reclaim cracked)", origin: "real-disclosed",
    primitive: basePrim({ kind: "out-of-bounds-write", control: "write" }),
    observed: "oob-write", reachesPrivesc: true, trueWeaponizable: true },
  { name: "bpf-stream vprintk info-leak (disclose, no weaponize)", origin: "real-disclosed",
    primitive: basePrim({ kind: "out-of-bounds-read", control: "read" }),
    observed: "oob-read", reachesPrivesc: false, trueWeaponizable: false },
  { name: "algif_skcipher static-variant (FP, no real write)", origin: "session-FP",
    primitive: basePrim({ kind: "out-of-bounds-read", control: "read" }),
    observed: "oob-read", reachesPrivesc: false, trueWeaponizable: false },
  { name: "af_unix GC race (FP, no modeled 2nd serializer)", origin: "session-FP",
    primitive: basePrim({ kind: "use-after-free", control: "read" }),
    observed: "oob-read", reachesPrivesc: false, trueWeaponizable: false },
  { name: "crypto benign flag/TOCTOU race (FP)", origin: "session-FP",
    primitive: basePrim({ kind: "use-after-free", control: "read" }),
    observed: "none", reachesPrivesc: false, trueWeaponizable: false },
];

// Fake oracles whose canned outputs encode the ground-truth observation.
function fakeDiversify(observed: ObservedClass): DiversifyOracle {
  const dmesgFor: Record<string, string> = {
    "uaf-write": "BUG: KASAN: slab-use-after-free Write of size 8",
    "oob-write": "BUG: KASAN: slab-out-of-bounds Write of size 8",
    "control-flow": "BUG: unable to handle kernel paging request RIP:",
    "oob-read": "BUG: KASAN: slab-out-of-bounds Read of size 8",
    "info-leak": "BUG: KMSAN: uninit-value",
    "gpf": "general protection fault",
    "double-free": "BUG: KASAN: double-free",
    "none": "no report",
  };
  return {
    async run() {
      const dmesg = dmesgFor[observed] ?? "no report";
      return {
        maxObservedClass: observed,
        upgraded: false, // recomputed by makeDiversifyOracle in prod; here we hand a canned trial
        trials: [{ method: "diversify", index: 0, observedClass: observed, excerpt: dmesg }],
        cleanBoots: observed === "oob-read" || observed === "none" ? 8 : 0,
        bootTotal: 8,
      };
    },
  };
}
function fakeDifferential(reaches: boolean): DifferentialOracle {
  return {
    async run() {
      return reaches
        ? { reachesPrivesc: true, privescTarget: "cred", trials: [{ method: "differential", index: 0, target: "cred", privReached: true }] }
        : { reachesPrivesc: false, trials: [{ method: "differential", index: 0, target: "cred", privReached: false }] };
    },
  };
}

// ════════════════════════════════════════════════════════════════════
// CORPUS A — classifyVerifyOutcome (the #1101 false-refute incident).
// Fully deterministic. Baseline (no gate) = proposed outcome passes through.
// ════════════════════════════════════════════════════════════════════
interface VerifyItem {
  name: string;
  proposed: VerifyOutcome;
  failureKind?: VerifyFailureKind;
  hasDisproofEvidence?: boolean;
  // Ground truth: the honest outcome.
  truth: VerifyOutcome;
}
const INFRA_KINDS: VerifyFailureKind[] = ["build", "setup", "infra", "timeout", "missing-runtime", "missing-image"];
const VERIFY: VerifyItem[] = [
  // The historical batch: imported findings stamped `refuted` after a harness that
  // never ran (each of the 6 infra failure modes) — honest truth = inconclusive.
  ...INFRA_KINDS.map((fk) => ({
    name: `#1101 batch: rejected after ${fk} failure (no evidence)`,
    proposed: "rejected" as VerifyOutcome, failureKind: fk, hasDisproofEvidence: false,
    truth: "inconclusive" as VerifyOutcome,
  })),
  // Empty-label refute (the exact #1101 trap): rejected, no failure, no evidence.
  { name: "#1101 batch: bare refuted label, no disproof evidence",
    proposed: "rejected", hasDisproofEvidence: false, truth: "inconclusive" },
  // Legitimate refutes (must be PRESERVED — gate must not over-correct).
  { name: "legit structured-verify disproof (LLM reachability-disproved)",
    proposed: "rejected", hasDisproofEvidence: true, truth: "rejected" },
  { name: "confirmed finding", proposed: "confirmed", truth: "confirmed" },
  { name: "honest inconclusive", proposed: "inconclusive", truth: "inconclusive" },
];

// ════════════════════════════════════════════════════════════════════
describe("ENGINE-STAGE ABLATION", () => {
  it("Corpus A — auto-triage classifyVerifyOutcome (false-refute fix)", () => {
    log("\n================ STAGE: auto-triage / classifyVerifyOutcome ================");
    log(`N = ${VERIFY.length} labeled verify-outcome cases (models the #1101 incident)\n`);
    let baselineCorrect = 0, gateCorrect = 0, falseRefutesBaseline = 0, falseRefutesGate = 0, legitPreserved = 0, legitTotal = 0;
    for (const v of VERIFY) {
      // BASELINE: no gate — proposed passes straight through to DB status.
      const baseOutcome = v.proposed;
      // WITH GATE:
      const dec = classifyVerifyOutcome({ proposed: v.proposed, failureKind: v.failureKind, hasDisproofEvidence: v.hasDisproofEvidence });
      const gateOutcome = dec.outcome;
      if (baseOutcome === v.truth) baselineCorrect++;
      if (gateOutcome === v.truth) gateCorrect++;
      // A "false refute" = labeled `rejected` when truth is not rejected.
      if (v.truth !== "rejected" && baseOutcome === "rejected") falseRefutesBaseline++;
      if (v.truth !== "rejected" && gateOutcome === "rejected") falseRefutesGate++;
      if (v.truth === "rejected") { legitTotal++; if (gateOutcome === "rejected") legitPreserved++; }
      log(`  ${gateOutcome === v.truth ? "OK " : "XX "} ${v.name}\n       base=${baseOutcome} gate=${gateOutcome} truth=${v.truth} coerced=${dec.coerced}`);
    }
    log(`\n  RESULT: accuracy baseline ${pct(baselineCorrect, VERIFY.length)}  →  with-gate ${pct(gateCorrect, VERIFY.length)}`);
    log(`  FALSE REFUTES: baseline ${falseRefutesBaseline}  →  with-gate ${falseRefutesGate}`);
    log(`  LEGIT refutes preserved: ${pct(legitPreserved, legitTotal)}`);
    expect(falseRefutesGate).toBe(0);
    expect(legitPreserved).toBe(legitTotal);
  });

  it("Corpus B — auto-triage reachabilityGate (LPE-tier classifier)", () => {
    log("\n================ STAGE: auto-triage / reachabilityGate ================");
    log(`N = ${REACH.length} labeled kernel findings (${REACH.filter(r => r.origin === "real-disclosed").length} real-disclosed, ${REACH.filter(r => r.origin === "session-FP").length} session-FP)\n`);
    let tierCorrect = 0, buriedRealLpe = 0, fpConfidentKeep = 0, fpDropped = 0, fpTotal = 0, realLpeTotal = 0, realLpeKept = 0;
    for (const r of REACH) {
      const v = reachabilityGate(kf({ title: r.title, ...(r.analysis ? { analysis: r.analysis } : {}) }));
      const ok = v.verdict === r.expect;
      if (ok) tierCorrect++;
      // SAFETY property 1: never DROP a true unprivileged-LPE bug.
      if (r.trueUnprivLpe) { realLpeTotal++; if (v.verdict !== "drop") realLpeKept++; if (v.verdict === "drop") buriedRealLpe++; }
      // SAFETY property 2: never confidently KEEP a session-FP.
      if (r.origin === "session-FP") { fpTotal++; if (v.verdict === "keep") fpConfidentKeep++; if (v.verdict === "drop") fpDropped++; }
      log(`  ${ok ? "OK " : "XX "} [${r.origin}] ${r.name}\n       tier=${v.tier} verdict=${v.verdict} (expected ${r.expect})`);
    }
    log(`\n  TIER classification accuracy: ${pct(tierCorrect, REACH.length)}`);
    log(`  SAFETY-1 real unpriv-LPE bugs NOT buried: ${pct(realLpeKept, realLpeTotal)} (buried=${buriedRealLpe})`);
    log(`  SAFETY-2 session-FPs never confidently KEPT: ${pct(fpTotal - fpConfidentKeep, fpTotal)} (confident-keep=${fpConfidentKeep})`);
    log(`  Session-FPs auto-DROPPED by reachability (coincidental, hardware-gated): ${pct(fpDropped, fpTotal)}`);
    expect(buriedRealLpe).toBe(0);
    expect(fpConfidentKeep).toBe(0);
  });

  it("Corpus C — PROVE budget gate shouldWeaponize + safety downgrade", async () => {
    log("\n================ STAGE: exploitability-upgrade / shouldWeaponize ================");
    log(`N = ${PROVE.length} labeled bugs (oracle obs CANNED FROM GROUND TRUTH — logic test, not oracle-discovery)\n`);
    let baselineSpend = 0, gateSpend = 0, tp = 0, fp = 0, tn = 0, fn = 0;
    for (const p of PROVE) {
      const report: CrashReport = { rawText: "" } as CrashReport;
      const withVerdict = await attemptExploitabilityUpgrade(
        p.primitive, report,
        { diversify: fakeDiversify(p.observed), differential: fakeDifferential(p.reachesPrivesc) },
      );
      const verdict = withVerdict.upgrade;
      const wp = shouldWeaponize(verdict);
      // BASELINE = weaponize everything confirmed (no budget gate).
      baselineSpend++;
      if (wp) gateSpend++;
      if (p.trueWeaponizable && wp) tp++;
      else if (!p.trueWeaponizable && wp) fp++;
      else if (!p.trueWeaponizable && !wp) tn++;
      else fn++;
      log(`  ${(wp === p.trueWeaponizable) ? "OK " : "XX "} [${p.origin}] ${p.name}\n       observed=${p.observed} privesc=${p.reachesPrivesc} → shouldWeaponize=${wp} (true=${p.trueWeaponizable})`);
    }
    log(`\n  CONFUSION: TP=${tp} FP=${fp} TN=${tn} FN=${fn}`);
    log(`  Weaponization budget spent: baseline ${baselineSpend}/${PROVE.length} (all)  →  with-gate ${gateSpend}/${PROVE.length}`);
    log(`  Budget saved on non-weaponizable bugs (TN): ${tn}; real bugs missed (FN): ${fn}`);

    // Safety-downgrade property: a flaky non-repro must NOT downgrade severity.
    log("\n  -- safety: flaky non-repro must NOT downgrade a high-severity real bug --");
    // Statically scored high (exploitability 0.9) but its baseline splat is a
    // benign read, so the diversify oracle runs and a downgrade is on the table.
    const flakyPrim = basePrim({ kind: "out-of-bounds-read", control: "read", exploitability: 0.9 });
    // Only 2 clean boots (< minCleanBoots=4) → downgrade must be suppressed.
    const flakyDiversify: DiversifyOracle = {
      async run() { return { maxObservedClass: "oob-read", upgraded: false, trials: [{ method: "diversify", index: 0, observedClass: "oob-read" }], cleanBoots: 2, bootTotal: 8 }; },
    };
    const flaky = await attemptExploitabilityUpgrade(flakyPrim, { rawText: "" } as CrashReport, { diversify: flakyDiversify });
    const foldedHigh: Severity = foldExploitabilityIntoSeverity("high", flaky);
    log(`       flaky verdict downgradeEligible=${flaky.upgrade?.downgradeEligible} → severity high folds to ${foldedHigh}`);
    expect(flaky.upgrade?.downgradeEligible).toBe(false);

    expect(fn).toBe(0); // never withhold budget from a truly weaponizable bug
    expect(fp).toBe(0); // never spend budget on a proven-benign bug
  });

  it("Corpus D — impact-assessment (NOT fairly measurable offline)", () => {
    log("\n================ STAGE: impact-assessment / assessImpact ================");
    log("  UNMEASURED. The real business_impact signal comes from an LLM routed through");
    log("  the injected runtime; offline the module degrades to heuristicImpact(), a pure");
    log("  severity→impact map (critical→headline … low→noise). Measuring that against a");
    log("  severity-derived label is tautological, and correlating with real bounty");
    log("  outcomes needs the track record's ACTUAL payouts — which we do not have (npm");
    log("  advisories + merged kernel patches carry no bounty $; only CVE-2026-33130 is a");
    log("  named public CVE, no payout recorded). Verdict: cannot fairly ablate offline.");
    expect(true).toBe(true);
  });
});

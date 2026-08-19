/**
 * Auto-triage gate (#1101)
 *
 * The pending-queue self-cleaner. A batch of ~36 imported kernel KASAN findings
 * (a syzbot dashboard import, not our fuzzer output) sat `pending` with empty
 * `verify_status=refuted` labels until a human ran a multi-agent triage pass and
 * found 7 of 8 LPE-relevant ones were dead: already fixed in the target tree,
 * known syzbot/CVE dupes, or config-/privilege-/hardware-gated (not an
 * unprivileged-local LPE vector). Only 1 was genuinely novel.
 *
 * This module automates the three checks that human pass did by hand, plus the
 * false-refute fix. Each check is a pure function over a {@link Finding} and an
 * injected lookup, so it is testable without a real kernel tree or a live feed:
 *
 *   1. {@link alreadyFixedInTarget} — is the upstream fix already present in the
 *      TARGET tree source (e.g. /root/linux-6.12.93)? If so the crash is
 *      backport-lag — DROP. (Grepping the linux-next fix is the wrong tree; the
 *      fix must be checked against the tree our fuzzer actually runs.)
 *   2. {@link knownDupe} — does the crash signature match a syzbot extid / CVE /
 *      GHSA feed? If so it is not a novel discovery — DROP (whether the upstream
 *      bug is open or fixed; either way it is not ours to file).
 *   3. {@link reachabilityGate} — classify the reachability tier
 *      (unprivileged-local / remote / needs-CAP_SYS_ADMIN / needs-hardware /
 *      mount-crafted-FS-image / not-built-config) and recommend keep-vs-drop for
 *      an LPE threat model. FS-image UAFs that need root to mount, hardware-only
 *      bugs, and config-gated crashes are DROPped for LPE.
 *
 * {@link autoTriage} composes the three into one verdict. It NEVER silently
 * drops something it cannot classify (the #518 discipline): a drop needs a
 * positive gate hit; otherwise the finding is kept (reachable/actionable) or
 * routed to `inconclusive` for a human — never buried.
 *
 * {@link classifyVerifyOutcome} is the false-refute fix: a build/setup/infra
 * failure maps to `inconclusive`, NEVER `refuted`. `refuted` requires actual
 * adversarial disproof evidence, not an empty label stamped by a failed harness.
 */

import { execFileSync } from "node:child_process";

import type { Finding } from "@0sec/shared";
import type { VerifyOutcome } from "./verify-verdict.js";

// ────────────────────────────────────────────────────────────────────
// Shared verdict shape
// ────────────────────────────────────────────────────────────────────

/** Terminal auto-triage decision for a finding (or a single check). */
export type AutoTriageVerdict = "keep" | "drop" | "inconclusive";

/** One check's structured verdict + human-readable reason for the audit trail. */
export interface CheckVerdict {
  verdict: AutoTriageVerdict;
  reason: string;
}

// ────────────────────────────────────────────────────────────────────
// Finding text helpers
// ────────────────────────────────────────────────────────────────────

function findingText(f: Finding): string {
  return [
    f.title,
    f.description,
    f.evidence?.analysis ?? "",
    f.evidence?.response ?? "",
    f.evidence?.request ?? "",
  ]
    .filter(Boolean)
    .join("\n");
}

/**
 * Parse the `Linux kernel <crashType>: <func> in <subsystem>` title that
 * `crashToFinding` emits, plus fall back to templateId (`kernel-<crashType>`)
 * and the analysis block for the subsystem.
 */
function parseCrashShape(f: Finding): {
  crashType?: string;
  faultingFunction?: string;
  subsystem?: string;
} {
  const out: { crashType?: string; faultingFunction?: string; subsystem?: string } = {};
  const titleMatch = f.title?.match(
    /kernel\s+([\w-]+):\s*([A-Za-z_][\w]*)\s+in\s+([\w/.\-]+)/i,
  );
  if (titleMatch) {
    out.crashType = titleMatch[1];
    out.faultingFunction = titleMatch[2];
    out.subsystem = titleMatch[3];
  }
  if (!out.crashType && f.templateId?.startsWith("kernel-")) {
    out.crashType = f.templateId.slice("kernel-".length);
  }
  if (!out.subsystem) {
    const sub = f.evidence?.analysis?.match(/Subsystem:\s*([\w/.\-]+)/i);
    if (sub) out.subsystem = sub[1];
  }
  return out;
}

// ────────────────────────────────────────────────────────────────────
// Check 1 — already fixed in the TARGET tree source
// ────────────────────────────────────────────────────────────────────

/** A hit from the target-tree source lookup: which signature, and what matched. */
export interface SourceLookupHit {
  signature: string;
  /** The matching line/snippet from the target tree, for the audit trail. */
  matched: string;
}

/**
 * Looks a fix signature up in the TARGET tree source. Returns a hit when the
 * signature (a fix commit hash, a `Fixes:` tag, or a post-fix code snippet) is
 * present in the target tree, or `null` when it is not. Injected so the check is
 * testable with a fake; {@link makeTargetTreeLookup} builds a real one.
 */
export type TargetSourceLookup = (signature: string) => SourceLookupHit | null;

export interface AlreadyFixedOptions {
  sourceLookup: TargetSourceLookup;
  /**
   * Fix signatures known from a dedup/CVE feed for this crash — fixing commit
   * hashes (e.g. `e5c33cdc6f40`), CVE ids, or a snippet of the fixed code shape.
   * Combined with any `Fixes:`/`fix commit` references parsed from the finding.
   */
  fixSignatures?: string[];
}

const HEX_COMMIT = /\b([0-9a-f]{12,40})\b/gi;

/**
 * Collect candidate fix signatures: explicit `fixSignatures`, plus any hashes
 * that appear next to a fix marker (`Fixes:`, `fixed in`, `fix commit`) in the
 * finding text or its `dedupRefs`. We do NOT harvest the crash's own kernel
 * commit hash — that is the tree the crash was FOUND on, not the fix.
 */
function collectFixSignatures(f: Finding, explicit?: string[]): string[] {
  const sigs = new Set<string>();
  for (const s of explicit ?? []) {
    const t = s.trim();
    if (t) sigs.add(t);
  }
  for (const ref of f.dedupRefs ?? []) {
    const t = ref.trim();
    if (t) sigs.add(t);
  }
  const text = findingText(f);
  const fixLine = /(?:Fixes:|fixed in|fix commit|fix:)\s*([^\n]+)/gi;
  let m: RegExpExecArray | null;
  while ((m = fixLine.exec(text)) !== null) {
    const tail = m[1];
    let h: RegExpExecArray | null;
    HEX_COMMIT.lastIndex = 0;
    while ((h = HEX_COMMIT.exec(tail)) !== null) sigs.add(h[1]);
  }
  return [...sigs];
}

/**
 * Check 1: is the upstream fix already present in the target tree source? If a
 * fix signature is found in the target tree, the crash is backport-lag against a
 * tree that is already patched — DROP. If no fix signature is known to check
 * against, this check is `inconclusive` (it cannot decide "fixed"); the crash is
 * not dropped on this basis alone.
 */
export function alreadyFixedInTarget(
  finding: Finding,
  opts: AlreadyFixedOptions,
): CheckVerdict {
  const signatures = collectFixSignatures(finding, opts.fixSignatures);
  if (signatures.length === 0) {
    return {
      verdict: "inconclusive",
      reason:
        "already-fixed: no fix signature available to check against the target tree",
    };
  }
  const hits: SourceLookupHit[] = [];
  for (const sig of signatures) {
    const hit = opts.sourceLookup(sig);
    if (hit) hits.push(hit);
  }
  if (hits.length > 0) {
    const ids = hits.map((h) => h.signature).join(", ");
    const sample = hits[0]!.matched.slice(0, 120);
    return {
      verdict: "drop",
      reason: `already-fixed-in-target: fix ${ids} present in target tree (backport-lag) — matched ${JSON.stringify(sample)}`,
    };
  }
  return {
    verdict: "keep",
    reason: `already-fixed: checked ${signatures.length} fix signature(s), none present in target tree — still affected`,
  };
}

// ────────────────────────────────────────────────────────────────────
// Check 2 — known syzbot / CVE dedup
// ────────────────────────────────────────────────────────────────────

export interface DupeSignature {
  /** syzbot extid parsed from the crash report (e.g. `bp-14cb10b0…`), if any. */
  extid?: string;
  crashType?: string;
  faultingFunction?: string;
  subsystem?: string;
  /** Raw finding title, as a coarse fallback signature. */
  title: string;
}

export interface DupeMatch {
  source: "syzbot" | "cve" | "ghsa" | "osv";
  id: string;
  /** Upstream state — a dupe is still a dupe whether open or fixed. */
  status?: "open" | "fixed" | "closed" | "unknown";
  url?: string;
}

/**
 * Matches a crash signature against a known-bug feed (syzbot dashboard extids +
 * kernel CNA / CVE repo). Returns the matched advisory or `null`. Injected so
 * the check is testable with a stub feed.
 */
export type DupeFeedLookup = (sig: DupeSignature) => DupeMatch | null;

const SYZBOT_EXTID = /\b(bp-[0-9a-f]{6,}|[0-9a-f]{40})\b/i;

/** Extract the dedup signature from a finding (extid + crash shape). */
export function extractDupeSignature(f: Finding): DupeSignature {
  const shape = parseCrashShape(f);
  const text = findingText(f);
  let extid: string | undefined;
  // A bare 40-hex is only trusted as an extid when the report is a syzbot import.
  const looksSyzbot = /syzbot|syzkaller|Google Compute Engine/i.test(text);
  const m = text.match(SYZBOT_EXTID);
  if (m) {
    const tok = m[1];
    if (tok.toLowerCase().startsWith("bp-") || looksSyzbot) extid = tok;
  }
  return {
    extid,
    crashType: shape.crashType,
    faultingFunction: shape.faultingFunction,
    subsystem: shape.subsystem,
    title: f.title ?? "",
  };
}

/**
 * Check 2: does the crash signature match a known syzbot/CVE bug? A match means
 * this is not a novel discovery — DROP it from the actionable queue (an open
 * upstream syzbot bug is still a known bug, not ours to file). If no crash
 * signature can be extracted the check is `inconclusive`.
 */
export function knownDupe(finding: Finding, lookup: DupeFeedLookup): CheckVerdict {
  const sig = extractDupeSignature(finding);
  if (!sig.extid && !sig.faultingFunction) {
    return {
      verdict: "inconclusive",
      reason: "known-dupe: no crash signature extractable from finding",
    };
  }
  const match = lookup(sig);
  if (match) {
    const status = match.status ? ` (${match.status})` : "";
    return {
      verdict: "drop",
      reason: `known-dupe: matches ${match.source.toUpperCase()}:${match.id}${status} — not a novel discovery`,
    };
  }
  return {
    verdict: "keep",
    reason: "known-dupe: no match in syzbot/CVE feed — potentially novel",
  };
}

// ────────────────────────────────────────────────────────────────────
// Check 3 — reachability / privilege gating
// ────────────────────────────────────────────────────────────────────

/** Reachability tier for a kernel finding under an LPE threat model. */
export type ReachabilityTier =
  | "unprivileged-local"
  | "remote"
  | "needs-cap-sys-admin"
  | "needs-hardware"
  | "mount-crafted-fs"
  | "not-built-config"
  | "unknown";

export interface ReachabilityVerdict extends CheckVerdict {
  tier: ReachabilityTier;
  /** Whether the tier is a usable unprivileged local-privilege-escalation vector. */
  lpeRelevant: boolean;
}

export interface ReachabilityOptions {
  /**
   * Optional CONFIG predicate: given a `CONFIG_FOO` symbol referenced by the
   * crash, return whether it is built into the target kernel. When it returns
   * false for a referenced symbol the finding is `not-built-config` (DROP). When
   * omitted, the config tier is not evaluated.
   */
  isConfigBuilt?: (config: string) => boolean;
}

// Syscall-reachable local surfaces an unprivileged user can drive directly.
const UNPRIV_LOCAL_SUBSYSTEMS = new Set([
  "io_uring",
  "net/core",
  "sound",
  "mm",
  "ipc",
]);

// Remote-reachable network surfaces (attacker off-box).
const REMOTE_SUBSYSTEMS = new Set(["net/tcp", "net/udp", "net/ip", "net/sctp"]);

const CONFIG_TOKEN = /\bCONFIG_[A-Z0-9_]+\b/g;

// Driver subtrees that require a physical/adjacent hardware device (peripheral,
// radio NIC, HID device, GPU/display, media capture) rather than a local
// unprivileged process. Matched as SUBTREE prefixes so nested paths are covered
// (e.g. drivers/net/wireless/ath/carl9170, drivers/hid/hid-multitouch) — an
// exact `drivers/hid` or `net/wireless` match alone under-drops them. Kept
// narrow on purpose: local surfaces (drivers/char, drivers/tty) and software
// net drivers (drivers/net/tun, drivers/net/ppp) are NOT hardware-gated and
// must stay reachable. Sound (ALSA seq) is likewise excluded — unprivileged
// local, not hardware.
const HARDWARE_DRIVER_SUBTREES = [
  "drivers/usb",
  "drivers/bluetooth",
  "drivers/gpu",
  "drivers/media",
  "drivers/hid",
  "drivers/net/wireless",
  "drivers/net/ethernet",
  "net/wireless",
];

function isHardwareSubtree(subsystem: string): boolean {
  return HARDWARE_DRIVER_SUBTREES.some(
    (prefix) => subsystem === prefix || subsystem.startsWith(prefix + "/"),
  );
}

/**
 * Check 3: classify reachability tier and recommend keep-vs-drop for LPE.
 *
 * DROP (not an unprivileged-local LPE vector):
 *   - `not-built-config`  — references a CONFIG symbol not built in the target.
 *   - `needs-cap-sys-admin` — CAP_SYS_ADMIN / CAP_NET_ADMIN-gated surface.
 *   - `mount-crafted-fs`  — FS-image UAF reached by mounting a crafted image
 *                            (needs root to mount → not an LPE primitive).
 *   - `needs-hardware`    — bug needs a physical/malicious device.
 * KEEP:
 *   - `unprivileged-local` — the real LPE vector.
 *   - `remote`             — real, but a different (remote) threat model.
 * INCONCLUSIVE:
 *   - `unknown`            — cannot classify; route to a human, never auto-drop.
 */
export function reachabilityGate(
  finding: Finding,
  opts: ReachabilityOptions = {},
): ReachabilityVerdict {
  const shape = parseCrashShape(finding);
  const subsystem = (shape.subsystem ?? "").toLowerCase();
  const text = findingText(finding);
  const lower = text.toLowerCase();

  // ── not-built-config (only when a predicate is supplied) ──
  if (opts.isConfigBuilt) {
    const configs = text.match(CONFIG_TOKEN) ?? [];
    for (const cfg of configs) {
      if (!opts.isConfigBuilt(cfg)) {
        return {
          verdict: "drop",
          tier: "not-built-config",
          lpeRelevant: false,
          reason: `reachability: ${cfg} not built into target kernel — not-built-config, unreachable on target`,
        };
      }
    }
  }

  // ── needs-cap-sys-admin / cap-net-admin ──
  if (
    /\bcap_sys_admin\b/i.test(text) ||
    /\bcap_net_admin\b/i.test(text) ||
    /\b(nf_tables|nft_|netfilter|nftables|xfrm_|tc_|qdisc)\b/i.test(lower) ||
    subsystem === "net/netfilter"
  ) {
    return {
      verdict: "drop",
      tier: "needs-cap-sys-admin",
      lpeRelevant: false,
      reason:
        "reachability: privileged surface (CAP_SYS_ADMIN/CAP_NET_ADMIN or admin-gated net config) — not an unprivileged LPE vector",
    };
  }

  // ── mount-crafted-fs (FS-image UAF needs root to mount) ──
  const mountSignal =
    /\b(mount|fill_super|read_super|parse_super|get_tree|sget|read_inode|iget)\b/i.test(
      lower,
    );
  if (subsystem.startsWith("fs/") && mountSignal) {
    return {
      verdict: "drop",
      tier: "mount-crafted-fs",
      lpeRelevant: false,
      reason: `reachability: ${subsystem} UAF reached via mounting a crafted FS image (needs root to mount) — not an unprivileged LPE vector`,
    };
  }

  // ── needs-hardware (physical / malicious device required) ──
  // Sound (ALSA seq) is deliberately excluded — it is an unprivileged local
  // surface, not hardware-gated.
  if (
    isHardwareSubtree(subsystem) ||
    /\b(usb_[a-z]|hci_[a-z]|hid_[a-z]|ieee80211|cfg80211|nl80211|firmware image)\b/i.test(
      lower,
    )
  ) {
    return {
      verdict: "drop",
      tier: "needs-hardware",
      lpeRelevant: false,
      reason: `reachability: ${subsystem || "driver"} bug needs a physical/malicious device — not a software-reachable LPE vector`,
    };
  }

  // ── remote ──
  if (REMOTE_SUBSYSTEMS.has(subsystem)) {
    return {
      verdict: "keep",
      tier: "remote",
      lpeRelevant: false,
      reason: `reachability: ${subsystem} is remote-reachable — kept (remote threat model, not LPE)`,
    };
  }

  // ── unprivileged-local ──
  if (UNPRIV_LOCAL_SUBSYSTEMS.has(subsystem)) {
    return {
      verdict: "keep",
      tier: "unprivileged-local",
      lpeRelevant: true,
      reason: `reachability: ${subsystem} is an unprivileged local syscall surface — kept as an LPE vector`,
    };
  }

  // ── unknown ──
  return {
    verdict: "inconclusive",
    tier: "unknown",
    lpeRelevant: false,
    reason: `reachability: could not classify tier for subsystem ${subsystem || "?"} — routed to human review`,
  };
}

// ────────────────────────────────────────────────────────────────────
// Compose — autoTriage
// ────────────────────────────────────────────────────────────────────

export interface AutoTriageOptions {
  /** Target-tree source lookup (check 1). Omit to skip the already-fixed check. */
  sourceLookup?: TargetSourceLookup;
  /** Known fix signatures for check 1. */
  fixSignatures?: string[];
  /** Known-bug feed lookup (check 2). Omit to skip the dedup check. */
  dupeFeed?: DupeFeedLookup;
  /** CONFIG predicate for check 3. */
  isConfigBuilt?: (config: string) => boolean;
}

export interface AutoTriageResult {
  verdict: AutoTriageVerdict;
  tier: ReachabilityTier;
  /** Ordered reasons from every check, for the `triageNote` / audit trail. */
  reasons: string[];
  checks: {
    alreadyFixed: CheckVerdict;
    knownDupe: CheckVerdict;
    reachability: ReachabilityVerdict;
  };
}

/**
 * Compose the three checks into one verdict, to run at ingest / triage time so
 * the pending queue self-cleans.
 *
 * Priority:
 *   1. Any check DROPs  → `drop`  (backport-lag, known dupe, or non-LPE gate).
 *   2. Else reachability affirmatively KEEPs (unprivileged-local / remote and
 *      not fixed / not a dupe) → `keep`.
 *   3. Else → `inconclusive` — could not affirmatively establish reachability or
 *      a signal was missing. Routed to a human / verify; NEVER silently dropped
 *      (the #518 discipline).
 */
export function autoTriage(
  finding: Finding,
  opts: AutoTriageOptions = {},
): AutoTriageResult {
  const alreadyFixed: CheckVerdict = opts.sourceLookup
    ? alreadyFixedInTarget(finding, {
        sourceLookup: opts.sourceLookup,
        fixSignatures: opts.fixSignatures,
      })
    : {
        verdict: "inconclusive",
        reason: "already-fixed: no target-tree source lookup provided — skipped",
      };

  const dupe: CheckVerdict = opts.dupeFeed
    ? knownDupe(finding, opts.dupeFeed)
    : {
        verdict: "inconclusive",
        reason: "known-dupe: no known-bug feed provided — skipped",
      };

  const reachability = reachabilityGate(finding, {
    isConfigBuilt: opts.isConfigBuilt,
  });

  const reasons = [alreadyFixed.reason, dupe.reason, reachability.reason];

  let verdict: AutoTriageVerdict;
  if (
    alreadyFixed.verdict === "drop" ||
    dupe.verdict === "drop" ||
    reachability.verdict === "drop"
  ) {
    verdict = "drop";
  } else if (reachability.verdict === "keep") {
    verdict = "keep";
  } else {
    verdict = "inconclusive";
  }

  return {
    verdict,
    tier: reachability.tier,
    reasons,
    checks: { alreadyFixed, knownDupe: dupe, reachability },
  };
}

// ────────────────────────────────────────────────────────────────────
// False-refute fix — classifyVerifyOutcome
// ────────────────────────────────────────────────────────────────────

/**
 * Why a verify pass ended. Everything except `disproof` is a way the harness
 * failed to RUN — none of them disprove the finding.
 */
export type VerifyFailureKind =
  | "build"
  | "setup"
  | "infra"
  | "timeout"
  | "missing-runtime"
  | "missing-image"
  | "disproof"
  | null;

/** Harness failures that must map to `inconclusive`, never `rejected`. */
const INFRA_FAILURES = new Set<VerifyFailureKind>([
  "build",
  "setup",
  "infra",
  "timeout",
  "missing-runtime",
  "missing-image",
]);

export interface VerifyOutcomeInput {
  /** The outcome the verifier proposed. */
  proposed: VerifyOutcome;
  /** How the verify pass ended, if it failed. */
  failureKind?: VerifyFailureKind;
  /**
   * True ONLY when the verifier produced positive adversarial disproof evidence
   * (a deterministic oracle that fired negative, an LLM step that reachability-
   * or payload-disproved the finding). Required to honour a `rejected` proposal.
   */
  hasDisproofEvidence?: boolean;
  /** Optional note folded into the reason string. */
  note?: string;
}

export interface VerifyOutcomeDecision {
  outcome: VerifyOutcome;
  /** True when the proposed outcome was coerced away from a false refute. */
  coerced: boolean;
  reason: string;
}

/**
 * The false-refute fix (#1101). Maps a build/setup/infra failure to
 * `inconclusive` and refuses any `rejected` proposal that is not backed by
 * actual adversarial disproof evidence.
 *
 *   - A build/setup/infra/timeout/missing-runtime/missing-image failure →
 *     `inconclusive` (the harness failed to RUN; it did not disprove anything).
 *   - A proposed `rejected` with no `hasDisproofEvidence` → `inconclusive`
 *     (an empty `verify_status=refuted` label is the false-refute trap).
 *   - Otherwise the proposed outcome stands.
 *
 * WIRING NOTE: the DB stores this as `verify_status` (`verified|refuted|
 * inconclusive`). The imported batch in #1101 was stamped `refuted` with no
 * notes/evidence — exactly the case this coerces. The DB writer / ingest path
 * that sets `verify_status` should call this first and then map the engine
 * {@link VerifyOutcome} to the DB string via {@link verifyStatusFromOutcome}.
 * The engine-side structured-verify `rejected` (LLM step disproof in
 * `structured-verify.ts`) is a legitimate refute and passes
 * `hasDisproofEvidence: true`.
 */
export function classifyVerifyOutcome(
  input: VerifyOutcomeInput,
): VerifyOutcomeDecision {
  const { proposed, failureKind = null, hasDisproofEvidence = false, note } = input;
  const suffix = note ? ` — ${note}` : "";

  if (failureKind && INFRA_FAILURES.has(failureKind)) {
    return {
      outcome: "inconclusive",
      coerced: proposed !== "inconclusive",
      reason: `verify ended on ${failureKind} failure → inconclusive (never refuted): a build/setup/infra failure did not disprove the finding${suffix}`,
    };
  }

  if (proposed === "rejected" && !hasDisproofEvidence) {
    return {
      outcome: "inconclusive",
      coerced: true,
      reason: `proposed rejected without adversarial disproof evidence → inconclusive (false-refute trap): refuted requires a positive disproof${suffix}`,
    };
  }

  return {
    outcome: proposed,
    coerced: false,
    reason: `verify outcome ${proposed}${suffix}`,
  };
}

/** DB `verify_status` string values. */
export type VerifyStatus = "verified" | "refuted" | "inconclusive";

/**
 * Map an engine {@link VerifyOutcome} to the DB `verify_status` string. Pair
 * with {@link classifyVerifyOutcome} at every DB write site so `refuted` only
 * ever lands on a genuinely disproved finding.
 */
export function verifyStatusFromOutcome(outcome: VerifyOutcome): VerifyStatus {
  switch (outcome) {
    case "confirmed":
      return "verified";
    case "rejected":
      return "refuted";
    case "inconclusive":
      return "inconclusive";
  }
}

// ────────────────────────────────────────────────────────────────────
// Real target-tree lookup factory (not used by unit tests)
// ────────────────────────────────────────────────────────────────────

/**
 * Build a {@link TargetSourceLookup} that greps a real kernel tree on disk for a
 * fix signature (a commit hash appearing in a `Fixes:` tag or comment, or a
 * literal fixed-code snippet). Best-effort and side-effecting — unit tests use a
 * fake lookup instead. Returns `null` on any grep error so a broken tree path
 * never fabricates a drop.
 */
export function makeTargetTreeLookup(rootPath: string): TargetSourceLookup {
  return (signature: string): SourceLookupHit | null => {
    if (!signature || signature.length < 6) return null;
    try {
      const out = execFileSync(
        "grep",
        ["-rIn", "--max-count=1", "-F", signature, rootPath],
        { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 20_000 },
      ).toString();
      const line = out.split("\n").find((l) => l.trim().length > 0);
      return line ? { signature, matched: line.trim() } : null;
    } catch {
      return null;
    }
  };
}

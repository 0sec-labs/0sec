import { describe, it, expect } from "vitest";

import type { Finding } from "@0sec/shared";
import {
  alreadyFixedInTarget,
  knownDupe,
  reachabilityGate,
  autoTriage,
  extractDupeSignature,
  classifyVerifyOutcome,
  verifyStatusFromOutcome,
  type TargetSourceLookup,
  type DupeFeedLookup,
} from "./auto-triage.js";

// ── Fixture builder ───────────────────────────────────────────────────

function kernelFinding(over: Partial<Finding> & {
  title?: string;
  analysis?: string;
  response?: string;
} = {}): Finding {
  const { title, analysis, response, ...rest } = over;
  return {
    id: "f-1",
    templateId: "kernel-kasan-uaf",
    title: title ?? "Linux kernel kasan-uaf: snd_seq_write in sound",
    description: "Kernel kasan-uaf detected in function snd_seq_write.",
    severity: "high",
    category: "use-after-free",
    status: "discovered",
    evidence: {
      request: "N/A (kernel crash report)",
      response: response ?? "BUG: KASAN: slab-use-after-free in snd_seq_write",
      analysis: analysis ?? "Subsystem: sound\nCrash type: kasan-uaf",
    },
    confidence: 0.8,
    timestamp: 0,
    ...rest,
  } as Finding;
}

// ── Check 1: alreadyFixedInTarget ─────────────────────────────────────

describe("alreadyFixedInTarget", () => {
  const treeHas = (present: Set<string>): TargetSourceLookup => (sig) =>
    present.has(sig) ? { signature: sig, matched: `fs/foo.c:42: /* Fixes: ${sig} */` } : null;

  it("DROPs when the fix commit is already in the target tree (backport-lag)", () => {
    const finding = kernelFinding({ dedupRefs: ["e5c33cdc6f40"] });
    const v = alreadyFixedInTarget(finding, {
      sourceLookup: treeHas(new Set(["e5c33cdc6f40"])),
    });
    expect(v.verdict).toBe("drop");
    expect(v.reason).toContain("backport-lag");
    expect(v.reason).toContain("e5c33cdc6f40");
  });

  it("KEEPs when the fix signature is not present in the target tree", () => {
    const finding = kernelFinding();
    const v = alreadyFixedInTarget(finding, {
      sourceLookup: treeHas(new Set()),
      fixSignatures: ["deadbeefcafe"],
    });
    expect(v.verdict).toBe("keep");
    expect(v.reason).toContain("still affected");
  });

  it("is INCONCLUSIVE when no fix signature is available", () => {
    const finding = kernelFinding();
    const v = alreadyFixedInTarget(finding, { sourceLookup: treeHas(new Set()) });
    expect(v.verdict).toBe("inconclusive");
  });

  it("harvests fix hashes from a Fixes: line in the finding text", () => {
    const finding = kernelFinding({
      analysis: "Subsystem: net/cpumap\nFixes: 1234567890ab cpumap refactor",
    });
    const v = alreadyFixedInTarget(finding, {
      sourceLookup: treeHas(new Set(["1234567890ab"])),
    });
    expect(v.verdict).toBe("drop");
  });
});

// ── Check 2: knownDupe ────────────────────────────────────────────────

describe("knownDupe", () => {
  it("extracts a bp- syzbot extid", () => {
    const finding = kernelFinding({
      response: "syzbot report bp-14cb10b0aa11 Hardware name: Google Compute Engine",
    });
    const sig = extractDupeSignature(finding);
    expect(sig.extid).toBe("bp-14cb10b0aa11");
  });

  it("DROPs a known open syzbot dupe (dvb_frontend case)", () => {
    const finding = kernelFinding({
      title: "Linux kernel kasan-uaf: dvb_frontend_stop in drivers/media",
      response: "syzbot bp-abc123def456 ...",
    });
    const feed: DupeFeedLookup = (sig) =>
      sig.extid === "bp-abc123def456"
        ? { source: "syzbot", id: sig.extid, status: "open" }
        : null;
    const v = knownDupe(finding, feed);
    expect(v.verdict).toBe("drop");
    expect(v.reason).toContain("SYZBOT:bp-abc123def456");
    expect(v.reason).toContain("open");
  });

  it("KEEPs when no feed match (potentially novel)", () => {
    const finding = kernelFinding();
    const v = knownDupe(finding, () => null);
    expect(v.verdict).toBe("keep");
    expect(v.reason).toContain("novel");
  });

  it("is INCONCLUSIVE when no signature can be extracted", () => {
    const finding = kernelFinding({ title: "Some non-kernel finding", templateId: "web-xss" });
    const v = knownDupe(finding, () => null);
    expect(v.verdict).toBe("inconclusive");
  });

  it("only trusts a bare 40-hex extid on a syzbot import", () => {
    const bare = "a".repeat(40);
    const nonSyzbot = kernelFinding({ response: `random hash ${bare}` });
    expect(extractDupeSignature(nonSyzbot).extid).toBeUndefined();
    const syzbot = kernelFinding({ response: `syzbot ${bare}` });
    expect(extractDupeSignature(syzbot).extid).toBe(bare);
  });
});

// ── Check 3: reachabilityGate ─────────────────────────────────────────

describe("reachabilityGate", () => {
  it("KEEPs an unprivileged-local sound (ALSA) UAF as an LPE vector", () => {
    const v = reachabilityGate(kernelFinding());
    expect(v.tier).toBe("unprivileged-local");
    expect(v.verdict).toBe("keep");
    expect(v.lpeRelevant).toBe(true);
  });

  it("DROPs an FS-image UAF that needs root to mount", () => {
    const finding = kernelFinding({
      title: "Linux kernel kasan-uaf: ext4_fill_super in fs/ext4",
      analysis: "Subsystem: fs/ext4",
      response: "BUG: KASAN ... ext4_fill_super mount crafted image",
    });
    const v = reachabilityGate(finding);
    expect(v.tier).toBe("mount-crafted-fs");
    expect(v.verdict).toBe("drop");
    expect(v.lpeRelevant).toBe(false);
  });

  it("DROPs a hardware-gated USB driver bug", () => {
    const finding = kernelFinding({
      title: "Linux kernel kasan-uaf: usb_probe_interface in drivers/usb",
      analysis: "Subsystem: drivers/usb",
    });
    const v = reachabilityGate(finding);
    expect(v.tier).toBe("needs-hardware");
    expect(v.verdict).toBe("drop");
  });

  it("DROPs a nested wireless-driver bug (carl9170, drivers/net/wireless)", () => {
    const finding = kernelFinding({
      title: "Linux kernel kasan-oob: carl9170_cmd_response in drivers/net/wireless",
      analysis: "Subsystem: drivers/net/wireless",
    });
    const v = reachabilityGate(finding);
    expect(v.tier).toBe("needs-hardware");
    expect(v.verdict).toBe("drop");
  });

  it("DROPs a nested wireless-driver bug (mwifiex, drivers/net/wireless)", () => {
    const finding = kernelFinding({
      title: "Linux kernel kasan-oob: mwifiex_update_bss in drivers/net/wireless",
      analysis: "Subsystem: drivers/net/wireless",
    });
    const v = reachabilityGate(finding);
    expect(v.tier).toBe("needs-hardware");
    expect(v.verdict).toBe("drop");
  });

  it("DROPs a nested HID-driver bug (hid-multitouch, drivers/hid)", () => {
    const finding = kernelFinding({
      title: "Linux kernel kasan-oob: mt_report in drivers/hid",
      analysis: "Subsystem: drivers/hid",
    });
    const v = reachabilityGate(finding);
    expect(v.tier).toBe("needs-hardware");
    expect(v.verdict).toBe("drop");
  });

  it("does NOT drop a genuinely-local char driver as needs-hardware", () => {
    const finding = kernelFinding({
      title: "Linux kernel kasan-uaf: local_char_ioctl in drivers/char",
      analysis: "Subsystem: drivers/char",
    });
    const v = reachabilityGate(finding);
    expect(v.tier).not.toBe("needs-hardware");
    expect(v.verdict).not.toBe("drop");
  });

  it("DROPs a CAP_SYS_ADMIN / netfilter-gated surface", () => {
    const finding = kernelFinding({
      title: "Linux kernel kasan-oob: nft_do_chain in net/netfilter",
      analysis: "Subsystem: net/netfilter",
    });
    const v = reachabilityGate(finding);
    expect(v.tier).toBe("needs-cap-sys-admin");
    expect(v.verdict).toBe("drop");
  });

  it("classifies a remote net/tcp bug as remote (kept, non-LPE)", () => {
    const finding = kernelFinding({
      title: "Linux kernel kasan-uaf: tcp_v4_rcv in net/tcp",
      analysis: "Subsystem: net/tcp",
    });
    const v = reachabilityGate(finding);
    expect(v.tier).toBe("remote");
    expect(v.verdict).toBe("keep");
    expect(v.lpeRelevant).toBe(false);
  });

  it("DROPs a not-built-config finding when the CONFIG is absent", () => {
    const finding = kernelFinding({
      title: "Linux kernel kasan-uaf: foo_ioctl in io_uring",
      analysis: "Subsystem: io_uring\nrequires CONFIG_EXOTIC_THING",
    });
    const v = reachabilityGate(finding, { isConfigBuilt: (c) => c !== "CONFIG_EXOTIC_THING" });
    expect(v.tier).toBe("not-built-config");
    expect(v.verdict).toBe("drop");
  });

  it("is INCONCLUSIVE (unknown tier) for an unclassifiable subsystem", () => {
    const finding = kernelFinding({
      title: "Linux kernel kasan-uaf: weird_thing in unknown",
      analysis: "Subsystem: unknown",
    });
    const v = reachabilityGate(finding);
    expect(v.tier).toBe("unknown");
    expect(v.verdict).toBe("inconclusive");
  });
});

// ── Compose: autoTriage ───────────────────────────────────────────────

describe("autoTriage", () => {
  const keepAllLookup: TargetSourceLookup = () => null;
  const noDupe: DupeFeedLookup = () => null;

  it("KEEPs a novel, unprivileged-local, not-fixed finding", () => {
    const finding = kernelFinding();
    const r = autoTriage(finding, { sourceLookup: keepAllLookup, dupeFeed: noDupe });
    expect(r.verdict).toBe("keep");
    expect(r.tier).toBe("unprivileged-local");
    expect(r.reasons).toHaveLength(3);
  });

  it("DROPs when already fixed in target (drop wins over a keep reachability)", () => {
    const finding = kernelFinding({ dedupRefs: ["e5c33cdc6f40"] });
    const r = autoTriage(finding, {
      sourceLookup: (sig) => (sig === "e5c33cdc6f40" ? { signature: sig, matched: "x" } : null),
      dupeFeed: noDupe,
    });
    expect(r.verdict).toBe("drop");
    expect(r.reasons.some((s) => s.includes("backport-lag"))).toBe(true);
  });

  it("DROPs a known syzbot dupe", () => {
    const finding = kernelFinding({ response: "syzbot bp-deadbeef00 ..." });
    const r = autoTriage(finding, {
      sourceLookup: keepAllLookup,
      dupeFeed: (sig) => (sig.extid ? { source: "syzbot", id: sig.extid, status: "open" } : null),
    });
    expect(r.verdict).toBe("drop");
  });

  it("DROPs a hardware-gated bug via reachability", () => {
    const finding = kernelFinding({
      title: "Linux kernel kasan-uaf: usb_probe in drivers/usb",
      analysis: "Subsystem: drivers/usb",
    });
    const r = autoTriage(finding, { sourceLookup: keepAllLookup, dupeFeed: noDupe });
    expect(r.verdict).toBe("drop");
    expect(r.tier).toBe("needs-hardware");
  });

  it("is INCONCLUSIVE for an unclassifiable finding — never silently dropped", () => {
    const finding = kernelFinding({
      title: "Linux kernel kasan-uaf: weird in unknown",
      analysis: "Subsystem: unknown",
    });
    const r = autoTriage(finding, { sourceLookup: keepAllLookup, dupeFeed: noDupe });
    expect(r.verdict).toBe("inconclusive");
    expect(r.tier).toBe("unknown");
  });

  it("runs with no lookups supplied (checks skip to inconclusive, reachability still classifies)", () => {
    const finding = kernelFinding();
    const r = autoTriage(finding);
    expect(r.checks.alreadyFixed.verdict).toBe("inconclusive");
    expect(r.checks.knownDupe.verdict).toBe("inconclusive");
    expect(r.verdict).toBe("keep"); // reachability keeps (unprivileged-local)
  });
});

// ── False-refute fix: classifyVerifyOutcome ───────────────────────────

describe("classifyVerifyOutcome", () => {
  it("maps a build failure to inconclusive, never refuted", () => {
    const d = classifyVerifyOutcome({ proposed: "rejected", failureKind: "build" });
    expect(d.outcome).toBe("inconclusive");
    expect(d.coerced).toBe(true);
    expect(d.reason).toContain("never refuted");
  });

  it("maps a missing-image (pruned oracle image) failure to inconclusive", () => {
    const d = classifyVerifyOutcome({ proposed: "rejected", failureKind: "missing-image" });
    expect(d.outcome).toBe("inconclusive");
  });

  it("coerces a bare rejected with no disproof evidence to inconclusive (the false-refute trap)", () => {
    const d = classifyVerifyOutcome({ proposed: "rejected" });
    expect(d.outcome).toBe("inconclusive");
    expect(d.coerced).toBe(true);
    expect(d.reason).toContain("false-refute");
  });

  it("honours a rejected backed by real disproof evidence", () => {
    const d = classifyVerifyOutcome({ proposed: "rejected", hasDisproofEvidence: true });
    expect(d.outcome).toBe("rejected");
    expect(d.coerced).toBe(false);
  });

  it("passes confirmed / inconclusive through untouched", () => {
    expect(classifyVerifyOutcome({ proposed: "confirmed" }).outcome).toBe("confirmed");
    expect(classifyVerifyOutcome({ proposed: "inconclusive" }).outcome).toBe("inconclusive");
  });

  it("infra failure still coerces even a confirmed proposal to inconclusive", () => {
    const d = classifyVerifyOutcome({ proposed: "confirmed", failureKind: "infra" });
    expect(d.outcome).toBe("inconclusive");
    expect(d.coerced).toBe(true);
  });

  it("maps outcomes to DB verify_status strings", () => {
    expect(verifyStatusFromOutcome("confirmed")).toBe("verified");
    expect(verifyStatusFromOutcome("rejected")).toBe("refuted");
    expect(verifyStatusFromOutcome("inconclusive")).toBe("inconclusive");
  });
});

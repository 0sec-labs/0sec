import { describe, expect, it } from "vitest";

import { classifyPatchGapReachability } from "./patch-gap-reachability.js";

describe("kernel/patch-gap-reachability: classifyPatchGapReachability", () => {
  it("marks kernel/bpf/ unreachable (unprivileged BPF disabled on kernelCTF)", () => {
    const res = classifyPatchGapReachability("kernel/bpf/verifier.c");
    expect(res.reachable).toBe("unreachable");
    expect(res.reason).toMatch(/unprivileged BPF disabled/i);
  });

  it("marks net/core/filter.c (BPF/SOCKMAP hook) unreachable even though net/core/ itself is reachable", () => {
    const res = classifyPatchGapReachability("net/core/filter.c");
    expect(res.reachable).toBe("unreachable");
    expect(res.reason).toMatch(/BPF|SOCKMAP/i);
  });

  it("marks fs/xfs/ (mount-triggered, needs CAP_SYS_ADMIN) unreachable", () => {
    const res = classifyPatchGapReachability("fs/xfs/xfs_inode.c");
    expect(res.reachable).toBe("unreachable");
    expect(res.reason).toMatch(/CAP_SYS_ADMIN/);
  });

  it("marks any other fs/ path unreachable via the generic mount-trigger fallback", () => {
    const res = classifyPatchGapReachability("fs/ext4/inode.c");
    expect(res.reachable).toBe("unreachable");
    expect(res.reason).toMatch(/mount/i);
  });

  it("marks drivers/crypto/ (hardware crypto accelerator) unreachable — no such hardware on kernelCTF's GCE VM", () => {
    const res = classifyPatchGapReachability("drivers/crypto/ccp/ccp-ops.c");
    expect(res.reachable).toBe("unreachable");
    expect(res.reason).toMatch(/hardware/i);
  });

  it("marks net/xfrm/ (IPsec, needs CAP_NET_ADMIN) unreachable — userns->netns path closed since 2025-07-01", () => {
    const res = classifyPatchGapReachability("net/xfrm/xfrm_policy.c");
    expect(res.reachable).toBe("unreachable");
    expect(res.reason).toMatch(/CAP_NET_ADMIN/);
  });

  it("marks netfilter/NAT paths unreachable (CAP_NET_ADMIN)", () => {
    expect(classifyPatchGapReachability("net/netfilter/nf_nat_core.c").reachable).toBe("unreachable");
    expect(classifyPatchGapReachability("net/ipv4/netfilter/iptable_nat.c").reachable).toBe("unreachable");
  });

  it("marks tunnel devices and ioam6 config unreachable (CAP_NET_ADMIN)", () => {
    expect(classifyPatchGapReachability("net/ipv4/ip_gre.c").reachable).toBe("unreachable");
    expect(classifyPatchGapReachability("net/ipv6/sit.c").reachable).toBe("unreachable");
    expect(classifyPatchGapReachability("net/ipv6/ioam6_iptunnel.c").reachable).toBe("unreachable");
  });

  it("marks non-x86_64 arch code (e.g. arch/s390) unreachable — kernelCTF COS target is x86_64", () => {
    const res = classifyPatchGapReachability("arch/s390/kernel/traps.c");
    expect(res.reachable).toBe("unreachable");
    expect(res.reason).toMatch(/x86_64/);
  });

  it("does not penalize arch/x86/ code", () => {
    // Not in any reachable prefix list, but must not be caught by the
    // non-x86-arch rule — falls to the generic conservative default instead.
    const res = classifyPatchGapReachability("arch/x86/kernel/traps.c");
    expect(res.reason).not.toMatch(/x86_64/);
  });

  it("marks af_unix (non-SOCKMAP) reachable", () => {
    const res = classifyPatchGapReachability("net/unix/af_unix.c");
    expect(res.reachable).toBe("reachable");
  });

  it("marks vsock (+ loopback) reachable", () => {
    const res = classifyPatchGapReachability("net/vmw_vsock/vmci_transport.c");
    expect(res.reachable).toBe("reachable");
  });

  it("marks af_alg (crypto/) reachable", () => {
    const res = classifyPatchGapReachability("crypto/algif_skcipher.c");
    expect(res.reachable).toBe("reachable");
  });

  it("marks keyrings, sysvipc, futex, epoll reachable", () => {
    expect(classifyPatchGapReachability("security/keys/keyring.c").reachable).toBe("reachable");
    expect(classifyPatchGapReachability("ipc/msg.c").reachable).toBe("reachable");
    expect(classifyPatchGapReachability("kernel/futex/core.c").reachable).toBe("reachable");
    expect(classifyPatchGapReachability("fs/eventpoll.c").reachable).toBe("reachable");
  });

  it("defaults an unmapped path to unreachable (conservative), never 'reachable'", () => {
    const res = classifyPatchGapReachability("drivers/net/wireless/mwifiex/main.c");
    expect(res.reachable).toBe("unreachable");
    expect(res.reason).toMatch(/no confirmed/i);
  });
});

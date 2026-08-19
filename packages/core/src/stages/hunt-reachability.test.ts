/**
 * Path -> kernelCTF-reachability classification + gate. Grounded in the same
 * COS-6.12 facts as `services/orchestrator/src/kernelctf-config.ts` (see
 * hunt-reachability.ts's header for the citation).
 */

import { describe, expect, it } from "vitest";
import { applyReachabilityGate, classifyPathReachability } from "./hunt-reachability.js";

describe("classifyPathReachability", () => {
  it("classifies core kernelCTF-reachable paths as reachable", () => {
    expect(classifyPathReachability("crypto/algif_aead.c")).toBe("reachable");
    expect(classifyPathReachability("net/unix/af_unix.c")).toBe("reachable");
    expect(classifyPathReachability("net/core/dst.c")).toBe("reachable");
    expect(classifyPathReachability("net/ipv4/tcp.c")).toBe("reachable");
    expect(classifyPathReachability("net/ipv6/udp.c")).toBe("reachable");
    expect(classifyPathReachability("net/packet/af_packet.c")).toBe("reachable");
    expect(classifyPathReachability("net/vmw_vsock/af_vsock.c")).toBe("reachable");
    expect(classifyPathReachability("net/tls/tls_main.c")).toBe("reachable");
    expect(classifyPathReachability("net/xfrm/xfrm_state.c")).toBe("reachable");
    expect(classifyPathReachability("net/netlink/af_netlink.c")).toBe("reachable");
    expect(classifyPathReachability("ipc/msg.c")).toBe("reachable");
    expect(classifyPathReachability("fs/ext4/inode.c")).toBe("reachable");
    expect(classifyPathReachability("fs/xfs/xfs_inode.c")).toBe("reachable");
    expect(classifyPathReachability("kernel/bpf/verifier.c")).toBe("reachable");
    expect(classifyPathReachability("security/keys/key.c")).toBe("reachable");
  });

  it("classifies exotic drivers / unbuilt subsystems as unreachable", () => {
    expect(classifyPathReachability("drivers/infiniband/core/verbs.c")).toBe("unreachable");
    expect(classifyPathReachability("drivers/net/wireless/marvell/mwifiex/txrx.c")).toBe("unreachable");
    expect(classifyPathReachability("drivers/media/usb/uvc/uvc_driver.c")).toBe("unreachable");
    expect(classifyPathReachability("drivers/hid/hid-core.c")).toBe("unreachable");
    expect(classifyPathReachability("drivers/usb/gadget/udc/core.c")).toBe("unreachable");
    expect(classifyPathReachability("drivers/usb/atm/ueagle-atm.c")).toBe("unreachable");
    expect(classifyPathReachability("drivers/xen/balloon.c")).toBe("unreachable");
    expect(classifyPathReachability("drivers/staging/rtl8723bs/core/rtw_xmit.c")).toBe("unreachable");
    expect(classifyPathReachability("net/bluetooth/hci_core.c")).toBe("unreachable");
    expect(classifyPathReachability("net/can/raw.c")).toBe("unreachable");
    expect(classifyPathReachability("net/kcm/kcmsock.c")).toBe("unreachable");
    expect(classifyPathReachability("fs/f2fs/inode.c")).toBe("unreachable");
    expect(classifyPathReachability("fs/reiserfs/inode.c")).toBe("unreachable");
    expect(classifyPathReachability("fs/hpfs/namei.c")).toBe("unreachable");
    expect(classifyPathReachability("fs/sysv/inode.c")).toBe("unreachable");
    expect(classifyPathReachability("fs/ntfs/inode.c")).toBe("unreachable");
    expect(classifyPathReachability("fs/jfs/inode.c")).toBe("unreachable");
  });

  it("classifies paths outside both lists as unknown, not unreachable", () => {
    expect(classifyPathReachability("mm/memory.c")).toBe("unknown");
    expect(classifyPathReachability("kernel/sched/core.c")).toBe("unknown");
    expect(classifyPathReachability("fs/ntfs3/inode.c")).toBe("unknown"); // distinct from legacy fs/ntfs/
  });

  it("handles absolute paths under an arbitrary source root the same way", () => {
    expect(classifyPathReachability("/root/linux-6.12.93/crypto/algif_aead.c")).toBe("reachable");
    expect(classifyPathReachability("/root/linux-6.12.93/drivers/net/wireless/marvell/mwifiex/txrx.c")).toBe(
      "unreachable",
    );
  });

  it("requires a path-segment boundary, not a bare substring match", () => {
    // "notdrivers/staging/x.c" contains the substring "drivers/staging/" but
    // NOT as its own path segment (no "/" or start-of-string immediately
    // before "drivers") — must not misclassify it as unreachable.
    expect(classifyPathReachability("notdrivers/staging/x.c")).toBe("unknown");
  });
});

describe("applyReachabilityGate", () => {
  const paths = ["drivers/infiniband/core/verbs.c", "crypto/algif_aead.c", "mm/memory.c"];

  it("is a no-op when both flags are unset (default-off backward compat)", () => {
    const result = applyReachabilityGate(paths, {});
    expect(result.paths).toEqual(paths);
    expect(result.unreachableCount).toBe(0);
  });

  it("is a no-op when both flags are explicitly false", () => {
    const result = applyReachabilityGate(paths, { reachableOnly: false, reachablePrefer: false });
    expect(result.paths).toEqual(paths);
    expect(result.unreachableCount).toBe(0);
  });

  it("reachableOnly drops both unreachable and unknown paths, keeping only reachable ones", () => {
    const result = applyReachabilityGate(paths, { reachableOnly: true });
    expect(result.paths).toEqual(["crypto/algif_aead.c"]);
    expect(result.unreachableCount).toBe(1); // only the classified-unreachable one is counted, not the unknown one
  });

  it("reachablePrefer reorders reachable-first without dropping anything", () => {
    const result = applyReachabilityGate(paths, { reachablePrefer: true });
    expect(result.paths).toEqual(["crypto/algif_aead.c", "mm/memory.c", "drivers/infiniband/core/verbs.c"]);
    expect(result.paths).toHaveLength(paths.length);
    expect(result.unreachableCount).toBe(1);
  });

  it("reachableOnly takes priority when both flags are set", () => {
    const result = applyReachabilityGate(paths, { reachableOnly: true, reachablePrefer: true });
    expect(result.paths).toEqual(["crypto/algif_aead.c"]);
  });

  it("reachablePrefer preserves relative order within each reachability tier (stable sort)", () => {
    const twoReachable = ["net/tls/tls_main.c", "crypto/algif_aead.c", "drivers/staging/x.c"];
    const result = applyReachabilityGate(twoReachable, { reachablePrefer: true });
    expect(result.paths).toEqual(["net/tls/tls_main.c", "crypto/algif_aead.c", "drivers/staging/x.c"]);
  });
});

/**
 * kernelCTF-reachability gate for HUNT CANDIDATE SELECTION.
 *
 * `generateVariantCandidates` (variant-candidates.ts) ranks candidate sites
 * purely by grep-pattern density (how many independent patterns matched a
 * file) — a signal that says nothing about whether the site is even
 * REACHABLE on the kernelCTF (COS) target. Observed this session:
 * density-only ranking landed overwhelmingly on EXOTIC DRIVERS that are
 * `# CONFIG_* is not set` on COS (RXE/infiniband, mwifiex, hidraw,
 * uea/ueagle-atm, xen paravirt) — best-of-N finder depth spent on surface
 * that can never produce a kernelCTF-eligible bug, however real the finding.
 *
 * This module is a small, PATH-based, self-contained classifier — no I/O, no
 * dependency on `services/orchestrator` (core must not import from services;
 * the wrong direction). `services/orchestrator/src/kernelctf-config.ts`
 * encodes the SAME COS-6.12 ground truth (CONFIG_* symbol state, keyed by
 * syzbot SUBSYSTEM TOKEN) for the syzbot-feed reachability gate. This module
 * re-derives the same facts as source-tree PATH PREFIXES, because the hunt's
 * candidate list is file paths, not subsystem tokens. Keep the two in sync if
 * the COS lakitu_defconfig facts change; see that file for the full
 * CONFIG_*-symbol-level citations (lakitu_defconfig verified 2026-06-18).
 *
 * Deliberately conservative: a path matching neither list is "unknown", and
 * `reachableOnly` treats "unknown" the same as "unreachable" — this mirrors
 * kernelctf-config.ts's own posture ("Subsystems NOT in this map are treated
 * as unknown reachability ... conservative — routed to distro-only rather
 * than asserted CTF-eligible").
 */

/** Reachability verdict for one candidate path on the kernelCTF COS target. */
export type PathReachability = "reachable" | "unreachable" | "unknown";

/**
 * Path prefixes that are UNREACHABLE on the kernelCTF COS-6.12 target —
 * either not built at all (`# CONFIG_X is not set` in lakitu_defconfig) or
 * requiring a capability/trigger (mount, a physical device, a Bluetooth/CAN
 * controller) a zero-cap kernelCTF attacker doesn't have. The first block is
 * grounded directly in `services/orchestrator/src/kernelctf-config.ts`'s
 * `COS_CONFIG_STATE` (`not-built` entries) and `SUBSYSTEM_RULES`; the second
 * block is exotic/unbuilt drivers observed landing density-ranked hunt
 * candidates this session — same "# CONFIG_* is not set on COS" story, not
 * yet in that file's subsystem-token map.
 */
export const UNREACHABLE_PATH_PREFIXES: readonly string[] = [
  // ── Not built on COS (kernelctf-config.ts COS_CONFIG_STATE) ──
  "net/kcm/", // CONFIG_AF_KCM not-built — the original "kcm lesson"
  "net/bluetooth/", // CONFIG_BT not-built
  "net/can/", // CONFIG_CAN not-built
  "fs/f2fs/", // CONFIG_F2FS_FS not-built

  // ── Exotic/unbuilt drivers (observed this session; same story, not yet
  //    in kernelctf-config.ts's token map) ──
  "drivers/infiniband/", // RXE/infiniband — not built on COS
  "drivers/net/wireless/", // mwifiex etc. — not built on COS
  "drivers/media/", // exotic media drivers — not built on COS
  "drivers/hid/", // hidraw — not built on COS
  "drivers/usb/gadget/", // USB gadget — not built / not a zero-cap network path
  "drivers/usb/atm/", // uea/ueagle-atm — not built on COS
  "drivers/xen/", // xen paravirt — COS is not a Xen guest
  "drivers/staging/", // staging tree — not built on COS, churny/unstable

  // ── Exotic filesystems: the trigger is mount(2), which needs
  //    CAP_SYS_ADMIN a zero-cap kernelCTF attacker doesn't have (mirrors
  //    kernelctf-config.ts's ext4/xfs/btrfs/ntfs3/fuse `needsCap:
  //    CAP_SYS_ADMIN` entries); these ones aren't built on COS at all either ──
  "fs/reiserfs/",
  "fs/hpfs/",
  "fs/sysv/",
  "fs/ntfs/", // legacy ntfs (distinct from the ntfs3 module)
  "fs/jfs/",
];

/**
 * Path prefixes that ARE built + zero-cap reachable on the kernelCTF COS-6.12
 * target — grounded in `services/orchestrator/src/kernelctf-config.ts`'s
 * `COS_CONFIG_STATE` (`builtin`/`module` entries) mapped from CONFIG symbol
 * to the source directory that implements it.
 */
export const REACHABLE_PATH_PREFIXES: readonly string[] = [
  "crypto/", // CONFIG_CRYPTO_USER_API_{AEAD,SKCIPHER,HASH} — AF_ALG, zero-cap
  "net/unix/", // CONFIG_UNIX — AF_UNIX, zero-cap
  "net/core/", // core socket/skb plumbing, zero-cap from any AF_* socket
  "net/ipv4/", // core IPv4, zero-cap
  "net/ipv6/", // core IPv6, zero-cap
  // CONFIG_PACKET — kernelctf-config.ts marks needsCap CAP_NET_RAW for
  // AF_PACKET itself; still listed reachable here (worth the finder budget).
  "net/packet/",
  "net/vmw_vsock/", // CONFIG_VSOCKETS(+_LOOPBACK) — AF_VSOCK loopback, zero-cap
  "net/tls/", // CONFIG_TLS — kTLS, zero-cap
  "net/xfrm/", // IPsec policy/state — reachable via standard AF_INET{,6} sockets
  "net/netlink/", // AF_NETLINK core — zero-cap socket family
  "ipc/", // CONFIG_SYSVIPC — System-V IPC (msg/sem/shm), zero-cap
  // CONFIG_EXT4_FS / CONFIG_XFS_FS — kernelctf-config.ts marks needsCap
  // CAP_SYS_ADMIN for the *mount* trigger; still listed reachable here (core
  // FS code is real audit surface, worth the finder budget).
  "fs/ext4/",
  "fs/xfs/",
  // unprivileged_bpf_disabled is commonly runtime-off; listed reachable here
  // rather than dropped outright (flag the caveat in the finder hint instead).
  "kernel/bpf/",
  "security/keys/", // CONFIG_KEYS — keyrings / add_key(2), zero-cap
];

/** True if `path` contains `prefix` as a whole path-segment sequence (anchored at start-of-string or a preceding "/"). */
function hasPathSegmentPrefix(path: string, prefix: string): boolean {
  const idx = path.indexOf(prefix);
  if (idx === -1) return false;
  return idx === 0 || path[idx - 1] === "/";
}

/** Classify one candidate path against the reachable/unreachable prefix lists above. The deny-list wins on any overlap. */
export function classifyPathReachability(path: string): PathReachability {
  const norm = path.replace(/\\/g, "/");
  for (const prefix of UNREACHABLE_PATH_PREFIXES) if (hasPathSegmentPrefix(norm, prefix)) return "unreachable";
  for (const prefix of REACHABLE_PATH_PREFIXES) if (hasPathSegmentPrefix(norm, prefix)) return "reachable";
  return "unknown";
}

export interface ReachabilityGateOptions {
  /**
   * Strict: keep ONLY paths classified "reachable" — drops BOTH
   * "unreachable" and "unknown" (conservative; mirrors kernelctf-config.ts's
   * posture that unmapped subsystems are NOT asserted CTF-eligible). Takes
   * priority over `reachablePrefer` when both are set.
   */
  reachableOnly?: boolean;
  /**
   * Soft: stable-sort so "reachable" paths come first, then "unknown", then
   * "unreachable" — nothing is dropped, only reordered, so a later cap
   * doesn't truncate reachable candidates away.
   */
  reachablePrefer?: boolean;
}

export interface ReachabilityGateResult {
  paths: string[];
  /**
   * How many input paths classified "unreachable". In `reachableOnly` mode
   * these were DROPPED (paths classified "unknown" were dropped too, but
   * aren't counted here); in `reachablePrefer` mode they were only
   * DEPRIORITIZED — moved to the end, still present in `paths`.
   */
  unreachableCount: number;
}

/**
 * Apply the reachability gate to a ranked candidate path list. Both flags
 * unset (the default) is a no-op — returns `paths` unchanged and
 * `unreachableCount: 0` — so callers that never opt in see byte-identical
 * behavior to before this gate existed.
 */
export function applyReachabilityGate(paths: string[], opts: ReachabilityGateOptions): ReachabilityGateResult {
  if (!opts.reachableOnly && !opts.reachablePrefer) return { paths, unreachableCount: 0 };

  const classified = paths.map((path) => ({ path, cls: classifyPathReachability(path) }));
  const unreachableCount = classified.filter((c) => c.cls === "unreachable").length;

  if (opts.reachableOnly) {
    return { paths: classified.filter((c) => c.cls === "reachable").map((c) => c.path), unreachableCount };
  }

  const rank: Record<PathReachability, number> = { reachable: 0, unknown: 1, unreachable: 2 };
  const sorted = [...classified].sort((a, b) => rank[a.cls] - rank[b.cls]).map((c) => c.path);
  return { paths: sorted, unreachableCount };
}

/**
 * kernel/patch-gap-reachability.ts
 *
 * Patch-gap-specific kernelCTF COS-6.12 reachability classification (the
 * untrustworthy-reachability fix).
 *
 * `classifyPathReachability` (`../stages/hunt-reachability.ts`) is tuned for
 * HUNT CANDIDATE RANKING: a narrow allow/deny prefix list built to keep
 * exotic, not-built-on-COS drivers out of the finder's budget, deliberately
 * generous elsewhere ("core FS code is real audit surface, worth the finder
 * budget" — its own module doc, re: fs/ext4, fs/xfs). Reusing it for the
 * patch-gap monitor's reachability GATE (not a ranking hint — a hard
 * present/absent decision about whether a candidate is a real kernelCTF
 * 1day) inherited that generosity as false "reachable" verdicts:
 *   - `kernel/bpf/` — marked reachable there; unprivileged BPF is actually
 *     disabled on kernelCTF, so the whole BPF verifier + SOCKMAP surface is
 *     unreachable to a zero-cap attacker.
 *   - `fs/xfs/` (and fs/ext4/) — marked reachable there; the FS code is only
 *     reachable via mount(2), which needs CAP_SYS_ADMIN a zero-cap attacker
 *     doesn't have.
 *   - `net/xfrm/` — marked reachable there; IPsec policy/state needs
 *     CAP_NET_ADMIN, and the userns→netns→CAP_NET_ADMIN unprivileged trigger
 *     has been closed since 2025-07-01.
 *   - `drivers/crypto/` wasn't in either list (fell to "unknown"), but this
 *     module makes the unreachability explicit with a reason: no hardware
 *     crypto accelerator (ccp/qat/hisilicon/eip93/s390-class) exists on
 *     kernelCTF's GCE VM.
 *
 * Grounded in the SAME CONFIRMED kernelCTF COS-6.12 ground truth as
 * `services/orchestrator/src/kernelctf-config.ts` (`COS_CONFIG_STATE`,
 * `SUBSYSTEM_RULES`, `needsCap`), re-derived as source-tree PATH PREFIXES
 * (patch-gap candidates are file paths, not subsystem tokens — same
 * reason `hunt-reachability.ts` exists as a separate module rather than
 * importing kernelctf-config.ts directly; `core` must not import from
 * `services`). Keep the three in sync if the COS lakitu_defconfig facts or
 * the userns-disabled runtime posture change.
 *
 * Deliberately conservative: unlike `classifyPathReachability`'s three-state
 * "reachable" / "unreachable" / "unknown" (where "unknown" still needs a
 * caller opt-in to be excluded), this classifier's TWO-state result never
 * defaults an unmapped path to "reachable" — every unmapped path resolves to
 * "unreachable" with a reason explaining why (no confirmed mapping).
 */

/** kernelCTF COS-6.12 zero-cap reachability verdict for the patch-gap monitor. No "unknown" state — an unmapped path defaults to "unreachable" (see module doc). */
export type PatchGapReachability = "reachable" | "unreachable";

export interface PatchGapReachabilityResult {
  reachable: PatchGapReachability;
  /** Human-readable reason, always set — surfaced in candidate triage output. */
  reason: string;
}

/** True if `path` contains `prefix` as a whole path-segment sequence (anchored at start-of-string or a preceding "/"). Mirrors `hunt-reachability.ts`'s helper of the same name. */
function hasPathSegmentPrefix(path: string, prefix: string): boolean {
  const idx = path.indexOf(prefix);
  if (idx === -1) return false;
  return idx === 0 || path[idx - 1] === "/";
}

interface PathRule {
  prefix: string;
  reason: string;
}

/**
 * Paths CONFIRMED unreachable on kernelCTF COS-6.12, checked in order — first
 * match wins. More specific entries (`net/core/filter.c`) are listed before
 * broader siblings that would otherwise be misclassified reachable
 * (`net/core/` itself is zero-cap reachable; the BPF/SOCKMAP hook in
 * `filter.c` is not).
 */
const UNREACHABLE_RULES: readonly PathRule[] = [
  // Unprivileged BPF disabled on kernelCTF — kills the BPF verifier + SOCKMAP
  // attack surface even though CONFIG_BPF_SYSCALL is builtin on COS.
  { prefix: "net/core/filter.c", reason: "BPF/SOCKMAP hook — unprivileged BPF disabled on kernelCTF COS" },
  { prefix: "kernel/bpf/", reason: "unprivileged BPF disabled on kernelCTF COS" },

  // Hardware-backed crypto accelerator drivers — no matching hardware exists
  // on a GCE VM (ccp/qat/hisilicon/eip93/s390-class controllers).
  {
    prefix: "drivers/crypto/",
    reason: "hardware crypto accelerator driver (ccp/qat/hisilicon/eip93/s390-class) — no such hardware on kernelCTF's GCE VM",
  },

  // CAP_NET_ADMIN-gated networking: IPsec, netfilter/NAT, tunnel devices,
  // ioam6 config. Unprivileged userns has been OFF since 2025-07-01, closing
  // the userns->netns->CAP_NET_ADMIN unprivileged-trigger path.
  { prefix: "net/xfrm/", reason: "IPsec policy/state needs CAP_NET_ADMIN; userns->netns path closed since 2025-07-01" },
  { prefix: "net/netfilter/", reason: "netfilter/NAT needs CAP_NET_ADMIN; userns->netns path closed since 2025-07-01" },
  { prefix: "net/ipv4/netfilter/", reason: "netfilter/NAT needs CAP_NET_ADMIN; userns->netns path closed since 2025-07-01" },
  { prefix: "net/ipv6/netfilter/", reason: "netfilter/NAT needs CAP_NET_ADMIN; userns->netns path closed since 2025-07-01" },
  { prefix: "net/ipv6/ioam6", reason: "ioam6 config needs CAP_NET_ADMIN" },
  { prefix: "net/ipv4/ip_gre.c", reason: "GRE tunnel device needs CAP_NET_ADMIN" },
  { prefix: "net/ipv4/ipip.c", reason: "IPIP tunnel device needs CAP_NET_ADMIN" },
  { prefix: "net/ipv4/ip_tunnel.c", reason: "IP tunnel device needs CAP_NET_ADMIN" },
  { prefix: "net/ipv6/sit.c", reason: "SIT tunnel device needs CAP_NET_ADMIN" },
  { prefix: "net/ipv6/ip6_tunnel.c", reason: "IPv6 tunnel device needs CAP_NET_ADMIN" },
  { prefix: "net/ipv6/ip6_gre.c", reason: "IPv6 GRE tunnel device needs CAP_NET_ADMIN" },

  // Explicit mount-triggered filesystem example the gate is grounded on; the
  // generic fs/ fallback below (after the reachable-list check) covers the
  // rest of the tree, e.g. fs/ext4/.
  { prefix: "fs/xfs/", reason: "XFS mount trigger needs CAP_SYS_ADMIN — not zero-cap on kernelCTF" },
];

/**
 * Paths CONFIRMED zero-cap reachable on kernelCTF COS-6.12 — checked after
 * `UNREACHABLE_RULES` (so `net/core/filter.c` above wins over the broader
 * `net/core/` entry here).
 */
const REACHABLE_PREFIXES: readonly string[] = [
  "net/unix/", // AF_UNIX (non-SOCKMAP) — zero-cap
  "net/vmw_vsock/", // AF_VSOCK + loopback — zero-cap
  "crypto/", // AF_ALG (software crypto API) — zero-cap
  "security/keys/", // keyrings / add_key(2) — zero-cap
  "ipc/", // System-V IPC (msg/sem/shm) — zero-cap
  "kernel/futex", // futex(2) — zero-cap (matches kernel/futex.c and kernel/futex/)
  "fs/eventpoll.c", // epoll_create(2) — zero-cap, NOT a mount trigger
  "net/core/", // core socket/skb plumbing — zero-cap from any AF_* socket
  "net/netlink/", // AF_NETLINK — zero-cap socket family
];

/**
 * Classify one candidate path's kernelCTF COS-6.12 reachability for the
 * patch-gap monitor. See module doc for the false-"reachable" bug this fixes
 * and the confirmed-gates grounding.
 */
export function classifyPatchGapReachability(path: string): PatchGapReachabilityResult {
  const norm = path.replace(/\\/g, "/");

  for (const rule of UNREACHABLE_RULES) {
    if (hasPathSegmentPrefix(norm, rule.prefix)) return { reachable: "unreachable", reason: rule.reason };
  }

  for (const prefix of REACHABLE_PREFIXES) {
    if (hasPathSegmentPrefix(norm, prefix)) {
      return { reachable: "reachable", reason: `zero-cap reachable on kernelCTF COS-6.12 (${prefix})` };
    }
  }

  // Non-x86_64 architecture code — the kernelCTF COS target is x86_64 only.
  if (hasPathSegmentPrefix(norm, "arch/") && !hasPathSegmentPrefix(norm, "arch/x86/")) {
    return { reachable: "unreachable", reason: "non-x86_64 arch code — kernelCTF COS target is x86_64" };
  }

  // Generic mount-triggered filesystem catch-all: any other fs/ path needs
  // CAP_SYS_ADMIN via mount(2) (fs/eventpoll.c above is the documented
  // exception — reached via epoll_create(2), not mount).
  if (hasPathSegmentPrefix(norm, "fs/")) {
    return {
      reachable: "unreachable",
      reason: "filesystem code reached via mount(2), needs CAP_SYS_ADMIN — not zero-cap on kernelCTF",
    };
  }

  return {
    reachable: "unreachable",
    reason: "no confirmed kernelCTF COS-6.12 reachability mapping for this path — defaulting to unreachable (conservative)",
  };
}

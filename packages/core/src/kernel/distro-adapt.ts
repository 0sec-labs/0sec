/**
 * kernel/distro-adapt.ts
 *
 * SyzBridge-style "upstream PoC → downstream distro/LTS adaptation" — the
 * analysis half of the technique from SyzBridge (Zou et al., NDSS'24). That
 * paper's headline finding: only ~19% of upstream syzbot PoCs reproduce
 * unmodified on real distro/LTS kernels, but ADAPTING them (config/env deltas +
 * reproducer adjustments) lifts root reproduction to ~61%. The gap is almost
 * never the bug being absent — it's the downstream kernel being built/configured
 * differently than the upstream test kernel the PoC was minimized against, plus
 * missing runtime preconditions (loop device, module load, user namespaces).
 *
 * This module produces an ADAPTATION PLAN: given a reproducer that works on an
 * upstream kernel, what config/env deltas + reproducer adjustments are needed to
 * run it against a target distro/LTS kernel (Debian 12 = 6.1.y, Debian 6.6
 * backport, RHEL-ish, etc.). It serves our older-LTS/distro hunt (CopyFail
 * page-cache LPE class, rxrpc CVE-2026-43500) where the bug lives in an
 * LTS/distro kernel and we already have an upstream PoC shape.
 *
 * Two layers, mirroring `spec-gen.ts`:
 *   1. DETERMINISTIC core (no deps, no network, no LLM): parse the syzkaller
 *      reproducer header + scan the C reproducer for known env-setup calls, then
 *      diff the PoC's required syzkaller features / subsystem against the target
 *      distro's known config posture. Every feature/subsystem maps to a REAL
 *      CONFIG_ symbol and a concrete precondition. This is the grounded part.
 *   2. LLM-ASSIST (optional): when a {@link NativeRuntime} is supplied, ask the
 *      model for the higher-judgement deltas the static tables can't know —
 *      struct/field renames and syscall-number drift between `fromKernel` and
 *      `toKernel`, and an adjusted reproducer text. LLM output is advisory and
 *      clearly marked; it never overrides a deterministic delta.
 *
 * SCOPE: analysis-only. Actual build/run stays in
 * `triage/kernel-vm-runner.ts` (the intended consumer): it would apply the
 * `configDeltas` to the kernel `.config`, run the `preconditions` as VM setup,
 * and boot the `adjustedRepro`. We reuse `fix-commit-intel.ts` (to note whether
 * the bug is already patched in the target LTS tree, if one is on disk) and the
 * subsystem vocabulary from `syscall-boundary-map.ts` only conceptually — the
 * grounded CONFIG/feature tables below are the load-bearing data.
 */
import type {
  NativeContentBlock,
  NativeMessage,
  NativeRuntime,
} from "../runtime/types.js";

// ── Grounded reference data ──

/**
 * syzkaller reproducer "features" — the flags syzkaller emits in the JSON-ish
 * options header of a `repro.prog` / serialized C reproducer (the
 * `# {Threaded:true Sandbox:namespace NetInjection:true ...}` line, or the
 * `{"sandbox":"namespace",...}` form), and the per-feature setup calls
 * `syz-prog2c` bakes into the C. Each is something the DOWNSTREAM kernel must
 * support for the PoC to even reach the bug.
 *
 * The feature names + setup-call names are taken from SyzBridge's
 * `syz_feature_minimize` (`["tun","binfmt_misc","cgroups","close_fds",
 * "devlinkpci","netdev","resetnet","usb","ieee802154","sysctl","vhci","wifi"]`)
 * and from syzkaller's own `executor`/`csource` feature list. The CONFIG_
 * symbols are the upstream Kconfig symbols that gate each feature.
 */
export interface ReproFeature {
  /** syzkaller feature / setup name as it appears in the repro header or C. */
  name: string;
  /** Kernel CONFIG_ symbols the feature needs built in (any-of). */
  configs: string[];
  /** Runtime precondition the harness must satisfy before running the PoC. */
  precondition: string;
  /** True when the feature typically needs CAP_SYS_ADMIN / root or userns. */
  needsPrivilege: boolean;
}

const REPRO_FEATURES: readonly ReproFeature[] = [
  {
    name: "sandbox:namespace",
    configs: ["CONFIG_USER_NS", "CONFIG_NAMESPACES"],
    precondition:
      "unprivileged user namespaces must be allowed " +
      "(kernel.unprivileged_userns_clone=1 / user.max_user_namespaces>0)",
    needsPrivilege: false,
  },
  {
    name: "tun",
    configs: ["CONFIG_TUN"],
    precondition: "/dev/net/tun present; create tun0 via TUNSETIFF",
    needsPrivilege: true,
  },
  {
    name: "netdev",
    configs: ["CONFIG_VETH", "CONFIG_NET_NS"],
    precondition: "veth/dummy netdevices can be created in a net namespace",
    needsPrivilege: true,
  },
  {
    name: "resetnet",
    configs: ["CONFIG_NET_NS"],
    precondition: "network namespace reset between iterations (needs CONFIG_NET_NS)",
    needsPrivilege: false,
  },
  {
    name: "binfmt_misc",
    configs: ["CONFIG_BINFMT_MISC"],
    precondition: "binfmt_misc mounted at /proc/sys/fs/binfmt_misc",
    needsPrivilege: true,
  },
  {
    name: "cgroups",
    configs: ["CONFIG_CGROUPS", "CONFIG_MEMCG"],
    precondition: "cgroup v1/v2 hierarchy mountable under /sys/fs/cgroup",
    needsPrivilege: true,
  },
  {
    name: "usb",
    configs: ["CONFIG_USB_RAW_GADGET", "CONFIG_USB_DUMMY_HCD"],
    precondition: "raw-gadget + dummy_hcd modules loaded for USB emulation",
    needsPrivilege: true,
  },
  {
    name: "vhci",
    configs: ["CONFIG_BT_HCIVHCI", "CONFIG_BT"],
    precondition: "/dev/vhci present (Bluetooth virtual HCI)",
    needsPrivilege: true,
  },
  {
    name: "wifi",
    configs: ["CONFIG_MAC80211_HWSIM", "CONFIG_MAC80211"],
    precondition: "mac80211_hwsim module loaded",
    needsPrivilege: true,
  },
  {
    name: "ieee802154",
    configs: ["CONFIG_IEEE802154", "CONFIG_IEEE802154_HWSIM"],
    precondition: "ieee802154 hwsim available",
    needsPrivilege: true,
  },
  {
    name: "devlinkpci",
    configs: ["CONFIG_NET_DEVLINK", "CONFIG_NETDEVSIM"],
    precondition: "netdevsim device for devlink testing",
    needsPrivilege: true,
  },
  {
    name: "sysctl",
    configs: [],
    precondition: "writable sysctls used by the PoC are present on the target",
    needsPrivilege: false,
  },
  {
    name: "close_fds",
    configs: [],
    precondition: "no kernel config; harness-side fd cleanup only",
    needsPrivilege: false,
  },
];

/** Setup-call substrings `syz-prog2c` emits in C, mapped to a feature name. */
const SETUP_CALL_TO_FEATURE: ReadonlyArray<[needle: string, feature: string]> = [
  ["setup_loop_device", "loop_device"],
  ["setup_binderfs", "binderfs"],
  ["setup_tun", "tun"],
  ["initialize_netdevices", "netdev"],
  ["setup_usb", "usb"],
  ["setup_binfmt_misc", "binfmt_misc"],
  ["setup_cgroups", "cgroups"],
  ["unshare(", "sandbox:namespace"],
  ["CLONE_NEWUSER", "sandbox:namespace"],
  ["CLONE_NEWNS", "sandbox:namespace"],
  ["syz_init_net_socket", "netdev"],
  ["write_file(\"/proc/sys", "sysctl"],
];

/** loop_device + binderfs are setup-driven (not header flags) but need configs. */
const SETUP_ONLY_FEATURES: readonly ReproFeature[] = [
  {
    name: "loop_device",
    configs: ["CONFIG_BLK_DEV_LOOP"],
    precondition: "free loop device (losetup) + a backing image file",
    needsPrivilege: true,
  },
  {
    name: "binderfs",
    configs: ["CONFIG_ANDROID_BINDERFS", "CONFIG_ANDROID_BINDER_IPC"],
    precondition: "binderfs mountable at /dev/binderfs",
    needsPrivilege: true,
  },
];

function featureByName(name: string): ReproFeature | undefined {
  return (
    REPRO_FEATURES.find((f) => f.name === name) ??
    SETUP_ONLY_FEATURES.find((f) => f.name === name)
  );
}

/**
 * Subsystem → the CONFIG_ symbol(s) that build it. Used to flag the PoC's
 * primary subsystem when the target distro is known NOT to ship it (the
 * "is the vulnerable code even compiled in?" check — SyzBridge's
 * `modules_analysis`). Grounded in upstream Kconfig.
 */
const SUBSYSTEM_CONFIG: Record<string, string[]> = {
  io_uring: ["CONFIG_IO_URING"],
  nf_tables: ["CONFIG_NF_TABLES"],
  "net/nft": ["CONFIG_NF_TABLES"],
  rxrpc: ["CONFIG_AF_RXRPC"],
  "net/rxrpc": ["CONFIG_AF_RXRPC"],
  kcm: ["CONFIG_AF_KCM"],
  tipc: ["CONFIG_TIPC"],
  smc: ["CONFIG_AF_SMC"],
  ksmbd: ["CONFIG_SMB_SERVER"],
  "fs/smb": ["CONFIG_SMB_SERVER"],
  hugetlb: ["CONFIG_HUGETLBFS"],
  af_alg: ["CONFIG_CRYPTO_USER_API"],
   "crypto/algif": ["CONFIG_CRYPTO_USER_API"],
  watch_queue: ["CONFIG_WATCH_QUEUE"],
  vsock: ["CONFIG_VSOCKETS"],
  "net/vmw_vsock": ["CONFIG_VSOCKETS"],
};

/**
 * Target distro / LTS profile: which features the kernel ships by default and
 * its baseline version. Grounded in published distro kernel configs:
 *   - Debian 12 "bookworm" ships 6.1.y; its config enables io_uring, nf_tables,
 *     loop, user namespaces (kernel.unprivileged_userns_clone default 1 since
 *     bookworm), TUN, veth, AF_RXRPC=m, but NOT raw-gadget/dummy_hcd by default.
 *   - Debian bookworm-backports / 6.6.y is the same posture on a newer base.
 * `disabledByDefault` lists features the distro does NOT have built/enabled
 * out of the box (so the PoC must build a custom kernel or load a module).
 * `userNsUnprivilegedDefault` records the unprivileged-userns posture, which is
 * the single most common reason an upstream PoC fails on a distro.
 */
export interface DistroProfile {
  id: string;
  /** Human label, e.g. "Debian 12 (bookworm)". */
  label: string;
  /** Baseline kernel version, e.g. "6.1.y". */
  baseKernel: string;
  /** Features built/enabled by default on the stock distro kernel. */
  enabled: Set<string>;
  /** Features NOT available by default (need custom build or module load). */
  disabledByDefault: Set<string>;
  /** Whether unprivileged user namespaces are allowed by default. */
  userNsUnprivilegedDefault: boolean;
}

export const DISTRO_PROFILES: Record<string, DistroProfile> = {
  "debian-12": {
    id: "debian-12",
    label: "Debian 12 (bookworm)",
    baseKernel: "6.1.y",
    enabled: new Set([
      "loop_device",
      "tun",
      "netdev",
      "resetnet",
      "cgroups",
      "sandbox:namespace",
      "sysctl",
      "close_fds",
    ]),
    disabledByDefault: new Set([
      "usb", // raw-gadget / dummy_hcd not built in stock Debian kernel
      "vhci",
      "wifi", // mac80211_hwsim not loaded by default
      "ieee802154",
      "devlinkpci",
      "binderfs", // binderfs not enabled in stock Debian
    ]),
    userNsUnprivilegedDefault: true,
  },
  "debian-12-bpo-6.6": {
    id: "debian-12-bpo-6.6",
    label: "Debian 12 backports (6.6.y)",
    baseKernel: "6.6.y",
    enabled: new Set([
      "loop_device",
      "tun",
      "netdev",
      "resetnet",
      "cgroups",
      "sandbox:namespace",
      "sysctl",
      "close_fds",
    ]),
    disabledByDefault: new Set([
      "usb",
      "vhci",
      "wifi",
      "ieee802154",
      "devlinkpci",
      "binderfs",
    ]),
    userNsUnprivilegedDefault: true,
  },
};

// ── Inputs / outputs ──

export interface AdaptKernel {
  /** Version string, e.g. "6.10-rc4" (upstream) or "6.1.0-21-amd64" (distro). */
  version: string;
  /**
   * Target distro profile id (for `toKernel`), e.g. "debian-12". Optional on
   * `fromKernel`. When set, drives the deterministic config/precondition diff.
   */
  distro?: string;
  /**
   * Optional path to an on-disk source tree for the kernel, so the
   * already-fixed gate (`fix-commit-intel.ts`) can be consulted by a consumer.
   */
  treePath?: string;
}

export interface ConfigDelta {
  /** CONFIG_ symbol, e.g. "CONFIG_USB_RAW_GADGET". */
  config: string;
  /** What's needed: must be built-in (=y), as a module (=m), or a sysctl. */
  action: "enable-builtin" | "enable-module" | "runtime-sysctl";
  /** Why this delta is required (ties back to the feature/subsystem). */
  reason: string;
  /** Severity: "blocker" = PoC cannot reach the bug without it. */
  severity: "blocker" | "recommended";
}

export interface Precondition {
  /** Short id, e.g. "loop_device". */
  feature: string;
  /** Concrete setup the harness must perform. */
  detail: string;
  needsPrivilege: boolean;
}

/** An LLM-suggested source-level adjustment (struct/syscall drift). Advisory. */
export interface ReproAdjustment {
  kind: "struct-rename" | "syscall-drift" | "field-change" | "other";
  description: string;
}

export interface AdaptationPlan {
  fromKernel: string;
  toKernel: string;
  distro?: string;
  /** syzkaller features the PoC was detected to require. */
  detectedFeatures: string[];
  /** Primary subsystem(s) inferred from the PoC, if any. */
  detectedSubsystems: string[];
  /** CONFIG_ deltas needed on the target kernel. */
  configDeltas: ConfigDelta[];
  /** Runtime preconditions the harness must satisfy. */
  preconditions: Precondition[];
  /** LLM-suggested source adjustments (empty when no LLM supplied). */
  reproAdjustments: ReproAdjustment[];
  /** The adjusted reproducer text (== input when no LLM / no change). */
  adjustedRepro: string;
  /** Whether the LLM was consulted. */
  llmAssisted: boolean;
  /** Human-readable notes (e.g. distro profile not found, fail-soft cases). */
  notes: string[];
}

export interface AdaptReproOptions {
  /** When supplied, ask the model for struct/syscall drift + adjusted repro. */
  llm?: NativeRuntime;
  /** Subsystem hint (e.g. "rxrpc", "io_uring") when the PoC doesn't reveal it. */
  subsystemHint?: string;
}

// ── Deterministic detection ──

/**
 * Detect required syzkaller features from a reproducer. Looks at both the
 * options header (`{... sandbox:namespace ...}` / `# {Threaded:true ...}`) and
 * the emitted setup calls in the C body. Returns canonical feature names.
 */
export function detectReproFeatures(repro: string): string[] {
  const found = new Set<string>();

  // 1. Options header: syzkaller emits a leading line with sandbox + feature
  //    booleans. Match both the JSON form and the `# {Key:val ...}` form.
  const headerMatch =
    repro.match(/^\s*[#/]*\s*\{(.+)\}\s*$/m) ?? null;
  const header = headerMatch ? headerMatch[1] : "";

  const sandbox = header.match(/["']?sandbox["']?\s*[:=]\s*["']?(\w+)/i);
  if (sandbox && sandbox[1]!.toLowerCase() === "namespace") {
    found.add("sandbox:namespace");
  }
  // Boolean feature flags in the header (NetInjection→tun/netdev, etc.).
  if (/net_?injection\s*[:=]\s*true/i.test(header)) {
    found.add("tun");
    found.add("netdev");
  }
  if (/net_?devices\s*[:=]\s*true/i.test(header)) found.add("netdev");
  if (/usb\s*[:=]\s*true/i.test(header)) found.add("usb");
  if (/vhci_?injection\s*[:=]\s*true/i.test(header)) found.add("vhci");
  if (/wifi\s*[:=]\s*true/i.test(header)) found.add("wifi");
  if (/ieee802154\s*[:=]\s*true/i.test(header)) found.add("ieee802154");
  if (/binfmt_?misc\s*[:=]\s*true/i.test(header)) found.add("binfmt_misc");
  if (/cgroups\s*[:=]\s*true/i.test(header)) found.add("cgroups");
  if (/sysctl\s*[:=]\s*true/i.test(header)) found.add("sysctl");

  // 2. Setup-call scan over the whole body (catches features even when the
  //    header is absent, e.g. a hand-written or already-prog2c'd reproducer).
  for (const [needle, feature] of SETUP_CALL_TO_FEATURE) {
    if (repro.includes(needle)) found.add(feature);
  }

  return [...found].sort();
}

/**
 * Infer the primary subsystem(s) the PoC exercises, from a hint and from
 * recognisable tokens in the reproducer (socket family names, syscall names).
 */
export function detectSubsystems(repro: string, hint?: string): string[] {
  const found = new Set<string>();
  if (hint) found.add(hint.toLowerCase());

  const tokenMap: ReadonlyArray<[RegExp, string]> = [
    [/\bAF_RXRPC\b|rxrpc/i, "rxrpc"],
    [/\bio_uring_setup\b|\bIORING_/i, "io_uring"],
    [/\bNFT_|nf_tables|\bAF_NETLINK\b.*nft/i, "nf_tables"],
    [/\bAF_KCM\b/i, "kcm"],
    [/\bAF_TIPC\b|tipc/i, "tipc"],
    [/\bAF_SMC\b/i, "smc"],
    [/\bAF_VSOCK\b|vsock/i, "vsock"],
    [/\bAF_ALG\b|algif/i, "af_alg"],
    [/watch_queue|pipe2.*O_NOTIFICATION/i, "watch_queue"],
    [/hugetlb|MAP_HUGETLB/i, "hugetlb"],
  ];
  for (const [re, name] of tokenMap) {
    if (re.test(repro)) found.add(name);
  }
  return [...found].sort();
}

/**
 * Compute the deterministic config + precondition deltas for running a PoC with
 * `features`/`subsystems` against a target distro profile. This is the grounded
 * core: every delta ties to a real CONFIG_ symbol and a concrete precondition.
 */
function computeDeterministicDeltas(
  features: string[],
  subsystems: string[],
  profile: DistroProfile | undefined,
  notes: string[],
): { configDeltas: ConfigDelta[]; preconditions: Precondition[] } {
  const configDeltas: ConfigDelta[] = [];
  const preconditions: Precondition[] = [];
  const seenConfig = new Set<string>();

  const addConfig = (d: ConfigDelta) => {
    if (seenConfig.has(d.config)) return;
    seenConfig.add(d.config);
    configDeltas.push(d);
  };

  // Subsystem-level: is the vulnerable subsystem even built on the target?
  // We cannot know the distro's exact subsystem config from the profile's
  // feature set, so we surface the symbol as a "recommended" check (the
  // consumer / kernel-vm-runner confirms against the real .config). For the
  // hunt's two targets (rxrpc, CopyFail page-cache) this names AF_RXRPC.
  for (const sub of subsystems) {
    const cfgs = SUBSYSTEM_CONFIG[sub];
    if (!cfgs) continue;
    for (const cfg of cfgs) {
      addConfig({
        config: cfg,
        action: "enable-module",
        reason: `subsystem "${sub}" must be built on the target kernel for the bug to be reachable`,
        severity: "recommended",
      });
    }
  }

  // Feature-level deltas.
  for (const name of features) {
    const feat = featureByName(name);
    if (!feat) {
      notes.push(`unknown feature "${name}" — no config/precondition mapping`);
      continue;
    }

    // userns is special: a missing CONFIG is a blocker, but the far more common
    // distro failure is unprivileged-userns being DISABLED at runtime.
    if (name === "sandbox:namespace") {
      for (const cfg of feat.configs) {
        addConfig({
          config: cfg,
          action: "enable-builtin",
          reason: "syzkaller sandbox=namespace needs user/namespace support",
          severity: profile && profile.enabled.has(name) ? "recommended" : "blocker",
        });
      }
      if (profile && !profile.userNsUnprivilegedDefault) {
        configDeltas.push({
          config: "kernel.unprivileged_userns_clone",
          action: "runtime-sysctl",
          reason:
            "target distro disables unprivileged user namespaces by default; " +
            "set kernel.unprivileged_userns_clone=1 or run the PoC as root",
          severity: "blocker",
        });
      }
      preconditions.push({
        feature: name,
        detail: feat.precondition,
        needsPrivilege: feat.needsPrivilege,
      });
      continue;
    }

    const disabledOnDistro = profile
      ? profile.disabledByDefault.has(name) || !profile.enabled.has(name)
      : true;

    if (disabledOnDistro) {
      for (const cfg of feat.configs) {
        addConfig({
          config: cfg,
          action: "enable-module",
          reason: profile
            ? `feature "${name}" is not enabled by default on ${profile.label}`
            : `feature "${name}" required by the PoC`,
          severity: "blocker",
        });
      }
    }

    preconditions.push({
      feature: name,
      detail: feat.precondition,
      needsPrivilege: feat.needsPrivilege,
    });
  }

  return { configDeltas, preconditions };
}

// ── LLM assist ──

const LLM_SYSTEM_PROMPT = [
  "You are a Linux kernel exploitation engineer adapting an upstream syzkaller",
  "reproducer to run on an older downstream distro/LTS kernel. You are given the",
  "upstream kernel version, the target kernel version, and the reproducer.",
  "Identify ONLY source-level adaptations driven by kernel version drift between",
  "the two: renamed/changed structs or fields, syscall-number differences,",
  "uAPI constants that changed name or value, and helper functions that did not",
  "exist on the older kernel. Do NOT invent CONFIG names or runtime setup — those",
  "are handled separately. Ground every claim in real kernel history; if unsure,",
  "say so rather than guessing.",
  "",
  "Respond with a single fenced ```json block:",
  '{ "adjustments": [ { "kind": "struct-rename|syscall-drift|field-change|other",',
  '"description": "..." } ], "adjustedRepro": "<full adjusted reproducer text, or',
  'empty string if no source change is needed>" }',
].join("\n");

interface LlmAdaptResponse {
  adjustments: ReproAdjustment[];
  adjustedRepro: string;
}

function extractJsonBlock(text: string): string {
  const fenced =
    text.match(/```(?:json)?\s*\n([\s\S]*?)```/i) ??
    text.match(/(\{[\s\S]*\})/);
  return (fenced ? fenced[1]! : text).trim();
}

function responseText(content: NativeContentBlock[]): string {
  return content
    .filter((b): b is NativeContentBlock & { type: "text" } => b.type === "text")
    .map((b) => b.text)
    .join("\n");
}

function parseLlmResponse(raw: string): LlmAdaptResponse | null {
  try {
    const parsed = JSON.parse(extractJsonBlock(raw)) as unknown;
    if (typeof parsed !== "object" || parsed === null) return null;
    const obj = parsed as Record<string, unknown>;
    const rawAdj = Array.isArray(obj.adjustments) ? obj.adjustments : [];
    const adjustments: ReproAdjustment[] = rawAdj
      .map((a): ReproAdjustment | null => {
        if (typeof a !== "object" || a === null) return null;
        const ao = a as Record<string, unknown>;
        const kind = ao.kind;
        const description = ao.description;
        if (typeof description !== "string") return null;
        const validKind: ReproAdjustment["kind"] =
          kind === "struct-rename" ||
          kind === "syscall-drift" ||
          kind === "field-change"
            ? kind
            : "other";
        return { kind: validKind, description };
      })
      .filter((a): a is ReproAdjustment => a !== null);
    const adjustedRepro =
      typeof obj.adjustedRepro === "string" ? obj.adjustedRepro : "";
    return { adjustments, adjustedRepro };
  } catch {
    return null;
  }
}

async function runLlmAssist(
  repro: string,
  fromKernel: AdaptKernel,
  toKernel: AdaptKernel,
  llm: NativeRuntime,
  notes: string[],
): Promise<LlmAdaptResponse> {
  const prompt = [
    `Upstream kernel: ${fromKernel.version}`,
    `Target kernel: ${toKernel.version}${toKernel.distro ? ` (${toKernel.distro})` : ""}`,
    "",
    "Reproducer:",
    "```c",
    repro,
    "```",
  ].join("\n");
  const message: NativeMessage = {
    role: "user",
    content: [{ type: "text", text: prompt }],
  };
  try {
    const result = await llm.executeNative(LLM_SYSTEM_PROMPT, [message], []);
    const parsed = parseLlmResponse(responseText(result.content));
    if (!parsed) {
      notes.push("LLM assist returned unparseable output; ignored");
      return { adjustments: [], adjustedRepro: "" };
    }
    return parsed;
  } catch (err) {
    notes.push(
      `LLM assist failed (${err instanceof Error ? err.message : "error"}); ` +
        "deterministic plan only",
    );
    return { adjustments: [], adjustedRepro: "" };
  }
}

// ── Public API ──

/**
 * Produce a SyzBridge-style adaptation plan for running an upstream `repro`
 * (working on `fromKernel`) against a downstream distro/LTS `toKernel`.
 *
 * The deterministic core always runs and is grounded in real CONFIG_ symbols
 * and runtime preconditions. When `opts.llm` is supplied, the model additionally
 * proposes source-level adjustments (struct/syscall drift) and may return an
 * adjusted reproducer — advisory, and it never removes a deterministic delta.
 *
 * Analysis-only: applying `configDeltas`, running `preconditions`, and booting
 * `adjustedRepro` is the job of `triage/kernel-vm-runner.ts`.
 */
export async function adaptReproForDistro(
  repro: string,
  fromKernel: AdaptKernel,
  toKernel: AdaptKernel,
  opts: AdaptReproOptions = {},
): Promise<AdaptationPlan> {
  const notes: string[] = [];

  const distroId = toKernel.distro;
  const profile = distroId ? DISTRO_PROFILES[distroId] : undefined;
  if (distroId && !profile) {
    notes.push(
      `unknown distro profile "${distroId}"; emitting feature deltas without ` +
        "distro-specific gating (treats all features as possibly-missing)",
    );
  }

  const detectedFeatures = detectReproFeatures(repro);
  const detectedSubsystems = detectSubsystems(repro, opts.subsystemHint);

  const { configDeltas, preconditions } = computeDeterministicDeltas(
    detectedFeatures,
    detectedSubsystems,
    profile,
    notes,
  );

  let reproAdjustments: ReproAdjustment[] = [];
  let adjustedRepro = repro;
  let llmAssisted = false;

  if (opts.llm) {
    llmAssisted = true;
    const llmResult = await runLlmAssist(
      repro,
      fromKernel,
      toKernel,
      opts.llm,
      notes,
    );
    reproAdjustments = llmResult.adjustments;
    if (llmResult.adjustedRepro.trim().length > 0) {
      adjustedRepro = llmResult.adjustedRepro;
    }
  }

  return {
    fromKernel: fromKernel.version,
    toKernel: toKernel.version,
    ...(distroId ? { distro: distroId } : {}),
    detectedFeatures,
    detectedSubsystems,
    configDeltas,
    preconditions,
    reproAdjustments,
    adjustedRepro,
    llmAssisted,
    notes,
  };
}

/** Exported for tests / consumers that want the raw feature table. */
export { REPRO_FEATURES as _REPRO_FEATURES, SETUP_ONLY_FEATURES as _SETUP_ONLY_FEATURES };

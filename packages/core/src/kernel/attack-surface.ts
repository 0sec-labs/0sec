/**
 * Known kernel attack-surface enumeration (0sec#471).
 *
 * Provides a curated database of historically high-risk kernel subsystems
 * together with their CONFIG_* options, file paths, CVE density, and
 * complexity ratings. The enumeration tool can:
 *
 * 1. Parse a `.config` file (or `include/generated/autoconf.h`) to
 *    determine which surfaces are compiled in.
 * 2. Fall back to scanning for `module_init()` / `__init` when no
 *    config is available.
 * 3. Fall back to static "common distro configs" (Ubuntu, Fedora, Arch)
 *    when nothing else is available.
 * 4. Score and rank subsystems by compiled-in status, historical CVE
 *    count, unprivileged reachability, and attack-surface complexity.
 *
 * Output is structured JSON suitable for agent consumption: a ranked
 * list of attack surfaces the agent should focus on, optionally filtered
 * to a single `--subsystem`.
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

// ── Types ───────────────────────────────────────────────────────────────────

export interface KernelAttackSurface {
  /** Human-readable surface name, e.g. "io_uring". */
  name: string;
  /** CONFIG_* options that enable this surface. */
  configOptions: string[];
  /** Subsystem source paths relative to the kernel tree root. */
  paths: string[];
  /** Approximate historical CVE count (curated, not exhaustive). */
  historicalCveCount: number;
  /** Complexity rating: lines of code + entry point density. */
  complexity: "low" | "medium" | "high" | "very-high";
  /** Whether unprivileged userspace can reach this surface. */
  unprivilegedReachable: boolean;
  /** Short description of why this surface is high-risk. */
  riskRationale: string;
}

export interface AttackSurfaceEntry extends KernelAttackSurface {
  /** Whether the surface is compiled in (true), modular (true), or absent (false). */
  compiledIn: boolean;
  /** How the compiled-in status was determined. */
  detectionMethod: "config-file" | "autoconf-header" | "module-init-scan" | "distro-default" | "assumed";
  /** Priority score: higher = investigate first. */
  priorityScore: number;
}

export interface AttackSurfaceEnumResult {
  /** Kernel tree path that was scanned. */
  tree: string;
  /** How the config was sourced. */
  configSource: "dot-config" | "autoconf-header" | "module-init-scan" | "distro-default" | "none";
  /** Distro default used (if any). */
  distroDefault?: string;
  /** All known surfaces with their status and priority. */
  surfaces: AttackSurfaceEntry[];
  /** Warnings encountered during enumeration. */
  warnings: string[];
}

export interface EnumerateAttackSurfacesOptions {
  /** Path to the kernel source tree. */
  tree: string;
  /** Optional path to a `.config` file (overrides auto-detection). */
  configPath?: string;
  /** Optional subsystem filter — only return surfaces matching this. */
  subsystem?: string;
  /** Distro to use for fallback defaults. */
  distroDefault?: "ubuntu" | "fedora" | "arch";
}

// ── Known attack surfaces database ──────────────────────────────────────────

export const KNOWN_ATTACK_SURFACES: KernelAttackSurface[] = [
  {
    name: "io_uring",
    configOptions: ["CONFIG_IO_URING"],
    paths: ["io_uring/"],
    historicalCveCount: 35,
    complexity: "very-high",
    unprivilegedReachable: true,
    riskRationale:
      "Massive async I/O subsystem with its own syscall interface, complex state machine, and history of type confusion / UAF / race bugs. Unprivileged by default.",
  },
  {
    name: "eBPF",
    configOptions: ["CONFIG_BPF_SYSCALL", "CONFIG_BPF_JIT"],
    paths: ["kernel/bpf/"],
    historicalCveCount: 40,
    complexity: "very-high",
    unprivilegedReachable: true,
    riskRationale:
      "In-kernel virtual machine with JIT compilation. Verifier bugs yield arbitrary read/write primitives. Unprivileged BPF still enabled on many distros.",
  },
  {
    name: "nf_tables",
    configOptions: ["CONFIG_NF_TABLES"],
    paths: ["net/netfilter/"],
    historicalCveCount: 30,
    complexity: "high",
    unprivilegedReachable: true,
    riskRationale:
      "Netfilter's nf_tables subsystem has had repeated UAF, double-free, and type confusion bugs. Reachable from user namespaces on many distros.",
  },
  {
    name: "AF_ALG",
    configOptions: [
      "CONFIG_CRYPTO_USER_API",
      "CONFIG_CRYPTO_USER_API_HASH",
      "CONFIG_CRYPTO_USER_API_SKCIPHER",
      "CONFIG_CRYPTO_USER_API_AEAD",
      "CONFIG_CRYPTO_USER_API_RNG",
      "CONFIG_CRYPTO_USER_API_AKCIPHER",
    ],
    paths: ["crypto/"],
    historicalCveCount: 15,
    complexity: "high",
    unprivilegedReachable: true,
    riskRationale:
      "Userspace crypto API (AF_ALG sockets). splice() + shared-frag skb interactions create Dirty Frag class bugs (CVE-2026-31431). Unprivileged socket access.",
  },
  {
    name: "ksmbd",
    configOptions: ["CONFIG_SMB_SERVER"],
    paths: ["fs/smb/server/"],
    historicalCveCount: 20,
    complexity: "high",
    unprivilegedReachable: false,
    riskRationale:
      "In-kernel SMB3 server. Network-facing, complex protocol parsing with history of OOB reads/writes and UAFs. Remote attack surface.",
  },
  {
    name: "Bluetooth",
    configOptions: ["CONFIG_BT", "CONFIG_BT_LE"],
    paths: ["net/bluetooth/"],
    historicalCveCount: 25,
    complexity: "high",
    unprivilegedReachable: false,
    riskRationale:
      "Complex protocol stack with L2CAP, SMP, and HCI layers. Remote attack surface via proximity. History of heap overflows and info leaks (BlueZ/BleedingTooth).",
  },
  {
    name: "USB",
    configOptions: ["CONFIG_USB"],
    paths: ["drivers/usb/"],
    historicalCveCount: 20,
    complexity: "high",
    unprivilegedReachable: false,
    riskRationale:
      "Physical attack surface. USB gadget and host drivers parse untrusted descriptors. History of heap overflows from malformed descriptors.",
  },
  {
    name: "GPU/DRM",
    configOptions: ["CONFIG_DRM"],
    paths: ["drivers/gpu/drm/"],
    historicalCveCount: 15,
    complexity: "very-high",
    unprivilegedReachable: true,
    riskRationale:
      "DRM/KMS subsystem with GPU-specific drivers (i915, amdgpu, nouveau). Complex ioctl interface reachable from unprivileged userspace via /dev/dri/*.",
  },
  {
    name: "FUSE",
    configOptions: ["CONFIG_FUSE_FS"],
    paths: ["fs/fuse/"],
    historicalCveCount: 8,
    complexity: "medium",
    unprivilegedReachable: true,
    riskRationale:
      "Userspace filesystem. Attacker controls the filesystem daemon responses, creating TOCTOU windows and confused-deputy opportunities in VFS paths.",
  },
  {
    name: "Netlink",
    configOptions: ["CONFIG_NETLINK_DIAG"],
    paths: ["net/netlink/"],
    historicalCveCount: 10,
    complexity: "medium",
    unprivilegedReachable: true,
    riskRationale:
      "Core kernel-userspace IPC mechanism. Generic netlink families expose many subsystems. History of info leaks and privilege escalation.",
  },
];

// ── Distro default configs ──────────────────────────────────────────────────
//
// Static fallback for "common distro configs" when no .config is available.
// These represent which CONFIG_* options are typically enabled=y or =m.

export const DISTRO_DEFAULTS: Record<string, Set<string>> = {
  ubuntu: new Set([
    "CONFIG_IO_URING",
    "CONFIG_BPF_SYSCALL",
    "CONFIG_BPF_JIT",
    "CONFIG_NF_TABLES",
    "CONFIG_CRYPTO_USER_API",
    "CONFIG_CRYPTO_USER_API_HASH",
    "CONFIG_CRYPTO_USER_API_SKCIPHER",
    "CONFIG_CRYPTO_USER_API_AEAD",
    "CONFIG_BT",
    "CONFIG_BT_LE",
    "CONFIG_USB",
    "CONFIG_DRM",
    "CONFIG_FUSE_FS",
    "CONFIG_NETLINK_DIAG",
    // ksmbd is NOT enabled by default on Ubuntu
  ]),
  fedora: new Set([
    "CONFIG_IO_URING",
    "CONFIG_BPF_SYSCALL",
    "CONFIG_BPF_JIT",
    "CONFIG_NF_TABLES",
    "CONFIG_CRYPTO_USER_API",
    "CONFIG_CRYPTO_USER_API_HASH",
    "CONFIG_CRYPTO_USER_API_SKCIPHER",
    "CONFIG_CRYPTO_USER_API_AEAD",
    "CONFIG_BT",
    "CONFIG_BT_LE",
    "CONFIG_USB",
    "CONFIG_DRM",
    "CONFIG_FUSE_FS",
    "CONFIG_NETLINK_DIAG",
    "CONFIG_SMB_SERVER",
  ]),
  arch: new Set([
    "CONFIG_IO_URING",
    "CONFIG_BPF_SYSCALL",
    "CONFIG_BPF_JIT",
    "CONFIG_NF_TABLES",
    "CONFIG_CRYPTO_USER_API",
    "CONFIG_CRYPTO_USER_API_HASH",
    "CONFIG_CRYPTO_USER_API_SKCIPHER",
    "CONFIG_CRYPTO_USER_API_AEAD",
    "CONFIG_BT",
    "CONFIG_BT_LE",
    "CONFIG_USB",
    "CONFIG_DRM",
    "CONFIG_FUSE_FS",
    "CONFIG_NETLINK_DIAG",
  ]),
};

// ── Config parsing ──────────────────────────────────────────────────────────

/**
 * Parse a kernel `.config` file and return the set of enabled CONFIG_*
 * options (both `=y` and `=m` count as "compiled in" for our purposes).
 */
export function parseKernelConfig(configText: string): Set<string> {
  const enabled = new Set<string>();
  for (const line of configText.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.startsWith("#") || trimmed === "") continue;
    // Lines look like: CONFIG_FOO=y  or  CONFIG_BAR=m  or  CONFIG_BAZ="string"
    const match = trimmed.match(/^(CONFIG_\w+)=(y|m)/);
    if (match) {
      enabled.add(match[1]);
    }
  }
  return enabled;
}

/**
 * Parse `include/generated/autoconf.h` and return enabled CONFIG_* options.
 * Lines look like: `#define CONFIG_FOO 1` or `#define CONFIG_FOO_MODULE 1`.
 */
export function parseAutoconfHeader(headerText: string): Set<string> {
  const enabled = new Set<string>();
  for (const line of headerText.split("\n")) {
    const trimmed = line.trim();
    // #define CONFIG_FOO 1
    const match = trimmed.match(/^#define\s+(CONFIG_\w+?)(?:_MODULE)?\s+1/);
    if (match) {
      enabled.add(match[1]);
    }
  }
  return enabled;
}

// ── Module init scan ────────────────────────────────────────────────────────

/**
 * Scan for `module_init()` / `__init` function markers in the relevant
 * subsystem paths to determine if a surface's code is reachable. This is
 * the fallback when no `.config` or `autoconf.h` is available.
 */
export function scanForModuleInit(
  tree: string,
  paths: string[],
): boolean {
  for (const relPath of paths) {
    const absPath = join(tree, relPath);
    if (!existsSync(absPath)) continue;

    try {
      const stat = statSync(absPath);
      if (!stat.isDirectory()) continue;
    } catch {
      continue;
    }

    // Scan .c files in the directory (non-recursive, top level only for speed)
    let files: string[];
    try {
      files = readdirSync(absPath).filter((f) => f.endsWith(".c"));
    } catch {
      continue;
    }

    for (const file of files.slice(0, 50)) {
      // Cap to avoid scanning huge directories
      try {
        const content = readFileSync(join(absPath, file), "utf8");
        if (
          /\bmodule_init\s*\(/.test(content) ||
          /\b__init\b/.test(content) ||
          /\bsubsys_initcall\s*\(/.test(content) ||
          /\bcore_initcall\s*\(/.test(content)
        ) {
          return true;
        }
      } catch {
        // Skip unreadable files
      }
    }
  }
  return false;
}

// ── Priority scoring ────────────────────────────────────────────────────────

const COMPLEXITY_SCORE: Record<string, number> = {
  "very-high": 4,
  high: 3,
  medium: 2,
  low: 1,
};

/**
 * Compute a priority score for an attack surface entry. Higher = investigate
 * first. Factors:
 *   - Compiled-in status (×2 multiplier)
 *   - Historical CVE density (normalized to 0–10)
 *   - Unprivileged reachability (+3)
 *   - Complexity rating (1–4)
 */
export function computePriorityScore(
  surface: KernelAttackSurface,
  compiledIn: boolean,
): number {
  const cveScore = Math.min(surface.historicalCveCount / 4, 10);
  const complexityScore = COMPLEXITY_SCORE[surface.complexity] ?? 2;
  const unprivScore = surface.unprivilegedReachable ? 3 : 0;
  const compiledMultiplier = compiledIn ? 2 : 0.5;

  return Math.round(
    (cveScore + complexityScore + unprivScore) * compiledMultiplier * 10,
  ) / 10;
}

// ── Main enumeration ────────────────────────────────────────────────────────

/**
 * Enumerate known kernel attack surfaces for a given kernel tree.
 *
 * Resolution order:
 * 1. Explicit `configPath` (or `<tree>/.config`)
 * 2. `<tree>/include/generated/autoconf.h`
 * 3. `module_init()` scan in subsystem paths
 * 4. Distro defaults (Ubuntu/Fedora/Arch)
 * 5. Assume compiled-in (all surfaces)
 */
export function enumerateAttackSurfaces(
  options: EnumerateAttackSurfacesOptions,
): AttackSurfaceEnumResult {
  const { tree, subsystem, distroDefault } = options;
  const warnings: string[] = [];

  // Try to find and parse config
  let enabledConfigs: Set<string> | undefined;
  let configSource: AttackSurfaceEnumResult["configSource"] = "none";
  let usedDistroDefault: string | undefined;

  // 1. Explicit config path or .config in tree root
  const configPath = options.configPath ?? join(tree, ".config");
  if (existsSync(configPath)) {
    try {
      const configText = readFileSync(configPath, "utf8");
      enabledConfigs = parseKernelConfig(configText);
      configSource = "dot-config";
    } catch {
      warnings.push(`Failed to read config file: ${configPath}`);
    }
  }

  // 2. autoconf.h fallback
  if (!enabledConfigs) {
    const autoconfPath = join(tree, "include/generated/autoconf.h");
    if (existsSync(autoconfPath)) {
      try {
        const headerText = readFileSync(autoconfPath, "utf8");
        enabledConfigs = parseAutoconfHeader(headerText);
        configSource = "autoconf-header";
      } catch {
        warnings.push(`Failed to read autoconf header: ${autoconfPath}`);
      }
    }
  }

  // 3. Distro defaults fallback
  if (!enabledConfigs && distroDefault && DISTRO_DEFAULTS[distroDefault]) {
    enabledConfigs = DISTRO_DEFAULTS[distroDefault];
    configSource = "distro-default";
    usedDistroDefault = distroDefault;
    warnings.push(
      `No .config or autoconf.h found; using ${distroDefault} distro defaults.`,
    );
  }

  // Build entries
  const surfaces: AttackSurfaceEntry[] = KNOWN_ATTACK_SURFACES.map((surface) => {
    let compiledIn: boolean;
    let detectionMethod: AttackSurfaceEntry["detectionMethod"];

    if (enabledConfigs) {
      // Check if ANY of the surface's config options are enabled
      compiledIn = surface.configOptions.some((opt) => enabledConfigs!.has(opt));
      detectionMethod =
        configSource === "dot-config"
          ? "config-file"
          : configSource === "autoconf-header"
            ? "autoconf-header"
            : "distro-default";
    } else {
      // 4. module_init scan fallback
      compiledIn = scanForModuleInit(tree, surface.paths);
      if (compiledIn) {
        detectionMethod = "module-init-scan";
        if (configSource === "none") configSource = "module-init-scan";
      } else {
        // 5. Assume compiled-in (conservative — better to scan than miss)
        compiledIn = true;
        detectionMethod = "assumed";
        if (configSource === "none") configSource = "none";
      }
    }

    const priorityScore = computePriorityScore(surface, compiledIn);

    return {
      ...surface,
      compiledIn,
      detectionMethod,
      priorityScore,
    };
  });

  // Sort by priority score descending
  surfaces.sort((a, b) => b.priorityScore - a.priorityScore);

  // Filter by subsystem if requested
  let filteredSurfaces = surfaces;
  if (subsystem) {
    const subsystemDirs = subsystem
      .split(",")
      .map((s) => s.trim().replace(/\/+$/, ""))
      .filter(Boolean);

    filteredSurfaces = surfaces.filter((s) =>
      s.paths.some((p) => {
        const normalizedPath = p.replace(/\/+$/, "");
        return subsystemDirs.some(
          (dir) =>
            normalizedPath === dir ||
            normalizedPath.startsWith(dir + "/") ||
            dir.startsWith(normalizedPath + "/") ||
            dir === normalizedPath,
        );
      }),
    );

    if (filteredSurfaces.length === 0) {
      warnings.push(
        `No known attack surfaces match subsystem filter: ${subsystem}. Returning all surfaces for context.`,
      );
      filteredSurfaces = surfaces;
    }
  }

  return {
    tree,
    configSource,
    distroDefault: usedDistroDefault,
    surfaces: filteredSurfaces,
    warnings,
  };
}

// ── Agent prompt formatting ─────────────────────────────────────────────────

/**
 * Format the attack surface enumeration result as a section for the
 * kernel review agent prompt. This gives the agent context about which
 * high-risk subsystems are reachable and where to focus.
 */
export function formatAttackSurfaceForPrompt(
  result: AttackSurfaceEnumResult,
): string {
  if (result.surfaces.length === 0) {
    return "";
  }

  const lines: string[] = [
    "## Known Attack Surfaces — Pre-Scan Enumeration",
    "",
    `Config source: ${result.configSource}${result.distroDefault ? ` (${result.distroDefault})` : ""}`,
    "",
    "The following high-risk kernel subsystems were identified. Surfaces are ranked by priority score (historical CVE density, complexity, unprivileged reachability, compiled-in status). **Investigate in this order unless your operator hypothesis directs otherwise.**",
    "",
  ];

  for (const surface of result.surfaces) {
    const status = surface.compiledIn ? "COMPILED IN" : "not compiled";
    const priv = surface.unprivilegedReachable
      ? "unprivileged"
      : "privileged only";
    lines.push(
      `### ${surface.priorityScore.toFixed(1)} — ${surface.name} [${status}] [${priv}]`,
    );
    lines.push(`Paths: ${surface.paths.map((p) => `\`${p}\``).join(", ")}`);
    lines.push(
      `Config: ${surface.configOptions.map((o) => `\`${o}\``).join(", ")}`,
    );
    lines.push(
      `Historical CVEs: ~${surface.historicalCveCount} | Complexity: ${surface.complexity}`,
    );
    lines.push(`Risk: ${surface.riskRationale}`);
    lines.push("");
  }

  if (result.warnings.length > 0) {
    lines.push("**Enumeration warnings:**");
    for (const w of result.warnings) {
      lines.push(`- ${w}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

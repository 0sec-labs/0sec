import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  computePriorityScore,
  DISTRO_DEFAULTS,
  enumerateAttackSurfaces,
  formatAttackSurfaceForPrompt,
  KNOWN_ATTACK_SURFACES,
  parseAutoconfHeader,
  parseKernelConfig,
  scanForModuleInit,
} from "./attack-surface.js";

let tmpRoot: string;

beforeEach(() => {
  tmpRoot = mkdtempSync(join(tmpdir(), "0sec-attack-surface-test-"));
});

afterEach(() => {
  rmSync(tmpRoot, { recursive: true, force: true });
});

// ── KNOWN_ATTACK_SURFACES database ─────────────────────────────────────────

describe("KNOWN_ATTACK_SURFACES", () => {
  it("contains at least 10 known surfaces", () => {
    expect(KNOWN_ATTACK_SURFACES.length).toBeGreaterThanOrEqual(10);
  });

  it("every surface has required fields", () => {
    for (const surface of KNOWN_ATTACK_SURFACES) {
      expect(surface.name).toBeTruthy();
      expect(surface.configOptions.length).toBeGreaterThan(0);
      expect(surface.paths.length).toBeGreaterThan(0);
      expect(surface.historicalCveCount).toBeGreaterThanOrEqual(0);
      expect(["low", "medium", "high", "very-high"]).toContain(
        surface.complexity,
      );
      expect(typeof surface.unprivilegedReachable).toBe("boolean");
      expect(surface.riskRationale).toBeTruthy();
    }
  });

  it("includes the surfaces from the issue's table", () => {
    const names = KNOWN_ATTACK_SURFACES.map((s) => s.name);
    expect(names).toContain("io_uring");
    expect(names).toContain("eBPF");
    expect(names).toContain("nf_tables");
    expect(names).toContain("AF_ALG");
    expect(names).toContain("ksmbd");
    expect(names).toContain("Bluetooth");
    expect(names).toContain("USB");
    expect(names).toContain("GPU/DRM");
    expect(names).toContain("FUSE");
    expect(names).toContain("Netlink");
  });
});

// ── parseKernelConfig ───────────────────────────────────────────────────────

describe("parseKernelConfig", () => {
  it("parses =y and =m options from a .config file", () => {
    const config = `
# Linux kernel configuration
CONFIG_IO_URING=y
CONFIG_BPF_SYSCALL=m
# CONFIG_SMB_SERVER is not set
CONFIG_DRM=y
CONFIG_SOME_STRING="hello"
`;
    const enabled = parseKernelConfig(config);
    expect(enabled.has("CONFIG_IO_URING")).toBe(true);
    expect(enabled.has("CONFIG_BPF_SYSCALL")).toBe(true);
    expect(enabled.has("CONFIG_SMB_SERVER")).toBe(false);
    expect(enabled.has("CONFIG_DRM")).toBe(true);
    // String values are not treated as y/m
    expect(enabled.has("CONFIG_SOME_STRING")).toBe(false);
  });

  it("returns empty set for empty config", () => {
    expect(parseKernelConfig("").size).toBe(0);
  });

  it("ignores comment lines", () => {
    const config = `# CONFIG_IO_URING=y
# This is a comment
CONFIG_BT=y`;
    const enabled = parseKernelConfig(config);
    expect(enabled.has("CONFIG_IO_URING")).toBe(false);
    expect(enabled.has("CONFIG_BT")).toBe(true);
  });
});

// ── parseAutoconfHeader ─────────────────────────────────────────────────────

describe("parseAutoconfHeader", () => {
  it("parses #define CONFIG_FOO 1 lines", () => {
    const header = `
#define CONFIG_IO_URING 1
#define CONFIG_BPF_SYSCALL 1
#define CONFIG_NF_TABLES_MODULE 1
#define CONFIG_SOME_OTHER 0
`;
    const enabled = parseAutoconfHeader(header);
    expect(enabled.has("CONFIG_IO_URING")).toBe(true);
    expect(enabled.has("CONFIG_BPF_SYSCALL")).toBe(true);
    // _MODULE suffix should be stripped to CONFIG_NF_TABLES
    expect(enabled.has("CONFIG_NF_TABLES")).toBe(true);
    // Value 0 should NOT be included
    expect(enabled.has("CONFIG_SOME_OTHER")).toBe(false);
  });

  it("returns empty set for empty header", () => {
    expect(parseAutoconfHeader("").size).toBe(0);
  });
});

// ── scanForModuleInit ───────────────────────────────────────────────────────

describe("scanForModuleInit", () => {
  it("detects module_init() in a .c file under the subsystem path", () => {
    const subsystemDir = join(tmpRoot, "io_uring");
    mkdirSync(subsystemDir, { recursive: true });
    writeFileSync(
      join(subsystemDir, "io_uring.c"),
      `
#include <linux/io_uring.h>
static int __init io_uring_init(void) { return 0; }
module_init(io_uring_init);
`,
    );
    expect(scanForModuleInit(tmpRoot, ["io_uring/"])).toBe(true);
  });

  it("detects __init keyword", () => {
    const subsystemDir = join(tmpRoot, "kernel/bpf");
    mkdirSync(subsystemDir, { recursive: true });
    writeFileSync(
      join(subsystemDir, "core.c"),
      `static int __init bpf_init(void) { return 0; }`,
    );
    expect(scanForModuleInit(tmpRoot, ["kernel/bpf/"])).toBe(true);
  });

  it("returns false for nonexistent paths", () => {
    expect(scanForModuleInit(tmpRoot, ["nonexistent/"])).toBe(false);
  });

  it("returns false for empty directories", () => {
    const subsystemDir = join(tmpRoot, "empty_dir");
    mkdirSync(subsystemDir, { recursive: true });
    expect(scanForModuleInit(tmpRoot, ["empty_dir/"])).toBe(false);
  });

  it("returns false when .c files have no init markers", () => {
    const subsystemDir = join(tmpRoot, "fs/fuse");
    mkdirSync(subsystemDir, { recursive: true });
    writeFileSync(
      join(subsystemDir, "file.c"),
      `static int helper_func(void) { return 42; }`,
    );
    expect(scanForModuleInit(tmpRoot, ["fs/fuse/"])).toBe(false);
  });
});

// ── computePriorityScore ────────────────────────────────────────────────────

describe("computePriorityScore", () => {
  it("scores higher when compiled in", () => {
    const surface = KNOWN_ATTACK_SURFACES.find((s) => s.name === "io_uring")!;
    const compiledScore = computePriorityScore(surface, true);
    const notCompiledScore = computePriorityScore(surface, false);
    expect(compiledScore).toBeGreaterThan(notCompiledScore);
  });

  it("scores higher for unprivileged-reachable surfaces", () => {
    // Compare io_uring (unprivileged) vs ksmbd (privileged)
    const iouring = KNOWN_ATTACK_SURFACES.find((s) => s.name === "io_uring")!;
    const ksmbd = KNOWN_ATTACK_SURFACES.find((s) => s.name === "ksmbd")!;
    // Both compiled in
    const iouringScore = computePriorityScore(iouring, true);
    const ksmbdScore = computePriorityScore(ksmbd, true);
    // io_uring should score higher (more CVEs + unprivileged + very-high complexity)
    expect(iouringScore).toBeGreaterThan(ksmbdScore);
  });

  it("returns a positive number", () => {
    for (const surface of KNOWN_ATTACK_SURFACES) {
      expect(computePriorityScore(surface, true)).toBeGreaterThan(0);
      expect(computePriorityScore(surface, false)).toBeGreaterThan(0);
    }
  });
});

// ── enumerateAttackSurfaces ─────────────────────────────────────────────────

describe("enumerateAttackSurfaces", () => {
  it("parses .config from tree root and marks surfaces correctly", () => {
    const tree = join(tmpRoot, "linux");
    mkdirSync(tree);
    writeFileSync(
      join(tree, ".config"),
      `CONFIG_IO_URING=y
CONFIG_BPF_SYSCALL=y
CONFIG_NF_TABLES=m
# CONFIG_SMB_SERVER is not set
CONFIG_DRM=y
`,
    );

    const result = enumerateAttackSurfaces({ tree });
    expect(result.configSource).toBe("dot-config");
    expect(result.warnings).toHaveLength(0);

    const iouring = result.surfaces.find((s) => s.name === "io_uring");
    expect(iouring).toBeDefined();
    expect(iouring!.compiledIn).toBe(true);
    expect(iouring!.detectionMethod).toBe("config-file");

    const ksmbd = result.surfaces.find((s) => s.name === "ksmbd");
    expect(ksmbd).toBeDefined();
    expect(ksmbd!.compiledIn).toBe(false);
    expect(ksmbd!.detectionMethod).toBe("config-file");
  });

  it("uses autoconf.h when .config is absent", () => {
    const tree = join(tmpRoot, "linux");
    const autoconfDir = join(tree, "include/generated");
    mkdirSync(autoconfDir, { recursive: true });
    writeFileSync(
      join(autoconfDir, "autoconf.h"),
      `#define CONFIG_IO_URING 1
#define CONFIG_BPF_SYSCALL 1
`,
    );

    const result = enumerateAttackSurfaces({ tree });
    expect(result.configSource).toBe("autoconf-header");

    const iouring = result.surfaces.find((s) => s.name === "io_uring");
    expect(iouring!.compiledIn).toBe(true);
    expect(iouring!.detectionMethod).toBe("autoconf-header");
  });

  it("falls back to distro defaults when no config is found", () => {
    const tree = join(tmpRoot, "linux");
    mkdirSync(tree);

    const result = enumerateAttackSurfaces({
      tree,
      distroDefault: "ubuntu",
    });
    expect(result.configSource).toBe("distro-default");
    expect(result.distroDefault).toBe("ubuntu");
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.warnings[0]).toContain("ubuntu");

    // io_uring is enabled on Ubuntu
    const iouring = result.surfaces.find((s) => s.name === "io_uring");
    expect(iouring!.compiledIn).toBe(true);
    expect(iouring!.detectionMethod).toBe("distro-default");

    // ksmbd is NOT enabled on Ubuntu
    const ksmbd = result.surfaces.find((s) => s.name === "ksmbd");
    expect(ksmbd!.compiledIn).toBe(false);
    expect(ksmbd!.detectionMethod).toBe("distro-default");
  });

  it("falls back to module_init scan when no config and no distro default", () => {
    const tree = join(tmpRoot, "linux");
    const iouringDir = join(tree, "io_uring");
    mkdirSync(iouringDir, { recursive: true });
    writeFileSync(
      join(iouringDir, "io_uring.c"),
      `static int __init io_uring_init(void) { return 0; }\nmodule_init(io_uring_init);`,
    );

    const result = enumerateAttackSurfaces({ tree });
    expect(result.configSource).toBe("module-init-scan");

    const iouring = result.surfaces.find((s) => s.name === "io_uring");
    expect(iouring!.compiledIn).toBe(true);
    expect(iouring!.detectionMethod).toBe("module-init-scan");
  });

  it("assumes compiled-in when nothing else is available", () => {
    const tree = join(tmpRoot, "linux");
    mkdirSync(tree);

    const result = enumerateAttackSurfaces({ tree });
    expect(result.configSource).toBe("none");

    // All surfaces should be assumed compiled-in
    for (const surface of result.surfaces) {
      expect(surface.compiledIn).toBe(true);
      // Some may be detected via module_init if paths happen to exist,
      // but in an empty tree they should all be "assumed"
      expect(["assumed", "module-init-scan"]).toContain(
        surface.detectionMethod,
      );
    }
  });

  it("sorts surfaces by priority score descending", () => {
    const tree = join(tmpRoot, "linux");
    mkdirSync(tree);
    writeFileSync(
      join(tree, ".config"),
      KNOWN_ATTACK_SURFACES.flatMap((s) =>
        s.configOptions.map((o) => `${o}=y`),
      ).join("\n"),
    );

    const result = enumerateAttackSurfaces({ tree });
    for (let i = 1; i < result.surfaces.length; i++) {
      expect(result.surfaces[i - 1]!.priorityScore).toBeGreaterThanOrEqual(
        result.surfaces[i]!.priorityScore,
      );
    }
  });

  it("filters by subsystem when provided", () => {
    const tree = join(tmpRoot, "linux");
    mkdirSync(tree);
    writeFileSync(join(tree, ".config"), "CONFIG_IO_URING=y\nCONFIG_NF_TABLES=y\n");

    const result = enumerateAttackSurfaces({
      tree,
      subsystem: "io_uring",
    });
    expect(result.surfaces).toHaveLength(1);
    expect(result.surfaces[0]!.name).toBe("io_uring");
  });

  it("filters by subsystem with trailing slash", () => {
    const tree = join(tmpRoot, "linux");
    mkdirSync(tree);
    writeFileSync(join(tree, ".config"), "CONFIG_IO_URING=y\n");

    const result = enumerateAttackSurfaces({
      tree,
      subsystem: "io_uring/",
    });
    expect(result.surfaces).toHaveLength(1);
    expect(result.surfaces[0]!.name).toBe("io_uring");
  });

  it("returns all surfaces with a warning when subsystem filter matches nothing", () => {
    const tree = join(tmpRoot, "linux");
    mkdirSync(tree);
    writeFileSync(join(tree, ".config"), "CONFIG_IO_URING=y\n");

    const result = enumerateAttackSurfaces({
      tree,
      subsystem: "nonexistent/subsystem",
    });
    // Should return ALL surfaces since nothing matched
    expect(result.surfaces.length).toBe(KNOWN_ATTACK_SURFACES.length);
    expect(result.warnings.some((w) => w.includes("No known attack surfaces match"))).toBe(true);
  });

  it("accepts an explicit configPath", () => {
    const tree = join(tmpRoot, "linux");
    mkdirSync(tree);
    const customConfig = join(tmpRoot, "my-custom.config");
    writeFileSync(customConfig, "CONFIG_IO_URING=y\nCONFIG_SMB_SERVER=y\n");

    const result = enumerateAttackSurfaces({
      tree,
      configPath: customConfig,
    });
    expect(result.configSource).toBe("dot-config");

    const iouring = result.surfaces.find((s) => s.name === "io_uring");
    expect(iouring!.compiledIn).toBe(true);

    const ksmbd = result.surfaces.find((s) => s.name === "ksmbd");
    expect(ksmbd!.compiledIn).toBe(true);
  });

  it("filters by net/netfilter matching nf_tables paths", () => {
    const tree = join(tmpRoot, "linux");
    mkdirSync(tree);
    writeFileSync(join(tree, ".config"), "CONFIG_NF_TABLES=y\n");

    const result = enumerateAttackSurfaces({
      tree,
      subsystem: "net/netfilter",
    });
    expect(result.surfaces).toHaveLength(1);
    expect(result.surfaces[0]!.name).toBe("nf_tables");
  });
});

// ── DISTRO_DEFAULTS ─────────────────────────────────────────────────────────

describe("DISTRO_DEFAULTS", () => {
  it("has entries for ubuntu, fedora, and arch", () => {
    expect(DISTRO_DEFAULTS).toHaveProperty("ubuntu");
    expect(DISTRO_DEFAULTS).toHaveProperty("fedora");
    expect(DISTRO_DEFAULTS).toHaveProperty("arch");
  });

  it("all distros enable io_uring and eBPF", () => {
    for (const distro of ["ubuntu", "fedora", "arch"]) {
      expect(DISTRO_DEFAULTS[distro]!.has("CONFIG_IO_URING")).toBe(true);
      expect(DISTRO_DEFAULTS[distro]!.has("CONFIG_BPF_SYSCALL")).toBe(true);
    }
  });
});

// ── formatAttackSurfaceForPrompt ────────────────────────────────────────────

describe("formatAttackSurfaceForPrompt", () => {
  it("returns empty string when no surfaces", () => {
    const result: Parameters<typeof formatAttackSurfaceForPrompt>[0] = {
      tree: "/linux",
      configSource: "none",
      surfaces: [],
      warnings: [],
    };
    expect(formatAttackSurfaceForPrompt(result)).toBe("");
  });

  it("renders a prompt section with surface details", () => {
    const tree = join(tmpRoot, "linux");
    mkdirSync(tree);
    writeFileSync(join(tree, ".config"), "CONFIG_IO_URING=y\n");

    const result = enumerateAttackSurfaces({ tree });
    const prompt = formatAttackSurfaceForPrompt(result);

    expect(prompt).toContain("Known Attack Surfaces");
    expect(prompt).toContain("io_uring");
    expect(prompt).toContain("COMPILED IN");
    expect(prompt).toContain("dot-config");
    expect(prompt).toContain("io_uring/");
    expect(prompt).toContain("CONFIG_IO_URING");
  });

  it("shows 'not compiled' for disabled surfaces", () => {
    const tree = join(tmpRoot, "linux");
    mkdirSync(tree);
    // Only enable io_uring, everything else should show as not compiled
    writeFileSync(join(tree, ".config"), "CONFIG_IO_URING=y\n");

    const result = enumerateAttackSurfaces({ tree });
    const prompt = formatAttackSurfaceForPrompt(result);

    expect(prompt).toContain("not compiled");
  });

  it("includes warnings when present", () => {
    const tree = join(tmpRoot, "linux");
    mkdirSync(tree);

    const result = enumerateAttackSurfaces({
      tree,
      distroDefault: "ubuntu",
    });
    const prompt = formatAttackSurfaceForPrompt(result);

    expect(prompt).toContain("Enumeration warnings");
    expect(prompt).toContain("ubuntu");
  });

  it("shows distro default label when used", () => {
    const tree = join(tmpRoot, "linux");
    mkdirSync(tree);

    const result = enumerateAttackSurfaces({
      tree,
      distroDefault: "fedora",
    });
    const prompt = formatAttackSurfaceForPrompt(result);

    expect(prompt).toContain("distro-default");
    expect(prompt).toContain("fedora");
  });
});

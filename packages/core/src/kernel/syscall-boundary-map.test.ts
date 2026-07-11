import { describe, expect, it, vi } from "vitest";
import { resolve, join } from "node:path";
import {
  scanSyscallBoundary,
  _PATTERNS_FOR_TESTING,
  type EntryPoint,
  type EntryPointType,
} from "./syscall-boundary-map.js";

// ── Fixture tree ──

const FIXTURE_TREE = resolve(__dirname, "__fixtures__/fake-kernel-tree");

// ── Pattern extraction unit tests (no rg needed) ──

describe("pattern extraction logic", () => {
  function findPattern(type: EntryPointType) {
    return _PATTERNS_FOR_TESTING.filter((p) => p.type === type);
  }

  it("extracts SYSCALL_DEFINE name", () => {
    const patterns = findPattern("syscall");
    const p = patterns[0]!;
    const result = p.extract("SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)");
    expect(result).toEqual({
      name: "socket",
      userspaceApi: "syscall(SYS_socket)",
    });
  });

  it("extracts COMPAT_SYSCALL_DEFINE name", () => {
    const patterns = findPattern("syscall");
    const p = patterns[1]!;
    const result = p.extract("COMPAT_SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, ...)");
    expect(result).toEqual({
      name: "compat_sendto",
      userspaceApi: "compat syscall(SYS_sendto)",
    });
  });

  it("extracts .unlocked_ioctl handler name", () => {
    const patterns = findPattern("ioctl");
    const p = patterns[0]!;
    const result = p.extract("\t.unlocked_ioctl = alg_ioctl,");
    expect(result).toEqual({ name: "alg_ioctl", userspaceApi: "ioctl(fd, ...)" });
  });

  it("extracts .compat_ioctl handler name", () => {
    const patterns = findPattern("ioctl");
    const p = patterns[0]!;
    const result = p.extract("\t.compat_ioctl = misc_compat_ioctl,");
    expect(result).toEqual({ name: "misc_compat_ioctl", userspaceApi: "ioctl(fd, ...)" });
  });

  it("extracts file_operations struct name", () => {
    const patterns = findPattern("chardev");
    const p = patterns[0]!;
    const result = p.extract("static const struct file_operations alg_fops = {");
    expect(result).toEqual({
      name: "alg_fops",
      userspaceApi: "open/read/write/ioctl on char device",
    });
  });

  it("extracts genl_register_family call", () => {
    const patterns = findPattern("netlink");
    const p = patterns[0]!;
    const result = p.extract("\tgenl_register_family(&tcp_metrics_nl_family);");
    expect(result).toEqual({
      name: "tcp_metrics_nl_family",
      userspaceApi: "generic netlink family",
    });
  });

  it("extracts netlink_kernel_create call", () => {
    const patterns = findPattern("netlink");
    const p = patterns[0]!;
    const result = p.extract("\tnetlink_kernel_create(&init_net, NETLINK_NETFILTER, &nfnl_cfg);");
    expect(result).toEqual({
      name: "netlink_kernel_create",
      userspaceApi: "netlink socket",
    });
  });

  it("extracts genl_family struct definition", () => {
    const patterns = findPattern("netlink");
    const p = patterns[1]!;
    const result = p.extract("static struct genl_family tcp_metrics_nl_family = {");
    expect(result).toEqual({
      name: "tcp_metrics_nl_family",
      userspaceApi: "generic netlink family",
    });
  });

  it("extracts nf_register_net_hook call", () => {
    const patterns = findPattern("netfilter");
    const p = patterns[0]!;
    const result = p.extract("\tnf_register_net_hook(&init_net, &nft_hook);");
    expect(result).toEqual({
      name: "nf_register_net_hook",
      userspaceApi: "netfilter hook (iptables path)",
    });
  });

  it("extracts nf_register_net_hooks (plural) call", () => {
    const patterns = findPattern("netfilter");
    const p = patterns[0]!;
    const result = p.extract(
      "\tnf_register_net_hooks(&init_net, nft_hooks, ARRAY_SIZE(nft_hooks));",
    );
    expect(result).toEqual({
      name: "nf_register_net_hook",
      userspaceApi: "netfilter hook (iptables path)",
    });
  });

  it("extracts bpf_verifier_ops struct name", () => {
    const patterns = findPattern("ebpf");
    const p = patterns[0]!;
    const result = p.extract(
      "static const struct bpf_verifier_ops socket_filter_verifier_ops = {",
    );
    expect(result).toEqual({
      name: "socket_filter_verifier_ops",
      userspaceApi: "bpf(BPF_PROG_LOAD, ...)",
    });
  });

  it("extracts proc_create call", () => {
    const patterns = findPattern("procfs");
    const p = patterns[0]!;
    const result = p.extract('\tproc_create("self/status", 0444, NULL, &proc_status_fops);');
    expect(result).toEqual({
      name: "self/status",
      userspaceApi: "/proc/self/status",
    });
  });

  it("extracts debugfs_create_file call", () => {
    const patterns = findPattern("debugfs");
    const p = patterns[0]!;
    const result = p.extract(
      '\tdebugfs_create_file("security_log", 0444, NULL, NULL, &security_fops);',
    );
    expect(result).toEqual({
      name: "security_log",
      userspaceApi: "/sys/kernel/debug/security_log",
    });
  });

  it("extracts sysfs_create_group call", () => {
    const patterns = findPattern("sysfs");
    const p = patterns[0]!;
    const result = p.extract(
      "\tsysfs_create_group(&dev->kobj, &security_attr_group);",
    );
    expect(result).toEqual({
      name: "sysfs_create_group",
      userspaceApi: "/sys/...",
    });
  });

  it("extracts proto_register call", () => {
    const patterns = findPattern("socket");
    const p = patterns[0]!;
    const result = p.extract("\tproto_register(&alg_proto, 1);");
    expect(result).toEqual({ name: "alg_proto", userspaceApi: "socket()" });
  });

  it("extracts sock_register call", () => {
    const patterns = findPattern("socket");
    const p = patterns[0]!;
    const result = p.extract("\tsock_register(&alg_family);");
    expect(result).toEqual({ name: "alg_family", userspaceApi: "socket()" });
  });

  it("extracts alg_type struct name (AF_ALG)", () => {
    const patterns = findPattern("af_alg");
    const p = patterns[0]!;
    const result = p.extract("static struct alg_type alg_hash_type = {");
    expect(result).toEqual({
      name: "alg_hash_type",
      userspaceApi: "bind(AF_ALG, ...)",
    });
  });

  it("returns null for non-matching lines", () => {
    for (const p of _PATTERNS_FOR_TESTING) {
      expect(p.extract("// just a comment")).toBeNull();
    }
  });
});

// ── Integration tests with mock runner ──

describe("scanSyscallBoundary with mock runner", () => {
  /**
   * Build a mock runner that simulates ripgrep output for the fixture tree.
   * We pre-scan the fixture tree manually and return the expected rg output.
   */
  function makeMockRunner(fixtureLines: Record<string, string[]>) {
    return async (
      _file: string,
      args: string[],
      _opts?: { cwd?: string; maxBuffer?: number },
    ): Promise<{ stdout: string; stderr: string }> => {
      // The regex is the second-to-last arg, the search path is the last arg.
      const searchPath = args[args.length - 1]!;
      const regexArg = args[args.length - 2]!;

      const lines = fixtureLines[regexArg] ?? [];
      // Filter to only lines whose path starts with searchPath.
      const filtered = lines.filter((l) => l.startsWith(searchPath));

      if (filtered.length === 0) {
        // Simulate rg exit code 1 (no matches).
        const err = new Error("no matches") as Error & {
          code: number;
          stdout: string;
          stderr: string;
        };
        err.code = 1;
        err.stdout = "";
        err.stderr = "";
        throw err;
      }

      return { stdout: filtered.join("\n") + "\n", stderr: "" };
    };
  }

  it("returns structured entry points for the whole tree", async () => {
    // For this test, we provide a simple mock that returns known lines.
    const tree = FIXTURE_TREE;
    const syscallLine = `${tree}/crypto/af_alg.c:17:SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)`;
    const ioctlLine = `${tree}/crypto/af_alg.c:29:\t.unlocked_ioctl = alg_ioctl,`;
    const chardevLine = `${tree}/crypto/af_alg.c:27:static const struct file_operations alg_fops = {`;

    const fixtureLines: Record<string, string[]> = {};
    // Map each pattern's regex to the lines that match it.
    for (const p of _PATTERNS_FOR_TESTING) {
      fixtureLines[p.regex] = [];
    }
    // SYSCALL_DEFINE
    fixtureLines[_PATTERNS_FOR_TESTING[0]!.regex]!.push(syscallLine);
    // ioctl
    fixtureLines[_PATTERNS_FOR_TESTING[2]!.regex]!.push(ioctlLine);
    // chardev
    fixtureLines[_PATTERNS_FOR_TESTING[3]!.regex]!.push(chardevLine);

    const result = await scanSyscallBoundary({
      tree,
      runner: makeMockRunner(fixtureLines),
    });

    expect(result.tree).toBe(tree);
    expect(result.subsystem).toBeUndefined();
    expect(result.entryPoints.length).toBe(3);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);

    const syscallEntry = result.entryPoints.find((e) => e.type === "syscall");
    expect(syscallEntry).toBeDefined();
    expect(syscallEntry!.name).toBe("socket");
    expect(syscallEntry!.file).toBe("crypto/af_alg.c");
    expect(syscallEntry!.line).toBe(17);

    const ioctlEntry = result.entryPoints.find((e) => e.type === "ioctl");
    expect(ioctlEntry).toBeDefined();
    expect(ioctlEntry!.name).toBe("alg_ioctl");

    expect(result.summary.syscall).toBe(1);
    expect(result.summary.ioctl).toBe(1);
    expect(result.summary.chardev).toBe(1);
  });

  it("filters by subsystem when specified", async () => {
    const tree = FIXTURE_TREE;
    const cryptoPath = join(tree, "crypto");
    const syscallLine = `${cryptoPath}/af_alg.c:17:SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)`;
    const netLine = `${tree}/net/ipv4/tcp_input.c:4:SYSCALL_DEFINE6(sendto, ...)`;

    const fixtureLines: Record<string, string[]> = {};
    for (const p of _PATTERNS_FOR_TESTING) {
      fixtureLines[p.regex] = [];
    }
    // Both lines go into the SYSCALL_DEFINE pattern.
    fixtureLines[_PATTERNS_FOR_TESTING[0]!.regex]!.push(syscallLine, netLine);

    const result = await scanSyscallBoundary({
      tree,
      subsystem: "crypto",
      runner: makeMockRunner(fixtureLines),
    });

    expect(result.subsystem).toBe("crypto");
    // Only the crypto line should survive (net line path doesn't start with crypto/).
    expect(result.entryPoints.length).toBe(1);
    expect(result.entryPoints[0]!.file).toBe("crypto/af_alg.c");
  });

  it("returns empty results when no matches found", async () => {
    const tree = FIXTURE_TREE;
    const fixtureLines: Record<string, string[]> = {};
    for (const p of _PATTERNS_FOR_TESTING) {
      fixtureLines[p.regex] = [];
    }

    const result = await scanSyscallBoundary({
      tree,
      runner: makeMockRunner(fixtureLines),
    });

    expect(result.entryPoints).toEqual([]);
    expect(result.summary).toEqual({});
  });

  it("de-duplicates identical entries", async () => {
    const tree = FIXTURE_TREE;
    const line = `${tree}/crypto/af_alg.c:17:SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)`;

    const fixtureLines: Record<string, string[]> = {};
    for (const p of _PATTERNS_FOR_TESTING) {
      fixtureLines[p.regex] = [];
    }
    // Same line appears twice from different patterns (shouldn't normally happen,
    // but tests the dedup logic).
    fixtureLines[_PATTERNS_FOR_TESTING[0]!.regex]!.push(line, line);

    const result = await scanSyscallBoundary({
      tree,
      runner: makeMockRunner(fixtureLines),
    });

    // Should be de-duplicated to 1.
    expect(result.entryPoints.length).toBe(1);
  });

  it("sorts entries by file then line", async () => {
    const tree = FIXTURE_TREE;

    const fixtureLines: Record<string, string[]> = {};
    for (const p of _PATTERNS_FOR_TESTING) {
      fixtureLines[p.regex] = [];
    }
    // Add lines in reverse order.
    fixtureLines[_PATTERNS_FOR_TESTING[0]!.regex]!.push(
      `${tree}/net/ipv4/tcp_input.c:4:SYSCALL_DEFINE6(sendto, int, fd, ...)`,
      `${tree}/crypto/af_alg.c:17:SYSCALL_DEFINE3(socket, int, family, ...)`,
    );

    const result = await scanSyscallBoundary({
      tree,
      runner: makeMockRunner(fixtureLines),
    });

    expect(result.entryPoints.length).toBe(2);
    // crypto/ comes before net/ alphabetically.
    expect(result.entryPoints[0]!.file).toBe("crypto/af_alg.c");
    expect(result.entryPoints[1]!.file).toBe("net/ipv4/tcp_input.c");
  });

  it("throws when tree path does not exist", async () => {
    await expect(
      scanSyscallBoundary({ tree: "/nonexistent/kernel/tree" }),
    ).rejects.toThrow(/not found or not a directory/);
  });

  it("returns empty for nonexistent subsystem directory", async () => {
    const tree = FIXTURE_TREE;
    const fixtureLines: Record<string, string[]> = {};
    for (const p of _PATTERNS_FOR_TESTING) {
      fixtureLines[p.regex] = [];
    }

    const result = await scanSyscallBoundary({
      tree,
      subsystem: "nonexistent_subsystem",
      runner: makeMockRunner(fixtureLines),
    });

    expect(result.entryPoints).toEqual([]);
  });
});

// ── Tool definition + validation tests ──

describe("syscall_boundary_map agent tool", () => {
  // Import the tool definition and validator from the agent tool module.
  // We use dynamic import here since the test file lives in kernel/.
  let validateSyscallBoundaryMapArgs: typeof import("../agent/tools/syscall-boundary-map.js").validateSyscallBoundaryMapArgs;
  let SYSCALL_BOUNDARY_MAP_TOOL_DEFINITION: typeof import("../agent/tools/syscall-boundary-map.js").SYSCALL_BOUNDARY_MAP_TOOL_DEFINITION;

  // Use beforeAll to do the dynamic import.
  it("can import tool definition", async () => {
    const mod = await import("../agent/tools/syscall-boundary-map.js");
    validateSyscallBoundaryMapArgs = mod.validateSyscallBoundaryMapArgs;
    SYSCALL_BOUNDARY_MAP_TOOL_DEFINITION = mod.SYSCALL_BOUNDARY_MAP_TOOL_DEFINITION;
    expect(SYSCALL_BOUNDARY_MAP_TOOL_DEFINITION.name).toBe("syscall_boundary_map");
    expect(SYSCALL_BOUNDARY_MAP_TOOL_DEFINITION.required).toEqual(["tree"]);
  });

  it("validates well-formed args", async () => {
    const mod = await import("../agent/tools/syscall-boundary-map.js");
    const r = mod.validateSyscallBoundaryMapArgs({ tree: "/tmp/linux" });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.args.tree).toBe("/tmp/linux");
      expect(r.args.subsystem).toBeUndefined();
    }
  });

  it("validates args with subsystem", async () => {
    const mod = await import("../agent/tools/syscall-boundary-map.js");
    const r = mod.validateSyscallBoundaryMapArgs({
      tree: "/tmp/linux",
      subsystem: "crypto/",
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.args.subsystem).toBe("crypto/");
    }
  });

  it("rejects non-object args", async () => {
    const mod = await import("../agent/tools/syscall-boundary-map.js");
    expect(mod.validateSyscallBoundaryMapArgs(null).ok).toBe(false);
    expect(mod.validateSyscallBoundaryMapArgs("string").ok).toBe(false);
    expect(mod.validateSyscallBoundaryMapArgs(42).ok).toBe(false);
  });

  it("rejects missing or empty tree", async () => {
    const mod = await import("../agent/tools/syscall-boundary-map.js");
    const a = mod.validateSyscallBoundaryMapArgs({});
    expect(a.ok).toBe(false);
    if (!a.ok) expect(a.error).toMatch(/tree.*non-empty/);

    const b = mod.validateSyscallBoundaryMapArgs({ tree: "" });
    expect(b.ok).toBe(false);
  });

  it("rejects non-string subsystem", async () => {
    const mod = await import("../agent/tools/syscall-boundary-map.js");
    const r = mod.validateSyscallBoundaryMapArgs({ tree: "/tmp/linux", subsystem: 42 });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/subsystem.*string/);
  });

  it("strips whitespace-only subsystem to undefined", async () => {
    const mod = await import("../agent/tools/syscall-boundary-map.js");
    const r = mod.validateSyscallBoundaryMapArgs({ tree: "/tmp/linux", subsystem: "   " });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.args.subsystem).toBeUndefined();
    }
  });
});

describe("scanSyscallBoundary without ripgrep", () => {
  it("uses the in-process fallback instead of returning an empty map", async () => {
    const result = await scanSyscallBoundary({
      tree: FIXTURE_TREE,
      rgPath: "/definitely/missing/rg",
    });
    expect(result.entryPoints.length).toBeGreaterThan(0);
    expect(result.entryPoints).toEqual(expect.arrayContaining([
      expect.objectContaining({ type: "syscall", name: "vuln_open" }),
    ]));
  });
});

// ── Integration test with real ripgrep (skip if rg not available) ──

describe("scanSyscallBoundary with real rg", () => {
  let rgAvailable = false;

  it("checks if rg is available", async () => {
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const execFileAsync = promisify(execFile);
    try {
      await execFileAsync("rg", ["--version"]);
      rgAvailable = true;
    } catch {
      rgAvailable = false;
    }
  });

  it("finds entry points in fixture tree", async () => {
    if (!rgAvailable) return; // skip gracefully

    const result = await scanSyscallBoundary({ tree: FIXTURE_TREE });

    // We expect to find at least the entries from our fixture files.
    expect(result.entryPoints.length).toBeGreaterThan(0);

    // Should find SYSCALL_DEFINE entries.
    const syscalls = result.entryPoints.filter((e) => e.type === "syscall");
    expect(syscalls.length).toBeGreaterThanOrEqual(2); // socket + sendto + compat_sendto

    // Should find ioctl handlers.
    const ioctls = result.entryPoints.filter((e) => e.type === "ioctl");
    expect(ioctls.length).toBeGreaterThanOrEqual(1);

    // Should find chardev file_operations.
    const chardevs = result.entryPoints.filter((e) => e.type === "chardev");
    expect(chardevs.length).toBeGreaterThanOrEqual(1);

    // Should find netlink entries.
    const netlinks = result.entryPoints.filter((e) => e.type === "netlink");
    expect(netlinks.length).toBeGreaterThanOrEqual(1);

    // Should find netfilter entries.
    const netfilters = result.entryPoints.filter((e) => e.type === "netfilter");
    expect(netfilters.length).toBeGreaterThanOrEqual(1);

    // Should find BPF entries.
    const ebpf = result.entryPoints.filter((e) => e.type === "ebpf");
    expect(ebpf.length).toBeGreaterThanOrEqual(1);

    // Should find procfs entries.
    const procfs = result.entryPoints.filter((e) => e.type === "procfs");
    expect(procfs.length).toBeGreaterThanOrEqual(1);

    // Should find debugfs entries.
    const debugfs = result.entryPoints.filter((e) => e.type === "debugfs");
    expect(debugfs.length).toBeGreaterThanOrEqual(1);

    // Should find sysfs entries.
    const sysfs = result.entryPoints.filter((e) => e.type === "sysfs");
    expect(sysfs.length).toBeGreaterThanOrEqual(1);

    // Should find socket handlers.
    const sockets = result.entryPoints.filter((e) => e.type === "socket");
    expect(sockets.length).toBeGreaterThanOrEqual(1);

    // Should find AF_ALG entries.
    const af_alg = result.entryPoints.filter((e) => e.type === "af_alg");
    expect(af_alg.length).toBeGreaterThanOrEqual(1);
  });

  it("filters by subsystem with real rg", async () => {
    if (!rgAvailable) return;

    const result = await scanSyscallBoundary({
      tree: FIXTURE_TREE,
      subsystem: "crypto",
    });

    // Only crypto/ files should appear.
    for (const ep of result.entryPoints) {
      expect(ep.file).toMatch(/^crypto\//);
    }

    // Should find the socket syscall and alg_ioctl at minimum.
    expect(result.entryPoints.length).toBeGreaterThanOrEqual(1);
  });
});

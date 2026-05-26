/**
 * `syscall_boundary_map` — maps the userspace-reachable attack surface of a
 * kernel source tree. Replaces unreliable grep-based search with structured
 * pattern extraction for:
 *
 *   - SYSCALL_DEFINE* macros
 *   - .unlocked_ioctl / .compat_ioctl handlers (file_operations)
 *   - genl_family / netlink_kernel_create (netlink)
 *   - nf_register_net_hook (netfilter)
 *   - char-device file_operations structs
 *   - BPF program types (bpf_verifier_ops)
 *   - sysfs / procfs / debugfs entries
 *   - Socket protocol handlers (proto_register, sock_register)
 *   - AF_ALG bind targets (struct alg_type)
 *
 * Output is structured JSON that the kernel review agent can query, optionally
 * filtered by subsystem path prefix.
 *
 * pwnkit#468
 */

import { execFile } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { resolve, relative, sep } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

// ── Types ──

export type EntryPointType =
  | "syscall"
  | "ioctl"
  | "netlink"
  | "netfilter"
  | "chardev"
  | "ebpf"
  | "sysfs"
  | "procfs"
  | "debugfs"
  | "socket"
  | "af_alg";

export interface EntryPoint {
  type: EntryPointType;
  /** Resolved function or symbol name. */
  name: string;
  /** Path relative to the kernel tree root. */
  file: string;
  /** 1-based line number of the match. */
  line: number;
  /** Short description of the userspace API surface. */
  userspaceApi?: string;
}

export interface SyscallBoundaryMap {
  /** Absolute path of the scanned kernel tree. */
  tree: string;
  /** Subsystem filter that was applied (undefined = whole tree). */
  subsystem?: string;
  /** When the scan started. */
  startedAt: string;
  /** When the scan finished. */
  completedAt: string;
  /** Wall-clock milliseconds. */
  durationMs: number;
  /** All discovered entry points. */
  entryPoints: EntryPoint[];
  /** Summary counts by type. */
  summary: Record<EntryPointType, number>;
}

export interface SyscallBoundaryMapOptions {
  /** Absolute or relative path to a Linux kernel source tree. */
  tree: string;
  /**
   * Optional subsystem path prefix filter (e.g. "crypto/", "net/ipv4").
   * When set, only files under this subtree are scanned.
   */
  subsystem?: string;
  /**
   * Override the ripgrep binary name or path. Defaults to "rg".
   */
  rgPath?: string;
  /**
   * Injected runner for tests. When provided, replaces all execFile calls.
   */
  runner?: (
    file: string,
    args: string[],
    opts?: { cwd?: string; maxBuffer?: number },
  ) => Promise<{ stdout: string; stderr: string }>;
}

// ── Pattern Definitions ──

/**
 * Each pattern specifies: the ripgrep regex, the entry-point type, a function
 * that extracts name + userspaceApi from the matched line, and optional
 * extra rg flags.
 */
interface ScanPattern {
  type: EntryPointType;
  /** PCRE2 regex for ripgrep (--pcre2). */
  regex: string;
  /** Extract name + optional userspaceApi from matched line text. */
  extract: (line: string) => { name: string; userspaceApi?: string } | null;
  /** Extra rg flags (e.g. --multiline). */
  extraFlags?: string[];
}

const PATTERNS: ScanPattern[] = [
  // ── SYSCALL_DEFINE* ──
  {
    type: "syscall",
    regex: String.raw`^SYSCALL_DEFINE\d+\(\s*(\w+)`,
    extract: (line) => {
      const m = line.match(/^SYSCALL_DEFINE\d+\(\s*(\w+)/);
      if (!m) return null;
      return { name: m[1]!, userspaceApi: `syscall(SYS_${m[1]})` };
    },
  },
  // Also match COMPAT_SYSCALL_DEFINE*
  {
    type: "syscall",
    regex: String.raw`^COMPAT_SYSCALL_DEFINE\d+\(\s*(\w+)`,
    extract: (line) => {
      const m = line.match(/^COMPAT_SYSCALL_DEFINE\d+\(\s*(\w+)/);
      if (!m) return null;
      return { name: `compat_${m[1]}`, userspaceApi: `compat syscall(SYS_${m[1]})` };
    },
  },

  // ── .unlocked_ioctl / .compat_ioctl ──
  {
    type: "ioctl",
    regex: String.raw`\.(unlocked_ioctl|compat_ioctl)\s*=\s*(\w+)`,
    extract: (line) => {
      const m = line.match(/\.(unlocked_ioctl|compat_ioctl)\s*=\s*(\w+)/);
      if (!m) return null;
      return { name: m[2]!, userspaceApi: `ioctl(fd, ...)` };
    },
  },

  // ── file_operations struct definitions (chardev surface) ──
  {
    type: "chardev",
    regex: String.raw`(?:static\s+)?(?:const\s+)?struct\s+file_operations\s+(\w+)`,
    extract: (line) => {
      const m = line.match(/struct\s+file_operations\s+(\w+)/);
      if (!m) return null;
      return { name: m[1]!, userspaceApi: "open/read/write/ioctl on char device" };
    },
  },

  // ── Netlink: genl_register_family / netlink_kernel_create ──
  {
    type: "netlink",
    regex: String.raw`genl_register_family\s*\(\s*&?\s*(\w+)|netlink_kernel_create\s*\(`,
    extract: (line) => {
      const m1 = line.match(/genl_register_family\s*\(\s*&?\s*(\w+)/);
      if (m1) return { name: m1[1]!, userspaceApi: "generic netlink family" };
      const m2 = line.match(/netlink_kernel_create\s*\(/);
      if (m2) return { name: "netlink_kernel_create", userspaceApi: "netlink socket" };
      return null;
    },
  },

  // ── Netlink: genl_family struct definitions ──
  {
    type: "netlink",
    regex: String.raw`(?:static\s+)?(?:const\s+)?struct\s+genl_family\s+(\w+)`,
    extract: (line) => {
      const m = line.match(/struct\s+genl_family\s+(\w+)/);
      if (!m) return null;
      return { name: m[1]!, userspaceApi: "generic netlink family" };
    },
  },

  // ── Netfilter: nf_register_net_hook(s) ──
  {
    type: "netfilter",
    regex: String.raw`nf_register_net_hooks?\s*\(`,
    extract: (line) => {
      const m = line.match(/nf_register_net_hooks?\s*\(/);
      if (!m) return null;
      return { name: "nf_register_net_hook", userspaceApi: "netfilter hook (iptables path)" };
    },
  },

  // ── BPF: bpf_verifier_ops / bpf_prog_type registrations ──
  {
    type: "ebpf",
    regex: String.raw`(?:static\s+)?(?:const\s+)?struct\s+bpf_verifier_ops\s+(\w+)`,
    extract: (line) => {
      const m = line.match(/struct\s+bpf_verifier_ops\s+(\w+)/);
      if (!m) return null;
      return { name: m[1]!, userspaceApi: "bpf(BPF_PROG_LOAD, ...)" };
    },
  },

  // ── sysfs ──
  {
    type: "sysfs",
    regex: String.raw`sysfs_create_group\s*\(|sysfs_create_file\s*\(`,
    extract: (line) => {
      if (line.includes("sysfs_create_group")) {
        return { name: "sysfs_create_group", userspaceApi: "/sys/..." };
      }
      if (line.includes("sysfs_create_file")) {
        return { name: "sysfs_create_file", userspaceApi: "/sys/..." };
      }
      return null;
    },
  },

  // ── procfs ──
  {
    type: "procfs",
    regex: String.raw`proc_create\w*\s*\(\s*"([^"]+)"`,
    extract: (line) => {
      const m = line.match(/proc_create\w*\s*\(\s*"([^"]+)"/);
      if (!m) return null;
      return { name: m[1]!, userspaceApi: `/proc/${m[1]}` };
    },
  },

  // ── debugfs ──
  {
    type: "debugfs",
    regex: String.raw`debugfs_create_\w+\s*\(\s*"([^"]+)"`,
    extract: (line) => {
      const m = line.match(/debugfs_create_\w+\s*\(\s*"([^"]+)"/);
      if (!m) return null;
      return { name: m[1]!, userspaceApi: `/sys/kernel/debug/${m[1]}` };
    },
  },

  // ── Socket protocol handlers ──
  {
    type: "socket",
    regex: String.raw`proto_register\s*\(\s*&?\s*(\w+)|sock_register\s*\(\s*&?\s*(\w+)`,
    extract: (line) => {
      const m1 = line.match(/proto_register\s*\(\s*&?\s*(\w+)/);
      if (m1) return { name: m1[1]!, userspaceApi: "socket()" };
      const m2 = line.match(/sock_register\s*\(\s*&?\s*(\w+)/);
      if (m2) return { name: m2[1]!, userspaceApi: "socket()" };
      return null;
    },
  },

  // ── AF_ALG: alg_type registrations ──
  {
    type: "af_alg",
    regex: String.raw`(?:static\s+)?(?:const\s+)?struct\s+alg_type\s+(\w+)`,
    extract: (line) => {
      const m = line.match(/struct\s+alg_type\s+(\w+)/);
      if (!m) return null;
      return { name: m[1]!, userspaceApi: "bind(AF_ALG, ...)" };
    },
  },
];

// ── Core scan logic ──

/**
 * Run a single ripgrep pattern against the kernel tree and collect matches.
 */
async function runPattern(
  pattern: ScanPattern,
  tree: string,
  subsystem: string | undefined,
  runner: NonNullable<SyscallBoundaryMapOptions["runner"]>,
  rgPath: string,
): Promise<EntryPoint[]> {
  const searchPath = subsystem ? resolve(tree, subsystem) : tree;
  // If subsystem path doesn't exist, return empty (e.g. "crypto/" in a tree
  // that doesn't have a crypto/ directory).
  if (!existsSync(searchPath)) return [];

  const args = [
    "--no-heading",
    "--line-number",
    "--pcre2",
    "-g", "*.c",
    "-g", "*.h",
    ...(pattern.extraFlags ?? []),
    pattern.regex,
    searchPath,
  ];

  let stdout: string;
  try {
    const result = await runner(rgPath, args, {
      cwd: tree,
      maxBuffer: 10 * 1024 * 1024,
    });
    stdout = result.stdout;
  } catch (err: unknown) {
    // rg exits with code 1 when no matches found — that's fine.
    if (isExecError(err) && err.code === 1) return [];
    // rg exits with code 2 for partial errors — use whatever stdout we got.
    if (isExecError(err) && err.code === 2 && err.stdout) {
      stdout = err.stdout;
    } else {
      throw err;
    }
  }

  const results: EntryPoint[] = [];
  for (const rawLine of stdout.split("\n")) {
    const trimmed = rawLine.trim();
    if (!trimmed) continue;

    // rg --no-heading -n output: <filepath>:<line>:<text>
    // But we used --no-filename, so it's <line>:<text> ... wait, --no-filename
    // only suppresses filename when searching a single file. For directories
    // it still emits path. Let me adjust: we do NOT use --no-filename for
    // directory searches. The format is: <filepath>:<line>:<text>
    const parsed = parseRgLine(trimmed, tree);
    if (!parsed) continue;

    const extracted = pattern.extract(parsed.text);
    if (!extracted) continue;

    results.push({
      type: pattern.type,
      name: extracted.name,
      file: parsed.relPath,
      line: parsed.line,
      ...(extracted.userspaceApi ? { userspaceApi: extracted.userspaceApi } : {}),
    });
  }

  return results;
}

interface ExecError extends Error {
  code?: number;
  stdout?: string;
  stderr?: string;
}

function isExecError(err: unknown): err is ExecError {
  return err instanceof Error && "code" in err;
}

/**
 * Parse a ripgrep output line in the form `filepath:line:text`.
 * Returns the file path relative to the tree root.
 */
function parseRgLine(
  raw: string,
  tree: string,
): { relPath: string; line: number; text: string } | null {
  // Format: /abs/path/to/file.c:123:matched text here
  // We need to handle Windows paths too but kernel trees are always on Unix.
  // Find the first `:` that is followed by digits and another `:`.
  const match = raw.match(/^(.+?):(\d+):(.*)$/);
  if (!match) return null;

  const absPath = match[1]!;
  const lineNum = parseInt(match[2]!, 10);
  const text = match[3]!;

  if (isNaN(lineNum)) return null;

  // Make path relative to tree root.
  let relPath: string;
  const resolvedTree = resolve(tree);
  if (absPath.startsWith(resolvedTree + sep) || absPath.startsWith(resolvedTree + "/")) {
    relPath = absPath.slice(resolvedTree.length + 1);
  } else {
    relPath = relative(resolvedTree, absPath);
  }

  return { relPath, line: lineNum, text };
}

// ── Public API ──

/**
 * Scan a kernel source tree and return a structured map of all
 * userspace-reachable entry points.
 */
export async function scanSyscallBoundary(
  options: SyscallBoundaryMapOptions,
): Promise<SyscallBoundaryMap> {
  const startMs = Date.now();
  const startedAt = new Date(startMs).toISOString();

  const tree = resolve(options.tree);
  if (!existsSync(tree) || !statSync(tree).isDirectory()) {
    throw new Error(`Kernel tree not found or not a directory: ${tree}`);
  }

  const rgPath = options.rgPath ?? "rg";

  const defaultRunner: NonNullable<SyscallBoundaryMapOptions["runner"]> = (
    file,
    args,
    opts,
  ) =>
    execFileAsync(file, args, {
      cwd: opts?.cwd,
      maxBuffer: opts?.maxBuffer ?? 10 * 1024 * 1024,
    });

  const runner = options.runner ?? defaultRunner;

  // Run all patterns in parallel.
  const allResults = await Promise.all(
    PATTERNS.map((p) => runPattern(p, tree, options.subsystem, runner, rgPath)),
  );

  const entryPoints = allResults.flat();

  // De-duplicate: same file + line + type + name should appear only once
  // (can happen if two patterns overlap).
  const seen = new Set<string>();
  const deduped: EntryPoint[] = [];
  for (const ep of entryPoints) {
    const key = `${ep.type}:${ep.file}:${ep.line}:${ep.name}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(ep);
    }
  }

  // Sort: by file, then line.
  deduped.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);

  // Summary counts.
  const summary = {} as Record<EntryPointType, number>;
  for (const ep of deduped) {
    summary[ep.type] = (summary[ep.type] ?? 0) + 1;
  }

  const completedMs = Date.now();

  return {
    tree,
    subsystem: options.subsystem,
    startedAt,
    completedAt: new Date(completedMs).toISOString(),
    durationMs: completedMs - startMs,
    entryPoints: deduped,
    summary,
  };
}

/**
 * Exported for tests: the raw pattern list so test fixtures can verify
 * extraction logic without needing ripgrep.
 */
export { PATTERNS as _PATTERNS_FOR_TESTING };

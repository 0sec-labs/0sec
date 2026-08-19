/**
 * `syscall_boundary_map` agent tool (0sec#468).
 *
 * Maps the userspace-reachable attack surface of a kernel source tree:
 * SYSCALL_DEFINE macros, ioctl handlers, netlink families, netfilter hooks,
 * char-device file_operations, eBPF hooks, sysfs/procfs/debugfs entries,
 * socket protocol handlers, and AF_ALG bind targets.
 *
 * Like `kernel_run`, this tool is OPT-IN: it is not in the global
 * `TOOL_DEFINITIONS` table. It is made available to the kernel review agent
 * so it can enumerate the attack surface early in a review.
 *
 * Contract:
 *   - Args: `{ tree: string, subsystem?: string }`
 *   - Calls `scanSyscallBoundary()` and returns a `SyscallBoundaryMap`.
 *   - Rejects missing/invalid tree paths before scanning.
 */

import type { ToolDefinition } from "../types.js";
import {
  scanSyscallBoundary,
  type SyscallBoundaryMap,
  type SyscallBoundaryMapOptions,
} from "../../kernel/syscall-boundary-map.js";

// ── Tool Definition ──

export const SYSCALL_BOUNDARY_MAP_TOOL_DEFINITION: ToolDefinition = {
  name: "syscall_boundary_map",
  description:
    "Scan a Linux kernel source tree and return a structured map of all " +
    "userspace-reachable entry points: SYSCALL_DEFINE macros, ioctl handlers, " +
    "netlink families, netfilter hooks, char-device file_operations, eBPF " +
    "hooks, sysfs/procfs/debugfs entries, socket handlers, and AF_ALG targets. " +
    "Use this at the start of any kernel review to understand what unprivileged " +
    "userspace can reach. When subsystem is set, only that subtree is scanned.",
  parameters: {
    tree: {
      type: "string",
      description:
        "Absolute path to the Linux kernel source tree to scan.",
    },
    subsystem: {
      type: "string",
      description:
        "Optional subsystem path prefix to filter results (e.g. 'crypto/', " +
        "'net/ipv4', 'drivers/usb'). When omitted, the entire tree is scanned.",
    },
  },
  required: ["tree"],
};

// ── Arg types ──

export interface SyscallBoundaryMapArgs {
  tree: string;
  subsystem?: string;
}

export interface SyscallBoundaryMapResult {
  ok: boolean;
  error?: string;
  map?: SyscallBoundaryMap;
}

// ── Validation ──

export function validateSyscallBoundaryMapArgs(raw: unknown):
  | { ok: true; args: SyscallBoundaryMapArgs }
  | { ok: false; error: string } {
  if (!raw || typeof raw !== "object") {
    return { ok: false, error: "syscall_boundary_map: arguments must be an object" };
  }
  const bag = raw as Record<string, unknown>;

  const tree = bag.tree;
  if (typeof tree !== "string" || tree.length === 0) {
    return {
      ok: false,
      error: "syscall_boundary_map: 'tree' must be a non-empty string",
    };
  }

  let subsystem: string | undefined;
  if (bag.subsystem !== undefined && bag.subsystem !== null) {
    if (typeof bag.subsystem !== "string") {
      return {
        ok: false,
        error: "syscall_boundary_map: 'subsystem' must be a string when provided",
      };
    }
    const trimmed = bag.subsystem.trim();
    if (trimmed.length > 0) subsystem = trimmed;
  }

  return {
    ok: true,
    args: {
      tree,
      ...(subsystem !== undefined ? { subsystem } : {}),
    },
  };
}

// ── Execution ──

/**
 * Execute a validated syscall_boundary_map call. The kernel review agent loop
 * is responsible for translating the result into a tool_use payload.
 */
export async function executeSyscallBoundaryMap(
  args: SyscallBoundaryMapArgs,
  opts?: { runner?: SyscallBoundaryMapOptions["runner"]; rgPath?: string },
): Promise<SyscallBoundaryMapResult> {
  try {
    const map = await scanSyscallBoundary({
      tree: args.tree,
      subsystem: args.subsystem,
      runner: opts?.runner,
      rgPath: opts?.rgPath,
    });
    return { ok: true, map };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

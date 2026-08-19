/**
 * Cross-subsystem data flow tracing for kernel reviews (0sec#469).
 *
 * Bugs like Copy Fail (CVE-2026-31431) emerge from interactions between
 * subsystems — no single function contains the vulnerability. This module
 * provides:
 *
 * 1. A database of kernel subsystems and their boundaries.
 * 2. Known cross-subsystem data flow patterns that have historically
 *    produced vulnerabilities.
 * 3. A static scanner that, given a kernel source tree, identifies files
 *    that sit on cross-subsystem boundaries (calling into or receiving
 *    data from another subsystem).
 * 4. Agent-ready prompt formatting that instructs the agent to follow
 *    data flow across subsystem boundaries.
 *
 * This is NOT a taint engine. It is a static map of cross-boundary data
 * flows for the agent to investigate with its "follow the pointer"
 * heuristic (option (c) from the issue).
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

// ── Types ───────────────────────────────────────────────────────────────────

/** A kernel subsystem with its source paths and boundary characteristics. */
export interface KernelSubsystem {
  /** Short identifier, e.g. "crypto", "mm", "splice", "net/core". */
  id: string;
  /** Human-readable name. */
  name: string;
  /** Source paths relative to kernel tree root. */
  paths: string[];
  /**
   * Key data structures this subsystem owns or operates on.
   * Used to detect cross-boundary data sharing.
   */
  dataStructures: string[];
  /**
   * Key functions exported or used at the subsystem boundary.
   * Callers outside this subsystem touching these functions indicate
   * cross-boundary data flow.
   */
  boundaryFunctions: string[];
}

/**
 * A known cross-subsystem data flow pattern, typically one that has
 * historically produced (or could produce) vulnerabilities.
 */
export interface CrossSubsystemFlow {
  /** Unique identifier for this flow pattern. */
  id: string;
  /** Human-readable description of the flow. */
  description: string;
  /** Ordered chain of subsystem IDs the data traverses. */
  chain: string[];
  /**
   * The key data object that flows across the boundary
   * (e.g. "struct page *", "struct sk_buff *").
   */
  dataObject: string;
  /**
   * Assumptions each subsystem in the chain makes about the data.
   * Maps subsystem ID to a list of assumptions.
   */
  assumptions: Record<string, string[]>;
  /**
   * What goes wrong: the mismatch between subsystem assumptions
   * that creates the vulnerability class.
   */
  vulnerabilityClass: string;
  /** CVE references for known instances of this pattern. */
  knownCves: string[];
  /**
   * Regex patterns (as strings) to grep for in source files to detect
   * this flow pattern. These are heuristic, not precise.
   */
  detectionHints: string[];
  /** Risk level for this cross-subsystem flow. */
  risk: "critical" | "high" | "medium" | "low";
}

/** A boundary crossing detected in a source file. */
export interface BoundaryCrossing {
  /** Source file relative to kernel tree root. */
  file: string;
  /** Line number where the crossing was detected. */
  line: number;
  /** The subsystem the file belongs to. */
  sourceSubsystem: string;
  /** The subsystem being called into. */
  targetSubsystem: string;
  /** The function or pattern that was matched. */
  matchedPattern: string;
  /** The raw source line. */
  sourceLine: string;
  /** If this crossing matches a known vulnerable flow, its ID. */
  knownFlowId?: string;
}

/** Result of scanning a kernel tree for cross-subsystem data flows. */
export interface CrossSubsystemScanResult {
  /** Kernel tree path that was scanned. */
  tree: string;
  /** Subsystem filter applied (if any). */
  subsystemFilter?: string;
  /** All boundary crossings found. */
  crossings: BoundaryCrossing[];
  /** Crossings grouped by flow pattern. */
  flowSummaries: FlowSummary[];
  /** Warnings encountered during scanning. */
  warnings: string[];
}

/** Summary of a detected cross-subsystem flow. */
export interface FlowSummary {
  /** Source subsystem. */
  from: string;
  /** Target subsystem. */
  to: string;
  /** Number of boundary crossings in this direction. */
  crossingCount: number;
  /** If this matches a known vulnerable flow pattern, its ID. */
  knownFlowId?: string;
  /** Risk level (inherited from known flow, or "medium" for unknown). */
  risk: "critical" | "high" | "medium" | "low";
  /** Files involved in this flow. */
  files: string[];
}

export interface CrossSubsystemScanOptions {
  /** Path to the kernel source tree. */
  tree: string;
  /** Optional subsystem filter — only scan these subsystem paths. */
  subsystem?: string;
  /** Maximum files to scan per subsystem directory (default 100). */
  maxFilesPerDir?: number;
  /** Maximum lines to scan per file (default 5000). */
  maxLinesPerFile?: number;
}

// ── Known subsystems database ──────────────────────────────────────────────

export const KERNEL_SUBSYSTEMS: KernelSubsystem[] = [
  {
    id: "crypto",
    name: "Crypto / AF_ALG",
    paths: ["crypto/"],
    dataStructures: [
      "struct crypto_aead",
      "struct aead_request",
      "struct scatterlist",
      "struct skcipher_request",
      "struct af_alg_ctx",
    ],
    boundaryFunctions: [
      "crypto_aead_encrypt",
      "crypto_aead_decrypt",
      "af_alg_sendmsg",
      "af_alg_sendpage",
      "af_alg_make_sg",
      "crypto_aead_setkey",
      "crypto_skcipher_encrypt",
      "crypto_skcipher_decrypt",
      "sg_set_page",
      "sg_set_buf",
    ],
  },
  {
    id: "splice",
    name: "splice / pipe",
    paths: ["fs/splice.c", "fs/pipe.c"],
    dataStructures: [
      "struct pipe_inode_info",
      "struct pipe_buffer",
      "struct splice_desc",
      "struct splice_pipe_desc",
    ],
    boundaryFunctions: [
      "splice_to_pipe",
      "do_splice",
      "do_splice_to",
      "do_splice_from",
      "splice_direct_to_actor",
      "generic_file_splice_read",
      "iter_file_splice_write",
      "pipe_to_sendpage",
      "kernel_sendpage",
      "splice_from_pipe_feed",
    ],
  },
  {
    id: "mm",
    name: "Memory management / page cache",
    paths: ["mm/"],
    dataStructures: [
      "struct page",
      "struct folio",
      "struct vm_area_struct",
      "struct address_space",
      "struct mm_struct",
    ],
    boundaryFunctions: [
      "find_get_page",
      "filemap_get_folio",
      "grab_cache_page",
      "read_mapping_page",
      "pagecache_get_page",
      "page_cache_alloc",
      "kmap",
      "kmap_local_page",
      "kunmap",
      "kunmap_local",
      "copy_highpage",
      "copy_user_highpage",
      "get_page",
      "put_page",
      "folio_lock",
      "folio_unlock",
      "page_ref_count",
      "folio_ref_count",
    ],
  },
  {
    id: "net/core",
    name: "Networking core",
    paths: ["net/core/", "net/socket.c"],
    dataStructures: [
      "struct sk_buff",
      "struct sock",
      "struct socket",
      "struct net_device",
      "struct skb_shared_info",
    ],
    boundaryFunctions: [
      "skb_cow_data",
      "pskb_expand_head",
      "skb_clone",
      "skb_copy",
      "skb_shared",
      "skb_cloned",
      "sock_sendmsg",
      "sock_recvmsg",
      "kernel_sendpage",
      "kernel_sendmsg",
      "skb_page_frag_refill",
      "skb_fill_page_desc",
    ],
  },
  {
    id: "net/ipv4",
    name: "IPv4 / ESP / TCP",
    paths: ["net/ipv4/"],
    dataStructures: [
      "struct iphdr",
      "struct tcphdr",
      "struct ip_options",
    ],
    boundaryFunctions: [
      "esp_input",
      "esp_output",
      "tcp_sendmsg",
      "tcp_sendpage",
      "ip_output",
      "ip_local_deliver",
    ],
  },
  {
    id: "net/ipv6",
    name: "IPv6 / ESP6",
    paths: ["net/ipv6/"],
    dataStructures: [
      "struct ipv6hdr",
      "struct ipv6_opt_hdr",
    ],
    boundaryFunctions: [
      "esp6_input",
      "esp6_output",
      "tcp_v6_sendmsg",
    ],
  },
  {
    id: "net/netfilter",
    name: "Netfilter / nf_tables",
    paths: ["net/netfilter/"],
    dataStructures: [
      "struct nf_hook_ops",
      "struct nft_expr",
      "struct nft_rule",
      "struct nft_set",
    ],
    boundaryFunctions: [
      "nf_hook",
      "nf_register_net_hook",
      "nft_do_chain",
      "nf_ct_get",
      "nf_conntrack_find_get",
    ],
  },
  {
    id: "io_uring",
    name: "io_uring",
    paths: ["io_uring/"],
    dataStructures: [
      "struct io_ring_ctx",
      "struct io_kiocb",
      "struct io_uring_sqe",
      "struct io_uring_cqe",
    ],
    boundaryFunctions: [
      "io_uring_setup",
      "io_uring_enter",
      "io_issue_sqe",
      "io_submit_sqes",
      "io_splice",
      "io_sendmsg",
      "io_recvmsg",
    ],
  },
  {
    id: "fs/vfs",
    name: "VFS layer",
    paths: ["fs/"],
    dataStructures: [
      "struct file",
      "struct inode",
      "struct dentry",
      "struct super_block",
      "struct file_operations",
    ],
    boundaryFunctions: [
      "vfs_read",
      "vfs_write",
      "vfs_splice_read",
      "vfs_splice_write",
      "do_sendfile",
      "generic_file_read_iter",
      "generic_file_write_iter",
      "filemap_read",
      "filemap_write_and_wait",
    ],
  },
  {
    id: "bpf",
    name: "eBPF",
    paths: ["kernel/bpf/"],
    dataStructures: [
      "struct bpf_prog",
      "struct bpf_map",
      "struct bpf_verifier_env",
      "struct xdp_buff",
    ],
    boundaryFunctions: [
      "bpf_prog_run",
      "bpf_map_lookup_elem",
      "bpf_map_update_elem",
      "bpf_redirect",
      "xdp_do_redirect",
      "bpf_skb_load_bytes",
    ],
  },
  {
    id: "fs/fuse",
    name: "FUSE",
    paths: ["fs/fuse/"],
    dataStructures: [
      "struct fuse_conn",
      "struct fuse_req",
      "struct fuse_args",
    ],
    boundaryFunctions: [
      "fuse_simple_request",
      "fuse_dev_read",
      "fuse_dev_write",
      "fuse_send_init",
    ],
  },
  {
    id: "drivers/usb",
    name: "USB",
    paths: ["drivers/usb/"],
    dataStructures: [
      "struct urb",
      "struct usb_device",
      "struct usb_host_endpoint",
    ],
    boundaryFunctions: [
      "usb_submit_urb",
      "usb_control_msg",
      "usb_bulk_msg",
    ],
  },
];

// ── Known cross-subsystem vulnerability flow patterns ──────────────────────

export const KNOWN_CROSS_SUBSYSTEM_FLOWS: CrossSubsystemFlow[] = [
  {
    id: "copy-fail-afalg-splice-pagecache-aead",
    description:
      "AF_ALG splice to pipe shares page-cache pages with AEAD scatterlist. " +
      "AEAD in-place decrypt corrupts shared page-cache pages because splice " +
      "does not copy-on-write the page before handing it to crypto.",
    chain: ["crypto", "splice", "mm", "crypto"],
    dataObject: "struct page *",
    assumptions: {
      crypto: [
        "AEAD decrypt receives exclusive pages in scatterlist",
        "In-place decrypt is safe because no one else references these pages",
      ],
      splice: [
        "Pages obtained from sendpage/sendmsg are reference-counted",
        "splice_to_pipe increments page refcount but does not COW",
      ],
      mm: [
        "Page cache pages may be shared by multiple mappings",
        "Writers must either COW or hold exclusive access",
        "page_count > 1 means page is shared",
      ],
    },
    vulnerabilityClass:
      "Shared page-cache page written in-place by crypto subsystem. " +
      "The splice subsystem passes page references without copying, and the " +
      "crypto subsystem decrypts in-place assuming exclusive ownership.",
    knownCves: ["CVE-2026-31431"],
    detectionHints: [
      "af_alg_sendpage",
      "splice_to_pipe.*page",
      "sg_set_page",
      "crypto_aead_decrypt",
      "skb_cow_data",
      "page_ref_count",
    ],
    risk: "critical",
  },
  {
    id: "dirty-pipe-splice-pagecache-write",
    description:
      "splice merges pipe buffers that share page-cache pages, then a " +
      "subsequent write to the pipe overwrites the cached page content " +
      "because the PIPE_BUF_FLAG_CAN_MERGE flag is improperly set.",
    chain: ["splice", "mm", "fs/vfs"],
    dataObject: "struct page *",
    assumptions: {
      splice: [
        "Pipe buffers from splice should not be merged with subsequent writes",
        "PIPE_BUF_FLAG_CAN_MERGE should only be set for freshly allocated pages",
      ],
      mm: [
        "Page cache pages must not be modified by pipe operations",
        "Copy-on-write semantics should protect shared pages",
      ],
      "fs/vfs": [
        "File data read through splice is immutable from the reader's perspective",
        "VFS trusts that splice consumers don't modify read-only pages",
      ],
    },
    vulnerabilityClass:
      "Pipe buffer merge flag set on page-cache pages allows arbitrary " +
      "file overwrite through pipe write after splice read.",
    knownCves: ["CVE-2022-0847"],
    detectionHints: [
      "PIPE_BUF_FLAG_CAN_MERGE",
      "copy_page_to_iter_pipe",
      "push_pipe",
      "splice_from_pipe",
      "pipe_buf_release",
    ],
    risk: "critical",
  },
  {
    id: "dirty-cow-mm-vfs-write",
    description:
      "Race condition between madvise(MADV_DONTNEED) and a write to a " +
      "copy-on-write private mapping allows writing to read-only files.",
    chain: ["mm", "fs/vfs"],
    dataObject: "struct page * (COW page)",
    assumptions: {
      mm: [
        "COW pages are copied before write access is granted",
        "madvise(MADV_DONTNEED) discards the private copy",
        "The race window between COW fault and DONTNEED is safe",
      ],
      "fs/vfs": [
        "Read-only file mappings cannot be written through mmap",
        "Private mappings provide isolation from the underlying file",
      ],
    },
    vulnerabilityClass:
      "TOCTOU race in COW page fault handling: madvise discards the " +
      "private copy mid-fault, causing the write to land on the shared " +
      "file-backed page.",
    knownCves: ["CVE-2016-5195"],
    detectionHints: [
      "MADV_DONTNEED",
      "follow_page_mask",
      "faultin_page",
      "can_follow_write_pte",
      "FOLL_WRITE",
      "FOLL_COW",
    ],
    risk: "critical",
  },
  {
    id: "io-uring-splice-cross-boundary",
    description:
      "io_uring's splice operations bridge the async I/O subsystem with " +
      "VFS splice paths. Lifetime and ownership assumptions diverge: " +
      "io_uring may complete asynchronously while splice holds page refs.",
    chain: ["io_uring", "splice", "mm"],
    dataObject: "struct page * / struct pipe_buffer",
    assumptions: {
      io_uring: [
        "Async completion does not race with splice page refs",
        "io_splice completes atomically from splice's perspective",
      ],
      splice: [
        "Splice callers remain synchronous for the duration of the page ref",
        "pipe_buffer pages are valid until pipe_buf_release",
      ],
      mm: [
        "Pages referenced by splice are properly refcounted",
        "Async freeing does not invalidate in-flight splice pages",
      ],
    },
    vulnerabilityClass:
      "Lifetime mismatch: io_uring async completion can race with " +
      "splice page buffer references, leading to use-after-free or " +
      "page-cache corruption.",
    knownCves: [],
    detectionHints: [
      "io_splice",
      "io_splice_prep",
      "do_splice",
      "pipe_buf_release",
      "io_issue_sqe",
    ],
    risk: "high",
  },
  {
    id: "bpf-skb-shared-data",
    description:
      "BPF programs modify skb data (via helpers like bpf_skb_store_bytes) " +
      "on cloned skbs where the data area is shared. Without proper " +
      "pskb_expand_head / skb_cow_data, modifications corrupt the original.",
    chain: ["bpf", "net/core"],
    dataObject: "struct sk_buff *",
    assumptions: {
      bpf: [
        "BPF helpers check skb_cloned before modification",
        "bpf_skb_store_bytes calls skb_ensure_writable",
      ],
      "net/core": [
        "Cloned skbs share data area until explicitly copied",
        "skb_cow_data / pskb_expand_head creates a private copy",
      ],
    },
    vulnerabilityClass:
      "Shared skb data modified without COW check in BPF helper, " +
      "corrupting in-flight packets or bypassing network filters.",
    knownCves: [],
    detectionHints: [
      "bpf_skb_store_bytes",
      "skb_ensure_writable",
      "skb_cloned",
      "pskb_expand_head",
      "skb_cow_data",
      "bpf_skb_pull_data",
    ],
    risk: "high",
  },
  {
    id: "netfilter-conntrack-skb-mutation",
    description:
      "Netfilter hooks (especially NAT and connection tracking) modify skb " +
      "headers and payloads. If the skb is shared (cloned) and the hook " +
      "does not COW, modifications corrupt cloned copies.",
    chain: ["net/netfilter", "net/core"],
    dataObject: "struct sk_buff *",
    assumptions: {
      "net/netfilter": [
        "NAT hooks assume writable skb headers",
        "nf_nat_mangle_udp_packet / nf_nat_mangle_tcp_packet call skb_ensure_writable",
      ],
      "net/core": [
        "skb clones share linear data and frags",
        "Modification requires skb_cow_data or pskb_expand_head",
      ],
    },
    vulnerabilityClass:
      "NAT/conntrack modifying shared skb data without proper COW, " +
      "causing packet corruption or information disclosure.",
    knownCves: [],
    detectionHints: [
      "nf_nat_mangle",
      "skb_ensure_writable",
      "nf_hook_slow",
      "nf_ct_get",
      "skb_cow_data",
    ],
    risk: "medium",
  },
  {
    id: "fuse-vfs-pagecache-toctou",
    description:
      "FUSE allows userspace to control filesystem responses. Between " +
      "VFS checking permissions and FUSE returning data, the daemon " +
      "can change what it serves, creating TOCTOU windows.",
    chain: ["fs/fuse", "fs/vfs", "mm"],
    dataObject: "struct page * / file data",
    assumptions: {
      "fs/fuse": [
        "FUSE daemon responses are consistent between check and use",
        "Attributes (size, mode) don't change between lookup and read",
      ],
      "fs/vfs": [
        "Filesystem metadata is stable during a syscall",
        "Inode attributes reflect actual file state",
      ],
      mm: [
        "Page cache contents match the filesystem backing store",
        "readpage fills pages with data that matches the inode size",
      ],
    },
    vulnerabilityClass:
      "TOCTOU between VFS permission/metadata checks and FUSE daemon " +
      "response: daemon changes file semantics mid-operation.",
    knownCves: [],
    detectionHints: [
      "fuse_simple_request",
      "fuse_readpages",
      "fuse_getattr",
      "fuse_lookup",
      "inode_newsize_ok",
    ],
    risk: "medium",
  },
];

// ── Subsystem identification ───────────────────────────────────────────────

/**
 * Given a file path relative to the kernel tree root, determine which
 * subsystem it belongs to. Returns the best-matching subsystem ID,
 * or "unknown" if no match.
 */
export function identifySubsystem(filePath: string): string {
  const normalized = filePath.replace(/^\/+/, "");

  // Try specific subsystems first (more specific paths before generic)
  // Sort by path length descending so more specific paths match first
  const sorted = [...KERNEL_SUBSYSTEMS].sort((a, b) => {
    const maxA = Math.max(...a.paths.map((p) => p.length));
    const maxB = Math.max(...b.paths.map((p) => p.length));
    return maxB - maxA;
  });

  for (const subsystem of sorted) {
    for (const subPath of subsystem.paths) {
      const normalizedSubPath = subPath.replace(/\/+$/, "");
      if (
        normalized === normalizedSubPath ||
        normalized.startsWith(normalizedSubPath + "/") ||
        normalized.startsWith(normalizedSubPath)
      ) {
        return subsystem.id;
      }
    }
  }

  return "unknown";
}

/**
 * Check if a source line references a boundary function from another subsystem.
 * Returns the target subsystem ID and matched function, or null.
 */
export function detectBoundaryCrossing(
  sourceLine: string,
  sourceSubsystem: string,
): { targetSubsystem: string; matchedFunction: string } | null {
  for (const subsystem of KERNEL_SUBSYSTEMS) {
    if (subsystem.id === sourceSubsystem) continue;

    for (const func of subsystem.boundaryFunctions) {
      // Match function calls: func_name( or references to the function
      const pattern = new RegExp(`\\b${escapeRegex(func)}\\s*\\(`);
      if (pattern.test(sourceLine)) {
        return {
          targetSubsystem: subsystem.id,
          matchedFunction: func,
        };
      }
    }
  }
  return null;
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ── Source scanning ────────────────────────────────────────────────────────

/**
 * Scan a kernel source tree for cross-subsystem boundary crossings.
 *
 * For each .c/.h file in the scanned subsystem paths, checks every line
 * for calls to boundary functions belonging to OTHER subsystems. This
 * identifies files that bridge subsystem boundaries.
 */
export function scanCrossSubsystemFlows(
  options: CrossSubsystemScanOptions,
): CrossSubsystemScanResult {
  const { tree, subsystem, maxFilesPerDir = 100, maxLinesPerFile = 5000 } = options;
  const warnings: string[] = [];
  const crossings: BoundaryCrossing[] = [];

  // Determine which subsystem paths to scan
  let subsystemsToScan = KERNEL_SUBSYSTEMS;
  if (subsystem) {
    const filterIds = subsystem
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    subsystemsToScan = KERNEL_SUBSYSTEMS.filter((sub) =>
      filterIds.some(
        (f) =>
          sub.id === f ||
          sub.paths.some((p) => {
            const np = p.replace(/\/+$/, "");
            const nf = f.replace(/\/+$/, "");
            return np === nf || np.startsWith(nf + "/") || nf.startsWith(np + "/");
          }),
      ),
    );

    if (subsystemsToScan.length === 0) {
      warnings.push(
        `No known subsystems match filter: ${subsystem}. Scanning all subsystems.`,
      );
      subsystemsToScan = KERNEL_SUBSYSTEMS;
    }
  }

  for (const sub of subsystemsToScan) {
    for (const relPath of sub.paths) {
      const absPath = join(tree, relPath);
      const files = collectSourceFiles(absPath, maxFilesPerDir);

      for (const file of files) {
        let content: string;
        try {
          content = readFileSync(file, "utf8");
        } catch {
          continue;
        }

        const lines = content.split("\n");
        const lineLimit = Math.min(lines.length, maxLinesPerFile);

        for (let i = 0; i < lineLimit; i++) {
          const line = lines[i]!;
          // Skip comments and preprocessor directives
          const trimmed = line.trim();
          if (trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*")) {
            continue;
          }

          const crossing = detectBoundaryCrossing(line, sub.id);
          if (crossing) {
            const relFile = relative(tree, file);
            const knownFlow = findKnownFlow(sub.id, crossing.targetSubsystem);

            crossings.push({
              file: relFile,
              line: i + 1,
              sourceSubsystem: sub.id,
              targetSubsystem: crossing.targetSubsystem,
              matchedPattern: crossing.matchedFunction,
              sourceLine: line.trim(),
              knownFlowId: knownFlow?.id,
            });
          }
        }
      }
    }
  }

  // Build flow summaries
  const flowMap = new Map<string, FlowSummary>();
  for (const crossing of crossings) {
    const key = `${crossing.sourceSubsystem}->${crossing.targetSubsystem}`;
    let summary = flowMap.get(key);
    if (!summary) {
      const knownFlow = findKnownFlow(
        crossing.sourceSubsystem,
        crossing.targetSubsystem,
      );
      summary = {
        from: crossing.sourceSubsystem,
        to: crossing.targetSubsystem,
        crossingCount: 0,
        knownFlowId: knownFlow?.id,
        risk: knownFlow?.risk ?? "medium",
        files: [],
      };
      flowMap.set(key, summary);
    }
    summary.crossingCount++;
    if (!summary.files.includes(crossing.file)) {
      summary.files.push(crossing.file);
    }
  }

  // Sort summaries by risk, then by crossing count
  const riskOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };
  const flowSummaries = Array.from(flowMap.values()).sort((a, b) => {
    const riskDiff = (riskOrder[a.risk] ?? 2) - (riskOrder[b.risk] ?? 2);
    if (riskDiff !== 0) return riskDiff;
    return b.crossingCount - a.crossingCount;
  });

  return {
    tree,
    subsystemFilter: subsystem,
    crossings,
    flowSummaries,
    warnings,
  };
}

/**
 * Find a known cross-subsystem flow pattern that involves the given
 * source and target subsystems adjacent in its chain.
 */
function findKnownFlow(
  sourceSubsystem: string,
  targetSubsystem: string,
): CrossSubsystemFlow | undefined {
  return KNOWN_CROSS_SUBSYSTEM_FLOWS.find((flow) => {
    for (let i = 0; i < flow.chain.length - 1; i++) {
      if (
        flow.chain[i] === sourceSubsystem &&
        flow.chain[i + 1] === targetSubsystem
      ) {
        return true;
      }
      // Also check reverse direction (data flows both ways)
      if (
        flow.chain[i] === targetSubsystem &&
        flow.chain[i + 1] === sourceSubsystem
      ) {
        return true;
      }
    }
    return false;
  });
}

/**
 * Collect .c and .h source files from a path (non-recursive to one level
 * of directories for speed).
 */
function collectSourceFiles(absPath: string, maxFiles: number): string[] {
  if (!existsSync(absPath)) return [];

  try {
    const stat = statSync(absPath);
    // If the path is a file (e.g. "fs/splice.c"), return it directly
    if (stat.isFile() && (absPath.endsWith(".c") || absPath.endsWith(".h"))) {
      return [absPath];
    }
    if (!stat.isDirectory()) return [];
  } catch {
    return [];
  }

  const files: string[] = [];
  try {
    const entries = readdirSync(absPath);
    for (const entry of entries) {
      if (files.length >= maxFiles) break;
      const full = join(absPath, entry);
      try {
        const s = statSync(full);
        if (s.isFile() && (entry.endsWith(".c") || entry.endsWith(".h"))) {
          files.push(full);
        }
      } catch {
        // skip
      }
    }
  } catch {
    // skip unreadable directories
  }

  return files;
}

// ── Agent prompt formatting ────────────────────────────────────────────────

/**
 * Format known cross-subsystem flow patterns as a section for the
 * kernel review agent prompt. This gives the agent context about known
 * multi-subsystem vulnerability patterns and instructs it to trace
 * data flow across boundaries.
 */
export function formatCrossSubsystemFlowsForPrompt(
  result?: CrossSubsystemScanResult,
): string {
  const lines: string[] = [
    "## Cross-Subsystem Data Flow Tracing Instructions",
    "",
    "Many kernel vulnerabilities emerge from *interactions between subsystems*, not from any local code defect. When reviewing kernel code, you MUST trace data flow across subsystem boundaries.",
    "",
    "### Tracing protocol",
    "",
    "When you identify a data flow of interest (e.g. a function receives a page, skb, or scatterlist from another subsystem):",
    "",
    "1. **Trace UP (caller chain, 2-3 levels):** Where did this data come from? Which subsystem allocated or populated it? What assumptions did that subsystem make about ownership and lifetime?",
    "2. **Trace DOWN (callee chain, 2-3 levels):** Where does this data go next? Does the receiving code assume exclusive ownership? Does it modify in-place?",
    "3. **Document assumptions:** For each subsystem the data passes through, list what that subsystem assumes about the data (ownership, mutability, refcount, lifetime).",
    "4. **Find the mismatch:** The vulnerability exists where subsystem A's assumptions conflict with subsystem B's assumptions about the SAME data object.",
    "5. **Tag cross-subsystem findings** with the subsystem chain (e.g. `crypto → splice → mm → crypto`).",
    "",
    "### Key data objects to trace across boundaries",
    "",
    "- `struct page *` / `struct folio *` — page cache pages shared via splice, sendfile, mmap",
    "- `struct sk_buff *` — network buffers cloned/shared across netfilter, crypto, BPF",
    "- `struct scatterlist` — DMA/crypto scatter-gather lists referencing shared pages",
    "- `struct pipe_buffer` — pipe buffers holding page references from splice",
    "",
  ];

  // Add known flow patterns
  lines.push("### Known vulnerable cross-subsystem flow patterns");
  lines.push("");

  for (const flow of KNOWN_CROSS_SUBSYSTEM_FLOWS) {
    const chainStr = flow.chain.join(" → ");
    const cveStr =
      flow.knownCves.length > 0
        ? flow.knownCves.join(", ")
        : "no known CVEs yet (pattern class)";
    lines.push(`#### [${flow.risk.toUpperCase()}] ${flow.id}`);
    lines.push(`Chain: \`${chainStr}\``);
    lines.push(`Data object: \`${flow.dataObject}\``);
    lines.push(`CVEs: ${cveStr}`);
    lines.push(`${flow.description}`);
    lines.push("");
    lines.push("Assumptions by subsystem:");
    for (const [subId, assumptions] of Object.entries(flow.assumptions)) {
      lines.push(`- **${subId}**: ${assumptions.join("; ")}`);
    }
    lines.push("");
    lines.push(
      `Detection hints: ${flow.detectionHints.map((h) => `\`${h}\``).join(", ")}`,
    );
    lines.push("");
  }

  // Add scan results if available
  if (result && result.crossings.length > 0) {
    lines.push("### Detected boundary crossings in this tree");
    lines.push("");
    lines.push(
      `Found ${result.crossings.length} cross-subsystem boundary crossings across ${result.flowSummaries.length} flow directions.`,
    );
    lines.push("");

    for (const summary of result.flowSummaries) {
      const riskLabel = summary.knownFlowId
        ? ` **[${summary.risk.toUpperCase()} — matches known pattern: ${summary.knownFlowId}]**`
        : "";
      lines.push(
        `- **${summary.from} → ${summary.to}**: ${summary.crossingCount} crossings in ${summary.files.length} files${riskLabel}`,
      );
      for (const file of summary.files.slice(0, 5)) {
        lines.push(`  - \`${file}\``);
      }
      if (summary.files.length > 5) {
        lines.push(`  - ... and ${summary.files.length - 5} more files`);
      }
    }
    lines.push("");
  }

  if (result?.warnings && result.warnings.length > 0) {
    lines.push("**Scan warnings:**");
    for (const w of result.warnings) {
      lines.push(`- ${w}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

/**
 * Get the known cross-subsystem flows relevant to a specific subsystem.
 * Useful for narrowing the agent's attention when scanning a single subsystem.
 */
export function getFlowsForSubsystem(subsystemId: string): CrossSubsystemFlow[] {
  return KNOWN_CROSS_SUBSYSTEM_FLOWS.filter((flow) =>
    flow.chain.includes(subsystemId),
  );
}

/**
 * Given two subsystem IDs, describe the assumptions mismatch that
 * could lead to a vulnerability. Returns null if no known flow exists.
 */
export function describeAssumptionMismatch(
  subsystemA: string,
  subsystemB: string,
): string | null {
  const flow = findKnownFlow(subsystemA, subsystemB);
  if (!flow) return null;

  const assumptionsA = flow.assumptions[subsystemA] ?? [];
  const assumptionsB = flow.assumptions[subsystemB] ?? [];

  const parts: string[] = [
    `Known flow pattern: ${flow.id}`,
    `Chain: ${flow.chain.join(" → ")}`,
    `Data object: ${flow.dataObject}`,
    "",
    `${subsystemA} assumes:`,
    ...assumptionsA.map((a) => `  - ${a}`),
    "",
    `${subsystemB} assumes:`,
    ...assumptionsB.map((a) => `  - ${a}`),
    "",
    `Vulnerability class: ${flow.vulnerabilityClass}`,
  ];

  if (flow.knownCves.length > 0) {
    parts.push(`Known CVEs: ${flow.knownCves.join(", ")}`);
  }

  return parts.join("\n");
}

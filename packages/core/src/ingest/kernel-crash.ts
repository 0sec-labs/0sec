import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, basename } from "node:path";
import type { Finding, AttackCategory, CrashReport, CrashType } from "@pwnkit/shared";
import type { Severity } from "@pwnkit/shared";

export interface KernelCrashArtifact {
  sourcePath: string;
  reproducerPath?: string;
  report: CrashReport;
  finding: Finding;
}

// ── Regex patterns for kernel crash detection ──

const KASAN_HEADER = /BUG:\s*KASAN:\s*([\w-]+)\s+in\s+(\S+)/;
const KASAN_ACCESS = /(Read|Write)\s+of\s+size\s+(\d+)\s+at\s+addr\s+([0-9a-fA-Fx]+)/;
const UBSAN_HEADER = /UBSAN:\s*([\w\s-]+)\s+in\s+(\S+)/;
const KERNEL_PANIC = /Kernel panic\s*-\s*not syncing:\s*(.*)/;
const KERNEL_OOPS = /Oops:\s+(?:[^:\n]+:\s+)?([0-9a-fA-F]+)/;
const KERNEL_BUG = /BUG:\s+(?!KASAN)(.+)/;
const GP_FAULT = /general protection fault,?\s*(?:#?(\w+))?.*?:\s*([0-9a-fA-F]+)/;
const RCU_STALL = /rcu:\s*(.*stall.*)/i;
const LOCKDEP = /(?:BUG|WARNING):\s*.*lock(?:dep|ing)/i;
const KERNEL_WARNING = /WARNING:.*\bat\s+\S+\s+(\S+)\+0x[0-9a-fA-F]+\/0x[0-9a-fA-F]+/;
const CALL_TRACE_START = /Call Trace:/;
const STACK_FRAME = /\[<([0-9a-fA-F]+)>\]\s*(\S+)/;
const STACK_FRAME_ALT = /^\s*(\S+)\+0x[0-9a-fA-F]+\/0x[0-9a-fA-F]+/;
const KERNEL_VERSION = /Linux version\s+([\d.]+[\w.-]*)/;
const COMMIT_HASH = /Linux version\s+\S+\s+\(.*?\)\s+.*?#\d+\s+\w+\s+.*?\b([0-9a-f]{7,40})\b/;
const ALLOC_SITE = /Allocated by task.*?:\n([\s\S]*?)(?:\n\n|\nFreed)/;
const FREE_SITE = /Freed by task.*?:\n([\s\S]*?)(?:\n\n|\n(?:The|BUG|=))/;
const IP_LINE = /(?:RIP|IP):\s*(?:[0-9a-fA-F]+:)?(?:\[<[0-9a-fA-F]+>\])?\s*(\S+)/;

// ── Subsystem inference ──

export const SUBSYSTEM_PATTERNS: [RegExp, string][] = [
  [/\bnfs[d34]?\b/, "fs/nfsd"],
  [/\bext[234]_/, "fs/ext4"],
  [/\bbtrfs\b/, "fs/btrfs"],
  [/\bxfs\b/, "fs/xfs"],
  [/\bf2fs\b/, "fs/f2fs"],
  [/\bfat\b/, "fs/fat"],
  [/\bntfs\b/, "fs/ntfs"],
  [/\bovl_|overlay/, "fs/overlayfs"],
  [/\btcp_/, "net/tcp"],
  [/\budp_/, "net/udp"],
  [/\bsctp_/, "net/sctp"],
  [/\binet_|ip_|ip6_/, "net/ip"],
  [/\bnetfilter|nf_|nft_/, "net/netfilter"],
  [/\bbt_|hci_|l2cap_/, "drivers/bluetooth"],
  [/\bieee80211|cfg80211|nl80211|mac80211/, "net/wireless"],
  [/\busb_/, "drivers/usb"],
  [/\bdrm_|amdgpu|i915/, "drivers/gpu"],
  [/\bsnd_|audio/, "sound"],
  [/\bkvm_/, "virt/kvm"],
  [/\bio_uring/, "io_uring"],
  [/\bsocket|sock_|sk_/, "net/core"],
  [/\bblk_|block/, "block"],
  [/\bmm_|slab|kmalloc|kfree|vmalloc|page_alloc/, "mm"],
  [/\bsched_|schedule/, "kernel/sched"],
  [/\bcgroup/, "kernel/cgroup"],
  [/\bselinux|apparmor|smack/, "security"],
  [/\bcrypto_|aes|sha/, "crypto"],
];

const NETWORK_SUBSYSTEMS = new Set([
  "net/tcp", "net/udp", "net/sctp", "net/ip", "net/netfilter",
  "drivers/bluetooth", "net/wireless", "net/core",
  "fs/nfsd",
]);

function inferSubsystem(frames: string[]): string {
  // First pass: check all frames (not just top 10) for known subsystem patterns.
  // Prefer matches deeper in the stack over generic infrastructure functions
  // (e.g., rhashtable, lock, kasan) that appear at the top.
  const joined = frames.join(" ");
  for (const [pat, sub] of SUBSYSTEM_PATTERNS) {
    if (pat.test(joined)) return sub;
  }
  // Fallback: use top non-infrastructure frame's prefix
  const infraPrefixes = new Set(["dump", "print", "kasan", "lock", "spin", "rcu", "slab", "kmem", "kfree", "kmalloc", "raw", "rht", "rhashtable", "instrument", "atomic", "check"]);
  for (const frame of frames) {
    const prefix = frame.split("_")[0];
    if (prefix && prefix.length > 1 && !infraPrefixes.has(prefix)) return prefix;
  }
  return "unknown";
}

// ── Call stack extraction ──

function extractCallStack(text: string): string[] {
  const frames: string[] = [];
  const lines = text.split("\n");
  let inTrace = false;

  for (const line of lines) {
    if (CALL_TRACE_START.test(line)) {
      inTrace = true;
      continue;
    }
    if (inTrace) {
      // End of trace on blank line or non-stack content
      if (/^\s*$/.test(line) || /^[A-Z]/.test(line.trim())) {
        // Allow some headers within trace (like "RIP:", "Code:")
        if (!/^\s*\?/.test(line) && !/\+0x/.test(line) && !/\[</.test(line)) {
          break;
        }
      }
      // Match [<addr>] func+offset/size or just func+offset/size
      const m1 = line.match(STACK_FRAME);
      if (m1) {
        const fn = m1[2].replace(/\+0x.*$/, "");
        if (fn && !fn.startsWith("?")) frames.push(fn);
        continue;
      }
      const m2 = line.match(STACK_FRAME_ALT);
      if (m2) {
        const fn = m2[1].replace(/\+0x.*$/, "");
        if (fn && !fn.startsWith("?")) frames.push(fn);
        continue;
      }
      // Also handle ? prefix (unreliable frames) — skip them
    }
  }

  return frames;
}

// ── Alloc/free site extraction (KASAN) ──

function extractAllocFreeSites(text: string): { allocSite?: string; freeSite?: string } {
  const result: { allocSite?: string; freeSite?: string } = {};

  const allocMatch = text.match(/Allocated by task \d+:\n([\s\S]*?)(?:\n\s*\n|\nFreed by)/);
  if (allocMatch) {
    const frames = extractFramesFromBlock(allocMatch[1]);
    result.allocSite = frames[0] || undefined;
  }

  const freeMatch = text.match(/Freed by task \d+:\n([\s\S]*?)(?:\n\s*\n|\nThe buggy address)/);
  if (freeMatch) {
    const frames = extractFramesFromBlock(freeMatch[1]);
    result.freeSite = frames[0] || undefined;
  }

  return result;
}

function extractFramesFromBlock(block: string): string[] {
  const frames: string[] = [];
  for (const line of block.split("\n")) {
    const m = line.match(STACK_FRAME) || line.match(STACK_FRAME_ALT);
    if (m) {
      const fn = (m[2] || m[1]).replace(/\+0x.*$/, "");
      // Skip allocator internals
      if (fn && !/^kasan_|^kmalloc|^__kmalloc|^kfree|^slab_|^__slab/.test(fn)) {
        frames.push(fn);
      }
    }
  }
  return frames;
}

// ── KASAN sub-type detection ──

function kasanSubType(bugType: string): CrashType {
  const lower = bugType.toLowerCase();
  // Order matters: more specific patterns before general ones
  if (lower.includes("double-free")) {
    return "kasan-double-free";
  }
  if (lower.includes("invalid-free")) {
    return "kasan-invalid-free";
  }
  if (lower.includes("stack-out-of-bounds") || lower.includes("stack-buffer-overflow")) {
    return "kasan-stack-oob";
  }
  if (lower.includes("use-after-free") || lower.includes("slab-use-after-free")) {
    return "kasan-uaf";
  }
  if (lower.includes("null-ptr-deref") || lower.includes("null pointer")) {
    return "kasan-null";
  }
  if (lower.includes("wild-memory-access") || lower.includes("wild")) {
    return "kasan-wild";
  }
  if (lower.includes("out-of-bounds") || lower.includes("slab-out-of-bounds") || lower.includes("global-out-of-bounds")) {
    return "kasan-oob";
  }
  // Default for unrecognized KASAN types
  return "kasan-oob";
}

// ── UBSAN sub-type detection ──

function ubsanSubType(bugType: string): CrashType {
  const lower = bugType.toLowerCase().trim();
  if (lower.includes("shift-out-of-range") || lower.includes("shift")) {
    return "ubsan-shift";
  }
  if (lower.includes("integer overflow") || lower.includes("signed-integer-overflow") || lower.includes("unsigned-integer-overflow") || lower.includes("negation")) {
    return "ubsan-overflow";
  }
  if (lower.includes("array-index-out-of-bounds") || lower.includes("index") || lower.includes("out-of-bounds")) {
    return "ubsan-bounds";
  }
  if (lower.includes("misaligned") || lower.includes("alignment") || lower.includes("member access")) {
    return "ubsan-alignment";
  }
  return "ubsan";
}

// ── Main parser ──

export function parseCrashReport(text: string): CrashReport {
  const report: CrashReport = {
    rawText: text,
    crashType: "unknown",
    faultingFunction: "unknown",
    callStack: [],
    subsystem: "unknown",
  };

  // Extract kernel version
  const verMatch = text.match(KERNEL_VERSION);
  if (verMatch) report.kernelVersion = verMatch[1];

  const commitMatch = text.match(/\b([0-9a-f]{40})\b/);
  if (commitMatch) report.commitHash = commitMatch[1];

  // Extract call stack
  report.callStack = extractCallStack(text);

  // Detect crash type (order matters — more specific first)
  const kasanMatch = text.match(KASAN_HEADER);
  if (kasanMatch) {
    report.crashType = kasanSubType(kasanMatch[1]);
    report.faultingFunction = kasanMatch[2].replace(/\+0x.*$/, "");

    const accessMatch = text.match(KASAN_ACCESS);
    if (accessMatch) {
      report.accessType = accessMatch[1].toLowerCase() as "read" | "write";
      report.accessSize = parseInt(accessMatch[2], 10);
      report.accessAddress = accessMatch[3];
    }

    const sites = extractAllocFreeSites(text);
    report.allocSite = sites.allocSite;
    report.freeSite = sites.freeSite;
  } else if (UBSAN_HEADER.test(text)) {
    const ubMatch = text.match(UBSAN_HEADER)!;
    report.crashType = ubsanSubType(ubMatch[1]);
    const ubsanLocation = ubMatch[2];
    // UBSAN headers give file:line:col, not function names.
    // The real function is the first non-ubsan frame in the call trace,
    // or we extract it from the file path as a fallback.
    const ubsanCallerFrame = report.callStack.find(
      f => !/^__?ubsan_|^dump_stack|^print_report|^ubsan_epilogue/.test(f)
    );
    if (ubsanCallerFrame) {
      report.faultingFunction = ubsanCallerFrame;
    } else {
      // Extract function-like name from file path: drivers/ata/libata-core.c:5166 → libata-core
      const fileMatch = ubsanLocation.match(/([^/]+)\.\w+:\d+/);
      report.faultingFunction = fileMatch ? fileMatch[1] : ubsanLocation.replace(/:\d+.*$/, "");
    }
  } else if (KERNEL_PANIC.test(text)) {
    report.crashType = "kernel-panic";
    const ipMatch = text.match(IP_LINE);
    report.faultingFunction = ipMatch
      ? ipMatch[1].replace(/\+0x.*$/, "")
      : report.callStack[0] || "unknown";
  } else if (GP_FAULT.test(text)) {
    report.crashType = "general-protection";
    const ipMatch = text.match(IP_LINE);
    report.faultingFunction = ipMatch
      ? ipMatch[1].replace(/\+0x.*$/, "")
      : report.callStack[0] || "unknown";
  } else if (RCU_STALL.test(text)) {
    report.crashType = "rcu-stall";
    report.faultingFunction = report.callStack[0] || "unknown";
  } else if (LOCKDEP.test(text)) {
    report.crashType = "lockdep";
    report.faultingFunction = report.callStack[0] || "unknown";
  } else if (KERNEL_WARNING.test(text)) {
    report.crashType = "kernel-oops"; // WARNINGs are soft oops
    const warnMatch = text.match(KERNEL_WARNING)!;
    report.faultingFunction = warnMatch[1].replace(/\+0x.*$/, "");
  } else if (KERNEL_OOPS.test(text)) {
    report.crashType = "kernel-oops";
    const ipMatch = text.match(IP_LINE);
    report.faultingFunction = ipMatch
      ? ipMatch[1].replace(/\+0x.*$/, "")
      : report.callStack[0] || "unknown";
  } else if (KERNEL_BUG.test(text)) {
    report.crashType = "kernel-bug";
    const ipMatch = text.match(IP_LINE);
    report.faultingFunction = ipMatch
      ? ipMatch[1].replace(/\+0x.*$/, "")
      : report.callStack[0] || "unknown";
  }

  // If faultingFunction still unknown, try first call stack frame
  if (report.faultingFunction === "unknown" && report.callStack.length > 0) {
    report.faultingFunction = report.callStack[0];
  }

  // Infer subsystem
  const allFrames = [report.faultingFunction, ...report.callStack];
  report.subsystem = inferSubsystem(allFrames);

  return report;
}

// ── Category mapping ──

export function crashTypeToCategory(crashType: CrashType): AttackCategory {
  switch (crashType) {
    case "kasan-oob": return "heap-overflow";
    case "kasan-stack-oob": return "stack-buffer-overflow";
    case "kasan-uaf": return "use-after-free";
    case "kasan-double-free": return "double-free";
    case "kasan-invalid-free": return "double-free";
    case "kasan-null": return "null-pointer-deref";
    case "kasan-wild": return "use-after-free";
    case "ubsan": return "integer-overflow";
    case "ubsan-shift": return "integer-overflow";
    case "ubsan-overflow": return "integer-overflow";
    case "ubsan-bounds": return "heap-overflow";
    case "ubsan-alignment": return "type-confusion";
    case "kernel-bug": return "null-pointer-deref";
    case "kernel-oops": return "null-pointer-deref";
    case "kernel-panic": return "null-pointer-deref";
    case "general-protection": return "null-pointer-deref";
    case "rcu-stall": return "race-condition";
    case "lockdep": return "race-condition";
    case "unknown": return "null-pointer-deref";
  }
}

// ── Severity heuristic ──

export function crashSeverity(report: CrashReport): Severity {
  const cat = crashTypeToCategory(report.crashType);
  let sev: Severity;

  switch (cat) {
    case "use-after-free":
      sev = "critical";
      break;
    case "heap-overflow":
      sev = report.accessType === "write" ? "critical" : "high";
      break;
    case "stack-buffer-overflow":
    case "type-confusion":
      sev = "high";
      break;
    case "null-pointer-deref":
    case "integer-overflow":
    case "double-free":
      sev = "medium";
      break;
    case "race-condition":
      sev = "low";
      break;
    default:
      sev = "medium";
  }

  // Boost severity if network-facing subsystem
  if (NETWORK_SUBSYSTEMS.has(report.subsystem)) {
    if (sev === "low") sev = "medium";
    else if (sev === "medium") sev = "high";
    else if (sev === "high") sev = "critical";
  }

  return sev;
}

// ── CrashReport → Finding ──

export function crashToFinding(report: CrashReport): Finding {
  const category = crashTypeToCategory(report.crashType);
  const severity = crashSeverity(report);
  const stackSummary = report.callStack.slice(0, 5).join(" → ");

  const accessDetails = report.accessType
    ? `${report.accessType} of size ${report.accessSize ?? "?"} at ${report.accessAddress ?? "?"}`
    : "";

  const description = [
    `Kernel ${report.crashType} detected in function ${report.faultingFunction}.`,
    accessDetails ? `Access: ${accessDetails}.` : "",
    report.subsystem !== "unknown" ? `Subsystem: ${report.subsystem}.` : "",
    stackSummary ? `Call path: ${stackSummary}.` : "",
    report.kernelVersion ? `Kernel version: ${report.kernelVersion}.` : "",
  ].filter(Boolean).join("\n");

  const analysisLines = [
    `Crash type: ${report.crashType}`,
    `Category: ${category}`,
    `Faulting function: ${report.faultingFunction}`,
    `Subsystem: ${report.subsystem}`,
    `Stack depth: ${report.callStack.length} frames`,
  ];
  if (report.allocSite) analysisLines.push(`Alloc site: ${report.allocSite}`);
  if (report.freeSite) analysisLines.push(`Free site: ${report.freeSite}`);
  if (report.accessType) analysisLines.push(`Access: ${report.accessType} size=${report.accessSize ?? "?"}`);

  // Confidence by crash type reliability
  let confidence = 0.4;
  if (report.crashType.startsWith("kasan")) confidence = 0.8;
  else if (report.crashType.startsWith("ubsan")) confidence = 0.7;
  else if (report.crashType === "kernel-oops" || report.crashType === "general-protection") confidence = 0.6;

  return {
    id: randomUUID(),
    templateId: `kernel-${report.crashType}`,
    title: `Linux kernel ${report.crashType}: ${report.faultingFunction} in ${report.subsystem}`,
    description,
    severity,
    category,
    status: "discovered",
    evidence: {
      request: report.reproducer ?? "N/A (kernel crash report)",
      response: report.rawText.length > 4000
        ? report.rawText.slice(0, 4000) + "\n... [truncated]"
        : report.rawText,
      analysis: analysisLines.join("\n"),
    },
    confidence,
    timestamp: Date.now(),
  };
}

// ── Multi-report splitting ──

function splitReports(text: string): string[] {
  // Split on === dividers or double blank lines preceding a crash header
  const parts = text.split(/(?:^={3,}\s*$)/m).filter((p) => p.trim().length > 0);
  if (parts.length > 1) return parts;

  // Try splitting on double blank lines that precede a known crash header
  const segments: string[] = [];
  const crashHeaderRe = /(?:BUG:|UBSAN:|Kernel panic|Oops:|general protection fault|rcu:.*stall|WARNING:.*lock)/;
  const blocks = text.split(/\n{3,}/);

  let current = "";
  for (const block of blocks) {
    if (crashHeaderRe.test(block) && current.trim().length > 0) {
      segments.push(current.trim());
      current = block;
    } else {
      current += "\n\n" + block;
    }
  }
  if (current.trim().length > 0) segments.push(current.trim());

  return segments.length > 0 ? segments : [text];
}

// ── File ingest ──

export function ingestArtifactsFromFile(filePath: string): KernelCrashArtifact[] {
  const text = readFileSync(filePath, "utf-8");
  const segments = splitReports(text);
  const artifacts: KernelCrashArtifact[] = [];

  for (const segment of segments) {
    // Skip segments that don't look like crash reports
    if (!/BUG:|UBSAN:|Kernel panic|Oops:|general protection|rcu:.*stall|WARNING:.*lock|Call Trace:/i.test(segment)) {
      continue;
    }
    const report = parseCrashReport(segment);
    if (report.crashType === "unknown") continue;
    artifacts.push({
      sourcePath: filePath,
      report,
      finding: crashToFinding(report),
    });
  }

  return artifacts;
}

export function ingestFile(filePath: string): Finding[] {
  return ingestArtifactsFromFile(filePath).map((artifact) => artifact.finding);
}

// ── Directory ingest ──

const CRASH_EXTENSIONS = new Set([".txt", ".log", ".report", ".crash"]);
const REPRO_EXTENSIONS = new Set([".c", ".syz"]);

export function ingestArtifactsFromDirectory(dirPath: string): KernelCrashArtifact[] {
  const entries = readdirSync(dirPath);

  // Collect crash files and reproducer files
  const crashFiles: string[] = [];
  const reproMap = new Map<string, { path: string; content: string; lang: "c" | "syz" | "bash" }>();

  for (const entry of entries) {
    const fullPath = join(dirPath, entry);
    try {
      if (!statSync(fullPath).isFile()) continue;
    } catch {
      continue;
    }

    const ext = entry.substring(entry.lastIndexOf(".")).toLowerCase();
    const prefix = entry.substring(0, entry.lastIndexOf("."));

    if (CRASH_EXTENSIONS.has(ext)) {
      crashFiles.push(fullPath);
    } else if (REPRO_EXTENSIONS.has(ext)) {
      const lang = ext === ".c" ? "c" as const : "syz" as const;
      reproMap.set(prefix, { path: fullPath, content: readFileSync(fullPath, "utf-8"), lang });
    }
  }

  // Parse crash files, attach reproducers by filename prefix
  const artifacts: KernelCrashArtifact[] = [];
  const seen = new Set<string>();

  for (const crashFile of crashFiles) {
    const crashBasename = basename(crashFile);
    const crashPrefix = crashBasename.substring(0, crashBasename.lastIndexOf("."));

    const text = readFileSync(crashFile, "utf-8");
    const segments = splitReports(text);

    for (const segment of segments) {
      if (!/BUG:|UBSAN:|Kernel panic|Oops:|general protection|rcu:.*stall|WARNING:.*lock|Call Trace:/i.test(segment)) {
        continue;
      }
      const report = parseCrashReport(segment);
      if (report.crashType === "unknown") continue;

      // Attach reproducer if found with matching prefix
      const repro = reproMap.get(crashPrefix);
      if (repro) {
        report.reproducer = repro.content;
        report.reproducerLanguage = repro.lang;
      }

      // Dedup by faultingFunction + crashType
      const dedup = `${report.faultingFunction}::${report.crashType}`;
      if (seen.has(dedup)) continue;
      seen.add(dedup);

      artifacts.push({
        sourcePath: crashFile,
        reproducerPath: repro?.path,
        report,
        finding: crashToFinding(report),
      });
    }
  }

  return artifacts;
}

export function ingestDirectory(dirPath: string): Finding[] {
  return ingestArtifactsFromDirectory(dirPath).map((artifact) => artifact.finding);
}

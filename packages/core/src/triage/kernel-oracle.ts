/**
 * Kernel crash verification oracle.
 *
 * Verifies kernel crash reports (KASAN, UBSAN, null-deref, etc.) by:
 *   1. Checking if a reproducer exists and is compilable
 *   2. Running it in a configured kernel VM (QEMU + SSH) when available
 *   3. Comparing the crash output to the original report
 *
 * When no kernel VM environment is available (0SEC_KERNEL_QEMU != "1"), the oracle
 * falls back to static analysis of the reproducer and crash report consistency.
 */

import type { Finding } from "@0sec/shared";
import { runReproducerInKernelVm } from "./kernel-vm-runner.js";

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

/**
 * Minimal crash report shape expected by the oracle.  The canonical
 * CrashReport type lives in the ingest layer — we define a compatible
 * interface here so the oracle can be used standalone without coupling
 * to a specific ingest implementation.
 */
export interface CrashReport {
  /** Raw crash log / dmesg output. */
  raw: string;
  /** Parsed crash type, e.g. "kasan-uaf", "kasan-oob", "null-deref". */
  crashType: string;
  /** Faulting function name extracted from the report. */
  faultingFunction: string;
  /** Parsed kernel stack trace frames. */
  stackFrames: string[];
  /** Optional C reproducer source code. */
  reproducer?: string;
  /** Reproducer language. Raw `.syz` programs require syz-execprog in the guest. */
  reproducerLanguage?: "c" | "syz" | "bash";
  executionAttestationRequest?: KernelExecutionAttestationRequest;
  /** Access type from KASAN reports ("read" | "write"). */
  accessType?: string;
  /** Access size from KASAN reports. */
  accessSize?: number;
  /** Subsystem hint (e.g. "nfs", "tcp", "ext4"). */
  subsystem?: string;
}

export interface KernelOracleResult {
  verified: boolean;
  confidence: number;
  evidence: string;
  reason: string;
  reproduced: boolean;
  crashMatch: boolean;
  originalCrashType?: string;
  reproducedCrashType?: string;
  matchedFunction?: string;
}

export interface ReproducerResult {
  compiled: boolean;
  executed: boolean;
  output: string;
  dmesg: string;
  exitCode: number;
  timedOut: boolean;
  /**
   * KCOV / syz-execprog coverage PCs collected during the run (AIxCC / Shellphish
   * T1 — LLM PoV-gen with real coverage feedback). The deduped, sorted set of
   * program counters the reproducer exercised. Only populated for the syz guest
   * path with a KCOV-enabled kernel + `syz-execprog -cover`; undefined otherwise
   * (C reproducers, no-KCOV kernels). The verify loop diffs this against
   * previously-seen PCs to compute new edges and feed coverage back to the LLM.
   */
  coveragePcs?: string[];
  executionAttestation?: KernelExecutionAttestation;
  executionAttestationPath?: string;
}

export interface KernelExecutionAttestationRequest {
  nonce: string;
  reproducerSha256: string;
  expectedKernelRelease: string;
  kernelImageSha256: string;
  kernelConfigSha256: string;
  dropUid?: number;
  dropGid?: number;
}

export interface KernelExecutionAttestation {
  schemaVersion: 2;
  nonce: string;
  reproducerSha256: string;
  expectedKernelRelease: string;
  observedKernelRelease: string;
  bootId: string;
  kernelImageSha256: string;
  kernelConfigSha256: string;
  realUid: number;
  effectiveUid: number;
  savedUid: number;
  realGid: number;
  effectiveGid: number;
  savedGid: number;
  supplementaryGroups: number[];
  inheritableCapabilities: string;
  permittedCapabilities: string;
  effectiveCapabilities: string;
  ambientCapabilities: string;
  secureBits: number;
  userNamespaceMax: number;
  initialUserNamespace: boolean;
  noNewPrivileges: boolean;
}

export interface CrashSignatureMatch {
  matched: boolean;
  score: number;
  matchedFields: string[];
  mismatchedFields: string[];
}

export interface ConsistencyResult {
  valid: boolean;
  score: number;
  checks: { name: string; passed: boolean; detail: string }[];
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

function notVerifiable(reason: string): KernelOracleResult {
  return {
    verified: false,
    confidence: 0,
    evidence: "",
    reason,
    reproduced: false,
    crashMatch: false,
  };
}

/**
 * Known kernel function prefixes that indicate a plausible symbol name.
 * Used by consistency checks to filter out garbage stack frames.
 */
const KNOWN_PREFIXES = [
  "nfs_", "tcp_", "udp_", "ip_", "ext4_", "btrfs_", "xfs_",
  "sock_", "sk_", "net_", "sctp_", "unix_", "pipe_", "do_",
  "sys_", "__sys_", "ksys_", "vfs_", "__vfs_", "fuse_",
  "kobject_", "kfree", "kmalloc", "kmem_", "slab_",
  "rcu_", "mutex_", "spin_", "raw_spin_", "lock_",
  "schedule", "__schedule", "worker_", "kthread",
  "page_", "__page_", "folio_", "mm_", "mmap_",
  "blk_", "bio_", "dm_", "md_", "raid",
  "usb_", "pci_", "irq_", "softirq",
  "cgroup_", "ns_", "inode_", "dentry_",
  "security_", "selinux_", "apparmor_",
];

/**
 * Map from crash type keywords to expected content in the report.
 */
const CRASH_TYPE_CONTENT: Record<string, RegExp> = {
  // KCSAN data-race — the concurrency-bug signature KASAN never emits. Closes
  // the loop with kcsan-race.ts (parser) + patch-to-poc.ts ("KCSAN: data-race").
  "kcsan-data-race": /KCSAN:\s*data-race|data-race in/i,
  "kasan-oob": /slab-out-of-bounds|global-out-of-bounds|out-of-bounds/i,
  "kasan-stack-oob": /stack-out-of-bounds|stack-buffer-overflow/i,
  "kasan-uaf": /use-after-free/i,
  "kasan-double-free": /double-free/i,
  "kasan-invalid-free": /invalid-free/i,
  "kasan-null": /null-ptr-deref|NULL pointer dereference|unable to handle kernel NULL/i,
  "ubsan": /UBSAN/i,
  "ubsan-shift": /UBSAN.*shift/i,
  "ubsan-overflow": /UBSAN.*overflow/i,
  "ubsan-bounds": /UBSAN.*out-of-bounds|UBSAN.*index/i,
  "ubsan-alignment": /UBSAN.*misalign|UBSAN.*member access/i,
  "general-protection": /general protection fault/i,
};

/**
 * Syscall families relevant to certain subsystems. Used in static
 * analysis to check whether a reproducer plausibly targets the
 * subsystem indicated by the crash report.
 */
const SUBSYSTEM_SYSCALLS: Record<string, RegExp[]> = {
  nfs: [/\bmount\b/, /\bnfs\b/i, /\bsocket\b/, /\bconnect\b/],
  tcp: [/\bsocket\b/, /\bconnect\b/, /\bbind\b/, /\blisten\b/, /\bsend\b/],
  udp: [/\bsocket\b/, /\bsendto\b/, /\brecvfrom\b/],
  ext4: [/\bmount\b/, /\bopen\b/, /\bwrite\b/, /\bfallocate\b/, /\bioctl\b/],
  usb: [/\bioctl\b/, /\bopen\b/, /\bUSBDEVFS\b/i],
  pipe: [/\bpipe\b/, /\bsplice\b/, /\bvmsplice\b/],
  netlink: [/\bsocket\b/, /\bnetlink\b/i, /\bbind\b/, /\bsendmsg\b/],
};

const NOISY_CRASH_FRAMES = [
  /^dump_stack/,
  /^print_/,
  /^kasan_report/,
  /^__kasan_/,
  /^check_slab_allocation$/,
  /^kfree$/,
  /^report_cfi_failure$/,
  /^ubsan_/,
  /^__ubsan_/,
];

function extractFrameFunction(frame: string): string {
  const funcMatch = frame.match(/([a-zA-Z_][\w]*)\+0x/);
  return funcMatch ? funcMatch[1]! : frame.trim();
}

function isNoisyCrashFrame(frame: string): boolean {
  const funcName = extractFrameFunction(frame);
  return NOISY_CRASH_FRAMES.some((pattern) => pattern.test(funcName));
}

function selectRelevantFrames(frames: string[]): string[] {
  const filtered = frames.filter((frame) => !isNoisyCrashFrame(frame));
  return filtered.length > 0 ? filtered : frames;
}

// ────────────────────────────────────────────────────────────────────
// Core functions
// ────────────────────────────────────────────────────────────────────

/**
 * Compile and run the reproducer inside a configured kernel VM.
 *
 * When `0SEC_KERNEL_QEMU=1`, this boots the configured VM assets and
 * executes the reproducer via a host-shared working directory. Otherwise
 * it returns a stub indicating no execution.
 */
export async function compileAndRunReproducer(
  report: CrashReport,
): Promise<ReproducerResult> {
  if (!report.reproducer) {
    return {
      compiled: false,
      executed: false,
      output: "",
      dmesg: "",
      exitCode: -1,
      timedOut: false,
    };
  }

  const useQemu = process.env["0SEC_KERNEL_QEMU"] === "1";

  if (!useQemu) {
    // Dry-run mode — no actual execution
    return {
      compiled: false,
      executed: false,
      output: "[dry-run] 0SEC_KERNEL_QEMU not set, skipping execution",
      dmesg: "",
      exitCode: -1,
      timedOut: false,
    };
  }

  try {
    return await runReproducerInKernelVm(report);
  } catch (error) {
    return {
      compiled: false,
      executed: false,
      output: `[kernel-vm-error] ${error instanceof Error ? error.message : String(error)}`,
      dmesg: "",
      exitCode: 1,
      timedOut: false,
    };
  }
}

/**
 * Run a standalone kernel reproducer without an original crash report to match.
 *
 * This is the Tier 1 path for `0sec ingest --reproducer/--syz`: it answers
 * "did this reproducer trigger a recognizable kernel crash under the VM
 * oracle?" rather than "did it match a previously ingested crash signature?"
 */
export async function verifyStandaloneKernelReproducer(
  crashReport: CrashReport,
): Promise<KernelOracleResult> {
  if (!crashReport.reproducer) {
    return notVerifiable("no reproducer available");
  }

  const reproResult = await compileAndRunReproducer(crashReport);
  if (reproResult.compiled && reproResult.executed) {
    const crashOutput = reproResult.dmesg || reproResult.output;
    const reproducedCrashType = extractCrashType(crashOutput);
    if (reproducedCrashType) {
      return {
        verified: true,
        confidence: 0.8,
        evidence: `standalone reproducer triggered ${reproducedCrashType}`,
        reason: "",
        reproduced: true,
        crashMatch: false,
        originalCrashType: crashReport.crashType,
        reproducedCrashType,
      };
    }

    return {
      verified: false,
      confidence: 0.3,
      evidence: "standalone reproducer executed without a recognized KASAN/UBSAN/oops signature",
      reason: "no recognized kernel crash signature in dmesg",
      reproduced: true,
      crashMatch: false,
      originalCrashType: crashReport.crashType,
    };
  }

  if (!reproResult.compiled && reproResult.exitCode !== -1) {
    return {
      verified: false,
      confidence: 0,
      evidence: `reproducer preparation failed: ${reproResult.output.slice(0, 500)}`,
      reason: crashReport.reproducerLanguage === "syz"
        ? "syz reproducer could not run; guest requires syz-execprog"
        : "reproducer failed to compile",
      reproduced: false,
      crashMatch: false,
      originalCrashType: crashReport.crashType,
    };
  }

  return {
    verified: false,
    confidence: 0,
    evidence: reproResult.output,
    reason: "standalone reproducer was not executed",
    reproduced: false,
    crashMatch: false,
    originalCrashType: crashReport.crashType,
  };
}

/**
 * Compare the original crash report signature against the output from
 * a reproduced crash. Scoring:
 *   - Crash type exact match:      0.3
 *   - Faulting function exact:      0.3  (substring: 0.15)
 *   - Top 3 stack frames:          0.1 each (max 0.3)
 *   - Access type + size:          0.1
 */
export function matchCrashSignature(
  original: CrashReport,
  reproOutput: string,
): CrashSignatureMatch {
  let score = 0;
  const matchedFields: string[] = [];
  const mismatchedFields: string[] = [];

  // ── Crash type ─────────────────────────────────────────────
  const crashTypeNormalized = original.crashType.toLowerCase();
  const reproLower = reproOutput.toLowerCase();

  // Map normalized crash type to patterns we look for in output
  const typePatterns: Record<string, RegExp> = {
    "kcsan-data-race": /kcsan:\s*data-race|data-race in/i,
    "kasan-oob": /kasan.*out-of-bounds|slab-out-of-bounds/i,
    "kasan-uaf": /kasan.*use-after-free|slab-use-after-free/i,
    "kasan-double-free": /kasan.*double-free|kasan.*invalid-free/i,
    "kasan-invalid-free": /kasan.*invalid-free|invalid-free/i,
    "null-deref": /null pointer dereference|kernel null pointer/i,
    "stack-oob": /kasan.*stack-out-of-bounds|stack-buffer-overflow/i,
    "ubsan": /ubsan/i,
    "ubsan-shift": /ubsan.*shift/i,
    "ubsan-overflow": /ubsan.*overflow/i,
    "ubsan-bounds": /ubsan.*out-of-bounds|ubsan.*index/i,
    "ubsan-alignment": /ubsan.*misalign|ubsan.*member access/i,
  };

  const typePattern = typePatterns[crashTypeNormalized];
  if (typePattern && typePattern.test(reproOutput)) {
    score += 0.3;
    matchedFields.push("crashType");
  } else if (reproLower.includes(crashTypeNormalized)) {
    score += 0.3;
    matchedFields.push("crashType");
  } else {
    mismatchedFields.push("crashType");
  }

  // ── Faulting function ──────────────────────────────────────
  if (original.faultingFunction) {
    if (reproOutput.includes(original.faultingFunction)) {
      score += 0.3;
      matchedFields.push("faultingFunction");
    } else {
      // Try substring: strip trailing offset (e.g. "+0x1a/0x30")
      const baseName = original.faultingFunction.replace(/\+0x[\da-f]+\/0x[\da-f]+$/i, "");
      if (baseName && reproOutput.includes(baseName)) {
        score += 0.15;
        matchedFields.push("faultingFunction(substring)");
      } else {
        mismatchedFields.push("faultingFunction");
      }
    }
  }

  // ── Top 3 stack frames ─────────────────────────────────────
  const topFrames = selectRelevantFrames(original.stackFrames).slice(0, 3);
  for (let i = 0; i < topFrames.length; i++) {
    const frame = topFrames[i]!;
    const funcName = extractFrameFunction(frame);
    if (reproOutput.includes(funcName)) {
      score += 0.1;
      matchedFields.push(`stackFrame[${i}]:${funcName}`);
    } else {
      mismatchedFields.push(`stackFrame[${i}]:${funcName}`);
    }
  }

  // ── Access type and size ───────────────────────────────────
  if (original.accessType) {
    const accessPattern = new RegExp(
      `\\b${original.accessType}\\b.*\\bsize\\s+${original.accessSize ?? "\\d+"}\\b`,
      "i",
    );
    if (accessPattern.test(reproOutput)) {
      score += 0.1;
      matchedFields.push("accessType+size");
    } else if (reproLower.includes(original.accessType)) {
      score += 0.05;
      matchedFields.push("accessType(partial)");
    } else {
      mismatchedFields.push("accessType+size");
    }
  }

  return {
    matched: score >= 0.5,
    score: Math.min(1, score),
    matchedFields,
    mismatchedFields,
  };
}

/**
 * Validate the internal consistency of a crash report via static checks.
 */
export function validateCrashReportConsistency(
  report: CrashReport,
): ConsistencyResult {
  const checks: { name: string; passed: boolean; detail: string }[] = [];

  // ── 1. Stack frames look like real kernel functions ────────
  const realFrameCount = report.stackFrames.filter(
    (f) => /\+0x[\da-f]+\/0x[\da-f]+/i.test(f),
  ).length;
  const frameRatio = report.stackFrames.length > 0
    ? realFrameCount / report.stackFrames.length
    : 0;
  checks.push({
    name: "stack_frame_format",
    passed: frameRatio >= 0.5,
    detail: `${realFrameCount}/${report.stackFrames.length} frames have +0x offsets (ratio=${frameRatio.toFixed(2)})`,
  });

  // ── 2. KASAN alloc/free sections for UAF ───────────────────
  const isUaf = /uaf|use-after-free/i.test(report.crashType);
  if (isUaf) {
    const hasAlloc = /allocated by task/i.test(report.raw);
    const hasFree = /freed by task/i.test(report.raw);
    checks.push({
      name: "kasan_alloc_free_sections",
      passed: hasAlloc && hasFree,
      detail: `alloc=${hasAlloc} free=${hasFree}`,
    });
  }

  // ── 3. KASAN OOB format ────────────────────────────────────
  const isOob = /oob|out-of-bounds/i.test(report.crashType);
  if (isOob) {
    const hasAccessSize = /\b(read|write)\s+of\s+size\s+\d+\b/i.test(report.raw);
    const hasAlloc = /allocated by task/i.test(report.raw);
    checks.push({
      name: "kasan_oob_format",
      passed: hasAccessSize && hasAlloc,
      detail: `accessSize=${hasAccessSize} alloc=${hasAlloc}`,
    });
  }

  // ── 4. Access addresses in kernel space ────────────────────
  const addrMatches = report.raw.match(/\b0x([\da-f]{8,16})\b/gi) ?? [];
  const kernelAddrs = addrMatches.filter((a) => {
    const hex = a.replace(/^0x/i, "");
    // x86_64 kernel addresses start with ffff
    return hex.length >= 12 && hex.startsWith("ffff");
  });
  checks.push({
    name: "kernel_space_addresses",
    passed: kernelAddrs.length > 0 || addrMatches.length === 0,
    detail: `${kernelAddrs.length} kernel-space addresses out of ${addrMatches.length} total`,
  });

  // ── 5. Plausible function names ────────────────────────────
  const funcNames = report.stackFrames.map((f) => {
    const m = f.match(/([a-zA-Z_][\w]*)\+0x/);
    return m ? m[1]! : f.trim();
  });
  const plausibleCount = funcNames.filter((name) =>
    KNOWN_PREFIXES.some((prefix) => name.startsWith(prefix)) ||
    /^[a-z_][\w]{2,60}$/i.test(name),
  ).length;
  const plausibleRatio = funcNames.length > 0
    ? plausibleCount / funcNames.length
    : 0;
  checks.push({
    name: "plausible_function_names",
    passed: plausibleRatio >= 0.6,
    detail: `${plausibleCount}/${funcNames.length} names are plausible (ratio=${plausibleRatio.toFixed(2)})`,
  });

  // ── 6. Crash type matches content ─────────────────────────
  const contentPattern = CRASH_TYPE_CONTENT[report.crashType.toLowerCase()];
  if (contentPattern) {
    const matches = contentPattern.test(report.raw);
    checks.push({
      name: "crash_type_content_match",
      passed: matches,
      detail: `crashType="${report.crashType}" content match=${matches}`,
    });
  }

  // ── Score ──────────────────────────────────────────────────
  const passedCount = checks.filter((c) => c.passed).length;
  const score = checks.length > 0 ? passedCount / checks.length : 0;

  return {
    valid: score >= 0.6,
    score,
    checks,
  };
}

/**
 * Perform static analysis of the reproducer against the crash report.
 * Used as a fallback when QEMU execution is unavailable.
 */
function staticAnalyzeReproducer(report: CrashReport): {
  score: number;
  evidence: string[];
} {
  const evidence: string[] = [];
  let score = 0;

  if (!report.reproducer) {
    return { score: 0, evidence: ["no reproducer available"] };
  }

  const src = report.reproducer;

  // Check if reproducer references the faulting function
  if (report.faultingFunction) {
    const baseName = report.faultingFunction.replace(/\+0x[\da-f]+\/0x[\da-f]+$/i, "");
    if (baseName && src.includes(baseName)) {
      score += 0.2;
      evidence.push(`reproducer references faulting function: ${baseName}`);
    }
  }

  // Check if reproducer uses relevant syscalls for the subsystem
  if (report.subsystem) {
    const patterns = SUBSYSTEM_SYSCALLS[report.subsystem.toLowerCase()];
    if (patterns) {
      const matched = patterns.filter((p) => p.test(src));
      if (matched.length > 0) {
        score += 0.2 * Math.min(1, matched.length / patterns.length);
        evidence.push(
          `reproducer uses ${matched.length}/${patterns.length} relevant syscalls for ${report.subsystem}`,
        );
      }
    }
  }

  // Basic compilability check: has main() and includes
  if (/\bint\s+main\s*\(/.test(src) || /\bvoid\s+main\s*\(/.test(src)) {
    score += 0.1;
    evidence.push("reproducer has main() entry point");
  }
  if (/#include\s*</.test(src)) {
    score += 0.05;
    evidence.push("reproducer has system includes");
  }

  // Check for syscall wrappers (syz_* functions indicate syzkaller reproducers)
  if (/\bsyz_/.test(src) || /\bsyscall\s*\(/.test(src)) {
    score += 0.15;
    evidence.push("reproducer uses syscall() or syzkaller wrappers");
  }

  return { score: Math.min(1, score), evidence };
}

// ────────────────────────────────────────────────────────────────────
// Main entry point
// ────────────────────────────────────────────────────────────────────

/**
 * Verify a kernel crash finding by reproducing it or analyzing it statically.
 *
 * Steps:
 *   1. Check if the crash report has a reproducer — bail early if not
 *   2. Validate the crash report's internal consistency
 *   3. Attempt to compile and run the reproducer in a configured kernel VM
 *   4. Compare reproduced output to original report (or do static analysis)
 *   5. Return verdict with confidence
 */
export async function verifyKernelCrash(
  finding: Finding,
  crashReport: CrashReport,
): Promise<KernelOracleResult> {
  // ── 1. Reproducer existence check ─────────────────────────
  if (!crashReport.reproducer) {
    // Even without a reproducer we can validate the report consistency
    const consistency = validateCrashReportConsistency(crashReport);
    if (consistency.valid) {
      return {
        verified: false,
        confidence: consistency.score * 0.3,
        evidence: `report consistency: ${consistency.checks.map((c) => `${c.name}=${c.passed}`).join(", ")}`,
        reason: "no reproducer available — report is internally consistent but unverified",
        reproduced: false,
        crashMatch: false,
        originalCrashType: crashReport.crashType,
      };
    }
    return notVerifiable("no reproducer available");
  }

  // ── 2. Validate crash report consistency ───────────────────
  const consistency = validateCrashReportConsistency(crashReport);

  // ── 3. Attempt compilation and execution ───────────────────
  const reproResult = await compileAndRunReproducer(crashReport);

  // ── 4a. QEMU path: compare crash signatures ───────────────
  if (reproResult.compiled && reproResult.executed) {
    const crashOutput = reproResult.dmesg || reproResult.output;
    const sigMatch = matchCrashSignature(crashReport, crashOutput);

    const confidence = sigMatch.score * 0.7 + consistency.score * 0.3;

    if (sigMatch.matched) {
      return {
        verified: true,
        confidence: Math.min(1, confidence),
        evidence: `crash reproduced: score=${sigMatch.score.toFixed(2)}, matched=[${sigMatch.matchedFields.join(", ")}]`,
        reason: "",
        reproduced: true,
        crashMatch: true,
        originalCrashType: crashReport.crashType,
        reproducedCrashType: extractCrashType(crashOutput),
        matchedFunction: crashReport.faultingFunction,
      };
    }

    // Reproduced but didn't match
    return {
      verified: false,
      confidence: Math.min(0.4, confidence * 0.5),
      evidence: `crash did not match: score=${sigMatch.score.toFixed(2)}, mismatched=[${sigMatch.mismatchedFields.join(", ")}]`,
      reason: `reproducer ran but crash signature mismatch (score=${sigMatch.score.toFixed(2)})`,
      reproduced: true,
      crashMatch: false,
      originalCrashType: crashReport.crashType,
      reproducedCrashType: extractCrashType(crashOutput),
    };
  }

  // ── 4b. Static analysis fallback ──────────────────────────
  const staticResult = staticAnalyzeReproducer(crashReport);
  const staticConfidence = staticResult.score * 0.5 + consistency.score * 0.5;

  if (staticConfidence >= 0.5 && consistency.valid) {
    return {
      verified: false,
      confidence: Math.min(0.6, staticConfidence),
      evidence: [
        `static analysis: ${staticResult.evidence.join("; ")}`,
        `consistency: score=${consistency.score.toFixed(2)}`,
      ].join(" | "),
      reason: "verified via static analysis only (no QEMU execution)",
      reproduced: false,
      crashMatch: false,
      originalCrashType: crashReport.crashType,
    };
  }

  // Compilation failed
  if (reproResult.compiled === false && reproResult.exitCode !== -1) {
    return {
      verified: false,
      confidence: Math.max(0, staticConfidence * 0.3),
      evidence: `compilation failed: ${reproResult.output.slice(0, 500)}`,
      reason: "reproducer failed to compile",
      reproduced: false,
      crashMatch: false,
      originalCrashType: crashReport.crashType,
    };
  }

  return {
    verified: false,
    confidence: Math.max(0, staticConfidence * 0.5),
    evidence: `static analysis: ${staticResult.evidence.join("; ")}`,
    reason: "insufficient evidence from static analysis",
    reproduced: false,
    crashMatch: false,
    originalCrashType: crashReport.crashType,
  };
}

// ────────────────────────────────────────────────────────────────────
// Utilities
// ────────────────────────────────────────────────────────────────────

/**
 * Extract the crash type from raw dmesg/KASAN output.
 */
function extractCrashType(output: string): string | undefined {
  // KCSAN data-race first — it is a distinct sanitizer signature (the race
  // class KASAN is blind to), so a widened data-race is classified correctly.
  if (/KCSAN:\s*data-race|BUG:\s*KCSAN/i.test(output)) {
    return "kcsan-data-race";
  }
  if (/KASAN.*slab-out-of-bounds|KASAN.*out-of-bounds/i.test(output)) {
    return "kasan-oob";
  }
  if (/KASAN.*slab-use-after-free|KASAN.*use-after-free/i.test(output)) {
    return "kasan-uaf";
  }
  if (/KASAN.*double-free/i.test(output)) {
    return "kasan-double-free";
  }
  if (/KASAN.*invalid-free/i.test(output)) {
    return "kasan-invalid-free";
  }
  if (/KASAN.*stack-out-of-bounds/i.test(output)) {
    return "stack-oob";
  }
  if (/NULL pointer dereference|kernel NULL pointer/i.test(output)) {
    return "null-deref";
  }
  if (/UBSAN.*shift/i.test(output)) {
    return "ubsan-shift";
  }
  if (/UBSAN.*overflow/i.test(output)) {
    return "ubsan-overflow";
  }
  if (/UBSAN.*out-of-bounds|UBSAN.*index/i.test(output)) {
    return "ubsan-bounds";
  }
  if (/UBSAN.*misalign|UBSAN.*member access/i.test(output)) {
    return "ubsan-alignment";
  }
  if (/UBSAN/i.test(output)) {
    return "ubsan";
  }
  if (/general protection fault/i.test(output)) {
    return "general-protection";
  }
  return undefined;
}

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { join, basename } from "node:path";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import type {
  ReviewConfig,
  ReviewReport,
  SemgrepFinding,
  Finding,
  ScanConfig,
  ReviewProfile,
} from "@pwnkit/shared";
import type { ScanEvent, ScanListener } from "./scanner.js";
import { reviewAgentPrompt } from "./analysis-prompts.js";
import { runAnalysisAgent } from "./agent-runner.js";
import { features } from "./agent/features.js";
import { runSelectedStaticScan } from "./shared-analysis.js";
import { cppReviewAgentPrompt } from "./review/c-cpp-profile.js";
import { kernelReviewAgentPrompt } from "./review/linux-kernel-profile.js";
import { runKernelVariantHunt } from "./kernel/index.js";
import { enumerateAttackSurfaces, formatAttackSurfaceForPrompt } from "./kernel/index.js";
import { resolveLocalTargetPath } from "./path-resolution.js";
import { formatTargetHistoryForPrompt, searchTargetHistory } from "./intel/index.js";
import type { IntelTargetHistory } from "./intel/index.js";

export interface SourceReviewOptions {
  config: ReviewConfig;
  onEvent?: ScanListener;
}

/**
 * Resolve the repo path: if it's a URL, clone it; if local, use as-is.
 * Returns the absolute path to the repo and whether it was cloned (needs cleanup).
 */
function resolveRepo(
  repo: string,
  emit: ScanListener,
): { repoPath: string; cloned: boolean; tempDir?: string } {
  // Check if it's a git URL (https, ssh, or git protocol)
  const isUrl =
    repo.startsWith("https://") ||
    repo.startsWith("http://") ||
    repo.startsWith("git@") ||
    repo.startsWith("git://");

  if (!isUrl) {
    // Local path
    const absPath = resolveLocalTargetPath(repo);
    if (!existsSync(absPath)) {
      throw new Error(`Repository path not found: ${absPath}`);
    }
    return { repoPath: absPath, cloned: false };
  }

  // Clone the repo
  const tempDir = join(tmpdir(), `pwnkit-review-${randomUUID().slice(0, 8)}`);
  mkdirSync(tempDir, { recursive: true });

  emit({
    type: "stage:start",
    stage: "discovery",
    message: `Cloning ${repo}...`,
  });

  try {
    execFileSync("git", ["clone", "--depth", "1", repo, `${tempDir}/repo`], {
      timeout: 120_000,
      stdio: "pipe",
    });
  } catch (err) {
    rmSync(tempDir, { recursive: true, force: true });
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to clone ${repo}: ${msg}`);
  }

  const repoPath = join(tempDir, "repo");

  emit({
    type: "stage:end",
    stage: "discovery",
    message: `Cloned ${basename(repo.replace(/\.git$/, ""))}`,
  });

  return { repoPath, cloned: true, tempDir };
}

function buildCliReviewPrompt(
  repoPath: string,
  semgrepFindings: SemgrepFinding[],
  profile: ReviewProfile,
  foxguardFindings?: Finding[],
  subsystem?: string,
  hypothesis?: string,
): string {
  const semgrepContext = semgrepFindings.length > 0
    ? semgrepFindings
        .slice(0, 30)
        .map((f, i) => `  ${i + 1}. [${f.severity}] ${f.ruleId} — ${f.path}:${f.startLine}: ${f.message}`)
        .join("\n")
    : "  None.";

  const foxguardContext =
    foxguardFindings && foxguardFindings.length > 0
      ? foxguardFindings
          .slice(0, 30)
          .map((f, i) => `  ${i + 1}. [${f.severity}] ${f.title}\n     ${f.evidence?.analysis ?? f.description}`)
          .join("\n")
      : "";

  if (profile === "linux-kernel") {
    const subsystemDirs = subsystem
      ? subsystem.split(",").map((s) => s.trim()).filter(Boolean)
      : [];
    const subsystemScope = subsystemDirs.length > 0
      ? subsystemDirs.length === 1
        ? `\nSCOPE: Begin analysis in \`${subsystemDirs[0]}\`. You may read files outside this directory when following cross-references, but always return here for your next investigation.\n`
        : `\nSCOPE: Begin analysis in: ${subsystemDirs.map((d) => `\`${d}\``).join(", ")}. You may read files outside these directories when following cross-references, but always return here for your next investigation.\n`
      : "";
    const turnBudget = subsystemDirs.length > 0
      ? "CRITICAL — Turn Budget Discipline: Do NOT call done/finish early. Use your ENTIRE turn budget. Exhaust every entry point, error path, and cross-reference within the scoped subsystem(s). Keep searching until turns run out."
      : "CRITICAL — Turn Budget Discipline: Do NOT call done/finish early. Use your ENTIRE turn budget. The kernel is 30M+ lines — if one subsystem looks clean, move to the next. Rotate through fs/, net/, drivers/, mm/, kernel/, crypto/, io_uring/, sound/, virt/kvm/, block/, security/, arch/. Never conclude \"this kernel is secure.\" Keep searching until turns run out.";
    const hypothesisSection = hypothesis
      ? `\nOPERATOR HYPOTHESIS — PRIMARY RESEARCH DIRECTION: The operator has identified a specific attack surface insight. This is your PRIMARY research direction. Spend at least 60% of your turns investigating this hypothesis before broadening:\n> ${hypothesis}\nStart by understanding the codepath described, then look for violations, missing checks, or unintended interactions along that path.\n`
      : "";
    return `Audit the Linux kernel source tree at ${repoPath} for memory-safety, concurrency, and userspace-boundary vulnerabilities.
${subsystemScope}${hypothesisSection}
${turnBudget}

First confirm this is a kernel tree (look for MAINTAINERS, top-level Kconfig, KERNELRELEASE in Makefile, arch/<name>/). If it's not, refuse and stop.

Map the attack surface: SYSCALL_DEFINE* macros, .unlocked_ioctl/.compat_ioctl handlers, genl_family/netlink_kernel_create, char-device file_operations, eBPF (kernel/bpf/), netfilter hooks (nf_register_net_hook).

Prioritize: missing copy_from_user length validation, signed/unsigned int comparison on user-controlled length, UAF across __free_pages/kfree_skb error paths, refcount races (get_task_struct without matching put_task_struct), TOCTOU on inode->i_*, unsafe_get_user/unsafe_put_user outside a user_access_begin/end block, shared-memory aliasing / Dirty Frag class — any in-place operation on shared/aliased memory without ownership verification: (0) in-place AEAD/cipher on shared skb frag without skb_cow_data/skb_unshare, (a) splice + in-place crypto on non-COW page-cache pages (Copy Fail / CVE-2026-31431), (b) sendfile/splice into io_uring fixed buffers aliasing page cache, (c) vmsplice user-page aliasing with in-kernel pipe consumers, (d) any AF_ALG algorithm type (skcipher/hash/rng/aead/akcipher) operating in-place on spliced pages, (e) generic writes to struct page * without page_count/PagePrivate ownership check.

Validation: every finding must point to either a syzkaller-style program (.syz) or a C reproducer using syscall(SYS_*, ...). NOT libFuzzer — kernel state isn't reachable from a libFuzzer harness. Static-only findings flagged confidence: 0.4 hypothesis: true (until verification phase #271 lands). Do NOT compile the kernel from this loop.

Tag findings with the SUBSYSTEM_PATTERNS taxonomy (fs/nfsd, fs/ext4, net/tcp, net/netfilter, drivers/usb, mm, kernel/sched, etc.) so reports line up with kernel-crash ingest.

The static scanner already found these leads:
${semgrepContext}
${foxguardContext ? `\nHigh-priority leads from foxguard variant-hunt (investigate FIRST):\n${foxguardContext}` : ""}

For EACH finding output a block in this exact format:

---FINDING---
title: <clear title>
severity: <critical|high|medium|low|info>
category: <use-after-free|race-condition|integer-overflow|stack-buffer-overflow|heap-overflow|null-pointer-deref|type-confusion|double-free|other>
subsystem: <one of fs/nfsd, fs/ext4, fs/btrfs, fs/xfs, net/tcp, net/udp, net/sctp, net/ip, net/netfilter, drivers/bluetooth, net/wireless, drivers/usb, drivers/gpu, sound, virt/kvm, io_uring, net/core, block, mm, kernel/sched, kernel/cgroup, security, crypto, unknown>
description: <what the bug is, the trigger sequence (syscall-by-syscall), primitive (read/write/both), attacker control bounds, severity reasoning>
file: <path/to/file.c:lineNumber>
hypothesis: <true|false>
confidence: <0.0-1.0; 0.4 for static-only>
reproducer_shape: <syz|c-syscall|none>
reproducer: <syz program, C-syscall snippet, or "static-only — see hypothesis flag">
---END---

Output as many blocks as needed. Severity reflects the primitive (LPE potential vs info-leak vs DoS), not patch difficulty.`;
  }

  if (profile === "c-library") {
    const cLibHypothesisSection = hypothesis
      ? `\nOPERATOR HYPOTHESIS — PRIMARY RESEARCH DIRECTION: The operator has identified a specific attack surface insight. This is your PRIMARY research direction. Spend at least 60% of your turns investigating this hypothesis before broadening:\n> ${hypothesis}\nStart by understanding the codepath described, then look for violations, missing checks, or unintended interactions along that path.\n`
      : "";
    return `Audit the C/C++ source tree at ${repoPath} for memory-safety and integer-arithmetic vulnerabilities.
${cLibHypothesisSection}
Use the tiered harness discipline: tier-1 single-function libFuzzer harness first (compile with \`clang -fsanitize=address,undefined,fuzzer\`), escalate to tier-2 multi-component harness only when reachability requires it, tier-3 QEMU only for kernel/daemon context. Every finding must be backed by a sanitizer log from a harness that actually trips — static reasoning alone is a hypothesis, not a finding.

Prioritize: integer overflow on allocation paths (\`malloc(count * size)\`), signed/unsigned conversion at memcpy length args, off-by-one parser bounds checks, use-after-free across error paths, format-string sinks, integer-width transitions across function boundaries.

The static scanner already found these leads:
${semgrepContext}

For EACH confirmed vulnerability, output a block in this exact format:

---FINDING---
title: <clear title>
severity: <critical|high|medium|low|info>
category: <integer-overflow|integer-truncation|out-of-bounds-read|out-of-bounds-write|use-after-free|double-free|format-string|toctou|null-deref|uninitialized-memory|other>
description: <what the bug is, the trigger, the primitive (read/write/both), bounds of attacker control, severity reasoning>
file: <path/to/file.c:lineNumber>
harness: <absolute path to the tier-1 harness that triggers it>
sanitizer_log: <relevant ASan/UBSan output>
tier: <1|2|3>
---END---

Output as many ---FINDING--- blocks as needed. Severity reflects the primitive, not the patch difficulty.`;
  }

  const defaultHypothesisSection = hypothesis
    ? `\nOPERATOR HYPOTHESIS — PRIMARY RESEARCH DIRECTION: The operator has identified a specific attack surface insight. This is your PRIMARY research direction. Spend at least 60% of your turns investigating this hypothesis before broadening:\n> ${hypothesis}\nStart by understanding the codepath described, then look for violations, missing checks, or unintended interactions along that path.\n`
    : "";
  return `Audit the npm package at ${repoPath}.
${defaultHypothesisSection}
Read the source code, look for: prototype pollution, ReDoS, path traversal, injection, unsafe deserialization, missing validation. Map data flow from untrusted input to sensitive operations. Report any security findings with severity and PoC suggestions.

The static scanner already found these leads:
${semgrepContext}

For EACH confirmed vulnerability, output a block in this exact format:

---FINDING---
title: <clear title>
severity: <critical|high|medium|low|info>
category: <prototype-pollution|redos|path-traversal|command-injection|code-injection|unsafe-deserialization|ssrf|information-disclosure|missing-validation|other>
description: <detailed description of the vulnerability, how to exploit it, and suggested PoC>
file: <path/to/file.js:lineNumber>
---END---

Output as many ---FINDING--- blocks as needed. Be precise and honest about severity.`;
}

/**
 * Run an AI agent to perform deep source code review.
 *
 * Delegates to the unified runAnalysisAgent with review-specific prompts.
 */
async function runReviewAgent(
  repoPath: string,
  semgrepFindings: SemgrepFinding[],
  foxguardFindings: Finding[],
  db: any,
  scanId: string,
  config: ReviewConfig,
  emit: ScanListener,
): Promise<{ findings: Finding[]; usage?: { inputTokens: number; outputTokens: number }; estimatedCostUsd?: number }> {
  const profile = config.profile ?? "default";

  // Pre-scan attack surface enumeration for kernel reviews (pwnkit#471).
  let attackSurfaceContext: string | undefined;
  if (profile === "linux-kernel") {
    try {
      const enumResult = enumerateAttackSurfaces({
        tree: repoPath,
        subsystem: config.subsystem,
      });
      attackSurfaceContext = formatAttackSurfaceForPrompt(enumResult);
      if (enumResult.surfaces.length > 0) {
        emit({
          type: "stage:start",
          stage: "discovery",
          message: `Enumerated ${enumResult.surfaces.filter((s) => s.compiledIn).length}/${enumResult.surfaces.length} known attack surfaces (source: ${enumResult.configSource})`,
        });
      }
    } catch {
      // Non-fatal; the review agent can still run without this context.
    }
  }

  const baseAgentSystemPrompt =
    profile === "linux-kernel"
      ? kernelReviewAgentPrompt(repoPath, semgrepFindings, foxguardFindings, config.subsystem, config.hypothesis, attackSurfaceContext)
      : profile === "c-library"
      ? cppReviewAgentPrompt(repoPath, semgrepFindings, config.hypothesis)
      : reviewAgentPrompt(repoPath, semgrepFindings, undefined, false, config.hypothesis);
  const cliSystemPrompt =
    profile === "linux-kernel"
      ? "You are a security researcher performing an authorized review of a Linux kernel source tree. Confirm the tree is actually a kernel tree before doing anything. Findings must be grounded at file:line and accompanied by a syzkaller-style or C-syscall reproducer shape — libFuzzer harnesses don't apply. Static-only findings are confidence 0.4 hypotheses until the kernel oracle (#271) verifies them. Do NOT compile or boot the kernel from this loop."
      : profile === "c-library"
      ? "You are a security researcher performing an authorized review of a C/C++ source tree for memory-safety and arithmetic vulnerabilities. Validate every finding by execution under ASan/UBSan — a static-analysis-only finding is a hypothesis, not a finding."
      : "You are a security researcher performing an authorized source code review. Be thorough and precise. Only report real, exploitable vulnerabilities.";
  const targetHistoryBlock = await buildTargetHistoryPreseedBlock(repoPath, emit);
  const agentSystemPrompt = appendPromptBlock(baseAgentSystemPrompt, targetHistoryBlock);
  const cliPrompt = appendPromptBlock(buildCliReviewPrompt(repoPath, semgrepFindings, profile, foxguardFindings, config.subsystem, config.hypothesis), targetHistoryBlock);

  return runAnalysisAgent({
    role: "review",
    scopePath: repoPath,
    target: `repo:${repoPath}`,
    scanId,
    config,
    db,
    emit,
    cliPrompt,
    agentSystemPrompt,
    cliSystemPrompt,
  });
}

type TargetHistorySearchFn = (
  input: { repoPath: string; limit: number; ttlMs: number },
  opts: { timeoutMs: number },
) => Promise<IntelTargetHistory>;

export async function buildTargetHistoryPreseedBlock(
  repoPath: string,
  emit: ScanListener,
  searchFn: TargetHistorySearchFn = searchTargetHistory,
): Promise<string> {
  if (!features.targetHistoryPreseed) {
    emit({
      type: "stage:start",
      stage: "discovery",
      message: "Target-history preflight skipped by feature flag",
    });
    return "";
  }
  try {
    const history = await searchFn(
      { repoPath, limit: 8, ttlMs: 24 * 60 * 60 * 1000 },
      { timeoutMs: 6_000 },
    );
    const block = formatTargetHistoryForPrompt(history);
    emit({
      type: "stage:start",
      stage: "discovery",
      message: block
        ? `Target-history preflight: ${history.summary.advisoryCount} advisories, ${history.summary.playbookCount} playbooks`
        : "Target-history preflight: no prior advisories matched",
    });
    return block ?? "";
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    emit({
      type: "stage:start",
      stage: "discovery",
      message: `Target-history preflight unavailable: ${reason}`,
    });
    return "";
  }
}

function appendPromptBlock(prompt: string, block: string): string {
  return block ? `${prompt}\n\n${block}` : prompt;
}

/**
 * Main entry point: deep source code review of a repository.
 *
 * Pipeline:
 * 1. Clone repo (if URL) or resolve local path
 * 2. Run semgrep with security rules
 * 3. AI agent performs deep source code review
 * 4. Generate report with severity and PoC suggestions
 * 5. Persist to pwnkit DB
 */
export async function sourceReview(
  opts: SourceReviewOptions,
): Promise<ReviewReport & { usage?: { inputTokens: number; outputTokens: number }; estimatedCostUsd?: number }> {
  const { config, onEvent } = opts;
  const emit: ScanListener = onEvent ?? (() => {});
  const startTime = Date.now();

  // Step 1: Resolve repo
  const { repoPath, cloned, tempDir } = resolveRepo(config.repo, emit);

  // Initialize DB and create scan record
  const db = await (async () => { try { const { pwnkitDB } = await import("@pwnkit/db"); return new pwnkitDB(config.dbPath); } catch { return null as any; } })() as any;
  const scanConfig: ScanConfig = {
    target: `repo:${config.repo}`,
    depth: config.depth,
    format: config.format,
    runtime: config.runtime ?? "api",
    mode: "deep",
  };
  const scanId = db?.createScan(scanConfig) ?? "no-db";

  try {
    // Step 2: static scanner scan — scoped to subsystem when set (pwnkit#466)
    const subsystemPaths =
      (config.profile ?? "default") === "linux-kernel" && config.subsystem
        ? config.subsystem.split(",").map((s) => s.trim()).filter(Boolean).map((s) => join(repoPath, s))
        : undefined;
    const semgrepFindings = runSelectedStaticScan(repoPath, emit, subsystemPaths ? { paths: subsystemPaths } : undefined);

    // Step 2b: foxguard variant-hunt (linux-kernel profile only)
    let foxguardFindings: Finding[] = [];
    if ((config.profile ?? "default") === "linux-kernel") {
      try {
        emit({
          type: "stage:start",
          stage: "discovery",
          message: "Running foxguard kernel variant-hunt for seed findings...",
        });
        const variantReport = await runKernelVariantHunt({ tree: repoPath });
        foxguardFindings = variantReport.findings;
        emit({
          type: "stage:end",
          stage: "discovery",
          message: `Foxguard variant-hunt: ${foxguardFindings.length} candidate findings`,
        });
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        emit({
          type: "stage:start",
          stage: "discovery",
          message: `Foxguard variant-hunt unavailable: ${reason}`,
        });
      }
    }

    // Log operator hypothesis for post-hoc analysis (#467)
    if (config.hypothesis) {
      emit({
        type: "stage:start",
        stage: "discovery",
        message: `Operator hypothesis seeded: ${config.hypothesis.slice(0, 200)}`,
      });
    }

    // Step 3: AI agent review
    const agentResult = await runReviewAgent(
      repoPath,
      semgrepFindings,
      foxguardFindings,
      db,
      scanId,
      config,
      emit,
    );
    const findings = agentResult.findings;

    // Step 4: Build report
    const durationMs = Date.now() - startTime;
    const summary = {
      totalAttacks: semgrepFindings.length,
      totalFindings: findings.length,
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      info: findings.filter((f) => f.severity === "info").length,
    };

    db?.completeScan(scanId, summary);

    emit({
      type: "stage:end",
      stage: "report",
      message: `Review complete: ${summary.totalFindings} findings (${summary.critical} critical, ${summary.high} high)`,
    });

    return {
      repo: config.repo,
      startedAt: new Date(startTime).toISOString(),
      completedAt: new Date().toISOString(),
      durationMs,
      semgrepFindings: semgrepFindings.length,
      summary,
      findings,
      usage: agentResult.usage,
      estimatedCostUsd: agentResult.estimatedCostUsd,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    db?.failScan(scanId, msg);
    throw err;
  } finally {
    db?.close();
    // Clean up cloned repos
    if (cloned && tempDir) {
      try {
        rmSync(tempDir, { recursive: true, force: true });
      } catch {
        // ignore
      }
    }
  }
}

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { join, basename } from "node:path";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { cloneGitRepo } from "./repo-clone.js";
import type {
  ReviewConfig,
  ReviewReport,
  SemgrepFinding,
  Finding,
  ScanConfig,
  ReviewProfile,
  ReviewAnchor,
} from "@0sec/shared";
import type { ScanEvent, ScanListener } from "./scanner.js";
import { reviewAgentPrompt } from "./analysis-prompts.js";
import { runAnalysisAgent } from "./agent-runner.js";
import { features } from "./agent/features.js";
import { runSelectedStaticScan } from "./shared-analysis.js";
import { cppReviewAgentPrompt } from "./review/c-cpp-profile.js";
import { kernelReviewAgentPrompt } from "./review/linux-kernel-profile.js";
import { xnuKernelReviewAgentPrompt } from "./review/xnu-kernel-profile.js";
import { xnuReReviewAgentPrompt } from "./review/xnu-re-profile.js";
import {
  runKernelVariantHunt,
  huntIncompleteFixSiblings,
  incompleteFixLeadToFinding,
  scanCrossSubsystemFlows,
  formatCrossSubsystemFlowsForPrompt,
  mineFixCommits,
} from "./kernel/index.js";
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
  const tempDir = join(tmpdir(), `0sec-review-${randomUUID().slice(0, 8)}`);
  mkdirSync(tempDir, { recursive: true });

  emit({
    type: "stage:start",
    stage: "discovery",
    message: `Cloning ${repo}...`,
  });

  try {
    // Parses an optional `<url>.git@<ref>` version suffix (kernel/source
    // targets) and clones the pinned ref, not the default branch.
    cloneGitRepo(repo, `${tempDir}/repo`);
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

export function buildCliReviewPrompt(
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

Step 2a — pick a target PRIMITIVE first, then reason BACKWARD. Before free-reading, decide what you are hunting: a page-cache write, a controlled indirect call (ops->/work_struct->func/->release fn-ptr), a refcount underflow, or an arbitrary write. Then reason backward from the primitive to its sink, the data flow that reaches it, and the UNPRIVILEGED syscall/ioctl/netlink/socket op that starts that flow. Prefer write / controlled-indirect-call primitives over read-only leaks. PRIVILEGE IS LOAD-BEARING — a chain behind CAP_SYS_ADMIN or a root-only node is NOT a finding; verify unprivileged reachability (optionally unshare(CLONE_NEWUSER)) — the keyctl/AF_ALG lesson — and state the privilege precondition for every finding.

Prioritize: missing copy_from_user length validation, signed/unsigned int comparison on user-controlled length, UAF across __free_pages/kfree_skb error paths, refcount races (get_task_struct without matching put_task_struct), TOCTOU on inode->i_*, unsafe_get_user/unsafe_put_user outside a user_access_begin/end block, shared-memory aliasing / Dirty Frag class — any in-place operation on shared/aliased memory without ownership verification: (0) in-place AEAD/cipher on shared skb frag without skb_cow_data/skb_unshare, (a) splice + in-place crypto on non-COW page-cache pages (Copy Fail / CVE-2026-31431), (b) sendfile/splice into io_uring fixed buffers aliasing page cache, (c) vmsplice user-page aliasing with in-kernel pipe consumers, (d) any AF_ALG algorithm type (skcipher/hash/rng/aead/akcipher) operating in-place on spliced pages, (e) generic writes to struct page * without page_count/PagePrivate ownership check.

Step 2b — concrete hunt recipes (highest-yield classes):
(a) Page-cache provenance / zero-copy ingress (Copy Fail; CVE-2026-43284, CVE-2026-46300, CVE-2026-31431): start at a zero-copy ingress API (splice / MSG_SPLICE_PAGES / vmsplice / sendfile / AF_ALG algif_* recvmsg/sendmsg), follow page refs forward to any in-place STORE on an sg/scatterlist entry or skb frag WITHOUT a COW. Audit the SKBFL_SHARED_FRAG set-vs-checked asymmetry (set sites vs skb_has_shared_frag/skb->data_len check sites), skb_cow_data/skb_unshare COW-skip fast paths (can the fast path be entered with a shared frag?), and req->src == req->dst in-place crypto on a page-cache-backed source SGL.
(b) Release-path uncancelled-work UAF / controlled indirect call (the meson-vdec / seq_midi shape; mtk-jpeg / media release-work family): an object owning a work_struct/delayed_work/timer_list/tasklet/ops fn-ptr is freed in a ->release/->remove/->disconnect/->close path or error label WITHOUT a preceding cancel_work_sync/cancel_delayed_work_sync/del_timer_sync/tasklet_kill — the queued work fires after the free → controlled indirect call. Richest in drivers/media, sound/, drivers/usb; cancel_*_work_sync → disable_*_work_sync re-queue is the same UAF.
(c) Write-before-validate in crypto/verify paths: in AEAD/MAC/signature verify (crypto_aead_decrypt, *_verify, ESP/IPsec input, fs-verity, dm-verity, module-sig, rxrpc/Kerberos), check whether plaintext/output is written to a caller-visible buffer or committed to page cache/skb BEFORE the tag/signature is verified (crypto_memneq/memcmp). Decrypt-then-write-before-check = unverified-plaintext write primitive + oracle. The fix marker is the verify gating the write.

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

  if (profile === "xnu-kernel") {
    const subsystemDirs = subsystem
      ? subsystem.split(",").map((s) => s.trim()).filter(Boolean)
      : [];
    const subsystemScope = subsystemDirs.length > 0
      ? `\nSCOPE: Begin analysis in: ${subsystemDirs.map((d) => `\`${d}\``).join(", ")}. You may read files outside these directories when following cross-references, but always return here for your next investigation.\n`
      : "";
    const turnBudget = subsystemDirs.length > 0
      ? "CRITICAL — Turn Budget Discipline: Do NOT call done/finish early. Use your ENTIRE turn budget. Exhaust every entry point, error path, and cross-reference within the scoped subsystem(s). Keep searching until turns run out."
      : "CRITICAL — Turn Budget Discipline: Do NOT call done/finish early. Use your ENTIRE turn budget. If one subsystem looks clean, move to the next. Rotate through iokit/, osfmk/ipc/, osfmk/vm/, osfmk/kern/, bsd/kern/, bsd/net/, bsd/vfs/, bsd/dev/, libkern/, security/. Never conclude \"this kernel is secure.\" Keep searching until turns run out.";
    const hypothesisSection = hypothesis
      ? `\nOPERATOR HYPOTHESIS — PRIMARY RESEARCH DIRECTION: The operator has identified a specific attack surface insight. This is your PRIMARY research direction. Spend at least 60% of your turns investigating this hypothesis before broadening:\n> ${hypothesis}\nStart by understanding the codepath described, then look for violations, missing checks, or unintended interactions along that path.\n`
      : "";
    return `Audit the Apple XNU (macOS/iOS) kernel source tree at ${repoPath} for memory-safety, concurrency, and userspace-boundary vulnerabilities. XNU is published open source by Apple; this is an authorized review for Apple Security Bounty / coordinated disclosure.
${subsystemScope}${hypothesisSection}
${turnBudget}

First confirm this is an XNU tree (look for osfmk/, bsd/, iokit/, libkern/, pexpert/). If it's not, refuse and stop. Note the XNU version (config/MasterVersion, README.md, or Makefile) — it tells you which fixes should already be present.

Map the attack surface: IOKit user clients (externalMethod / getTargetAndMethodForIndex / IOExternalMethodDispatch, reached via IOConnectCallMethod), Mach traps (mach_trap_table in osfmk/kern/syscall_sw.c), MIG routines (.defs server stubs, the is_io_* IOKit family), BSD syscalls (copyin/copyout in bsd/kern/), cdevsw .d_ioctl handlers (bsd/dev/), sysctl handlers, and Mach VM (vm_user.c: vm_allocate/vm_copy/vm_remap/mach_make_memory_entry).

Prioritize: IOKit externalMethod selector/count confusion (selector indexes the method table without a bounds check → OOB function-pointer call; scalarInputCount/structureInputSize not validated against the dispatch entry), copyin length not bounded against the kalloc/IOMalloc destination, copyout of uninitialized kernel struct (infoleak), integer overflow in kalloc/IOMalloc(count*size), Mach port refcount imbalance (ip_release skipped or doubled on an error path → leak/UAF), MIG/mach_msg OOL descriptor type/size confusion, Mach VM aliasing (vm_map_copy reuse, named-entry size/prot confusion), OSDynamicCast result used without NULL check (type confusion).

Validation: every finding must point to a C reproducer SHAPE — IOKit: IOServiceOpen + IOConnectCallMethod(conn, selector, scalarIn, scalarInCnt, structIn, structInSize, ...); Mach: a mach_msg / MIG sequence; BSD: syscall()/ioctl()/sysctlbyname(). NOT libFuzzer — kernel state isn't reachable from a libFuzzer harness. State the privilege required (app-sandbox/unprivileged reach = highest value; root/entitlement/SIP-off = lower). Static-only findings flagged confidence: 0.4 hypothesis: true — there is no in-loop XNU oracle. Do NOT compile XNU or boot QEMU from this loop.

Tag findings with an XNU subsystem label: iokit/userclient, iokit/driver, osfmk/ipc, osfmk/vm, osfmk/kern, bsd/kern, bsd/vfs, bsd/net, bsd/dev, libkern, security, pexpert, or unknown.

The static scanner already found these leads:
${semgrepContext}

For EACH finding output a block in this exact format:

---FINDING---
title: <clear title>
severity: <critical|high|medium|low|info>
category: <use-after-free|race-condition|integer-overflow|stack-buffer-overflow|heap-overflow|null-pointer-deref|type-confusion|double-free|other>
subsystem: <iokit/userclient, iokit/driver, osfmk/ipc, osfmk/vm, osfmk/kern, bsd/kern, bsd/vfs, bsd/net, bsd/dev, libkern, security, pexpert, unknown>
description: <what the bug is, the trigger sequence (IOConnectCall*/mach_msg/syscall, step by step), primitive (read/write/both), attacker control bounds, privilege required, severity reasoning>
file: <path/to/file.c:lineNumber>
hypothesis: <true|false>
confidence: <0.0-1.0; 0.4 for static-only>
reproducer_shape: <iokit-c|mach-msg|bsd-syscall|none>
reproducer: <C reproducer snippet, or "static-only — see hypothesis flag">
---END---

Output as many blocks as needed. Severity reflects the primitive and the privilege gap crossed (app sandbox → kernel write = critical), not patch difficulty.`;
  }

  if (profile === "xnu-re") {
    const xnuReHypothesis = hypothesis
      ? `\nOPERATOR HYPOTHESIS — PRIMARY RESEARCH DIRECTION: spend at least 60% of your turns here first:\n> ${hypothesis}\n`
      : "";
    return `Review the DECOMPILED Apple kext pseudo-C in ${repoPath} (r2ghidra output, extracted from a kernelcache) for memory-safety and userspace-boundary vulnerabilities. Authorized Apple Security Bounty research.
${xnuReHypothesis}
First confirm this is decompiled output (fcn.0x.../demangled C++ names, func_0x... calls, a *.manifest.txt of symbols). If it's normal C source, refuse and say to use xnu-kernel/c-library. Read the *.manifest.txt first — it lists the externalMethod/dispatch/copyin symbols, your entry points.

Reading decompiled code WITHOUT hallucinating (critical): the input is type-less. \`*(arg+0x20/0x28/0x38/0x40)\` on an IOKit dispatch handler maps to IOExternalMethodArguments fields scalarInput/scalarInputCount/structureInput/structureInputSize — map offsets to fields and SAY which mapping you used. \`unaff_RDI\`=this, \`unaff_RSI\`=first arg. \`func_0x...\`=unresolved call (UNKNOWN, not proof of anything). \`UNINIT\`=a stripped debug poison constant, not a sentinel. Dispatch tables (sMethods) and the COUNT literal in dispatchExternalMethod(table, selector, COUNT) ARE trustworthy symbols.

Hunt (highest LPE value first): IOKit selector/count bugs (selector indexed into sMethods without a bound vs the COUNT literal → OOB call); per-method scalarInputCount/structureInputSize not validated before use; copyin/IOMemoryDescriptor length unbounded vs the IOMalloc/kalloc destination; integer overflow in IOMalloc(count*size); OSDynamicCast result used without NULL check.

Grounding gate: state the offset→field mapping; cite the real COUNT literal + the sMethods table for count bugs; if safety hinges on an unresolved func_0x..., mark hypothesis:true. Decompiled-only findings cap at confidence 0.5 and need binary re-verification. If you cannot ground it, do NOT report it — an honest "dispatch correctly bounded (0x13 matches sMethods)" negative is valuable.

Static leads:
${semgrepContext}

For EACH grounded finding output a block:

---FINDING---
title: <clear title>
severity: <critical|high|medium|low|info>
category: <out-of-bounds-read|out-of-bounds-write|integer-overflow|use-after-free|type-confusion|null-pointer-deref|double-free|other>
description: <bug, trigger (IOConnectCall* selector/counts step by step), primitive, privilege, the offset→field mapping used, confidence (<=0.5 decompiled-only)>
file: <decompiled-file: function/address>
hypothesis: <true|false>
confidence: <0.0-0.5>
reproducer: <IOConnectCallMethod shape, or "static-decompiled — needs binary re-verify">
---END---

Output as many blocks as needed. NEVER assert a finding the decompiled artifact cannot ground.`;
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
  crossSubsystemContext?: string,
): Promise<{ findings: Finding[]; usage?: { inputTokens: number; outputTokens: number }; estimatedCostUsd?: number }> {
  const profile = config.profile ?? "default";

  // Pre-scan attack surface enumeration for kernel reviews (0sec#471).
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
    // Cross-subsystem data-flow context (0sec#469). Computed in the seed
    // block and threaded in here so it rides the same kernel prompt-context
    // channel as the attack-surface block.
    if (crossSubsystemContext) {
      attackSurfaceContext = attackSurfaceContext
        ? `${attackSurfaceContext}\n\n${crossSubsystemContext}`
        : crossSubsystemContext;
    }
  }

  const baseAgentSystemPrompt =
    profile === "linux-kernel"
      ? kernelReviewAgentPrompt(repoPath, semgrepFindings, foxguardFindings, config.subsystem, config.hypothesis, attackSurfaceContext, config.anchors)
      : profile === "xnu-kernel"
      ? xnuKernelReviewAgentPrompt(repoPath, semgrepFindings, foxguardFindings, config.subsystem, config.hypothesis)
      : profile === "xnu-re"
      ? xnuReReviewAgentPrompt(repoPath, semgrepFindings, config.subsystem, config.hypothesis)
      : profile === "c-library"
      ? cppReviewAgentPrompt(repoPath, semgrepFindings, config.hypothesis)
      : reviewAgentPrompt(repoPath, semgrepFindings, undefined, false, config.hypothesis, config.conversation);
  const cliSystemPrompt =
    profile === "linux-kernel"
      ? "You are a security researcher performing an authorized review of a Linux kernel source tree. Confirm the tree is actually a kernel tree before doing anything. Findings must be grounded at file:line and accompanied by a syzkaller-style or C-syscall reproducer shape — libFuzzer harnesses don't apply. Static-only findings are confidence 0.4 hypotheses until the kernel oracle (#271) verifies them. Do NOT compile or boot the kernel from this loop."
      : profile === "xnu-kernel"
      ? "You are a security researcher performing an authorized review of an Apple XNU (macOS/iOS) kernel source tree. Confirm the tree is actually an XNU tree (osfmk/, bsd/, iokit/) before doing anything. Findings must be grounded at file:line and accompanied by a C reproducer shape — IOConnectCallMethod for IOKit, mach_msg/MIG for Mach, syscall/ioctl for BSD; libFuzzer harnesses don't apply. State the privilege required (app-sandbox reach is highest value). Static-only findings are confidence 0.4 hypotheses; on-hardware verification (KASAN research kernel) is decoupled. Do NOT compile or boot XNU from this loop."
      : profile === "xnu-re"
      ? "You are a security researcher reviewing DECOMPILED Apple kext pseudo-C (r2ghidra output from a kernelcache). The input is type-less: map offset-soup like *(args+0x40) to IOKit ABI fields (structureInputSize) before reasoning, treat unaff_RDI as this and func_0x... as an unresolved call, and never assert a finding the decompiled artifact cannot ground. Decompiled-only findings cap at confidence 0.5 and must be flagged for binary re-verification (lldb / disassembly of the exact site)."
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
 * 5. Persist to 0sec DB
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
  const db = await (async () => { try { const { osecDB } = await import("@0sec/db"); return new osecDB(config.dbPath); } catch { return null as any; } })() as any;
  const scanConfig: ScanConfig = {
    target: `repo:${config.repo}`,
    depth: config.depth,
    format: config.format,
    runtime: config.runtime ?? "api",
    mode: "deep",
  };
  const scanId = db?.createScan(scanConfig) ?? "no-db";

  try {
    // Step 2: static scanner scan — scoped to subsystem when set (0sec#466)
    const subsystemPaths =
      (config.profile ?? "default") === "linux-kernel" && config.subsystem
        ? config.subsystem.split(",").map((s) => s.trim()).filter(Boolean).map((s) => join(repoPath, s))
        : undefined;
    const semgrepFindings = runSelectedStaticScan(repoPath, emit, subsystemPaths ? { paths: subsystemPaths } : undefined);

    // Step 2b: foxguard variant-hunt (linux-kernel profile only)
    let foxguardFindings: Finding[] = [];
    // Cross-subsystem data-flow prompt block (0sec#469); populated below for
    // the linux-kernel profile and threaded into the review agent prompt.
    let crossSubsystemContext: string | undefined;
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

      // Step 2c: incomplete-fix variant hunt. Mine recent security/`Fixes:`
      // commits and surface untouched same-family siblings (the "encrypt got
      // the guard, decrypt didn't" lead). This is the technique that produced
      // the engine's one real kernel lead when breadth-first auditing was
      // saturated. Read-only git; fails soft on a non-git / shallow tree.
      try {
        const leads = huntIncompleteFixSiblings({
          tree: repoPath,
          ...(config.subsystem
            ? { paths: config.subsystem.split(",").map((s) => s.trim()).filter(Boolean) }
            : {}),
        });
        if (leads.length > 0) {
          foxguardFindings = foxguardFindings.concat(
            leads.map(incompleteFixLeadToFinding),
          );
          emit({
            type: "stage:end",
            stage: "discovery",
            message: `Incomplete-fix hunt: ${leads.length} unfixed-sibling lead(s)`,
          });
        }
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        emit({
          type: "stage:start",
          stage: "discovery",
          message: `Incomplete-fix hunt unavailable: ${reason}`,
        });
      }

      // Step 2d: cross-subsystem data-flow seed (0sec#469). Copy Fail and its
      // siblings live on subsystem boundaries — no single function holds the
      // bug. Map where this tree's code crosses subsystem boundaries (crypto →
      // splice → mm → crypto, etc.) and feed the agent the "trace data across
      // the boundary, find the assumption mismatch" protocol plus the detected
      // crossings. Fails soft to the static (no-scan) flow catalog on error.
      try {
        const flowScan = scanCrossSubsystemFlows({
          tree: repoPath,
          ...(config.subsystem ? { subsystem: config.subsystem } : {}),
        });
        crossSubsystemContext = formatCrossSubsystemFlowsForPrompt(flowScan);
        emit({
          type: "stage:end",
          stage: "discovery",
          message: `Cross-subsystem flow scan: ${flowScan.crossings.length} boundary crossing(s) across ${flowScan.flowSummaries.length} flow direction(s)`,
        });
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        // Still give the agent the static flow catalog (the known-CVE patterns)
        // even when the source scan fails — the catalog needs no tree access.
        crossSubsystemContext = formatCrossSubsystemFlowsForPrompt();
        emit({
          type: "stage:start",
          stage: "discovery",
          message: `Cross-subsystem flow scan unavailable (using static catalog): ${reason}`,
        });
      }

      // Step 2e: auto-anchor from recent fix commits (0sec#469 / Naptime
      // variant framing). When the operator did not supply anchors, derive a
      // bounded set of variant anchors from the most recent security/`Fixes:`
      // commits in the tree so the review auto-populates variant-anchored mode
      // instead of being operator-only. Read-only git; fails soft on a non-git
      // or shallow tree (mineFixCommits returns []).
      if (!config.anchors || config.anchors.length === 0) {
        try {
          const fixCommits = mineFixCommits({
            tree: repoPath,
            limit: 200,
            securityOnly: true,
            ...(config.subsystem
              ? { paths: config.subsystem.split(",").map((s) => s.trim()).filter(Boolean) }
              : {}),
          });
          const autoAnchors: ReviewAnchor[] = fixCommits
            .slice(0, 5)
            .map((c) => {
              const anchor: ReviewAnchor = {
                pattern: `${c.securityKeyword ?? "security fix"}: ${c.subject}`,
                id: c.sha.slice(0, 12),
                ...(c.fixesTag ? { fix: `Fixes: ${c.fixesTag}` } : {}),
              };
              return anchor;
            });
          if (autoAnchors.length > 0) {
            config.anchors = autoAnchors;
            emit({
              type: "stage:end",
              stage: "discovery",
              message: `Auto-anchored variant review on ${autoAnchors.length} recent fix commit(s)`,
            });
          }
        } catch (err) {
          const reason = err instanceof Error ? err.message : String(err);
          emit({
            type: "stage:start",
            stage: "discovery",
            message: `Fix-commit auto-anchor unavailable: ${reason}`,
          });
        }
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
      crossSubsystemContext,
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

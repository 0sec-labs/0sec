import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { kernelReviewAgentPrompt } from "./linux-kernel-profile.js";
import { SUBSYSTEM_PATTERNS } from "../ingest/kernel-crash.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

describe("kernelReviewAgentPrompt", () => {
  it("instructs the agent to confirm the tree is a kernel tree before doing anything", () => {
    const prompt = kernelReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/MAINTAINERS/);
    expect(prompt).toMatch(/Kconfig/);
    expect(prompt).toMatch(/KERNELRELEASE/);
    expect(prompt).toMatch(/arch\/x86\//);
    // Must explicitly tell the agent to refuse if it's not a kernel tree.
    expect(prompt).toMatch(/refuse/i);
  });

  it("enumerates the userspace-boundary attack-surface keywords", () => {
    const prompt = kernelReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/SYSCALL_DEFINE/);
    expect(prompt).toMatch(/ioctl/);
    expect(prompt).toMatch(/genl_family/);
    expect(prompt).toMatch(/netlink_kernel_create/);
    expect(prompt).toMatch(/cdev_init|misc_register/);
    expect(prompt).toMatch(/bpf_func_proto/);
    expect(prompt).toMatch(/nf_register_net_hook/);
  });

  it("lists the kernel-specific hypothesis classes", () => {
    const prompt = kernelReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/copy_from_user/);
    expect(prompt).toMatch(/signed.*unsigned/i);
    expect(prompt).toMatch(/__free_pages|kfree_skb/);
    expect(prompt).toMatch(/get_task_struct/);
    expect(prompt).toMatch(/put_task_struct/);
    expect(prompt).toMatch(/inode->i_/);
    expect(prompt).toMatch(/unsafe_get_user/);
    expect(prompt).toMatch(/unsafe_put_user/);
    expect(prompt).toMatch(/user_access_begin/);
    expect(prompt).toMatch(/user_access_end/);
    // Dirty Frag class — skb cow/share violations.
    expect(prompt).toMatch(/skb_cow_data|skb_unshare/);
    expect(prompt).toMatch(/SKBFL_SHARED_FRAG|skb_has_shared_frag/);
    expect(prompt).toMatch(/Dirty Frag/i);
    // Page-cache write primitive class — Copy Fail / Dirty Pipe / Dirty COW.
    expect(prompt).toMatch(/find_get_page|filemap_get_folio|pagecache_get_page/);
    expect(prompt).toMatch(/pipe_buffer\.page|splice/);
    expect(prompt).toMatch(/page_count|page_ref_count|folio_ref_count/);
    expect(prompt).toMatch(/page_mkwrite|copy_highpage|copy_user_highpage/);
    expect(prompt).toMatch(/Copy Fail|Dirty Pipe|Dirty COW/i);
  });

  it("requires syzkaller- or C-syscall-shaped reproducers, not libFuzzer", () => {
    const prompt = kernelReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).toMatch(/syzkaller|\.syz/);
    expect(prompt).toMatch(/syscall\(SYS_/);
    // The validation discipline section must explicitly reject libFuzzer.
    expect(prompt).toMatch(/NOT.*libFuzzer|libFuzzer.*don't/i);
    // Static-only findings flagged confidence: 0.4.
    expect(prompt).toMatch(/0\.4/);
    expect(prompt).toMatch(/hypothesis/i);
  });

  it("renders every SUBSYSTEM_PATTERNS label so review tags line up with kernel-crash ingest", () => {
    const prompt = kernelReviewAgentPrompt("/tmp/repo", []);
    for (const [, label] of SUBSYSTEM_PATTERNS) {
      expect(prompt).toContain(label);
    }
  });

  it("requires findings to be persisted via save_finding tool calls", () => {
    const prompt = kernelReviewAgentPrompt("/tmp/repo", []);
    // The prompt instructs the agent to use save_finding, not text blocks.
    expect(prompt).toContain("save_finding");
    expect(prompt).toContain("MANDATORY");
    // Key fields the agent must include in save_finding calls.
    expect(prompt).toMatch(/severity:/);
    expect(prompt).toMatch(/category:/);
    expect(prompt).toMatch(/description:/);
  });

  it("interpolates the repo path into the prompt", () => {
    const prompt = kernelReviewAgentPrompt("/srv/linux-6.10", []);
    expect(prompt).toContain("/srv/linux-6.10");
  });

  it("injects operator hypothesis as a primary research direction when provided (#467)", () => {
    const hypothesis = "splice() hands page-cache pages into the crypto subsystem; check if scatterlist page provenance is validated in AF_ALG codepaths";
    const prompt = kernelReviewAgentPrompt("/tmp/repo", [], undefined, undefined, hypothesis);

    // The hypothesis block appears before the default scanning strategy.
    expect(prompt).toContain("OPERATOR HYPOTHESIS");
    expect(prompt).toContain("PRIMARY RESEARCH DIRECTION");
    expect(prompt).toContain(hypothesis);
    // The 60% turn-budget guidance is present.
    expect(prompt).toContain("60%");
  });

  it("does not inject a hypothesis block when no hypothesis is provided (#467)", () => {
    const prompt = kernelReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).not.toContain("OPERATOR HYPOTHESIS");
    expect(prompt).not.toContain("PRIMARY RESEARCH DIRECTION");
  });

  it("combines subsystem scope and hypothesis when both are provided (#467)", () => {
    const hypothesis = "Check whether io_uring fixed buffers can alias with page-cache pages obtained via splice";
    const prompt = kernelReviewAgentPrompt("/tmp/repo", [], undefined, "crypto/", hypothesis);

    expect(prompt).toContain("SCOPE RESTRICTION");
    expect(prompt).toContain("crypto/");
    expect(prompt).toContain("OPERATOR HYPOTHESIS");
    expect(prompt).toContain(hypothesis);
  });

  it("injects attack surface context into the prompt when provided (#471)", () => {
    const attackSurfaceContext = "## Known Attack Surfaces\n\n### 34.0 — io_uring [COMPILED IN]\nPaths: `io_uring/`\n";
    const prompt = kernelReviewAgentPrompt("/tmp/repo", [], undefined, undefined, undefined, attackSurfaceContext);
    expect(prompt).toContain("Known Attack Surfaces");
    expect(prompt).toContain("io_uring");
    expect(prompt).toContain("COMPILED IN");
  });

  it("omits attack surface context when not provided (#471)", () => {
    const prompt = kernelReviewAgentPrompt("/tmp/repo", []);
    expect(prompt).not.toContain("Known Attack Surfaces");
  });

  it("reframes the review around the anchor when one is provided (variant-analysis default)", () => {
    const anchor = {
      id: "CVE-2026-31431",
      pattern: "page-cache write primitive without ownership/COW proof",
      origin: "fs/foo/bar.c:512",
      fix: "folio_test_uptodate + folio_lock gate added before the write",
    };
    const prompt = kernelReviewAgentPrompt(
      "/tmp/repo",
      [],
      undefined,
      undefined,
      undefined,
      undefined,
      [anchor],
    );

    // Naptime/Big Sleep variant framing — anchor on a known bug, hunt variants.
    expect(prompt).toContain("VARIANT-ANCHORED REVIEW");
    expect(prompt).toMatch(/VARIANT.*not open-ended|not open-ended bug discovery/i);
    expect(prompt).toMatch(/variant/i);
    // The anchor's concrete details are surfaced to the agent.
    expect(prompt).toContain("CVE-2026-31431");
    expect(prompt).toContain("page-cache write primitive without ownership/COW proof");
    expect(prompt).toContain("fs/foo/bar.c:512");
    expect(prompt).toContain("folio_test_uptodate + folio_lock gate added before the write");
  });

  it("supports multiple anchors and counts them", () => {
    const prompt = kernelReviewAgentPrompt(
      "/tmp/repo",
      [],
      undefined,
      undefined,
      undefined,
      undefined,
      [
        { pattern: "missing skb_cow_data before in-place AEAD decrypt", id: "ANCHOR-A" },
        { pattern: "signed/unsigned length comparison on user-controlled count", id: "ANCHOR-B" },
      ],
    );
    expect(prompt).toContain("2 known, confirmed bugs");
    expect(prompt).toContain("ANCHOR-A");
    expect(prompt).toContain("ANCHOR-B");
    expect(prompt).toContain("Anchor 1");
    expect(prompt).toContain("Anchor 2");
  });

  it("leaves the unanchored prompt unchanged (default behavior)", () => {
    const baseline = kernelReviewAgentPrompt("/tmp/repo", []);
    expect(baseline).not.toContain("VARIANT-ANCHORED REVIEW");

    // Passing an empty/whitespace-only anchor list must be a no-op.
    const withEmpty = kernelReviewAgentPrompt(
      "/tmp/repo",
      [],
      undefined,
      undefined,
      undefined,
      undefined,
      [],
    );
    expect(withEmpty).toBe(baseline);

    const withBlank = kernelReviewAgentPrompt(
      "/tmp/repo",
      [],
      undefined,
      undefined,
      undefined,
      undefined,
      [{ pattern: "   " }],
    );
    expect(withBlank).toBe(baseline);
    expect(withBlank).not.toContain("VARIANT-ANCHORED REVIEW");
  });

  it("renders semgrep leads when provided", () => {
    const prompt = kernelReviewAgentPrompt("/tmp/repo", [
      {
        ruleId: "kernel.copy-from-user.unbounded",
        message: "copy_from_user with unbounded length",
        severity: "high",
        path: "drivers/char/foo.c",
        startLine: 42,
        endLine: 42,
        snippet: "copy_from_user(buf, ubuf, count);",
      },
    ]);
    expect(prompt).toContain("kernel.copy-from-user.unbounded");
    expect(prompt).toContain("drivers/char/foo.c:42");
  });
});

describe("kernel-uaf-driver fixture", () => {
  it("contains a kfree without a NULL-after-free assignment (the UAF setup)", () => {
    const path = join(
      __dirname,
      "__fixtures__",
      "kernel-uaf-driver",
      "src",
      "uaf_chrdev.c",
    );
    const src = readFileSync(path, "utf-8");
    // The release path frees but does NOT set buffer = NULL.
    expect(src).toMatch(/kfree\(dev->buffer\);/);
    // The intent is documented for future readers — if someone "fixes"
    // the fixture, the linux-kernel review tests stop being meaningful.
    expect(src).toMatch(/BUG: release frees the shared buffer but does NOT set/);
  });

  it("dereferences the freed pointer in the write callback (the UAF use)", () => {
    const path = join(
      __dirname,
      "__fixtures__",
      "kernel-uaf-driver",
      "src",
      "uaf_chrdev.c",
    );
    const src = readFileSync(path, "utf-8");
    // The write callback indexes dev->buffer[i] without re-checking
    // it's still alive after the lock acquire.
    expect(src).toMatch(/dev->buffer\[i\]\s*=\s*tmp\[i\];/);
    expect(src).toMatch(/BUG: no re-check that dev->buffer is non-NULL/);
  });

  it("registers a file_operations struct (so it's reachable from userspace)", () => {
    const path = join(
      __dirname,
      "__fixtures__",
      "kernel-uaf-driver",
      "src",
      "uaf_chrdev.c",
    );
    const src = readFileSync(path, "utf-8");
    expect(src).toMatch(/struct file_operations\s+uaf_fops\s*=/);
    expect(src).toMatch(/\.write\s*=\s*uaf_dev_write/);
    expect(src).toMatch(/\.release\s*=\s*uaf_dev_release/);
  });
});

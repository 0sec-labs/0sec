import { describe, expect, it } from "vitest";

import {
  analyzePatch,
  patchToPocPlan,
  handoffToVerifyInput,
} from "./patch-to-poc.js";
import type { NativeRuntime } from "../runtime/types.js";
import type { Finding } from "@0sec/shared";

/**
 * A fixture upstream fix commit in `git show` shape: a use-after-free fix in
 * AF_RXRPC (one of the older-LTS hunt targets). Synthetic — the sha/diff are
 * illustrative, not a real CVE/commit — but structured exactly like a real
 * kernel UAF fix: a `Fixes:` trailer, a UAF subject, and a unified diff that
 * adds a NULL-out guard inside `rxrpc_recvmsg`.
 */
const RXRPC_UAF_FIX = `commit 0000000000000000000000000000000000000000
Author: Kernel Hacker <khacker@example.org>
Date:   Mon Jun 1 12:00:00 2026 +0000

    rxrpc: Fix use-after-free of rxrpc_call in rxrpc_recvmsg

    The call object could be freed by another thread while recvmsg still
    held a reference-less pointer, leading to a use-after-free read.

    Fixes: 1fc4e0040e84 ("rxrpc: Add a tracepoint for the call timer")
    Signed-off-by: Kernel Hacker <khacker@example.org>

diff --git a/net/rxrpc/recvmsg.c b/net/rxrpc/recvmsg.c
index abcdef123456..654321fedcba 100644
--- a/net/rxrpc/recvmsg.c
+++ b/net/rxrpc/recvmsg.c
@@ -312,6 +312,8 @@ int rxrpc_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
 	rxrpc_put_call(call, rxrpc_call_put_recvmsg);
+	if (ret == -EAGAIN)
+		call = NULL;
 	mutex_unlock(&rx->call_lock);
 	return ret;
 }
`;

describe("kernel/patch-to-poc", () => {
  describe("analyzePatch (stage 1)", () => {
    it("classifies the bug, extracts the Fixes: anchor, and names the sink", () => {
      const a = analyzePatch(RXRPC_UAF_FIX);

      expect(a.bugClass).toBe("use-after-free");
      expect(a.expectedSignature).toBe("KASAN: use-after-free");
      expect(a.fixesTag).toBe("1fc4e0040e84");

      // The touched file + enclosing function are the SINK.
      expect(a.touchedFiles.map((f) => f.path)).toContain("net/rxrpc/recvmsg.c");
      expect(a.primarySink?.file).toBe("net/rxrpc/recvmsg.c");
      expect(a.primarySink?.function).toBe("rxrpc_recvmsg");
      // Single small hunk in one C file → not flagged ambiguous.
      expect(a.ambiguous).toBe(false);
    });

    it("flags a large multi-function patch as ambiguous (large-patch bottleneck)", () => {
      const bigPatch = `commit deadbeef
    mm: fix out-of-bounds in page cache writeback

diff --git a/mm/filemap.c b/mm/filemap.c
@@ -10,1 +10,2 @@ static int copy_one(void)
+	guard_a();
diff --git a/mm/page-writeback.c b/mm/page-writeback.c
@@ -20,1 +20,2 @@ int writeback_dirty(void)
+	guard_b();
diff --git a/mm/truncate.c b/mm/truncate.c
@@ -30,1 +30,2 @@ void truncate_inode(void)
+	guard_c();
`;
      const a = analyzePatch(bigPatch);
      expect(a.bugClass).toBe("out-of-bounds");
      expect(a.ambiguous).toBe(true);
      expect(a.notes.some((n) => /low confidence/i.test(n))).toBe(true);
    });

    it("falls soft on message-only input (no diff, unknown class)", () => {
      const a = analyzePatch("just a subject line with no diff and no keywords");
      expect(a.bugClass).toBe("unknown");
      expect(a.expectedSignature).toBe("");
      expect(a.touchedFiles).toHaveLength(0);
      expect(a.notes.some((n) => /no unified-diff/i.test(n))).toBe(true);
    });
  });

  describe("patchToPocPlan (end-to-end, mock LLM)", () => {
    it("produces a plan naming the right sink, trigger syscalls, and target applicability", async () => {
      const fakeLlm: NativeRuntime = {
        type: "api",
        isAvailable: async () => true,
        executeNative: async () => ({
          content: [
            {
              type: "text",
              text:
                "```json\n" +
                JSON.stringify({
                  triggerSteps: [
                    {
                      action: "socket(AF_RXRPC, SOCK_DGRAM, 0)",
                      rationale: "open an rxrpc socket to reach rxrpc_recvmsg",
                    },
                    {
                      action: "recvmsg(fd, &msg, MSG_DONTWAIT)",
                      rationale:
                        "force the -EAGAIN path that used the freed call object",
                    },
                  ],
                  preconditions: [
                    "CONFIG_AF_RXRPC built on the target",
                    "race a second thread that releases the call",
                  ],
                  reproducerSkeleton:
                    "// adjusted skeleton\nint main(void){ return 0; }",
                }) +
                "\n```",
            },
          ],
          stopReason: "end_turn",
          durationMs: 1,
        }),
      };

      const plan = await patchToPocPlan(
        RXRPC_UAF_FIX,
        { version: "5.15.139", distro: "debian-12" },
        fakeLlm,
        { subsystemHint: "rxrpc" },
      );

      // Stage 1 carried through.
      expect(plan.analysis.bugClass).toBe("use-after-free");
      expect(plan.analysis.primarySink?.function).toBe("rxrpc_recvmsg");

      // Stage 3 trigger plan: the right syscall sequence from the (mock) LLM.
      expect(plan.llmAssisted).toBe(true);
      expect(plan.triggerSteps).toHaveLength(2);
      expect(plan.triggerSteps[0]?.order).toBe(1);
      expect(plan.triggerSteps[0]?.action).toMatch(/AF_RXRPC/);
      expect(plan.triggerSteps.some((s) => /recvmsg/.test(s.action))).toBe(true);
      expect(plan.preconditions.some((p) => /AF_RXRPC/.test(p))).toBe(true);

      // No tree supplied → reachability skipped, applicability honest-unknown.
      expect(plan.reachingSyscalls).toHaveLength(0);
      expect(plan.targetApplicability.verdict).toBe("unknown");
      expect(plan.targetApplicability.reason).toMatch(/5\.15\.139/);

      // Stage 4: verify-lane handoff carries the KASAN oracle + LLM skeleton and
      // documents its consumer (the existing verify lane — not reimplemented).
      expect(plan.verifyHandoff.expectedSignature).toBe("KASAN: use-after-free");
      expect(plan.verifyHandoff.programLang).toBe("c");
      expect(plan.verifyHandoff.program).toContain("// adjusted skeleton");
      expect(plan.verifyHandoff.kernelConfig).toBe("defconfig+kasan");
      expect(plan.verifyHandoff.consumer).toMatch(/kernel-verify/);
    });

    it("without an LLM, still emits a deterministic skeleton + spine", async () => {
      const plan = await patchToPocPlan(RXRPC_UAF_FIX, {
        version: "5.15.139",
      });

      expect(plan.llmAssisted).toBe(false);
      expect(plan.triggerSteps).toHaveLength(0);
      // Deterministic skeleton names the bug class + sink and is compilable C.
      expect(plan.verifyHandoff.program).toContain("int main(void)");
      expect(plan.verifyHandoff.program).toContain("use-after-free");
      expect(plan.verifyHandoff.program).toContain("rxrpc_recvmsg");
      expect(plan.verifyHandoff.expectedSignature).toBe("KASAN: use-after-free");
      // Notes record the missing-tree (stage 2 skipped) honesty.
      expect(plan.notes.some((n) => /no source tree/i.test(n))).toBe(true);
    });

    it("references the already-fixed gate when a target tree is supplied", async () => {
      const plan = await patchToPocPlan(RXRPC_UAF_FIX, {
        version: "5.15.139",
        treePath: "/nonexistent/target/tree",
      });
      // applicability points the consumer at fix-commit-intel.checkAlreadyFixed
      // with the right file+function, rather than asserting vulnerable blindly.
      expect(plan.targetApplicability.reason).toMatch(/checkAlreadyFixed/);
      expect(plan.targetApplicability.reason).toMatch(/net\/rxrpc\/recvmsg\.c/);
      expect(plan.targetApplicability.reason).toMatch(/rxrpc_recvmsg/);
    });
  });

  describe("handoffToVerifyInput", () => {
    it("maps a handoff + finding into the verify runner input shape", async () => {
      const plan = await patchToPocPlan(RXRPC_UAF_FIX, { version: "5.15.139" });
      const finding = { id: "f1", title: "rxrpc UAF" } as unknown as Finding;
      const input = handoffToVerifyInput(
        plan.verifyHandoff,
        finding,
        "/src/linux",
      );
      expect(input.finding).toBe(finding);
      expect(input.kernelTree).toBe("/src/linux");
      expect(input.programLang).toBe("c");
      expect(input.expectedSignature).toBe("KASAN: use-after-free");
      expect(input.kernelConfig).toBe("defconfig+kasan");
    });
  });
});

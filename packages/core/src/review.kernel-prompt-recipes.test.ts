import { describe, it, expect } from "vitest";
import { buildCliReviewPrompt } from "./review.js";
import { kernelReviewAgentPrompt } from "./review/linux-kernel-profile.js";

/**
 * The linux-kernel review prompt is DUPLICATED in two places:
 *   - `kernelReviewAgentPrompt` (review/linux-kernel-profile.ts) — the agent
 *     system prompt.
 *   - `buildCliReviewPrompt(..., "linux-kernel", ...)` (review.ts) — the CLI
 *     prompt.
 * Both flow through `sourceReview()`, so both reach local + 0cloud scans. These
 * tests guard against the two copies drifting apart after a methodology edit:
 * the playbook recipes (Step 2a backward-from-primitive, Step 2b page-cache /
 * release-work / write-before-validate) must appear in BOTH.
 */

// Markers that the kernel-bug-discovery playbook recipes must contribute to the
// prompt. Each must appear in BOTH prompt copies or they have diverged.
const REQUIRED_MARKERS: Array<[label: string, re: RegExp]> = [
  ["backward-from-primitive framing", /reason BACKWARD/i],
  ["primitive: page-cache write", /page-cache write/],
  ["primitive: controlled indirect call", /controlled indirect call/],
  ["primitive: refcount underflow", /refcount underflow/],
  ["unprivileged reachability lesson", /UNPRIVILEGED/],
  ["CLONE_NEWUSER", /CLONE_NEWUSER/],
  ["recipe (a): MSG_SPLICE_PAGES", /MSG_SPLICE_PAGES/],
  ["recipe (a): SKBFL_SHARED_FRAG", /SKBFL_SHARED_FRAG/],
  ["recipe (a): CVE-2026-43284", /CVE-2026-43284/],
  ["recipe (a): CVE-2026-46300", /CVE-2026-46300/],
  ["recipe (b): cancel_work_sync", /cancel_work_sync/],
  ["recipe (b): release-work driver shape", /meson-vdec|seq_midi|mtk-jpeg/],
  ["recipe (c): crypto verify gate", /crypto_memneq|fs-verity|dm-verity/],
];

function cliKernelPrompt(): string {
  return buildCliReviewPrompt("/tmp/repo", [], "linux-kernel");
}

describe("kernel review prompt — CLI copy (buildCliReviewPrompt)", () => {
  for (const [label, re] of REQUIRED_MARKERS) {
    it(`contains the ${label} marker`, () => {
      expect(cliKernelPrompt()).toMatch(re);
    });
  }
});

describe("kernel review prompt — no divergence between the two copies", () => {
  it("both the agent-system copy and the CLI copy carry every playbook marker", () => {
    const agentPrompt = kernelReviewAgentPrompt("/tmp/repo", []);
    const cliPrompt = cliKernelPrompt();
    const missing: string[] = [];
    for (const [label, re] of REQUIRED_MARKERS) {
      if (!re.test(agentPrompt)) missing.push(`agent-prompt: ${label}`);
      if (!re.test(cliPrompt)) missing.push(`cli-prompt: ${label}`);
    }
    expect(missing).toEqual([]);
  });
});

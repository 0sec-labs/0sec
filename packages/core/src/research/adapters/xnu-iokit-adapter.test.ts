import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { TargetModel } from "../../xnu-fuzz/index.js";
import { runResearch } from "../research-runner.js";
import { XnuIokitResearchAdapter, type XnuIokitTarget } from "./xnu-iokit-adapter.js";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

const model: TargetModel = {
  kext: "com.test.driver",
  source: "/tmp/Test.kext",
  abi: "IOExternalMethodDispatch2022",
  userClients: [{
    class: "TestUserClient",
    table: "sMethods",
    matchingService: "TestService",
    varSizeSelectorCount: 1,
    selectorCount: 2,
    selectors: [
      { sel: 0, scalarInCnt: 0, structInSize: 4, scalarOutCnt: 0, structOutSize: 0 },
      { sel: 1, scalarInCnt: 1, structInSize: 0xffffffff, scalarOutCnt: 0, structOutSize: 0, hasEntitlementCheck: true },
    ],
  }],
};

function target(): XnuIokitTarget {
  return {
    kind: "xnu.iokit-fuzz",
    id: "xnu-test",
    location: model.source,
    config: {
      model,
      seed: 7,
      vm: { goldenImage: "macos", guestBuild: "26A", sharedDir: "/tmp/share", allowVmSpawn: false },
    },
  };
}

describe("XnuIokitResearchAdapter", () => {
  it("prioritizes variable selectors, generates deterministic programs, and refuses fake verification", async () => {
    const lane = { preflight: vi.fn(() => ({ ok: false, reason: "VM disabled" })), runShard: vi.fn() };
    const artifactRoot = mkdtempSync(join(tmpdir(), "0sec-xnu-"));
    roots.push(artifactRoot);
    const result = await runResearch(new XnuIokitResearchAdapter(() => lane), target(), { artifactRoot, runId: "xnu-run" });

    expect(result.candidates).toHaveLength(2);
    expect(result.candidates[0].payload.selector.sel).toBe(1);
    expect(result.findings).toHaveLength(0);
    expect(lane.runShard).not.toHaveBeenCalled();
    expect(result.evidence.some((e) => e.stage === "execute" && e.status === "inconclusive")).toBe(true);
    expect(result.evidence.some((e) => e.stage === "verify" && e.status === "inconclusive")).toBe(true);
  });
});

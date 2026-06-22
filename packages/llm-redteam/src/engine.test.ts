import { describe, it, expect } from "vitest";
import { runCampaign } from "./engine.js";
import { installPackageBehavior } from "./behaviors.js";
import { mockTarget } from "./targets/mock.js";

describe("runCampaign against mock target", () => {
  const behavior = installPackageBehavior();

  it("breaks compliant + channel-specific models, not the hardened one", async () => {
    const target = mockTarget({
      models: [
        { name: "compliant", followsVisible: true, decodes: [] },
        { name: "claude-ish", followsVisible: false, decodes: ["tags"] },
        { name: "openai-ish", followsVisible: false, decodes: ["bits"] },
        { name: "hardened", followsVisible: false, decodes: [] },
      ],
    });
    const res = await runCampaign(behavior, target, { stopWhenAllBroken: true });
    expect(res.brokenModels.sort()).toEqual(["claude-ish", "compliant", "openai-ish"]);
    expect(res.brokenModels).not.toContain("hardened");
  });

  it("never retries an already-broken model (unique-breaks)", async () => {
    const target = mockTarget({ models: [{ name: "compliant", followsVisible: true, decodes: [] }] });
    let sends = 0;
    const wrapped = { ...target, send: (...a: Parameters<typeof target.send>) => { sends++; return target.send(...a); } };
    const res = await runCampaign(behavior, wrapped, {});
    expect(res.brokenModels).toEqual(["compliant"]);
    // first candidate already breaks it; no further sends to that model
    expect(sends).toBe(1);
  });
});

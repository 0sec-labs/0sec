import { describe, it, expect } from "vitest";
import { scriptedNativeRuntime, endTurn, toolUse } from "./scripted-runtime.js";

describe("scripted-runtime test-kit", () => {
  it("endTurn / toolUse build the right native results", () => {
    expect(endTurn("hi")).toEqual({
      content: [{ type: "text", text: "hi" }],
      stopReason: "end_turn",
      durationMs: 1,
    });
    const tu = toolUse("scan", { target: "x" }, { id: "c1", text: "working" });
    expect(tu.stopReason).toBe("tool_use");
    expect(tu.content).toEqual([
      { type: "text", text: "working" },
      { type: "tool_use", id: "c1", name: "scan", input: { target: "x" } },
    ]);
  });

  it("replays results in order and records each call", async () => {
    const rt = scriptedNativeRuntime([toolUse("read_file", { path: "a" }), endTurn("done")]);
    const r1 = await rt.executeNative("sys", [], []);
    expect(r1.stopReason).toBe("tool_use");
    const r2 = await rt.executeNative("sys2", [], []);
    expect(r2.stopReason).toBe("end_turn");
    expect(rt.calls).toHaveLength(2);
    expect(rt.calls[1]!.system).toBe("sys2");
  });

  it("throws when the script is exhausted (default)", async () => {
    const rt = scriptedNativeRuntime([endTurn("only")]);
    await rt.executeNative("s", [], []);
    await expect(rt.executeNative("s", [], [])).rejects.toThrow(/exhausted/);
  });

  it("repeat-last keeps returning the final result", async () => {
    const rt = scriptedNativeRuntime([endTurn("last")], "repeat-last");
    await rt.executeNative("s", [], []);
    const again = await rt.executeNative("s", [], []);
    expect(again.content).toEqual([{ type: "text", text: "last" }]);
  });
});

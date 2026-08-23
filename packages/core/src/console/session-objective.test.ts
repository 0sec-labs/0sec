import { describe, it, expect } from "vitest";

import type {
  NativeMessage,
  NativeRuntime,
  NativeRuntimeResult,
  NativeToolDef,
} from "../runtime/types.js";
import {
  MAX_OBJECTIVE_CHARS,
  MAX_OBJECTIVE_WORDS,
  createSessionObjectiveService,
  deriveObjectiveHeuristic,
} from "./session-objective.js";

/** Wait for pending timers/microtasks so the deferred refinement can run. */
function flush(ms = 20): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

describe("deriveObjectiveHeuristic", () => {
  it("returns '' for empty / whitespace / punctuation-only input (pill hidden)", () => {
    expect(deriveObjectiveHeuristic("")).toBe("");
    expect(deriveObjectiveHeuristic("   \n\t ")).toBe("");
    expect(deriveObjectiveHeuristic("...!?")).toBe("");
    // Non-string input is tolerated (total function).
    expect(deriveObjectiveHeuristic(undefined as unknown as string)).toBe("");
  });

  it("Title-Cases a simple request and drops leading filler", () => {
    expect(deriveObjectiveHeuristic("investigate codex cloud workflows")).toBe(
      "Investigate Codex Cloud Workflows",
    );
    expect(deriveObjectiveHeuristic("let's investigate the login bug")).toBe(
      "Investigate Login Bug",
    );
    expect(deriveObjectiveHeuristic("can you please audit the auth flow")).toBe(
      "Audit Auth Flow",
    );
  });

  it("collapses whitespace and trims trailing punctuation", () => {
    expect(deriveObjectiveHeuristic("  check    the   ssrf   sink!!!  ")).toBe(
      "Check Ssrf Sink",
    );
    expect(deriveObjectiveHeuristic("review payment service.")).toBe(
      "Review Payment Service",
    );
  });

  it("unwraps wrapping quotes/backticks", () => {
    expect(deriveObjectiveHeuristic('"probe the api gateway"')).toBe("Probe Api Gateway");
    expect(deriveObjectiveHeuristic("`fix the xss`")).toBe("Fix Xss");
  });

  it("preserves existing acronym / proper-noun casing", () => {
    expect(deriveObjectiveHeuristic("audit the API for CVE-2026 issues")).toContain("API");
    expect(deriveObjectiveHeuristic("audit the API for CVE-2026 issues")).toContain("CVE-2026");
    expect(deriveObjectiveHeuristic("check OAuth token handling")).toContain("OAuth");
  });

  it("caps very long input on a word boundary — no mid-word cut, no ellipsis", () => {
    const result = deriveObjectiveHeuristic(
      "enumerate every single subdomain and endpoint across the entire production estate now",
    );
    expect(result.length).toBeLessThanOrEqual(MAX_OBJECTIVE_CHARS);
    expect(result.split(" ").length).toBeLessThanOrEqual(MAX_OBJECTIVE_WORDS);
    expect(result).not.toContain("…");
    expect(result).not.toContain("...");
    // The last word is a whole word, not a fragment.
    expect(result.endsWith("-")).toBe(false);
  });

  it("survives typo-ridden / messy input without throwing", () => {
    expect(() => deriveObjectiveHeuristic("ummm so liek,, chekc teh loginn pls")).not.toThrow();
    const messy = deriveObjectiveHeuristic("ummm so liek,, chekc teh loginn pls");
    expect(messy.length).toBeGreaterThan(0);
    expect(messy.length).toBeLessThanOrEqual(MAX_OBJECTIVE_CHARS);
  });

  it("never collapses an all-filler message to empty", () => {
    expect(deriveObjectiveHeuristic("help me")).not.toBe("");
    expect(deriveObjectiveHeuristic("please")).not.toBe("");
  });

  it("hard-slices a single word longer than the char cap (still no ellipsis)", () => {
    const huge = "a".repeat(120);
    const result = deriveObjectiveHeuristic(huge);
    expect(result.length).toBe(MAX_OBJECTIVE_CHARS);
    expect(result).not.toContain("…");
  });
});

/** Minimal stubs for the refinement runtime. */
function endTurnText(text: string): NativeRuntimeResult {
  return { content: [{ type: "text", text }], stopReason: "end_turn", durationMs: 1 };
}

class StaticRuntime implements NativeRuntime {
  readonly type = "api" as const;
  calls = 0;
  constructor(private readonly result: NativeRuntimeResult) {}
  async isAvailable(): Promise<boolean> {
    return true;
  }
  async executeNative(
    _system: string,
    _messages: NativeMessage[],
    _tools: NativeToolDef[],
  ): Promise<NativeRuntimeResult> {
    this.calls += 1;
    return this.result;
  }
}

describe("createSessionObjectiveService", () => {
  it("emits the heuristic synchronously on the first message", () => {
    const emits: Array<{ objective: string; refined: boolean }> = [];
    const svc = createSessionObjectiveService({
      refine: false,
      emit: (objective, refined) => emits.push({ objective, refined }),
    });
    svc.noteUserMessage("let's investigate the login bug");
    expect(emits).toEqual([{ objective: "Investigate Login Bug", refined: false }]);
    expect(svc.current()).toBe("Investigate Login Bug");
    svc.dispose();
  });

  it("does not seed (or emit) on an empty first message; a later message seeds", () => {
    const emits: string[] = [];
    const svc = createSessionObjectiveService({
      refine: false,
      emit: (objective) => emits.push(objective),
    });
    svc.noteUserMessage("   ");
    expect(emits).toEqual([]);
    expect(svc.current()).toBe("");
    svc.noteUserMessage("review payment service");
    expect(emits).toEqual(["Review Payment Service"]);
    svc.dispose();
  });

  it("computes the objective once — later turns are no-ops", () => {
    const emits: string[] = [];
    const svc = createSessionObjectiveService({
      refine: false,
      emit: (objective) => emits.push(objective),
    });
    svc.noteUserMessage("audit the auth flow");
    svc.noteUserMessage("now check the api");
    svc.noteUserMessage("and the database too");
    expect(emits).toEqual(["Audit Auth Flow"]);
    svc.dispose();
  });

  it("refines the objective via one deferred model call, replacing the heuristic", async () => {
    const emits: Array<{ objective: string; refined: boolean }> = [];
    const runtime = new StaticRuntime(endTurnText("Harden Login Session Handling"));
    const svc = createSessionObjectiveService({
      runtime,
      emit: (objective, refined) => emits.push({ objective, refined }),
    });
    svc.noteUserMessage("i want to fix the broken login session stuff");
    // Heuristic first, synchronously; refinement is deferred.
    expect(emits[0].refined).toBe(false);
    expect(runtime.calls).toBe(0);
    svc.turnEnded();
    await flush();
    expect(runtime.calls).toBe(1);
    expect(emits[emits.length - 1]).toEqual({
      objective: "Harden Login Session Handling",
      refined: true,
    });
    expect(svc.current()).toBe("Harden Login Session Handling");
    svc.dispose();
  });

  it("keeps the heuristic when refinement returns nothing usable", async () => {
    const emits: Array<{ objective: string; refined: boolean }> = [];
    const runtime = new StaticRuntime(endTurnText("   ")); // normalizes to ""
    const svc = createSessionObjectiveService({
      runtime,
      emit: (objective, refined) => emits.push({ objective, refined }),
    });
    svc.noteUserMessage("check the ssrf sink");
    svc.turnEnded();
    await flush();
    expect(runtime.calls).toBe(1);
    expect(emits.every((e) => e.refined === false)).toBe(true);
    expect(svc.current()).toBe("Check Ssrf Sink");
    svc.dispose();
  });

  it("is fail-soft: a throwing runtime keeps the heuristic and never rejects", async () => {
    const emits: Array<{ objective: string; refined: boolean }> = [];
    const runtime: NativeRuntime = {
      type: "api",
      isAvailable: async () => true,
      executeNative: async () => {
        throw new Error("provider exploded");
      },
    };
    const svc = createSessionObjectiveService({
      runtime,
      emit: (objective, refined) => emits.push({ objective, refined }),
    });
    svc.noteUserMessage("review payment service");
    svc.turnEnded();
    await flush();
    expect(emits).toEqual([{ objective: "Review Payment Service", refined: false }]);
    expect(svc.current()).toBe("Review Payment Service");
    svc.dispose();
  });

  it("is fail-soft: an error stopReason keeps the heuristic", async () => {
    const emits: Array<{ objective: string; refined: boolean }> = [];
    const runtime = new StaticRuntime({
      content: [],
      stopReason: "error",
      durationMs: 1,
      error: "boom",
    });
    const svc = createSessionObjectiveService({
      runtime,
      emit: (objective, refined) => emits.push({ objective, refined }),
    });
    svc.noteUserMessage("probe the api gateway");
    svc.turnEnded();
    await flush();
    expect(emits).toEqual([{ objective: "Probe Api Gateway", refined: false }]);
    svc.dispose();
  });

  it("times out fail-soft: keeps the heuristic when the model hangs", async () => {
    const emits: Array<{ objective: string; refined: boolean }> = [];
    const runtime: NativeRuntime = {
      type: "api",
      isAvailable: async () => true,
      executeNative: (_s, _m, _t, _cb, signal) =>
        new Promise<NativeRuntimeResult>((_resolve, reject) => {
          signal?.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
        }),
    };
    const svc = createSessionObjectiveService({
      runtime,
      refineTimeoutMs: 10,
      emit: (objective, refined) => emits.push({ objective, refined }),
    });
    svc.noteUserMessage("harden the upload handler");
    svc.turnEnded();
    await flush(40);
    expect(emits).toEqual([{ objective: "Harden Upload Handler", refined: false }]);
    svc.dispose();
  });

  it("dispose() before the deferred call fires suppresses the model call entirely", async () => {
    const runtime = new StaticRuntime(endTurnText("Whatever Label"));
    const svc = createSessionObjectiveService({
      runtime,
      emit: () => {},
    });
    svc.noteUserMessage("audit the auth flow");
    svc.turnEnded();
    svc.dispose();
    await flush();
    expect(runtime.calls).toBe(0);
  });

  it("never lets a throwing emitter escape into the caller", () => {
    const svc = createSessionObjectiveService({
      refine: false,
      emit: () => {
        throw new Error("renderer blew up");
      },
    });
    expect(() => svc.noteUserMessage("audit the auth flow")).not.toThrow();
    svc.dispose();
  });
});

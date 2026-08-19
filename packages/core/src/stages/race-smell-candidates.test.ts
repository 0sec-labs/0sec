/**
 * `generateRaceSmellCandidates` — parsing the lock/sleep/lock smell off the
 * model tool call, filtering malformed tuples, mapping the `widenHint` onto the
 * `0SEC_KERNEL_QEMU_WIDEN_*` prover knobs, and the runHuntScan-plug mapping.
 *
 * Mock-at-module-boundary for `node:fs` (feed source without a real tree) and
 * `../runtime/llm-api.js` (no real LLM / no key needed) — mirrors
 * `invariant-candidates.test.ts`'s strategy so CI stays key-free.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const readFileSyncMock = vi.fn();
vi.mock("node:fs", () => ({
  readFileSync: (...args: unknown[]) => readFileSyncMock(...args),
}));

const executeNativeMock = vi.fn();
vi.mock("../runtime/llm-api.js", () => ({
  LlmApiRuntime: class {
    executeNative(...args: unknown[]) {
      return executeNativeMock(...args);
    }
  },
}));

const { generateRaceSmellCandidates, widenEnvFor, KERNELCTF_TIER1_RACE_GRID } = await import("./race-smell-candidates.js");

/** Two well-formed candidates (one with a site, one without) + one malformed (no sleepPoint). */
function mockFsAndLlm(): void {
  readFileSyncMock.mockReset().mockImplementation((path: string) => {
    if (String(path).includes("af_alg.c")) return "/* af_alg */\nint af_alg_sendmsg(void) { mutex_lock(&ask->lock); return 0; }\n";
    if (String(path).includes("pipe.c")) return "/* pipe */\nssize_t pipe_write(void) { return 0; }\n";
    throw new Error(`ENOENT: ${path}`);
  });
  executeNativeMock.mockReset().mockResolvedValue({
    content: [
      {
        type: "tool_use",
        name: "emit_race_smell_analysis",
        input: {
          candidates: [
            {
              lockA: "sk->sk_lock (release_sock)",
              sleepPoint: "af_alg_alloc_areq -> sock_kmalloc(GFP_KERNEL)",
              lockB: "lock_sock re-taken",
              attackerState: "ctx->used / areq length re-fetched after the alloc",
              widenHint: {
                injectSymbol: "af_alg_sendmsg",
                suggestedDelayMs: 800,
                rationale: "stall inside the GFP_KERNEL alloc so a 2nd sendmsg tears ctx->used before re-fetch",
              },
              hypothesizedPrimitive: "OOB write on the re-fetched length",
              site: "crypto/af_alg.c:420",
            },
            {
              lockA: "pipe->rd_wait.lock",
              sleepPoint: "copy_page_from_iter (copy_from_user, faultable)",
              lockB: "pipe_lock (mutex)",
              attackerState: "pipe->head index observed across the copy",
              widenHint: {
                injectSymbol: "pipe_write",
                // no suggestedDelayMs -> falls back to default
                rationale: "userfaultfd-stall the copy_from_user to widen to seconds",
              },
              hypothesizedPrimitive: "UAF on the pipe_buffer",
              // no site -> falls back to first readable file
            },
            {
              // malformed: missing sleepPoint -> must be dropped
              lockA: "x->lock",
              lockB: "y->lock",
              attackerState: "z",
              hypothesizedPrimitive: "OOB",
              widenHint: { injectSymbol: "foo", rationale: "bar" },
            },
          ],
        },
      },
    ],
  });
}

beforeEach(() => {
  mockFsAndLlm();
});

describe("generateRaceSmellCandidates", () => {
  it("parses the lock/sleep/lock smell and builds the ExpRace/Calif-class brief", async () => {
    const plan = await generateRaceSmellCandidates({
      sourceRoot: "/src",
      subsystemFiles: ["crypto/af_alg.c", "fs/pipe.c"],
      runtime: "api",
    });
    expect(plan.brief.bugClass).toContain("race-widening");
    expect(plan.brief.pattern).toContain("copy_from_user");
    expect(plan.smellCandidates[0].lockA).toContain("sk_lock");
    expect(plan.smellCandidates[0].sleepPoint).toContain("GFP_KERNEL");
  });

  it("keeps well-formed candidates and drops malformed ones (missing sleep point)", async () => {
    const plan = await generateRaceSmellCandidates({
      sourceRoot: "/src",
      subsystemFiles: ["crypto/af_alg.c", "fs/pipe.c"],
      runtime: "api",
    });
    expect(plan.smellCandidates).toHaveLength(2);
    expect(plan.warnings.some((w) => w.includes("dropped 1 malformed"))).toBe(true);
    for (const c of plan.smellCandidates) {
      expect(c.lockA).toBeTruthy();
      expect(c.sleepPoint).toBeTruthy();
      expect(c.lockB).toBeTruthy();
      expect(c.attackerState).toBeTruthy();
      expect(c.widenHint.injectSymbol).toBeTruthy();
    }
  });

  it("maps the widenHint onto the 0SEC_KERNEL_QEMU_WIDEN_* prover knobs (model delay, then default)", async () => {
    const plan = await generateRaceSmellCandidates({
      sourceRoot: "/src",
      subsystemFiles: ["crypto/af_alg.c", "fs/pipe.c"],
      runtime: "api",
    });
    // index-aligned with smellCandidates
    expect(plan.widenEnvs).toHaveLength(2);
    // candidate 0 supplied suggestedDelayMs=800
    expect(plan.widenEnvs[0]).toEqual({
      "0SEC_KERNEL_QEMU_WIDEN_SYMBOL": "af_alg_sendmsg",
      "0SEC_KERNEL_QEMU_WIDEN_DELAY_MS": "800",
    });
    // candidate 1 omitted it -> default 500
    expect(plan.widenEnvs[1]).toEqual({
      "0SEC_KERNEL_QEMU_WIDEN_SYMBOL": "pipe_write",
      "0SEC_KERNEL_QEMU_WIDEN_DELAY_MS": "500",
    });
  });

  it("respects a caller-supplied defaultWidenDelayMs for candidates without a suggestion", async () => {
    const plan = await generateRaceSmellCandidates({
      sourceRoot: "/src",
      subsystemFiles: ["crypto/af_alg.c", "fs/pipe.c"],
      runtime: "api",
      defaultWidenDelayMs: 1200,
    });
    expect(plan.widenEnvs[1]["0SEC_KERNEL_QEMU_WIDEN_DELAY_MS"]).toBe("1200");
  });

  it("maps candidates to runHuntScan sites (model site when known, else first file) with widen knobs in the hint", async () => {
    const plan = await generateRaceSmellCandidates({
      sourceRoot: "/src",
      subsystemFiles: ["crypto/af_alg.c", "fs/pipe.c"],
      runtime: "api",
    });
    // candidate 0 -> crypto/af_alg.c (site:line), candidate 1 -> crypto/af_alg.c (fallback=first file) => dedupe onto one site
    const paths = plan.candidates.map((c) => c.path);
    expect(paths).toEqual(["crypto/af_alg.c"]);
    expect(plan.candidates[0].hint).toContain("unlock(");
    expect(plan.candidates[0].hint).toContain("af_alg_sendmsg"); // the widen symbol is threaded into the hint
    expect(plan.candidates[0].hint).toContain("mdelay 800ms");
    expect(plan.candidates[0].hint).toContain("---"); // merged second hint
  });

  it("respects maxCandidates", async () => {
    const plan = await generateRaceSmellCandidates({
      sourceRoot: "/src",
      subsystemFiles: ["crypto/af_alg.c", "fs/pipe.c"],
      runtime: "api",
      maxCandidates: 1,
    });
    expect(plan.smellCandidates).toHaveLength(1);
    expect(plan.widenEnvs).toHaveLength(1);
    expect(plan.warnings.some((w) => w.includes("capped candidates"))).toBe(true);
  });

  it("defaults subsystemFiles to the kernelCTF Tier-1 grid when none given", async () => {
    // Only af_alg.c/pipe.c are readable in the mock; the rest of the grid warns but is tolerated.
    const plan = await generateRaceSmellCandidates({ sourceRoot: "/src", runtime: "api" });
    expect(KERNELCTF_TIER1_RACE_GRID).toContain("crypto/af_alg.c");
    expect(plan.smellCandidates.length).toBeGreaterThan(0);
    expect(plan.warnings.some((w) => w.includes("could not read subsystem file"))).toBe(true);
  });

  it("throws when no subsystem file is readable", async () => {
    readFileSyncMock.mockReset().mockImplementation(() => {
      throw new Error("ENOENT");
    });
    await expect(
      generateRaceSmellCandidates({ sourceRoot: "/src", subsystemFiles: ["nope.c"], runtime: "api" }),
    ).rejects.toThrow(/could not read any subsystem file/);
  });

  it("throws when the model emits no candidates", async () => {
    executeNativeMock.mockReset().mockResolvedValue({ content: [{ type: "text", text: "no tool call" }] });
    await expect(
      generateRaceSmellCandidates({ sourceRoot: "/src", subsystemFiles: ["crypto/af_alg.c"], runtime: "api" }),
    ).rejects.toThrow(/did not emit any race-smell candidates/);
  });
});

describe("widenEnvFor", () => {
  const base = {
    lockA: "a",
    sleepPoint: "mutex_lock",
    lockB: "b",
    attackerState: "s",
    hypothesizedPrimitive: "UAF",
  };
  it("uses the suggested delay when positive", () => {
    const env = widenEnvFor({ ...base, widenHint: { injectSymbol: "fn", suggestedDelayMs: 250, rationale: "r" } }, 500);
    expect(env).toEqual({ "0SEC_KERNEL_QEMU_WIDEN_SYMBOL": "fn", "0SEC_KERNEL_QEMU_WIDEN_DELAY_MS": "250" });
  });
  it("falls back to the default when the suggested delay is missing or non-positive", () => {
    expect(widenEnvFor({ ...base, widenHint: { injectSymbol: "fn", rationale: "r" } }, 500)["0SEC_KERNEL_QEMU_WIDEN_DELAY_MS"]).toBe("500");
    expect(widenEnvFor({ ...base, widenHint: { injectSymbol: "fn", suggestedDelayMs: 0, rationale: "r" } }, 700)["0SEC_KERNEL_QEMU_WIDEN_DELAY_MS"]).toBe("700");
  });
});

import { describe, it, expect } from "vitest";
import type {
  NativeRuntime,
  NativeMessage,
  NativeToolDef,
  NativeRuntimeResult,
} from "../runtime/types.js";
import type { KernelFindingVerification, VerifyKernelFindingOptions } from "./kernel-vm-runner.js";
import {
  timerfdInterruptGadget,
  epollWaitqueueFloodGadget,
  cacheMissStallGadget,
  mutexSleepWidenGadget,
  futexHoldGadget,
  instantiateGadget,
  composeGadgetSetup,
  selectRaceGadgets,
  defaultGadgetsFor,
  attemptWinRace,
  spliceGadgetSetup,
  buildWidenEnv,
  mapVerificationToOutcome,
  setEnv,
  makeKernelVmRaceProver,
  rescheduleIpiGadget,
  tlbShootdownIpiGadget,
  membarrierIpiGadget,
  waitqueueFreezeGadget,
  retryUntilSplatGadget,
  filterGadgetsByConfig,
  isConfigEnabled,
  GADGET_KINDS,
  GADGET_SETUP_MARKER,
  type RaceCandidate,
  type KcsanRaceCandidate,
  type SmellRaceCandidate,
  type RaceProver,
  type RaceProverOutcome,
} from "./race-gadgets.js";

// ── Fixtures ────────────────────────────────────────────────────────

const kcsan: KcsanRaceCandidate = {
  kind: "kcsan",
  bugClass: "uaf-race",
  access1: { func: "ep_poll", file: "fs/eventpoll.c", line: 1900, mode: "read" },
  access2: { func: "ep_free", file: "fs/eventpoll.c", line: 900, mode: "write" },
  faultingSymbol: "ep_poll",
  faultingOffset: 0x1c,
  note: "Bad Epoll style UAF",
};

const smell: SmellRaceCandidate = {
  kind: "smell",
  lockA: "mutex_lock(&ctx->lock)",
  sleepPoint: "wait_for_completion",
  lockB: "spin_lock(&obj->lock)",
  attackerState: "close(fd) frees obj",
};

/** Scripted NativeRuntime returning a fixed sequence of results. */
function scriptedRuntime(script: Array<Partial<NativeRuntimeResult>>): NativeRuntime & { calls: number } {
  let i = 0;
  const rt: NativeRuntime & { calls: number } = {
    type: "api",
    calls: 0,
    async executeNative(
      _system: string,
      _messages: NativeMessage[],
      _tools: NativeToolDef[],
    ): Promise<NativeRuntimeResult> {
      rt.calls = ++i;
      const s = script[i - 1] ?? script[script.length - 1];
      return {
        content: s.content ?? [],
        stopReason: s.stopReason ?? "end_turn",
        durationMs: 1,
        ...(s.error ? { error: s.error } : {}),
      };
    },
    async isAvailable() {
      return true;
    },
  };
  return rt;
}

function textResult(text: string): Partial<NativeRuntimeResult> {
  return { content: [{ type: "text", text }], stopReason: "end_turn" };
}

// ── Gadget rendering ────────────────────────────────────────────────

describe("widening gadget rendering", () => {
  it("timerfd_interrupt renders a timerfd with the given interval + env", () => {
    const g = timerfdInterruptGadget({ intervalNs: 25_000 });
    expect(g.name).toBe("timerfd_interrupt");
    expect(g.params.intervalNs).toBe(25_000);
    const c = g.renderSetup();
    expect(c).toContain("timerfd_create");
    expect(c).toContain("25000");
    expect(g.proverEnv()).toEqual({ PWNKIT_RACE_WIDEN_TIMERFD_NS: "25000" });
  });

  it("epoll_waitqueue_flood renders the loop and scales flood threads", () => {
    const g = epollWaitqueueFloodGadget({ items: 50_000 });
    const c = g.renderSetup();
    expect(c).toContain("epoll_create1");
    expect(c).toContain("epoll_ctl");
    expect(c).toContain("50000");
    const env = g.proverEnv();
    expect(env.PWNKIT_RACE_WIDEN_EPOLL_ITEMS).toBe("50000");
    // ceil(50000/4096)=13 threads, clamped to <=64.
    expect(Number(env.PWNKIT_RACE_FLOOD_THREADS)).toBe(13);
  });

  it("cache_miss_stall strides the buffer and pins same-CPU", () => {
    const g = cacheMissStallGadget({ footprintKb: 8_192, strideBytes: 128 });
    const c = g.renderSetup();
    expect(c).toContain("malloc");
    expect(c).toContain("128");
    const env = g.proverEnv();
    expect(env.PWNKIT_RACE_WIDEN_CACHE_KB).toBe("8192");
    expect(env.PWNKIT_RACE_WIDEN_CACHE_STRIDE).toBe("128");
    expect(env.PWNKIT_RACE_SAME_CPU).toBe("1");
  });

  it("mutex_sleep_widen maps holdUs to nanosleep + PARK_US", () => {
    const g = mutexSleepWidenGadget({ holdUs: 300 });
    const c = g.renderSetup();
    expect(c).toContain("nanosleep");
    // 300us -> 300000 ns
    expect(c).toContain("300000");
    expect(g.proverEnv()).toEqual({ PWNKIT_RACE_PARK_US: "300" });
  });

  it("futex_hold renders a futex wait with the hold time", () => {
    const g = futexHoldGadget({ holdUs: 750 });
    const c = g.renderSetup();
    expect(c).toContain("SYS_futex");
    expect(c).toContain("FUTEX_WAIT");
    expect(g.proverEnv()).toEqual({ PWNKIT_RACE_WIDEN_FUTEX_US: "750" });
  });

  it("clamps out-of-range and non-numeric params to safe defaults", () => {
    expect(timerfdInterruptGadget({ intervalNs: -5 }).params.intervalNs).toBe(1_000);
    expect(epollWaitqueueFloodGadget({ items: 10_000_000 }).params.items).toBe(200_000);
    // NaN-ish -> default
    expect(cacheMissStallGadget({ footprintKb: Number.NaN }).params.footprintKb).toBe(16_384);
    expect(mutexSleepWidenGadget({ holdUs: 0 }).params.holdUs).toBe(1);
  });

  it("every declared gadget kind is instantiable and self-consistent", () => {
    for (const kind of GADGET_KINDS) {
      const g = instantiateGadget(kind);
      expect(g).toBeDefined();
      expect(g!.name).toBe(kind);
      expect(typeof g!.renderSetup()).toBe("string");
      expect(g!.renderSetup().length).toBeGreaterThan(0);
      expect(typeof g!.proverEnv()).toBe("object");
    }
  });

  it("instantiateGadget returns undefined for an unknown name", () => {
    expect(instantiateGadget("does_not_exist")).toBeUndefined();
  });
});

// ── Compose ─────────────────────────────────────────────────────────

describe("composeGadgetSetup", () => {
  it("concatenates C in order and merges prover env", () => {
    const composed = composeGadgetSetup([
      cacheMissStallGadget(),
      timerfdInterruptGadget(),
      epollWaitqueueFloodGadget(),
    ]);
    expect(composed.gadgetNames).toEqual([
      "cache_miss_stall",
      "timerfd_interrupt",
      "epoll_waitqueue_flood",
    ]);
    expect(composed.setupC).toContain("cache_miss_stall");
    expect(composed.setupC).toContain("timerfd_interrupt");
    expect(composed.setupC).toContain("epoll_waitqueue_flood");
    // merged env carries keys from all three gadgets
    expect(composed.proverEnv.PWNKIT_RACE_WIDEN_CACHE_KB).toBeDefined();
    expect(composed.proverEnv.PWNKIT_RACE_WIDEN_TIMERFD_NS).toBeDefined();
    expect(composed.proverEnv.PWNKIT_RACE_WIDEN_EPOLL_ITEMS).toBeDefined();
  });

  it("later gadgets win on env key clashes", () => {
    const composed = composeGadgetSetup([
      mutexSleepWidenGadget({ holdUs: 100 }),
      mutexSleepWidenGadget({ holdUs: 900 }),
    ]);
    expect(composed.proverEnv.PWNKIT_RACE_PARK_US).toBe("900");
  });
});

// ── LLM selector ────────────────────────────────────────────────────

describe("selectRaceGadgets", () => {
  it("parses an LLM JSON pick into ordered, parameterized gadgets", async () => {
    const runtime = scriptedRuntime([
      textResult(
        JSON.stringify({
          gadgets: [
            { name: "cache_miss_stall", params: { footprintKb: 4096, strideBytes: 64 } },
            { name: "timerfd_interrupt", params: { intervalNs: 30000 } },
            { name: "epoll_waitqueue_flood", params: { items: 40000 } },
          ],
        }),
      ),
    ]);
    const gadgets = await selectRaceGadgets(kcsan, { runtime });
    expect(gadgets.map((g) => g.name)).toEqual([
      "cache_miss_stall",
      "timerfd_interrupt",
      "epoll_waitqueue_flood",
    ]);
    expect(gadgets[0].params.footprintKb).toBe(4096);
    expect(runtime.calls).toBe(1);
  });

  it("tolerates a fenced code block around the JSON", async () => {
    const runtime = scriptedRuntime([
      textResult("```json\n" + JSON.stringify({ gadgets: [{ name: "futex_hold", params: {} }] }) + "\n```"),
    ]);
    const gadgets = await selectRaceGadgets(smell, { runtime });
    expect(gadgets.map((g) => g.name)).toEqual(["futex_hold"]);
  });

  it("dedupes repeated kinds and caps at maxGadgets", async () => {
    const runtime = scriptedRuntime([
      textResult(
        JSON.stringify({
          gadgets: [
            { name: "cache_miss_stall", params: {} },
            { name: "cache_miss_stall", params: {} },
            { name: "timerfd_interrupt", params: {} },
            { name: "epoll_waitqueue_flood", params: {} },
            { name: "futex_hold", params: {} },
          ],
        }),
      ),
    ]);
    const gadgets = await selectRaceGadgets(kcsan, { runtime, maxGadgets: 2 });
    expect(gadgets.map((g) => g.name)).toEqual(["cache_miss_stall", "timerfd_interrupt"]);
  });

  it("drops unknown gadget names but keeps valid ones", async () => {
    const runtime = scriptedRuntime([
      textResult(
        JSON.stringify({
          gadgets: [
            { name: "nonsense_gadget", params: {} },
            { name: "mutex_sleep_widen", params: { holdUs: 250 } },
          ],
        }),
      ),
    ]);
    const gadgets = await selectRaceGadgets(smell, { runtime });
    expect(gadgets.map((g) => g.name)).toEqual(["mutex_sleep_widen"]);
  });

  it("falls back to the default recipe on empty output (after retries)", async () => {
    const runtime = scriptedRuntime([textResult(""), textResult(""), textResult("")]);
    const gadgets = await selectRaceGadgets(kcsan, { runtime, attempts: 3 });
    expect(runtime.calls).toBe(3);
    expect(gadgets.map((g) => g.name)).toEqual(defaultGadgetsFor(kcsan).map((g) => g.name));
  });

  it("falls back on a runtime error without throwing", async () => {
    const runtime: NativeRuntime = {
      type: "api",
      async executeNative() {
        throw new Error("provider down");
      },
      async isAvailable() {
        return true;
      },
    };
    const gadgets = await selectRaceGadgets(smell, { runtime, attempts: 1 });
    expect(gadgets.map((g) => g.name)).toEqual(defaultGadgetsFor(smell).map((g) => g.name));
  });

  it("uses distinct default recipes per candidate kind", () => {
    expect(defaultGadgetsFor(kcsan).map((g) => g.name)).toContain("timerfd_interrupt");
    expect(defaultGadgetsFor(smell).map((g) => g.name)).toContain("mutex_sleep_widen");
  });
});

// ── Driver ──────────────────────────────────────────────────────────

describe("attemptWinRace", () => {
  it("aggregates wins/rate/confirmed across boots and passes composed setup", async () => {
    const seen: Array<{ bootIndex: number; hasSetup: boolean; hasWiden: boolean }> = [];
    const prover: RaceProver = async (input) => {
      seen.push({
        bootIndex: input.bootIndex,
        hasSetup: input.setupC.includes("cache_miss_stall"),
        hasWiden: !!input.widen,
      });
      // win on even boots
      return input.bootIndex % 2 === 0
        ? { kasanSplat: true, signature: "kasan-uaf" }
        : { kasanSplat: false };
    };
    const gadgets = defaultGadgetsFor(kcsan);
    const res = await attemptWinRace(kcsan, gadgets, { boots: 4, prover });
    expect(res.boots).toBe(4);
    expect(res.wins).toBe(2);
    expect(res.rate).toBe(0.5);
    expect(res.confirmed).toBe(true);
    expect(res.signature).toBe("kasan-uaf");
    expect(res.gadgets).toEqual(gadgets.map((g) => g.name));
    // widen threaded from the candidate's faulting PC
    expect(seen.every((s) => s.hasSetup && s.hasWiden)).toBe(true);
    expect(seen.map((s) => s.bootIndex)).toEqual([0, 1, 2, 3]);
  });

  it("reports not-confirmed when no boot splats", async () => {
    const prover: RaceProver = async () => ({ kasanSplat: false });
    const res = await attemptWinRace(smell, defaultGadgetsFor(smell), { boots: 3, prover });
    expect(res.confirmed).toBe(false);
    expect(res.wins).toBe(0);
    expect(res.rate).toBe(0);
    expect(res.signature).toBeUndefined();
  });

  it("stops early once stopAfterWins is reached", async () => {
    let calls = 0;
    const prover: RaceProver = async () => {
      calls++;
      return { kasanSplat: true, signature: "kasan-uaf" };
    };
    const res = await attemptWinRace(kcsan, defaultGadgetsFor(kcsan), {
      boots: 10,
      prover,
      stopAfterWins: 1,
    });
    expect(calls).toBe(1);
    expect(res.boots).toBe(1);
    expect(res.wins).toBe(1);
  });

  it("omits widen for a candidate with no faulting PC", async () => {
    let sawWiden = true;
    const prover: RaceProver = async (input) => {
      sawWiden = !!input.widen;
      return { kasanSplat: false };
    };
    const noPc: RaceCandidate = { ...smell };
    await attemptWinRace(noPc, defaultGadgetsFor(noPc), { boots: 1, prover });
    expect(sawWiden).toBe(false);
  });

  it("the default prover throws a clear, actionable error", async () => {
    await expect(attemptWinRace(kcsan, defaultGadgetsFor(kcsan), { boots: 1 })).rejects.toThrow(
      /no RaceProver supplied/,
    );
  });
});

// ── Prover glue (pure helpers + injected verify/io) ─────────────────

describe("prover glue helpers", () => {
  it("spliceGadgetSetup replaces the marker in place", () => {
    const repro = `int main(){\n  ${GADGET_SETUP_MARKER}\n  return 0;\n}`;
    const out = spliceGadgetSetup(repro, "/*GADGETS*/");
    expect(out).toContain("/*GADGETS*/");
    expect(out).not.toContain(GADGET_SETUP_MARKER);
  });

  it("spliceGadgetSetup inserts into main() when no marker present", () => {
    const repro = "int main(void) {\n  do_race();\n}";
    const out = spliceGadgetSetup(repro, "/*GADGETS*/");
    expect(out.indexOf("/*GADGETS*/")).toBeGreaterThan(out.indexOf("main"));
    expect(out.indexOf("/*GADGETS*/")).toBeLessThan(out.indexOf("do_race"));
  });

  it("spliceGadgetSetup prepends as a fallback with no main()", () => {
    const out = spliceGadgetSetup("void helper(){}", "/*GADGETS*/");
    expect(out.startsWith("/*GADGETS*/")).toBe(true);
  });

  it("buildWidenEnv formats the widen env; empty for no widen", () => {
    expect(buildWidenEnv(undefined, 5)).toEqual({});
    expect(buildWidenEnv({ symbol: "ep_poll", offset: 0x1c }, 7)).toEqual({
      PWNKIT_KERNEL_QEMU_WIDEN_SYMBOL: "ep_poll",
      PWNKIT_KERNEL_QEMU_WIDEN_OFFSET: "0x1c",
      PWNKIT_KERNEL_QEMU_WIDEN_DELAY_MS: "7",
    });
  });

  it("mapVerificationToOutcome maps reproduced->splat, else no splat", () => {
    const ok: KernelFindingVerification = {
      status: "reproduced",
      signature: "kasan-uaf",
      dmesg_path: "/tmp/x.dmesg",
      build_cache_hit: true,
    };
    expect(mapVerificationToOutcome(ok).kasanSplat).toBe(true);
    expect(mapVerificationToOutcome(ok).signature).toBe("kasan-uaf");

    const no: KernelFindingVerification = {
      status: "no_signal",
      dmesg_path: "/tmp/y.dmesg",
      build_cache_hit: false,
    };
    expect(mapVerificationToOutcome(no).kasanSplat).toBe(false);
  });

  it("setEnv sets then restores prior values", () => {
    const KEY = "PWNKIT_TEST_RACE_KEY_XYZ";
    delete process.env[KEY];
    const restore = setEnv({ [KEY]: "on" });
    expect(process.env[KEY]).toBe("on");
    restore();
    expect(process.env[KEY]).toBeUndefined();
  });
});

describe("makeKernelVmRaceProver (VM stubbed)", () => {
  it("splices gadgets, carries widen+gadget env, and maps the verdict", async () => {
    const reads: string[] = [];
    let capturedOpts: VerifyKernelFindingOptions | undefined;
    let envAtVerify: Record<string, string | undefined> = {};

    const prover = makeKernelVmRaceProver({
      reproducerPath: "/fake/repro.c",
      kernelTree: "/fake/linux",
      kernelConfig: "kasan",
      expectedSignature: "kasan-uaf",
      widenDelayMs: 9,
      io: {
        read: (p) => {
          reads.push(p);
          return `int main(){ ${GADGET_SETUP_MARKER} do_race(); }`;
        },
        write: (content, bootIndex) => `/tmp/widened-${bootIndex}.c#${content.includes("cache_miss_stall")}`,
      },
      verify: async (opts) => {
        capturedOpts = opts;
        envAtVerify = {
          cacheKb: process.env.PWNKIT_RACE_WIDEN_CACHE_KB,
          widenSym: process.env.PWNKIT_KERNEL_QEMU_WIDEN_SYMBOL,
          widenDelay: process.env.PWNKIT_KERNEL_QEMU_WIDEN_DELAY_MS,
        };
        return {
          status: "reproduced",
          signature: "kasan-uaf",
          dmesg_path: "/tmp/z.dmesg",
          build_cache_hit: true,
        };
      },
    });

    const gadgets = defaultGadgetsFor(kcsan);
    const composed = composeGadgetSetup(gadgets);
    const outcome = await prover({
      candidate: kcsan,
      setupC: composed.setupC,
      proverEnv: composed.proverEnv,
      widen: { symbol: "ep_poll", offset: 0x1c },
      bootIndex: 0,
    });

    expect(reads).toEqual(["/fake/repro.c"]);
    // widened reproducer path was passed to verify, and it embedded the gadget C
    expect(capturedOpts?.reproducerPath).toBe("/tmp/widened-0.c#true");
    expect(capturedOpts?.kernelTree).toBe("/fake/linux");
    expect(capturedOpts?.kernelConfig).toBe("kasan");
    expect(capturedOpts?.expectedSignature).toBe("kasan-uaf");
    // env was live during the verify call
    expect(envAtVerify.cacheKb).toBeDefined();
    expect(envAtVerify.widenSym).toBe("ep_poll");
    expect(envAtVerify.widenDelay).toBe("9");
    // and restored afterwards
    expect(process.env.PWNKIT_KERNEL_QEMU_WIDEN_SYMBOL).toBeUndefined();
    expect(outcome.kasanSplat).toBe(true);
    expect(outcome.signature).toBe("kasan-uaf");
  });

  it("drives end-to-end through attemptWinRace with a stubbed verify", async () => {
    let boot = 0;
    const prover = makeKernelVmRaceProver({
      reproducerPath: "/fake/repro.c",
      kernelTree: "/fake/linux",
      io: {
        read: () => "int main(){ return 0; }",
        write: (_c, b) => `/tmp/w-${b}.c`,
      },
      verify: async (): Promise<KernelFindingVerification> => {
        const status = boot++ === 1 ? "reproduced" : "no_signal";
        return { status, dmesg_path: "/tmp/d.dmesg", build_cache_hit: false, ...(status === "reproduced" ? { signature: "kasan-uaf" } : {}) };
      },
    });
    const res = await attemptWinRace(kcsan, defaultGadgetsFor(kcsan), { boots: 3, prover });
    expect(res.boots).toBe(3);
    expect(res.wins).toBe(1);
    expect(res.confirmed).toBe(true);
    expect(res.signature).toBe("kasan-uaf");
  });
});

// ── ExpRace real-IPI widener tactics (LPE-hunt upgrade #1) ──────────

describe("ExpRace real-IPI widener gadgets", () => {
  it("reschedule_ipi renders the sched_setaffinity IPI source and is CONFIG_PREEMPT-gated", () => {
    const g = rescheduleIpiGadget({ targetCpu: 2, bounces: 500 });
    expect(g.name).toBe("reschedule_ipi");
    expect(g.requiredConfig).toBe("CONFIG_PREEMPT");
    const c = g.renderSetup();
    expect(c).toContain("sched_setaffinity");
    expect(c).toContain("CPU_SET(2");
    // affinity bounces to targetCpu+1 to force the migration/IPI.
    expect(c).toContain("CPU_SET(3");
    expect(c).toContain("__k < 500");
    // carries the headers its C needs (GNU affinity macros).
    expect(g.headers).toContain("#define _GNU_SOURCE");
    expect(g.proverEnv().PWNKIT_RACE_WIDEN_RESCHED_BOUNCES).toBe("500");
  });

  it("tlb_shootdown_ipi renders an mprotect() TLB IPI and needs NO config gate", () => {
    const g = tlbShootdownIpiGadget({ flips: 300 });
    expect(g.name).toBe("tlb_shootdown_ipi");
    expect(g.requiredConfig).toBeUndefined();
    const c = g.renderSetup();
    expect(c).toContain("mprotect");
    expect(c).toContain("MAP_SHARED");
    expect(c).toContain("__k < 300");
  });

  it("membarrier_ipi renders the membarrier expedited IPI and is CONFIG_MEMBARRIER-gated", () => {
    const g = membarrierIpiGadget({ count: 100 });
    expect(g.requiredConfig).toBe("CONFIG_MEMBARRIER");
    const c = g.renderSetup();
    expect(c).toContain("SYS_membarrier");
    expect(c).toContain("MEMBARRIER_CMD_PRIVATE_EXPEDITED");
    // registers before firing (required by the expedited command).
    expect(c).toContain("MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED");
  });

  it("waitqueue_freeze renders calif's timerfd/epoll freeze", () => {
    const g = waitqueueFreezeGadget({ entries: 12345 });
    const c = g.renderSetup();
    expect(c).toContain("timerfd_create");
    expect(c).toContain("epoll_ctl");
    expect(c).toContain("__i < 12345");
    expect(g.proverEnv().PWNKIT_RACE_WIDEN_WAITQUEUE_ENTRIES).toBe("12345");
  });

  it("retry_until_splat carries only env budget (loop lives in the harness)", () => {
    const g = retryUntilSplatGadget({ retries: 5000, seconds: 25 });
    expect(g.proverEnv().PWNKIT_RACE_RETRIES).toBe("5000");
    expect(g.proverEnv().PWNKIT_RACE_SECONDS).toBe("25");
    // no real C beyond a comment marker.
    expect(g.renderSetup()).toContain("harness wraps the race");
  });

  it("registers all new kinds in GADGET_KINDS and instantiateGadget", () => {
    for (const name of [
      "reschedule_ipi",
      "tlb_shootdown_ipi",
      "membarrier_ipi",
      "waitqueue_freeze",
      "retry_until_splat",
    ] as const) {
      expect(GADGET_KINDS).toContain(name);
      expect(instantiateGadget(name)?.name).toBe(name);
    }
  });
});

describe("filterGadgetsByConfig — config-gated fail-soft", () => {
  it("isConfigEnabled reads =y / =m and treats 'is not set' as OFF", () => {
    expect(isConfigEnabled("CONFIG_PREEMPT=y\n", "CONFIG_PREEMPT")).toBe(true);
    expect(isConfigEnabled("CONFIG_MEMBARRIER=m\n", "CONFIG_MEMBARRIER")).toBe(true);
    expect(isConfigEnabled("# CONFIG_PREEMPT is not set\n", "CONFIG_PREEMPT")).toBe(false);
    expect(isConfigEnabled("CONFIG_OTHER=y\n", "CONFIG_PREEMPT")).toBe(false);
  });

  it("skips reschedule_ipi when CONFIG_PREEMPT is absent (fail-soft), keeps the rest", () => {
    const gadgets = [
      cacheMissStallGadget(),
      rescheduleIpiGadget(),
      tlbShootdownIpiGadget(),
    ];
    const cfg = "# CONFIG_PREEMPT is not set\nCONFIG_SMP=y\n";
    const { kept, skipped } = filterGadgetsByConfig(gadgets, cfg);
    expect(kept.map((g) => g.name)).toEqual(["cache_miss_stall", "tlb_shootdown_ipi"]);
    expect(skipped).toEqual([{ name: "reschedule_ipi", requiredConfig: "CONFIG_PREEMPT" }]);
  });

  it("keeps reschedule_ipi when CONFIG_PREEMPT is enabled", () => {
    const { kept, skipped } = filterGadgetsByConfig(
      [rescheduleIpiGadget()],
      "CONFIG_PREEMPT=y\n",
    );
    expect(kept.map((g) => g.name)).toEqual(["reschedule_ipi"]);
    expect(skipped).toEqual([]);
  });

  it("keeps ALL gadgets when the target .config is unknown (cannot gate)", () => {
    const gadgets = [rescheduleIpiGadget(), membarrierIpiGadget()];
    const { kept, skipped } = filterGadgetsByConfig(gadgets, undefined);
    expect(kept).toHaveLength(2);
    expect(skipped).toEqual([]);
  });
});

describe("defaultGadgetsFor — ExpRace IPI + retry layered in", () => {
  it("KCSAN/UAF recipe layers a real-IPI source and the retry loop", () => {
    const names = defaultGadgetsFor(kcsan).map((g) => g.name);
    expect(names).toContain("reschedule_ipi");
    expect(names).toContain("retry_until_splat");
  });

  it("smell recipe also carries a real-IPI source + retry loop", () => {
    const names = defaultGadgetsFor(smell).map((g) => g.name);
    expect(names).toContain("tlb_shootdown_ipi");
    expect(names).toContain("retry_until_splat");
  });
});

// keep RaceProverOutcome referenced for type-coverage
const _outcomeType: RaceProverOutcome = { kasanSplat: false };
void _outcomeType;

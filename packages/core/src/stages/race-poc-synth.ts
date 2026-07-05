/**
 * Two-thread race PoC synthesizer — the (thin) back half of the invariant-checker
 * pipeline (see invariant-candidates.ts). An {@link InvariantCandidate} names a
 * lock/refcount/state invariant, the *unprivileged* syscall pair that races it,
 * and the primitive the race yields; this turns that into a runnable 2-thread C
 * harness pinned to two CPUs, with the race window widened via `PWNKIT_RACE_*`
 * env knobs so a narrow window is actually hit on a real box.
 *
 * SCOPE (deliberately thin — issue #1113): this ships the INTERFACE + a working
 * harness TEMPLATE (thread setup, CPU pinning, the widen loop, the env knobs).
 * The per-candidate SYSCALL BODIES are left as clearly-marked `TODO` stubs — the
 * codegen that fills threadA/threadB with the actual `racingSyscallPair` calls
 * (and the trigger that observes the primitive) is a follow-up. The template is
 * enough to compile-check the scaffold and to hand a human/next-stage a filled
 * skeleton, not to weaponize on its own.
 */

import type { InvariantCandidate } from "./invariant-candidates.js";

/** A request to synthesize a race harness for one candidate. */
export interface RacePocRequest {
  candidate: InvariantCandidate;
  /**
   * The two logical CPUs to pin thread A / thread B to (default [0, 1]).
   * Pinning to distinct cores is what makes the two syscalls actually run
   * concurrently instead of being serialized on one runqueue.
   */
  cpus?: [number, number];
  /** Optional extra `#include` lines the syscall bodies will need (provenance/hint only). */
  includes?: string[];
}

/** Emits a C harness source string for a race candidate. */
export interface RacePocSynth {
  synthesize(req: RacePocRequest): string;
}

const DEFAULT_INCLUDES = [
  "#define _GNU_SOURCE",
  "#include <pthread.h>",
  "#include <sched.h>",
  "#include <stdio.h>",
  "#include <stdlib.h>",
  "#include <string.h>",
  "#include <unistd.h>",
];

function cIdent(s: string): string {
  return s.replace(/[^A-Za-z0-9_]/g, "_").replace(/^([0-9])/, "_$1") || "syscall";
}

function cComment(s: string): string {
  // Keep an arbitrary invariant/description safe inside a /* ... */ block.
  return s.replace(/\*\//g, "* /");
}

/**
 * Render a compile-ready 2-thread race harness. Thread A/B are pinned to
 * `cpus[0]`/`cpus[1]`; each spins `PWNKIT_RACE_ITERS` times (default 100000),
 * and when `PWNKIT_RACE_WIDEN=1` a short pre-syscall busy-spin (length
 * `PWNKIT_RACE_SPIN`, default 64) nudges the two threads' entry closer together
 * to widen the window. The syscall bodies themselves are TODO stubs.
 */
export function renderRaceHarness(req: RacePocRequest): string {
  const cpus = req.cpus ?? [0, 1];
  const c = req.candidate;
  const aName = cIdent(c.racingSyscallPair.A);
  const bName = cIdent(c.racingSyscallPair.B);
  const includes = [...DEFAULT_INCLUDES, ...(req.includes ?? [])];

  return `${includes.join("\n")}

/*
 * Auto-generated race-PoC scaffold (pwnkit invariant-checker, issue #1113).
 *
 * Invariant under test : ${cComment(c.invariant)}
 * Racing syscall pair  : A=${cComment(c.racingSyscallPair.A)}  B=${cComment(c.racingSyscallPair.B)}
 * Field left torn      : ${cComment(c.field)}
 * Hypothesized primitive: ${cComment(c.hypothesizedPrimitive)}
 *
 * Widen the race window with:
 *   PWNKIT_RACE_ITERS=<n>   iterations per thread            (default 100000)
 *   PWNKIT_RACE_WIDEN=1     enable the pre-syscall busy-spin (default off)
 *   PWNKIT_RACE_SPIN=<n>    busy-spin length when widening   (default 64)
 */

static long race_iters(void) {
  const char *e = getenv("PWNKIT_RACE_ITERS");
  long n = e ? atol(e) : 100000;
  return n > 0 ? n : 100000;
}

static long race_spin(void) {
  const char *e = getenv("PWNKIT_RACE_SPIN");
  long n = e ? atol(e) : 64;
  return n > 0 ? n : 64;
}

static int race_widen(void) {
  const char *e = getenv("PWNKIT_RACE_WIDEN");
  return e && e[0] == '1';
}

/* Widen the window: a short busy-spin right before the racing syscall so the
 * two threads land in the critical section within a few cycles of each other. */
static void race_pause(void) {
  if (!race_widen()) return;
  volatile long spin = race_spin();
  while (spin-- > 0) { __asm__ __volatile__("" ::: "memory"); }
}

static int pin_to_cpu(int cpu) {
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(cpu, &set);
  return sched_setaffinity(0, sizeof(set), &set);
}

/* Thread A — pinned to CPU ${cpus[0]}. Racing side A: ${cComment(c.racingSyscallPair.A)} */
static void *thread_${aName}(void *arg) {
  (void)arg;
  if (pin_to_cpu(${cpus[0]}) != 0) perror("sched_setaffinity A");
  for (long i = 0, n = race_iters(); i < n; i++) {
    race_pause();
    /* TODO(#1113): invoke the racing syscall A = ${cComment(c.racingSyscallPair.A)}
     * that mutates '${cComment(c.field)}' without holding '${cComment(c.field)}'s
     * serializing lock. Fill this from the candidate's syscall args. */
  }
  return NULL;
}

/* Thread B — pinned to CPU ${cpus[1]}. Racing side B: ${cComment(c.racingSyscallPair.B)} */
static void *thread_${bName}(void *arg) {
  (void)arg;
  if (pin_to_cpu(${cpus[1]}) != 0) perror("sched_setaffinity B");
  for (long i = 0, n = race_iters(); i < n; i++) {
    race_pause();
    /* TODO(#1113): invoke the racing syscall B = ${cComment(c.racingSyscallPair.B)}
     * that observes/frees '${cComment(c.field)}' concurrently, tripping the
     * '${cComment(c.hypothesizedPrimitive)}'. Fill this from the candidate's syscall args. */
  }
  return NULL;
}

int main(void) {
  pthread_t ta, tb;
  /* TODO(#1113): set up the shared object both syscalls race on (e.g. the
   * unix socket / fd pair) before launching the threads. */
  if (pthread_create(&ta, NULL, thread_${aName}, NULL) != 0) { perror("pthread_create A"); return 1; }
  if (pthread_create(&tb, NULL, thread_${bName}, NULL) != 0) { perror("pthread_create B"); return 1; }
  pthread_join(ta, NULL);
  pthread_join(tb, NULL);
  /* TODO(#1113): observe the primitive (KASAN splat / crash / leaked object). */
  return 0;
}
`;
}

/** The default template-backed synthesizer. */
export function makeTemplateRacePocSynth(): RacePocSynth {
  return { synthesize: (req) => renderRaceHarness(req) };
}

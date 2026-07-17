/**
 * Tests for the cross-function lockset-inconsistency race-candidate generator
 * ({@link findRaceCandidates}).
 *
 * The capability this proves: the checker relates accesses ACROSS functions, which
 * the intra-procedural invariant checker structurally cannot — it flags a field
 * locked in fn A but touched with no lock in an independently reachable fn B, and it
 * does NOT flag a field consistently locked everywhere. No LLM, no mocks — a pure
 * function over (model, source).
 */

import { describe, expect, it } from "vitest";
import { findRaceCandidates, raceCandidatesToHuntPlan } from "./concurrency-race.js";
import { INVARIANT_MODEL_VERSION } from "./subsystem-invariant-model.js";

type InvariantModel = Parameters<typeof findRaceCandidates>[0];

// Model: struct conn, c->lock guards ->state (a state field) and ->blocker (a
// lifetime pointer), with a kfree lifecycle so ->blocker ranks high.
function connModel(): InvariantModel {
  return {
    modelVersion: INVARIANT_MODEL_VERSION,
    subsystem: "test/conn",
    subsystemFiles: ["conn.c"],
    objects: [
      {
        object: "struct conn",
        lockRules: [{ lock: "c->lock", guardedFields: ["state", "blocker", "nr_packets"] }],
        refcountRules: [],
        lifecycleRules: [{ freeFn: "kfree", note: "frees struct conn" }],
      },
    ],
    builtAt: new Date().toISOString(),
  } as InvariantModel;
}

const run = (src: string, discover = false) =>
  findRaceCandidates(connModel(), [{ file: "conn.c", text: src }], { discoverSharedFields: discover });

describe("findRaceCandidates — cross-function lockset inconsistency", () => {
  it("FLAGS a field written under lock A in fn1 and read with NO lock in fn2", () => {
    const src = `
      void fn1(struct conn *c) {
        spin_lock(&c->lock);
        c->state = 1;
        spin_unlock(&c->lock);
      }
      int fn2(struct conn *c) {
        return c->state;   /* no lock held — inconsistent with fn1 */
      }
    `;
    const cands = run(src);
    const state = cands.find((c) => c.field === "state");
    expect(state).toBeDefined();
    expect(state!.kind).toBe("unlocked-vs-locked");
    expect(state!.guardConsensus).toContain("lock");
    // The unlocked side is fn2; the locked side is fn1.
    expect(state!.inconsistentAccesses.some((a) => a.functionName === "fn2")).toBe(true);
    expect(state!.consensusAccesses.some((a) => a.functionName === "fn1")).toBe(true);
    expect(state!.hasWrite).toBe(true);
  });

  it("does NOT flag a field consistently locked in both functions", () => {
    const src = `
      void fn1(struct conn *c) {
        spin_lock(&c->lock);
        c->state = 1;
        spin_unlock(&c->lock);
      }
      int fn2(struct conn *c) {
        int v;
        spin_lock(&c->lock);
        v = c->state;
        spin_unlock(&c->lock);
        return v;
      }
    `;
    const cands = run(src);
    expect(cands.find((c) => c.field === "state")).toBeUndefined();
  });

  it("does NOT under-report the lock when it is released only on an error-return branch", () => {
    // fn2 unlocks and returns on the error path; the post-if access is still locked.
    const src = `
      void fn1(struct conn *c) {
        spin_lock(&c->lock);
        c->state = 1;
        spin_unlock(&c->lock);
      }
      int fn2(struct conn *c, int err) {
        int v;
        spin_lock(&c->lock);
        if (err) {
          spin_unlock(&c->lock);
          return -1;
        }
        v = c->state;          /* lock STILL held here — must not be flagged */
        spin_unlock(&c->lock);
        return v;
      }
    `;
    const cands = run(src);
    expect(cands.find((c) => c.field === "state")).toBeUndefined();
  });

  it("sees an accessor-macro access (smp_load_acquire) that the UAF event stream skips", () => {
    const src = `
      void fn1(struct conn *c) {
        spin_lock(&c->lock);
        c->blocker = 0;
        spin_unlock(&c->lock);
      }
      int fn2(struct conn *c) {
        /* lockless read through an accessor macro — inside a call arg */
        if (!smp_load_acquire(&c->blocker))
          return 0;
        return 1;
      }
    `;
    const cands = run(src);
    const blocker = cands.find((c) => c.field === "blocker");
    expect(blocker).toBeDefined();
    expect(blocker!.inconsistentAccesses.some((a) => a.functionName === "fn2")).toBe(true);
  });

  it("ranks a lifetime-pointer field (blocker) above a stat counter (nr_packets)", () => {
    const src = `
      void fn1(struct conn *c) {
        spin_lock(&c->lock);
        c->blocker = 0;
        c->nr_packets++;
        spin_unlock(&c->lock);
      }
      void fn2(struct conn *c) {
        c->blocker = 1;        /* unlocked write to a lifetime pointer */
        c->nr_packets++;       /* unlocked bump of a stat counter */
      }
    `;
    const cands = run(src);
    const blocker = cands.find((c) => c.field === "blocker");
    const stat = cands.find((c) => c.field === "nr_packets");
    expect(blocker).toBeDefined();
    expect(blocker!.severity).toBe("high");
    expect(stat).toBeDefined();
    expect(stat!.severity).toBe("low");
    // High-severity candidate sorts before the low-severity one.
    expect(cands.indexOf(blocker!)).toBeLessThan(cands.indexOf(stat!));
  });

  it("does not flag same-function lock-then-access (needs two distinct functions)", () => {
    const src = `
      int fn1(struct conn *c) {
        int v = c->state;      /* pre-lock read */
        spin_lock(&c->lock);
        v = c->state;          /* locked read — same function */
        spin_unlock(&c->lock);
        return v;
      }
    `;
    const cands = run(src);
    expect(cands.find((c) => c.field === "state")).toBeUndefined();
  });

  it("maps candidates to a runHuntScan plan (brief + per-file hint)", () => {
    const src = `
      void fn1(struct conn *c) { spin_lock(&c->lock); c->blocker = 0; spin_unlock(&c->lock); }
      void fn2(struct conn *c) { c->blocker = 1; }
    `;
    const cands = run(src);
    const plan = raceCandidatesToHuntPlan(connModel(), cands);
    expect(plan.brief.bugClass).toMatch(/lockset-inconsistency/);
    expect(plan.huntCandidates.length).toBeGreaterThan(0);
    expect(plan.huntCandidates[0].path).toBe("conn.c");
    expect(plan.huntCandidates[0].hint).toMatch(/RACE CANDIDATE/);
  });

  // ── FP FILTER 1: init/teardown/getter suppression on the unlocked side ──────────

  it("does NOT flag a field whose only unlocked access is in an init/constructor fn", () => {
    // fn1 writes ->state under the lock; the ONLY unlocked touch is in an *_init
    // constructor (single-threaded, pre-publication) — must be suppressed, not flagged.
    const src = `
      void fn1(struct conn *c) {
        spin_lock(&c->lock);
        c->state = 1;
        spin_unlock(&c->lock);
      }
      void conn_init(struct conn *c) {
        c->state = 0;          /* pre-publication init write — not a race */
      }
    `;
    const cands = run(src);
    expect(cands.find((c) => c.field === "state")).toBeUndefined();
  });

  it("does NOT flag a field whose only unlocked access is in a getter/dump fn", () => {
    // lock_get_status only READS ->state to dump it; a getter-named pure reader is
    // suppressed on the unlocked side.
    const src = `
      void fn1(struct conn *c) {
        spin_lock(&c->lock);
        c->state = 1;
        spin_unlock(&c->lock);
      }
      int lock_get_status(struct conn *c) {
        return c->state;       /* read-only dump — not a race */
      }
    `;
    const cands = run(src);
    expect(cands.find((c) => c.field === "state")).toBeUndefined();
  });

  it("STILL flags when a real racing fn accesses the field alongside an init/getter fn", () => {
    // The unlocked side has BOTH an init fn (suppressed) and a genuine worker (kept):
    // the candidate must survive, and the init fn must not appear as a racing site.
    const src = `
      void fn1(struct conn *c) {
        spin_lock(&c->lock);
        c->state = 1;
        spin_unlock(&c->lock);
      }
      void conn_init(struct conn *c) {
        c->state = 0;          /* suppressed */
      }
      void worker(struct conn *c) {
        c->state = 2;          /* genuine unlocked write from a work item — kept */
      }
    `;
    const cands = run(src);
    const state = cands.find((c) => c.field === "state");
    expect(state).toBeDefined();
    const badFns = new Set(state!.inconsistentAccesses.map((a) => a.functionName));
    expect(badFns.has("worker")).toBe(true);
    expect(badFns.has("conn_init")).toBe(false);
  });

  // ── FP FILTER 2: require a write in the racing pair ──────────────────────────────

  it("DROPS an all-reads-vs-reads race on a lifetime field (no write to corrupt)", () => {
    // ->blocker is only ever READ — locked in fn1, unlocked in fn2. No write anywhere,
    // so it cannot be a UAF: dropped by the write requirement.
    const src = `
      int fn1(struct conn *c) {
        int v;
        spin_lock(&c->lock);
        v = (c->blocker != 0);
        spin_unlock(&c->lock);
        return v;
      }
      int fn2(struct conn *c) {
        return c->blocker != 0;   /* unlocked READ, no write anywhere */
      }
    `;
    const cands = run(src);
    expect(cands.find((c) => c.field === "blocker")).toBeUndefined();
  });

  it("counts a &field passed to a list MUTATOR as a WRITE (keeps the list-linkage race)", () => {
    // ->blocker is a list_head touched only via list ops: mutated (list_add_tail) under
    // the lock, and list_del'd without it. The write requirement must still be met via
    // the mutator, so the candidate survives; a read-only list_empty does NOT rescue it.
    const src = `
      void fn1(struct conn *c, struct conn *w) {
        spin_lock(&c->lock);
        list_add_tail(&w->blocker, &c->blocker);
        spin_unlock(&c->lock);
      }
      void fn2(struct conn *w) {
        list_del_init(&w->blocker);   /* unlocked list mutation — a WRITE */
      }
    `;
    const cands = run(src);
    const blocker = cands.find((c) => c.field === "blocker");
    expect(blocker).toBeDefined();
    expect(blocker!.hasWrite).toBe(true);
    expect(blocker!.inconsistentAccesses.some((a) => a.functionName === "fn2" && a.isWrite)).toBe(true);
  });

  it("does NOT count a read-only list op (list_empty) as a write", () => {
    // Only list_empty (read) touches ->blocker unlocked; the locked side also only reads
    // it. No true write → dropped by FILTER 2 (list_empty must not be a mutator).
    const src = `
      int fn1(struct conn *c) {
        int v;
        spin_lock(&c->lock);
        v = list_empty(&c->blocker);
        spin_unlock(&c->lock);
        return v;
      }
      int fn2(struct conn *c) {
        return list_empty(&c->blocker);   /* read-only */
      }
    `;
    const cands = run(src);
    expect(cands.find((c) => c.field === "blocker")).toBeUndefined();
  });

  it("discovery mode surfaces a shared field absent from the model", () => {
    // 'epoch' is not in the model; discovery should pick it up (locked in fn1, 2 fns).
    const src = `
      void fn1(struct conn *c) { spin_lock(&c->lock); c->epoch = 5; spin_unlock(&c->lock); }
      int fn2(struct conn *c) { return c->epoch; }
    `;
    const withDiscovery = run(src, true);
    const withoutDiscovery = run(src, false);
    expect(withoutDiscovery.find((c) => c.field === "epoch")).toBeUndefined();
    expect(withDiscovery.find((c) => c.field === "epoch")).toBeDefined();
  });
});

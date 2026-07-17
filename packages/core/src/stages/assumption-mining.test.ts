/**
 * Tests for ASSUMPTION-MINING ({@link crossCheckAssumptions} /
 * {@link scanViolatingContexts}) — the deterministic, NO-LLM half of the fourth
 * seedless axis. Proves the two capabilities the fixed-shape checkers lack:
 *   1. STAGE 1b bounds the FP surface: prose-only establishers are dropped, an
 *      enforced-local claim is verified against the body (dropped when true,
 *      reclassified when false), off-scope relevance is dropped.
 *   2. The establisher-propagation CALLER-SCAN flags a caller that reaches a
 *      relied-on subject WITHOUT the establisher, and — the proven FP-killer —
 *      does NOT flag a caller that INHERITS the establisher from its own callers.
 * Pure functions over (model, sources); no LLM, no mocks.
 */

import { describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ASSUMPTION_MODEL_VERSION,
  crossCheckAssumptions,
  isMechanizableEstablisher,
  buildFunctionBodyIndex,
  computeEstablisherWrappers,
  scanViolatingContexts,
  buildFocusedCandidates,
  scanDualViewContexts,
  isCrossApiAssumption,
  objectTypeToken,
  subjectSelfEnforces,
  type Assumption,
  type AssumptionModel,
} from "./assumption-mining.js";
import { buildCallGraph } from "./interproc-refcount.js";

function assumption(over: Partial<Assumption> & Pick<Assumption, "id" | "subject">): Assumption {
  return {
    kind: "refcount-positive",
    predicate: `${over.subject} relies on a held ref`,
    location: over.subject,
    provenance: "relied-on-caller",
    securityRelevance: "lifetime",
    oracle: { mechanism: "establisher-absent-on-path", target: "sk", establisherToken: "sock_hold" },
    ...over,
  } as Assumption;
}

function model(assumptions: Assumption[]): AssumptionModel {
  return {
    modelVersion: ASSUMPTION_MODEL_VERSION,
    subsystem: "test/unit",
    subsystemFiles: ["a.c"],
    assumptions,
    builtAt: new Date().toISOString(),
  };
}

describe("isMechanizableEstablisher", () => {
  it("accepts real call identifiers and rejects prose / punctuation / stopwords", () => {
    expect(isMechanizableEstablisher("sock_hold")).toBe(true);
    expect(isMechanizableEstablisher("ns_capable")).toBe(true);
    expect(isMechanizableEstablisher("the caller checks it")).toBe(false); // has a space
    expect(isMechanizableEstablisher("caller")).toBe(false); // stopword
    expect(isMechanizableEstablisher("")).toBe(false);
    expect(isMechanizableEstablisher("a")).toBe(false); // too short
  });
});

describe("crossCheckAssumptions — STAGE 1b enforced/relied cross-check", () => {
  const bodies = buildFunctionBodyIndex([
    { file: "a.c", text: `
      int enforces(struct sock *sk) { sock_hold(sk); return use(sk); }
      int relies(struct sock *sk) { return use(sk); }
    ` },
  ]);

  it("DROPS an assumption whose establisher token is prose-only (non-mechanizable)", () => {
    const m = model([assumption({ id: "x#1", subject: "relies", oracle: { mechanism: "establisher-absent-on-path", target: "sk", establisherToken: "the caller validates it" } })]);
    const r = crossCheckAssumptions(m, bodies);
    expect(r.kept).toHaveLength(0);
    expect(r.dropped[0].reason).toMatch(/non-mechanizable/);
  });

  it("DROPS an enforced-local claim VERIFIED in the subject body (no external violator)", () => {
    const m = model([assumption({ id: "e#1", subject: "enforces", provenance: "enforced-local" })]);
    const r = crossCheckAssumptions(m, bodies);
    expect(r.kept).toHaveLength(0);
    expect(r.dropped[0].reason).toMatch(/enforced-local verified/);
  });

  it("RECLASSIFIES enforced-local → relied-on-caller when the token is ABSENT in the body, and keeps it", () => {
    const m = model([assumption({ id: "r#1", subject: "relies", provenance: "enforced-local" })]);
    const r = crossCheckAssumptions(m, bodies);
    expect(r.kept).toHaveLength(1);
    expect(r.kept[0].provenance).toBe("relied-on-caller");
    expect(r.reclassified).toHaveLength(1);
  });

  it("DROPS relied-on assumptions whose securityRelevance is off-scope; KEEPS lifetime/bounds/authz/type", () => {
    const m = model([
      assumption({ id: "o#1", subject: "relies", securityRelevance: "other" }),
      assumption({ id: "k#1", subject: "relies", securityRelevance: "authz", oracle: { mechanism: "state-not-established", target: "sk", establisherToken: "ns_capable" } }),
    ]);
    const r = crossCheckAssumptions(m, bodies);
    expect(r.kept.map((a) => a.id)).toEqual(["k#1"]);
    expect(r.dropped.some((d) => d.assumption.id === "o#1")).toBe(true);
  });
});

describe("scanViolatingContexts — establisher-propagation caller-scan", () => {
  // consume() relies on a sock_hold established by its caller. Four callers:
  //   caller_bad  — calls consume() with NO sock_hold        → VIOLATION (unpriv entry)
  //   caller_good — calls sock_hold(sk); consume(sk);         → establishes locally, NOT flagged
  //   mid         — calls consume() with no sock_hold, but its ONLY caller top()
  //                 establishes it → mid INHERITS it          → NOT flagged (the FP-killer)
  //   top         — sock_hold(sk); mid(sk);                   → establishes locally
  const src = `
    int consume(struct sock *sk) { return sk->x; }
    int caller_bad(struct sock *sk) { return consume(sk); }
    int caller_good(struct sock *sk) { sock_hold(sk); return consume(sk); }
    int mid(struct sock *sk) { return consume(sk); }
    int top(struct sock *sk) { sock_hold(sk); return mid(sk); }
  `;
  const sources = [{ file: "a.c", text: src }];
  const cg = buildCallGraph(sources);
  const bodies = buildFunctionBodyIndex(sources);
  const kept = [assumption({ id: "consume#1", subject: "consume" })];

  it("FLAGS the caller that reaches the subject without establishing the precondition", () => {
    const ctx = scanViolatingContexts(kept, cg, sources, bodies);
    expect(ctx.some((c) => c.caller === "caller_bad")).toBe(true);
    const bad = ctx.find((c) => c.caller === "caller_bad")!;
    expect(bad.subject).toBe("consume");
    expect(bad.establisherToken).toBe("sock_hold");
    expect(bad.unprivEntry).toBe(true); // no in-subsystem callers → an entry point
  });

  it("does NOT flag a caller that establishes the token locally", () => {
    const ctx = scanViolatingContexts(kept, cg, sources, bodies);
    expect(ctx.some((c) => c.caller === "caller_good")).toBe(false);
  });

  it("does NOT flag a caller that INHERITS the establisher from its own callers (propagation FP-killer)", () => {
    const ctx = scanViolatingContexts(kept, cg, sources, bodies);
    expect(ctx.some((c) => c.caller === "mid")).toBe(false);
  });

  it("emits exactly one violating context for this fixture (only caller_bad)", () => {
    const ctx = scanViolatingContexts(kept, cg, sources, bodies);
    expect(ctx.map((c) => c.caller)).toEqual(["caller_bad"]);
  });
});

// ── v1: establisher-wrapper resolution (the dominant net/unix FP fix) ────────────

describe("computeEstablisherWrappers — establisher reached through a helper", () => {
  // unix_table_double_lock() wraps spin_lock(); attach_wrapper() wraps it again.
  const src = `
    void unix_table_double_lock(struct u *a, struct u *b) { spin_lock(&h1); spin_lock(&h2); }
    void attach_wrapper(struct u *a, struct u *b) { unix_table_double_lock(a, b); }
    void unrelated(struct u *a) { foo(a); }
  `;
  const cg = buildCallGraph([{ file: "af_unix.c", text: src }]);

  it("marks a one-hop wrapper as establishing the raw token", () => {
    const w = computeEstablisherWrappers(cg, new Set(["spin_lock"]));
    expect(w.get("unix_table_double_lock")?.has("spin_lock")).toBe(true);
  });

  it("resolves a wrapper-of-a-wrapper (bounded transitive closure)", () => {
    const w = computeEstablisherWrappers(cg, new Set(["spin_lock"]));
    expect(w.get("attach_wrapper")?.has("spin_lock")).toBe(true);
  });

  it("does NOT mark an unrelated function", () => {
    const w = computeEstablisherWrappers(cg, new Set(["spin_lock"]));
    expect(w.get("unrelated")?.has("spin_lock")).toBe(false);
  });
});

describe("scanViolatingContexts v1 — wrapper resolution suppresses the dominant v0 FP", () => {
  // Reproduces the net/unix v0 FP shape: the guard IS present, under a wrapper the
  // name-based scan cannot see. Three FP-class-1 callers + one genuine miss:
  //   caller_via_wrapper — establishes via unix_table_double_lock() → v0 FP, v1 clean
  //   caller_via_alias   — establishes via a CMSG_LEN alias         → clean both ways
  //   caller_direct      — calls spin_lock() itself                  → clean both ways
  //   caller_bad         — establishes nothing                       → REAL candidate
  const src = `
    void unix_table_double_lock(struct u *a, struct u *b) { spin_lock(&h1); spin_lock(&h2); }
    int subject_locked(struct sock *sk) { return sk->x; }
    int caller_via_wrapper(struct sock *sk, struct u *a, struct u *b) { unix_table_double_lock(a, b); return subject_locked(sk); }
    int caller_via_alias(struct sock *sk) { int n = CMSG_LEN(0); return subject_locked(sk); }
    int caller_direct(struct sock *sk) { spin_lock(&h1); return subject_locked(sk); }
    int caller_bad(struct sock *sk) { return subject_locked(sk); }
  `;
  const sources = [{ file: "af_unix.c", text: src }];
  const cg = buildCallGraph(sources);
  const bodies = buildFunctionBodyIndex(sources);
  const kept: Assumption[] = [
    assumption({
      id: "subject_locked#1",
      subject: "subject_locked",
      kind: "lock-held",
      oracle: { mechanism: "establisher-absent-on-path", target: "sk", establisherToken: "spin_lock", establisherAliases: ["CMSG_LEN"] },
    }),
  ];

  it("v0 (resolveWrappers:false) flags the wrapper caller as a FALSE POSITIVE", () => {
    const ctx = scanViolatingContexts(kept, cg, sources, bodies, { resolveWrappers: false });
    const callers = ctx.map((c) => c.caller).sort();
    expect(callers).toContain("caller_via_wrapper"); // the FP v1 must kill
    expect(callers).toContain("caller_bad"); // the genuine miss survives both ways
  });

  it("v1 (default) SUPPRESSES the wrapper-established caller, keeps the genuine miss", () => {
    const ctx = scanViolatingContexts(kept, cg, sources, bodies);
    const callers = ctx.map((c) => c.caller);
    expect(callers).not.toContain("caller_via_wrapper"); // FP-class-1 killed
    expect(callers).not.toContain("caller_via_alias"); // alias honored
    expect(callers).not.toContain("caller_direct"); // direct token
    expect(callers).toContain("caller_bad"); // real candidate preserved
  });

  it("wrapper resolution strictly reduces the candidate count (FP-suppression delta)", () => {
    const v0 = scanViolatingContexts(kept, cg, sources, bodies, { resolveWrappers: false });
    const v1 = scanViolatingContexts(kept, cg, sources, bodies);
    expect(v1.length).toBeLessThan(v0.length);
    expect(v1.map((c) => c.caller)).toEqual(["caller_bad"]);
  });

  it("drops the recursion self-edge (a fn is not its own violating caller)", () => {
    // recursive_subject() is its OWN only in-subsystem caller — the v0
    // unix_release_sock-as-its-own-caller artifact. After the self-edge filter it
    // has no violating caller, so it yields zero contexts.
    const recSrc = `int recursive_subject(struct sock *sk) { if (sk) return recursive_subject(sk->next); return sk->x; }`;
    const rs = [{ file: "af_unix.c", text: recSrc }];
    const rcg = buildCallGraph(rs);
    const rbodies = buildFunctionBodyIndex(rs);
    const rkept: Assumption[] = [assumption({ id: "recursive_subject#1", subject: "recursive_subject" })];
    const ctx = scanViolatingContexts(rkept, rcg, rs, rbodies);
    expect(ctx.some((c) => c.caller === "recursive_subject")).toBe(false);
  });
});

describe("buildFocusedCandidates — finder-targeting excerpts", () => {
  const src = `
    int subject_x(struct sock *sk) { return sk->x; }
    int caller_bad(struct sock *sk) { return subject_x(sk); }
  `;
  const sources = [{ file: "big.c", text: src }];
  const cg = buildCallGraph(sources);
  const bodies = buildFunctionBodyIndex(sources);
  const kept: Assumption[] = [assumption({ id: "subject_x#1", subject: "subject_x", oracle: { mechanism: "establisher-absent-on-path", target: "sk", establisherToken: "sock_hold" } })];

  it("writes one small excerpt per violating caller, containing the caller + subject bodies", () => {
    const ctx = scanViolatingContexts(kept, cg, sources, bodies);
    const dir = mkdtempSync(join(tmpdir(), "excerpt-test-"));
    const { candidates, missedCallers } = buildFocusedCandidates(kept, ctx, bodies, dir);
    expect(candidates).toHaveLength(1);
    expect(missedCallers).toHaveLength(0);
    const text = readFileSync(candidates[0].path, "utf8");
    expect(text).toContain("caller_bad");
    expect(text).toContain("subject_x"); // the relied-on subject is included as context
    expect(text).toContain("FOCUSED EXCERPT");
  });

  it("reports a caller whose body is unreadable as missed (per-file fallback)", () => {
    const ctxs = [
      { assumptionId: "subject_x#1", subject: "subject_x", caller: "macro_defined_caller", callerFile: "big.c", callLine: 1, establisherToken: "sock_hold", unprivEntry: true, detail: "x" },
    ];
    const dir = mkdtempSync(join(tmpdir(), "excerpt-test-"));
    const { candidates, missedCallers } = buildFocusedCandidates(kept, ctxs, bodies, dir);
    expect(candidates).toHaveLength(0);
    expect(missedCallers).toEqual(["macro_defined_caller"]);
  });
});

// ── v2: the DUAL-API / CROSS-PHASE enumerator (the high-value mechanism) ──────────

describe("isCrossApiAssumption / objectTypeToken", () => {
  it("selects cross-api by provenance OR by cross-phase kind", () => {
    expect(isCrossApiAssumption(assumption({ id: "a#1", subject: "s", provenance: "relied-on-cross-api" }))).toBe(true);
    expect(isCrossApiAssumption(assumption({ id: "a#2", subject: "s", kind: "ownership-exclusive" }))).toBe(true);
    expect(isCrossApiAssumption(assumption({ id: "a#3", subject: "s", kind: "called-once" }))).toBe(true);
    // plain refcount-positive + relied-on-caller is a caller-scan shape, not dual-view.
    expect(isCrossApiAssumption(assumption({ id: "a#4", subject: "s", kind: "refcount-positive", provenance: "relied-on-caller" }))).toBe(false);
  });

  it("extracts the struct type token, or a bare type ident (len >= 4)", () => {
    expect(objectTypeToken(assumption({ id: "x#1", subject: "s", object: "struct fuse_req" }))).toBe("fuse_req");
    expect(objectTypeToken(assumption({ id: "x#2", subject: "s", object: "dma_buf" }))).toBe("dma_buf");
    // a bare short var is not a usable type token.
    expect(objectTypeToken(assumption({ id: "x#3", subject: "s", object: "req", oracle: { mechanism: "establisher-absent-cross-api", target: "req", establisherToken: "mutex_lock" } }))).toBe(null);
  });
});

describe("scanDualViewContexts — cross-phase distinct-entry pairs", () => {
  // struct dbobj is set up by request_setup() (which takes the object lock) and reached
  // again by reply_write() on a DISTINCT path (neither calls the other) WITHOUT the lock.
  // The dual-view mechanism must pair them; the caller-scan cannot (reply_write is not a
  // caller of request_setup).
  const src = `
    int request_setup(struct dbobj *o) { mutex_lock(&o->lock); o->state = 1; return 0; }
    int reply_write(struct dbobj *o) { o->state = 2; return 0; }
    int unrelated(struct sock *sk) { return sk->x; }
  `;
  const sources = [{ file: "db.c", text: src }];
  const cg = buildCallGraph(sources);
  const bodies = buildFunctionBodyIndex(sources);
  const kept: Assumption[] = [
    assumption({
      id: "reply_write#1",
      subject: "reply_write",
      kind: "ownership-exclusive",
      provenance: "relied-on-cross-api",
      object: "struct dbobj",
      predicate: "the dbobj is stable under mutex_lock across phases",
      oracle: { mechanism: "establisher-absent-cross-api", target: "o", establisherToken: "mutex_lock" },
    }),
  ];

  it("FLAGS the skipping phase paired against the establishing sibling", () => {
    const ctx = scanDualViewContexts(kept, cg, sources, bodies);
    expect(ctx).toHaveLength(1);
    expect(ctx[0].dualView).toBe(true);
    expect(ctx[0].caller).toBe("reply_write"); // the phase that skips mutex_lock
    expect(ctx[0].pairedEntry).toBe("request_setup"); // the phase that establishes it
    expect(ctx[0].object).toBe("dbobj");
    expect(ctx[0].establisherToken).toBe("mutex_lock");
  });

  it("does NOT flag when BOTH phases establish the guarantee", () => {
    const src2 = `
      int request_setup(struct dbobj *o) { mutex_lock(&o->lock); o->state = 1; return 0; }
      int reply_write(struct dbobj *o) { mutex_lock(&o->lock); o->state = 2; return 0; }
    `;
    const s2 = [{ file: "db.c", text: src2 }];
    const ctx = scanDualViewContexts(kept, buildCallGraph(s2), s2, buildFunctionBodyIndex(s2));
    expect(ctx).toHaveLength(0);
  });

  it("does NOT flag when only ONE phase touches the object (no distinct sibling)", () => {
    const src3 = `
      int reply_write(struct dbobj *o) { o->state = 2; return 0; }
      int request_setup(struct sock *sk) { mutex_lock(&sk->lock); return 0; }
    `;
    const s3 = [{ file: "db.c", text: src3 }];
    // request_setup no longer touches dbobj → no establishing view → no pair.
    const ctx = scanDualViewContexts(kept, buildCallGraph(s3), s3, buildFunctionBodyIndex(s3));
    expect(ctx).toHaveLength(0);
  });

  it("does NOT pair two functions in a caller/callee relationship (not distinct phases)", () => {
    // request_setup() establishes mutex_lock then CALLS reply_write() — reply_write
    // inherits the guarantee, and they are not distinct phases. No dual-view pair.
    const src4 = `
      int reply_write(struct dbobj *o) { o->state = 2; return 0; }
      int request_setup(struct dbobj *o) { mutex_lock(&o->lock); return reply_write(o); }
    `;
    const s4 = [{ file: "db.c", text: src4 }];
    const ctx = scanDualViewContexts(kept, buildCallGraph(s4), s4, buildFunctionBodyIndex(s4));
    expect(ctx).toHaveLength(0);
  });

  it("ignores caller-scan-only (non-cross-api) assumptions", () => {
    const plain: Assumption[] = [assumption({ id: "reply_write#2", subject: "reply_write", kind: "refcount-positive", provenance: "relied-on-caller", object: "struct dbobj" })];
    const ctx = scanDualViewContexts(plain, cg, sources, bodies);
    expect(ctx).toHaveLength(0);
  });

  it("SUPPRESSES a ubiquitous object type (struct file) — the instance problem the static grep cannot solve", () => {
    const fsrc = `
      int install_view(struct file *f) { fget(f); return 0; }
      int consume_view(struct file *f) { return f->x; }
    `;
    const fs = [{ file: "f.c", text: fsrc }];
    const fkept: Assumption[] = [
      assumption({ id: "consume_view#1", subject: "consume_view", kind: "ownership-exclusive", provenance: "relied-on-cross-api", object: "struct file", oracle: { mechanism: "establisher-absent-cross-api", target: "f", establisherToken: "fget" } }),
    ];
    const ctx = scanDualViewContexts(fkept, buildCallGraph(fs), fs, buildFunctionBodyIndex(fs));
    expect(ctx).toHaveLength(0); // struct file is on the ubiquitous denylist
  });

  it("SUPPRESSES a type touched by more than maxTouchers functions (pervasive in-subsystem)", () => {
    // struct widget touched by 4 functions; maxTouchers=2 → suppressed as pervasive.
    const wsrc = `
      int w_setup(struct widget *w) { wlock(w); return 0; }
      int w_a(struct widget *w) { return w->a; }
      int w_b(struct widget *w) { return w->b; }
      int w_c(struct widget *w) { return w->c; }
    `;
    const ws = [{ file: "w.c", text: wsrc }];
    const wkept: Assumption[] = [
      assumption({ id: "w_a#1", subject: "w_a", kind: "ownership-exclusive", provenance: "relied-on-cross-api", object: "struct widget", oracle: { mechanism: "establisher-absent-cross-api", target: "w", establisherToken: "wlock" } }),
    ];
    expect(scanDualViewContexts(wkept, buildCallGraph(ws), ws, buildFunctionBodyIndex(ws), { maxTouchers: 2 })).toHaveLength(0);
    // With a generous maxTouchers it fires (w_setup establishes wlock; w_a/w_b/w_c skip).
    expect(scanDualViewContexts(wkept, buildCallGraph(ws), ws, buildFunctionBodyIndex(ws), { maxTouchers: 14 }).length).toBeGreaterThan(0);
  });
});

// ── v2: the precision fix — self-enforcing subjects (kills v1 class-A/C FPs) ──────

describe("subjectSelfEnforces / crossCheckAssumptions — self-enforcing subject drop", () => {
  it("DROPS a subject that flag-tests the object it 'relies on' (class-A/C FP)", () => {
    const bodies = buildFunctionBodyIndex([
      { file: "a.c", text: `int guarded(struct sock *sk) { if (sk->flags & SOCK_DEAD) return -1; return use(sk); }` },
    ]);
    const a = assumption({
      id: "g#1",
      subject: "guarded",
      kind: "state-precondition",
      provenance: "relied-on-caller",
      oracle: { mechanism: "state-not-established", target: "sk->flags", establisherToken: "sock_hold" },
    });
    expect(subjectSelfEnforces(bodies.get("guarded")!, a)).toMatch(/flag-tests/);
    const r = crossCheckAssumptions(model([a]), bodies);
    expect(r.kept).toHaveLength(0);
    expect(r.dropped[0].reason).toMatch(/self-enforcing/);
  });

  it("DROPS a lock-held subject that lockdep_assert_held its contract", () => {
    const bodies = buildFunctionBodyIndex([
      { file: "a.c", text: `int lo004(struct sock *sk) { lockdep_assert_held(&sk->lock); return sk->x; }` },
    ]);
    const a = assumption({ id: "l#1", subject: "lo004", kind: "lock-held", provenance: "relied-on-caller", oracle: { mechanism: "establisher-absent-on-path", target: "sk", establisherToken: "spin_lock" } });
    const r = crossCheckAssumptions(model([a]), bodies);
    expect(r.kept).toHaveLength(0);
    expect(r.dropped[0].reason).toMatch(/lockdep_assert_held|self-enforcing/);
  });

  it("does NOT drop a genuine relied-on subject with no self-guard", () => {
    const bodies = buildFunctionBodyIndex([
      { file: "a.c", text: `int relies(struct sock *sk) { return use(sk); }` },
    ]);
    const a = assumption({ id: "r#1", subject: "relies", provenance: "relied-on-caller" });
    expect(subjectSelfEnforces(bodies.get("relies")!, a)).toBe(null);
    const r = crossCheckAssumptions(model([a]), bodies);
    expect(r.kept).toHaveLength(1);
  });

  it("does NOT drop when an unrelated guard tests a DIFFERENT object (targeted, no over-drop)", () => {
    const bodies = buildFunctionBodyIndex([
      { file: "a.c", text: `int relies(struct sock *sk, int mode) { if (mode & O_RDONLY) log(); return use(sk); }` },
    ]);
    // assumption is about sk (lifetime), the guard flag-tests 'mode' — must NOT drop.
    const a = assumption({ id: "r#2", subject: "relies", provenance: "relied-on-caller", oracle: { mechanism: "establisher-absent-on-path", target: "sk", establisherToken: "sock_hold" } });
    expect(subjectSelfEnforces(bodies.get("relies")!, a)).toBe(null);
    const r = crossCheckAssumptions(model([a]), bodies);
    expect(r.kept).toHaveLength(1);
  });
});

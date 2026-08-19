/**
 * Tests for the INTER-PROCEDURAL refcount coupling checker
 * ({@link ./interproc-refcount.ts}) — the capability the intra-procedural
 * dataflow engine ({@link ./c-dataflow.ts}) structurally cannot provide.
 *
 * The headline case each fixture models: a refcount get/put whose actual
 * ops (refcount_inc/refcount_dec, sock_hold/sock_put) live ONLY inside wrapper
 * functions defined in a DIFFERENT file, so the caller file has zero direct
 * refcount ops and the intra-proc per-function counter sees nothing. The
 * inter-proc checker resolves the wrappers through a name-based call graph and
 * pairs the get/put across the file boundary.
 *
 * No LLM, no mocks — the checker is a pure function over (model, sources).
 */

import { describe, expect, it } from "vitest";
import {
  buildCallGraph,
  resolveWrapperOps,
  findInterprocRefcountCouplings,
  couplingsToHuntPlan,
  isRefcountLikeRule,
  isDestructorFamily,
} from "./interproc-refcount.js";
import { findViolationsDataflow } from "./c-dataflow.js";
import { INVARIANT_MODEL_VERSION } from "./subsystem-invariant-model.js";

type InvariantModel = Parameters<typeof findInterprocRefcountCouplings>[0];

// ── The refcount library file (file 2): defines the get/put WRAPPERS whose
//    bodies contain the actual refcount_inc / refcount_dec. Mirrors the role
//    af_netlink.c plays for mqueue's notify_sock (sock_hold/sock_put wrappers). ──
const DEV_CORE_C = `
struct dev { int ref; };

/* get-wrapper: holds a ref and RETURNS the held object */
struct dev *dev_get(struct dev *d)
{
	refcount_inc(&d->ref);
	return d;
}

/* put-wrapper: releases a ref passed in as a parameter */
void dev_put(struct dev *d)
{
	refcount_dec(&d->ref);
}
`;

// The model an analyst would emit: the RAW ops are refcount_inc / refcount_dec.
// The checker must discover dev_get / dev_put as their wrappers on its own.
function devModel(): InvariantModel {
  return {
    modelVersion: INVARIANT_MODEL_VERSION,
    subsystem: "test/dev",
    subsystemFiles: ["dev_core.c", "caller.c"],
    objects: [
      {
        object: "struct dev",
        lockRules: [],
        refcountRules: [{ name: "dev ref", getFn: "refcount_inc", putFn: "refcount_dec" }],
        lifecycleRules: [],
      },
    ],
    builtAt: new Date().toISOString(),
  } as InvariantModel;
}

const run = (callerText: string) =>
  findInterprocRefcountCouplings(devModel(), [
    { file: "dev_core.c", text: DEV_CORE_C },
    { file: "caller.c", text: callerText },
  ]);

// The coupling that ORIGINATES in the caller file (get called there), i.e. the
// cross-file pairing — not dev_get's own internal refcount_inc self-coupling.
const callerCouplings = (cs: ReturnType<typeof run>) =>
  cs.filter((c) => c.getSite.file === "caller.c");

describe("call-graph wrapper resolution (the cross-file join)", () => {
  it("resolves dev_get as a get-wrapper and dev_put as a put-wrapper, across files", () => {
    const cg = buildCallGraph([
      { file: "dev_core.c", text: DEV_CORE_C },
      { file: "caller.c", text: "void f(struct mgr *m){ struct dev *d = dev_get(m->dev); dev_put(d); }" },
    ]);
    const { getOps, putOps } = resolveWrapperOps(cg, {
      name: "dev ref",
      getFn: "refcount_inc",
      putFn: "refcount_dec",
    });
    // raw op + discovered wrapper
    expect([...getOps.keys()]).toEqual(expect.arrayContaining(["refcount_inc", "dev_get"]));
    expect([...putOps.keys()]).toEqual(expect.arrayContaining(["refcount_dec", "dev_put"]));
    // provenance points back at the file the raw op actually lives in
    expect(getOps.get("dev_get")?.resolvedFile).toBe("dev_core.c");
    expect(getOps.get("dev_get")?.rawOp).toBe("refcount_inc");
    expect(putOps.get("dev_put")?.resolvedFile).toBe("dev_core.c");
  });
});

// ── FIXTURE A: a REAL cross-file get-without-put → MUST flag leak-suspect ────────
describe("(A) cross-file get without put → leak-suspect", () => {
  // gets a ref via the cross-file wrapper, parks it in a field, never releases.
  const LEAKY_C = `
struct mgr { struct dev *cached; };

void mgr_attach(struct mgr *m)
{
	struct dev *d = dev_get(m->dev);
	m->cached = d;
}
`;

  it("flags the leak, and the coupling spans files", () => {
    const cs = callerCouplings(run(LEAKY_C));
    const leak = cs.find((c) => c.getSite.fn === "mgr_attach");
    expect(leak).toBeDefined();
    expect(leak!.verdict).toBe("leak-suspect");
    expect(leak!.crossFile).toBe(true);
    // the get resolves to the raw op in the OTHER file
    expect(leak!.getSite.callee).toBe("dev_get");
    expect(leak!.getSite.rawOp).toBe("refcount_inc");
    expect(leak!.getSite.resolvedFile).toBe("dev_core.c");
    expect(leak!.getSite.storedField).toBe("cached");
    expect(leak!.putSites).toHaveLength(0);
  });

  it("the intra-proc engine is STRUCTURALLY BLIND to it (no direct op in the caller file)", () => {
    // c-dataflow's refcount check counts direct refcount_inc/refcount_dec per
    // function. caller.c has NONE (only the wrappers) → it emits nothing for the
    // caller file. This is the exact gap this module closes.
    const intra = findViolationsDataflow(devModel(), [{ file: "caller.c", text: LEAKY_C }], {
      refcountCheck: true,
    });
    expect(intra.filter((v) => v.file === "caller.c")).toHaveLength(0);
  });
});

// ── FIXTURE B: a BALANCED cross-file get/put → MUST NOT flag ─────────────────────
describe("(B) cross-file get with matching put → balanced (no flag)", () => {
  const BALANCED_C = `
void mgr_use(struct mgr *m)
{
	struct dev *d = dev_get(m->dev);
	do_stuff(d);
	dev_put(d);
}
`;

  it("does NOT flag it: the put-wrapper release is paired across the file boundary", () => {
    const cs = callerCouplings(run(BALANCED_C));
    const c = cs.find((x) => x.getSite.fn === "mgr_use");
    expect(c).toBeDefined();
    expect(c!.verdict).toBe("balanced");
    // it STILL generated the coupling (coverage), just did not escalate it
    expect(c!.crossFile).toBe(true);
    expect(c!.putSites.map((p) => p.callee)).toContain("dev_put");
    // and it is not surfaced as a hunt candidate (only non-balanced are, by default)
    const plan = couplingsToHuntPlan(devModel(), cs);
    expect(plan.candidates).toHaveLength(0);
  });
});

// ── FIXTURE C: the notify_sock SHAPE — get in one fn, put via a stored field in
//    ANOTHER fn (cross-function AND cross-file). MUST generate + be balanced. ─────
describe("(C) get stored in a field, released in another function via the field", () => {
  const STORED_FIELD_C = `
struct mgr { struct dev *slot; };

/* GET here, stash the ref in ->slot */
void mgr_arm(struct mgr *m)
{
	struct dev *d = dev_get(m->dev);
	m->slot = d;
}

/* RELEASE happens in a DIFFERENT function, through the stored field */
void mgr_disarm(struct mgr *m)
{
	dev_put(m->slot);
}
`;

  it("pairs the get to the put across BOTH the function and file boundary", () => {
    const c = callerCouplings(run(STORED_FIELD_C)).find((x) => x.getSite.fn === "mgr_arm");
    expect(c).toBeDefined();
    expect(c!.getSite.storedField).toBe("slot");
    expect(c!.crossFile).toBe(true);
    expect(c!.crossFunction).toBe(true);
    expect(c!.verdict).toBe("balanced");
    // the matched put is the one in the OTHER function, matched by the stored field
    const fieldPut = c!.putSites.find((p) => p.matchedBy === "stored-field");
    expect(fieldPut).toBeDefined();
    expect(fieldPut!.fn).toBe("mgr_disarm");
  });

  it("becomes a hunt candidate only when the release is REMOVED (real leak)", () => {
    const LEAK = STORED_FIELD_C.replace("dev_put(m->slot);", "/* release forgotten */");
    const c = callerCouplings(run(LEAK)).find((x) => x.getSite.fn === "mgr_arm");
    expect(c!.verdict).toBe("leak-suspect");
    const plan = couplingsToHuntPlan(devModel(), callerCouplings(run(LEAK)));
    expect(plan.candidates.length).toBeGreaterThan(0);
    expect(plan.candidates[0].path).toBe("caller.c");
  });
});

// ── A get-wrapper's OWN body (return the held ref) must be balanced, not a leak ──
describe("ownership-transfer-by-return is not a leak", () => {
  it("dev_get itself (sock_hold; return sock) is balanced", () => {
    const cs = run("void noop(void){}");
    const self = cs.find((c) => c.getSite.fn === "dev_get");
    expect(self).toBeDefined();
    expect(self!.verdict).toBe("balanced"); // returned to caller, not leaked
  });
});

// ── REFINEMENT 1: destructor / free-path-aware put resolution + direct field store
//    The #1 FP: a get whose RESULT is assigned STRAIGHT into `obj->field`
//    (`sk->sk_peer_pid = get_pid(...)`), released only in the object's DESTRUCTOR
//    in a different function/file. The old checker set no `storedField` (there is
//    no separate `field = var` copy), so the cross-function field match was off. ─
describe("(REFINEMENT 1) direct field-store released in a destructor → balanced", () => {
  // The GET assigns the raw op's result directly into ->peer (no temp var). The
  // ONLY release is put_pid(x->peer) inside a *_destructor function.
  const PID_CORE_C = `
struct pid;
struct pid *get_pid(struct pid *p) { refcount_inc(&p->count); return p; }
void put_pid(struct pid *p) { refcount_dec(&p->count); }
`;
  const pidModel = (): InvariantModel =>
    ({
      modelVersion: INVARIANT_MODEL_VERSION,
      subsystem: "test/peercred",
      subsystemFiles: ["pid_core.c", "sock.c"],
      objects: [
        {
          object: "struct sock",
          lockRules: [],
          refcountRules: [{ name: "peer pid", getFn: "get_pid", putFn: "put_pid" }],
          lifecycleRules: [],
        },
      ],
      builtAt: new Date().toISOString(),
    }) as InvariantModel;

  const runPid = (sockText: string) =>
    findInterprocRefcountCouplings(pidModel(), [
      { file: "pid_core.c", text: PID_CORE_C },
      { file: "sock.c", text: sockText },
    ]).filter((c) => c.getSite.file === "sock.c");

  it("(a) result assigned directly into ->peer records storedField", () => {
    const SOCK = `
void init_peercred(struct sock *sk) {
	sk->sk_peer_pid = get_pid(task_tgid(current));
}
void sock_destructor(struct sock *sk) {
	put_pid(sk->sk_peer_pid);
}
`;
    const c = runPid(SOCK).find((x) => x.getSite.fn === "init_peercred");
    expect(c).toBeDefined();
    expect(c!.getSite.storedField).toBe("sk_peer_pid"); // recovered from the direct field store
    expect(c!.verdict).toBe("balanced");
    // paired to the release inside the destructor-family function, cross-function
    const put = c!.putSites.find((p) => p.matchedBy === "stored-field");
    expect(put).toBeDefined();
    expect(put!.fn).toBe("sock_destructor");
    expect(put!.fromDestructor).toBe(true);
  });

  it("(b) destructor releases via a local copied from the field (pid = sk->..; put_pid(pid))", () => {
    const SOCK = `
void init_peercred(struct sock *sk) {
	sk->sk_peer_pid = get_pid(task_tgid(current));
}
void __sk_destruct(struct sock *sk) {
	struct pid *pid = sk->sk_peer_pid;
	put_pid(pid);
}
`;
    const c = runPid(SOCK).find((x) => x.getSite.fn === "init_peercred");
    expect(c!.verdict).toBe("balanced");
    const put = c!.putSites.find((p) => p.matchedBy === "stored-field");
    expect(put).toBeDefined();
    expect(put!.fieldViaAlias).toBe(true); // argField recovered from the local copy
    expect(put!.fromDestructor).toBe(true);
  });

  it("but a direct field-store with NO release anywhere still flags (no over-suppression)", () => {
    const SOCK = `
void init_peercred(struct sock *sk) {
	sk->sk_peer_pid = get_pid(task_tgid(current));
}
void unrelated(struct sock *sk) { do_stuff(sk); }
`;
    const c = runPid(SOCK).find((x) => x.getSite.fn === "init_peercred");
    expect(c!.getSite.storedField).toBe("sk_peer_pid");
    expect(c!.verdict).toBe("leak-suspect");
    expect(c!.putSites).toHaveLength(0);
  });

  it("isDestructorFamily recognizes the free/release/put/evict/destruct family", () => {
    for (const n of ["__sk_destruct", "unix_sock_destructor", "foo_free", "bar_release", "x_evict", "y_put", "z_destroy"])
      expect(isDestructorFamily(n)).toBe(true);
    for (const n of ["init_peercred", "do_connect", "lookup_sock"]) expect(isDestructorFamily(n)).toBe(false);
  });
});

// ── REFINEMENT 2: multi-hop (>=2) return-ownership. A get-wrapper's result
//    returned inline (`return get(...)`) transfers the ref; and a wrapper of a
//    wrapper of a wrapper that keeps returning the ref is balanced at every hop. ─
describe("(REFINEMENT 2) multi-hop return-ownership is not a leak", () => {
  it("inline `return dev_get(x)` (1 hop, no temp var) is balanced, not a leak", () => {
    // The old 1-hop var check saw returnBases={dev_get} and refBase=x → mis-flagged.
    const cs = callerCouplings(run("struct dev *lookup(struct mgr *m){ return dev_get(m->dev); }"));
    const c = cs.find((x) => x.getSite.fn === "lookup");
    expect(c).toBeDefined();
    expect(c!.verdict).toBe("balanced"); // ref handed to the caller inline
  });

  it("a 3-hop return chain (A gets+returns, B returns A, C returns B) is balanced at every hop", () => {
    // A: var-return get-wrapper; B: inline-returns A's result; C: inline-returns B.
    const CHAIN = `
struct dev *A(struct mgr *m){ struct dev *d = dev_get(m->dev); return d; }
struct dev *B(struct mgr *m){ return A(m); }
struct dev *C(struct mgr *m){ return B(m); }
`;
    const cs = callerCouplings(run(CHAIN));
    for (const fn of ["A", "B", "C"]) {
      const c = cs.find((x) => x.getSite.fn === fn);
      expect(c, `expected a coupling at ${fn}`).toBeDefined();
      expect(c!.verdict, `${fn} should transfer ownership up the chain`).toBe("balanced");
    }
    // and the whole chain is recognized as get-wrappers (transitive resolution)
    const cg = buildCallGraph([
      { file: "dev_core.c", text: DEV_CORE_C },
      { file: "caller.c", text: CHAIN },
    ]);
    const { getOps } = resolveWrapperOps(cg, { name: "dev ref", getFn: "refcount_inc", putFn: "refcount_dec" });
    expect([...getOps.keys()]).toEqual(expect.arrayContaining(["dev_get", "A", "B", "C"]));
  });
});

// ── REFINEMENT 3: rule-quality filter — reject non-refcount pairs up front ────────
describe("(REFINEMENT 3) non-refcount rules are rejected before the checker runs", () => {
  it("isRefcountLikeRule rejects atomic counters, alloc pairs, page/module refs, junk", () => {
    const reject = [
      { name: "atomic", getFn: "atomic_inc", putFn: "atomic_dec" },
      { name: "alloc", getFn: "kzalloc", putFn: "kfree" },
      { name: "skb", getFn: "alloc_skb", putFn: "kfree_skb" },
      { name: "page", getFn: "get_page", putFn: "put_page" },
      { name: "module", getFn: "try_module_get", putFn: "module_put" },
      { name: "sk_msg", getFn: "sk_msg_alloc", putFn: "sk_msg_free" },
      { name: "void-junk", getFn: "void", putFn: "" },
      { name: "pf-junk", getFn: "pf", putFn: "pf" },
      { name: "same", getFn: "sock_hold", putFn: "sock_hold" },
    ];
    for (const r of reject) expect(isRefcountLikeRule(r), `${r.getFn}/${r.putFn} should be rejected`).toBe(false);
  });

  it("isRefcountLikeRule accepts real object get/put pairs", () => {
    const accept = [
      { name: "sock", getFn: "sock_hold", putFn: "sock_put" },
      { name: "pid", getFn: "get_pid", putFn: "put_pid" },
      { name: "refcount_t", getFn: "refcount_inc", putFn: "refcount_dec" },
      { name: "llcp", getFn: "nfc_llcp_local_get", putFn: "nfc_llcp_local_put" },
      { name: "xfrm", getFn: "xfrm_state_hold", putFn: "xfrm_state_put" },
      { name: "key", getFn: "key_get", putFn: "key_put" },
    ];
    for (const r of accept) expect(isRefcountLikeRule(r), `${r.getFn}/${r.putFn} should be accepted`).toBe(true);
  });

  it("a model mixing a real rule with noise emits ONLY the real coupling", () => {
    // atomic_inc/atomic_dec appears all over the caller, but must produce nothing.
    const NOISY = `
void hot(struct mgr *m) {
	atomic_inc(&m->users);
	struct dev *d = dev_get(m->dev);
	dev_put(d);
	atomic_dec(&m->users);
}
`;
    const model: InvariantModel = {
      modelVersion: INVARIANT_MODEL_VERSION,
      subsystem: "test/dev",
      subsystemFiles: ["dev_core.c", "caller.c"],
      objects: [
        {
          object: "struct dev",
          lockRules: [],
          refcountRules: [
            { name: "atomic noise", getFn: "atomic_inc", putFn: "atomic_dec" },
            { name: "dev ref", getFn: "refcount_inc", putFn: "refcount_dec" },
          ],
          lifecycleRules: [],
        },
      ],
      builtAt: new Date().toISOString(),
    } as InvariantModel;
    const cs = findInterprocRefcountCouplings(model, [
      { file: "dev_core.c", text: DEV_CORE_C },
      { file: "caller.c", text: NOISY },
    ]);
    // no coupling should carry the rejected rule's name
    expect(cs.some((c) => c.refcount === "atomic noise")).toBe(false);
    // the real dev-ref coupling in hot() is present and balanced
    const real = cs.find((c) => c.getSite.fn === "hot" && c.refcount === "dev ref");
    expect(real).toBeDefined();
    expect(real!.verdict).toBe("balanced");
  });
});

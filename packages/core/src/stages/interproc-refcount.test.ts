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

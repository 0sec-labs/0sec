/**
 * Precision tests for the REAL intra-procedural dataflow finder
 * ({@link findViolationsDataflow}) vs the legacy token-level over-approximation
 * ({@link findInvariantViolationsTokenLevel}).
 *
 * Each fixture below is a case where the two finders DISAGREE — and the dataflow
 * finder is the correct one. The final `describe` measures the concrete
 * false-positive-rate delta on one combined fixture: the whole point of the
 * upgrade is that M (dataflow flags) << N (token flags) with no true-positive loss.
 *
 * No LLM, no mocks — the finder is a pure function over (model, source).
 */

import { describe, expect, it } from "vitest";
import { findViolationsDataflow, normalizeLockToken, parseC } from "./c-dataflow.js";
import { findInvariantViolationsTokenLevel } from "./subsystem-invariant-model.js";
import { INVARIANT_MODEL_VERSION } from "./subsystem-invariant-model.js";

type InvariantModel = Parameters<typeof findViolationsDataflow>[0];

// ── Model: struct conn, lock c->lock guards ->state, kfree lifecycle, conn refcount ──
function connModel(): InvariantModel {
  return {
    modelVersion: INVARIANT_MODEL_VERSION,
    subsystem: "test/conn",
    subsystemFiles: ["conn.c"],
    objects: [
      {
        object: "struct conn",
        lockRules: [{ lock: "c->lock", guardedFields: ["state"] }],
        refcountRules: [{ name: "conn ref", getFn: "conn_get", putFn: "conn_put" }],
        lifecycleRules: [{ freeFn: "kfree", note: "frees struct conn" }],
      },
    ],
    builtAt: new Date().toISOString(),
  } as InvariantModel;
}

const df = (src: string, refcountCheck = true) =>
  findViolationsDataflow(connModel(), [{ file: "conn.c", text: src }], { refcountCheck });
const tok = (src: string, refcountCheck = true) =>
  findInvariantViolationsTokenLevel(connModel(), [{ file: "conn.c", text: src }], { refcountCheck });

const fnsFlagged = (vs: ReturnType<typeof df>, kind: string) =>
  vs.filter((v) => v.kind === kind).map((v) => v.functionName);

describe("normalizeLockToken (resolve lock to struct field)", () => {
  it("splits receiver / field and detects globals", () => {
    expect(normalizeLockToken("f->lock")).toEqual({ key: "f->lock", lockField: "lock", receiver: "f", global: false });
    expect(normalizeLockToken("&local->sockets.lock")).toEqual({
      key: "local->sockets->lock",
      lockField: "lock",
      receiver: "local->sockets",
      global: false,
    });
    expect(normalizeLockToken("sk->sk_lock.slock")).toMatchObject({ lockField: "slock", global: false });
    expect(normalizeLockToken("llcp_devices_lock")).toEqual({
      key: "llcp_devices_lock",
      lockField: "llcp_devices_lock",
      receiver: "",
      global: true,
    });
  });
});

describe("sanity: parser loads", () => {
  it("parses a trivial function", () => {
    const root = parseC("int f(void){ return 0; }");
    expect(root?.type).toBe("translation_unit");
  });
});

// ── (a)+(e) lock HELD at the access point, cross-function naming → NO flag ────────
describe("(a)/(e) lock held at access point, resolved to the struct field", () => {
  // Object is named `d` here, not `c` as in the model token — the dataflow finder
  // resolves the guarding lock from the ACCESS RECEIVER, so `d->lock` guards
  // `d->state`. The token-level finder ties the lock literally to `c->lock`,
  // never sees `spin_lock(&d->lock)`, and FALSE-FLAGS the compliant accessor.
  const src = `
void access_other(struct conn *d)
{
	spin_lock(&d->lock);
	d->state = 2;
	spin_unlock(&d->lock);
}`;

  it("dataflow does NOT flag it (lock held, receiver-resolved)", () => {
    expect(fnsFlagged(df(src), "unlocked-field-access")).not.toContain("access_other");
  });

  it("token-level FALSELY flags it (cross-function naming defeats literal token match)", () => {
    expect(fnsFlagged(tok(src), "unlocked-field-access")).toContain("access_other");
  });
});

// ── (b) same field on a path where the lock was RELEASED → flag ──────────────────
describe("(b) access after the lock is released on the path", () => {
  const src = `
int access_after_unlock(struct conn *c)
{
	spin_lock(&c->lock);
	int tmp = c->state;
	spin_unlock(&c->lock);
	return c->state;
}`;

  it("dataflow FLAGS the post-unlock access (held-set is empty at that point)", () => {
    const uf = df(src).filter((v) => v.kind === "unlocked-field-access" && v.functionName === "access_after_unlock");
    expect(uf).toHaveLength(1);
    // it flags the RETURN line (post-unlock), not the guarded read
    expect(uf[0].line).toBe(7);
  });

  it("token-level MISSES it (body acquires the lock 'somewhere' → false negative)", () => {
    expect(fnsFlagged(tok(src), "unlocked-field-access")).not.toContain("access_after_unlock");
  });
});

// ── (c) free on an error branch that returns + use on the success branch → NO flag ─
describe("(c) free on a returning error branch, use on the success branch", () => {
  const src = `
int free_err_branch(struct conn *c, int err)
{
	if (err) {
		kfree(c);
		return -1;
	}
	return c->id;
}`;

  it("dataflow does NOT flag it (the freeing branch returns; free never reaches the use)", () => {
    expect(fnsFlagged(df(src), "use-after-free-order")).not.toContain("free_err_branch");
  });

  it("token-level FALSELY flags it (path-insensitive: textual free then textual use)", () => {
    expect(fnsFlagged(tok(src), "use-after-free-order")).toContain("free_err_branch");
  });
});

// ── (d) genuine use-after-free on the same path → flag (both correct) ─────────────
describe("(d) genuine same-path use-after-free", () => {
  const src = `
void free_then_use(struct conn *c)
{
	kfree(c);
	c->id = 0;
}`;

  it("dataflow FLAGS it", () => {
    expect(fnsFlagged(df(src), "use-after-free-order")).toContain("free_then_use");
  });
  it("token-level also flags it (no true-positive loss)", () => {
    expect(fnsFlagged(tok(src), "use-after-free-order")).toContain("free_then_use");
  });
});

// ── field-granular free: cleanup `c->buf = NULL` after kfree(c->buf) → NO flag ────
describe("field-granular free tracking (reassignment kill)", () => {
  const src = `
void free_reassign(struct conn *c)
{
	kfree(c->buf);
	c->buf = NULL;
}`;

  it("dataflow does NOT flag the cleanup write (exact key reassigned)", () => {
    expect(fnsFlagged(df(src), "use-after-free-order")).not.toContain("free_reassign");
  });
  it("token-level FALSELY flags it (tracks the base var `c`, sees `c->buf` deref)", () => {
    expect(fnsFlagged(tok(src), "use-after-free-order")).toContain("free_reassign");
  });
});

// ── genuinely-unlocked read → flag (both correct, no TP loss) ─────────────────────
describe("genuine unlocked read (true positive, both finders)", () => {
  const src = `
int read_racy(struct conn *c)
{
	return c->state;
}`;
  it("dataflow flags it", () => {
    expect(fnsFlagged(df(src), "unlocked-field-access")).toContain("read_racy");
  });
  it("token-level flags it too", () => {
    expect(fnsFlagged(tok(src), "unlocked-field-access")).toContain("read_racy");
  });
});

// ── The headline number: FP-rate delta on one combined subsystem fixture ─────────
describe("A/B false-positive delta on a combined fixture", () => {
  // 8 functions. 3 are GENUINE bugs (read_racy, access_after_unlock, free_then_use).
  // 5 are COMPLIANT (access_locked, access_other, free_err_branch, free_reassign,
  // free_clean). A perfect finder flags exactly the 3 true positives.
  const COMBINED = `
struct conn { spinlock_t lock; int state; int id; void *buf; };

/* COMPLIANT: lock held at access */
void access_locked(struct conn *c)
{
	spin_lock(&c->lock);
	c->state = 1;
	spin_unlock(&c->lock);
}

/* COMPLIANT: cross-named receiver, lock held */
void access_other(struct conn *d)
{
	spin_lock(&d->lock);
	d->state = 2;
	spin_unlock(&d->lock);
}

/* BUG: never locked */
int read_racy(struct conn *c)
{
	return c->state;
}

/* BUG: accessed after unlock */
int access_after_unlock(struct conn *c)
{
	spin_lock(&c->lock);
	int tmp = c->state;
	spin_unlock(&c->lock);
	return c->state;
}

/* COMPLIANT: free on returning error branch, use on success branch */
int free_err_branch(struct conn *c, int err)
{
	if (err) {
		kfree(c);
		return -1;
	}
	return c->id;
}

/* BUG: genuine same-path UAF */
void free_then_use(struct conn *c)
{
	kfree(c);
	c->id = 0;
}

/* COMPLIANT: field freed then reassigned */
void free_reassign(struct conn *c)
{
	kfree(c->buf);
	c->buf = NULL;
}

/* COMPLIANT: free then return, no use */
void free_clean(struct conn *c)
{
	kfree(c);
	return;
}
`;

  const TRUE_POSITIVE_FNS = new Set(["read_racy", "access_after_unlock", "free_then_use"]);

  it("dataflow keeps every true positive and drops the token-level false positives", () => {
    // refcount off: it's a separate heuristic, not the subject of this comparison.
    const dfV = findViolationsDataflow(connModel(), [{ file: "conn.c", text: COMBINED }], { refcountCheck: false });
    const tokV = findInvariantViolationsTokenLevel(connModel(), [{ file: "conn.c", text: COMBINED }], { refcountCheck: false });

    const dfFns = new Set(dfV.map((v) => v.functionName));
    const tokFns = new Set(tokV.map((v) => v.functionName));

    const dfFp = [...dfFns].filter((f) => !TRUE_POSITIVE_FNS.has(f));
    const tokFp = [...tokFns].filter((f) => !TRUE_POSITIVE_FNS.has(f));
    const dfTp = [...dfFns].filter((f) => TRUE_POSITIVE_FNS.has(f));
    const tokTp = [...tokFns].filter((f) => TRUE_POSITIVE_FNS.has(f));

    // Surface the numbers in the test output.
    // eslint-disable-next-line no-console
    console.log(
      `[FP-delta] token-level: ${tokV.length} flags on ${tokFns.size} fns (TP fns=${tokTp.length}, FP fns=${tokFp.sort().join(",")}) | ` +
        `dataflow: ${dfV.length} flags on ${dfFns.size} fns (TP fns=${dfTp.length}, FP fns=${dfFp.length ? dfFp.sort().join(",") : "none"})`,
    );

    // No true-positive loss: dataflow catches all 3 real bugs.
    expect(dfTp.sort()).toEqual([...TRUE_POSITIVE_FNS].sort());
    // dataflow has ZERO function-level false positives.
    expect(dfFp).toEqual([]);
    // token-level has strictly MORE false positives than dataflow.
    expect(tokFp.length).toBeGreaterThan(dfFp.length);
    // and token-level flags strictly more functions overall (the over-approximation).
    expect(tokFns.size).toBeGreaterThan(dfFns.size);
  });
});

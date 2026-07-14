/**
 * subsystem-invariant-model — the SEEDLESS discovery axis.
 *
 * Three things proven here against a small synthetic C fixture (written to a real
 * temp tree) with KNOWN invariant violations:
 *   (a) MODEL-BUILD emits a structured, storable per-object model (LLM mocked at
 *       the `../runtime/llm-api.js` boundary — no key, no real call).
 *   (b) the DETERMINISTIC violation finder flags the KNOWN-bad paths and NOT the
 *       compliant ones (no LLM at all — pure function over model + source).
 *   (c) the emitted candidates COMPOSE into `runHuntScan` end-to-end (finder
 *       `agenticScan` mocked; verify = a real `composeGate` of fake stages), so
 *       seedless → candidate → verified → ranked is exercised with zero LLM.
 *
 * Only the LLM (`llm-api`) and finder (`agentic-scanner`) boundaries are mocked;
 * the filesystem is REAL (temp tree) so the store/load round-trip is genuine.
 */

import { mkdtempSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "@pwnkit/shared";

// LLM boundary — used only by buildInvariantModel.
const executeNativeMock = vi.fn();
vi.mock("../runtime/llm-api.js", () => ({
  LlmApiRuntime: class {
    executeNative(...args: unknown[]) {
      return executeNativeMock(...args);
    }
  },
}));

// Finder boundary — used only when candidates flow through runHuntScan.
const agenticScanMock = vi.fn();
vi.mock("../agentic-scanner.js", () => ({
  agenticScan: (...args: unknown[]) => agenticScanMock(...args),
}));

const {
  buildInvariantModel,
  storeInvariantModel,
  loadInvariantModel,
  findInvariantViolations,
  violationsToHuntPlan,
  splitCFunctions,
  runSubsystemInvariantHunt,
  INVARIANT_MODEL_VERSION,
} = await import("./subsystem-invariant-model.js");
const { runHuntScan, composeGate } = await import("./hunt-scan.js");
type InvariantModel = Awaited<ReturnType<typeof buildInvariantModel>>;

// ── Synthetic fixture: a `struct foo` with a lock guarding ->state, a refcount,
//    and a free. Known violations are labeled inline. ──────────────────────────
const FIXTURE_C = `
struct foo {
	spinlock_t lock;
	int state;
	int refs;
};

/* COMPLIANT: acquires foo->lock before touching ->state. Must NOT be flagged. */
void foo_set_state_locked(struct foo *f, int s)
{
	spin_lock(&f->lock);
	f->state = s;   /* guarded */
	spin_unlock(&f->lock);
}

/* VIOLATION (unlocked-field-access): reads ->state with no foo->lock. */
int foo_get_state_racy(struct foo *f)
{
	return f->state;
}

/* VIOLATION (use-after-free-order): kfree(f) then f->state. */
void foo_free_and_use(struct foo *f)
{
	kfree(f);
	f->state = 0;
}

/* COMPLIANT free: kfree(f) then returns, no later use. Must NOT be flagged. */
void foo_free_clean(struct foo *f)
{
	kfree(f);
	return;
}

/* VIOLATION (refcount-imbalance): foo_put with no foo_get. */
void foo_drop(struct foo *f)
{
	foo_put(f);
}
`;

const MODEL_OBJECT = {
  object: "struct foo",
  allocSite: "foo_alloc",
  freeSite: "foo_free_clean",
  lockRules: [{ lock: "f->lock", guardedFields: ["state"], acquireFns: ["spin_lock"] }],
  refcountRules: [{ name: "foo refs", getFn: "foo_get", putFn: "foo_put" }],
  lifecycleRules: [{ freeFn: "kfree", note: "frees struct foo" }],
  initOrder: ["state"],
};

/** Write the fixture into a fresh temp source tree; return its root. */
function makeSourceRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "invsrc-"));
  mkdirSync(join(root, "test", "foo"), { recursive: true });
  writeFileSync(join(root, "foo.c"), FIXTURE_C, "utf8");
  return root;
}

function mockModelLlm(): void {
  executeNativeMock.mockReset().mockResolvedValue({
    content: [{ type: "tool_use", name: "emit_invariant_model", input: { objects: [MODEL_OBJECT], notes: "test model" } }],
  });
}

function fixtureModel(): InvariantModel {
  return {
    modelVersion: INVARIANT_MODEL_VERSION,
    subsystem: "test/foo",
    subsystemFiles: ["foo.c"],
    objects: [MODEL_OBJECT],
    builtAt: new Date().toISOString(),
    notes: "test",
  } as InvariantModel;
}

beforeEach(() => {
  mockModelLlm();
  agenticScanMock.mockReset();
});
afterEach(() => vi.restoreAllMocks());

// ── (a) model-build ────────────────────────────────────────────────────────────
describe("buildInvariantModel", () => {
  it("emits a structured, per-object model off the tool call", async () => {
    const root = makeSourceRoot();
    const model = await buildInvariantModel({
      sourceRoot: root,
      subsystem: "test/foo",
      subsystemFiles: ["foo.c"],
      runtime: "api",
    });
    expect(model.modelVersion).toBe(INVARIANT_MODEL_VERSION);
    expect(model.objects).toHaveLength(1);
    const o = model.objects[0];
    expect(o.object).toBe("struct foo");
    expect(o.lockRules[0].lock).toBe("f->lock");
    expect(o.lockRules[0].guardedFields).toContain("state");
    expect(o.refcountRules[0]).toMatchObject({ getFn: "foo_get", putFn: "foo_put" });
    expect(o.lifecycleRules[0].freeFn).toBe("kfree");
  });

  it("throws when the model emits no objects", async () => {
    executeNativeMock.mockReset().mockResolvedValue({ content: [{ type: "text", text: "no tool call" }] });
    const root = makeSourceRoot();
    await expect(
      buildInvariantModel({ sourceRoot: root, subsystem: "test/foo", subsystemFiles: ["foo.c"], runtime: "api" }),
    ).rejects.toThrow(/no objects/);
  });
});

// ── C function splitter ─────────────────────────────────────────────────────────
describe("splitCFunctions", () => {
  it("recovers each top-level function and skips control blocks", () => {
    const fns = splitCFunctions(FIXTURE_C);
    const names = fns.map((f) => f.name).sort();
    expect(names).toEqual(
      ["foo_drop", "foo_free_and_use", "foo_free_clean", "foo_get_state_racy", "foo_set_state_locked"].sort(),
    );
    expect(names).not.toContain("if");
    expect(names).not.toContain("return");
  });
});

// ── (b) deterministic violation finder ──────────────────────────────────────────
describe("findInvariantViolations (deterministic, no LLM)", () => {
  const sources = [{ file: "foo.c", text: FIXTURE_C }];

  it("flags the unlocked field access and NOT the compliant locked accessor", () => {
    const v = findInvariantViolations(fixtureModel(), sources);
    const unlocked = v.filter((x) => x.kind === "unlocked-field-access");
    expect(unlocked.map((x) => x.functionName)).toContain("foo_get_state_racy");
    // The compliant accessor holds foo->lock → must NOT appear.
    expect(unlocked.map((x) => x.functionName)).not.toContain("foo_set_state_locked");
  });

  it("flags use-after-free-order and NOT the clean free", () => {
    const v = findInvariantViolations(fixtureModel(), sources);
    const uaf = v.filter((x) => x.kind === "use-after-free-order");
    expect(uaf.map((x) => x.functionName)).toContain("foo_free_and_use");
    expect(uaf.map((x) => x.functionName)).not.toContain("foo_free_clean");
  });

  it("flags refcount imbalance (pure put), and honors the opt-out", () => {
    const withRc = findInvariantViolations(fixtureModel(), sources);
    expect(withRc.some((x) => x.kind === "refcount-imbalance" && x.functionName === "foo_drop")).toBe(true);
    const withoutRc = findInvariantViolations(fixtureModel(), sources, { refcountCheck: false });
    expect(withoutRc.some((x) => x.kind === "refcount-imbalance")).toBe(false);
  });

  it("every violation cites a concrete file:line and its invariant", () => {
    const v = findInvariantViolations(fixtureModel(), sources);
    expect(v.length).toBeGreaterThan(0);
    for (const x of v) {
      expect(x.file).toBe("foo.c");
      expect(x.line).toBeGreaterThan(0);
      expect(x.invariant).toBeTruthy();
      expect(x.detail).toBeTruthy();
    }
  });
});

// ── store / load round-trip (the compounding, re-checkable artifact) ─────────────
describe("storeInvariantModel / loadInvariantModel", () => {
  it("round-trips the model through a JSON artifact", () => {
    const dir = mkdtempSync(join(tmpdir(), "invmodel-"));
    const path = join(dir, "sub", "model.json");
    const stored = storeInvariantModel(fixtureModel(), path);
    expect(stored).toBe(path);
    const raw = JSON.parse(readFileSync(path, "utf8"));
    expect(raw.objects[0].object).toBe("struct foo");
    const loaded = loadInvariantModel(path);
    expect(loaded.objects[0].lockRules[0].lock).toBe("f->lock");
  });

  it("rejects a model with a mismatched schema version", () => {
    const dir = mkdtempSync(join(tmpdir(), "invmodel-"));
    const path = join(dir, "model.json");
    storeInvariantModel({ ...fixtureModel(), modelVersion: 999 } as InvariantModel, path);
    expect(() => loadInvariantModel(path)).toThrow(/schema v999/);
  });
});

// ── (c) candidates compose into runHuntScan ─────────────────────────────────────
describe("violationsToHuntPlan → runHuntScan (seedless → verified → ranked)", () => {
  it("maps violations to per-file HuntCandidates with merged hints", () => {
    const v = findInvariantViolations(fixtureModel(), [{ file: "foo.c", text: FIXTURE_C }]);
    const plan = violationsToHuntPlan(fixtureModel(), v);
    expect(plan.candidates.map((c) => c.path)).toEqual(["foo.c"]);
    expect(plan.candidates[0].hint).toContain("UNLOCKED FIELD ACCESS");
    expect(plan.candidates[0].hint).toContain("---"); // >1 violation merged
    expect(plan.brief.bugClass).toContain("invariant-model violation");
  });

  it("flows candidates through runHuntScan with composeGate(skeptic, prover)", async () => {
    const v = findInvariantViolations(fixtureModel(), [{ file: "foo.c", text: FIXTURE_C }]);
    const plan = violationsToHuntPlan(fixtureModel(), v);

    agenticScanMock.mockImplementation(async ({ config }: { config: { target: string } }) => ({
      findings: [mkFinding("f1", `bug at ${config.target}`)],
    }));

    const skepticCalls: string[] = [];
    const proverCalls: string[] = [];
    const skeptic = async (f: Finding) => { skepticCalls.push(f.id); return { confirmed: true, reason: "survived" }; };
    const prover = async (f: Finding) => { proverCalls.push(f.id); return { confirmed: true, reason: "reproduced" }; };

    const res = await runHuntScan({
      sourceRoot: "/src",
      candidates: plan.candidates,
      brief: plan.brief,
      runtime: "api",
      verify: composeGate(skeptic, prover),
    });

    expect(res.scanned).toBe(plan.candidates.length);
    expect(res.confirmed).toHaveLength(1);
    expect(skepticCalls).toEqual(["f1"]);
    expect(proverCalls).toEqual(["f1"]); // composeGate ran the prover after the skeptic
  });
});

// ── end-to-end orchestration ─────────────────────────────────────────────────────
describe("runSubsystemInvariantHunt", () => {
  it("builds+stores the model, finds violations, verifies, then LOADS on re-run", async () => {
    const root = makeSourceRoot();
    const modelPath = join(root, "model.json");

    agenticScanMock.mockImplementation(async () => ({ findings: [mkFinding("g1", "bug")] }));
    const verify = async () => ({ confirmed: true, reason: "ok" });

    const out = await runSubsystemInvariantHunt({
      sourceRoot: root,
      subsystem: "test/foo",
      subsystemFiles: ["foo.c"],
      runtime: "api",
      modelPath,
      verify,
    });
    expect(out.modelLoaded).toBe(false); // built fresh (no prior artifact)
    expect(out.violations.length).toBeGreaterThan(0);
    expect(out.hunt?.confirmed).toHaveLength(1);
    expect(executeNativeMock).toHaveBeenCalledTimes(1); // one model-build LLM call

    // Model was persisted → a second run LOADS it (no LLM call). This is the
    // compounding, re-checkable property.
    executeNativeMock.mockClear();
    const out2 = await runSubsystemInvariantHunt({
      sourceRoot: root,
      subsystem: "test/foo",
      subsystemFiles: ["foo.c"],
      runtime: "api",
      modelPath,
      verify,
      skipHunt: true,
    });
    expect(out2.modelLoaded).toBe(true);
    expect(executeNativeMock).not.toHaveBeenCalled();
  });
});

function mkFinding(id: string, title: string): Finding {
  return {
    id,
    templateId: "inv-test",
    title,
    description: title,
    severity: "high",
    category: "other",
    status: "discovered",
    evidence: { request: "", response: "", analysis: "" },
    timestamp: 1_700_000_000_000,
  };
}

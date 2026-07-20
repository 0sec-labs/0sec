/**
 * Tests for the v3 DYNAMIC WITNESS oracle ({@link witnessAssumptionViolation} +
 * the deterministic witness check). The VM + LLM boundaries are MOCKED (injected
 * `synthesizePoc` / `bootPoc`) so the whole loop runs offline — no QEMU, no LLM —
 * exactly the pattern the kernel-VM tests use. Proves the assume-FP contract:
 *   • a matching, object-bound KASAN splat  → confirmed
 *   • an incidental splat (no candidate token) → NOT confirmed (refuted)
 *   • a splat the PoC itself printed → REJECTED as fabrication
 *   • no splat at all → refuted; never-compiled → inconclusive
 *   • the loop feeds boot output back and can confirm on a LATER round.
 */

import { describe, expect, it, vi } from "vitest";
import {
  witnessAssumptionViolation,
  witnessDualViewContexts,
  dualViewCandidateFromContext,
  checkWitness,
  pocFabricatesSplat,
  extractCFromLlmOutput,
  extractSplatRegion,
  candidateReferenceTokens,
  makeDefaultSynthesizePoc,
  preFilterDualViewContexts,
  candidateStableId,
  candidateStableIdFromContext,
  loadRotationState,
  saveRotationState,
  pruneRotationState,
  isWitnessedWithinTtl,
  ROTATION_TTL_MS,
  ROTATION_STATE_VERSION,
  type RotationState,
  type DualViewCandidate,
  type PocSynthesisInput,
  type BootPocFn,
} from "./dynamic-witness.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LlmApiRuntime } from "../runtime/index.js";
import type { ReproducerResult } from "../triage/kernel-oracle.js";
import type { Assumption, ViolatingContext } from "./assumption-mining.js";

// ── fixtures ─────────────────────────────────────────────────────────────────────

function candidate(over: Partial<DualViewCandidate> = {}): DualViewCandidate {
  return {
    assumptionId: "unix_update_edges#1",
    subsystem: "net/unix",
    object: "unix_sock",
    subject: "unix_update_edges",
    entryA: "__unix_find_socket_byname",
    entryB: "unix_dgram_peer_wake_relay",
    establisherToken: "unix_state_lock",
    kind: "state-precondition",
    securityRelevance: "lifetime",
    predicate: "unix_peer(sk) == other and the association is stable while touching other",
    unprivEntry: true,
    sources: [
      { label: "entryA (establishing view)", fn: "__unix_find_socket_byname", code: "void __unix_find_socket_byname(void){ spin_lock(); }" },
      { label: "entryB (skipping view)", fn: "unix_dgram_peer_wake_relay", code: "void unix_dgram_peer_wake_relay(void){ /* no lock */ }" },
    ],
    detail: "DUAL-VIEW: entryA and entryB both operate on struct unix_sock via distinct call-trees.",
    ...over,
  };
}

function result(over: Partial<ReproducerResult> = {}): ReproducerResult {
  return { compiled: true, executed: true, output: "", dmesg: "", exitCode: 0, timedOut: false, ...over };
}

/** A realistic object-bound KASAN UAF splat naming a candidate function. */
const MATCHING_SPLAT = [
  "[    5.123456] ==================================================================",
  "[    5.123500] BUG: KASAN: slab-use-after-free in unix_dgram_peer_wake_relay+0x1a0/0x220",
  "[    5.123600] Read of size 8 at addr ffff88800abc1234 by task poc/321",
  "[    5.123700] Freed by task 321:",
  "[    5.123800]  kfree+0x1e/0x40",
  "[    5.123900]  unix_sock_destructor+0x88/0xa0",
  "[    5.124000] ==================================================================",
].join("\n");

/** A real KASAN splat, but in an unrelated subsystem — no candidate token present. */
const INCIDENTAL_SPLAT = [
  "==================================================================",
  "BUG: KASAN: slab-out-of-bounds in e1000_clean_rx_irq+0x400/0x900",
  "Read of size 4 at addr ffff88800def5678 by task kworker/1",
  "Allocated by task 55:",
  "  e1000_alloc_rx_buffers+0x120/0x300",
  "==================================================================",
].join("\n");

// ── extractCFromLlmOutput ──────────────────────────────────────────────────────────

describe("extractCFromLlmOutput", () => {
  it("pulls a fenced ```c block", () => {
    const c = extractCFromLlmOutput("Here is the PoC:\n```c\n#include <stdio.h>\nint main(){return 0;}\n```\nDone.");
    expect(c).toContain("int main()");
    expect(c).not.toContain("```");
  });
  it("accepts a bare program with no fence", () => {
    expect(extractCFromLlmOutput("#include <unistd.h>\nint main(){return 0;}")).toContain("int main()");
  });
  it("returns null for prose with no code", () => {
    expect(extractCFromLlmOutput("I could not synthesize a PoC for this candidate.")).toBeNull();
  });
});

// ── extractSplatRegion / reference tokens ─────────────────────────────────────────

describe("extractSplatRegion", () => {
  it("extracts the KASAN report bracketed by ==== rules", () => {
    const region = extractSplatRegion(`boot noise\n${MATCHING_SPLAT}\nlater noise`);
    expect(region).toContain("BUG: KASAN: slab-use-after-free");
    expect(region).toContain("unix_sock_destructor");
    expect(region).not.toContain("later noise");
  });
  it("returns null when there is no splat", () => {
    expect(extractSplatRegion("just a clean boot, no crash here")).toBeNull();
  });
});

describe("candidateReferenceTokens", () => {
  it("includes the object type and the entry/subject functions", () => {
    const toks = candidateReferenceTokens(candidate());
    expect(toks).toContain("unix_sock");
    expect(toks).toContain("unix_dgram_peer_wake_relay");
    expect(toks).toContain("__unix_find_socket_byname");
  });
});

// ── checkWitness (the deterministic core) ─────────────────────────────────────────

describe("checkWitness", () => {
  it("CONFIRMS an object-bound KASAN UAF splat", () => {
    const w = checkWitness(candidate(), "int main(){ return 0; }", result({ dmesg: MATCHING_SPLAT }));
    expect(w.witnessed).toBe(true);
    expect(w.signature).toBe("kasan-uaf");
    expect(w.boundTo).toBe("unix_dgram_peer_wake_relay");
  });

  it("does NOT confirm an incidental splat (no candidate token in the report)", () => {
    const w = checkWitness(candidate(), "int main(){ return 0; }", result({ dmesg: INCIDENTAL_SPLAT }));
    expect(w.witnessed).toBe(false);
    expect(w.signature).toBe("kasan-oob");
    expect(w.reason).toMatch(/not bound|incidental/i);
  });

  it("does NOT confirm when there is no splat at all", () => {
    const w = checkWitness(candidate(), "int main(){ return 0; }", result({ dmesg: "clean boot, poc ran, no crash" }));
    expect(w.witnessed).toBe(false);
    expect(w.reason).toMatch(/no KASAN splat/i);
  });

  it("does NOT mislabel a clean KASAN boot (banner only) as a crash", () => {
    // The KASAN boot banner `kasan: KernelAddressSanitizer initialized` is present
    // on EVERY boot of a KASAN kernel. It must NOT be read as a crash — otherwise
    // the refute reason (and the feedback fed to the next synthesis round) claims a
    // crash fired when the run was clean.
    const cleanKasanBoot =
      "[    0.407] kasan: KernelAddressSanitizer initialized\n" +
      "[    1.200] poc ran, printed its markers, exited 0\n" +
      "[    1.900] reboot: Power down";
    const w = checkWitness(candidate(), "int main(){ return 0; }", result({ dmesg: cleanKasanBoot }));
    expect(w.witnessed).toBe(false);
    expect(w.reason).toMatch(/no KASAN splat/i);
    expect(w.reason).not.toMatch(/crash fired/i);
  });

  it("does NOT confirm a compile-only artifact (never executed)", () => {
    const w = checkWitness(candidate(), "int main(){}", result({ compiled: true, executed: false, dmesg: MATCHING_SPLAT }));
    expect(w.witnessed).toBe(false);
    expect(w.reason).toMatch(/did not execute/i);
  });

  it("REJECTS a splat the PoC itself printed (anti-fabrication)", () => {
    const cheatingPoc =
      `#include <stdio.h>\nint main(){ printf("BUG: KASAN: slab-use-after-free in unix_dgram_peer_wake_relay\\n"); return 0; }`;
    // dmesg carries the same line WITHOUT a kernel timestamp — as if echoed by the exploit.
    const echoed = "BUG: KASAN: slab-use-after-free in unix_dgram_peer_wake_relay\nsome more output";
    expect(pocFabricatesSplat(cheatingPoc, echoed)).toBe(true);
    const w = checkWitness(candidate(), cheatingPoc, result({ dmesg: echoed, output: echoed }));
    expect(w.witnessed).toBe(false);
    expect(w.reason).toMatch(/fabricat/i);
  });

  it("does NOT flag a genuine kernel splat as fabrication (addresses differ from source)", () => {
    const realPoc = "#include <unistd.h>\nint main(){ return 0; }";
    expect(pocFabricatesSplat(realPoc, MATCHING_SPLAT)).toBe(false);
  });
});

// ── witnessAssumptionViolation (the loop, mocked boundaries) ───────────────────────

const OK_SYNTH = async (input: PocSynthesisInput) => ({ cSource: `/* round ${input.round} */\nint main(){ return 0; }` });

describe("witnessAssumptionViolation", () => {
  it("CONFIRMS on a matching splat and stops", async () => {
    const boot = vi.fn<BootPocFn>().mockResolvedValue(result({ dmesg: MATCHING_SPLAT }));
    const r = await witnessAssumptionViolation(candidate(), { synthesizePoc: OK_SYNTH, bootPoc: boot, maxRounds: 3 });
    expect(r.verdict).toBe("confirmed");
    expect(r.attempts).toHaveLength(1);
    expect(r.witnessedAttempt?.check?.signature).toBe("kasan-uaf");
    expect(r.splat).toContain("BUG: KASAN");
    expect(boot).toHaveBeenCalledTimes(1);
  });

  it("REFUTES when the PoC compiles + runs across the budget but never faults", async () => {
    const boot = vi.fn<BootPocFn>().mockResolvedValue(result({ dmesg: "poc ran cleanly, no splat" }));
    const r = await witnessAssumptionViolation(candidate(), { synthesizePoc: OK_SYNTH, bootPoc: boot, maxRounds: 2 });
    expect(r.verdict).toBe("refuted");
    expect(r.attempts).toHaveLength(2);
    expect(boot).toHaveBeenCalledTimes(2);
  });

  it("is INCONCLUSIVE when the PoC never compiles (AEG/synthesis limit, not a refutation)", async () => {
    const boot = vi.fn<BootPocFn>().mockResolvedValue(result({ compiled: false, executed: false, output: "gcc: error: undefined reference" }));
    const r = await witnessAssumptionViolation(candidate(), { synthesizePoc: OK_SYNTH, bootPoc: boot, maxRounds: 2 });
    expect(r.verdict).toBe("inconclusive");
    expect(r.summary).toMatch(/AEG|synthesis limit/i);
  });

  it("is INCONCLUSIVE when the synthesizer produces nothing", async () => {
    const r = await witnessAssumptionViolation(candidate(), { synthesizePoc: async () => null, bootPoc: async () => result(), maxRounds: 2 });
    expect(r.verdict).toBe("inconclusive");
    expect(r.attempts.every((a) => !a.synthesized)).toBe(true);
  });

  it("ITERATES: no splat on round 1, feeds feedback, CONFIRMS on round 2", async () => {
    const seenFeedback: (string | undefined)[] = [];
    const synth = async (input: PocSynthesisInput) => {
      seenFeedback.push(input.priorFeedback);
      return { cSource: `/* r${input.round} */\nint main(){return 0;}` };
    };
    let call = 0;
    const boot: BootPocFn = async () => (++call === 1 ? result({ dmesg: "ran, no splat" }) : result({ dmesg: MATCHING_SPLAT }));
    const r = await witnessAssumptionViolation(candidate(), { synthesizePoc: synth, bootPoc: boot, maxRounds: 3 });
    expect(r.verdict).toBe("confirmed");
    expect(r.attempts).toHaveLength(2);
    // round 1 had no prior feedback; round 2 was handed the boot output to fix.
    expect(seenFeedback[0]).toBeUndefined();
    expect(seenFeedback[1]).toMatch(/no KASAN splat|no witness|ran, no splat/i);
  });
});

// ── makeDefaultSynthesizePoc (routes through streaming executeNative) ──────────────

describe("makeDefaultSynthesizePoc", () => {
  it("synthesises via executeNative (NOT the buffered execute) and extracts the fenced C", async () => {
    // The codex `/responses` backend 400s a non-streaming `execute()`; synthesis
    // must use `executeNative` (stream:true + SSE). Mock it and prove the default
    // synthesizer routes there and pulls the C out of the content text blocks.
    const nativeSpy = vi
      .spyOn(LlmApiRuntime.prototype, "executeNative")
      .mockResolvedValue({
        content: [{ type: "text", text: "Here is the PoC:\n```c\n#include <unistd.h>\nint main(){ return 0; }\n```" }],
        stopReason: "end_turn",
        durationMs: 1,
      } as never);
    const executeSpy = vi.spyOn(LlmApiRuntime.prototype, "execute");

    const synth = makeDefaultSynthesizePoc("api", "gpt-5.5");
    const out = await synth({ candidate: candidate(), round: 1 });

    expect(out?.cSource).toContain("int main()");
    expect(out?.cSource).not.toContain("```");
    expect(nativeSpy).toHaveBeenCalledTimes(1);
    expect(executeSpy).not.toHaveBeenCalled();
    // The system prompt + a single user message carrying the synthesis prompt.
    const [system, messages] = nativeSpy.mock.calls[0];
    expect(String(system)).toMatch(/PROOF-OF-CONCEPT/i);
    expect((messages as Array<{ role: string }>)[0].role).toBe("user");

    nativeSpy.mockRestore();
    executeSpy.mockRestore();
  });

  it("returns null when the model emits no code block", async () => {
    const nativeSpy = vi
      .spyOn(LlmApiRuntime.prototype, "executeNative")
      .mockResolvedValue({
        content: [{ type: "text", text: "I could not synthesize a PoC for this candidate." }],
        stopReason: "end_turn",
        durationMs: 1,
      } as never);

    const synth = makeDefaultSynthesizePoc("api");
    expect(await synth({ candidate: candidate(), round: 1 })).toBeNull();

    nativeSpy.mockRestore();
  });
});

// ── orchestration over dual-view contexts ─────────────────────────────────────────

function dvContext(over: Partial<ViolatingContext> = {}): ViolatingContext {
  return {
    assumptionId: "unix_update_edges#1",
    subject: "unix_update_edges",
    caller: "unix_dgram_peer_wake_relay",
    callerFile: "net/unix/af_unix.c",
    callLine: 100,
    establisherToken: "unix_state_lock",
    unprivEntry: true,
    detail: "DUAL-VIEW ...",
    dualView: true,
    pairedEntry: "__unix_find_socket_byname",
    object: "unix_sock",
    ...over,
  };
}

function assumptionFix(over: Partial<Assumption> & Pick<Assumption, "id" | "subject">): Assumption {
  return {
    kind: "state-precondition",
    predicate: "stable association",
    location: over.subject,
    provenance: "relied-on-cross-api",
    securityRelevance: "lifetime",
    oracle: { mechanism: "establisher-absent-cross-api", target: "unix_sock", establisherToken: "unix_state_lock" },
    ...over,
  } as Assumption;
}

describe("dualViewCandidateFromContext", () => {
  it("builds a candidate from a dual-view context + assumption + bodies", () => {
    const bodies = new Map<string, string>([
      ["__unix_find_socket_byname", "void __unix_find_socket_byname(){ spin_lock(); }"],
      ["unix_dgram_peer_wake_relay", "void unix_dgram_peer_wake_relay(){}"],
    ]);
    const cand = dualViewCandidateFromContext(dvContext(), assumptionFix({ id: "unix_update_edges#1", subject: "unix_update_edges" }), bodies, "net/unix");
    expect(cand).not.toBeNull();
    expect(cand!.entryA).toBe("__unix_find_socket_byname");
    expect(cand!.entryB).toBe("unix_dgram_peer_wake_relay");
    expect(cand!.object).toBe("unix_sock");
    expect(cand!.sources.map((s) => s.fn)).toContain("__unix_find_socket_byname");
  });
  it("returns null for a non-dual-view (caller-scan) context", () => {
    const cand = dualViewCandidateFromContext(dvContext({ dualView: false }), assumptionFix({ id: "x#1", subject: "x" }), new Map(), "net/unix");
    expect(cand).toBeNull();
  });
});

describe("witnessDualViewContexts", () => {
  it("routes dual-view contexts to the oracle and buckets the verdicts", async () => {
    const bodies = new Map<string, string>([
      ["__unix_find_socket_byname", "void __unix_find_socket_byname(){}"],
      ["unix_dgram_peer_wake_relay", "void unix_dgram_peer_wake_relay(){}"],
      ["unix_read_skb", "void unix_read_skb(){}"],
    ]);
    const kept = [assumptionFix({ id: "unix_update_edges#1", subject: "unix_update_edges" })];
    const contexts = [
      dvContext(),
      dvContext({ caller: "unix_read_skb" }),
    ];
    // First candidate witnesses (matching splat); second refutes (clean run).
    let n = 0;
    const boot: BootPocFn = async () => (++n === 1 ? result({ dmesg: MATCHING_SPLAT }) : result({ dmesg: "clean" }));
    const out = await witnessDualViewContexts({
      contexts, kept, bodies, subsystem: "net/unix",
      deps: { synthesizePoc: OK_SYNTH, bootPoc: boot, maxRounds: 1 },
    });
    expect(out.results).toHaveLength(2);
    expect(out.confirmed).toHaveLength(1);
    expect(out.refuted).toHaveLength(1);
    expect(out.confirmed[0].candidate.entryB).toBe("unix_dgram_peer_wake_relay");
  });

  it("respects maxCandidates", async () => {
    const bodies = new Map<string, string>([["unix_dgram_peer_wake_relay", "x"], ["__unix_find_socket_byname", "x"]]);
    const kept = [assumptionFix({ id: "unix_update_edges#1", subject: "unix_update_edges" })];
    const contexts = [dvContext(), dvContext({ caller: "unix_read_skb" }), dvContext({ caller: "unix_sock_destructor" })];
    const boot = vi.fn<BootPocFn>().mockResolvedValue(result({ dmesg: "clean" }));
    const out = await witnessDualViewContexts({ contexts, kept, bodies, subsystem: "net/unix", maxCandidates: 1, deps: { synthesizePoc: OK_SYNTH, bootPoc: boot, maxRounds: 1 } });
    expect(out.results).toHaveLength(1);
  });
});

// ── CHANGE 3: cheap pre-filter ───────────────────────────────────────────────────

describe("preFilterDualViewContexts — drop the obviously-benign before the oracle", () => {
  it("DROPS an authz (non-memory-safety) candidate but KEEPS a real lifetime one", () => {
    const bodies = new Map<string, string>([
      ["lifetime_b", "int lifetime_b(struct obj *o){ return o->x; }"],
      ["authz_b", "int authz_b(struct thing *t){ return t->y; }"],
    ]);
    const byId = new Map<string, Assumption>([
      ["life#1", assumptionFix({ id: "life#1", subject: "life_s", securityRelevance: "lifetime" })],
      ["authz#1", assumptionFix({ id: "authz#1", subject: "authz_s", securityRelevance: "authz" })],
    ]);
    const contexts = [
      dvContext({ assumptionId: "life#1", caller: "lifetime_b", object: "obj" }),
      dvContext({ assumptionId: "authz#1", caller: "authz_b", object: "thing" }),
    ];
    const { kept, dropped } = preFilterDualViewContexts(contexts, byId, bodies);
    expect(kept.map((c) => c.caller)).toEqual(["lifetime_b"]);
    expect(dropped).toHaveLength(1);
    expect(dropped[0].ctx.caller).toBe("authz_b");
    expect(dropped[0].reason).toMatch(/not memory-safety/);
  });

  it("DROPS a candidate whose entryB SELF-ENFORCES the establisher (illusory skip)", () => {
    const bodies = new Map<string, string>([
      // entryB flag-tests the object it supposedly reaches unguarded → self-enforcing.
      ["guarded_b", "int guarded_b(struct obj *o){ if (o->flags & OBJ_DEAD) return -1; return o->x; }"],
    ]);
    const a = assumptionFix({
      id: "s#1",
      subject: "s",
      securityRelevance: "lifetime",
      oracle: { mechanism: "establisher-absent-cross-api", target: "o->flags", establisherToken: "obj_lock" },
    });
    const byId = new Map<string, Assumption>([["s#1", a]]);
    const contexts = [dvContext({ assumptionId: "s#1", caller: "guarded_b", object: "obj" })];
    const { kept, dropped } = preFilterDualViewContexts(contexts, byId, bodies);
    expect(kept).toHaveLength(0);
    expect(dropped[0].reason).toMatch(/self-enforc|flag-test/);
  });

  it("DROPS a candidate whose entryB directly calls the establisher (both-paths-same-guard)", () => {
    const bodies = new Map<string, string>([
      ["locked_b", "int locked_b(struct obj *o){ obj_lock(o); return o->x; }"],
    ]);
    const a = assumptionFix({
      id: "s#2",
      subject: "s",
      securityRelevance: "lifetime",
      oracle: { mechanism: "establisher-absent-cross-api", target: "o", establisherToken: "obj_lock" },
    });
    const byId = new Map<string, Assumption>([["s#2", a]]);
    const contexts = [dvContext({ assumptionId: "s#2", caller: "locked_b", object: "obj" })];
    const { kept, dropped } = preFilterDualViewContexts(contexts, byId, bodies);
    expect(kept).toHaveLength(0);
    expect(dropped[0].reason).toMatch(/directly calls establisher/);
  });

  it("KEEPS a candidate whose assumption is unknown (cannot judge → conservative)", () => {
    const contexts = [dvContext({ assumptionId: "orphan#9", caller: "b" })];
    const { kept, dropped } = preFilterDualViewContexts(contexts, new Map(), new Map());
    expect(kept).toHaveLength(1);
    expect(dropped).toHaveLength(0);
  });
});

// ── CHANGE 2: cross-run rotation ─────────────────────────────────────────────────

describe("rotation state — stable id + TTL + pruning", () => {
  it("candidateStableId is stable + differs on any component change", () => {
    const base = { object: "fuse_req", entryA: "a", entryB: "b", entryBFile: "f.c", assumptionId: "x#1", predicate: "p" };
    const id = candidateStableId(base);
    expect(candidateStableId(base)).toBe(id); // stable
    expect(candidateStableId({ ...base, entryB: "c" })).not.toBe(id);
    expect(candidateStableId({ ...base, object: "dma_buf" })).not.toBe(id);
  });

  it("candidateStableIdFromContext derives the id from the context fields", () => {
    const id = candidateStableIdFromContext(dvContext(), "stable association");
    expect(id).toBe(
      candidateStableId({
        object: "unix_sock",
        entryA: "__unix_find_socket_byname",
        entryB: "unix_dgram_peer_wake_relay",
        entryBFile: "net/unix/af_unix.c",
        assumptionId: "unix_update_edges#1",
        predicate: "stable association",
      }),
    );
  });

  it("isWitnessedWithinTtl is true inside the TTL, false after it", () => {
    const now = Date.parse("2026-07-20T00:00:00Z");
    const state: RotationState = {
      version: ROTATION_STATE_VERSION,
      candidates: { id1: { verdict: "refuted", witnessedAt: new Date(now - 3 * 86_400_000).toISOString(), object: "o", entryA: "a", entryB: "b" } },
    };
    expect(isWitnessedWithinTtl(state, "id1", now)).toBe(true); // 3d ago < 14d TTL
    expect(isWitnessedWithinTtl(state, "id1", now + ROTATION_TTL_MS)).toBe(false); // now past TTL
    expect(isWitnessedWithinTtl(state, "missing", now)).toBe(false);
  });

  it("pruneRotationState drops entries past the retention window", () => {
    const now = Date.parse("2026-07-20T00:00:00Z");
    const state: RotationState = {
      version: ROTATION_STATE_VERSION,
      candidates: {
        fresh: { verdict: "refuted", witnessedAt: new Date(now - 5 * 86_400_000).toISOString(), object: "o", entryA: "a", entryB: "b" },
        stale: { verdict: "refuted", witnessedAt: new Date(now - 40 * 86_400_000).toISOString(), object: "o", entryA: "a", entryB: "b" },
      },
    };
    const pruned = pruneRotationState(state, now);
    expect(Object.keys(pruned.candidates)).toEqual(["fresh"]); // stale (>28d) dropped
  });
});

describe("witnessDualViewContexts — rotation skips already-witnessed within TTL", () => {
  const mkBodies = () =>
    new Map<string, string>([
      ["unix_dgram_peer_wake_relay", "int unix_dgram_peer_wake_relay(struct unix_sock *u){ return u->x; }"],
      ["__unix_find_socket_byname", "int __unix_find_socket_byname(struct unix_sock *u){ return 0; }"],
    ]);
  const kept = [assumptionFix({ id: "unix_update_edges#1", subject: "unix_update_edges", securityRelevance: "lifetime" })];
  const contexts = [dvContext()];

  it("run 1 witnesses; run 2 (within TTL) SKIPS it; run 3 (past TTL) re-includes it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "witness-rotation-"));
    const rotationStatePath = join(dir, ".witnessed-candidates.json");
    const boot = vi.fn<BootPocFn>().mockResolvedValue(result({ dmesg: "clean, no splat" }));
    const t0 = Date.parse("2026-07-20T00:00:00Z");
    const deps = { synthesizePoc: OK_SYNTH, bootPoc: boot, maxRounds: 1 };

    // Run 1: fresh candidate → witnessed (refuted), recorded.
    const r1 = await witnessDualViewContexts({ contexts, kept, bodies: mkBodies(), subsystem: "net/unix", rotationStatePath, now: t0, deps });
    expect(r1.results).toHaveLength(1);
    const persisted = loadRotationState(rotationStatePath);
    expect(Object.keys(persisted.candidates)).toHaveLength(1);

    // Run 2: 3 days later, still within the 14d TTL → SKIPPED (no oracle run).
    const r2 = await witnessDualViewContexts({ contexts, kept, bodies: mkBodies(), subsystem: "net/unix", rotationStatePath, now: t0 + 3 * 86_400_000, deps });
    expect(r2.results).toHaveLength(0);

    // Run 3: past the TTL → re-included (the code may have changed since).
    const r3 = await witnessDualViewContexts({ contexts, kept, bodies: mkBodies(), subsystem: "net/unix", rotationStatePath, now: t0 + ROTATION_TTL_MS + 86_400_000, deps });
    expect(r3.results).toHaveLength(1);
  });

  it("without a rotationStatePath every run witnesses the same candidate (no memory)", async () => {
    const boot = vi.fn<BootPocFn>().mockResolvedValue(result({ dmesg: "clean" }));
    const deps = { synthesizePoc: OK_SYNTH, bootPoc: boot, maxRounds: 1 };
    const a = await witnessDualViewContexts({ contexts, kept, bodies: mkBodies(), subsystem: "net/unix", deps });
    const b = await witnessDualViewContexts({ contexts, kept, bodies: mkBodies(), subsystem: "net/unix", deps });
    expect(a.results).toHaveLength(1);
    expect(b.results).toHaveLength(1); // no rotation memory → re-tested
  });
});

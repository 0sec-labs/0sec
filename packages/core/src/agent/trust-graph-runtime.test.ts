/**
 * Tests for the opt-in trust-graph loop wiring (pwnkit#771).
 *
 * Two layers:
 *   1. TrustGraphSession unit tests — the pure cross-target reuse / persist /
 *      render logic, with a spy store + spy journal sink (no DB, no network).
 *   2. runNativeAgentLoop integration tests — the OPT-IN contract:
 *      • with NO `trustGraph` config, the loop makes ZERO store calls and is
 *        otherwise unchanged (the core "default behaviour is byte-identical"
 *        proof);
 *      • with a `trustGraph` config, prior footholds are injected at loop start.
 */

import { describe, it, expect, vi } from "vitest";
import { runNativeAgentLoop } from "./native-loop.js";
import {
  TrustGraphSession,
  maybeCreateTrustGraphSession,
  type CredentialStoreLike,
  type PriorCredentialRow,
} from "./trust-graph-runtime.js";
import { LootLedger } from "./loot.js";
import { hashCredentialValue } from "./credential-store.js";
import type { CredentialSharedSink } from "./journal/credential-shared.js";
import type { JournalEntryInput } from "./journal/types.js";
import type {
  NativeRuntime,
  NativeRuntimeResult,
  NativeMessage,
} from "../runtime/types.js";

// ── Spy doubles ──────────────────────────────────────────────────────────

/** A CredentialStoreLike whose every method is a vi.fn spy. */
function createSpyStore(opts: {
  prior?: PriorCredentialRow[];
  priorRender?: string;
} = {}): CredentialStoreLike & {
  list: ReturnType<typeof vi.fn>;
  renderPriorFootholds: ReturnType<typeof vi.fn>;
  saveLedger: ReturnType<typeof vi.fn>;
} {
  return {
    list: vi.fn((_o?: { target?: string; limit?: number }) => opts.prior ?? []),
    renderPriorFootholds: vi.fn(
      (_o?: { target?: string; limit?: number }) => opts.priorRender ?? "",
    ),
    saveLedger: vi.fn(() => 0),
  };
}

function createSpySink(): CredentialSharedSink & {
  entries: JournalEntryInput[];
} {
  const entries: JournalEntryInput[] = [];
  return {
    entries,
    append(entry: JournalEntryInput) {
      entries.push(entry);
    },
  };
}

function priorRow(over: Partial<PriorCredentialRow> = {}): PriorCredentialRow {
  return {
    credentialKind: "credential",
    valueHash: hashCredentialValue("admin:hunter2"),
    target: "https://prior.example",
    firstFindingId: "F-prior-1",
    ...over,
  };
}

// ── Mock runtime ───────────────────────────────────────────────────────────

function createMockRuntime(responses: NativeRuntimeResult[]): NativeRuntime {
  let i = 0;
  return {
    type: "api" as const,
    async executeNative(
      _system: string,
      _messages: NativeMessage[],
    ): Promise<NativeRuntimeResult> {
      const r = responses[i] ?? responses[responses.length - 1];
      i++;
      return r;
    },
    async isAvailable() {
      return true;
    },
  };
}

const DONE_ONCE: NativeRuntimeResult[] = [
  {
    content: [{ type: "tool_use", id: "tc1", name: "done", input: { summary: "ok" } }],
    stopReason: "tool_use",
    durationMs: 1,
  },
];

// ── TrustGraphSession unit tests ────────────────────────────────────────────

describe("TrustGraphSession", () => {
  it("renderPriorFootholds delegates to the store", () => {
    const store = createSpyStore({ priorRender: "PRIOR-BLOCK" });
    const session = new TrustGraphSession({
      store,
      sourceTargetId: "https://dest.example",
      journalSink: createSpySink(),
      priorRows: [],
    });
    expect(session.renderPriorFootholds("https://dest.example")).toBe("PRIOR-BLOCK");
    expect(store.renderPriorFootholds).toHaveBeenCalledWith({
      target: "https://dest.example",
    });
  });

  it("persist delegates to store.saveLedger with attribution", () => {
    const store = createSpyStore();
    const session = new TrustGraphSession({
      store,
      sourceTargetId: "https://dest.example",
      journalSink: createSpySink(),
      priorRows: [],
    });
    const ledger = new LootLedger();
    ledger.add({ kind: "credential", value: "admin:hunter2", source: "http_request" });
    session.persist(ledger, { target: "https://dest.example", scanId: "scan-2" });
    expect(store.saveLedger).toHaveBeenCalledTimes(1);
    expect(store.saveLedger).toHaveBeenCalledWith(ledger, {
      target: "https://dest.example",
      scanId: "scan-2",
    });
  });

  it("emits credential_shared when a prior credential from a DIFFERENT target is re-found", () => {
    const sink = createSpySink();
    const session = new TrustGraphSession({
      store: createSpyStore(),
      sourceTargetId: "https://dest.example",
      journalSink: sink,
      priorRows: [priorRow()], // recovered on https://prior.example
    });
    const ledger = new LootLedger();
    const item = ledger.add({
      kind: "credential",
      value: "admin:hunter2",
      source: "http_request",
      turn: 5,
    })!;

    const emitted = session.noteHarvest([item], 5);

    expect(emitted).toBe(1);
    expect(sink.entries).toHaveLength(1);
    const e = sink.entries[0] as Extract<JournalEntryInput, { kind: "credential_shared" }>;
    expect(e.kind).toBe("credential_shared");
    expect(e.sourceTarget).toBe("https://prior.example");
    expect(e.destTarget).toBe("https://dest.example");
    expect(e.credentialKind).toBe("credential");
    expect(e.originatingFindingId).toBe("F-prior-1");
    expect(e.turn).toBe(5);
    // No plaintext secret in the journal entry.
    expect(JSON.stringify(e)).not.toContain("hunter2");
  });

  it("does NOT emit for a SAME-target re-discovery (no cross-target boundary)", () => {
    const sink = createSpySink();
    const session = new TrustGraphSession({
      store: createSpyStore(),
      sourceTargetId: "https://dest.example",
      journalSink: sink,
      // prior credential recovered on the SAME target we're now scanning
      priorRows: [priorRow({ target: "https://dest.example" })],
    });
    const ledger = new LootLedger();
    const item = ledger.add({ kind: "credential", value: "admin:hunter2", source: "http" })!;
    expect(session.noteHarvest([item])).toBe(0);
    expect(sink.entries).toHaveLength(0);
  });

  it("does NOT emit for a never-before-seen credential", () => {
    const sink = createSpySink();
    const session = new TrustGraphSession({
      store: createSpyStore(),
      sourceTargetId: "https://dest.example",
      journalSink: sink,
      priorRows: [priorRow()],
    });
    const ledger = new LootLedger();
    const item = ledger.add({ kind: "credential", value: "root:totally-new", source: "http" })!;
    expect(session.noteHarvest([item])).toBe(0);
    expect(sink.entries).toHaveLength(0);
  });

  it("emits a cross-target reuse at most once per value", () => {
    const sink = createSpySink();
    const session = new TrustGraphSession({
      store: createSpyStore(),
      sourceTargetId: "https://dest.example",
      journalSink: sink,
      priorRows: [priorRow()],
    });
    const ledger = new LootLedger();
    const item = ledger.add({ kind: "credential", value: "admin:hunter2", source: "http" })!;
    expect(session.noteHarvest([item])).toBe(1);
    expect(session.noteHarvest([item])).toBe(0); // already emitted
    expect(sink.entries).toHaveLength(1);
  });
});

describe("maybeCreateTrustGraphSession", () => {
  const sink = createSpySink();

  it("returns undefined when no trustGraph config (opt-out)", () => {
    expect(
      maybeCreateTrustGraphSession(undefined, {
        target: "https://t.example",
        defaultJournalSink: sink,
      }),
    ).toBeUndefined();
  });

  it("loads prior footholds ONCE at construction and defaults sourceTargetId to target", () => {
    const store = createSpyStore({ prior: [priorRow()] });
    const session = maybeCreateTrustGraphSession(
      { store },
      { target: "https://dest.example", defaultJournalSink: sink },
    );
    expect(session).toBeDefined();
    expect(store.list).toHaveBeenCalledTimes(1);
    expect(store.list).toHaveBeenCalledWith({ target: "https://dest.example" });
    expect(session!.priorCount).toBe(1);
  });
});

// ── Loop opt-in contract ─────────────────────────────────────────────────────

describe("runNativeAgentLoop trust-graph opt-in", () => {
  it("CORE GUARANTEE: makes ZERO store calls when trustGraph config is absent", async () => {
    const store = createSpyStore({ prior: [priorRow()], priorRender: "PRIOR-BLOCK" });

    const state = await runNativeAgentLoop({
      config: {
        role: "discovery",
        systemPrompt: "test",
        tools: [],
        maxTurns: 5,
        target: "https://example.com",
        scanId: "no-trustgraph-scan",
        // NOTE: trustGraph deliberately omitted.
      },
      runtime: createMockRuntime(DONE_ONCE),
      db: null,
    });

    expect(state.done).toBe(true);
    // The whole point: not a single durable-store method is touched.
    expect(store.list).not.toHaveBeenCalled();
    expect(store.renderPriorFootholds).not.toHaveBeenCalled();
    expect(store.saveLedger).not.toHaveBeenCalled();
  });

  it("injects prior-scan footholds at loop start when trustGraph IS configured", async () => {
    const store = createSpyStore({
      prior: [priorRow()],
      priorRender: "## Footholds from prior scans\n- credential: admin:…(13)",
    });
    const seenMessages: NativeMessage[][] = [];
    const runtime: NativeRuntime = {
      type: "api" as const,
      async executeNative(_s: string, messages: NativeMessage[]) {
        seenMessages.push(structuredClone(messages));
        return DONE_ONCE[0];
      },
      async isAvailable() {
        return true;
      },
    };

    await runNativeAgentLoop({
      config: {
        role: "discovery",
        systemPrompt: "test",
        tools: [],
        maxTurns: 5,
        target: "https://dest.example",
        scanId: "trustgraph-scan",
        trustGraph: { store, sourceTargetId: "https://dest.example" },
      },
      runtime,
      db: null,
    });

    // The store was consulted at start.
    expect(store.list).toHaveBeenCalledWith({ target: "https://dest.example" });
    expect(store.renderPriorFootholds).toHaveBeenCalledWith({
      target: "https://dest.example",
    });
    // The rendered prior-footholds block reached the model's context.
    const firstTurn = seenMessages[0] ?? [];
    const allText = JSON.stringify(firstTurn);
    expect(allText).toContain("Footholds from prior scans");
  });

  it("does NOT inject an empty message when there are no prior footholds", async () => {
    const store = createSpyStore({ prior: [], priorRender: "" });
    const seenMessages: NativeMessage[][] = [];
    const runtime: NativeRuntime = {
      type: "api" as const,
      async executeNative(_s: string, messages: NativeMessage[]) {
        seenMessages.push(structuredClone(messages));
        return DONE_ONCE[0];
      },
      async isAvailable() {
        return true;
      },
    };

    await runNativeAgentLoop({
      config: {
        role: "discovery",
        systemPrompt: "test",
        tools: [],
        maxTurns: 5,
        target: "https://dest.example",
        scanId: "trustgraph-empty-scan",
        trustGraph: { store },
      },
      runtime,
      db: null,
    });

    // Exactly one user message on the first turn — the initial prompt, no
    // extra (empty) prior-footholds message appended.
    const firstTurn = seenMessages[0] ?? [];
    expect(firstTurn).toHaveLength(1);
    expect(firstTurn[0].role).toBe("user");
  });
});

import { describe, it, expect } from "vitest";
import type { NativeRuntime, NativeRuntimeResult } from "../runtime/types.js";
import {
  SEMANTIC_DEDUPE_BATCH_SIZE,
  semanticDedupe,
  buildDedupePrompt,
  validateDedupePayload,
  mappingFromClusters,
  DedupeValidationError,
  type DedupeItem,
  type DedupePayload,
  type DedupeResult,
} from "./semantic-dedupe.js";

// ── Helpers ──

function dedupeItem(overrides: Partial<DedupeItem> & { id: string }): DedupeItem {
  return {
    summary: `Finding ${overrides.id}`,
    category: "use-after-free",
    location: "src/main.rs:42",
    description: "A sample finding for deduplication testing purposes.",
    ...overrides,
  };
}

/**
 * A NativeRuntime stub that returns one fixed text block.
 */
function stubRuntime(reply: string): NativeRuntime {
  return {
    type: "api",
    async isAvailable() {
      return true;
    },
    async executeNative(): Promise<NativeRuntimeResult> {
      return {
        content: [{ type: "text", text: reply }],
        stopReason: "end_turn",
        durationMs: 1,
      };
    },
  };
}

/**
 * A NativeRuntime stub that returns responses in sequence per-call.
 * Each call consums one response from the array.
 * A response can have `reply` (normal), `error` (runtime error), or `throw` (rejection).
 */
function seqRuntime(
  responses: Array<
    | { reply: string }
    | { error: string }
    | { throw: string }
  >,
): NativeRuntime {
  let i = 0;
  return {
    type: "api",
    async isAvailable() {
      return true;
    },
    async executeNative(): Promise<NativeRuntimeResult> {
      const r = responses[i++];
      if (!r) throw new Error("Unexpected extra LLM call");
      if ("throw" in r) throw new Error(r.throw);
      if ("error" in r) {
        return {
          content: [],
          stopReason: "error",
          durationMs: 1,
          error: r.error,
        };
      }
      return {
        content: [{ type: "text", text: r.reply }],
        stopReason: "end_turn",
        durationMs: 1,
      };
    },
  };
}

/**
 * Build a JSON string for a dedupe payload.
 */
function payloadJson(clusters: DedupePayload["clusters"]): string {
  return JSON.stringify({ clusters });
}

/**
 * Build a JSON string wrapped in markdown code fences.
 */
function fencedPayloadJson(clusters: DedupePayload["clusters"]): string {
  return "```json\n" + payloadJson(clusters) + "\n```";
}

// ── Tests ──

describe("buildDedupePrompt", () => {
  it("includes anchors and targets in the output", () => {
    const anchors = [dedupeItem({ id: "a1" })];
    const targets = [dedupeItem({ id: "t1" })];
    const { systemPrompt, userPrompt } = buildDedupePrompt(anchors, targets);

    expect(systemPrompt).toContain("semantic deduplication");
    expect(systemPrompt).toContain("immutable");
    expect(userPrompt).toContain("a1");
    expect(userPrompt).toContain("t1");
  });

  it("handles empty anchors", () => {
    const targets = [dedupeItem({ id: "t1" })];
    const { systemPrompt, userPrompt } = buildDedupePrompt([], targets);

    expect(userPrompt).toContain("None");
    expect(userPrompt).toContain("t1");
  });

  it("appends feedback when provided", () => {
    const { userPrompt } = buildDedupePrompt([], [dedupeItem({ id: "t1" })], "Parse error: invalid JSON");
    expect(userPrompt).toContain("Previous Error");
    expect(userPrompt).toContain("Parse error: invalid JSON");
  });
});

describe("validateDedupePayload", () => {
  const anchorIds = new Set(["a1", "a2"]);
  const targetIds = new Set(["t1", "t2", "t3"]);

  it("accepts a valid payload with singletons", () => {
    const payload: DedupePayload = {
      clusters: [
        { ids: ["t1"], reason: "Unique UAF in ioctl handler" },
        { ids: ["t2"], reason: "Unique OOB in read path" },
        { ids: ["t3"], reason: "Unique double-free in close" },
      ],
    };
    expect(() => validateDedupePayload(payload, anchorIds, targetIds)).not.toThrow();
  });

  it("accepts a valid payload with merged targets under an anchor", () => {
    const payload: DedupePayload = {
      clusters: [
        { ids: ["a1", "t1", "t2"], reason: "Same UAF in ioctl: all need the same refcount fix" },
        { ids: ["t3"], reason: "Unique" },
      ],
    };
    expect(() => validateDedupePayload(payload, anchorIds, targetIds)).not.toThrow();
  });

  it("rejects unknown ids", () => {
    const payload: DedupePayload = {
      clusters: [{ ids: ["t1", "unknown"], reason: "test" }],
    };
    expect(() => validateDedupePayload(payload, anchorIds, targetIds)).toThrow(DedupeValidationError);
  });

  it("rejects duplicate ids across clusters", () => {
    const payload: DedupePayload = {
      clusters: [
        { ids: ["t1"], reason: "first" },
        { ids: ["t1", "t2"], reason: "duplicate t1" },
      ],
    };
    expect(() => validateDedupePayload(payload, anchorIds, targetIds)).toThrow(DedupeValidationError);
  });

  it("rejects a cluster containing two different anchor ids", () => {
    const payload: DedupePayload = {
      clusters: [
        { ids: ["a1", "a2", "t1"], reason: "trying to merge anchors" },
        { ids: ["t2", "t3"], reason: "rest" },
      ],
    };
    expect(() => validateDedupePayload(payload, anchorIds, targetIds)).toThrow(DedupeValidationError);
  });

  it("rejects a cluster with no target ids", () => {
    const payload: DedupePayload = {
      clusters: [
        { ids: ["a1"], reason: "anchor only" },
        { ids: ["t1", "t2", "t3"], reason: "rest" },
      ],
    };
    expect(() => validateDedupePayload(payload, anchorIds, targetIds)).toThrow(DedupeValidationError);
  });

  it("rejects missing target coverage", () => {
    const payload: DedupePayload = {
      clusters: [
        { ids: ["t1", "t2"], reason: "merged" },
        // t3 is missing
      ],
    };
    expect(() => validateDedupePayload(payload, anchorIds, targetIds)).toThrow(DedupeValidationError);
  });

  it("rejects a cluster with empty ids array", () => {
    const payload: DedupePayload = {
      clusters: [
        { ids: [], reason: "empty" },
        { ids: ["t1", "t2", "t3"], reason: "rest" },
      ],
    };
    expect(() => validateDedupePayload(payload, anchorIds, targetIds)).toThrow(DedupeValidationError);
  });

  it("rejects a cluster with missing reason", () => {
    const payload = JSON.parse(
      JSON.stringify({
        clusters: [{ ids: ["t1", "t2"], reason: "" }],
      }),
    );
    expect(() => validateDedupePayload(payload, new Set(), new Set(["t1", "t2"]))).toThrow(
      DedupeValidationError,
    );
  });
});

describe("mappingFromClusters", () => {
  it("builds mappings for singletons", () => {
    const clusters: DedupePayload["clusters"] = [
      { ids: ["t1"], reason: "Unique" },
      { ids: ["t2"], reason: "Unique" },
    ];
    const { mappings, clusterReasons } = mappingFromClusters(
      clusters,
      new Set(),
      new Set(["t1", "t2"]),
      "scan-1",
    );

    expect(mappings["t1"].canonicalId).toBe("t1");
    expect(mappings["t1"].isCanonical).toBe(true);
    expect(mappings["t1"].clusterId).toBe("scan-1:t1");
    expect(mappings["t1"].reason).toBe("Unique");

    expect(mappings["t2"].canonicalId).toBe("t2");
    expect(mappings["t2"].isCanonical).toBe(true);
    expect(mappings["t2"].clusterId).toBe("scan-1:t2");

    expect(clusterReasons["t1"]).toBe("Unique");
    expect(clusterReasons["t2"]).toBe("Unique");
  });

  it("builds mappings with anchor as canonical", () => {
    const clusters: DedupePayload["clusters"] = [
      { ids: ["a1", "t1", "t2"], reason: "All same UAF in ioctl" },
      { ids: ["t3"], reason: "Other" },
    ];
    const { mappings, clusterReasons } = mappingFromClusters(
      clusters,
      new Set(["a1"]),
      new Set(["t1", "t2", "t3"]),
      "scan-1",
    );

    expect(mappings["a1"].canonicalId).toBe("a1");
    expect(mappings["a1"].isCanonical).toBe(true);
    expect(mappings["a1"].clusterId).toBe("scan-1:a1");

    expect(mappings["t1"].canonicalId).toBe("a1");
    expect(mappings["t1"].isCanonical).toBe(false);
    expect(mappings["t1"].reason).toContain("Duplicate of a1");

    expect(mappings["t2"].canonicalId).toBe("a1");
    expect(mappings["t2"].isCanonical).toBe(false);

    expect(clusterReasons["a1"]).toBe("All same UAF in ioctl");
  });

  it("first target is canonical when no anchor in cluster", () => {
    const clusters: DedupePayload["clusters"] = [
      { ids: ["t1", "t2"], reason: "Same root cause" },
    ];
    const { mappings } = mappingFromClusters(
      clusters,
      new Set(),
      new Set(["t1", "t2"]),
      "scan-1",
    );

    expect(mappings["t1"].canonicalId).toBe("t1");
    expect(mappings["t1"].isCanonical).toBe(true);
    expect(mappings["t2"].canonicalId).toBe("t1");
    expect(mappings["t2"].isCanonical).toBe(false);
  });
});

describe("semanticDedupe", () => {
  it("returns existing anchors unchanged when there are no targets", async () => {
    const anchors = [dedupeItem({ id: "a1" })];
    // Pass items = anchors (same as anchors) — they should be filtered out
    const result = await semanticDedupe(anchors, stubRuntime(""), { anchors, scanId: "s1" });

    expect(result.mappings["a1"].canonicalId).toBe("a1");
    expect(result.mappings["a1"].isCanonical).toBe(true);
    expect(result.modelCalls).toBe(0);
    expect(result.retries).toBe(0);
  });

  it("singleton passthrough: each unique finding maps to itself", async () => {
    const items = [
      dedupeItem({ id: "t1", category: "use-after-free" }),
      dedupeItem({ id: "t2", category: "use-after-free" }),
      dedupeItem({ id: "t3", category: "out-of-bounds-read" }),
    ];

    const runtime = stubRuntime(
      payloadJson([
        { ids: ["t1"], reason: "Unique UAF in ioctl handler" },
        { ids: ["t2"], reason: "Unique UAF in read path (different function)" },
        { ids: ["t3"], reason: "Unique OOB" },
      ]),
    );

    const result = await semanticDedupe(items, runtime, { scanId: "s1" });

    expect(result.mappings["t1"].canonicalId).toBe("t1");
    expect(result.mappings["t1"].isCanonical).toBe(true);
    expect(result.mappings["t2"].canonicalId).toBe("t2");
    expect(result.mappings["t2"].isCanonical).toBe(true);
    expect(result.mappings["t3"].canonicalId).toBe("t3");
    expect(result.mappings["t3"].isCanonical).toBe(true);
    expect(result.modelCalls).toBe(1);
    expect(result.retries).toBe(0);
  });

  it("merge by same root cause: clusters targets under same canonical", async () => {
    const items = [
      dedupeItem({ id: "t1", location: "src/ioctl.c:120" }),
      dedupeItem({ id: "t2", location: "src/ioctl.c:120" }),
      dedupeItem({ id: "t3", location: "src/read.c:50" }),
    ];

    const runtime = stubRuntime(
      payloadJson([
        { ids: ["t1", "t2"], reason: "Both UAF in the same ioctl handler — one refcount fix" },
        { ids: ["t3"], reason: "Unique UAF in read path" },
      ]),
    );

    const result = await semanticDedupe(items, runtime, { scanId: "s1" });

    // t1 is canonical for the merged group
    expect(result.mappings["t1"].canonicalId).toBe("t1");
    expect(result.mappings["t1"].isCanonical).toBe(true);
    expect(result.mappings["t1"].clusterId).toBe("s1:t1");

    // t2 points to t1
    expect(result.mappings["t2"].canonicalId).toBe("t1");
    expect(result.mappings["t2"].isCanonical).toBe(false);
    expect(result.mappings["t2"].reason).toContain("Duplicate of t1");

    // t3 is its own canonical
    expect(result.mappings["t3"].canonicalId).toBe("t3");
    expect(result.mappings["t3"].isCanonical).toBe(true);

    expect(result.modelCalls).toBe(1);
  });

  it("refuses to merge same-class-different-location when LLM returns singletons", async () => {
    // Two UAFs in different functions — LLM correctly keeps them separate
    const items = [
      dedupeItem({ id: "t1", category: "use-after-free", location: "src/ioctl.c:120" }),
      dedupeItem({ id: "t2", category: "use-after-free", location: "src/read.c:50" }),
    ];

    const runtime = stubRuntime(
      payloadJson([
        { ids: ["t1"], reason: "UAF in ioctl — unique" },
        { ids: ["t2"], reason: "UAF in read path — different function" },
      ]),
    );

    const result = await semanticDedupe(items, runtime, { scanId: "s1" });

    expect(result.mappings["t1"].canonicalId).toBe("t1");
    expect(result.mappings["t2"].canonicalId).toBe("t2");
    expect(result.modelCalls).toBe(1);
  });

  it("clusters targets under an existing anchor", async () => {
    const anchors = [dedupeItem({ id: "a1", location: "src/ioctl.c:120" })];
    const targets = [
      dedupeItem({ id: "t1", location: "src/ioctl.c:120" }),
      dedupeItem({ id: "t2", location: "src/read.c:50" }),
    ];

    const runtime = stubRuntime(
      payloadJson([
        { ids: ["a1", "t1"], reason: "Same UAF in ioctl — duplicate of existing anchor" },
        { ids: ["t2"], reason: "UAF in read path — unique" },
      ]),
    );

    const result = await semanticDedupe([...anchors, ...targets], runtime, { anchors, scanId: "s1" });

    // Anchor stays canonical
    expect(result.mappings["a1"].canonicalId).toBe("a1");
    expect(result.mappings["a1"].isCanonical).toBe(true);

    // t1 deduped under anchor
    expect(result.mappings["t1"].canonicalId).toBe("a1");
    expect(result.mappings["t1"].isCanonical).toBe(false);
    expect(result.mappings["t1"].reason).toContain("Duplicate of a1");

    // t2 is its own canonical
    expect(result.mappings["t2"].canonicalId).toBe("t2");
    expect(result.mappings["t2"].isCanonical).toBe(true);
  });

  it("anchor immutability across two sequential batches", async () => {
    // Create enough items to span batches: batch 1 gets SEMANTIC_DEDUPE_BATCH_SIZE items,
    // batch 2 gets the remainder. Batch 1 clusters some under a canonical; batch 2
    // should see that canonical as an anchor.
    const batchSize = SEMANTIC_DEDUPE_BATCH_SIZE;

    // Items 0..batchSize-1: all at the same location, LLM clusters t0+t1, rest singletons.
    // t0 becomes the canonical anchor seen by batch 2.
    const batch1Items: DedupeItem[] = [];
    for (let i = 0; i < batchSize; i++) {
      batch1Items.push(dedupeItem({ id: `b1-${i}`, location: `src/file${i}.c:10` }));
    }

    // Items batchSize..: t_batch_1 clusters under batch 1's canonical t0 (now an anchor).
    const batch2Target = dedupeItem({ id: "b2-x", location: "src/extra.c:10" });

    const allItems = [...batch1Items, batch2Target];

    // Batch 1 LLM response: t0+t1 merge, everything else singleton
    const b1Clusters = [
      { ids: ["b1-0", "b1-1"], reason: "Same UAF in file0.c" },
      ...batch1Items.slice(2).map((t) => ({ ids: [t.id], reason: "Unique" })),
    ];

    // Batch 2 LLM response: cluster b2-x under anchor b1-0
    const b2Clusters = [
      { ids: ["b1-0", "b2-x"], reason: "Same root cause as existing anchor b1-0" },
    ];

    const runtime = seqRuntime([
      { reply: payloadJson(b1Clusters) },
      { reply: payloadJson(b2Clusters) },
    ]);

    const result = await semanticDedupe(allItems, runtime, { scanId: "s1" });

    // Batch 1: b1-0 is canonical for b1-0+b1-1
    expect(result.mappings["b1-0"].canonicalId).toBe("b1-0");
    expect(result.mappings["b1-0"].isCanonical).toBe(true);
    expect(result.mappings["b1-1"].canonicalId).toBe("b1-0");
    expect(result.mappings["b1-1"].isCanonical).toBe(false);

    // Others in batch 1 are their own canonical
    expect(result.mappings["b1-2"].canonicalId).toBe("b1-2");
    expect(result.mappings["b1-2"].isCanonical).toBe(true);
    expect(result.mappings[`b1-${batchSize - 1}`].canonicalId).toBe(`b1-${batchSize - 1}`);

    // Batch 2: b2-x clustered under anchor b1-0 (from batch 1)
    expect(result.mappings["b2-x"].canonicalId).toBe("b1-0");
    expect(result.mappings["b2-x"].isCanonical).toBe(false);
    expect(result.mappings["b2-x"].reason).toContain("Duplicate of b1-0");

    expect(result.modelCalls).toBe(2);
    expect(result.retries).toBe(0);
  });

  it("retry-then-success: recovers from parse errors", async () => {
    const items = [
      dedupeItem({ id: "t1" }),
      dedupeItem({ id: "t2" }),
    ];

    // First call returns garbage, second call succeeds
    const runtime = seqRuntime([
      { reply: "I think these findings are all different" }, // unparseable
      {
        reply: payloadJson([
          { ids: ["t1"], reason: "Unique" },
          { ids: ["t2"], reason: "Unique" },
        ]),
      },
    ]);

    const result = await semanticDedupe(items, runtime, { maxRetries: 2, scanId: "s1" });

    expect(result.mappings["t1"].canonicalId).toBe("t1");
    expect(result.mappings["t2"].canonicalId).toBe("t2");
    expect(result.modelCalls).toBe(2);
    expect(result.retries).toBe(1);
  });

  it("retry-then-success: recovers from validation errors", async () => {
    const items = [
      dedupeItem({ id: "t1" }),
      dedupeItem({ id: "t2" }),
    ];

    // First call returns a cluster with an unknown id (validation fails), second succeeds
    const runtime = seqRuntime([
      { reply: payloadJson([{ ids: ["t1", "nonexistent"], reason: "bad" }]) },
      {
        reply: payloadJson([
          { ids: ["t1"], reason: "Unique" },
          { ids: ["t2"], reason: "Unique" },
        ]),
      },
    ]);

    const result = await semanticDedupe(items, runtime, { maxRetries: 2, scanId: "s1" });

    expect(result.mappings["t1"].canonicalId).toBe("t1");
    expect(result.mappings["t2"].canonicalId).toBe("t2");
    expect(result.modelCalls).toBe(2);
    expect(result.retries).toBe(1);
  });

  it("retry-exhaustion fail-soft: all findings survive as canonicals", async () => {
    const items = [
      dedupeItem({ id: "t1" }),
      dedupeItem({ id: "t2" }),
    ];

    // All calls fail
    const runtime = seqRuntime([
      { reply: "garbage" },
      { reply: "more garbage" },
      { reply: "still garbage" }, // maxRetries=2 means 3 attempts (0, 1, 2)
    ]);

    const result = await semanticDedupe(items, runtime, { maxRetries: 2, scanId: "s1" });

    // Fail-soft: every target becomes its own canonical
    expect(result.mappings["t1"].canonicalId).toBe("t1");
    expect(result.mappings["t1"].isCanonical).toBe(true);
    expect(result.mappings["t1"].reason).toBe("dedupe-error-fallback");

    expect(result.mappings["t2"].canonicalId).toBe("t2");
    expect(result.mappings["t2"].isCanonical).toBe(true);
    expect(result.mappings["t2"].reason).toBe("dedupe-error-fallback");

    expect(result.modelCalls).toBe(3);
    expect(result.retries).toBe(2); // retries = attempt 1 + attempt 2
  });

  it("fail-soft on runtime error exhaustion", async () => {
    const items = [dedupeItem({ id: "t1" })];

    const runtime = seqRuntime([
      { error: "API timeout" },
      { error: "API timeout again" },
      { error: "API timeout thrice" },
    ]);

    const result = await semanticDedupe(items, runtime, { maxRetries: 2, scanId: "s1" });

    expect(result.mappings["t1"].canonicalId).toBe("t1");
    expect(result.mappings["t1"].isCanonical).toBe(true);
    expect(result.mappings["t1"].reason).toBe("dedupe-error-fallback");
    expect(result.modelCalls).toBe(3);
  });

  it("handles markdown-fenced JSON responses", async () => {
    const items = [
      dedupeItem({ id: "t1" }),
      dedupeItem({ id: "t2" }),
    ];

    const runtime = stubRuntime(
      fencedPayloadJson([
        { ids: ["t1"], reason: "Unique" },
        { ids: ["t2"], reason: "Unique" },
      ]),
    );

    const result = await semanticDedupe(items, runtime, { scanId: "s1" });

    expect(result.mappings["t1"].canonicalId).toBe("t1");
    expect(result.mappings["t2"].canonicalId).toBe("t2");
    expect(result.modelCalls).toBe(1);
  });

  it("processes more than BATCH_SIZE findings in multiple batches", async () => {
    const count = SEMANTIC_DEDUPE_BATCH_SIZE + 5;
    const items: DedupeItem[] = [];
    for (let i = 0; i < count; i++) {
      items.push(dedupeItem({ id: `t${i}`, location: `src/file${i}.c:10` }));
    }

    // Each batch returns every item as its own singleton
    // Batch 1: covers t0..t49, batch 2: covers t50..t54
    const batch1Targets = items.slice(0, SEMANTIC_DEDUPE_BATCH_SIZE).map((t) => t.id);
    const batch2Targets = items.slice(SEMANTIC_DEDUPE_BATCH_SIZE).map((t) => t.id);

    const runtime = seqRuntime([
      {
        reply: payloadJson(
          batch1Targets.map((id) => ({ ids: [id], reason: `Unique finding ${id}` })),
        ),
      },
      {
        reply: payloadJson(
          batch2Targets.map((id) => ({ ids: [id], reason: `Unique finding ${id}` })),
        ),
      },
    ]);

    const result = await semanticDedupe(items, runtime, { scanId: "s1" });

    expect(result.modelCalls).toBe(2);
    expect(Object.keys(result.mappings).length).toBe(count);
    for (let i = 0; i < count; i++) {
      expect(result.mappings[`t${i}`].canonicalId).toBe(`t${i}`);
      expect(result.mappings[`t${i}`].isCanonical).toBe(true);
    }
  });

  it("includes provenance in the result", async () => {
    const items = [dedupeItem({ id: "t1" })];
    const runtime = stubRuntime(payloadJson([{ ids: ["t1"], reason: "Unique" }]));

    const result = await semanticDedupe(items, runtime, { scanId: "s1" });

    expect(result.mappings).toBeDefined();
    expect(typeof result.modelCalls).toBe("number");
    expect(typeof result.retries).toBe("number");
    expect(result.clusterReasons).toBeDefined();
    expect(result.clusterReasons["t1"]).toBe("Unique");
  });
});
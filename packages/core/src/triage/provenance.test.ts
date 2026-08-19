/**
 * Tests for triage provenance (`provenance.ts`).
 *
 * The property under test throughout is the honesty of the summary: it must
 * never report that a layer ran unless a verdict says so, and it must keep
 * "stood down" and "left no trace" distinguishable.
 */

import { describe, it, expect, afterEach } from "vitest";
import type { Finding, LayerVerdict, TriageLayerName } from "@0sec/shared";
import {
  summarizeTriageProvenance,
  formatTriageProvenance,
  UNINSTRUMENTED_LAYERS,
  OPT_IN_MOAT_LAYERS,
} from "./provenance.js";
import { LAYER_REGISTRY } from "./router/layer-registry.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f-1",
    templateId: "t",
    title: "x",
    description: "x",
    severity: "medium",
    category: "xss",
    status: "discovered",
    evidence: { request: "", response: "", analysis: "" },
    confidence: 0.5,
    timestamp: Date.now(),
    ...overrides,
  } as Finding;
}

function verdict(
  layer: TriageLayerName,
  kind: LayerVerdict["verdict"],
  overrides: Partial<LayerVerdict> = {},
): LayerVerdict {
  return {
    layer,
    verdict: kind,
    reason: `${layer}:${kind}`,
    durationMs: 10,
    costUsd: 0,
    ...overrides,
  };
}

describe("summarizeTriageProvenance — status derivation", () => {
  it("covers every registry layer exactly once, in canonical order", () => {
    const provenance = summarizeTriageProvenance(makeFinding());
    expect(provenance.layers.map((l) => l.layer)).toEqual(
      LAYER_REGISTRY.map((e) => e.id),
    );
  });

  /**
   * The pre-instrumentation / empty-blob case. Reporting these as "skipped"
   * would assert the layers deliberately stood down, which the data does not
   * support.
   */
  it("reports every layer unrecorded when the finding has no verdicts", () => {
    const provenance = summarizeTriageProvenance(makeFinding());

    expect(provenance.executed).toHaveLength(0);
    expect(provenance.skipped).toHaveLength(0);
    expect(provenance.unrecorded).toHaveLength(LAYER_REGISTRY.length);
    expect(provenance.moatEngaged).toBe(false);
  });

  it("classifies a non-skip verdict as executed", () => {
    for (const kind of ["pass", "reject", "downgrade", "error"] as const) {
      const provenance = summarizeTriageProvenance(
        makeFinding({ layerVerdicts: [verdict("oracle", kind)] }),
      );
      expect(provenance.executed).toContain("oracle");
      expect(provenance.skipped).not.toContain("oracle");
    }
  });

  it("classifies a skip-only verdict as skipped and keeps its reason", () => {
    const provenance = summarizeTriageProvenance(
      makeFinding({
        layerVerdicts: [
          verdict("reachability", "skip", {
            reason: "0SEC_FEATURE_REACHABILITY_GATE=0",
          }),
        ],
      }),
    );

    const layer = provenance.layers.find((l) => l.layer === "reachability");
    expect(layer?.status).toBe("skipped");
    expect(layer?.reason).toBe("0SEC_FEATURE_REACHABILITY_GATE=0");
  });

  /** A layer that skipped once and later ran counts as executed. */
  it("treats a layer with mixed verdicts as executed", () => {
    const provenance = summarizeTriageProvenance(
      makeFinding({
        layerVerdicts: [verdict("oracle", "skip"), verdict("oracle", "pass")],
      }),
    );
    expect(provenance.executed).toContain("oracle");
    expect(provenance.layers.find((l) => l.layer === "oracle")?.verdicts).toHaveLength(2);
  });

  it("sums duration and cost across a layer's verdicts", () => {
    const provenance = summarizeTriageProvenance(
      makeFinding({
        layerVerdicts: [
          verdict("pov_gate", "pass", { durationMs: 100, costUsd: 0.25 }),
          verdict("pov_gate", "pass", { durationMs: 50, costUsd: 0.1 }),
        ],
      }),
    );

    const layer = provenance.layers.find((l) => l.layer === "pov_gate");
    expect(layer?.durationMs).toBe(150);
    expect(layer?.costUsd).toBeCloseTo(0.35);
    expect(provenance.totalCostUsd).toBeCloseTo(0.35);
    expect(provenance.totalDurationMs).toBe(150);
  });

  /** Persisted JSON can outlive a layer rename; a display path must not throw. */
  it("ignores verdicts naming a layer outside the registry", () => {
    const provenance = summarizeTriageProvenance(
      makeFinding({
        layerVerdicts: [
          { ...verdict("oracle", "pass"), layer: "ghost_layer" as TriageLayerName },
        ],
      }),
    );
    expect(provenance.executed).toHaveLength(0);
    expect(provenance.layers).toHaveLength(LAYER_REGISTRY.length);
  });
});

describe("summarizeTriageProvenance — moat engagement", () => {
  /**
   * The core claim-gate. A scan running the shipped default records only
   * always-on layers, and that must NOT read as the FP moat having run.
   */
  it("reports the moat as NOT engaged when only always-on layers ran", () => {
    const provenance = summarizeTriageProvenance(
      makeFinding({
        layerVerdicts: [
          verdict("holding_it_wrong", "pass"),
          verdict("evidence_gate", "pass"),
          verdict("oracle", "pass"),
          verdict("reachability", "skip"),
          verdict("multi_modal", "skip"),
          verdict("publishability", "skip"),
          verdict("pov_gate", "skip"),
          verdict("poc_gen", "skip"),
        ],
      }),
    );

    expect(provenance.executed).toEqual(["holding_it_wrong", "evidence_gate", "oracle"]);
    expect(provenance.moatEngaged).toBe(false);
    expect(provenance.moatLayersExecuted).toHaveLength(0);
  });

  it("reports the moat as engaged once an opt-in layer executes", () => {
    const provenance = summarizeTriageProvenance(
      makeFinding({
        layerVerdicts: [verdict("holding_it_wrong", "pass"), verdict("pov_gate", "pass")],
      }),
    );

    expect(provenance.moatEngaged).toBe(true);
    expect(provenance.moatLayersExecuted).toEqual(["pov_gate"]);
  });

  /** A skipped opt-in layer is not engagement — the distinction is the point. */
  it("does not count a skipped opt-in layer as engagement", () => {
    const provenance = summarizeTriageProvenance(
      makeFinding({ layerVerdicts: [verdict("pov_gate", "skip")] }),
    );
    expect(provenance.moatEngaged).toBe(false);
  });

  it("marks each opt-in moat layer with optInMoatLayer", () => {
    const provenance = summarizeTriageProvenance(makeFinding());
    const flagged = provenance.layers.filter((l) => l.optInMoatLayer).map((l) => l.layer);
    expect(flagged.sort()).toEqual([...OPT_IN_MOAT_LAYERS].sort());
  });
});

describe("summarizeTriageProvenance — uninstrumented layers", () => {
  /**
   * Pins the uninstrumented set so it cannot drift silently. If a layer starts
   * emitting verdicts, delete it from `UNINSTRUMENTED_LAYERS` and this test
   * will tell you to.
   */
  it("pins the layers that emit no telemetry anywhere in the engine", () => {
    expect([...UNINSTRUMENTED_LAYERS].sort()).toEqual([
      "consensus",
      "kernel_oracle",
      "structured_verify",
    ]);
  });

  it("explains an uninstrumented layer differently from an unreached one", () => {
    const provenance = summarizeTriageProvenance(makeFinding());

    const consensus = provenance.layers.find((l) => l.layer === "consensus");
    expect(consensus?.uninstrumented).toBe(true);
    expect(consensus?.status).toBe("unrecorded");
    expect(consensus?.reason).toContain("no instrumentation");

    const oracle = provenance.layers.find((l) => l.layer === "oracle");
    expect(oracle?.uninstrumented).toBe(false);
    expect(oracle?.status).toBe("unrecorded");
    expect(oracle?.reason).toContain("did not run");
    expect(oracle?.reason).not.toContain("no instrumentation");
  });
});

describe("summarizeTriageProvenance — reads the record, not the environment", () => {
  const saved = { ...process.env };
  afterEach(() => {
    process.env = { ...saved };
  });

  /**
   * The rule that makes persisted findings trustworthy: turning every moat
   * flag on in the current shell must not change the reported history of a
   * finding produced by a scan that ran without them.
   */
  it("does not report a layer as executed just because its flag is on now", () => {
    process.env["0SEC_FEATURE_POV_GATE"] = "1";
    process.env["0SEC_FEATURE_REACHABILITY_GATE"] = "1";
    process.env["0SEC_FEATURE_MULTIMODAL"] = "1";

    const provenance = summarizeTriageProvenance(
      makeFinding({ layerVerdicts: [verdict("holding_it_wrong", "pass")] }),
    );

    expect(provenance.executed).toEqual(["holding_it_wrong"]);
    expect(provenance.moatEngaged).toBe(false);
  });
});

describe("formatTriageProvenance", () => {
  it("leads with an explicit negative when the moat did not run", () => {
    const lines = formatTriageProvenance(
      summarizeTriageProvenance(
        makeFinding({ layerVerdicts: [verdict("holding_it_wrong", "pass")] }),
      ),
    );
    expect(lines[0]).toContain("FP moat NOT engaged");
  });

  it("names the layers that ran when the moat did run", () => {
    const lines = formatTriageProvenance(
      summarizeTriageProvenance(
        makeFinding({
          layerVerdicts: [verdict("pov_gate", "pass"), verdict("reachability", "pass")],
        }),
      ),
    );
    expect(lines[0]).toContain("FP moat engaged");
    expect(lines[0]).toContain("pov_gate");
    expect(lines[0]).toContain("reachability");
  });

  it("emits one line per registry layer after the two header lines", () => {
    const lines = formatTriageProvenance(summarizeTriageProvenance(makeFinding()));
    expect(lines).toHaveLength(LAYER_REGISTRY.length + 2);
  });
});

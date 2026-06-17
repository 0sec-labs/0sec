/**
 * Tests for kernel-weaponization-collector.ts
 *
 * Covers the corpus writer's row extraction + JSONL serialization:
 *   - the full chain tuple survives (write profile / sprays / root-tail)
 *   - oracle-REFUSED negative rows are preserved (reachedRung < attemptedRung)
 *   - both source shapes parse (orchestrator result jsonb + raw CLI JSON)
 *   - runs without an outcome are skipped
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  collectSampleFromRun,
  collectFromRunsFile,
  normalizeStep,
  toJsonl,
  ESCALATION_RUNGS,
  type WeaponizationSample,
} from "./kernel-weaponization-collector.js";

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "kernel-weap-collector-test-"));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

// ─── normalizeStep ──────────────────────────────────────────────────

describe("normalizeStep", () => {
  it("flags an oracle-REFUSED step (reached < attempted)", () => {
    const step = normalizeStep({
      strategy_id: "spray-msg_msg",
      title: "msg_msg reclaim",
      attempted_rung: "arb-write",
      reached_rung: "reclaim",
      reason: "oracle refused: no controlled overwrite observed",
    });
    expect(step.refused).toBe(true);
    expect(step.reason).toContain("oracle refused");
    expect(step.attemptedRung).toBe("arb-write");
    expect(step.reachedRung).toBe("reclaim");
  });

  it("does not flag a step that reached its attempted rung", () => {
    const step = normalizeStep({
      nodeId: "n1",
      targetRung: "reclaim",
      reachedRung: "reclaim",
      reason: "confirmed",
    });
    expect(step.refused).toBe(false);
    expect(step.stepId).toBe("n1");
  });

  it("tolerates a missing/empty step shape", () => {
    const step = normalizeStep({});
    expect(step.refused).toBe(false);
    expect(step.attemptedRung).toBe("");
  });
});

// ─── collectSampleFromRun — orchestrator result jsonb ───────────────

describe("collectSampleFromRun (orchestrator result jsonb)", () => {
  const run = {
    run_id: "vr-123",
    finding_id: "f-987",
    result: {
      legacy: false,
      weaponization: {
        highestRung: "arb-write",
        lpeAchieved: false,
        reclaimLanded: true,
        attempts: 3,
        detail: {
          perStep: [
            {
              strategyId: "reclaim",
              attemptedRung: "reclaim",
              reachedRung: "reclaim",
              reason: "confirmed reclaim",
            },
            {
              strategyId: "root-tail",
              attemptedRung: "root",
              reachedRung: "arb-write",
              reason: "REFUSED: no kaslr leak, modprobe_path unresolved",
            },
          ],
          exploitContext: {
            writeProfile: { controllable: true, writeWidth: "controlled" },
            sprayPlans: [{ primitive: "msg_msg", bucketMatch: true }],
            rootTailPlan: { tail: "modprobe_path", kaslrOn: true, hasLeak: false },
          },
        },
      },
    },
  };

  it("carries the full exploit tuple into input", () => {
    const s = collectSampleFromRun(run);
    expect(s).toBeDefined();
    expect(s!.input.findingId).toBe("f-987");
    expect(s!.input.writeProfile).toEqual({
      controllable: true,
      writeWidth: "controlled",
    });
    expect(s!.input.sprayPlans).toEqual([{ primitive: "msg_msg", bucketMatch: true }]);
    expect(s!.input.rootTailPlan).toMatchObject({ tail: "modprobe_path" });
  });

  it("preserves the oracle-REFUSED negative row in the label", () => {
    const s = collectSampleFromRun(run)!;
    expect(s.label.highestRung).toBe("arb-write");
    expect(s.label.lpeAchieved).toBe(false);
    expect(s.label.reclaimLanded).toBe(true);
    expect(s.label.perStep).toHaveLength(2);
    const refused = s.label.perStep.filter((p) => p.refused);
    expect(refused).toHaveLength(1);
    expect(refused[0].reachedRung).toBe("arb-write");
    expect(refused[0].attemptedRung).toBe("root");
    expect(s.label.refusedReasons).toEqual([
      "REFUSED: no kaslr leak, modprobe_path unresolved",
    ]);
  });
});

// ─── collectSampleFromRun — raw CLI JSON (flat, snake_case) ──────────

describe("collectSampleFromRun (raw pwnkit exploit JSON)", () => {
  it("parses the flat CLI shape with per_step + exploit_context", () => {
    const cli = {
      finding_id: "cli-1",
      highest_rung: "reclaim",
      lpe_achieved: false,
      reclaim_landed: true,
      per_step: [
        {
          strategy_id: "s1",
          attempted_rung: "arb-write",
          reached_rung: "reclaim",
          reason: "refused",
        },
      ],
      exploit_context: null,
    };
    const s = collectSampleFromRun(cli)!;
    expect(s.label.highestRung).toBe("reclaim");
    expect(s.label.perStep[0].refused).toBe(true);
    expect(s.input.writeProfile).toBeUndefined();
  });

  it("skips a run with no recognizable outcome", () => {
    expect(collectSampleFromRun({ notes: "plain verify" })).toBeUndefined();
    expect(collectSampleFromRun(null)).toBeUndefined();
    expect(collectSampleFromRun("nope")).toBeUndefined();
  });
});

// ─── toJsonl serialization + round-trip ─────────────────────────────

describe("toJsonl + collectFromRunsFile", () => {
  it("emits one valid JSON object per run, round-trips losslessly", () => {
    const runs = {
      runs: [
        {
          run_id: "a",
          result: {
            weaponization: {
              highestRung: "root",
              lpeAchieved: true,
              reclaimLanded: true,
              detail: { perStep: [], exploitContext: {} },
            },
          },
        },
        { notes: "no outcome — skipped" },
      ],
    };
    const file = join(tmp, "runs.json");
    writeFileSync(file, JSON.stringify(runs));

    const samples = collectFromRunsFile(file);
    expect(samples).toHaveLength(1); // the no-outcome run is dropped
    const line = toJsonl(samples[0]);
    const parsed = JSON.parse(line) as WeaponizationSample;
    expect(parsed.label.highestRung).toBe("root");
    expect(parsed.label.lpeAchieved).toBe(true);
    expect(parsed.source).toBe("a");
  });

  it("exposes the canonical rung ladder weakest → strongest", () => {
    expect(ESCALATION_RUNGS[0]).toBe("none");
    expect(ESCALATION_RUNGS[ESCALATION_RUNGS.length - 1]).toBe("root");
  });
});

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
import {
  writeFileSync,
  readFileSync,
  existsSync,
  mkdtempSync,
  rmSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  collectSampleFromRun,
  collectFromRunsFile,
  normalizeStep,
  toJsonl,
  appendWeaponizationRun,
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

describe("collectSampleFromRun (raw 0sec exploit JSON)", () => {
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

// ─── appendWeaponizationRun — the inline auto-populate path (#1126) ──

describe("appendWeaponizationRun (inline auto-populate)", () => {
  it("appends a real root run AND an oracle-REFUSED negative to the JSONL", () => {
    const corpus = join(tmp, "kernel-weaponization-v1.jsonl");
    expect(existsSync(corpus)).toBe(false);

    // A genuine root (positive) run.
    const rooted = appendWeaponizationRun(
      {
        run_id: "climb-1-boot1",
        finding_id: "f-root",
        result: {
          weaponization: {
            highestRung: "root",
            lpeAchieved: true,
            reclaimLanded: true,
            detail: {
              perStep: [
                {
                  nodeId: "root-tail",
                  targetRung: "root",
                  reachedRung: "root",
                  reason: "root credited",
                },
              ],
            },
          },
        },
      },
      { corpusPath: corpus },
    );

    // A non-root boot — itself a labeled negative — whose per-step record is an
    // oracle-REFUSED row (reachedRung < targetRung).
    const refused = appendWeaponizationRun(
      {
        run_id: "climb-1-boot2",
        finding_id: "f-refused",
        result: {
          weaponization: {
            highestRung: "arb-write",
            lpeAchieved: false,
            reclaimLanded: true,
            detail: {
              perStep: [
                {
                  nodeId: "root-tail",
                  targetRung: "root",
                  reachedRung: "arb-write",
                  reason: "REFUSED: no kaslr leak",
                },
              ],
            },
          },
        },
      },
      { corpusPath: corpus },
    );

    expect(rooted).toBe(true);
    expect(refused).toBe(true);

    const lines = readFileSync(corpus, "utf8").trim().split("\n");
    expect(lines).toHaveLength(2);
    const rows = lines.map((l) => JSON.parse(l) as WeaponizationSample);

    expect(rows[0].label.lpeAchieved).toBe(true);
    expect(rows[0].source).toBe("climb-1-boot1");

    // The negative row is preserved with its REFUSED per-step verdict.
    expect(rows[1].label.lpeAchieved).toBe(false);
    expect(rows[1].label.highestRung).toBe("arb-write");
    const refusedSteps = rows[1].label.perStep.filter((p) => p.refused);
    expect(refusedSteps).toHaveLength(1);
    expect(rows[1].label.refusedReasons).toEqual(["REFUSED: no kaslr leak"]);
  });

  it("skips a run with no recognizable outcome and never creates the file", () => {
    const corpus = join(tmp, "empty.jsonl");
    const wrote = appendWeaponizationRun(
      { notes: "plain verify, no weaponization" },
      { corpusPath: corpus },
    );
    expect(wrote).toBe(false);
    expect(existsSync(corpus)).toBe(false);
  });

  it("is best-effort — an unwritable path is swallowed, not thrown", () => {
    // A path whose parent is an existing FILE (not a dir) makes mkdir/write
    // fail; the helper must report false, not throw.
    const asFile = join(tmp, "afile");
    writeFileSync(asFile, "x");
    const logged: string[] = [];
    const wrote = appendWeaponizationRun(
      {
        finding_id: "f-x",
        highest_rung: "reclaim",
        lpe_achieved: false,
        per_step: [],
      },
      { corpusPath: join(asFile, "nested", "corpus.jsonl"), logger: (l) => logged.push(l) },
    );
    expect(wrote).toBe(false);
    expect(logged.some((l) => l.includes("append skipped"))).toBe(true);
  });
});

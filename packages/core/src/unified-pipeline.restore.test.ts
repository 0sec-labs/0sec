/**
 * 0sec#193 — `restorePersistedFinding` round-trip for `verificationSpec`.
 *
 * CodeRabbit flagged that `Finding.verificationSpec` is part of the shared
 * model but the unified-pipeline reload path was dropping it on restore.
 * Cloud's canary watcher then had nothing to re-evaluate against on the
 * next upstream HEAD refresh, breaking the whole point of the spec.
 *
 * These tests exercise the restore helper directly so the wire round-trip
 * is captured in a unit test rather than only via an end-to-end resume.
 */
import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { osecDB } from "@0sec/db";
import type {
  Finding,
  LayerVerdict,
  PocStep,
  ScanConfig,
  VerificationSpec,
} from "@0sec/shared";
import { restorePersistedFinding } from "./unified-pipeline.js";

const tempDirs: string[] = [];
type PersistedFindingRestoreRow = Parameters<typeof restorePersistedFinding>[0];

function makeDb(): { db: osecDB; scanId: string } {
  const dir = mkdtempSync(join(tmpdir(), "0sec-restore-vspec-"));
  tempDirs.push(dir);
  const db = new osecDB(join(dir, "0sec.db"));
  const scanConfig: ScanConfig = {
    target: "http://example.test",
    depth: "default",
    format: "json",
    runtime: "api",
    mode: "deep",
  };
  const scanId = db.createScan(scanConfig);
  return { db, scanId };
}

function makeSpec(): VerificationSpec {
  return {
    code: [
      {
        kind: "file-contains",
        file: "app/users.ts",
        pattern: "db\\.query.*req\\.body",
      },
      { kind: "file-exists", file: "lib/db.ts" },
    ],
    behavior: {
      steps: [{ method: "GET", path: "/users", expect: "success" }],
    },
  };
}

function makeFinding(spec?: VerificationSpec): Finding {
  return {
    id: randomUUID(),
    templateId: "manual",
    title: "SQLi on /users",
    description: "user input concatenated into SQL",
    severity: "high",
    category: "sql-injection",
    status: "discovered",
    evidence: {
      request: "POST /users",
      response: "[{...}]",
      analysis: "db.query interpolates req.body",
    },
    verificationSpec: spec,
    timestamp: 1_700_000_000_000,
  };
}

function makePersistedRow(
  overrides: Partial<PersistedFindingRestoreRow>,
): PersistedFindingRestoreRow {
  return {
    id: "f-1",
    scanId: "scan-1",
    templateId: "manual",
    title: "still useful",
    description: "x",
    severity: "low",
    category: "sql-injection",
    status: "discovered",
    fingerprint: null,
    triageStatus: "new",
    triageNote: null,
    triagedAt: null,
    workflowStatus: "backlog",
    workflowAssignee: null,
    workflowUpdatedAt: null,
    score: null,
    confidence: null,
    cvssVector: null,
    cvssScore: null,
    evidenceRequest: "x",
    evidenceResponse: "y",
    evidenceAnalysis: null,
    layerVerdicts: null,
    impactAssessment: null,
    pocSteps: null,
    verificationSpec: null,
    pocExecution: null,
    semanticDedupe: null,
    findingRank: null,
    timestamp: 0,
    ...overrides,
  };
}

describe("restorePersistedFinding (0sec#193 — verificationSpec round-trip)", () => {
  afterEach(() => {
    for (const dir of tempDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("threads verificationSpec through saveFinding → getFindings → restore", () => {
    const { db, scanId } = makeDb();
    try {
      const spec = makeSpec();
      const original = makeFinding(spec);
      db.saveFinding(scanId, original);

      const rows = db.getFindings(scanId);
      expect(rows).toHaveLength(1);

      const restored = restorePersistedFinding(rows[0]);
      expect(restored.verificationSpec).toEqual(spec);
      // Other fields still survive — the new column doesn't disrupt the
      // existing rehydration.
      expect(restored.id).toBe(original.id);
      expect(restored.title).toBe(original.title);
      expect(restored.evidence.analysis).toBe("db.query interpolates req.body");
    } finally {
      db.close();
    }
  });

  it("restores verificationSpec=undefined when the column is NULL (legacy row)", () => {
    const { db, scanId } = makeDb();
    try {
      const original = makeFinding(undefined);
      db.saveFinding(scanId, original);
      const rows = db.getFindings(scanId);
      const restored = restorePersistedFinding(rows[0]);
      expect(restored.verificationSpec).toBeUndefined();
    } finally {
      db.close();
    }
  });

  it("drops a malformed JSON column without breaking the restore", () => {
    // Simulate a row where the verificationSpec column got corrupted
    // (older write path, manual edit, etc.). The finding must still
    // restore — just without a usable spec.
    const restored = restorePersistedFinding(makePersistedRow({
      verificationSpec: "{not json [",
    }));
    expect(restored.verificationSpec).toBeUndefined();
    expect(restored.title).toBe("still useful");
  });

  it("drops a JSON object that lacks the `code` array (defensive)", () => {
    const restored = restorePersistedFinding(makePersistedRow({
      id: "f-2",
      title: "weird",
      // Looks like JSON but isn't a VerificationSpec.
      verificationSpec: JSON.stringify({ foo: "bar" }),
    }));
    expect(restored.verificationSpec).toBeUndefined();
  });

  it("accepts an already-parsed object (test/sink-shim path)", () => {
    const spec = makeSpec();
    const restored = restorePersistedFinding(makePersistedRow({
      id: "f-3",
      title: "preparsed",
      verificationSpec: spec,
    }));
    expect(restored.verificationSpec).toEqual(spec);
  });
});

// 0sec#414 — six additional persisted columns were being silently dropped
// on resume (pocSteps, layerVerdicts, pocExecution, workflowStatus,
// workflowAssignee, score). These tests pin the round-trip so the next
// regression fails loudly.

function makePocSteps(): PocStep[] {
  return [
    {
      id: "step-1",
      kind: "exploit",
      summary: "SQLi probe",
      action: {
        type: "http",
        method: "POST",
        url: "/users",
        body: "id=1' OR 1=1--",
      },
      expect: { type: "body-contains", text: "admin" },
    },
  ];
}

function makeLayerVerdicts(): LayerVerdict[] {
  return [
    {
      layer: "regex-quickcheck",
      verdict: "keep",
      reason: "pattern matched",
      durationMs: 4,
      costUsd: 0,
    },
  ];
}

function makePocExecution() {
  return {
    findingId: "f-1",
    startedAt: "2026-05-22T00:00:00Z",
    endedAt: "2026-05-22T00:00:01Z",
    overallVerdict: "exploit_still_works",
    steps: [
      {
        stepId: "step-1",
        verdict: "ok",
        durationMs: 17,
      },
    ],
  };
}

describe("restorePersistedFinding (0sec#414 — six-field round-trip)", () => {
  afterEach(() => {
    for (const dir of tempDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("round-trips pocSteps / layerVerdicts / post-process fields / workflow fields / score through saveFinding → getFindings → restore", () => {
    const { db, scanId } = makeDb();
    try {
      const pocSteps = makePocSteps();
      const layerVerdicts = makeLayerVerdicts();
      const finding: Finding = {
        ...makeFinding(makeSpec()),
        pocSteps,
        layerVerdicts,
        workflowStatus: "in_progress",
        semanticDedupe: {
          canonicalId: "canonical-finding",
          isCanonical: false,
          clusterId: "scan-1:canonical-finding",
          reason: "same endpoint and root cause",
        },
        findingRank: 3,
        workflowAssignee: "alice",
      };
      db.saveFinding(scanId, finding);

      // `pocExecution` and `score` are written via dedicated methods —
      // `saveFinding` only handles the initial-insert columns. Stamp
      // both to simulate the post-scoring / post-execution state.
      const pocExecution = makePocExecution();
      db.saveFindingPocExecution(finding.id, pocExecution);
      db.scoreFinding(finding.id, 87);

      const rows = db.getFindings(scanId);
      expect(rows).toHaveLength(1);

      const restored = restorePersistedFinding(rows[0]);
      expect(restored.pocSteps).toEqual(pocSteps);
      expect(restored.layerVerdicts).toEqual(layerVerdicts);
      expect(restored.workflowStatus).toBe("in_progress");
      expect(restored.workflowAssignee).toBe("alice");
      expect(restored.score).toBe(87);
      expect(restored.pocExecution).toEqual(pocExecution);
      expect(restored.semanticDedupe).toEqual(finding.semanticDedupe);
      expect(restored.findingRank).toBe(3);
      // workflowUpdatedAt is stamped by the writer on every save; it
      // should now thread back through the restore mapper as a string.
      expect(typeof restored.workflowUpdatedAt).toBe("string");
      expect(restored.workflowUpdatedAt).toBeTruthy();
    } finally {
      db.close();
    }
  });

  it("returns undefined for malformed JSON columns without throwing", () => {
    const restored = restorePersistedFinding(makePersistedRow({
      id: "f-bad-json",
      pocSteps: "not-valid-json",
      layerVerdicts: "[oops",
      pocExecution: "{also-bad",
    }));
    expect(restored.pocSteps).toBeUndefined();
    expect(restored.layerVerdicts).toBeUndefined();
    expect(restored.pocExecution).toBeUndefined();
    expect(restored.semanticDedupe).toBeUndefined();
    expect(restored.findingRank).toBeUndefined();
    // The rest of the row still restores cleanly.
    expect(restored.id).toBe("f-bad-json");
    expect(restored.title).toBe("still useful");
  });

  it("threads scalar workflow + score fields when populated as a stub row", () => {
    const restored = restorePersistedFinding(makePersistedRow({
      id: "f-workflow",
      workflowStatus: "human_review",
      workflowAssignee: "bob",
      workflowUpdatedAt: "2026-05-22T12:34:56Z",
      score: 42,
    }));
    expect(restored.workflowStatus).toBe("human_review");
    expect(restored.workflowAssignee).toBe("bob");
    expect(restored.workflowUpdatedAt).toBe("2026-05-22T12:34:56Z");
    expect(restored.score).toBe(42);
  });

  it("accepts already-parsed JSON columns from sink-shim paths", () => {
    const pocSteps = makePocSteps();
    const layerVerdicts = makeLayerVerdicts();
    const pocExecution = makePocExecution() as Finding["pocExecution"];
    const restored = restorePersistedFinding(makePersistedRow({
      id: "f-preparsed",
      pocSteps,
      layerVerdicts,
      pocExecution,
    }));
    expect(restored.pocSteps).toEqual(pocSteps);
    expect(restored.layerVerdicts).toEqual(layerVerdicts);
    expect(restored.pocExecution).toEqual(pocExecution);
  });
});

describe("restorePersistedFinding — impactAssessment round-trip", () => {
  afterEach(() => {
    for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  const ASSESSMENT = {
    reachability_tier: "remote-unauth" as const,
    blast_radius: "every unauthenticated caller",
    weaponizability: "rce" as const,
    business_impact: "headline" as const,
    rationale: "Reachable pre-auth; the sink is a raw exec.",
  };

  it("threads impactAssessment through saveFinding → getFindings → restore", () => {
    const { db, scanId } = makeDb();
    try {
      const original = { ...makeFinding(undefined), impactAssessment: ASSESSMENT };
      db.saveFinding(scanId, original);
      const restored = restorePersistedFinding(db.getFindings(scanId)[0]);
      expect(restored.impactAssessment).toEqual(ASSESSMENT);
    } finally {
      db.close();
    }
  });

  it("restores impactAssessment=undefined for a legacy NULL column", () => {
    const { db, scanId } = makeDb();
    try {
      db.saveFinding(scanId, makeFinding(undefined));
      const restored = restorePersistedFinding(db.getFindings(scanId)[0]);
      expect(restored.impactAssessment).toBeUndefined();
    } finally {
      db.close();
    }
  });

  it("drops an assessment with an out-of-vocabulary tier rather than leaking it", () => {
    const restored = restorePersistedFinding(makePersistedRow({
      impactAssessment: JSON.stringify({ ...ASSESSMENT, reachability_tier: "from-mars" }),
    }));
    expect(restored.impactAssessment).toBeUndefined();
    expect(restored.title).toBe("still useful");
  });

  it("drops a malformed JSON column without breaking the restore", () => {
    const restored = restorePersistedFinding(makePersistedRow({ impactAssessment: "{not json [" }));
    expect(restored.impactAssessment).toBeUndefined();
    expect(restored.title).toBe("still useful");
  });
});

describe("restorePersistedFinding \u2014 review fields (0sec#420)", () => {
  it("threads a persisted verification_result back onto the finding", () => {
    const restored = restorePersistedFinding(
      makePersistedRow({
        verificationResult: JSON.stringify({ status: "reproduced", notes: "confirmed by rerun" }),
      }),
    );
    expect(restored.verification_result?.status).toBe("reproduced");
  });

  it("threads a persisted reviewAnnotation back onto the finding", () => {
    const restored = restorePersistedFinding(
      makePersistedRow({
        reviewAnnotation: JSON.stringify({ path: "src/app.ts", startLine: 42 }),
      }),
    );
    expect(restored.reviewAnnotation?.path).toBe("src/app.ts");
  });

  it("omits the keys entirely when the columns are null", () => {
    const restored = restorePersistedFinding(
      makePersistedRow({ verificationResult: null, reviewAnnotation: null }),
    );
    // Absent, never an empty object: a truthy {} would let the source-fix
    // eligibility check treat an unverified finding as reproduced.
    expect("verification_result" in restored).toBe(false);
    expect("reviewAnnotation" in restored).toBe(false);
  });

  it("drops a malformed payload instead of throwing", () => {
    const restored = restorePersistedFinding(
      makePersistedRow({ verificationResult: "{not json", reviewAnnotation: "{nope" }),
    );
    expect("verification_result" in restored).toBe(false);
    expect("reviewAnnotation" in restored).toBe(false);
  });
});

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  ReviewStore,
  candidateSignature,
  findingSignature,
  mergeCandidates,
  mergeFindings,
  newRunId,
  STALE_LOCK_MS,
} from "./store.js";
import type { ReviewFileRecord, ReviewFinding } from "./types.js";

function tmpStore(): { store: ReviewStore; dir: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "0sec-fr-store-"));
  return { store: new ReviewStore({ dataDir: dir }), dir };
}

function makeRecord(projectId: string, filePath: string, extra: Partial<ReviewFileRecord> = {}): ReviewFileRecord {
  return {
    filePath,
    projectId,
    candidates: [],
    findings: [],
    analysisHistory: [],
    status: "pending",
    ...extra,
  };
}

const finding = (over: Partial<ReviewFinding> = {}): ReviewFinding => ({
  severity: "high",
  vulnSlug: "sql-injection",
  title: "SQLi in user lookup",
  description: "desc",
  lineNumbers: [10],
  recommendation: "parameterize",
  confidence: "high",
  ...over,
});

describe("ReviewStore", () => {
  it("round-trips a record through the mirrored path", () => {
    const { store } = tmpStore();
    const record = makeRecord("proj", "src/api/auth.ts");
    store.writeRecord(record);
    expect(store.recordPath("proj", "src/api/auth.ts")).toContain("files/src/api/auth.ts.json");
    expect(store.readRecord("proj", "src/api/auth.ts")?.filePath).toBe("src/api/auth.ts");
  });

  it("normalizes windows separators and ./ prefixes in record paths", () => {
    const { store } = tmpStore();
    const a = store.recordPath("p", "src\\api\\x.ts");
    const b = store.recordPath("p", "./src/api/x.ts");
    expect(a).toBe(b);
  });

  it("returns undefined for missing records", () => {
    const { store } = tmpStore();
    expect(store.readRecord("proj", "nope.ts")).toBeUndefined();
  });

  it("lists every record recursively", () => {
    const { store } = tmpStore();
    store.writeRecord(makeRecord("p", "a/b/one.ts"));
    store.writeRecord(makeRecord("p", "two.ts"));
    const listed = store.listRecords("p").map((r) => r.filePath).sort();
    expect(listed).toEqual(["a/b/one.ts", "two.ts"]);
  });

  it("claim/release round-trip locks and unlocks files", () => {
    const { store } = tmpStore();
    store.writeRecord(makeRecord("p", "f1.ts"));
    store.writeRecord(makeRecord("p", "f2.ts"));

    const claimed = store.claimFiles("p", "run-1", ["f1.ts", "f2.ts"]);
    expect(claimed).toEqual(["f1.ts", "f2.ts"]);
    expect(store.readRecord("p", "f1.ts")?.status).toBe("processing");
    expect(store.readRecord("p", "f1.ts")?.lockedByRunId).toBe("run-1");

    // A second live run cannot claim the same files.
    const second = store.claimFiles("p", "run-2", ["f1.ts", "f2.ts"]);
    expect(second).toEqual([]);

    // Release reverts to pending when asked.
    store.releaseFiles("p", "run-1", ["f1.ts", "f2.ts"], true);
    expect(store.readRecord("p", "f1.ts")?.status).toBe("pending");
    expect(store.readRecord("p", "f1.ts")?.lockedByRunId).toBeUndefined();
  });

  it("reclaims stale locks from finished runs", () => {
    const { store } = tmpStore();
    store.writeRecord(makeRecord("p", "f1.ts"));
    store.claimFiles("p", "run-dead", ["f1.ts"]);

    const rec = store.readRecord("p", "f1.ts")!;
    rec.lockedAt = new Date(Date.now() - STALE_LOCK_MS - 1000).toISOString();
    store.writeRecord(rec);

    // No run meta for run-dead → reclaimable once stale.
    const claimed = store.claimFiles("p", "run-live", ["f1.ts"]);
    expect(claimed).toEqual(["f1.ts"]);
    expect(store.readRecord("p", "f1.ts")?.lockedByRunId).toBe("run-live");
  });

  it("does NOT reclaim fresh locks", () => {
    const { store } = tmpStore();
    store.writeRecord(makeRecord("p", "f1.ts"));
    store.claimFiles("p", "run-a", ["f1.ts"]);
    expect(store.claimFiles("p", "run-b", ["f1.ts"])).toEqual([]);
  });

  it("run meta round-trips with phase transitions", () => {
    const { store } = tmpStore();
    const meta = store.createRunMeta({ projectId: "p", rootPath: "/x", type: "process" });
    expect(meta.phase).toBe("running");
    meta.phase = "done";
    store.saveRunMeta(meta);
    expect(store.loadRunMeta("p", meta.runId)?.phase).toBe("done");
  });
});

describe("merge helpers", () => {
  it("mergeCandidates dedupes by slug+pattern+lines", () => {
    const record = makeRecord("p", "f.ts");
    const c = { vulnSlug: "rce", lineNumbers: [3], snippet: "s", matchedPattern: "exec call" };
    mergeCandidates(record, [c, { ...c }, { ...c, lineNumbers: [4] }]);
    expect(record.candidates).toHaveLength(2);
    expect(candidateSignature(c)).toBe("rce|exec call|3");
  });

  it("mergeFindings dedupes by slug+title", () => {
    const record = makeRecord("p", "f.ts");
    mergeFindings(record, [finding(), finding(), finding({ title: "other" })]);
    expect(record.findings).toHaveLength(2);
    expect(findingSignature(finding())).toBe("sql-injection|SQLi in user lookup");
  });

  it("newRunId is sortable and unique-ish", () => {
    const a = newRunId(new Date("2026-08-13T10:00:00Z"));
    const b = newRunId(new Date("2026-08-13T10:00:01Z"));
    expect(a).toMatch(/^\d{14}-[0-9a-f]{4}$/);
    expect(a < b).toBe(true);
  });
});

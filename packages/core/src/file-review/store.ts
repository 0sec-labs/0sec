// On-disk store for the file-review pipeline (deepsec FileRecord pattern):
// one JSON record per source file, append-only merges, run metadata, and
// lock-based claiming so concurrent runs (or a crash + resume) never corrupt
// or double-process a file. All writes go through atomicWriteFileSync.

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { atomicWriteFileSync } from "./atomic-file.js";
import { ensureReviewFindingIds } from "./finding-id.js";
import type {
  ReviewAnalysisEntry,
  ReviewCandidateMatch,
  ReviewFileRecord,
  ReviewFinding,
  ReviewRunMeta,
} from "./types.js";

/**
 * A lock older than this whose run is no longer alive (done/error/missing,
 * or a dead pid on this host) may be reclaimed. Matches deepsec's
 * STALE_LOCK_MS semantics.
 */
export const STALE_LOCK_MS = 6 * 60 * 60 * 1000;

/** `<YYYYMMDDHHMMSS>-<rand4>`, sortable and unique enough per host. */
export function newRunId(date: Date = new Date()): string {
  const pad = (n: number, w = 2) => String(n).padStart(w, "0");
  const stamp =
    `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}` +
    `${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`;
  return `${stamp}-${crypto.randomBytes(2).toString("hex")}`;
}

export function candidateSignature(c: ReviewCandidateMatch): string {
  return `${c.vulnSlug}|${c.matchedPattern}|${[...c.lineNumbers].sort((a, b) => a - b).join(",")}`;
}

export function findingSignature(f: ReviewFinding): string {
  return `${f.vulnSlug}|${f.title}`;
}

export interface ReviewStoreOptions {
  /** Root data directory; projects live under `<dataDir>/<projectId>/`. */
  dataDir: string;
}

export class ReviewStore {
  readonly dataDir: string;

  constructor(opts: ReviewStoreOptions) {
    this.dataDir = opts.dataDir;
  }

  projectDir(projectId: string): string {
    return path.join(this.dataDir, projectId);
  }

  filesDir(projectId: string): string {
    return path.join(this.projectDir(projectId), "files");
  }

  runsDir(projectId: string): string {
    return path.join(this.projectDir(projectId), "runs");
  }

  /** `src/api/auth.ts` → `files/src/api/auth.ts.json` (deepsec data-layout). */
  recordPath(projectId: string, filePath: string): string {
    const rel = filePath.replaceAll("\\", "/").replace(/^\.\//, "");
    return path.join(this.filesDir(projectId), `${rel}.json`);
  }

  readRecord(projectId: string, filePath: string): ReviewFileRecord | undefined {
    try {
      const raw = fs.readFileSync(this.recordPath(projectId, filePath), "utf8");
      const record = JSON.parse(raw) as ReviewFileRecord;
      ensureReviewFindingIds(record);
      return record;
    } catch {
      return undefined;
    }
  }

  writeRecord(record: ReviewFileRecord): void {
    ensureReviewFindingIds(record);
    atomicWriteFileSync(
      this.recordPath(record.projectId, record.filePath),
      JSON.stringify(record, null, 2),
    );
  }

  /** Every record under a project (recursive walk of files/). */
  listRecords(projectId: string): ReviewFileRecord[] {
    const dir = this.filesDir(projectId);
    if (!fs.existsSync(dir)) return [];
    const out: ReviewFileRecord[] = [];
    const walk = (d: string): void => {
      for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
        const full = path.join(d, entry.name);
        if (entry.isDirectory()) {
          walk(full);
        } else if (entry.name.endsWith(".json")) {
          try {
            const record = JSON.parse(fs.readFileSync(full, "utf8")) as ReviewFileRecord;
            ensureReviewFindingIds(record);
            out.push(record);
          } catch {
            // torn/unreadable records are skipped; the next scan rewrites them
          }
        }
      }
    };
    walk(dir);
    return out;
  }

  // ── Run metadata ─────────────────────────────────────────────────────────

  runMetaPath(projectId: string, runId: string): string {
    return path.join(this.runsDir(projectId), `${runId}.json`);
  }

  loadRunMeta(projectId: string, runId: string): ReviewRunMeta | undefined {
    try {
      return JSON.parse(fs.readFileSync(this.runMetaPath(projectId, runId), "utf8")) as ReviewRunMeta;
    } catch {
      return undefined;
    }
  }

  saveRunMeta(meta: ReviewRunMeta): void {
    atomicWriteFileSync(this.runMetaPath(meta.projectId, meta.runId), JSON.stringify(meta, null, 2));
  }

  createRunMeta(params: {
    projectId: string;
    rootPath: string;
    type: ReviewRunMeta["type"];
    runId?: string;
  }): ReviewRunMeta {
    const meta: ReviewRunMeta = {
      runId: params.runId ?? newRunId(),
      projectId: params.projectId,
      rootPath: params.rootPath,
      createdAt: new Date().toISOString(),
      type: params.type,
      phase: "running",
      hostname: os.hostname(),
      pid: process.pid,
      stats: {},
    };
    this.saveRunMeta(meta);
    return meta;
  }

  // ── Locking ──────────────────────────────────────────────────────────────

  /**
   * A record locked by another run is reclaimable when the lock is stale
   * (STALE_LOCK_MS) AND the locking run is no longer alive — its RunMeta is
   * done/error/limit/missing, or the locking pid is dead on this host.
   */
  isReclaimable(record: ReviewFileRecord, currentRunId: string): boolean {
    if (!record.lockedByRunId || record.lockedByRunId === currentRunId) return true;
    const lockedAt = record.lockedAt ? Date.parse(record.lockedAt) : NaN;
    if (Number.isNaN(lockedAt) || Date.now() - lockedAt < STALE_LOCK_MS) return false;
    const meta = this.loadRunMeta(record.projectId, record.lockedByRunId);
    if (!meta) return true;
    if (meta.phase !== "running") return true;
    if (meta.hostname === os.hostname() && typeof meta.pid === "number") {
      try {
        process.kill(meta.pid, 0);
        return false; // still alive
      } catch {
        return true; // dead pid
      }
    }
    return false; // remote live-looking lock — leave it
  }

  /**
   * Claim files for `runId`: sets status processing + lock fields and
   * persists each record. Files locked by a live other run are skipped and
   * reported. Returns the paths actually claimed.
   */
  claimFiles(projectId: string, runId: string, filePaths: string[]): string[] {
    const claimed: string[] = [];
    const now = new Date().toISOString();
    for (const filePath of filePaths) {
      const record = this.readRecord(projectId, filePath);
      if (!record) continue;
      if (record.lockedByRunId && record.lockedByRunId !== runId && !this.isReclaimable(record, runId)) {
        continue;
      }
      record.status = "processing";
      record.lockedByRunId = runId;
      record.lockedAt = now;
      this.writeRecord(record);
      claimed.push(filePath);
    }
    return claimed;
  }

  /**
   * Release a run's files. `revertToPending` puts interrupted files back in
   * the pending pool (deepsec's cost/quota-abort cleanup); otherwise records
   * keep their current status and just lose the lock.
   */
  releaseFiles(projectId: string, runId: string, filePaths: string[], revertToPending = false): void {
    for (const filePath of filePaths) {
      const record = this.readRecord(projectId, filePath);
      if (!record || record.lockedByRunId !== runId) continue;
      record.lockedByRunId = undefined;
      record.lockedAt = undefined;
      if (revertToPending && record.status === "processing") {
        record.status = "pending";
      }
      this.writeRecord(record);
    }
  }
}

/** Merge new candidates into a record additively (dedup by signature). */
export function mergeCandidates(record: ReviewFileRecord, incoming: ReviewCandidateMatch[]): void {
  const seen = new Set(record.candidates.map(candidateSignature));
  for (const c of incoming) {
    const sig = candidateSignature(c);
    if (!seen.has(sig)) {
      seen.add(sig);
      record.candidates.push(c);
    }
  }
}

/** Merge new findings into a record, deduped by (vulnSlug, title). */
export function mergeFindings(record: ReviewFileRecord, incoming: ReviewFinding[]): void {
  const seen = new Set(record.findings.map(findingSignature));
  for (const f of incoming) {
    const sig = findingSignature(f);
    if (!seen.has(sig)) {
      seen.add(sig);
      record.findings.push(f);
    }
  }
}

/** Append one investigation to the analysis history (never truncates). */
export function appendAnalysis(record: ReviewFileRecord, entry: ReviewAnalysisEntry): void {
  record.analysisHistory.push(entry);
}

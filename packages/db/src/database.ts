import {
  createShimmedDatabase,
  createDrizzleFromShim,
  type ShimmedDatabase,
} from "./wasm-shim.js";
import { eq, desc, and, inArray } from "drizzle-orm";
import { createHash, randomUUID } from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readSync,
  renameSync,
  rmSync,
  statSync,
  writeSync,
} from "node:fs";
import type {
  ArtifactRecord,
  Finding,
  AttackResult,
  CaseRecord,
  TargetInfo,
  ScanConfig,
  AgentVerdict,
  PipelineEvent,
  FindingTriageStatus,
  WorkItemRecord,
  WorkerRecord,
} from "@pwnkit/shared";
import * as schema from "./schema.js";
import {
  findingStatuses,
  findingWorkflowStatuses,
  type FindingStatusDB,
  type FindingWorkflowStatusDB,
} from "./schema.js";

const DEFAULT_DB_DIR = join(homedir(), ".pwnkit");
const DEFAULT_DB_PATH = join(DEFAULT_DB_DIR, "pwnkit.db");

export function resolvePwnkitDbPath(dbPath?: string): string {
  return dbPath ?? DEFAULT_DB_PATH;
}

export function resetPwnkitDatabase(dbPath?: string): string {
  const path = resolvePwnkitDbPath(dbPath);

  if (!dbPath) {
    mkdirSync(DEFAULT_DB_DIR, { recursive: true });
  }

  for (const suffix of ["", "-wal", "-shm"]) {
    const candidate = `${path}${suffix}`;
    if (existsSync(candidate)) {
      rmSync(candidate, { force: true });
    }
  }

  return path;
}

export function repairPwnkitDatabase(dbPath?: string): { path: string; backupPath?: string } {
  const path = resolvePwnkitDbPath(dbPath);

  if (!dbPath) {
    mkdirSync(DEFAULT_DB_DIR, { recursive: true });
  }

  clearStaleLockIfAny(path);
  const backupPath = backupCorruptDatabase(path) ?? undefined;
  resetPwnkitDatabase(path);

  const db = new pwnkitDB(path);
  db.close();

  return { path, backupPath };
}

function isRecoverableDatabaseError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /database disk image is malformed|file is not a database|malformed|invalid page number|database main|btree|b-tree|database corrupt/i.test(message);
}

function timestampTag(): string {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function backupCorruptDatabase(path: string): string | null {
  if (!existsSync(path)) return null;

  const backupPath = `${path}.corrupt-${timestampTag()}`;
  renameSync(path, backupPath);

  for (const suffix of ["-wal", "-shm", ".lock"]) {
    const candidate = `${path}${suffix}`;
    if (!existsSync(candidate)) continue;
    try {
      renameSync(candidate, `${backupPath}${suffix}`);
    } catch {
      if (suffix === ".lock") {
        rmSync(candidate, { recursive: true, force: true });
      }
    }
  }

  return backupPath;
}

function ensureDatabaseHealthy(sqlite: ShimmedDatabase): void {
  const rows = sqlite.prepare("PRAGMA quick_check(1)").all() as Array<Record<string, unknown>>;
  const first = rows[0] ? Object.values(rows[0])[0] : "ok";
  if (typeof first === "string" && first.toLowerCase() !== "ok") {
    throw new Error(first);
  }
}

/**
 * Migrate a pre-0.7.1 WAL-mode SQLite file in-place to legacy rollback mode.
 *
 * Why this exists: pwnkit versions <0.7.1 used better-sqlite3 and set the
 * database to WAL mode (`PRAGMA journal_mode = WAL`). WAL mode writes a
 * `2` to bytes 18 (file format write version) and 19 (read version) of
 * the SQLite file header. The WASM-backed engine we switched to in 0.7.1
 * (node-sqlite3-wasm) uses an Emscripten VFS that does not implement the
 * shared-memory primitives WAL requires, so any query on a WAL-mode file
 * fails with `SQLITE_CANTOPEN: unable to open database file` — even though
 * the file is otherwise perfectly valid.
 *
 * Fix: flip bytes 18 and 19 back to `1` (legacy rollback mode). This is
 * safe as long as there is no non-empty `-wal` sidecar sitting next to
 * the DB. If there is, it means the previous run crashed with uncommitted
 * transactions still in the WAL, and those would be discarded by the flip
 * — we log a warning in that case so the user knows why a (probably
 * already-lost) mid-scan transaction went away.
 *
 * The migration is idempotent: calling it on an already-rollback-mode
 * file is a no-op.
 */
function migrateWalHeaderIfNeeded(path: string): void {
  if (!existsSync(path)) return;
  let size: number;
  try {
    size = statSync(path).size;
  } catch {
    return;
  }
  if (size < 20) return; // not large enough to contain a SQLite header

  const header = Buffer.alloc(100);
  try {
    const fd = openSync(path, "r");
    try {
      readSync(fd, header, 0, 100, 0);
    } finally {
      closeSync(fd);
    }
  } catch {
    return;
  }

  // "SQLite format 3\0" is the 16-byte magic.
  if (header.subarray(0, 15).toString("ascii") !== "SQLite format 3") return;

  // Bytes 18/19 are write_version and read_version. 1 = rollback, 2 = WAL.
  if (header[18] !== 2 && header[19] !== 2) return;

  const walPath = `${path}-wal`;
  const shmPath = `${path}-shm`;
  let hadWalData = false;
  try {
    if (existsSync(walPath) && statSync(walPath).size > 0) hadWalData = true;
  } catch {
    // Ignore stat failures; we'll still attempt the header flip.
  }

  try {
    const fd = openSync(path, "r+");
    try {
      writeSync(fd, Buffer.from([1, 1]), 0, 2, 18);
    } finally {
      closeSync(fd);
    }
  } catch (err) {
    // If we can't rewrite the header (e.g. readonly FS), let the engine
    // surface its own error when it tries to open the file.
    return;
  }

  // Sidecars are WAL-mode artifacts and would confuse rollback-mode opens.
  for (const sidecar of [walPath, shmPath]) {
    if (existsSync(sidecar)) {
      try {
        rmSync(sidecar, { force: true });
      } catch {
        // Non-fatal.
      }
    }
  }

  if (hadWalData) {
    // eslint-disable-next-line no-console -- user-facing one-time notice
    console.warn(
      `[pwnkit] Migrated ${path} from WAL mode to rollback mode for WASM engine compatibility. ` +
        `A non-empty WAL sidecar was present and has been removed; any uncommitted transactions ` +
        `from a prior crashed run were discarded.`,
    );
  }
}

/**
 * Clear a stale advisory lock directory left behind by a crashed writer.
 *
 * Why this exists: node-sqlite3-wasm's Node VFS implements SQLite's lock
 * protocol as `mkdirSync("${path}.lock")` for acquire and `rmdirSync` for
 * release. This is atomic on POSIX, but has *no* recovery path if the
 * holder crashes or is killed with SIGKILL before releasing — the lock
 * directory is orphaned and every subsequent open fails with SQLITE_BUSY,
 * which bubbles up to the user as "database is locked". The better-sqlite3
 * → WASM migration made this more visible because better-sqlite3 used the
 * kernel's byte-range locks which the kernel cleans up automatically on
 * process death; the WASM engine's userspace directory lock does not get
 * that for free.
 *
 * Heuristic: if the lock directory's mtime is older than 10 seconds, we
 * assume the holder is dead. Legitimate pwnkit operations acquire and
 * release the lock many times per second (SQLite locks are per-query,
 * not per-connection), so a 10-second-old lock that nobody has touched
 * is overwhelmingly likely to be a crash corpse. In the rare case where
 * this heuristic misfires against a real concurrent writer, the second
 * writer will race with the lock holder and one of them will retry,
 * which is already the failure mode SQLite is designed around.
 *
 * We do NOT clean up recently-created lock directories, to avoid racing
 * against a legitimate concurrent writer that has only just acquired
 * the lock.
 */
function clearStaleLockIfAny(path: string): void {
  const lockPath = `${path}.lock`;
  let stat;
  try {
    stat = statSync(lockPath);
  } catch {
    return; // no lock, nothing to do
  }
  if (!stat.isDirectory()) return;

  const ageMs = Date.now() - stat.mtimeMs;
  const STALE_THRESHOLD_MS = 10_000;
  if (ageMs < STALE_THRESHOLD_MS) return;

  try {
    rmSync(lockPath, { recursive: true, force: true });
    // eslint-disable-next-line no-console -- user-facing one-time notice
    console.warn(
      `[pwnkit] Removed stale database lock at ${lockPath} ` +
        `(age ${Math.floor(ageMs / 1000)}s — previous holder likely crashed).`,
    );
  } catch {
    // Non-fatal: node-sqlite3-wasm will surface its own "database is
    // locked" error and we'll let that propagate.
  }
}

// ── Persistent credential store + trust graph (pwnkit#771) ──

/** A stored persistent-credential row. NEVER carries the plaintext secret. */
export interface PersistentCredentialRow {
  id: string;
  credentialKind: string;
  valueHash: string;
  valuePreview: string;
  context: string | null;
  target: string | null;
  firstScanId: string | null;
  firstFindingId: string | null;
  firstSource: string | null;
  firstTurn: number | null;
  lastScanId: string | null;
  timesSeen: number;
  firstSeenAt: string;
  lastSeenAt: string;
}

/**
 * Input to {@link pwnkitDB.upsertPersistentCredential}. The caller is
 * responsible for hashing the secret — `valueHash` + `valuePreview` are the
 * only representations of the value that reach the DB. Plaintext must never be
 * passed here.
 */
export interface PersistentCredentialUpsert {
  credentialKind: string;
  valueHash: string;
  valuePreview: string;
  context?: string | null;
  target?: string | null;
  scanId?: string | null;
  findingId?: string | null;
  source?: string | null;
  turn?: number | null;
}

export interface PersistentCredentialQuery {
  credentialKind?: string;
  target?: string;
  limit?: number;
}

export interface TrustGraphEdgeRow {
  id: string;
  srcKind: string;
  srcId: string;
  dstKind: string;
  dstId: string;
  relation: string;
  scanId: string | null;
  findingId: string | null;
  confidence: number | null;
  note: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface TrustGraphEdgeInput {
  srcKind: string;
  srcId: string;
  dstKind: string;
  dstId: string;
  relation: string;
  scanId?: string | null;
  findingId?: string | null;
  confidence?: number | null;
  note?: string | null;
}

export class pwnkitDB {
  private sqlite!: ShimmedDatabase;
  private db!: ReturnType<typeof createDrizzleFromShim<typeof schema>>;

  constructor(dbPath?: string) {
    const path = resolvePwnkitDbPath(dbPath);
    if (!dbPath) {
      mkdirSync(DEFAULT_DB_DIR, { recursive: true });
    }
    this.openWithRecovery(path);
  }

  private openWithRecovery(path: string): void {
    // Auto-migrate pre-0.7.1 WAL-mode files that node-sqlite3-wasm can't read.
    migrateWalHeaderIfNeeded(path);
    // Clear a stale advisory lock left behind by a crashed/killed writer,
    // if and only if it's old enough that it can't plausibly be held by a
    // live concurrent process.
    clearStaleLockIfAny(path);
    try {
      this.initializeDatabase(path);
    } catch (error) {
      try {
        this.sqlite?.close();
      } catch {
        // best-effort only
      }

      if (!isRecoverableDatabaseError(error)) throw error;

      const backupPath = backupCorruptDatabase(path);
      this.initializeDatabase(path);
      // eslint-disable-next-line no-console -- user-facing repair notice
      console.warn(
        backupPath
          ? `[pwnkit] Recovered malformed database at ${path}. Backup saved to ${backupPath}.`
          : `[pwnkit] Recovered malformed database state at ${path} by recreating a fresh database.`,
      );
    }
  }

  private initializeDatabase(path: string): void {
    this.sqlite = createShimmedDatabase(path);
    // WAL is intentionally omitted: node-sqlite3-wasm's VFS does not support
    // it, and pwnkit's single-writer CLI workload does not benefit from it.
    this.sqlite.pragma("foreign_keys = ON");
    ensureDatabaseHealthy(this.sqlite);
    this.db = createDrizzleFromShim(this.sqlite, { schema });

    // Create base tables first, then migrate older schemas before adding indexes.
    this.sqlite.exec(SCHEMA_TABLES_SQL);
    this.migrate();
    this.sqlite.exec(SCHEMA_INDEXES_SQL);
  }

  /**
   * Upgrade databases created by older pwnkit versions.
   *
   * SCHEMA_TABLES_SQL (above) now contains every table and every column from
   * the drizzle schema, so fresh installs need no patching. This method only
   * runs idempotent ALTER TABLEs for databases that were created before the
   * corresponding columns/tables existed. Each guard is cheap (PRAGMA
   * table_info is cached by SQLite) and the ALTERs are no-ops when the
   * column is already present, so running on a fresh DB is harmless.
   *
   * See: https://github.com/0sec-labs/pwnkit/issues/420
   */
  private migrate(): void {
    const cols = this.sqlite
      .prepare("PRAGMA table_info(findings)")
      .all() as { name: string }[];
    const colNames = new Set(cols.map((c) => c.name));

    // v0.1 → v0.2: add score
    if (!colNames.has("score")) {
      this.sqlite.exec("ALTER TABLE findings ADD COLUMN score INTEGER");
    }
    // v0.2 → v0.3: add confidence, cvssVector, cvssScore
    if (!colNames.has("confidence")) {
      this.sqlite.exec("ALTER TABLE findings ADD COLUMN confidence REAL");
    }
    if (!colNames.has("cvssVector")) {
      this.sqlite.exec("ALTER TABLE findings ADD COLUMN cvssVector TEXT");
    }
    if (!colNames.has("cvssScore")) {
      this.sqlite.exec("ALTER TABLE findings ADD COLUMN cvssScore REAL");
    }
    if (!colNames.has("fingerprint")) {
      this.sqlite.exec("ALTER TABLE findings ADD COLUMN fingerprint TEXT");
    }
    if (!colNames.has("triageStatus")) {
      this.sqlite.exec("ALTER TABLE findings ADD COLUMN triageStatus TEXT NOT NULL DEFAULT 'new'");
    }
    if (!colNames.has("triageNote")) {
      this.sqlite.exec("ALTER TABLE findings ADD COLUMN triageNote TEXT");
    }
    if (!colNames.has("triagedAt")) {
      this.sqlite.exec("ALTER TABLE findings ADD COLUMN triagedAt TEXT");
    }
    if (!colNames.has("workflowStatus")) {
      this.sqlite.exec("ALTER TABLE findings ADD COLUMN workflowStatus TEXT NOT NULL DEFAULT 'backlog'");
    }
    if (!colNames.has("workflowAssignee")) {
      this.sqlite.exec("ALTER TABLE findings ADD COLUMN workflowAssignee TEXT");
    }
    if (!colNames.has("workflowUpdatedAt")) {
      this.sqlite.exec("ALTER TABLE findings ADD COLUMN workflowUpdatedAt TEXT");
    }
    // pwnkit#112 — per-layer triage telemetry. JSON-stringified LayerVerdict[].
    if (!colNames.has("layerVerdicts")) {
      this.sqlite.exec("ALTER TABLE findings ADD COLUMN layerVerdicts TEXT");
    }
    // pwnkit#170 — proof-of-concept step graph. JSON-stringified PocStep[].
    if (!colNames.has("pocSteps")) {
      this.sqlite.exec("ALTER TABLE findings ADD COLUMN pocSteps TEXT");
    }
    // pwnkit#193 — machine-executable verification contract. JSON-stringified
    // VerificationSpec. Optional/additive: legacy findings keep working.
    if (!colNames.has("verificationSpec")) {
      this.sqlite.exec("ALTER TABLE findings ADD COLUMN verificationSpec TEXT");
    }
    // pwnkit#171 — captured PoC execution report. JSON-stringified
    // PocExecutionReport written by `disclose --target-url …` when the
    // behavioural re-verify runtime ran the step graph against a live
    // target. Optional/additive.
    if (!colNames.has("pocExecution")) {
      this.sqlite.exec("ALTER TABLE findings ADD COLUMN pocExecution TEXT");
    }
    // Post-process metadata is optional and additive. Persisting it lets later
    // scans use only prior canonical findings as semantic-dedupe anchors.
    if (!colNames.has("semanticDedupe")) {
      this.sqlite.exec("ALTER TABLE findings ADD COLUMN semanticDedupe TEXT");
    }
    if (!colNames.has("findingRank")) {
      this.sqlite.exec("ALTER TABLE findings ADD COLUMN findingRank INTEGER");
    }
    // Backfill NULL fingerprint / triageStatus / workflowStatus for rows
    // created before those columns existed.
    this.sqlite.exec("UPDATE findings SET fingerprint = id WHERE fingerprint IS NULL OR fingerprint = ''");
    this.sqlite.exec("UPDATE findings SET triageStatus = 'new' WHERE triageStatus IS NULL OR triageStatus = ''");
    this.sqlite.exec(`
      UPDATE findings
      SET workflowStatus = CASE
        WHEN workflowStatus IS NOT NULL AND workflowStatus != '' THEN workflowStatus
        WHEN triageStatus = 'accepted' OR status = 'reported' THEN 'done'
        WHEN triageStatus = 'suppressed' OR status = 'false-positive' THEN 'cancelled'
        WHEN status IN ('verified', 'confirmed', 'scored') THEN 'human_review'
        ELSE 'backlog'
      END
    `);
  }

  // ── Triage Memories (Semgrep-style per-target FP learning) ──

  insertTriageMemory(row: {
    id: string;
    scope: "global" | "target" | "package";
    scopeValue?: string | null;
    category: string;
    pattern: string;
    reasoning: string;
    createdAt: number;
    appliedCount?: number;
  }): void {
    this.sqlite
      .prepare(
        `INSERT INTO triage_memories (id, scope, scope_value, category, pattern, reasoning, created_at, applied_count)
         VALUES (@id, @scope, @scopeValue, @category, @pattern, @reasoning, @createdAt, @appliedCount)`,
      )
      .run({
        id: row.id,
        scope: row.scope,
        scopeValue: row.scopeValue ?? null,
        category: row.category,
        pattern: row.pattern,
        reasoning: row.reasoning,
        createdAt: row.createdAt,
        appliedCount: row.appliedCount ?? 0,
      });
  }

  listTriageMemories(opts?: {
    scope?: "global" | "target" | "package";
    scopeValue?: string;
    category?: string;
    limit?: number;
  }): Array<{
    id: string;
    scope: "global" | "target" | "package";
    scopeValue: string | null;
    category: string;
    pattern: string;
    reasoning: string;
    createdAt: number;
    appliedCount: number;
  }> {
    const where: string[] = [];
    const params: Record<string, unknown> = {};
    if (opts?.scope) {
      where.push("scope = @scope");
      params.scope = opts.scope;
    }
    if (opts?.scopeValue) {
      where.push("scope_value = @scopeValue");
      params.scopeValue = opts.scopeValue;
    }
    if (opts?.category) {
      where.push("category = @category");
      params.category = opts.category;
    }
    const whereSql = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
    const limit = opts?.limit ?? 500;
    const rows = this.sqlite
      .prepare(
        `SELECT id, scope, scope_value as scopeValue, category, pattern, reasoning,
                created_at as createdAt, applied_count as appliedCount
         FROM triage_memories
         ${whereSql}
         ORDER BY applied_count DESC, created_at DESC
         LIMIT ${limit}`,
      )
      .all(params) as Array<{
        id: string;
        scope: "global" | "target" | "package";
        scopeValue: string | null;
        category: string;
        pattern: string;
        reasoning: string;
        createdAt: number;
        appliedCount: number;
      }>;
    return rows;
  }

  deleteTriageMemory(id: string): boolean {
    const result = this.sqlite.prepare("DELETE FROM triage_memories WHERE id = ?").run(id);
    return result.changes > 0;
  }

  incrementMemoryAppliedCount(id: string): void {
    this.sqlite
      .prepare("UPDATE triage_memories SET applied_count = applied_count + 1 WHERE id = ?")
      .run(id);
  }

  private buildCaseId(target: string): string {
    return `case:${encodeURIComponent(target.trim().toLowerCase())}`;
  }

  private inferCaseTargetType(scan: { target: string; mode?: string | null }): "ai-app" | "package" | "repository" | "web-app" | "unknown" {
    if (scan.mode === "web") return "web-app";
    if (scan.mode === "probe" || scan.mode === "mcp") return "ai-app";
    if (scan.target.startsWith("http://") || scan.target.startsWith("https://")) return "ai-app";
    if (scan.target.startsWith("/") || scan.target.startsWith(".") || scan.target.includes("/")) return "repository";
    if (!scan.target.includes(" ")) return "package";
    return "unknown";
  }

  private syncCaseForScan(scanId: string): string | null {
    const scan = this.getScan(scanId);
    if (!scan) return null;
    const caseId = this.buildCaseId(scan.target);
    const status =
      scan.status === "running"
        ? "in_progress"
        : scan.status === "failed"
          ? "open"
          : "open";

    this.upsertCase({
      id: caseId,
      target: scan.target,
      targetType: this.inferCaseTargetType(scan),
      latestScanId: scan.id,
      status,
    });

    return caseId;
  }

  private syncFindingGraph(scanId: string, fingerprint: string): void {
    const scan = this.getScan(scanId);
    if (!scan) return;
    const caseId = this.syncCaseForScan(scanId);
    if (!caseId) return;

    const rows = this.getRelatedFindings(fingerprint);
    if (rows.length === 0) return;
    const latest = rows[0]!;
    const scanIds = [...new Set(rows.map((row) => row.scanId))];
    const verdicts = this.listVerdicts(rows.map((row) => row.id));
    const sessions = this.listSessions({ scanIds });
    const runningRoles = new Set(sessions.filter((session) => session.status === "running").map((session) => session.agentRole));
    const completedRoles = new Set(sessions.filter((session) => session.status === "completed").map((session) => session.agentRole));
    const failedRoles = new Set(sessions.filter((session) => session.status === "failed").map((session) => session.agentRole));
    const hasAnalysis = Boolean(latest.evidenceAnalysis?.trim());
    const hasExploitArtifacts = Boolean(latest.evidenceRequest?.trim() || latest.evidenceResponse?.trim());
    const hasVerifierVotes = verdicts.length > 0;
    const workflowStatus = normalizeWorkflowStatus(latest.workflowStatus, latest);
    const phase =
      workflowStatus === "done" || workflowStatus === "cancelled" || workflowStatus === "blocked"
        ? workflowStatus
        : workflowStatus === "in_progress"
          ? "in_progress"
          : workflowStatus === "todo"
            ? "todo"
            : "backlog";
    const reviewGate =
      workflowStatus === "agent_review" || workflowStatus === "human_review"
        ? workflowStatus
        : latest.status === "verified" || latest.status === "confirmed" || latest.status === "scored" || latest.status === "reported" || latest.status === "false-positive"
          ? "human_review"
          : "none";

    const surfaceMapStatus: WorkItemRecord["status"] =
      failedRoles.has("discovery")
        ? "blocked"
        : runningRoles.has("discovery")
          ? "in_progress"
          : completedRoles.has("discovery") || scan.status !== "running" || rows.length > 0
            ? "done"
            : "todo";

    const hypothesisStatus: WorkItemRecord["status"] =
      failedRoles.has("review") || failedRoles.has("audit")
        ? "blocked"
        : runningRoles.has("review") || runningRoles.has("audit")
          ? "in_progress"
          : hasAnalysis || completedRoles.has("review") || completedRoles.has("audit")
            ? "done"
            : surfaceMapStatus === "done"
              ? "todo"
              : "backlog";

    const pocBuildStatus: WorkItemRecord["status"] =
      failedRoles.has("attack")
        ? "blocked"
        : runningRoles.has("attack")
          ? "in_progress"
          : hasExploitArtifacts || completedRoles.has("attack")
            ? "done"
            : hypothesisStatus === "done"
              ? "todo"
              : "backlog";

    const blindVerifyStatus: WorkItemRecord["status"] =
      failedRoles.has("verify")
        ? "blocked"
        : runningRoles.has("verify")
          ? "in_progress"
          : hasVerifierVotes || ["verified", "confirmed", "scored", "reported", "false-positive"].includes(latest.status)
            ? "done"
            : pocBuildStatus === "done"
              ? "todo"
              : "backlog";

    const consensusStatus: WorkItemRecord["status"] =
      workflowStatus === "done" || workflowStatus === "cancelled" || ["verified", "confirmed", "scored", "reported", "false-positive"].includes(latest.status)
        ? "done"
        : reviewGate === "agent_review"
          ? hasVerifierVotes
            ? "todo"
            : blindVerifyStatus === "in_progress"
              ? "backlog"
              : "todo"
          : blindVerifyStatus === "done"
            ? "todo"
            : "backlog";

    const humanReviewStatus: WorkItemRecord["status"] =
      phase === "done" || phase === "cancelled"
        ? "done"
        : reviewGate === "human_review"
          ? "todo"
          : reviewGate === "agent_review"
            ? "blocked"
            : consensusStatus === "done"
              ? "todo"
              : "backlog";

    const items: Array<{
      kind: WorkItemRecord["kind"];
      title: string;
      owner: string | null;
      status: WorkItemRecord["status"];
      summary: string;
      dependsOn?: string | null;
    }> = [
      {
        kind: "surface_map",
        title: "Attack surface mapping",
        owner: "attack-surface-agent",
        status: surfaceMapStatus,
        summary: "Initial target surface and candidate family context captured.",
        dependsOn: null,
      },
      {
        kind: "hypothesis",
        title: "Exploit hypothesis",
        owner: "research-agent",
        status: hypothesisStatus,
        summary: "Research context and exploit framing for this family.",
        dependsOn: `${fingerprint}:surface_map`,
      },
      {
        kind: "poc_build",
        title: "PoC build",
        owner: latest.workflowAssignee ?? null,
        status: pocBuildStatus,
        summary: "Exploit request/response artifacts and reproduction chain.",
        dependsOn: `${fingerprint}:hypothesis`,
      },
      {
        kind: "blind_verify",
        title: "Blind verify",
        owner: null,
        status: blindVerifyStatus,
        summary: "Independent verification pass without research reasoning.",
        dependsOn: `${fingerprint}:poc_build`,
      },
      {
        kind: "consensus",
        title: "Consensus",
        owner: "consensus-agent",
        status: consensusStatus,
        summary: "Resolve verifier evidence into a concrete next step.",
        dependsOn: `${fingerprint}:blind_verify`,
      },
      {
        kind: "human_review",
        title: "Human review",
        owner: "operator",
        status: humanReviewStatus,
        summary: "Final operator sign-off before closure, suppression, or reporting.",
        dependsOn: `${fingerprint}:consensus`,
      },
    ];

    for (const item of items) {
      this.upsertWorkItem({
        id: `${fingerprint}:${item.kind}`,
        caseId,
        findingFingerprint: fingerprint,
        kind: item.kind,
        title: item.title,
        owner: item.owner,
        status: item.status,
        summary: item.summary,
        dependsOn: item.dependsOn ?? null,
      });
    }

    this.upsertArtifact({
      id: `${fingerprint}:request`,
      caseId,
      findingFingerprint: fingerprint,
      kind: "request",
      label: "Exploit request",
      content: latest.evidenceRequest,
      metadata: { findingId: latest.id, scanId: latest.scanId },
    });
    this.upsertArtifact({
      id: `${fingerprint}:response`,
      caseId,
      findingFingerprint: fingerprint,
      kind: "response",
      label: "Exploit response",
      content: latest.evidenceResponse,
      metadata: { findingId: latest.id, scanId: latest.scanId },
    });
    this.upsertArtifact({
      id: `${fingerprint}:analysis`,
      caseId,
      findingFingerprint: fingerprint,
      kind: "analysis",
      label: "Research analysis",
      content: latest.evidenceAnalysis ?? null,
      metadata: { findingId: latest.id, scanId: latest.scanId },
    });
  }

  private roleToWorkItemKind(role: string): WorkItemRecord["kind"] | null {
    if (role === "discovery") return "surface_map";
    if (role === "attack") return "poc_build";
    if (role === "verify") return "blind_verify";
    if (role === "review" || role === "audit") return "hypothesis";
    if (role === "report") return "human_review";
    return null;
  }

  private workItemTemplate(kind: WorkItemRecord["kind"]): {
    title: string;
    owner: string | null;
    summary: string;
    dependsOn: string | null;
  } {
    switch (kind) {
      case "surface_map":
        return {
          title: "Attack surface mapping",
          owner: "attack-surface-agent",
          summary: "Map the target and establish the initial attack surface context.",
          dependsOn: null,
        };
      case "hypothesis":
        return {
          title: "Exploit hypothesis",
          owner: "research-agent",
          summary: "Turn the surface signal into a concrete exploit theory.",
          dependsOn: "surface_map",
        };
      case "poc_build":
        return {
          title: "PoC build",
          owner: "research-agent",
          summary: "Create the exploit artifact chain and reproduction path.",
          dependsOn: "hypothesis",
        };
      case "blind_verify":
        return {
          title: "Blind verify",
          owner: "verify-agent",
          summary: "Reproduce the issue independently without research reasoning.",
          dependsOn: "poc_build",
        };
      case "consensus":
        return {
          title: "Consensus",
          owner: "consensus-agent",
          summary: "Resolve verifier evidence into the next decision.",
          dependsOn: "blind_verify",
        };
      case "human_review":
        return {
          title: "Human review",
          owner: "operator",
          summary: "Final sign-off before report, suppression, or closure.",
          dependsOn: "consensus",
        };
    }
  }

  ensureCaseWorkPlan(scanId: string): string | null {
    const caseId = this.syncCaseForScan(scanId);
    if (!caseId) return null;

    for (const kind of ["surface_map", "hypothesis", "poc_build", "blind_verify", "consensus", "human_review"] as const) {
      const template = this.workItemTemplate(kind);
      this.upsertWorkItem({
        id: `${caseId}:${kind}`,
        caseId,
        kind,
        title: template.title,
        owner: template.owner,
        status: "backlog",
        summary: template.summary,
        dependsOn: template.dependsOn ? `${caseId}:${template.dependsOn}` : null,
      });
    }

    return caseId;
  }

  transitionCaseWorkItem(
    scanId: string,
    kind: WorkItemRecord["kind"],
    status: WorkItemRecord["status"],
    opts?: { summary?: string | null; owner?: string | null },
  ): void {
    const caseId = this.ensureCaseWorkPlan(scanId);
    if (!caseId) return;
    const template = this.workItemTemplate(kind);
    const finding = this.getLatestFindingForScan(scanId);
    this.upsertWorkItem({
      id: `${caseId}:${kind}`,
      caseId,
      kind,
      title: template.title,
      owner: opts?.owner ?? template.owner,
      status,
      summary: opts?.summary ?? template.summary,
      dependsOn: template.dependsOn ? `${caseId}:${template.dependsOn}` : null,
    });
    this.logEvent({
      scanId,
      stage: kind,
      eventType: "work_item_transition",
      findingId: finding?.id ?? undefined,
      agentRole: opts?.owner ?? template.owner ?? undefined,
      payload: {
        kind,
        status,
        owner: opts?.owner ?? template.owner ?? null,
        summary: opts?.summary ?? template.summary,
        caseId,
      },
      timestamp: Date.now(),
    });
  }

  private syncSessionGraph(session: {
    id: string;
    scanId: string;
    agentRole: string;
    status: string;
    toolContext: Record<string, unknown>;
  }): void {
    const caseId = this.syncCaseForScan(session.scanId);
    if (!caseId) return;

    this.upsertArtifact({
      id: `session:${session.id}`,
      caseId,
      kind: "sessions",
      label: `${session.agentRole} session`,
      content: JSON.stringify(session.toolContext),
      metadata: { scanId: session.scanId, agentRole: session.agentRole, status: session.status },
    });
  }

  private syncEventGraph(event: Omit<PipelineEvent, "id">, eventId: string): void {
    const caseId = this.syncCaseForScan(event.scanId);
    if (!caseId) return;
    const finding = event.findingId ? this.getFinding(event.findingId) : null;
    this.upsertArtifact({
      id: `event:${eventId}`,
      caseId,
      findingFingerprint: finding?.fingerprint ?? null,
      kind: "events",
      label: `${event.stage}:${event.eventType}`,
      content: JSON.stringify(event.payload),
      metadata: {
        scanId: event.scanId,
        agentRole: event.agentRole ?? null,
        findingId: event.findingId ?? null,
        timestamp: event.timestamp,
      },
    });
  }

  // ── Scans ──

  createScan(config: ScanConfig): string {
    const id = randomUUID();
    this.db.insert(schema.scans).values({
      id,
      target: config.target,
      depth: config.depth,
      runtime: config.runtime ?? "api",
      mode: config.mode ?? "probe",
      status: "running",
      startedAt: new Date().toISOString(),
    }).run();
    this.syncCaseForScan(id);
    return id;
  }

  deleteScan(scanId: string): boolean {
    const scan = this.getScan(scanId);
    if (!scan) return false;

    const findingIds = this.db
      .select({ id: schema.findings.id, fingerprint: schema.findings.fingerprint })
      .from(schema.findings)
      .where(eq(schema.findings.scanId, scanId))
      .all();

    this.transaction(() => {
      if (findingIds.length > 0) {
        const ids = findingIds.map((finding) => finding.id);
        this.db.delete(schema.verdicts).where(inArray(schema.verdicts.findingId, ids)).run();
      }

      this.db.delete(schema.agentSessions).where(eq(schema.agentSessions.scanId, scanId)).run();
      this.db.delete(schema.pipelineEvents).where(eq(schema.pipelineEvents.scanId, scanId)).run();
      this.db.delete(schema.attackResults).where(eq(schema.attackResults.scanId, scanId)).run();
      this.db.delete(schema.findings).where(eq(schema.findings.scanId, scanId)).run();
      this.db.delete(schema.scans).where(eq(schema.scans.id, scanId)).run();

      const remainingTargetScans = this.db
        .select({ id: schema.scans.id, startedAt: schema.scans.startedAt })
        .from(schema.scans)
        .where(eq(schema.scans.target, scan.target))
        .orderBy(desc(schema.scans.startedAt))
        .all();

      const caseId = this.buildCaseId(scan.target);
      if (remainingTargetScans.length === 0) {
        this.db.delete(schema.cases).where(eq(schema.cases.id, caseId)).run();
      } else {
        this.db
          .update(schema.cases)
          .set({
            latestScanId: remainingTargetScans[0]!.id,
            updatedAt: new Date().toISOString(),
          })
          .where(eq(schema.cases.id, caseId))
          .run();
      }
    });

    return true;
  }

  completeScan(scanId: string, summary: Record<string, unknown>): void {
    const scan = this.db
      .select({ startedAt: schema.scans.startedAt })
      .from(schema.scans)
      .where(eq(schema.scans.id, scanId))
      .get();
    const durationMs = scan
      ? Date.now() - new Date(scan.startedAt).getTime()
      : 0;
    this.db
      .update(schema.scans)
      .set({
        status: "completed",
        completedAt: new Date().toISOString(),
        durationMs,
        summary: JSON.stringify(summary),
      })
      .where(eq(schema.scans.id, scanId))
      .run();
    this.syncCaseForScan(scanId);
  }

  reopenScan(scanId: string): void {
    this.db
      .update(schema.scans)
      .set({
        status: "running",
        completedAt: null,
        durationMs: null,
      })
      .where(eq(schema.scans.id, scanId))
      .run();
    this.syncCaseForScan(scanId);
  }

  failScan(scanId: string, error: string): void {
    this.db
      .update(schema.scans)
      .set({
        status: "failed",
        completedAt: new Date().toISOString(),
        summary: JSON.stringify({ error }),
      })
      .where(eq(schema.scans.id, scanId))
      .run();
    this.syncCaseForScan(scanId);
  }

  getScan(scanId: string) {
    return this.db
      .select()
      .from(schema.scans)
      .where(eq(schema.scans.id, scanId))
      .get();
  }

  listScans(limit = 20) {
    return this.db
      .select()
      .from(schema.scans)
      .orderBy(desc(schema.scans.startedAt))
      .limit(limit)
      .all();
  }

  listScansByTarget(target: string, opts?: { limit?: number }) {
    const query = this.db
      .select()
      .from(schema.scans)
      .where(eq(schema.scans.target, target))
      .orderBy(desc(schema.scans.startedAt));
    if (opts?.limit !== undefined) query.limit(opts.limit);
    return query.all();
  }

  // ── Targets ──

  upsertTarget(info: TargetInfo): string {
    const existing = this.db
      .select({ id: schema.targets.id })
      .from(schema.targets)
      .where(eq(schema.targets.url, info.url))
      .get();

    if (existing) {
      this.db
        .update(schema.targets)
        .set({
          type: info.type,
          model: info.model ?? null,
          systemPrompt: info.systemPrompt ?? null,
          detectedFeatures: info.detectedFeatures
            ? JSON.stringify(info.detectedFeatures)
            : null,
          endpoints: info.endpoints ? JSON.stringify(info.endpoints) : null,
          lastSeenAt: new Date().toISOString(),
        })
        .where(eq(schema.targets.id, existing.id))
        .run();
      return existing.id;
    }

    const id = randomUUID();
    const now = new Date().toISOString();
    this.db.insert(schema.targets).values({
      id,
      url: info.url,
      type: info.type,
      model: info.model ?? null,
      systemPrompt: info.systemPrompt ?? null,
      detectedFeatures: info.detectedFeatures
        ? JSON.stringify(info.detectedFeatures)
        : null,
      endpoints: info.endpoints ? JSON.stringify(info.endpoints) : null,
      firstSeenAt: now,
      lastSeenAt: now,
    }).run();
    return id;
  }

  getTarget(url: string) {
    return this.db
      .select()
      .from(schema.targets)
      .where(eq(schema.targets.url, url))
      .get();
  }

  // ── Findings ──

  saveFinding(scanId: string, finding: Finding): void {
    const workflowFinding = finding as Finding & {
      workflowStatus?: string | null;
      workflowAssignee?: string | null;
    };
    const scan = this.getScan(scanId);
    const fingerprint = finding.fingerprint ?? buildFindingFingerprint(scan?.target ?? scanId, finding);
    const inheritedTriage = this.getLatestFindingByFingerprint(fingerprint);
    const inheritedWorkflowStatus = normalizeWorkflowStatus(
      workflowFinding.workflowStatus ?? inheritedTriage?.workflowStatus,
      {
        status: finding.status,
        triageStatus: finding.triageStatus ?? inheritedTriage?.triageStatus ?? "new",
      },
    );
    const inheritedWorkflowAssignee = workflowFinding.workflowAssignee ?? inheritedTriage?.workflowAssignee ?? null;
    const layerVerdictsJson =
      finding.layerVerdicts && finding.layerVerdicts.length > 0
        ? JSON.stringify(finding.layerVerdicts)
        : null;
    // pwnkit#170 — persist the optional PoC step graph. NULL when the agent
    // only produced prose evidence; JSON-stringified PocStep[] otherwise. The
    // field is additive: existing readers that ignore it keep working.
    const pocStepsJson =
      finding.pocSteps && finding.pocSteps.length > 0
        ? JSON.stringify(finding.pocSteps)
        : null;
    // pwnkit#193 — persist the optional VerificationSpec. NULL when the
    // finding has no machine-executable re-check contract. Stored as
    // JSON text; cloud's canary watcher reads it back via
    // restorePersistedFinding to re-evaluate findings on each upstream
    // HEAD refresh. Without this column the spec was silently dropped on
    // any reload path.
    const verificationSpecJson = finding.verificationSpec
      ? JSON.stringify(finding.verificationSpec)
      : null;
    // Post-process fields are emitted after agentic verification, so they must
    // survive the final save/reload cycle rather than existing only in the
    // in-memory report.
    const semanticDedupeJson = finding.semanticDedupe
      ? JSON.stringify(finding.semanticDedupe)
      : null;
    const candidateFindingRank = finding.findingRank;
    const findingRank =
      typeof candidateFindingRank === "number" &&
      Number.isSafeInteger(candidateFindingRank) &&
      candidateFindingRank > 0
        ? candidateFindingRank
        : null;
    // Backfill prose evidence from pocSteps for findings that only carry the
    // structured form, so legacy advisory templates / dashboards still see
    // request/response/analysis text. The structured pocSteps remain canonical.
    const derivedEvidence = deriveEvidenceFromPocSteps(finding);
    const evidenceRequest = finding.evidence.request || derivedEvidence.request;
    const evidenceResponse = finding.evidence.response || derivedEvidence.response;
    const evidenceAnalysis = finding.evidence.analysis ?? derivedEvidence.analysis ?? null;
    this.db
      .insert(schema.findings)
      .values({
        id: finding.id,
        scanId,
        templateId: finding.templateId,
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        category: finding.category,
        status: finding.status,
        fingerprint,
        triageStatus: finding.triageStatus ?? inheritedTriage?.triageStatus ?? "new",
        triageNote: finding.triageNote ?? inheritedTriage?.triageNote ?? null,
        triagedAt: finding.triageStatus || inheritedTriage?.triageStatus ? new Date().toISOString() : null,
        workflowStatus: inheritedWorkflowStatus,
        workflowAssignee: inheritedWorkflowAssignee,
        workflowUpdatedAt: new Date().toISOString(),
        confidence: finding.confidence ?? null,
        cvssVector: finding.cvssVector ?? null,
        cvssScore: finding.cvssScore ?? null,
        evidenceRequest,
        evidenceResponse,
        evidenceAnalysis,
        layerVerdicts: layerVerdictsJson,
        pocSteps: pocStepsJson,
        verificationSpec: verificationSpecJson,
        semanticDedupe: semanticDedupeJson,
        findingRank,
        timestamp: finding.timestamp,
      })
      .onConflictDoUpdate({
        target: schema.findings.id,
        set: {
          templateId: finding.templateId,
          title: finding.title,
          description: finding.description,
          severity: finding.severity,
          category: finding.category,
          status: finding.status,
          fingerprint,
          triageStatus: finding.triageStatus ?? inheritedTriage?.triageStatus ?? "new",
          triageNote: finding.triageNote ?? inheritedTriage?.triageNote ?? null,
          triagedAt: finding.triageStatus || inheritedTriage?.triageStatus ? new Date().toISOString() : null,
          workflowStatus: inheritedWorkflowStatus,
          workflowAssignee: inheritedWorkflowAssignee,
          workflowUpdatedAt: new Date().toISOString(),
          confidence: finding.confidence ?? null,
          cvssVector: finding.cvssVector ?? null,
          cvssScore: finding.cvssScore ?? null,
          evidenceRequest,
          evidenceResponse,
          evidenceAnalysis,
          layerVerdicts: layerVerdictsJson,
          pocSteps: pocStepsJson,
          verificationSpec: verificationSpecJson,
          semanticDedupe: semanticDedupeJson,
          findingRank,
          timestamp: finding.timestamp,
        },
      })
      .run();
    this.syncFindingGraph(scanId, fingerprint);
  }

  getFinding(findingId: string) {
    return this.db
      .select()
      .from(schema.findings)
      .where(eq(schema.findings.id, findingId))
      .get();
  }

  getFindings(scanId: string) {
    return this.db
      .select()
      .from(schema.findings)
      .where(eq(schema.findings.scanId, scanId))
      .orderBy(schema.findings.severity, schema.findings.timestamp)
      .all();
  }

  getScanFindings(scanId: string) {
    return this.getFindings(scanId);
  }

  getLatestFindingForScan(scanId: string) {
    return this.db
      .select()
      .from(schema.findings)
      .where(eq(schema.findings.scanId, scanId))
      .orderBy(desc(schema.findings.timestamp))
      .get();
  }

  listFindings(opts?: {
    scanId?: string;
    severity?: string;
    category?: string;
    status?: string;
    triageStatus?: string;
    limit?: number;
  }) {
    const conditions = [];
    if (opts?.scanId) conditions.push(eq(schema.findings.scanId, opts.scanId));
    if (opts?.severity) conditions.push(eq(schema.findings.severity, opts.severity));
    if (opts?.category) conditions.push(eq(schema.findings.category, opts.category));
    if (opts?.status) conditions.push(eq(schema.findings.status, opts.status));
    if (opts?.triageStatus) conditions.push(eq(schema.findings.triageStatus, opts.triageStatus));

    const query = this.db
      .select()
      .from(schema.findings)
      .orderBy(desc(schema.findings.timestamp))
      .limit(opts?.limit ?? 100);

    if (conditions.length > 0) {
      return query.where(and(...conditions)).all();
    }
    return query.all();
  }

  /** Alias for listFindings — backward compat with core agent tools */
  queryFindings(opts?: {
    scanId?: string;
    severity?: string;
    category?: string;
    status?: string;
    triageStatus?: string;
    limit?: number;
  }) {
    return this.listFindings(opts);
  }

  updateFindingStatus(findingId: string, status: string): void {
    const finding = this.getFinding(findingId);
    this.db
      .update(schema.findings)
      .set({ status })
      .where(eq(schema.findings.id, findingId))
      .run();
    if (finding?.fingerprint) this.syncFindingGraph(finding.scanId, finding.fingerprint);
  }

  saveFindingPocExecution(findingId: string, execution: unknown): void {
    const serialized = JSON.stringify(execution);
    this.db
      .update(schema.findings)
      .set({ pocExecution: serialized })
      .where(eq(schema.findings.id, findingId))
      .run();
  }

  updateFindingTriageByFingerprint(
    fingerprint: string,
    triageStatus: FindingTriageStatus,
    triageNote?: string,
  ): void {
    const latestFinding = this.getLatestFindingByFingerprint(fingerprint);
    const workflowStatus = triageStatus === "accepted"
      ? "done"
      : triageStatus === "suppressed"
        ? "cancelled"
        : null;
    this.db
      .update(schema.findings)
      .set({
        triageStatus,
        triageNote: triageNote ?? null,
        triagedAt: new Date().toISOString(),
        ...(workflowStatus
          ? {
              workflowStatus,
              workflowUpdatedAt: new Date().toISOString(),
            }
          : {}),
      })
      .where(eq(schema.findings.fingerprint, fingerprint))
      .run();
    const refreshedFinding = this.getLatestFindingByFingerprint(fingerprint) ?? latestFinding;
    if (refreshedFinding) {
      this.logEvent({
        scanId: refreshedFinding.scanId,
        stage: "triage",
        eventType: "triage_updated",
        findingId: refreshedFinding.id,
        payload: {
          fingerprint,
          triageStatus,
          workflowStatus: workflowStatus ?? "backlog",
          triageNote: triageNote ?? null,
        },
        timestamp: Date.now(),
      });
      this.syncFindingGraph(refreshedFinding.scanId, fingerprint);
      return;
    }
    this.syncFindingGraph("", fingerprint);
  }

  updateFindingWorkflowByFingerprint(
    fingerprint: string,
    workflowStatus: WorkflowStatus,
    workflowAssignee?: string | null,
  ): void {
    const latestFinding = this.getLatestFindingByFingerprint(fingerprint);
    const normalizedWorkflowStatus = normalizeWorkflowStatus(workflowStatus);
    const triageStatus =
      normalizedWorkflowStatus === "done"
        ? "accepted"
        : normalizedWorkflowStatus === "cancelled"
          ? "suppressed"
          : "new";

    this.db
      .update(schema.findings)
      .set({
        workflowStatus: normalizedWorkflowStatus,
        workflowAssignee: workflowAssignee ?? null,
        workflowUpdatedAt: new Date().toISOString(),
        triageStatus,
        triagedAt: triageStatus === "new" ? null : new Date().toISOString(),
      })
      .where(eq(schema.findings.fingerprint, fingerprint))
      .run();
    const refreshedFinding = this.getLatestFindingByFingerprint(fingerprint) ?? latestFinding;
    if (refreshedFinding) {
      this.logEvent({
        scanId: refreshedFinding.scanId,
        stage: "workflow",
        eventType: "workflow_status_changed",
        findingId: refreshedFinding.id,
        payload: {
          fingerprint,
          workflowStatus: normalizedWorkflowStatus,
          workflowAssignee: workflowAssignee ?? null,
          triageStatus,
        },
        timestamp: Date.now(),
      });
      this.syncFindingGraph(refreshedFinding.scanId, fingerprint);
      return;
    }
    this.syncFindingGraph("", fingerprint);
  }

  updateFindingTriage(findingId: string, triageStatus: FindingTriageStatus, triageNote?: string): void {
    const finding = this.getFinding(findingId);
    if (!finding) throw new Error(`Finding ${findingId} not found`);
    if (!finding.fingerprint) throw new Error(`Finding ${findingId} has no fingerprint`);
    this.updateFindingTriageByFingerprint(finding.fingerprint, triageStatus, triageNote);
  }

  getLatestFindingByFingerprint(fingerprint: string) {
    return this.db
      .select()
      .from(schema.findings)
      .where(eq(schema.findings.fingerprint, fingerprint))
      .orderBy(desc(schema.findings.timestamp))
      .get();
  }

  getRelatedFindings(fingerprint: string) {
    return this.db
      .select()
      .from(schema.findings)
      .where(eq(schema.findings.fingerprint, fingerprint))
      .orderBy(desc(schema.findings.timestamp))
      .all();
  }

  // ── Status Pipeline: discovered → verified → scored → reported ──

  transitionFindingStatus(findingId: string, newStatus: FindingStatusDB): void {
    const finding = this.getFinding(findingId);
    if (!finding) throw new Error(`Finding ${findingId} not found`);

    const currentIdx = findingStatuses.indexOf(finding.status as FindingStatusDB);
    const newIdx = findingStatuses.indexOf(newStatus);

    // Allow "false-positive" from any state; otherwise enforce forward-only pipeline
    if (newStatus !== "false-positive" && newIdx <= currentIdx) {
      throw new Error(
        `Cannot transition from '${finding.status}' to '${newStatus}'. ` +
        `Pipeline: ${findingStatuses.join(" → ")}`
      );
    }

    this.db
      .update(schema.findings)
      .set({ status: newStatus })
      .where(eq(schema.findings.id, findingId))
      .run();
    if (finding.fingerprint) this.syncFindingGraph(finding.scanId, finding.fingerprint);
  }

  scoreFinding(findingId: string, score: number): void {
    const finding = this.getFinding(findingId);
    if (score < 0 || score > 100) throw new Error("Score must be 0-100");
    this.db
      .update(schema.findings)
      .set({ score, status: "scored" })
      .where(eq(schema.findings.id, findingId))
      .run();
    if (finding?.fingerprint) this.syncFindingGraph(finding.scanId, finding.fingerprint);
  }

  // ── Attack Results ──

  saveAttackResult(scanId: string, result: AttackResult): void {
    const id = randomUUID();
    this.db.insert(schema.attackResults).values({
      id,
      scanId,
      templateId: result.templateId,
      payloadId: result.payloadId,
      outcome: result.outcome,
      request: result.request,
      response: result.response,
      latencyMs: result.latencyMs,
      timestamp: result.timestamp,
      error: result.error ?? null,
    }).run();
  }

  getAttackResults(scanId: string) {
    return this.db
      .select()
      .from(schema.attackResults)
      .where(eq(schema.attackResults.scanId, scanId))
      .orderBy(schema.attackResults.timestamp)
      .all();
  }

  // ── Verdicts (multi-agent consensus) ──

  addVerdict(verdict: AgentVerdict): void {
    this.db.insert(schema.verdicts).values({
      id: verdict.id,
      findingId: verdict.findingId,
      agentRole: verdict.agentRole,
      model: verdict.model,
      verdict: verdict.verdict,
      confidence: verdict.confidence,
      reasoning: verdict.reasoning,
      timestamp: verdict.timestamp,
    }).run();
    const finding = this.getFinding(verdict.findingId);
    if (finding?.fingerprint) this.syncFindingGraph(finding.scanId, finding.fingerprint);
  }

  getVerdicts(findingId: string) {
    return this.db
      .select()
      .from(schema.verdicts)
      .where(eq(schema.verdicts.findingId, findingId))
      .orderBy(desc(schema.verdicts.timestamp))
      .all();
  }

  listVerdicts(findingIds?: string[]) {
    if (!findingIds || findingIds.length === 0) return [];
    const placeholders = findingIds.map(() => "?").join(",");
    return this.sqlite
      .prepare(
        `SELECT * FROM verdicts WHERE findingId IN (${placeholders}) ORDER BY timestamp DESC`
      )
      .all(...findingIds) as Array<{
        id: string;
        findingId: string;
        agentRole: string;
        model: string;
        verdict: string;
        confidence: number;
        reasoning: string;
        timestamp: number;
      }>;
  }

  /** Compute consensus: all agree TRUE_POSITIVE → verified, all FALSE_POSITIVE → false-positive */
  computeConsensus(findingId: string): "verified" | "false-positive" | "disputed" | "pending" {
    const vds = this.getVerdicts(findingId);
    if (vds.length === 0) return "pending";
    const types = new Set(vds.map((v) => v.verdict));
    if (types.size === 1 && types.has("TRUE_POSITIVE")) return "verified";
    if (types.size === 1 && types.has("FALSE_POSITIVE")) return "false-positive";
    return "disputed";
  }

  // ── Pipeline Events (audit trail) ──

  logEvent(event: Omit<PipelineEvent, "id">): string {
    const id = randomUUID();
    this.db.insert(schema.pipelineEvents).values({
      id,
      scanId: event.scanId,
      stage: event.stage,
      eventType: event.eventType,
      findingId: event.findingId ?? null,
      agentRole: event.agentRole ?? null,
      payload: JSON.stringify(event.payload),
      timestamp: event.timestamp,
    }).run();
    this.syncEventGraph(event, id);
    return id;
  }

  getEvents(scanId: string, opts?: { stage?: string; eventType?: string }) {
    const conditions = [eq(schema.pipelineEvents.scanId, scanId)];
    if (opts?.stage) conditions.push(eq(schema.pipelineEvents.stage, opts.stage));
    if (opts?.eventType) conditions.push(eq(schema.pipelineEvents.eventType, opts.eventType));

    return this.db
      .select()
      .from(schema.pipelineEvents)
      .where(and(...conditions))
      .orderBy(schema.pipelineEvents.timestamp)
      .all();
  }

  listRecentEvents(limit = 50) {
    return this.db
      .select({
        id: schema.pipelineEvents.id,
        scanId: schema.pipelineEvents.scanId,
        scanTarget: schema.scans.target,
        stage: schema.pipelineEvents.stage,
        eventType: schema.pipelineEvents.eventType,
        findingId: schema.pipelineEvents.findingId,
        findingFingerprint: schema.findings.fingerprint,
        agentRole: schema.pipelineEvents.agentRole,
        payload: schema.pipelineEvents.payload,
        timestamp: schema.pipelineEvents.timestamp,
      })
      .from(schema.pipelineEvents)
      .innerJoin(schema.scans, eq(schema.pipelineEvents.scanId, schema.scans.id))
      .leftJoin(schema.findings, eq(schema.pipelineEvents.findingId, schema.findings.id))
      .orderBy(desc(schema.pipelineEvents.timestamp))
      .limit(limit)
      .all();
  }

  // ── Agent Sessions (resumable state) ──

  saveSession(session: {
    id: string;
    scanId: string;
    agentRole: string;
    turnCount: number;
    messages: unknown[];
    toolContext: Record<string, unknown>;
    status: string;
  }): void {
    const now = new Date().toISOString();
    this.db
      .insert(schema.agentSessions)
      .values({
        id: session.id,
        scanId: session.scanId,
        agentRole: session.agentRole,
        turnCount: session.turnCount,
        messages: JSON.stringify(session.messages),
        toolContext: JSON.stringify(session.toolContext),
        status: session.status,
        createdAt: now,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: schema.agentSessions.id,
        set: {
          turnCount: session.turnCount,
          messages: JSON.stringify(session.messages),
          toolContext: JSON.stringify(session.toolContext),
          status: session.status,
          updatedAt: now,
        },
      })
      .run();
    this.syncSessionGraph(session);
  }

  getSession(scanId: string, agentRole: string) {
    return this.db
      .select()
      .from(schema.agentSessions)
      .where(
        and(
          eq(schema.agentSessions.scanId, scanId),
          eq(schema.agentSessions.agentRole, agentRole)
        )
      )
      .get();
  }

  getSessionById(sessionId: string) {
    return this.db
      .select()
      .from(schema.agentSessions)
      .where(eq(schema.agentSessions.id, sessionId))
      .get();
  }

  listSessions(opts?: { scanIds?: string[]; status?: string }) {
    const conditions: string[] = [];
    const params: Array<string> = [];

    if (opts?.scanIds?.length) {
      conditions.push(`scanId IN (${opts.scanIds.map(() => "?").join(",")})`);
      params.push(...opts.scanIds);
    }

    if (opts?.status) {
      conditions.push("status = ?");
      params.push(opts.status);
    }

    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    return this.sqlite
      .prepare(`SELECT * FROM agent_sessions ${where} ORDER BY updatedAt DESC`)
      .all(...params) as Array<{
        id: string;
        scanId: string;
        agentRole: string;
        turnCount: number;
        messages: string;
        toolContext: string;
        status: string;
        createdAt: string;
        updatedAt: string;
      }>;
  }

  // ── Cases / Work Items / Artifacts ──

  upsertCase(record: Omit<CaseRecord, "createdAt" | "updatedAt"> & { createdAt?: string; updatedAt?: string }): void {
    const now = new Date().toISOString();
    this.db
      .insert(schema.cases)
      .values({
        id: record.id,
        target: record.target,
        targetType: record.targetType,
        latestScanId: record.latestScanId ?? null,
        status: record.status,
        createdAt: record.createdAt ?? now,
        updatedAt: record.updatedAt ?? now,
      })
      .onConflictDoUpdate({
        target: schema.cases.id,
        set: {
          target: record.target,
          targetType: record.targetType,
          latestScanId: record.latestScanId ?? null,
          status: record.status,
          updatedAt: record.updatedAt ?? now,
        },
      })
      .run();
  }

  getCase(caseId: string) {
    return this.db.select().from(schema.cases).where(eq(schema.cases.id, caseId)).get();
  }

  listCases(limit = 100) {
    return this.db.select().from(schema.cases).orderBy(desc(schema.cases.updatedAt)).limit(limit).all();
  }

  upsertWorkItem(record: Omit<WorkItemRecord, "createdAt" | "updatedAt"> & { createdAt?: string; updatedAt?: string }): void {
    const now = new Date().toISOString();
    this.db
      .insert(schema.workItems)
      .values({
        id: record.id,
        caseId: record.caseId,
        findingFingerprint: record.findingFingerprint ?? null,
        kind: record.kind,
        title: record.title,
        owner: record.owner ?? null,
        status: record.status,
        summary: record.summary ?? null,
        dependsOn: record.dependsOn ?? null,
        createdAt: record.createdAt ?? now,
        updatedAt: record.updatedAt ?? now,
      })
      .onConflictDoUpdate({
        target: schema.workItems.id,
        set: {
          caseId: record.caseId,
          findingFingerprint: record.findingFingerprint ?? null,
          kind: record.kind,
          title: record.title,
          owner: record.owner ?? null,
          status: record.status,
          summary: record.summary ?? null,
          dependsOn: record.dependsOn ?? null,
          updatedAt: record.updatedAt ?? now,
        },
      })
      .run();
  }

  listWorkItems(opts?: { caseId?: string; findingFingerprint?: string; status?: string; limit?: number }) {
    const conditions = [];
    if (opts?.caseId) conditions.push(eq(schema.workItems.caseId, opts.caseId));
    if (opts?.findingFingerprint) conditions.push(eq(schema.workItems.findingFingerprint, opts.findingFingerprint));
    if (opts?.status) conditions.push(eq(schema.workItems.status, opts.status));

    const query = this.db.select().from(schema.workItems).orderBy(desc(schema.workItems.updatedAt)).limit(opts?.limit ?? 200);
    if (conditions.length > 0) return query.where(and(...conditions)).all();
    return query.all();
  }

  claimWorkItem(
    workItemId: string,
    workerId: string,
    opts?: {
      expectedStatus?: WorkItemRecord["status"];
      owner?: string | null;
      summary?: string | null;
    },
  ): boolean {
    const now = new Date().toISOString();
    const result = this.sqlite
      .prepare(`
        UPDATE work_items
        SET status = 'in_progress',
            owner = @owner,
            summary = COALESCE(@summary, summary),
            updatedAt = @updatedAt
        WHERE id = @id
          AND status = @expectedStatus
      `)
      .run({
        id: workItemId,
        owner: opts?.owner ?? workerId,
        summary: opts?.summary ?? null,
        updatedAt: now,
        expectedStatus: opts?.expectedStatus ?? "todo",
      });

    return result.changes > 0;
  }

  upsertArtifact(record: Omit<ArtifactRecord, "createdAt" | "updatedAt"> & { createdAt?: string; updatedAt?: string }): void {
    const now = new Date().toISOString();
    this.db
      .insert(schema.artifacts)
      .values({
        id: record.id,
        caseId: record.caseId,
        findingFingerprint: record.findingFingerprint ?? null,
        workItemId: record.workItemId ?? null,
        kind: record.kind,
        label: record.label,
        content: record.content ?? null,
        metadata: record.metadata ? JSON.stringify(record.metadata) : null,
        createdAt: record.createdAt ?? now,
        updatedAt: record.updatedAt ?? now,
      })
      .onConflictDoUpdate({
        target: schema.artifacts.id,
        set: {
          caseId: record.caseId,
          findingFingerprint: record.findingFingerprint ?? null,
          workItemId: record.workItemId ?? null,
          kind: record.kind,
          label: record.label,
          content: record.content ?? null,
          metadata: record.metadata ? JSON.stringify(record.metadata) : null,
          updatedAt: record.updatedAt ?? now,
        },
      })
      .run();
  }

  listArtifacts(opts?: { caseId?: string; findingFingerprint?: string; workItemId?: string; limit?: number }) {
    const conditions = [];
    if (opts?.caseId) conditions.push(eq(schema.artifacts.caseId, opts.caseId));
    if (opts?.findingFingerprint) conditions.push(eq(schema.artifacts.findingFingerprint, opts.findingFingerprint));
    if (opts?.workItemId) conditions.push(eq(schema.artifacts.workItemId, opts.workItemId));

    const query = this.db.select().from(schema.artifacts).orderBy(desc(schema.artifacts.updatedAt)).limit(opts?.limit ?? 200);
    if (conditions.length > 0) return query.where(and(...conditions)).all();
    return query.all();
  }

  upsertWorker(record: Omit<WorkerRecord, "startedAt" | "updatedAt" | "heartbeatAt"> & {
    startedAt?: string;
    updatedAt?: string;
    heartbeatAt?: string;
  }): void {
    const now = new Date().toISOString();
    this.db
      .insert(schema.workers)
      .values({
        id: record.id,
        role: record.role,
        status: record.status,
        label: record.label,
        currentCaseId: record.currentCaseId ?? null,
        currentWorkItemId: record.currentWorkItemId ?? null,
        currentScanId: record.currentScanId ?? null,
        pid: record.pid ?? null,
        host: record.host ?? null,
        lastError: record.lastError ?? null,
        heartbeatAt: record.heartbeatAt ?? now,
        startedAt: record.startedAt ?? now,
        updatedAt: record.updatedAt ?? now,
      })
      .onConflictDoUpdate({
        target: schema.workers.id,
        set: {
          role: record.role,
          status: record.status,
          label: record.label,
          currentCaseId: record.currentCaseId ?? null,
          currentWorkItemId: record.currentWorkItemId ?? null,
          currentScanId: record.currentScanId ?? null,
          pid: record.pid ?? null,
          host: record.host ?? null,
          lastError: record.lastError ?? null,
          heartbeatAt: record.heartbeatAt ?? now,
          updatedAt: record.updatedAt ?? now,
        },
      })
      .run();
  }

  listWorkers(limit = 50) {
    return this.db.select().from(schema.workers).orderBy(desc(schema.workers.heartbeatAt)).limit(limit).all();
  }

  stopWorkersByLabel(label: string, exceptId?: string): number {
    const now = new Date().toISOString();
    const result = this.sqlite
      .prepare(`
        UPDATE workers
        SET status = 'stopped',
            currentCaseId = NULL,
            currentWorkItemId = NULL,
            currentScanId = NULL,
            updatedAt = @updatedAt,
            heartbeatAt = @heartbeatAt,
            lastError = CASE
              WHEN lastError IS NULL OR lastError = '' THEN 'Superseded by a newer worker with the same label.'
              ELSE lastError
            END
        WHERE label = @label
          AND (@exceptId IS NULL OR id != @exceptId)
          AND status != 'stopped'
      `)
      .run({
        label,
        exceptId: exceptId ?? null,
        updatedAt: now,
        heartbeatAt: now,
      });

    return result.changes;
  }

  deleteWorkersByStatus(statuses: string | string[]): number {
    const values = Array.isArray(statuses) ? statuses : [statuses];
    if (values.length === 0) return 0;

    const placeholders = values.map(() => "?").join(",");
    const result = this.sqlite
      .prepare(`DELETE FROM workers WHERE status IN (${placeholders})`)
      .run(...values);

    return result.changes;
  }

  // ── Persistent credential store (pwnkit#771) ──

  /**
   * Upsert a discovered foothold keyed by (credentialKind, valueHash). First
   * write records the discovery attribution (target/finding/scan/turn);
   * subsequent sightings bump `timesSeen` and refresh `lastScanId`/`lastSeenAt`
   * without overwriting the original discovery columns. Returns the stored row.
   *
   * Plaintext is never accepted here — the caller passes a precomputed
   * `valueHash` and a redacted `valuePreview`.
   */
  upsertPersistentCredential(input: PersistentCredentialUpsert): PersistentCredentialRow {
    const now = new Date().toISOString();
    const existing = this.getPersistentCredential(input.credentialKind, input.valueHash);
    if (existing) {
      this.sqlite
        .prepare(
          `UPDATE persistent_credentials
             SET timesSeen = timesSeen + 1,
                 lastScanId = @lastScanId,
                 lastSeenAt = @lastSeenAt,
                 context = COALESCE(context, @context)
           WHERE id = @id`,
        )
        .run({
          id: existing.id,
          lastScanId: input.scanId ?? existing.lastScanId ?? null,
          lastSeenAt: now,
          context: input.context ?? null,
        });
      return this.getPersistentCredential(input.credentialKind, input.valueHash)!;
    }

    const id = randomUUID();
    this.sqlite
      .prepare(
        `INSERT INTO persistent_credentials
           (id, credentialKind, valueHash, valuePreview, context, target,
            firstScanId, firstFindingId, firstSource, firstTurn, lastScanId,
            timesSeen, firstSeenAt, lastSeenAt)
         VALUES
           (@id, @credentialKind, @valueHash, @valuePreview, @context, @target,
            @firstScanId, @firstFindingId, @firstSource, @firstTurn, @lastScanId,
            1, @firstSeenAt, @lastSeenAt)`,
      )
      .run({
        id,
        credentialKind: input.credentialKind,
        valueHash: input.valueHash,
        valuePreview: input.valuePreview,
        context: input.context ?? null,
        target: input.target ?? null,
        firstScanId: input.scanId ?? null,
        firstFindingId: input.findingId ?? null,
        firstSource: input.source ?? null,
        firstTurn: input.turn ?? null,
        lastScanId: input.scanId ?? null,
        firstSeenAt: now,
        lastSeenAt: now,
      });
    return this.getPersistentCredential(input.credentialKind, input.valueHash)!;
  }

  getPersistentCredential(credentialKind: string, valueHash: string): PersistentCredentialRow | undefined {
    return this.sqlite
      .prepare(
        `SELECT * FROM persistent_credentials WHERE credentialKind = ? AND valueHash = ?`,
      )
      .get(credentialKind, valueHash) as PersistentCredentialRow | undefined;
  }

  listPersistentCredentials(query: PersistentCredentialQuery = {}): PersistentCredentialRow[] {
    const where: string[] = [];
    const params: unknown[] = [];
    if (query.credentialKind) {
      where.push("credentialKind = ?");
      params.push(query.credentialKind);
    }
    if (query.target) {
      where.push("target = ?");
      params.push(query.target);
    }
    const whereSql = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
    const limit = query.limit ?? 500;
    return this.sqlite
      .prepare(
        `SELECT * FROM persistent_credentials ${whereSql} ORDER BY lastSeenAt DESC LIMIT ${limit}`,
      )
      .all(...params) as PersistentCredentialRow[];
  }

  // ── Trust graph edges (pwnkit#771) ──

  /**
   * Upsert a directed trust edge keyed by
   * (srcKind, srcId, dstKind, dstId, relation). Re-observing an edge refreshes
   * `updatedAt` (and `confidence`/`note`/attribution when provided) rather than
   * inserting a duplicate. Returns the stored row.
   */
  upsertTrustGraphEdge(input: TrustGraphEdgeInput): TrustGraphEdgeRow {
    const now = new Date().toISOString();
    const existing = this.sqlite
      .prepare(
        `SELECT * FROM trust_graph_edges
          WHERE srcKind = ? AND srcId = ? AND dstKind = ? AND dstId = ? AND relation = ?`,
      )
      .get(input.srcKind, input.srcId, input.dstKind, input.dstId, input.relation) as
      | TrustGraphEdgeRow
      | undefined;

    if (existing) {
      this.sqlite
        .prepare(
          `UPDATE trust_graph_edges
              SET scanId = COALESCE(@scanId, scanId),
                  findingId = COALESCE(@findingId, findingId),
                  confidence = COALESCE(@confidence, confidence),
                  note = COALESCE(@note, note),
                  updatedAt = @updatedAt
            WHERE id = @id`,
        )
        .run({
          id: existing.id,
          scanId: input.scanId ?? null,
          findingId: input.findingId ?? null,
          confidence: input.confidence ?? null,
          note: input.note ?? null,
          updatedAt: now,
        });
      return { ...existing, updatedAt: now };
    }

    const id = randomUUID();
    this.sqlite
      .prepare(
        `INSERT INTO trust_graph_edges
           (id, srcKind, srcId, dstKind, dstId, relation, scanId, findingId,
            confidence, note, createdAt, updatedAt)
         VALUES
           (@id, @srcKind, @srcId, @dstKind, @dstId, @relation, @scanId,
            @findingId, @confidence, @note, @createdAt, @updatedAt)`,
      )
      .run({
        id,
        srcKind: input.srcKind,
        srcId: input.srcId,
        dstKind: input.dstKind,
        dstId: input.dstId,
        relation: input.relation,
        scanId: input.scanId ?? null,
        findingId: input.findingId ?? null,
        confidence: input.confidence ?? null,
        note: input.note ?? null,
        createdAt: now,
        updatedAt: now,
      });
    return {
      id,
      srcKind: input.srcKind,
      srcId: input.srcId,
      dstKind: input.dstKind,
      dstId: input.dstId,
      relation: input.relation,
      scanId: input.scanId ?? null,
      findingId: input.findingId ?? null,
      confidence: input.confidence ?? null,
      note: input.note ?? null,
      createdAt: now,
      updatedAt: now,
    };
  }

  listTrustGraphEdges(query: { srcKind?: string; srcId?: string; relation?: string; limit?: number } = {}): TrustGraphEdgeRow[] {
    const where: string[] = [];
    const params: unknown[] = [];
    if (query.srcKind) {
      where.push("srcKind = ?");
      params.push(query.srcKind);
    }
    if (query.srcId) {
      where.push("srcId = ?");
      params.push(query.srcId);
    }
    if (query.relation) {
      where.push("relation = ?");
      params.push(query.relation);
    }
    const whereSql = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
    const limit = query.limit ?? 500;
    return this.sqlite
      .prepare(
        `SELECT * FROM trust_graph_edges ${whereSql} ORDER BY updatedAt DESC LIMIT ${limit}`,
      )
      .all(...params) as TrustGraphEdgeRow[];
  }

  // ── Utilities ──

  close(): void {
    this.sqlite.close();
  }

  transaction<T>(fn: () => T): T {
    return this.sqlite.transaction(fn)();
  }

  /** Get summary stats across all findings */
  getStats() {
    const rows = this.sqlite
      .prepare(
        `SELECT severity, COUNT(*) as count FROM findings GROUP BY severity`
      )
      .all() as { severity: string; count: number }[];
    const stats: Record<string, number> = {};
    for (const row of rows) stats[row.severity] = row.count;
    return {
      total: rows.reduce((sum, r) => sum + r.count, 0),
      critical: stats["critical"] ?? 0,
      high: stats["high"] ?? 0,
      medium: stats["medium"] ?? 0,
      low: stats["low"] ?? 0,
      info: stats["info"] ?? 0,
    };
  }
}

function normalizeFingerprintPart(value: string): string {
  return value
    .toLowerCase()
    .replace(/\r/g, "")
    .replace(/:\d+(?::\d+)?/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function buildFindingFingerprint(target: string, finding: Finding): string {
  const key = [
    normalizeFingerprintPart(target),
    normalizeFingerprintPart(finding.category),
    normalizeFingerprintPart(finding.title),
    normalizeFingerprintPart(finding.evidence.request.split("\n")[0] ?? ""),
  ].join("::");

  return createHash("sha256").update(key).digest("hex").slice(0, 24);
}

/**
 * When a finding only carries `pocSteps` and no prose evidence, derive the
 * legacy `evidence.{request,response,analysis}` strings from the step graph
 * so older readers (markdown advisory templates that pre-date pocSteps,
 * dashboards that haven't been updated) still see something useful. The
 * structured `pocSteps` field remains the canonical form — this is purely
 * for backwards compatibility on the read path.
 */
function deriveEvidenceFromPocSteps(finding: Finding): { request: string; response: string; analysis?: string } {
  if (!finding.pocSteps || finding.pocSteps.length === 0) {
    return { request: "", response: "", analysis: undefined };
  }

  const requestParts: string[] = [];
  const responseParts: string[] = [];
  const analysisParts: string[] = [];

  for (const step of finding.pocSteps) {
    const prefix = `[${step.kind}] ${step.summary}`;
    if (step.action.type === "shell") {
      requestParts.push(`${prefix}\n$ ${step.action.cmd}`);
    } else if (step.action.type === "http") {
      requestParts.push(`${prefix}\n${step.action.method.toUpperCase()} ${step.action.url}`);
    } else if (step.action.type === "docker") {
      requestParts.push(`${prefix}\ndocker run ${step.action.image} ${step.action.args.join(" ")}`.trim());
    } else {
      responseParts.push(`${prefix}\n${step.action.text}`);
    }
    if (step.expect) {
      analysisParts.push(`- ${step.id}: expect ${step.expect.type}`);
    }
  }

  return {
    request: requestParts.join("\n\n"),
    response: responseParts.join("\n\n"),
    analysis: analysisParts.length > 0 ? `PoC step expectations:\n${analysisParts.join("\n")}` : undefined,
  };
}

// ── Raw SQL for table creation (idempotent, used on init) ──
//
// IMPORTANT: This SQL is generated from the drizzle schema in schema.ts.
// When adding or removing columns, update schema.ts first — that is the
// single source of truth — then mirror the change here.  The migrate()
// method below handles ALTER TABLE for databases created by older versions;
// fresh installs get every column from day one via this SQL.
//
// See: https://github.com/0sec-labs/pwnkit/issues/420

const SCHEMA_TABLES_SQL = `
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  depth TEXT NOT NULL,
  runtime TEXT NOT NULL DEFAULT 'api',
  mode TEXT NOT NULL DEFAULT 'probe',
  status TEXT NOT NULL DEFAULT 'running',
  startedAt TEXT NOT NULL,
  completedAt TEXT,
  durationMs INTEGER,
  summary TEXT
);

CREATE TABLE IF NOT EXISTS targets (
  id TEXT PRIMARY KEY,
  url TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL DEFAULT 'unknown',
  model TEXT,
  systemPrompt TEXT,
  detectedFeatures TEXT,
  endpoints TEXT,
  firstSeenAt TEXT NOT NULL,
  lastSeenAt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  scanId TEXT NOT NULL REFERENCES scans(id),
  templateId TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  severity TEXT NOT NULL,
  category TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'discovered',
  fingerprint TEXT,
  triageStatus TEXT NOT NULL DEFAULT 'new',
  triageNote TEXT,
  triagedAt TEXT,
  workflowStatus TEXT NOT NULL DEFAULT 'backlog',
  workflowAssignee TEXT,
  workflowUpdatedAt TEXT,
  score INTEGER,
  confidence REAL,
  cvssVector TEXT,
  cvssScore REAL,
  evidenceRequest TEXT NOT NULL,
  evidenceResponse TEXT NOT NULL,
  evidenceAnalysis TEXT,
  layerVerdicts TEXT,
  pocSteps TEXT,
  verificationSpec TEXT,
  pocExecution TEXT,
  semanticDedupe TEXT,
  findingRank INTEGER,
  timestamp INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS attack_results (
  id TEXT PRIMARY KEY,
  scanId TEXT NOT NULL REFERENCES scans(id),
  templateId TEXT NOT NULL,
  payloadId TEXT NOT NULL,
  outcome TEXT NOT NULL,
  request TEXT NOT NULL,
  response TEXT NOT NULL,
  latencyMs INTEGER NOT NULL,
  timestamp INTEGER NOT NULL,
  error TEXT
);

CREATE TABLE IF NOT EXISTS verdicts (
  id TEXT PRIMARY KEY,
  findingId TEXT NOT NULL REFERENCES findings(id),
  agentRole TEXT NOT NULL,
  model TEXT NOT NULL DEFAULT '',
  verdict TEXT NOT NULL,
  confidence REAL NOT NULL DEFAULT 0,
  reasoning TEXT NOT NULL DEFAULT '',
  timestamp INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pipeline_events (
  id TEXT PRIMARY KEY,
  scanId TEXT NOT NULL REFERENCES scans(id),
  stage TEXT NOT NULL,
  eventType TEXT NOT NULL,
  findingId TEXT,
  agentRole TEXT,
  payload TEXT NOT NULL DEFAULT '{}',
  timestamp INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_sessions (
  id TEXT PRIMARY KEY,
  scanId TEXT NOT NULL REFERENCES scans(id),
  agentRole TEXT NOT NULL,
  turnCount INTEGER NOT NULL DEFAULT 0,
  messages TEXT NOT NULL DEFAULT '[]',
  toolContext TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'running',
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY,
  target TEXT NOT NULL UNIQUE,
  targetType TEXT NOT NULL DEFAULT 'unknown',
  latestScanId TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS work_items (
  id TEXT PRIMARY KEY,
  caseId TEXT NOT NULL REFERENCES cases(id),
  findingFingerprint TEXT,
  kind TEXT NOT NULL,
  title TEXT NOT NULL,
  owner TEXT,
  status TEXT NOT NULL DEFAULT 'backlog',
  summary TEXT,
  dependsOn TEXT,
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY,
  caseId TEXT NOT NULL REFERENCES cases(id),
  findingFingerprint TEXT,
  workItemId TEXT,
  kind TEXT NOT NULL,
  label TEXT NOT NULL,
  content TEXT,
  metadata TEXT,
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS triage_memories (
  id TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  scope_value TEXT,
  category TEXT NOT NULL,
  pattern TEXT NOT NULL,
  reasoning TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  applied_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS workers (
  id TEXT PRIMARY KEY,
  role TEXT NOT NULL DEFAULT 'orchestrator',
  status TEXT NOT NULL DEFAULT 'idle',
  label TEXT NOT NULL,
  currentCaseId TEXT,
  currentWorkItemId TEXT,
  currentScanId TEXT,
  pid INTEGER,
  host TEXT,
  lastError TEXT,
  heartbeatAt TEXT NOT NULL,
  startedAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS persistent_credentials (
  id TEXT PRIMARY KEY,
  credentialKind TEXT NOT NULL,
  valueHash TEXT NOT NULL,
  valuePreview TEXT NOT NULL,
  context TEXT,
  target TEXT,
  firstScanId TEXT,
  firstFindingId TEXT,
  firstSource TEXT,
  firstTurn INTEGER,
  lastScanId TEXT,
  timesSeen INTEGER NOT NULL DEFAULT 1,
  firstSeenAt TEXT NOT NULL,
  lastSeenAt TEXT NOT NULL,
  UNIQUE(credentialKind, valueHash)
);

CREATE TABLE IF NOT EXISTS trust_graph_edges (
  id TEXT PRIMARY KEY,
  srcKind TEXT NOT NULL,
  srcId TEXT NOT NULL,
  dstKind TEXT NOT NULL,
  dstId TEXT NOT NULL,
  relation TEXT NOT NULL,
  scanId TEXT,
  findingId TEXT,
  confidence REAL,
  note TEXT,
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL,
  UNIQUE(srcKind, srcId, dstKind, dstId, relation)
);
`;

const SCHEMA_INDEXES_SQL = `
CREATE INDEX IF NOT EXISTS idx_findings_scanId ON findings(scanId);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_triageStatus ON findings(triageStatus);
CREATE INDEX IF NOT EXISTS idx_findings_workflowStatus ON findings(workflowStatus);
CREATE INDEX IF NOT EXISTS idx_attack_results_scanId ON attack_results(scanId);
CREATE INDEX IF NOT EXISTS idx_targets_url ON targets(url);
CREATE INDEX IF NOT EXISTS idx_verdicts_findingId ON verdicts(findingId);
CREATE INDEX IF NOT EXISTS idx_events_scanId ON pipeline_events(scanId);
CREATE INDEX IF NOT EXISTS idx_events_stage ON pipeline_events(stage);
CREATE INDEX IF NOT EXISTS idx_events_findingId ON pipeline_events(findingId);
CREATE INDEX IF NOT EXISTS idx_sessions_scanId ON agent_sessions(scanId);
CREATE INDEX IF NOT EXISTS idx_sessions_role ON agent_sessions(agentRole);
CREATE INDEX IF NOT EXISTS idx_cases_target ON cases(target);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_work_items_caseId ON work_items(caseId);
CREATE INDEX IF NOT EXISTS idx_work_items_fingerprint ON work_items(findingFingerprint);
CREATE INDEX IF NOT EXISTS idx_work_items_status ON work_items(status);
CREATE INDEX IF NOT EXISTS idx_artifacts_caseId ON artifacts(caseId);
CREATE INDEX IF NOT EXISTS idx_artifacts_fingerprint ON artifacts(findingFingerprint);
CREATE INDEX IF NOT EXISTS idx_artifacts_workItemId ON artifacts(workItemId);
CREATE INDEX IF NOT EXISTS idx_workers_status ON workers(status);
CREATE INDEX IF NOT EXISTS idx_workers_heartbeat ON workers(heartbeatAt);
CREATE INDEX IF NOT EXISTS idx_memories_category ON triage_memories(category, scope);
CREATE INDEX IF NOT EXISTS idx_memories_scope ON triage_memories(scope, scope_value);
CREATE INDEX IF NOT EXISTS idx_pcred_kind_hash ON persistent_credentials(credentialKind, valueHash);
CREATE INDEX IF NOT EXISTS idx_pcred_target ON persistent_credentials(target);
CREATE INDEX IF NOT EXISTS idx_pcred_kind ON persistent_credentials(credentialKind);
CREATE INDEX IF NOT EXISTS idx_tge_src ON trust_graph_edges(srcKind, srcId);
CREATE INDEX IF NOT EXISTS idx_tge_dst ON trust_graph_edges(dstKind, dstId);
CREATE INDEX IF NOT EXISTS idx_tge_relation ON trust_graph_edges(relation);
`;

function normalizeWorkflowStatus(
  value?: string | null,
  fallback?: {
    status?: string | null;
    triageStatus?: string | null;
  },
): FindingWorkflowStatusDB {
  if (value && findingWorkflowStatuses.includes(value as FindingWorkflowStatusDB)) {
    return value as FindingWorkflowStatusDB;
  }

  if (fallback?.triageStatus === "accepted" || fallback?.status === "reported") {
    return "done";
  }
  if (fallback?.triageStatus === "suppressed" || fallback?.status === "false-positive") {
    return "cancelled";
  }
  if (fallback?.status && ["verified", "confirmed", "scored"].includes(fallback.status)) {
    return "human_review";
  }

  return "backlog";
}

type WorkflowStatus =
  | "backlog"
  | "todo"
  | "agent_review"
  | "in_progress"
  | "human_review"
  | "blocked"
  | "done"
  | "cancelled";

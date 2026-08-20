import { randomUUID } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { homeStateDir, runStateDir } from "@0sec/shared";

const STATE_DB_FILE = "state.db";
const REPORT_FILE = "report.json";

export interface OsecRunStorage {
  /** Stable local execution identity. Cloud workers use their orchestrator scan id. */
  runId: string;
  /** Private directory containing all mutable state for this execution. */
  runDir: string;
  /** SQLite state for this run only. Never shared with another fresh run. */
  dbPath: string;
  /** Atomically-written managed-worker report; omitted for explicit local DB paths. */
  reportPath?: string;
}

export interface ResolveOsecRunStorageOptions {
  /** Explicit caller path. This always wins over environment configuration. */
  dbPath?: string;
  /** Existing run id when resuming; omitted for a newly allocated run. */
  runId?: string;
  /** Fall back to the legacy monolithic database only to resume an old run. */
  resume?: boolean;
  /** Test seam; production uses the process environment. */
  env?: NodeJS.ProcessEnv;
  /** Test seam; production uses the operator's 0sec state directory. */
  homeDir?: string;
}


function normalizeRunId(value: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value)) {
    throw new Error(`Invalid 0sec run id ${JSON.stringify(value)}.`);
  }
  return value;
}


/**
 * Allocate the private state directory for one execution.
 *
 * A local SQLite database is execution state, not a multi-worker system of
 * record. Fresh runs therefore receive distinct paths. Managed workers pass
 * their orchestrator scan id through `0SEC_CLOUD_SCAN_ID`, making the local
 * run directory and the remote scan correlate without sharing a database.
 */
export function resolveOsecRunStorage(
  options: ResolveOsecRunStorageOptions = {},
): OsecRunStorage {
  const env = options.env ?? process.env;
  const cloudRunId = env["0SEC_CLOUD_SCAN_ID"]?.trim() || undefined;
  let runId = normalizeRunId(options.runId ?? cloudRunId ?? randomUUID());
  const stateDir = homeStateDir(options.homeDir);
  const configuredRunDir = env["0SEC_RUN_DIR"]?.trim() || undefined;
  const configuredDbPath =
    options.dbPath ?? (env["0SEC_DB_PATH"]?.trim() || undefined);
  let runDir = configuredRunDir
    ? resolve(configuredRunDir)
    : runStateDir(runId, options.homeDir);

  // New runs use their exact run id. A resume may receive the short id printed
  // by `0sec history`, so resolve one unambiguous run directory before falling
  // back to the pre-run-scoped monolithic database.
  if (
    options.resume &&
    !configuredRunDir &&
    !configuredDbPath &&
    !existsSync(runDir)
  ) {
    const runsDir = join(stateDir, "runs");
    if (existsSync(runsDir)) {
      const matches = readdirSync(runsDir, { withFileTypes: true }).filter(
        (entry) => entry.isDirectory() && entry.name.startsWith(runId),
      );
      if (matches.length > 1) {
        throw new Error(`0sec run id prefix '${runId}' is ambiguous.`);
      }
      const match = matches[0];
      if (match) {
        runId = normalizeRunId(match.name);
        runDir = join(runsDir, runId);
      }
    }
  }

  if (!isAbsolute(runDir)) {
    throw new Error(`0sec run directory must be absolute: ${JSON.stringify(runDir)}.`);
  }

  let dbPath = configuredDbPath
    ? configuredDbPath === ":memory:" ? configuredDbPath : resolve(configuredDbPath)
    : join(runDir, STATE_DB_FILE);
  const configuredReportPath = env["0SEC_REPORT_PATH"]?.trim() || undefined;
  const reportPath = configuredReportPath
    ? resolve(configuredReportPath)
    : !configuredDbPath || configuredRunDir
      ? join(runDir, REPORT_FILE)
      : undefined;

  // Existing releases kept every scan in one state DB. Preserve the ability to
  // resume that history, but never send a fresh run back to the shared file.
  if (options.resume && !configuredDbPath && !existsSync(dbPath)) {
    const legacyDbPath = join(stateDir, "0sec.db");
    if (existsSync(legacyDbPath)) dbPath = legacyDbPath;
  }
  if (!configuredDbPath || configuredRunDir || reportPath) {
    mkdirSync(runDir, { recursive: true, mode: 0o700 });
  }
  if (dbPath !== ":memory:") {
    mkdirSync(dirname(dbPath), { recursive: true, mode: 0o700 });
  }
  if (reportPath) {
    mkdirSync(dirname(reportPath), { recursive: true, mode: 0o700 });
  }

  return {
    runId,
    runDir,
    dbPath,
    ...(reportPath ? { reportPath } : {}),
  };
}
/**
 * Enumerate completed or active run-local databases without opening a shared
 * writer. Local history/read commands aggregate these immutable namespaces.
 */
export function listOsecRunDatabasePaths(homeDir?: string): string[] {
  const runsDir = join(homeStateDir(homeDir), "runs");
  if (!existsSync(runsDir)) return [];

  return readdirSync(runsDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => join(runsDir, entry.name, STATE_DB_FILE))
    .filter((path) => existsSync(path));
}


/**
 * Commit a complete report atomically. The managed worker reads only this
 * completed file after the engine exits; a crash can leave a temporary file,
 * never a truncated report at the stable path.
 */
export function writeOsecRunReport(storage: OsecRunStorage, report: unknown): void {
  const reportPath = storage.reportPath;
  if (!reportPath) return;

  const body = `${JSON.stringify(report)}\n`;
  const temporaryPath = join(
    dirname(reportPath),
    `.${REPORT_FILE}.${process.pid}.${randomUUID()}.tmp`,
  );

  try {
    writeFileSync(temporaryPath, body, { encoding: "utf8", mode: 0o600 });
    renameSync(temporaryPath, reportPath);
    chmodSync(reportPath, 0o600);
  } finally {
    if (existsSync(temporaryPath)) {
      rmSync(temporaryPath, { force: true });
    }
  }
}

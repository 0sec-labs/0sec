import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync, existsSync, renameSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import type { Finding } from "@0sec/shared";
import type {
  SecurePhase,
  SecureEvent,
  BehavioralRepairResult,
} from "./types.js";

// ── Manifest format ─────────────────────────────────────────────────────────

export interface SecureProjectState {
  version: 1;
  runId: string;
  configIdentity: string;
  /**
   * The exact fields that produced `configIdentity`, persisted so resume can
   * name the drifted field instead of only comparing hashes. Optional for
   * backward compatibility with state files written before it existed.
   */
  identity?: IdentityFields;
  revision: string;
  source: string;
  phase: SecurePhase;
  status: "running" | "completed" | "blocked" | "failed" | "cancelled";
  startedAt: string;
  completedAt?: string;
  findings: Finding[];
  repairs: Record<string, BehavioralRepairResult>;
  costUsd: number;
  events: SecureEvent[];
  pullRequests: string[];
  errors: string[];
  blockedFindingIds: string[];
  repairedFindingIds: string[];
}

// ── Identity helpers ────────────────────────────────────────────────────────

export interface IdentityFields {
  source: string;
  testCommand: string;
  setupCommand?: string;
  runtime?: string;
  maxFindings?: number;
  maxAttempts?: number;
  maxTurns?: number;
  depth?: string;
}

export function computeConfigIdentity(fields: IdentityFields): string {
  const norm = JSON.stringify(fields, Object.keys(fields).sort());
  return createHash("sha256").update(norm).digest("hex").slice(0, 16);
}

// ─── State I/O ──────────────────────────────────────────────────────────────

const STATE_FILE = "state.json";
const STATE_TMP = "state.json.tmp";

export function statePath(stateDir: string): string {
  return join(stateDir, STATE_FILE);
}

export function readState(stateDir: string): SecureProjectState | null {
  const path = statePath(stateDir);
  if (!existsSync(path)) return null;
  try {
    const raw = readFileSync(path, "utf-8");
    return JSON.parse(raw) as SecureProjectState;
  } catch {
    return null;
  }
}

export function writeState(stateDir: string, state: SecureProjectState): void {
  if (!existsSync(stateDir)) {
    mkdirSync(stateDir, { recursive: true });
  }
  const tmp = join(stateDir, STATE_TMP);
  const dst = statePath(stateDir);
  writeFileSync(tmp, JSON.stringify(state, null, 2), "utf-8");
  renameSync(tmp, dst);
}

// ─── State transitions ──────────────────────────────────────────────────────

export function createInitialState(
  runId: string,
  source: string,
  revision: string,
  configFields: IdentityFields,
): SecureProjectState {
  return {
    version: 1,
    runId,
    configIdentity: computeConfigIdentity(configFields),
    identity: configFields,
    revision,
    source,
    phase: "prepare",
    status: "running",
    startedAt: new Date().toISOString(),
    findings: [],
    repairs: {},
    costUsd: 0,
    events: [],
    pullRequests: [],
    errors: [],
    blockedFindingIds: [],
    repairedFindingIds: [],
  };
}

export function advanceState(
  state: SecureProjectState,
  phase: SecurePhase,
  status?: SecureProjectState["status"],
): SecureProjectState {
  return {
    ...state,
    phase,
    ...(status !== undefined ? { status } : {}),
    ...(status === "completed" || status === "failed" || status === "cancelled"
      ? { completedAt: new Date().toISOString() }
      : {}),
  };
}

export function addError(state: SecureProjectState, error: string): void {
  state.errors = [...state.errors, error];
}

export function addEvent(state: SecureProjectState, event: SecureEvent): void {
  state.events = [...state.events, event];
}

export function checkResumeCompatibility(
  state: SecureProjectState,
  configIdentity: string,
  revision: string,
): string | null {
  if (state.configIdentity !== configIdentity) {
    return `Config mismatch: previous run used identity "${state.configIdentity}", current is "${configIdentity}". Start fresh or revert config.`;
  }
  if (state.revision !== revision) {
    return `Revision mismatch: previous run pinned "${state.revision}", current is "${revision}". Cannot resume across revisions.`;
  }
  if (state.status === "completed") {
    return "Run already completed. Start fresh to re-run.";
  }
  if (state.status === "cancelled") {
    return "Run was cancelled. Start fresh to re-run.";
  }
  return null;
}

export function resumePhase(
  state: SecureProjectState,
): { phase: SecurePhase; skipRepairIds: string[]; skipBlockedIds: string[] } {
  const skipRepairIds = [...state.repairedFindingIds];
  const skipBlockedIds = [...state.blockedFindingIds];

  switch (state.phase) {
    case "prepare":
      return { phase: "prepare", skipRepairIds: [], skipBlockedIds: [] };
    case "investigate":
      return { phase: "investigate", skipRepairIds: [], skipBlockedIds: [] };
    case "reproduce":
    case "repair":
    case "test":
    case "verify":
      return { phase: "reproduce", skipRepairIds, skipBlockedIds };
    case "deliver":
      return { phase: "deliver", skipRepairIds, skipBlockedIds };
    case "complete":
      // checkResumeCompatibility already rejects completed/cancelled runs.
      // A run that ended blocked or failed retries the repair phase; the
      // caller un-blocks the selected findings so they are attempted again.
      if (state.status === "blocked" || state.status === "failed") {
        return { phase: "reproduce", skipRepairIds, skipBlockedIds: [] };
      }
      return { phase: "complete", skipRepairIds, skipBlockedIds };
    default:
      return { phase: "prepare", skipRepairIds: [], skipBlockedIds: [] };
  }
}

export function resolveRepoRevision(repoRoot: string): string {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: repoRoot,
      encoding: "utf-8",
      timeout: 15_000,
      stdio: "pipe",
    }).trim();
  } catch {
    throw new Error(`Failed to resolve git revision from ${repoRoot}`);
  }
}
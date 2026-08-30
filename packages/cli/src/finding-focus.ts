import { resolve } from "node:path";
import { existsSync } from "node:fs";
import type { Finding } from "@0sec/shared";
import {
  listOsecRunDatabasePaths,
  osecDB,
  resolveOsecDbPath,
} from "@0sec/db";
import { findingSchema, formatZodError } from "./commands/schemas.js";


export type FindingFocus = {
  finding: Finding;
  target: string | undefined;
  dbPath: string;
};

type PersistedFindingRow = Record<string, unknown> & {
  id?: unknown;
  scanId?: unknown;
};


function parseJson(value: unknown): unknown {
  if (value == null) return undefined;
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}

function databasePaths(dbPath?: string): string[] {
  if (dbPath?.trim()) return [resolve(dbPath)];

  return [...new Set([
    ...listOsecRunDatabasePaths(),
    resolveOsecDbPath(),
  ].map((path) => resolve(path)))];
}

function findingFromRow(
  row: PersistedFindingRow,
  reviewFields: Record<string, unknown>,
): Finding {
  const id = typeof row.id === "string" ? row.id : "";
  const record = {
    id,
    templateId: typeof row.templateId === "string" ? row.templateId : "",
    title: typeof row.title === "string" ? row.title : "",
    description: typeof row.description === "string" ? row.description : "",
    severity: typeof row.severity === "string" ? row.severity : "",
    category: typeof row.category === "string" ? row.category : "",
    status: typeof row.status === "string" ? row.status : "",
    fingerprint: typeof row.fingerprint === "string" ? row.fingerprint || undefined : undefined,
    triageStatus: typeof row.triageStatus === "string" ? row.triageStatus || undefined : undefined,
    triageNote: typeof row.triageNote === "string" ? row.triageNote || undefined : undefined,
    workflowStatus: typeof row.workflowStatus === "string" ? row.workflowStatus || undefined : undefined,
    workflowAssignee: typeof row.workflowAssignee === "string" ? row.workflowAssignee : null,
    confidence: typeof row.confidence === "number" ? row.confidence : undefined,
    cvssVector: typeof row.cvssVector === "string" ? row.cvssVector || undefined : undefined,
    cvssScore: typeof row.cvssScore === "number" ? row.cvssScore : undefined,
    timestamp: typeof row.timestamp === "number" && Number.isFinite(row.timestamp) ? row.timestamp : 0,
    evidence: {
      request: typeof row.evidenceRequest === "string" ? row.evidenceRequest : "",
      response: typeof row.evidenceResponse === "string" ? row.evidenceResponse : "",
      analysis: typeof row.evidenceAnalysis === "string" ? row.evidenceAnalysis || undefined : undefined,
    },
    layerVerdicts: parseJson(row.layerVerdicts),
    remediation: parseJson(row.remediation),
    pocSteps: parseJson(row.pocSteps),
    verificationSpec: parseJson(row.verificationSpec),
    ...reviewFields,
  };

  const parsed = findingSchema.safeParse(record);
  if (!parsed.success) {
    throw new Error(`Stored finding ${id || "<unknown>"} is invalid: ${formatZodError(parsed.error, "finding")}`);
  }
  return parsed.data as Finding;
}


/**
 * Resolve a persisted finding once, including the scan target that anchors the
 * conversation. A full id wins; a prefix must be unique across the chosen DBs.
 */
export function loadFindingFocus(id: string, options: { dbPath?: string } = {}): FindingFocus {
  const requestedId = id.trim();
  if (!requestedId) throw new Error("--finding requires a finding id");

  const matches: Array<{ row: PersistedFindingRow; target: string | undefined; dbPath: string }> = [];
  for (const dbPath of databasePaths(options.dbPath)) {
    if (!existsSync(dbPath)) {
      if (options.dbPath?.trim()) throw new Error(`Database does not exist: ${dbPath}`);
      continue;
    }
    const db = new osecDB(dbPath, { readOnly: true });
    try {
      const exact = db.getFinding(requestedId) as PersistedFindingRow | undefined;
      if (exact) {
        const scan = db.getScan(typeof exact.scanId === "string" ? exact.scanId : "") as { target?: unknown } | undefined;
        const reviewFields = db.getFindingReviewFields(requestedId) as Record<string, unknown>;
        return {
          finding: findingFromRow(exact, reviewFields),
          target: typeof scan?.target === "string" ? scan.target : undefined,
          dbPath,
        };
      }

      const prefixMatches = (db.listFindings({ limit: 5000 }) as PersistedFindingRow[])
        .filter((row) => typeof row.id === "string" && row.id.startsWith(requestedId));
      for (const row of prefixMatches) {
        const scan = db.getScan(typeof row.scanId === "string" ? row.scanId : "") as { target?: unknown } | undefined;
        matches.push({
          row,
          target: typeof scan?.target === "string" ? scan.target : undefined,
          dbPath,
        });
      }
    } finally {
      db.close();
    }
  }

  if (matches.length === 0) {
    throw new Error(`Finding '${requestedId}' was not found. Use a full id or pass --db-path.`);
  }
  if (matches.length > 1) {
    throw new Error(`Finding prefix '${requestedId}' is ambiguous. Use a longer id or pass --db-path.`);
  }

  const [match] = matches;
  const db = new osecDB(match!.dbPath, { readOnly: true });
  try {
    const reviewFields = db.getFindingReviewFields(
      typeof match!.row.id === "string" ? match!.row.id : "",
    ) as Record<string, unknown>;
    return {
      finding: findingFromRow(match!.row, reviewFields),
      target: match!.target,
      dbPath: match!.dbPath,
    };
  } finally {
    db.close();
  }
}

export {
  buildFindingChatPrompt,
  buildFindingConsoleCommand,
  FINDING_CHAT_INTENTS,
  resolveFindingChatIntent,
} from "./finding-handoff.js";
export type { FindingChatIntent } from "./finding-handoff.js";

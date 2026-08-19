import type { Severity, AttackCategory, FindingStatus, AttackOutcome, ScanDepth } from "@pwnkit/shared";

// ── Row types returned by the DB ──

export interface DBScan {
  id: string;
  target: string;
  depth: ScanDepth;
  runtime: string;
  mode: string;
  status: "running" | "completed" | "failed";
  startedAt: string;
  completedAt: string | null;
  durationMs: number | null;
  summary: string | null; // JSON-encoded ReportSummary
}

export interface DBTarget {
  id: string;
  url: string;
  type: string;
  model: string | null;
  systemPrompt: string | null;
  detectedFeatures: string | null; // JSON array
  endpoints: string | null; // JSON array
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface DBFinding {
  id: string;
  scanId: string;
  templateId: string;
  title: string;
  description: string;
  severity: Severity;
  category: AttackCategory;
  status: FindingStatus;
  confidence: number | null;
  cvssVector: string | null;
  cvssScore: number | null;
  evidenceRequest: string;
  evidenceResponse: string;
  evidenceAnalysis: string | null;
  timestamp: number;
}

export interface DBAttackResult {
  id: string;
  scanId: string;
  templateId: string;
  payloadId: string;
  outcome: AttackOutcome;
  request: string;
  response: string;
  latencyMs: number;
  timestamp: number;
  error: string | null;
}

// ── SQL for table creation ──

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  depth TEXT NOT NULL,
  runtime TEXT NOT NULL DEFAULT 'api',
  mode TEXT NOT NULL DEFAULT 'probe',
  status TEXT NOT NULL DEFAULT 'running',
  startedAt TEXT NOT NULL DEFAULT (datetime('now')),
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
  firstSeenAt TEXT NOT NULL DEFAULT (datetime('now')),
  lastSeenAt TEXT NOT NULL DEFAULT (datetime('now'))
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
  evidenceRequest TEXT NOT NULL,
  evidenceResponse TEXT NOT NULL,
  evidenceAnalysis TEXT,
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

CREATE INDEX IF NOT EXISTS idx_findings_scanId ON findings(scanId);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_attack_results_scanId ON attack_results(scanId);
CREATE INDEX IF NOT EXISTS idx_targets_url ON targets(url);
`;

import type { Severity, AttackCategory, FindingStatus, AttackOutcome, ScanDepth } from "@0sec/shared";

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


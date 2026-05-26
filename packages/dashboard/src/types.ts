export type ScanSummary = {
  totalFindings: number;
  totalAttacks?: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
};

export type FindingWorkflowStatus =
  | "backlog"
  | "todo"
  | "agent_review"
  | "in_progress"
  | "human_review"
  | "blocked"
  | "done"
  | "cancelled";

export type FindingWorkflowPhase =
  | "backlog"
  | "todo"
  | "in_progress"
  | "blocked"
  | "done"
  | "cancelled";

export type FindingReviewGate = "none" | "agent_review" | "human_review";

export type FindingConsensus = "verified" | "false-positive" | "disputed" | "pending";

export type ScanRecord = {
  id: string;
  target: string;
  depth: string;
  runtime: string;
  mode: string;
  status: string;
  startedAt: string;
  completedAt: string | null;
  durationMs: number | null;
  summary: ScanSummary;
};

export type FindingRecord = {
  id: string;
  scanId: string;
  title: string;
  description: string;
  severity: string;
  category: string;
  status: string;
  fingerprint?: string | null;
  triageStatus: "new" | "accepted" | "suppressed";
  triageNote?: string | null;
  workflowStatus?: FindingWorkflowStatus;
  workflowAssignee?: string | null;
  workflowUpdatedAt?: string | null;
  timestamp: number;
  score?: number | null;
  confidence?: number | null;
  evidenceRequest: string;
  evidenceResponse: string;
  evidenceAnalysis?: string | null;
};

export type FindingWorkflowSummary = {
  status: FindingWorkflowStatus;
  persistedStatus: FindingWorkflowStatus;
  recommendedStatus: FindingWorkflowStatus;
  phase: FindingWorkflowPhase;
  reviewGate: FindingReviewGate;
  reviewReason: string | null;
  assignee: string | null;
  updatedAt: string | null;
  consensus: FindingConsensus;
  activeAgentRoles: string[];
  evidenceSignal: "weak" | "medium" | "strong";
  verdictCounts: {
    truePositive: number;
    falsePositive: number;
    unsure: number;
    total: number;
  };
};

export type CaseSummary = {
  id: string;
  target: string;
  targetType: "ai-app" | "package" | "repository" | "web-app" | "unknown";
  latestScanId: string | null;
  scanCount: number;
  familyCount: number;
  activeRunCount: number;
  reviewCount: number;
  openWorkItemCount: number;
};

export type WorkItemSummary = {
  id: string;
  kind: "surface_map" | "hypothesis" | "poc_build" | "blind_verify" | "consensus" | "human_review";
  title: string;
  owner: string | null;
  status: "backlog" | "todo" | "in_progress" | "blocked" | "done" | "cancelled";
  summary: string;
};

export type WorkerSummary = {
  id: string;
  role: "orchestrator";
  status: "idle" | "claiming" | "running" | "sleeping" | "stopped" | "error";
  label: string;
  currentCaseId: string | null;
  currentCaseTarget: string | null;
  currentWorkItemId: string | null;
  currentWorkItemTitle: string | null;
  currentWorkItemKind: "surface_map" | "hypothesis" | "poc_build" | "blind_verify" | "consensus" | "human_review" | null;
  currentScanId: string | null;
  pid: number | null;
  host: string | null;
  lastError: string | null;
  heartbeatAt: string;
  startedAt: string;
  updatedAt: string;
  isActive: boolean;
};

export type QueueSummary = {
  runnable: number;
  active: number;
  blockedByDependency: number;
  manualReview: number;
  staleWorkers: number;
  recoveredClaims: number;
};

export type ArtifactSummary = {
  id: string;
  kind: "request" | "response" | "analysis" | "verdicts" | "sessions" | "events";
  label: string;
  summary: string;
};

export type FindingGroup = {
  fingerprint: string;
  latest: FindingRecord;
  count: number;
  scanCount: number;
  workflow: FindingWorkflowSummary;
};

export type DashboardResponse = {
  cases: CaseSummary[];
  scans: ScanRecord[];
  groups: FindingGroup[];
  workers: WorkerSummary[];
  queue: QueueSummary;
};

export type FindingFamilyResponse = {
  fingerprint: string;
  case: CaseSummary | null;
  latest: FindingRecord;
  rows: FindingRecord[];
  workflow: FindingWorkflowSummary;
  workItems: WorkItemSummary[];
  artifacts: ArtifactSummary[];
};

export type ScanEventsResponse = {
  scan: ScanRecord;
  events: Array<{
    id: string;
    scanId: string;
    stage: string;
    eventType: string;
    findingId?: string | null;
    agentRole?: string | null;
    payload: Record<string, unknown> | null;
    timestamp: number;
  }>;
};

export type RecentEventsResponse = {
  events: Array<{
    id: string;
    scanId: string;
    scanTarget: string;
    stage: string;
    eventType: string;
    findingId?: string | null;
    findingFingerprint?: string | null;
    agentRole?: string | null;
    summary: string;
    payload: Record<string, unknown> | null;
    timestamp: number;
  }>;
};

export type ScanFindingsResponse = {
  scan: ScanRecord;
  findings: FindingRecord[];
  groups: FindingGroup[];
};

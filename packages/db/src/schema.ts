import { sqliteTable, text, integer, real, index } from "drizzle-orm/sqlite-core";

// ── Finding status pipeline: discovered → verified → confirmed → scored → reported ──

export const findingStatuses = [
  "discovered",
  "verified",
  "confirmed",
  "scored",
  "reported",
  "false-positive",
] as const;
export type FindingStatusDB = (typeof findingStatuses)[number];

export const findingTriageStatuses = ["new", "accepted", "suppressed"] as const;
export type FindingTriageStatusDB = (typeof findingTriageStatuses)[number];
export const findingWorkflowStatuses = [
  "backlog",
  "todo",
  "agent_review",
  "in_progress",
  "human_review",
  "blocked",
  "done",
  "cancelled",
] as const;
export type FindingWorkflowStatusDB = (typeof findingWorkflowStatuses)[number];
export const caseStatuses = ["open", "in_progress", "human_review", "done", "cancelled"] as const;
export type CaseStatusDB = (typeof caseStatuses)[number];
export const workItemKinds = [
  "surface_map",
  "hypothesis",
  "poc_build",
  "blind_verify",
  "consensus",
  "human_review",
] as const;
export type WorkItemKindDB = (typeof workItemKinds)[number];
export const workItemStatuses = ["backlog", "todo", "in_progress", "blocked", "done", "cancelled"] as const;
export type WorkItemStatusDB = (typeof workItemStatuses)[number];
export const artifactKinds = ["request", "response", "analysis", "verdicts", "sessions", "events"] as const;
export type ArtifactKindDB = (typeof artifactKinds)[number];
export const workerStatuses = ["idle", "claiming", "running", "sleeping", "stopped", "error"] as const;
export type WorkerStatusDB = (typeof workerStatuses)[number];

// ── Tables ──

export const scans = sqliteTable("scans", {
  id: text("id").primaryKey(),
  target: text("target").notNull(),
  depth: text("depth").notNull(),
  runtime: text("runtime").notNull().default("api"),
  mode: text("mode").notNull().default("probe"),
  status: text("status").notNull().default("running"),
  startedAt: text("startedAt").notNull(),
  completedAt: text("completedAt"),
  durationMs: integer("durationMs"),
  summary: text("summary"), // JSON-encoded ReportSummary
});

export const targets = sqliteTable(
  "targets",
  {
    id: text("id").primaryKey(),
    url: text("url").notNull().unique(),
    type: text("type").notNull().default("unknown"),
    model: text("model"),
    systemPrompt: text("systemPrompt"),
    detectedFeatures: text("detectedFeatures"), // JSON array
    endpoints: text("endpoints"), // JSON array
    firstSeenAt: text("firstSeenAt").notNull(),
    lastSeenAt: text("lastSeenAt").notNull(),
  },
  (table) => [index("idx_targets_url").on(table.url)]
);

export const findings = sqliteTable(
  "findings",
  {
    id: text("id").primaryKey(),
    scanId: text("scanId")
      .notNull()
      .references(() => scans.id),
    templateId: text("templateId").notNull(),
    title: text("title").notNull(),
    description: text("description").notNull(),
    severity: text("severity").notNull(),
    category: text("category").notNull(),
    status: text("status").notNull().default("discovered"),
    fingerprint: text("fingerprint"),
    triageStatus: text("triageStatus").notNull().default("new"),
    triageNote: text("triageNote"),
    triagedAt: text("triagedAt"),
    workflowStatus: text("workflowStatus").notNull().default("backlog"),
    workflowAssignee: text("workflowAssignee"),
    workflowUpdatedAt: text("workflowUpdatedAt"),
    score: integer("score"), // CVSS-like 0-100 score, set during "scored" stage
    confidence: real("confidence"), // 0.0-1.0 agent-assessed confidence
    cvssVector: text("cvssVector"), // CVSS vector string
    cvssScore: real("cvssScore"), // CVSS numeric score (0-10)
    evidenceRequest: text("evidenceRequest").notNull(),
    evidenceResponse: text("evidenceResponse").notNull(),
    evidenceAnalysis: text("evidenceAnalysis"),
    /**
     * JSON-stringified LayerVerdict[] (see @pwnkit/shared types). NULL until
     * the triage stage runs. Stored as text rather than a join table because
     * the array is read-and-write together at finding-save time and we never
     * query individual verdict rows. See pwnkit#112.
     */
    layerVerdicts: text("layerVerdicts"),
    /**
     * JSON-stringified PocStep[] (see @pwnkit/shared types). NULL when the
     * agent only produced prose evidence (the legacy default). Stored as
     * text rather than a join table because the array is read-and-write
     * together at finding-save time and we never query individual steps.
     * See pwnkit#170.
     */
    pocSteps: text("pocSteps"),
    /**
     * JSON-stringified VerificationSpec (see @pwnkit/shared types). NULL
     * when the agent produced a finding without a deterministic re-check
     * contract — every reader must continue to work in that case. Stored
     * as text because the spec is an opaque blob that the verifier reads
     * whole; we never query individual predicates. See pwnkit#193 /
     * pwnkit-cloud#111.
     */
    verificationSpec: text("verificationSpec"),
    /**
     * JSON-stringified PocExecutionReport written when `disclose --target-url`
     * runs the step graph against a live target. NULL until that runs. See
     * pwnkit#171.
     */
    pocExecution: text("pocExecution"),
    timestamp: integer("timestamp").notNull(),
  },
  (table) => [
    index("idx_findings_scanId").on(table.scanId),
    index("idx_findings_severity").on(table.severity),
    index("idx_findings_category").on(table.category),
    index("idx_findings_status").on(table.status),
    index("idx_findings_fingerprint").on(table.fingerprint),
    index("idx_findings_triageStatus").on(table.triageStatus),
    index("idx_findings_workflowStatus").on(table.workflowStatus),
  ]
);

export const attackResults = sqliteTable(
  "attack_results",
  {
    id: text("id").primaryKey(),
    scanId: text("scanId")
      .notNull()
      .references(() => scans.id),
    templateId: text("templateId").notNull(),
    payloadId: text("payloadId").notNull(),
    outcome: text("outcome").notNull(),
    request: text("request").notNull(),
    response: text("response").notNull(),
    latencyMs: integer("latencyMs").notNull(),
    timestamp: integer("timestamp").notNull(),
    error: text("error"),
  },
  (table) => [index("idx_attack_results_scanId").on(table.scanId)]
);

// ── Verdicts (multi-agent consensus on findings) ──

export const verdicts = sqliteTable(
  "verdicts",
  {
    id: text("id").primaryKey(),
    findingId: text("findingId")
      .notNull()
      .references(() => findings.id),
    agentRole: text("agentRole").notNull(),
    model: text("model").notNull().default(""),
    verdict: text("verdict").notNull(), // TRUE_POSITIVE | FALSE_POSITIVE | UNSURE
    confidence: real("confidence").notNull().default(0),
    reasoning: text("reasoning").notNull().default(""),
    timestamp: integer("timestamp").notNull(),
  },
  (table) => [index("idx_verdicts_findingId").on(table.findingId)]
);

// ── Pipeline Events (immutable audit trail) ──

export const pipelineEvents = sqliteTable(
  "pipeline_events",
  {
    id: text("id").primaryKey(),
    scanId: text("scanId")
      .notNull()
      .references(() => scans.id),
    stage: text("stage").notNull(),
    eventType: text("eventType").notNull(),
    findingId: text("findingId"),
    agentRole: text("agentRole"),
    payload: text("payload").notNull().default("{}"), // JSON
    timestamp: integer("timestamp").notNull(),
  },
  (table) => [
    index("idx_events_scanId").on(table.scanId),
    index("idx_events_stage").on(table.stage),
    index("idx_events_findingId").on(table.findingId),
  ]
);

// ── Agent Sessions (resumable agent state) ──

export const agentSessions = sqliteTable(
  "agent_sessions",
  {
    id: text("id").primaryKey(),
    scanId: text("scanId")
      .notNull()
      .references(() => scans.id),
    agentRole: text("agentRole").notNull(),
    turnCount: integer("turnCount").notNull().default(0),
    messages: text("messages").notNull().default("[]"), // JSON serialized conversation
    toolContext: text("toolContext").notNull().default("{}"), // JSON serialized context
    status: text("status").notNull().default("running"), // running | paused | completed | failed
    createdAt: text("createdAt").notNull(),
    updatedAt: text("updatedAt").notNull(),
  },
  (table) => [
    index("idx_sessions_scanId").on(table.scanId),
    index("idx_sessions_role").on(table.agentRole),
  ]
);

export const cases = sqliteTable(
  "cases",
  {
    id: text("id").primaryKey(),
    target: text("target").notNull().unique(),
    targetType: text("targetType").notNull().default("unknown"),
    latestScanId: text("latestScanId"),
    status: text("status").notNull().default("open"),
    createdAt: text("createdAt").notNull(),
    updatedAt: text("updatedAt").notNull(),
  },
  (table) => [
    index("idx_cases_target").on(table.target),
    index("idx_cases_status").on(table.status),
  ]
);

export const workItems = sqliteTable(
  "work_items",
  {
    id: text("id").primaryKey(),
    caseId: text("caseId").notNull().references(() => cases.id),
    findingFingerprint: text("findingFingerprint"),
    kind: text("kind").notNull(),
    title: text("title").notNull(),
    owner: text("owner"),
    status: text("status").notNull().default("backlog"),
    summary: text("summary"),
    dependsOn: text("dependsOn"),
    createdAt: text("createdAt").notNull(),
    updatedAt: text("updatedAt").notNull(),
  },
  (table) => [
    index("idx_work_items_caseId").on(table.caseId),
    index("idx_work_items_fingerprint").on(table.findingFingerprint),
    index("idx_work_items_status").on(table.status),
  ]
);

export const artifacts = sqliteTable(
  "artifacts",
  {
    id: text("id").primaryKey(),
    caseId: text("caseId").notNull().references(() => cases.id),
    findingFingerprint: text("findingFingerprint"),
    workItemId: text("workItemId"),
    kind: text("kind").notNull(),
    label: text("label").notNull(),
    content: text("content"),
    metadata: text("metadata"),
    createdAt: text("createdAt").notNull(),
    updatedAt: text("updatedAt").notNull(),
  },
  (table) => [
    index("idx_artifacts_caseId").on(table.caseId),
    index("idx_artifacts_fingerprint").on(table.findingFingerprint),
    index("idx_artifacts_workItemId").on(table.workItemId),
  ]
);

export const triageMemories = sqliteTable(
  "triage_memories",
  {
    id: text("id").primaryKey(),
    scope: text("scope").notNull(), // global | target | package
    scopeValue: text("scope_value"),
    category: text("category").notNull(),
    pattern: text("pattern").notNull(),
    reasoning: text("reasoning").notNull(),
    createdAt: integer("created_at").notNull(),
    appliedCount: integer("applied_count").notNull().default(0),
  },
  (table) => [
    index("idx_memories_category").on(table.category, table.scope),
    index("idx_memories_scope").on(table.scope, table.scopeValue),
  ]
);

export const workers = sqliteTable(
  "workers",
  {
    id: text("id").primaryKey(),
    role: text("role").notNull().default("orchestrator"),
    status: text("status").notNull().default("idle"),
    label: text("label").notNull(),
    currentCaseId: text("currentCaseId"),
    currentWorkItemId: text("currentWorkItemId"),
    currentScanId: text("currentScanId"),
    pid: integer("pid"),
    host: text("host"),
    lastError: text("lastError"),
    heartbeatAt: text("heartbeatAt").notNull(),
    startedAt: text("startedAt").notNull(),
    updatedAt: text("updatedAt").notNull(),
  },
  (table) => [
    index("idx_workers_status").on(table.status),
    index("idx_workers_heartbeat").on(table.heartbeatAt),
  ]
);

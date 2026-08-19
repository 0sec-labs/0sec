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

// ── Persistent credential store (0sec#771, extends #687) ──
//
// Durable cross-scan home for the footholds the in-memory LootLedger
// (single-scan; core/src/agent/loot.ts) harvests. The `credentialKinds` mirror
// the LootLedger `LootKind` union so the two can sync without a lossy mapping.
// NOTE: never persist the plaintext secret — the store keys on a SHA-256
// `valueHash` and keeps only a short `valuePreview` for human/agent recognition.
export const credentialKinds = [
  "credential",
  "token",
  "path",
  "endpoint",
  "hash",
  "cookie",
] as const;
export type CredentialKindDB = (typeof credentialKinds)[number];

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
     * JSON-stringified LayerVerdict[] (see @0sec/shared types). NULL until
     * the triage stage runs. Stored as text rather than a join table because
     * the array is read-and-write together at finding-save time and we never
     * query individual verdict rows. See 0sec#112.
     */
    layerVerdicts: text("layerVerdicts"),
    /**
     * JSON-stringified PocStep[] (see @0sec/shared types). NULL when the
     * agent only produced prose evidence (the legacy default). Stored as
     * text rather than a join table because the array is read-and-write
     * together at finding-save time and we never query individual steps.
     * See 0sec#170.
     */
    pocSteps: text("pocSteps"),
    /**
     * JSON-stringified VerificationSpec (see @0sec/shared types). NULL
     * when the agent produced a finding without a deterministic re-check
     * contract — every reader must continue to work in that case. Stored
     * as text because the spec is an opaque blob that the verifier reads
     * whole; we never query individual predicates. See 0sec#193 /
     * 0sec-cloud#111.
     */
    verificationSpec: text("verificationSpec"),
    /**
     * JSON-stringified semantic-dedupe mapping assigned by the post-process
     * pass. NULL until that opt-in pass runs. Keeping this with the finding
     * preserves canonical anchors across later scans.
     */
    semanticDedupe: text("semanticDedupe"),
    /**
     * Per-scan post-process rank. NULL when incremental ranking did not run.
     */
    findingRank: integer("findingRank"),
    /**
     * JSON-stringified PocExecutionReport written when `disclose --target-url`
     * runs the step graph against a live target. NULL until that runs. See
     * 0sec#171.
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

// ── Persistent credentials (0sec#771) ──
//
// Durable, cross-scan store of discovered footholds keyed by
// (credentialKind, valueHash). A row is upserted the first time a value is
// seen; `timesSeen` / `lastSeenAt` and the attribution columns track WHERE it
// was discovered (which target / finding / scan / agent turn) so a later scan
// can reuse a credential harvested in an earlier one. The plaintext secret is
// NEVER stored — only its SHA-256 `valueHash` and a short `valuePreview`.
export const persistentCredentials = sqliteTable(
  "persistent_credentials",
  {
    id: text("id").primaryKey(),
    credentialKind: text("credentialKind").notNull(),
    /** SHA-256 hex of the normalized value. Half of the natural key. */
    valueHash: text("valueHash").notNull(),
    /** Short, redacted preview for recognition (e.g. `admin:hun…`). Not a secret. */
    valuePreview: text("valuePreview").notNull(),
    /** Optional short label the value sat behind (e.g. `password`, `jwt`). */
    context: text("context"),
    /** Target the value was first discovered against. */
    target: text("target"),
    /** Discovery attribution — first sighting. */
    firstScanId: text("firstScanId"),
    firstFindingId: text("firstFindingId"),
    firstSource: text("firstSource"),
    firstTurn: integer("firstTurn"),
    /** Most-recent sighting attribution. */
    lastScanId: text("lastScanId"),
    timesSeen: integer("timesSeen").notNull().default(1),
    firstSeenAt: text("firstSeenAt").notNull(),
    lastSeenAt: text("lastSeenAt").notNull(),
  },
  (table) => [
    index("idx_pcred_kind_hash").on(table.credentialKind, table.valueHash),
    index("idx_pcred_target").on(table.target),
    index("idx_pcred_kind").on(table.credentialKind),
  ]
);

// ── Trust graph edges (0sec#771) ──
//
// Directed edges describing how one node (a credential, target, finding, or
// host) grants reach to another — the substrate for "leaked here, reused
// there" exploit chains. Nodes are opaque `kind:id` strings so the table can
// reference persistent_credentials rows, targets, findings, etc. without a
// hard FK to any one of them. `relation` describes the edge (e.g.
// `authenticates_to`, `discovered_on`, `reused_on`).
export const trustGraphEdges = sqliteTable(
  "trust_graph_edges",
  {
    id: text("id").primaryKey(),
    srcKind: text("srcKind").notNull(),
    srcId: text("srcId").notNull(),
    dstKind: text("dstKind").notNull(),
    dstId: text("dstId").notNull(),
    relation: text("relation").notNull(),
    /** Optional attribution for when/where this edge was observed. */
    scanId: text("scanId"),
    findingId: text("findingId"),
    /** 0.0-1.0 confidence the edge is real. */
    confidence: real("confidence"),
    note: text("note"),
    createdAt: text("createdAt").notNull(),
    updatedAt: text("updatedAt").notNull(),
  },
  (table) => [
    index("idx_tge_src").on(table.srcKind, table.srcId),
    index("idx_tge_dst").on(table.dstKind, table.dstId),
    index("idx_tge_relation").on(table.relation),
  ]
);

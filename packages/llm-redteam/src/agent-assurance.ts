import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve, sep } from "node:path";
import {
  AGENT_ACTION_ASSURANCE_SCHEMA_VERSION,
  AgentActionEvidenceManifestSchema,
  AgentActionScenarioSchema,
  AgentActionTargetMetadataSchema,
  type AgentActionEvidenceManifest,
  type AgentActionOutcome,
  type AgentActionScenario,
  type AgentActionTargetMetadata,
} from "@0sec/shared";
import { isRecord } from "./guards.js";


/** Version of the narrow HTTP contract a customer-owned agent test adapter implements. */
export const AGENT_ACTION_TARGET_PROTOCOL_VERSION = "0sec.agent-action-target/v1" as const;

const DEFAULT_HTTP_TIMEOUT_MS = 30_000;
const DEFAULT_ORACLE_TIMEOUT_MS = 10_000;
const DEFAULT_ORACLE_POLL_MS = 250;
const SENSITIVE_KEY = /(?:authorization|api[-_]?key|cookie|password|secret|token|credential)/i;
const INLINE_SECRET = /\b(?:bearer\s+|basic\s+|api[_-]?key[=:]\s*|token[=:]\s*|password[=:]\s*|cookie[=:]\s*)[^\s,;"']+/gi;

export interface AgentActionToolCall {
  name: string;
  args: unknown;
}

/** A target adapter executes a customer-defined agent test envelope. */
export interface AgentActionTarget {
  name: string;
  execute(input: AgentActionInvocation): Promise<AgentActionExecution>;
}

/** The agent adapter must preserve what it sent and received so the bundle can bind them by hash. */
export interface AgentActionExecution {
  request: unknown;
  response: unknown;
  transcript: string;
  toolCalls: AgentActionToolCall[];
  mcpTools: unknown[];
}

export interface AgentActionInvocation {
  runId: string;
  canaryToken: string;
  scenario: AgentActionScenario;
}

/** A state oracle, not a model response, determines whether the prohibited action occurred. */
export interface AgentActionOracle {
  name: string;
  observe(input: AgentActionInvocation): Promise<AgentActionObservation>;
}

export interface AgentActionObservation {
  observed: boolean;
  complete: boolean;
  observedAt?: string;
  summary?: string;
  raw: unknown;
}

export interface AgentActionTargetConfig {
  scopeSha256: string;
  environment: "local" | "test" | "staging";
  agentEndpoint: string;
  mcpEndpoint: string;
  oracleEndpoint: string;
  targetVersion: string;
  policyVersion: string;
  modelVersion: string;
  toolVersions: Record<string, string>;
}

export interface AgentActionRetestReference {
  previousRunId: string;
  previousManifestSha256: string;
  previousConfigurationSha256: string;
}

export interface AgentActionRunOptions {
  target: AgentActionTarget;
  oracle: AgentActionOracle;
  scenario: AgentActionScenario;
  targetConfig: AgentActionTargetConfig;
  retestOf?: AgentActionRetestReference;
  now?: () => Date;
  runId?: string;
  canaryToken?: string;
}

export interface AgentActionRun {
  manifest: AgentActionEvidenceManifest;
  execution: AgentActionExecution;
  observation: AgentActionObservation;
  canaryToken: string;
}

export interface McpAgentTargetOptions {
  agentEndpoint: string;
  mcpEndpoint: string;
  agentHeaders?: Record<string, string>;
  mcpHeaders?: Record<string, string>;
  model?: string;
  name?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export interface HttpActionOracleOptions {
  endpoint: string;
  headers?: Record<string, string>;
  name?: string;
  timeoutMs?: number;
  pollIntervalMs?: number;
  pollTimeoutMs?: number;
  fetchImpl?: typeof fetch;
  wait?: (milliseconds: number) => Promise<void>;
}

export interface AgentActionEvidenceBundle {
  directory: string;
  manifestPath: string;
  manifest: AgentActionEvidenceManifest;
  artifactPaths: string[];
}


function normalizeForHash(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => normalizeForHash(entry));
  }
  if (isRecord(value)) {
    const normalized: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      if (value[key] !== undefined) normalized[key] = normalizeForHash(value[key]);
    }
    return normalized;
  }
  return String(value);
}

function hashValue(value: unknown): string {
  const serialized = typeof value === "string"
    ? value
    : JSON.stringify(normalizeForHash(value)) ?? "null";
  return createHash("sha256").update(serialized).digest("hex");
}

function ensureHttpEndpoint(value: string, field: string): string {
  const parsed = new URL(value);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`${field} must use http or https`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${field} must not embed credentials`);
  }
  return parsed.toString();
}

function positiveMilliseconds(value: number | undefined, fallback: number, field: string): number {
  if (value === undefined) return fallback;
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${field} must be a positive number of milliseconds`);
  }
  return Math.floor(value);
}

async function postJson(
  endpoint: string,
  payload: unknown,
  headers: Record<string, string>,
  timeoutMs: number,
  fetchImpl: typeof fetch,
): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        ...headers,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    const text = await response.text();
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} from ${endpoint}: ${text.slice(0, 400)}`);
    }
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new Error(`Expected JSON response from ${endpoint}`);
    }
  } finally {
    clearTimeout(timer);
  }
}

function extractMcpTools(value: unknown): unknown[] {
  if (!isRecord(value) || !isRecord(value.result) || !Array.isArray(value.result.tools)) {
    throw new Error("MCP tools/list response did not contain result.tools");
  }
  return value.result.tools;
}

function parseAgentExecutionResponse(value: unknown): {
  transcript: string;
  toolCalls: AgentActionToolCall[];
} {
  if (!isRecord(value) || typeof value.transcript !== "string") {
    throw new Error("agent endpoint response must contain a string transcript");
  }

  const toolCalls: AgentActionToolCall[] = [];
  if (value.tool_calls !== undefined) {
    if (!Array.isArray(value.tool_calls)) {
      throw new Error("agent endpoint tool_calls must be an array when supplied");
    }
    for (const call of value.tool_calls) {
      if (!isRecord(call) || typeof call.name !== "string" || call.name.length === 0) {
        throw new Error("each agent endpoint tool_call must contain a non-empty name");
      }
      toolCalls.push({ name: call.name, args: call.args ?? {} });
    }
  }
  return { transcript: value.transcript, toolCalls };
}

function parseOracleObservation(value: unknown): AgentActionObservation {
  if (!isRecord(value) || typeof value.observed !== "boolean" || typeof value.complete !== "boolean") {
    throw new Error("action oracle response must contain boolean observed and complete fields");
  }
  let observedAt: string | undefined;
  if (typeof value.observed_at === "string") {
    const timestamp = new Date(value.observed_at);
    if (!Number.isNaN(timestamp.valueOf())) observedAt = timestamp.toISOString();
  }
  return {
    observed: value.observed,
    complete: value.complete,
    observedAt,
    summary: typeof value.summary === "string" ? value.summary : undefined,
    raw: value,
  };
}

function defaultWait(milliseconds: number): Promise<void> {
  const { promise, resolve } = Promise.withResolvers<void>();
  setTimeout(resolve, milliseconds);
  return promise;
}

function createTargetMetadata(config: AgentActionTargetConfig): AgentActionTargetMetadata {
  const metadata = {
    scope_sha256: config.scopeSha256,
    environment: config.environment,
    agent_endpoint: ensureHttpEndpoint(config.agentEndpoint, "agentEndpoint"),
    mcp_endpoint: ensureHttpEndpoint(config.mcpEndpoint, "mcpEndpoint"),
    oracle_endpoint: ensureHttpEndpoint(config.oracleEndpoint, "oracleEndpoint"),
    target_version: config.targetVersion,
    policy_version: config.policyVersion,
    model_version: config.modelVersion,
    tool_versions: config.toolVersions,
  };
  return AgentActionTargetMetadataSchema.parse({
    ...metadata,
    configuration_sha256: hashValue(metadata),
  });
}

function outcomeFromObservation(observation: AgentActionObservation): AgentActionOutcome {
  if (!observation.complete) return "inconclusive";
  return observation.observed ? "observed" : "not_observed";
}

function redactedText(value: string, canaryToken: string, redactedFields: Set<string>): string {
  let redacted = value;
  if (canaryToken.length > 0 && redacted.includes(canaryToken)) {
    redacted = redacted.replaceAll(canaryToken, "[REDACTED_CANARY]");
    redactedFields.add("canary_token");
  }
  const withoutInlineSecrets = redacted.replace(INLINE_SECRET, "[REDACTED_SECRET]");
  if (withoutInlineSecrets !== redacted) {
    redacted = withoutInlineSecrets;
    redactedFields.add("inline_secret");
  }
  return redacted;
}

function redactEvidence(value: unknown, canaryToken: string, redactedFields: Set<string>): unknown {
  if (typeof value === "string") return redactedText(value, canaryToken, redactedFields);
  if (Array.isArray(value)) {
    return value.map((entry) => redactEvidence(entry, canaryToken, redactedFields));
  }
  if (isRecord(value)) {
    const redacted: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      if (SENSITIVE_KEY.test(key)) {
        redacted[key] = "[REDACTED]";
        redactedFields.add(key.toLowerCase());
      } else {
        redacted[key] = redactEvidence(entry, canaryToken, redactedFields);
      }
    }
    return redacted;
  }
  return value;
}

function ensureBundlePath(directory: string, relativePath: string): string {
  const destination = resolve(directory, relativePath);
  if (destination !== directory && !destination.startsWith(`${directory}${sep}`)) {
    throw new Error(`evidence artifact path escapes output directory: ${relativePath}`);
  }
  return destination;
}

async function writeArtifact(
  directory: string,
  relativePath: string,
  kind: string,
  value: unknown,
): Promise<{ kind: string; path: string; sha256: string; bytes: number; absolutePath: string }> {
  const absolutePath = ensureBundlePath(directory, relativePath);
  const content = typeof value === "string"
    ? value
    : `${JSON.stringify(normalizeForHash(value), null, 2)}\n`;
  await mkdir(dirname(absolutePath), { recursive: true });
  await writeFile(absolutePath, content, "utf8");
  return {
    kind,
    path: relativePath,
    sha256: hashValue(content),
    bytes: Buffer.byteLength(content),
    absolutePath,
  };
}

/**
 * MCP-aware adapter for a customer-owned agent test endpoint. It inventories the
 * actual MCP tool surface first, then sends that inventory and one untrusted
 * payload to an explicit test adapter; it never treats model text as proof.
 */
export function mcpAgentTarget(options: McpAgentTargetOptions): AgentActionTarget {
  const agentEndpoint = ensureHttpEndpoint(options.agentEndpoint, "agentEndpoint");
  const mcpEndpoint = ensureHttpEndpoint(options.mcpEndpoint, "mcpEndpoint");
  const timeoutMs = positiveMilliseconds(options.timeoutMs, DEFAULT_HTTP_TIMEOUT_MS, "timeoutMs");
  const fetchImpl = options.fetchImpl ?? fetch;

  return {
    name: options.name ?? "mcp-agent",
    async execute(input: AgentActionInvocation): Promise<AgentActionExecution> {
      const toolsRequest = {
        jsonrpc: "2.0",
        id: input.runId,
        method: "tools/list",
      };
      const toolsResponse = await postJson(
        mcpEndpoint,
        toolsRequest,
        options.mcpHeaders ?? {},
        timeoutMs,
        fetchImpl,
      );
      const tools = extractMcpTools(toolsResponse);
      const request = {
        protocol_version: AGENT_ACTION_TARGET_PROTOCOL_VERSION,
        run_id: input.runId,
        canary_token: input.canaryToken,
        model: options.model,
        scenario: input.scenario,
        mcp: {
          endpoint: mcpEndpoint,
          tools,
        },
      };
      const response = await postJson(
        agentEndpoint,
        request,
        options.agentHeaders ?? {},
        timeoutMs,
        fetchImpl,
      );
      const parsed = parseAgentExecutionResponse(response);
      return {
        request,
        response,
        transcript: parsed.transcript,
        toolCalls: parsed.toolCalls,
        mcpTools: tools,
      };
    },
  };
}

/**
 * Poll a customer-owned state observer. A safe outcome is issued only when the
 * observer marks its observation complete and confirms the prohibited action did
 * not occur.
 */
export function httpActionOracle(options: HttpActionOracleOptions): AgentActionOracle {
  const endpoint = ensureHttpEndpoint(options.endpoint, "oracleEndpoint");
  const timeoutMs = positiveMilliseconds(options.timeoutMs, DEFAULT_HTTP_TIMEOUT_MS, "timeoutMs");
  const pollIntervalMs = positiveMilliseconds(options.pollIntervalMs, DEFAULT_ORACLE_POLL_MS, "pollIntervalMs");
  const pollTimeoutMs = positiveMilliseconds(options.pollTimeoutMs, DEFAULT_ORACLE_TIMEOUT_MS, "pollTimeoutMs");
  const fetchImpl = options.fetchImpl ?? fetch;
  const wait = options.wait ?? defaultWait;

  return {
    name: options.name ?? "http-action-oracle",
    async observe(input: AgentActionInvocation): Promise<AgentActionObservation> {
      const deadline = Date.now() + pollTimeoutMs;
      let lastObservation: AgentActionObservation | undefined;
      while (Date.now() <= deadline) {
        const response = await postJson(
          endpoint,
          {
            protocol_version: AGENT_ACTION_TARGET_PROTOCOL_VERSION,
            run_id: input.runId,
            canary_token: input.canaryToken,
            scenario_id: input.scenario.id,
          },
          options.headers ?? {},
          timeoutMs,
          fetchImpl,
        );
        const observation = parseOracleObservation(response);
        if (observation.complete) return observation;
        lastObservation = observation;
        if (Date.now() + pollIntervalMs > deadline) break;
        await wait(pollIntervalMs);
      }
      return {
        observed: lastObservation?.observed ?? false,
        complete: false,
        summary: lastObservation?.summary ?? "action oracle did not complete before its deadline",
        raw: lastObservation?.raw ?? { error: "action oracle timed out" },
      };
    },
  };
}

/**
 * Run one deterministic prohibited-action assertion. The action oracle, rather
 * than the agent transcript, determines the outcome and is bound into a manifest
 * suitable for a later retest.
 */
export async function runAgentActionAssurance(options: AgentActionRunOptions): Promise<AgentActionRun> {
  const scenario = AgentActionScenarioSchema.parse(options.scenario);
  const target = createTargetMetadata(options.targetConfig);
  const runId = options.runId ?? randomUUID();
  const canaryToken = options.canaryToken ?? randomBytes(24).toString("base64url");
  const invocation: AgentActionInvocation = { runId, canaryToken, scenario };

  let execution: AgentActionExecution = {
    request: { protocol_version: AGENT_ACTION_TARGET_PROTOCOL_VERSION, run_id: runId },
    response: {},
    transcript: "",
    toolCalls: [],
    mcpTools: [],
  };
  let observation: AgentActionObservation;
  let outcome: AgentActionOutcome;

  try {
    execution = await options.target.execute(invocation);
    try {
      observation = await options.oracle.observe(invocation);
      outcome = outcomeFromObservation(observation);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      observation = {
        observed: false,
        complete: false,
        summary: message,
        raw: { error: message },
      };
      outcome = "error";
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    execution = {
      request: execution.request,
      response: { error: message },
      transcript: "",
      toolCalls: [],
      mcpTools: [],
    };
    observation = {
      observed: false,
      complete: false,
      summary: message,
      raw: { error: message },
    };
    outcome = "error";
  }

  const retest = options.retestOf
    ? {
        previous_run_id: options.retestOf.previousRunId,
        previous_manifest_sha256: options.retestOf.previousManifestSha256,
        configuration_changed: options.retestOf.previousConfigurationSha256 !== target.configuration_sha256,
      }
    : undefined;

  const manifestRedactedFields = new Set<string>();

  const manifest = AgentActionEvidenceManifestSchema.parse({
    schema_version: AGENT_ACTION_ASSURANCE_SCHEMA_VERSION,
    run_id: runId,
    created_at: options.now ? options.now().toISOString() : new Date().toISOString(),
    target,
    scenario: {
      id: scenario.id,
      title: scenario.title,
      injection_vector: scenario.injection_vector,
      payload_sha256: hashValue(scenario.payload),
      prohibited_action: scenario.prohibited_action,
    },
    execution: {
      request_sha256: hashValue(execution.request),
      response_sha256: hashValue(execution.response),
      transcript_sha256: hashValue(execution.transcript),
      mcp_tools_sha256: hashValue(execution.mcpTools),
      tool_calls: execution.toolCalls.map((call) => ({
        name: call.name,
        args_sha256: hashValue(call.args),
      })),
    },
    oracle: {
      name: options.oracle.name,
      outcome,
      complete: observation.complete,
      observation_sha256: hashValue(observation.raw),
      ...(observation.observedAt ? { observed_at: observation.observedAt } : {}),
      ...(observation.summary ? { summary: redactedText(observation.summary, canaryToken, manifestRedactedFields) } : {}),
    },
    redaction: {
      strategy: "sensitive-text-v1",
      redacted_fields: [...manifestRedactedFields].sort(),
      raw_artifacts: false,
    },
    ...(retest ? { retest } : {}),
    artifacts: [],
  });

  return { manifest, execution, observation, canaryToken };
}

/** Compare a prior result to the current tested configuration before scheduling a retest. */
export function agentActionConfigurationChanges(
  baseline: AgentActionEvidenceManifest,
  target: AgentActionTargetMetadata,
): string[] {
  const changes: string[] = [];
  if (baseline.target.environment !== target.environment) changes.push("environment");
  if (baseline.target.target_version !== target.target_version) changes.push("target_version");
  if (baseline.target.policy_version !== target.policy_version) changes.push("policy_version");
  if (baseline.target.model_version !== target.model_version) changes.push("model_version");
  if (baseline.target.configuration_sha256 !== target.configuration_sha256) {
    if (hashValue(baseline.target.tool_versions) !== hashValue(target.tool_versions)) {
      changes.push("tool_versions");
    }
    if (baseline.target.scope_sha256 !== target.scope_sha256) changes.push("scope");
    if (baseline.target.agent_endpoint !== target.agent_endpoint) changes.push("agent_endpoint");
    if (baseline.target.mcp_endpoint !== target.mcp_endpoint) changes.push("mcp_endpoint");
    if (baseline.target.oracle_endpoint !== target.oracle_endpoint) changes.push("oracle_endpoint");
  }
  return changes;
}

/** Write a redacted, hash-addressed evidence bundle. The manifest intentionally excludes raw bytes. */
export async function writeAgentActionEvidenceBundle(
  run: AgentActionRun,
  outputDirectory: string,
): Promise<AgentActionEvidenceBundle> {
  const directory = resolve(outputDirectory);
  await mkdir(directory, { recursive: true });
  const redactedFields = new Set<string>();
  const [
    requestArtifact,
    responseArtifact,
    transcriptArtifact,
    mcpToolsArtifact,
    oracleArtifact,
  ] = await Promise.all([
    writeArtifact(
      directory,
      "artifacts/request.json",
      "agent-request",
      redactEvidence(run.execution.request, run.canaryToken, redactedFields),
    ),
    writeArtifact(
      directory,
      "artifacts/response.json",
      "agent-response",
      redactEvidence(run.execution.response, run.canaryToken, redactedFields),
    ),
    writeArtifact(
      directory,
      "artifacts/transcript.txt",
      "agent-transcript",
      redactedText(run.execution.transcript, run.canaryToken, redactedFields),
    ),
    writeArtifact(
      directory,
      "artifacts/mcp-tools.json",
      "mcp-tool-inventory",
      redactEvidence(run.execution.mcpTools, run.canaryToken, redactedFields),
    ),
    writeArtifact(
      directory,
      "artifacts/oracle.json",
      "action-oracle-observation",
      redactEvidence(run.observation.raw, run.canaryToken, redactedFields),
    ),
  ]);
  const artifactRows = [
    requestArtifact,
    responseArtifact,
    transcriptArtifact,
    mcpToolsArtifact,
    oracleArtifact,
  ];
  const manifest = AgentActionEvidenceManifestSchema.parse({
    ...run.manifest,
    execution: {
      ...run.manifest.execution,
      request_sha256: requestArtifact.sha256,
      response_sha256: responseArtifact.sha256,
      transcript_sha256: transcriptArtifact.sha256,
      mcp_tools_sha256: mcpToolsArtifact.sha256,
    },
    oracle: {
      ...run.manifest.oracle,
      observation_sha256: oracleArtifact.sha256,
    },
    redaction: {
      ...run.manifest.redaction,
      redacted_fields: [...new Set([
        ...run.manifest.redaction.redacted_fields,
        ...redactedFields,
      ])].sort(),
    },
    artifacts: artifactRows.map(({ absolutePath: _absolutePath, ...artifact }) => artifact),
  });
  const manifestPath = ensureBundlePath(directory, "manifest.json");
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  return {
    directory,
    manifestPath,
    manifest,
    artifactPaths: artifactRows.map((artifact) => artifact.absolutePath),
  };
}

/** Compute the digest from raw manifest bytes before using it as a retest parent. */
export function agentActionManifestSha256(rawManifest: string | Buffer): string {
  return createHash("sha256").update(rawManifest).digest("hex");
}

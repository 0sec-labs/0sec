import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import type { Command } from "commander";
import { loadScope, type ScopePolicy } from "@0sec/core";
import {
  AgentActionScenarioSchema,
  parseAgentActionEvidenceManifest,
  type AgentActionEvidenceManifest,
  type AgentActionScenario,
} from "@0sec/shared";
import {
  agentActionConfigurationChanges,
  agentActionManifestSha256,
  httpActionOracle,
  mcpAgentTarget,
  runAgentActionAssurance,
  writeAgentActionEvidenceBundle,
} from "@0sec/llm-redteam";

interface AgentAssureOptions {
  agentEndpoint: string;
  mcpEndpoint: string;
  oracleEndpoint: string;
  scenario: string;
  scope: string;
  output?: string;
  baseline?: string;
  environment: "local" | "test" | "staging";
  targetVersion: string;
  policyVersion: string;
  modelVersion: string;
  toolVersion: string[];
  agentHeaders?: string;
  mcpHeaders?: string;
  oracleHeaders?: string;
  model?: string;
  timeout: string;
  oracleTimeout: string;
}

interface LoadedAgentAssureBaseline {
  manifest: AgentActionEvidenceManifest;
  sha256: string;
}

function readScenario(path: string): AgentActionScenario {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`agent-assure: failed to read scenario ${path}: ${message}`);
  }
  return AgentActionScenarioSchema.parse(raw);
}

function readHeaders(path: string | undefined, field: string): Record<string, string> {
  if (!path) return {};
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`agent-assure: failed to read ${field} file ${path}: ${message}`);
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`agent-assure: ${field} must be a JSON object of string headers`);
  }
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(raw)) {
    if (typeof value !== "string" || name.trim().length === 0) {
      throw new Error(`agent-assure: ${field} must contain non-empty string header names and string values`);
    }
    headers[name] = value;
  }
  return headers;
}

function parseToolVersions(entries: string[]): Record<string, string> {
  const versions: Record<string, string> = {};
  for (const entry of entries) {
    const delimiter = entry.indexOf("=");
    if (delimiter <= 0 || delimiter === entry.length - 1) {
      throw new Error(`agent-assure: --tool-version must be name=version (got '${entry}')`);
    }
    const name = entry.slice(0, delimiter).trim();
    const version = entry.slice(delimiter + 1).trim();
    if (name.length === 0 || version.length === 0 || Object.hasOwn(versions, name)) {
      throw new Error(`agent-assure: --tool-version names must be unique non-empty name=version pairs`);
    }
    versions[name] = version;
  }
  return versions;
}

function parsePositiveMilliseconds(raw: string, field: string): number {
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`agent-assure: ${field} must be a positive integer in milliseconds`);
  }
  return value;
}

function assertInScope(scope: ScopePolicy, endpoint: string, label: string): void {
  const match = scope.match(endpoint);
  if (!match.allowed) {
    throw new Error(`agent-assure: ${label} is ${match.reason}`);
  }
}

function readBaseline(path: string): LoadedAgentAssureBaseline {
  const raw = readFileSync(path, "utf8");
  return {
    manifest: parseAgentActionEvidenceManifest(JSON.parse(raw) as unknown),
    sha256: agentActionManifestSha256(raw),
  };
}

/** Register the explicit, scope-bound agent-action test command. */
export function registerAgentAssureCommand(program: Command): void {
  program
    .command("agent-assure")
    .description("Test whether untrusted MCP content causes a prohibited action in an authorized agent environment")
    .requiredOption("--agent-endpoint <url>", "Customer-owned agent test adapter endpoint (HTTP JSON contract)")
    .requiredOption("--mcp-endpoint <url>", "Authorized MCP tools/list endpoint")
    .requiredOption("--oracle-endpoint <url>", "Customer-owned state-observer endpoint")
    .requiredOption("--scenario <path>", "Scenario JSON: id, title, injection_vector, benign_task, payload, prohibited_action")
    .requiredOption("--scope <path>", "Engagement scope JSON; all three endpoints must be in scope")
    .requiredOption("--target-version <version>", "Version or build digest of the tested agent deployment")
    .requiredOption("--policy-version <version>", "Version or digest of the agent prompt and authorization policy")
    .requiredOption("--model-version <version>", "Model deployment/version identifier")
    .option("--tool-version <name=version>", "Version of an MCP tool; repeatable", (value: string, previous: string[] = []) => [...previous, value], [])
    .option("--environment <name>", "local, test, or staging", "staging")
    .option("-m, --model <name>", "Optional model identifier passed to the customer agent adapter")
    .option("--agent-headers <path>", "JSON file of headers for the agent adapter; never written to evidence")
    .option("--mcp-headers <path>", "JSON file of headers for the MCP endpoint; never written to evidence")
    .option("--oracle-headers <path>", "JSON file of headers for the state observer; never written to evidence")
    .option("--timeout <ms>", "Per-request timeout in milliseconds", "30000")
    .option("--oracle-timeout <ms>", "Maximum state-observer wait in milliseconds", "10000")
    .option("--baseline <manifest>", "Prior manifest to bind as a retest parent")
    .option("--output <directory>", "Evidence bundle directory; defaults to agent-assurance-<run-id>")
    .action(async (opts: AgentAssureOptions) => {
      const scenario = readScenario(opts.scenario);
      if (!(["local", "test", "staging"] as const).includes(opts.environment)) {
        throw new Error("agent-assure: --environment must be local, test, or staging");
      }
      const scope = loadScope(opts.scope);
      assertInScope(scope, opts.agentEndpoint, "agent endpoint");
      assertInScope(scope, opts.mcpEndpoint, "MCP endpoint");
      assertInScope(scope, opts.oracleEndpoint, "oracle endpoint");

      const baseline = opts.baseline ? readBaseline(opts.baseline) : undefined;
      const scenarioPayloadSha256 = createHash("sha256").update(scenario.payload).digest("hex");
      if (baseline && (
        baseline.manifest.scenario.id !== scenario.id
        || baseline.manifest.scenario.payload_sha256 !== scenarioPayloadSha256
      )) {
        throw new Error("agent-assure: --baseline must describe the same scenario id and payload");
      }

      const scopeRaw = readFileSync(opts.scope, "utf8");
      const timeoutMs = parsePositiveMilliseconds(opts.timeout, "--timeout");
      const oracleTimeoutMs = parsePositiveMilliseconds(opts.oracleTimeout, "--oracle-timeout");
      const run = await runAgentActionAssurance({
        target: mcpAgentTarget({
          agentEndpoint: opts.agentEndpoint,
          mcpEndpoint: opts.mcpEndpoint,
          agentHeaders: readHeaders(opts.agentHeaders, "--agent-headers"),
          mcpHeaders: readHeaders(opts.mcpHeaders, "--mcp-headers"),
          model: opts.model,
          timeoutMs,
        }),
        oracle: httpActionOracle({
          endpoint: opts.oracleEndpoint,
          headers: readHeaders(opts.oracleHeaders, "--oracle-headers"),
          timeoutMs,
          pollTimeoutMs: oracleTimeoutMs,
        }),
        scenario,
        targetConfig: {
          scopeSha256: createHash("sha256").update(scopeRaw).digest("hex"),
          environment: opts.environment,
          agentEndpoint: opts.agentEndpoint,
          mcpEndpoint: opts.mcpEndpoint,
          oracleEndpoint: opts.oracleEndpoint,
          targetVersion: opts.targetVersion,
          policyVersion: opts.policyVersion,
          modelVersion: opts.modelVersion,
          toolVersions: parseToolVersions(opts.toolVersion),
        },
        ...(baseline
          ? {
              retestOf: {
                previousRunId: baseline.manifest.run_id,
                previousManifestSha256: baseline.sha256,
                previousConfigurationSha256: baseline.manifest.target.configuration_sha256,
              },
            }
          : {}),
      });
      const bundle = await writeAgentActionEvidenceBundle(
        run,
        opts.output ?? `agent-assurance-${run.manifest.run_id}`,
      );
      const configurationChanges = baseline
        ? agentActionConfigurationChanges(baseline.manifest, bundle.manifest.target)
        : [];
      process.stdout.write(`${JSON.stringify({
        run_id: bundle.manifest.run_id,
        outcome: bundle.manifest.oracle.outcome,
        complete: bundle.manifest.oracle.complete,
        evidence_manifest: bundle.manifestPath,
        configuration_changes: configurationChanges,
      })}\n`);

      const exitCodes: Record<string, number> = {
        observed: 1,
        not_observed: 0,
        inconclusive: 2,
        error: 2,
      };
      process.exitCode = exitCodes[bundle.manifest.oracle.outcome];
    });
}

import { describe, expect, it } from "vitest";
import {
  AGENT_ACTION_ASSURANCE_SCHEMA_VERSION,
  AgentActionEvidenceManifestSchema,
  type AgentActionEvidenceManifest,
} from "./agent-assurance.js";

const sha = (char: string) => char.repeat(64);

function validManifest(): AgentActionEvidenceManifest {
  return {
    schema_version: AGENT_ACTION_ASSURANCE_SCHEMA_VERSION,
    run_id: "92f2765f-6a2e-4c7a-a4d8-32ba7a131ec3",
    created_at: "2026-08-20T12:00:00.000Z",
    target: {
      scope_sha256: sha("a"),
      environment: "staging",
      agent_endpoint: "https://agent.example.test/execute",
      mcp_endpoint: "https://mcp.example.test/mcp",
      oracle_endpoint: "https://oracle.example.test/observe",
      target_version: "build-42",
      policy_version: "policy-7",
      model_version: "model-2026-08-20",
      tool_versions: { invoices: "v3" },
      configuration_sha256: sha("b"),
    },
    scenario: {
      id: "mcp-tool-poisoning",
      title: "Poisoned invoice enrichment tool",
      injection_vector: "tool-output",
      payload_sha256: sha("c"),
      prohibited_action: "Export seeded invoice data to an external destination",
    },
    execution: {
      request_sha256: sha("d"),
      response_sha256: sha("e"),
      transcript_sha256: sha("f"),
      mcp_tools_sha256: sha("0"),
      tool_calls: [{ name: "invoice_lookup", args_sha256: sha("1") }],
    },
    oracle: {
      name: "seeded-egress-observer",
      outcome: "not_observed",
      complete: true,
      observation_sha256: sha("2"),
      observed_at: "2026-08-20T12:00:02.000Z",
    },
    redaction: {
      strategy: "sensitive-text-v1",
      redacted_fields: ["authorization", "canary_token"],
      raw_artifacts: false,
    },
    artifacts: [{
      kind: "agent-response",
      path: "artifacts/response.json",
      sha256: sha("3"),
      bytes: 512,
    }],
  };
}

describe("AgentActionEvidenceManifestSchema", () => {
  it("round-trips a complete, redacted action-assurance result", () => {
    const input = validManifest();
    const parsed = AgentActionEvidenceManifestSchema.parse(JSON.parse(JSON.stringify(input)));
    expect(parsed).toEqual(input);
  });

  it("refuses a conclusive outcome without a complete action-oracle observation", () => {
    const manifest = validManifest();
    manifest.oracle = { ...manifest.oracle, outcome: "observed", complete: false };
    expect(() => AgentActionEvidenceManifestSchema.parse(manifest)).toThrow(/complete action-oracle/);
  });

  it("refuses credentials and escaping paths in customer-facing evidence", () => {
    const credentials = validManifest();
    credentials.target = {
      ...credentials.target,
      agent_endpoint: "https://operator:secret@agent.example.test/execute",
    };
    expect(() => AgentActionEvidenceManifestSchema.parse(credentials)).toThrow(/must not embed credentials/);

    const escaping = validManifest();
    escaping.artifacts = [{ ...escaping.artifacts[0]!, path: "../raw-response.json" }];
    expect(() => AgentActionEvidenceManifestSchema.parse(escaping)).toThrow(/must be relative/);
  });
});

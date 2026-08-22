/**
 * Tool registry barrel (0sec#611).
 *
 * Assembles the canonical `TOOL_DEFINITIONS` map from the per-domain
 * definition modules. Splitting the old 600-line object literal into
 * per-domain files lets parallel feature PRs (scanner #585, WAF #590,
 * access-control #586, …) edit disjoint files instead of all serializing on
 * one merge-conflict chokepoint.
 *
 * `agent/tools.ts` imports + re-exports `TOOL_DEFINITIONS` and
 * `SCANNER_TOOL_NAMES` from here, so every existing `./tools.js` importer is
 * unaffected.
 */
import type { ToolDefinition } from "../types.js";
import { reconToolDefinitions } from "./recon.js";
import { findingsToolDefinitions } from "./findings.js";
import { systemToolDefinitions } from "./system.js";
import { accessControlToolDefinitions } from "./access-control.js";
import { exploitToolDefinitions } from "./exploit.js";
import { intelToolDefinitions } from "./intel.js";
import { skillsToolDefinitions } from "./skills.js";
import { scannerToolDefinitions, SCANNER_TOOL_NAMES } from "./scanner.js";
import { detectionToolDefinitions } from "./detections.js";
import { cloudToolDefinitions, CLOUD_TOOL_NAMES } from "./cloud.js";
import {
  orchestratorToolDefinitions,
  ORCHESTRATOR_TOOL_NAMES,
} from "./orchestrator.js";
import { oastToolDefinitions, OAST_TOOL_NAMES } from "./oast.js";
import { pythonToolDefinitions } from "./python.js";
import { binaryToolDefinitions, BINARY_TOOL_NAMES } from "./binary.js";

export {
  SCANNER_TOOL_NAMES,
  CLOUD_TOOL_NAMES,
  ORCHESTRATOR_TOOL_NAMES,
  OAST_TOOL_NAMES,
  BINARY_TOOL_NAMES,
};

// Every per-domain definition map, merged. Key collisions are impossible —
// each tool name is owned by exactly one domain module.
const DOMAIN_DEFINITIONS: Record<string, ToolDefinition> = {
  ...reconToolDefinitions,
  ...findingsToolDefinitions,
  ...systemToolDefinitions,
  ...accessControlToolDefinitions,
  ...exploitToolDefinitions,
  ...intelToolDefinitions,
  ...skillsToolDefinitions,
  ...scannerToolDefinitions,
  ...detectionToolDefinitions,
  ...cloudToolDefinitions,
  ...orchestratorToolDefinitions,
  ...oastToolDefinitions,
  ...pythonToolDefinitions,
  ...binaryToolDefinitions,
};

// Canonical registry order. getToolsForRole("audit"/"review") enumerates
// Object.keys(TOOL_DEFINITIONS), so keep additions deliberate and deterministic.
const TOOL_REGISTRY_ORDER = [
  "http_request",
  "send_prompt",
  "save_finding",
  "query_findings",
  "use_loot",
  "plan",
  "update_finding",
  "read_file",
  "list_files",
  "search_files",
  "apply_patch",
  "run_command",
  "update_target",
  "crawl",
  "submit_form",
  "access_control_probe",
  "bash",
  "browser",
  "spawn_agent",
  "spawn_agents",
  "web_search",
  "intel_search_advisories",
  "intel_lookup_cve",
  "intel_search_similar",
  "intel_build_dossier",
  "intel_search_target_history",
  "payload_lookup",
  "pty_session",
  "wp_fingerprint",
  "discover_api_surface",
  "surface_sweep",
  "js_recon",
  "mongo_objectid",
  "list_skills",
  "load_skill",
  "done",
  "run_sqlmap",
  "run_nmap",
  "run_ffuf",
  "run_nuclei",
  "structural_sqli_probe",
  "prompt_layer_probe",
  "auth_boundary_probe",
  "cloud_s3_probe",
  "cloud_validate_credentials",
  "start_scan",
  "oast_register",
  "oast_poll",
  "python_exec",
  "analyze_binary",
] as const;

export const TOOL_DEFINITIONS: Record<string, ToolDefinition> = Object.fromEntries(
  TOOL_REGISTRY_ORDER.map((name): [string, ToolDefinition] => [name, DOMAIN_DEFINITIONS[name]]),
);

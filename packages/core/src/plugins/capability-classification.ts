import type { PluginCapability } from "./manifest.js";

/** Shared built-in gate tables. Session contributions extend copies, never these defaults. */
export const NETWORK_CAPABLE_TOOLS: Readonly<Record<string, true>> = Object.freeze({
  http_request: true,
  send_prompt: true,
  crawl: true,
  submit_form: true,
  access_control_probe: true,
  access_control_workflow: true,
  browser: true,
  wp_fingerprint: true,
  discover_api_surface: true,
  surface_sweep: true,
  js_recon: true,
  bash: true,
  run_command: true,
  pty_session: true,
  python_exec: true,
  spawn_agent: true,
  spawn_agents: true,
  spawn_persistent_agent: true,
  monitor: true,
  run_scanner: true,
  structural_sqli_probe: true,
  prompt_layer_probe: true,
  auth_boundary_probe: true,
  cloud_s3_probe: true,
  cloud_validate_credentials: true,
  start_scan: true,
  oast_register: true,
  oast_poll: true,
});

/** Copilot-exempt reads and authority-free session bookkeeping. */
export const READ_ONLY_TOOLS: Readonly<Record<string, true>> = Object.freeze({
  read_file: true,
  search_files: true,
  list_files: true,
  query_findings: true,
  list_skills: true,
  load_skill: true,
  intel_search_advisories: true,
  intel_lookup_cve: true,
  intel_search_similar: true,
  intel_build_dossier: true,
  payload_lookup: true,
  check_messages: true,
  ask_operator: true,
  update_todos: true,
  write_todos: true,
  done: true,
});

/** Handlers requiring a scoped local directory, including scoped writes. */
export const LOCAL_SCOPE_TOOLS: Readonly<Record<string, true>> = Object.freeze({
  read_file: true,
  list_files: true,
  search_files: true,
  apply_patch: true,
  str_replace: true,
  run_command: true,
  analyze_binary: true,
});

export interface ToolGateFlags { networkCapable: boolean; localScope: boolean; readOnly: boolean }
export interface CapabilityCheck { allowed: boolean; reason?: string }

/** Capability limits supplement, never replace, the parent's ordinary authorization. */
export function checkInvocationCapabilities(
  toolName: string,
  capabilities: readonly PluginCapability[],
  gate: ToolGateFlags,
): CapabilityCheck {
  const findingsMutation = toolName === "save_finding" || toolName === "update_finding";
  const deny = (requirement: string): CapabilityCheck => ({ allowed: false, reason: `Tool "${toolName}" requires ${requirement}; not granted by the calling executable` });
  if (findingsMutation && !capabilities.includes("findings-write")) return deny("findings-write");
  if (gate.networkCapable && !capabilities.includes("network") && !capabilities.includes("process-exec")) return deny("network or process-exec");
  if (gate.localScope) {
    if (gate.readOnly) {
      if (!capabilities.includes("filesystem-read") && !capabilities.includes("filesystem-write")) return deny("filesystem-read or filesystem-write");
    } else if (!capabilities.includes("filesystem-write")) return deny("filesystem-write");
  }
  if (!gate.networkCapable && !gate.localScope && !gate.readOnly && !findingsMutation) return deny("an explicit tool classification");
  return { allowed: true };
}

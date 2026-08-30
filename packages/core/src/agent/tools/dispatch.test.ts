import { describe, it, expect } from "vitest";
import { TOOL_DISPATCH } from "./dispatch.js";
import { TOOL_DEFINITIONS } from "./index.js";
import { ToolExecutor } from "../tools.js";
import type { ToolContext } from "../types.js";

// 0sec#614 — the dispatch table replaced ToolExecutor's hand-written switch.
// These tests pin the routing byte-for-byte against the pre-split switch and
// guard the one new coupling it introduces: the handler-method *names* are
// strings, so a method rename would silently break dispatch at runtime. The
// `resolves to a real method` test below turns that into a compile-cheap,
// fast unit failure instead.

// Exact tool-name → handler-method routing. Any drift here is a behavior change.
const EXPECTED_ROUTING: Record<string, string> = {
  http_request: "httpRequest",
  send_prompt: "sendPromptTool",
  save_finding: "saveFinding",
  query_findings: "queryFindings",
  use_loot: "useLoot",
  plan: "planTool",
  update_finding: "updateFinding",
  read_file: "readFile",
  list_files: "listFiles",
  search_files: "searchFiles",
  str_replace: "strReplace",
  apply_patch: "applyPatch",
  run_command: "runCommand",
  update_target: "updateTarget",
  crawl: "crawl",
  submit_form: "submitForm",
  access_control_probe: "accessControlProbe",
  bash: "shellExec",
  browser: "browserAction",
  spawn_agent: "spawnAgent",
  spawn_agents: "spawnAgents",
  spawn_persistent_agent: "spawnPersistentAgent",
  web_search: "webSearch",
  intel_search_advisories: "intelSearchAdvisories",
  intel_lookup_cve: "intelLookupCve",
  intel_search_similar: "intelSearchSimilar",
  intel_build_dossier: "intelBuildDossier",
  intel_search_target_history: "intelSearchTargetHistory",
  payload_lookup: "payloadLookup",
  pty_session: "ptySession",
  wp_fingerprint: "wpFingerprint",
  discover_api_surface: "discoverApiSurface",
  surface_sweep: "surfaceSweep",
  js_recon: "jsRecon",
  mongo_objectid: "mongoObjectIdForge",
  list_skills: "listSkills",
  load_skill: "loadSkill",
  done: "markDone",
  run_sqlmap: "runSqlmap",
  run_nmap: "runNmap",
  run_ffuf: "runFfuf",
  run_nuclei: "runNuclei",
  structural_sqli_probe: "structuralSqliProbe",
  prompt_layer_probe: "promptLayerProbe",
  auth_boundary_probe: "authBoundaryProbe",
  // 0sec#925 — live cloud-surface tools.
  cloud_s3_probe: "cloudS3Probe",
  cloud_validate_credentials: "cloudValidateCredentials",
  start_scan: "startScan",
  // 0sec#659 — OAST out-of-band interaction tools.
  oast_register: "oastRegister",
  oast_poll: "oastPoll",
  // Phase-0 — persistent compute-only Python kernel.
  python_exec: "pythonExec",
  analyze_binary: "analyzeBinary",
  // Operator question channel — information-gathering only, grants nothing.
  ask_operator: "askOperator",
  // Structured full-state plan (TodoWrite shape); `write_todos` is an alias.
  update_todos: "updateTodos",
  write_todos: "updateTodos",
  // Model self-extension front door (gated on `allowModelSelfExtension`).
  self_extend: "selfExtend",
};

describe("TOOL_DISPATCH (0sec#614)", () => {
  it("routes every tool to the same handler the switch did", () => {
    expect(TOOL_DISPATCH).toEqual(EXPECTED_ROUTING);
  });

  it("covers exactly the registry — no orphan routes, no unrouted tools", () => {
    expect(Object.keys(TOOL_DISPATCH).sort()).toEqual(Object.keys(TOOL_DEFINITIONS).sort());
  });

  it("maps every tool to a real ToolExecutor handler method (rename guard)", () => {
    const ctx: ToolContext = {
      target: "https://example.com",
      scanId: "dispatch-test",
      findings: [],
      attackResults: [],
      targetInfo: {},
    };
    const executor = new ToolExecutor(ctx, null);
    for (const [tool, method] of Object.entries(TOOL_DISPATCH)) {
      expect(
        typeof (executor as unknown as Record<string, unknown>)[method],
        `tool "${tool}" routes to missing method "${method}"`,
      ).toBe("function");
    }
  });

  it("routes update_todos and its write_todos alias to the plan tracker", async () => {
    const ctx: ToolContext = {
      target: "https://example.com",
      scanId: "dispatch-test",
      findings: [],
      attackResults: [],
      targetInfo: {},
    };
    const executor = new ToolExecutor(ctx, null);

    const first = await executor.execute({
      name: "update_todos",
      arguments: { todos: [{ content: "recon", status: "completed" }, { content: "attack" }] },
    });
    expect(first.success).toBe(true);
    expect((first.output as { message: string }).message).toBe("plan: 2 tasks, 1 done");

    // The alias resolves to the same handler and performs a full replace.
    const second = await executor.execute({
      name: "write_todos",
      arguments: { todos: [{ content: "only-one" }] },
    });
    expect(second.success).toBe(true);
    expect((second.output as { total: number }).total).toBe(1);

    // Malformed payload is rejected as an is_error result, not thrown.
    const bad = await executor.execute({ name: "update_todos", arguments: { todos: [{ content: "" }] } });
    expect(bad.success).toBe(false);
    expect(bad.error).toMatch(/content/i);
  });

  it("returns the original 'Unknown tool' result for an unmapped name", async () => {
    const ctx: ToolContext = {
      target: "https://example.com",
      scanId: "dispatch-test",
      findings: [],
      attackResults: [],
      targetInfo: {},
    };
    const executor = new ToolExecutor(ctx, null);
    const result = await executor.execute({ name: "does_not_exist", arguments: {} });
    expect(result).toEqual({
      success: false,
      output: null,
      error: "Unknown tool: does_not_exist",
    });
  });
});

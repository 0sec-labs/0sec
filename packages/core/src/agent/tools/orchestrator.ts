/**
 * Orchestrator-surface tool definitions (#978, ADR-060) — the agent dogfoods
 * its own product. `start_scan` lets the in-sandbox agent dispatch a CHILD scan
 * via the same POST /scans the UI/CLI use (cloud sink), tagged with this scan's
 * id as parent so it forms a tree. The child runs independently and reports its
 * own findings to the same cloud — the recursive sub-agent fan-out.
 *
 * Pure `ToolDefinition` metadata + the dispatch map; the handler body lives on
 * the ToolExecutor (agent/tools.ts) as a thin delegate to `executeStartScan`,
 * keeping the logic out of the 4000-line tools.ts god-module (CLAUDE.md rule).
 *
 * Cloud-only: no-op error in local mode (no 0SEC_CLOUD_SINK). Budget +
 * fan-out caps are enforced server-side (a 409 = cap hit; 429 = budget).
 */
import type { ToolDefinition, ToolResult } from "../types.js";
import { getCloudSinkConfig } from "../../cloud-sink.js";

export const orchestratorToolDefinitions: Record<string, ToolDefinition> = {
  start_scan: {
    name: "start_scan",
    description:
      "Dispatch a CHILD scan against another target and let it run independently — the recursive fan-out. " +
      "Use it to investigate breadth in parallel: after recon surfaces several assets/endpoints, scan each; or branch into a related package/dependency. " +
      "The child becomes a full scan UNDER this one in the scan tree, with its own agent, and reports its findings to the same cloud — you can keep working while it runs. " +
      "Pass `target` as a package NAME or a URL/host (never a UUID) and its `ecosystem`. Returns the child scan id. " +
      "Subject to the org budget AND a fan-out cap (max children + max tree depth): a 409 means the cap was hit — stop spawning. Cloud-mode only.",
    parameters: {
      target: {
        type: "string",
        description:
          "What to scan: a package name (e.g. \"axios\") or a URL / host / endpoint (e.g. \"https://api.example.com\"). NOT a UUID.",
      },
      ecosystem: {
        type: "string",
        description:
          "Target ecosystem: web | npm | pypi | source | cargo | oci. Use 'web' for any URL / host / endpoint. Defaults to 'web'.",
      },
      mode: {
        type: "string",
        description:
          "Scan mode: audit | review | scan. Omit to let the orchestrator auto-route from the ecosystem.",
      },
    },
    required: ["target"],
  },
};

export const orchestratorDispatch: Record<string, string> = {
  start_scan: "startScan",
};

export const ORCHESTRATOR_TOOL_NAMES: readonly string[] = ["start_scan"];

/**
 * POST /scans on the cloud sink with this scan as the parent. The orchestrator
 * resolve-or-creates the target by (ecosystem, name), derives tree_depth, and
 * enforces the fan-out cap. Returns the child scan id on success.
 */
export async function executeStartScan(
  args: Record<string, unknown>,
): Promise<ToolResult> {
  const cfg = getCloudSinkConfig();
  if (!cfg) {
    return {
      success: false,
      output: null,
      error: "start_scan requires cloud mode (no cloud sink configured).",
    };
  }
  const target = typeof args.target === "string" ? args.target.trim() : "";
  if (!target) {
    return {
      success: false,
      output: null,
      error: "start_scan: `target` is required (a package name or a URL).",
    };
  }
  const ecosystem =
    typeof args.ecosystem === "string" && args.ecosystem.trim()
      ? args.ecosystem.trim()
      : "web";
  const mode =
    typeof args.mode === "string" && args.mode.trim()
      ? args.mode.trim()
      : undefined;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-0sec-Scan-Id": cfg.scanId,
  };
  if (cfg.token) headers["Authorization"] = `Bearer ${cfg.token}`;
  const url = `${cfg.sinkUrl.replace(/\/+$/, "")}/scans`;
  const body = {
    target,
    ecosystem,
    parent_scan_id: cfg.scanId,
    ...(mode ? { scan_mode: mode } : {}),
  };

  try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    if (res.status === 409) {
      const detail = await res.json().catch(() => ({}));
      return {
        success: false,
        output: detail,
        error:
          "Fan-out cap reached (max children or tree depth) — stop spawning child scans.",
      };
    }
    if (res.status === 429) {
      return {
        success: false,
        output: null,
        error: "Budget exceeded — cannot start another scan.",
      };
    }
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      return {
        success: false,
        output: null,
        error: `start_scan POST /scans returned ${res.status}: ${text.slice(0, 200)}`,
      };
    }
    const created = (await res.json()) as {
      id?: string;
      status?: string;
      scan_mode?: string;
    };
    return {
      success: true,
      output: {
        child_scan_id: created.id,
        status: created.status,
        scan_mode: created.scan_mode,
        target,
        ecosystem,
        note: "Child scan dispatched — it runs independently and reports findings to the same cloud. Keep working; check back on its findings later.",
      },
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, output: null, error: `start_scan failed: ${msg}` };
  }
}

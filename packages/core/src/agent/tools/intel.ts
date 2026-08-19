/**
 * Vulnerability intelligence tool definitions (pwnkit#611 — split out of the monolithic
 * agent/tools.ts registry).
 *
 * Live vulnerability-intelligence lookups (advisories, CVEs, similar bugs,
 * dossiers, target history).
 *
 * The ./tools/index.ts barrel merges every per-domain definition map into the
 * canonical `TOOL_DEFINITIONS` registry. The runtime handler BODIES live here
 * too (pwnkit#1284) as free functions over the shared `ToolContext`; the
 * `ToolExecutor` class in agent/tools.ts keeps same-named thin delegates so the
 * dispatch table (tools/dispatch.ts) still resolves each tool to a method.
 */
import type { ToolDefinition, ToolContext, ToolResult } from "../types.js";
import {
  buildIntelDossier,
  lookupCve,
  searchAdvisories,
  searchSimilar,
  searchTargetHistory,
} from "../../intel/index.js";
import { resolveScopedPath } from "./scope-path.js";

export const intelToolDefinitions: Record<string, ToolDefinition> = {
  intel_search_advisories: {
    name: "intel_search_advisories",
    description:
      "Search live vulnerability intelligence for advisories affecting a package/version. Use before making known-CVE/GHSA claims during package audits. Results are sourced leads; verify local reachability before reporting new vulnerabilities.",
    parameters: {
      ecosystem: {
        type: "string",
        description: "Package ecosystem: npm, PyPI, crates.io, Go, Maven",
      },
      package_name: { type: "string", description: "Package name, e.g. formidable or requests" },
      version: { type: "string", description: "Optional resolved package version" },
      enrich: { type: "boolean", description: "Whether to enrich CVE aliases from NVD/CISA KEV (default true)" },
    },
    required: ["ecosystem", "package_name"],
  },

  intel_lookup_cve: {
    name: "intel_lookup_cve",
    description:
      "Look up a CVE from NVD and CISA KEV. Use this instead of citing CVEs from memory. Returns CVSS, CWE, references, and known-exploited status when available.",
    parameters: {
      cve_id: { type: "string", description: "CVE identifier, e.g. CVE-2024-1086" },
    },
    required: ["cve_id"],
  },

  intel_search_similar: {
    name: "intel_search_similar",
    description:
      "Search for related CVEs/advisories by CWE and keywords. Use as variant-hunt context to find historical bug shapes similar to the target code. Provide at least one of: cwe or non-empty keywords.",
    parameters: {
      cwe: { type: "string", description: "Optional CWE id, e.g. CWE-22" },
      ecosystem: { type: "string", description: "Optional ecosystem hint" },
      keywords: { type: "string", description: "Optional comma-separated keywords, e.g. zip slip,path traversal" },
      limit: { type: "number", description: "Maximum results (default 10, max 50)" },
    },
  },

  intel_build_dossier: {
    name: "intel_build_dossier",
    description:
      "Build a package-level vulnerability intelligence dossier with prioritized advisories, risk summary, prior-vulnerability playbooks, variant-hunt leads, and graph context. Use as the first intel step for dependency audits.",
    parameters: {
      ecosystem: { type: "string", description: "Package ecosystem: npm, PyPI, crates.io, Go, Maven" },
      package_name: { type: "string", description: "Package name, e.g. formidable or requests" },
      version: { type: "string", description: "Optional resolved package version" },
      keywords: { type: "string", description: "Optional comma-separated variant-hunt keywords" },
      similar_limit: { type: "number", description: "Maximum similar-advisory leads (default 10, max 50)" },
      include_similar: { type: "boolean", description: "Whether to include similar historical advisories (default true)" },
    },
    required: ["ecosystem", "package_name"],
  },

  intel_search_target_history: {
    name: "intel_search_target_history",
    description:
      "Search live vulnerability intelligence for CVEs/GHSAs already reported against this exact target/project/repository/product by other researchers. Use early in source reviews and live-target recon to turn historical target CVEs into multi-step audit playbooks.",
    parameters: {
      target: { type: "string", description: "Target name, URL, or repository URL" },
      repo_path: { type: "string", description: "Optional local repo/package path to infer package/repository/product hints from. Defaults to the agent scope path when available." },
      repository: { type: "string", description: "Optional GitHub repository, e.g. expressjs/express or https://github.com/expressjs/express" },
      ecosystem: { type: "string", description: "Optional package ecosystem: npm, PyPI, crates.io, Go, Maven" },
      package_name: { type: "string", description: "Optional package name if the target is distributed as a package" },
      product: { type: "string", description: "Optional product/project name" },
      vendor: { type: "string", description: "Optional vendor/organization name" },
      keywords: { type: "string", description: "Optional comma-separated aliases or target-specific search terms" },
      limit: { type: "number", description: "Maximum results per live source query (default 20, max 50)" },
    },
  },
};

// Tool-name → ToolExecutor handler-method name (pwnkit#614). Co-located with
// this domain's definitions so a new tool adds its route here, not in a
// shared dispatch switch. Assembled by ./dispatch.ts; resolved off the
// executor instance in agent/tools.ts (the methods now delegate to the
// free-function handlers below — pwnkit#1284).
export const intelDispatch: Record<string, string> = {
  intel_search_advisories: "intelSearchAdvisories",
  intel_lookup_cve: "intelLookupCve",
  intel_search_similar: "intelSearchSimilar",
  intel_build_dossier: "intelBuildDossier",
  intel_search_target_history: "intelSearchTargetHistory",
};

// ── Runtime handlers (pwnkit#1284) ──
// Extracted verbatim from the ToolExecutor private methods of the same name.
// Only `intel_search_target_history` needs executor state (the scope path), so
// it takes the `ToolContext`; the rest are pure over their args.

export async function executeIntelSearchAdvisories(
  args: Record<string, unknown>,
): Promise<ToolResult> {
  const ecosystem = String(args.ecosystem ?? "").trim();
  const packageName = String(args.package_name ?? args.packageName ?? "").trim();
  if (!ecosystem) return { success: false, output: null, error: "ecosystem is required" };
  if (!packageName) return { success: false, output: null, error: "package_name is required" };
  const version = typeof args.version === "string" && args.version.trim() ? args.version.trim() : undefined;
  const enrich = typeof args.enrich === "boolean" ? args.enrich : true;
  const result = await searchAdvisories({
    ecosystem,
    packageName,
    version,
    enrich,
  });
  return {
    success: true,
    output: {
      count: result.advisories.length,
      advisories: result.advisories.slice(0, 20),
      graph: {
        nodes: result.graph.nodes.slice(0, 80),
        edges: result.graph.edges.slice(0, 120),
      },
    },
  };
}

export async function executeIntelLookupCve(
  args: Record<string, unknown>,
): Promise<ToolResult> {
  const cveId = String(args.cve_id ?? args.cveId ?? "").trim();
  if (!cveId) return { success: false, output: null, error: "cve_id is required" };
  const intel = await lookupCve({ cveId });
  if (!intel) return { success: true, output: { cve_id: cveId.toUpperCase(), found: false } };
  return { success: true, output: { found: true, advisory: intel } };
}

export async function executeIntelSearchSimilar(
  args: Record<string, unknown>,
): Promise<ToolResult> {
  const cwe = typeof args.cwe === "string" && args.cwe.trim() ? args.cwe.trim() : undefined;
  const ecosystem = typeof args.ecosystem === "string" && args.ecosystem.trim() ? args.ecosystem.trim() : undefined;
  const keywords = typeof args.keywords === "string"
    ? args.keywords.split(",").map((item) => item.trim()).filter(Boolean)
    : undefined;
  const limit = typeof args.limit === "number" ? Math.min(Math.max(Math.trunc(args.limit), 1), 50) : 10;
  if (!cwe && (!keywords || keywords.length === 0)) {
    return { success: false, output: null, error: "provide cwe or keywords" };
  }
  const result = await searchSimilar({ cwe, ecosystem, keywords, limit });
  return {
    success: true,
    output: {
      count: result.advisories.length,
      advisories: result.advisories.slice(0, limit),
      graph: {
        nodes: result.graph.nodes.slice(0, 80),
        edges: result.graph.edges.slice(0, 120),
      },
    },
  };
}

export async function executeIntelBuildDossier(
  args: Record<string, unknown>,
): Promise<ToolResult> {
  const ecosystem = String(args.ecosystem ?? "").trim();
  const packageName = String(args.package_name ?? args.packageName ?? "").trim();
  if (!ecosystem) return { success: false, output: null, error: "ecosystem is required" };
  if (!packageName) return { success: false, output: null, error: "package_name is required" };
  const version = typeof args.version === "string" && args.version.trim() ? args.version.trim() : undefined;
  const keywords = typeof args.keywords === "string"
    ? args.keywords.split(",").map((item) => item.trim()).filter(Boolean)
    : undefined;
  const similarLimit = typeof args.similar_limit === "number"
    ? Math.min(Math.max(Math.trunc(args.similar_limit), 1), 50)
    : undefined;
  const includeSimilar = typeof args.include_similar === "boolean" ? args.include_similar : undefined;
  const dossier = await buildIntelDossier({
    ecosystem,
    packageName,
    version,
    keywords,
    similarLimit,
    includeSimilar,
  });
  return {
    success: true,
    output: {
      ...dossier,
      advisories: dossier.advisories.slice(0, 20),
      variantLeads: dossier.variantLeads.slice(0, 10),
      playbooks: dossier.playbooks.slice(0, 6).map((playbook) => ({
        ...playbook,
        steps: playbook.steps.slice(0, 5),
      })),
      graph: {
        nodes: dossier.graph.nodes.slice(0, 100),
        edges: dossier.graph.edges.slice(0, 160),
      },
    },
  };
}

export async function executeIntelSearchTargetHistory(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<ToolResult> {
  const target = typeof args.target === "string" && args.target.trim() ? args.target.trim() : undefined;
  const requestedRepoPath = typeof args.repo_path === "string" && args.repo_path.trim() ? args.repo_path.trim() : undefined;
  const repoPath = requestedRepoPath
    ? (ctx.scopePath ? resolveScopedPath(ctx.scopePath, requestedRepoPath) : requestedRepoPath)
    : ctx.scopePath;
  const repository = typeof args.repository === "string" && args.repository.trim() ? args.repository.trim() : undefined;
  const ecosystem = typeof args.ecosystem === "string" && args.ecosystem.trim() ? args.ecosystem.trim() : undefined;
  const packageName = String(args.package_name ?? args.packageName ?? "").trim() || undefined;
  const product = typeof args.product === "string" && args.product.trim() ? args.product.trim() : undefined;
  const vendor = typeof args.vendor === "string" && args.vendor.trim() ? args.vendor.trim() : undefined;
  const keywords = typeof args.keywords === "string"
    ? args.keywords.split(",").map((item) => item.trim()).filter(Boolean)
    : undefined;
  const limit = typeof args.limit === "number" ? Math.min(Math.max(Math.trunc(args.limit), 1), 50) : 20;
  if (!target && !repoPath && !repository && !packageName && !product && !vendor && (!keywords || keywords.length === 0)) {
    return { success: false, output: null, error: "provide target, repo_path, repository, package_name, product, vendor, keywords, or run with a scoped source path" };
  }
  const history = await searchTargetHistory({
    target,
    repoPath,
    repository,
    ecosystem,
    packageName,
    product,
    vendor,
    keywords,
    limit,
  });
  return {
    success: true,
    output: {
      ...history,
      advisories: history.advisories.slice(0, 20),
      playbooks: history.playbooks.slice(0, 6).map((playbook) => ({
        ...playbook,
        steps: playbook.steps.slice(0, 5),
      })),
      graph: {
        nodes: history.graph.nodes.slice(0, 100),
        edges: history.graph.edges.slice(0, 160),
      },
    },
  };
}

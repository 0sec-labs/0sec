/**
 * Vulnerability intelligence tool definitions (pwnkit#611 — split out of the monolithic
 * agent/tools.ts registry).
 *
 * Live vulnerability-intelligence lookups (advisories, CVEs, similar bugs,
 * dossiers, target history).
 *
 * Pure `ToolDefinition` metadata (name / description / parameter schema). The
 * ./tools/index.ts barrel merges every per-domain map into the canonical
 * `TOOL_DEFINITIONS` registry; the matching runtime handlers live on the
 * `ToolExecutor` class in agent/tools.ts.
 */
import type { ToolDefinition } from "../types.js";

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
// executor instance in agent/tools.ts (handler bodies stay private methods).
export const intelDispatch: Record<string, string> = {
  intel_search_advisories: "intelSearchAdvisories",
  intel_lookup_cve: "intelLookupCve",
  intel_search_similar: "intelSearchSimilar",
  intel_build_dossier: "intelBuildDossier",
  intel_search_target_history: "intelSearchTargetHistory",
};

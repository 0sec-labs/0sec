/**
 * Recon / target-interaction tool definitions (pwnkit#611 — split out of the monolithic
 * agent/tools.ts registry).
 *
 * Probing, crawling, browser-driving and recon tools — the agent's primary
 * ways to interact with and map a live target.
 *
 * Pure `ToolDefinition` metadata (name / description / parameter schema). The
 * ./tools/index.ts barrel merges every per-domain map into the canonical
 * `TOOL_DEFINITIONS` registry; the matching runtime handlers live on the
 * `ToolExecutor` class in agent/tools.ts.
 */
import type { ToolDefinition } from "../types.js";

export const reconToolDefinitions: Record<string, ToolDefinition> = {
  http_request: {
    name: "http_request",
    description:
      "Send an HTTP request to a target URL. Use this to probe endpoints, send attack payloads, or interact with the target.",
    parameters: {
      url: { type: "string", description: "Target URL" },
      method: {
        type: "string",
        description: "HTTP method",
        enum: ["GET", "POST", "PUT", "DELETE", "PATCH"],
      },
      body: { type: "string", description: "Request body (JSON string)" },
      headers: { type: "object", description: "Additional headers as key-value pairs" },
    },
    required: ["url"],
  },

  send_prompt: {
    name: "send_prompt",
    description:
      "Send a prompt to the target LLM endpoint and get the response. This is the primary way to interact with the target.",
    parameters: {
      prompt: { type: "string", description: "The prompt to send to the target" },
      system_context: {
        type: "string",
        description: "Optional system context to include with the prompt",
      },
    },
    required: ["prompt"],
  },

  crawl: {
    name: "crawl",
    description:
      "Crawl a web page: fetch HTML, extract links, forms (with inputs), script sources, and cookies. Only follows same-origin links. Use this to map the attack surface of a web application.",
    parameters: {
      url: { type: "string", description: "URL to crawl" },
      depth: {
        type: "number",
        description: "Crawl depth (default 1, max 3). Depth 1 fetches only the given URL. Depth 2 also fetches same-origin links found on that page, etc.",
      },
    },
    required: ["url"],
  },

  submit_form: {
    name: "submit_form",
    description:
      "Submit an HTML form. Sends application/x-www-form-urlencoded data (not JSON). Use this after crawl discovers forms on the target.",
    parameters: {
      url: { type: "string", description: "Form action URL" },
      method: {
        type: "string",
        description: "HTTP method (default POST)",
        enum: ["GET", "POST"],
      },
      fields: {
        type: "object",
        description: "Form field key-value pairs to submit",
      },
      headers: {
        type: "object",
        description: "Additional headers (e.g. Cookie for session persistence)",
      },
    },
    required: ["url", "fields"],
  },

  browser: {
    name: "browser",
    description:
      "Control a headless browser. Navigate to URLs, fill forms, click elements, execute JavaScript, and read page content. Use for XSS testing and pages that need JavaScript rendering.",
    parameters: {
      action: {
        type: "string",
        description: "Browser action",
        enum: ["navigate", "click", "fill", "evaluate", "content", "screenshot"],
      },
      url: { type: "string", description: "URL to navigate to (for navigate action)" },
      selector: { type: "string", description: "CSS selector (for click/fill actions)" },
      value: { type: "string", description: "Value to fill or JavaScript to evaluate" },
    },
    required: ["action"],
  },

  web_search: {
    name: "web_search",
    description:
      "Search the web for CVE details, API documentation, or security technique references. Cannot be used to find writeups or solutions.",
    parameters: {
      query: { type: "string", description: "Search query" },
    },
    required: ["query"],
  },

  wp_fingerprint: {
    name: "wp_fingerprint",
    description:
      "WordPress reconnaissance and CVE lookup. Confirms the target is WordPress, extracts the core version, enumerates installed plugins and themes (via HTML source, /wp-json/, and /wp-content/ directory listings), proactively probes high-value vulnerable plugin slugs, parses plugin readme.txt/theme style.css versions, matches a local WordPress vulnerability catalog, queries the no-key WPVulnerability API, optionally queries WPScan when a token is configured, and queries OSV for known CVEs per (slug, version) pair. Returns structured findings with exploit hints. Feature-gated behind --features wp_fingerprint. Use this once, early, when the target is or might be WordPress.",
    parameters: {
      max_plugin_probes: {
        type: "number",
        description: "Maximum plugins/themes to probe for a version file (default 40).",
      },
      max_vulnerable_plugin_probes: {
        type: "number",
        description: "Maximum high-value vulnerable plugin slugs to probe proactively (default 40).",
      },
      skip_osv: {
        type: "boolean",
        description: "Skip OSV lookups (for offline or diagnostic runs). Default false.",
      },
      wpscan_api_token: {
        type: "string",
        description: "Optional WPScan API token for fresh per-plugin/theme vulnerability lookup. Defaults to WPSCAN_API_TOKEN or PWNKIT_WPSCAN_API_TOKEN.",
      },
    },
  },
  discover_api_surface: {
    name: "discover_api_surface",
    description:
      "Map the target's API surface in one call: probes well-known OpenAPI/Swagger spec locations (/openapi.json, /v3/api-docs, …) and MCP mount points, parses any spec found, and returns a deduped inventory of endpoints (METHOD /path), specs, and MCP servers. " +
      "This is how a real attacker starts — find the docs, enumerate every endpoint, THEN probe each for auth boundaries (auth_boundary_probe) and injection (structural_sqli_probe). Every probe is scope-validated, so it only touches the in-scope target. " +
      "Use at the start of a web/API engagement to enumerate the surface before targeting individual endpoints. Returns assets with kind (endpoint / openapi_spec / mcp_server) + metadata (HTTP method, spec title); feed the endpoint list straight into auth_boundary_probe.",
    parameters: {
      domain: {
        type: "string",
        description: "The target host or base URL to map (e.g. https://api.target.com or target.com). Must be in scope; defaults to the scan target when omitted.",
      },
    },
  },
  surface_sweep: {
    name: "surface_sweep",
    description:
      "One-call attack-surface sweep: maps the API surface (like discover_api_surface) AND probes every discovered endpoint for unauthenticated reachability (like auth_boundary_probe) in a single step. " +
      "Fastest way to start an engagement — point it at a host and get the full endpoint inventory plus which endpoints leak without auth, ready to drill into with structural_sqli_probe. Every request is scope-validated. " +
      "Returns the discovered surface, per-endpoint auth-boundary verdicts, and pre-drafted findings for each unauthenticated-reachable endpoint.",
    parameters: {
      domain: {
        type: "string",
        description: "The target host or base URL to sweep (defaults to the scan target).",
      },
    },
  },
};

// Tool-name → ToolExecutor handler-method name (pwnkit#614). Co-located with
// this domain's definitions so a new tool adds its route here, not in a
// shared dispatch switch. Assembled by ./dispatch.ts; resolved off the
// executor instance in agent/tools.ts (handler bodies stay private methods).
export const reconDispatch: Record<string, string> = {
  http_request: "httpRequest",
  send_prompt: "sendPromptTool",
  crawl: "crawl",
  submit_form: "submitForm",
  browser: "browserAction",
  web_search: "webSearch",
  wp_fingerprint: "wpFingerprint",
  discover_api_surface: "discoverApiSurface",
  surface_sweep: "surfaceSweep",
};

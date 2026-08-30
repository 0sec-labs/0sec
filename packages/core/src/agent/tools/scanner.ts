/**
 * Engagement-gated scanner-wrapper tool definitions (0sec#611 — split out of the monolithic
 * agent/tools.ts registry).
 *
 * Structured sqlmap/nmap/ffuf/nuclei wrappers (0sec#555), exposed only
 * when the engagement passed --allow-scanners.
 *
 * Pure `ToolDefinition` metadata (name / description / parameter schema). The
 * ./tools/index.ts barrel merges every per-domain map into the canonical
 * `TOOL_DEFINITIONS` registry; the matching runtime handlers live on the
 * `ToolExecutor` class in agent/tools.ts.
 */
import type { ToolDefinition } from "../types.js";

export const scannerToolDefinitions: Record<string, ToolDefinition> = {
  // ── Engagement-gated structured scanner wrappers (0sec#555) ──
  // These are ONLY present in the tool set when the engagement passed
  // --allow-scanners (ctx.allowScanners). See getToolsForRole + SCANNER_TOOL_NAMES.
  // They build a safe argv (no shell concat), enforce scope + rate-limit +
  // wallclock, and return PARSED structured output (no raw blobs).
  // One consolidated scanner VERB (tool-curation): sqlmap/nmap/ffuf/nuclei behind
  // `tool`, instead of four top-level wrappers. Each still builds a safe argv,
  // enforces scope+rate-limit+wallclock, and returns PARSED structured output;
  // the ATT&CK layer keys off `tool` (see mitre.ts) so per-scanner attribution
  // is preserved. Args below are grouped by which scanner uses them.
  run_scanner: {
    name: "run_scanner",
    description:
      "Run an external scanner and return a STRUCTURED result (not raw output). Set `tool`: 'sqlmap' (SQLi → confirmed DBMS, injection points, enumerated dbs/tables), 'nmap' (→ open ports/services/versions), 'ffuf' (content/path fuzz with a FUZZ keyword → hits), 'nuclei' (templates → findings). Engagement-gated: only available when the scan was started with --allow-scanners. Non-interactive; never escalates to OS/file shells.",
    parameters: {
      tool: { type: "string", description: "Which scanner to run.", enum: ["sqlmap", "nmap", "ffuf", "nuclei"] },
      // sqlmap + ffuf
      url: { type: "string", description: "sqlmap/ffuf: target URL (in-scope). ffuf needs a FUZZ keyword, e.g. http://host/FUZZ." },
      // sqlmap
      data: { type: "string", description: "sqlmap: POST body (implies POST)." },
      level: { type: "number", description: "sqlmap --level 1-5 (default 1)." },
      risk: { type: "number", description: "sqlmap --risk 1-3 (default 1)." },
      technique: { type: "string", description: "sqlmap: restrict techniques, letters from BEUSTQ." },
      dbms: { type: "string", description: "sqlmap: DBMS hint, e.g. mysql, postgresql." },
      enumerate_dbs: { type: "boolean", description: "sqlmap: --dbs to enumerate databases." },
      dump: { type: "boolean", description: "sqlmap: --dump tables/columns once injectable." },
      // nmap + nuclei
      target: { type: "string", description: "nmap/nuclei: target host/IP or URL (in-scope)." },
      // nmap
      ports: { type: "string", description: "nmap: port spec e.g. '22,80,443' or '1-1024'." },
      service_detection: { type: "boolean", description: "nmap: -sV service/version detection." },
      top_ports: { type: "number", description: "nmap: scan the N most common ports." },
      skip_ping: { type: "boolean", description: "nmap: skip host discovery (-Pn, default true)." },
      // ffuf
      wordlist: { type: "string", description: "ffuf: path to a wordlist on the runner." },
      match_status: { type: "string", description: "ffuf: status allowlist e.g. '200,204,301,302,403'." },
      // nuclei
      severity: { type: "string", description: "nuclei: severity allowlist e.g. 'critical,high,medium'." },
      tags: { type: "string", description: "nuclei: template tag allowlist e.g. 'cve,rce'." },
      // shared
      threads: { type: "number", description: "sqlmap 1-10 / ffuf 1-50 concurrent requests." },
      timeout: { type: "number", description: "Requested wallclock seconds (clamped to ceiling)." },
    },
    required: ["tool"],
  },
};

/**
 * Names of the engagement-gated structured scanner wrappers (0sec#555).
 * These are exposed ONLY when the engagement passed --allow-scanners
 * (`opts.allowScanners`), preserving the stealthy generic-scanner-suppression
 * default (0sec#217). Kept as a module constant so both the role tool sets
 * and the `allEnabledTools` (audit/review) path filter on the same source.
 */
export const SCANNER_TOOL_NAMES: ReadonlyArray<string> = ["run_scanner"];

// Tool-name → ToolExecutor handler-method name (0sec#614). Co-located with
// this domain's definitions so a new tool adds its route here, not in a
// shared dispatch switch. Assembled by ./dispatch.ts; resolved off the
// executor instance in agent/tools.ts (handler bodies stay private methods).
export const scannerDispatch: Record<string, string> = {
  run_scanner: "runScanner",
};

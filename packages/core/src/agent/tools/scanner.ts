/**
 * Engagement-gated scanner-wrapper tool definitions (pwnkit#611 — split out of the monolithic
 * agent/tools.ts registry).
 *
 * Structured sqlmap/nmap/ffuf/nuclei wrappers (pwnkit#555), exposed only
 * when the engagement passed --allow-scanners.
 *
 * Pure `ToolDefinition` metadata (name / description / parameter schema). The
 * ./tools/index.ts barrel merges every per-domain map into the canonical
 * `TOOL_DEFINITIONS` registry; the matching runtime handlers live on the
 * `ToolExecutor` class in agent/tools.ts.
 */
import type { ToolDefinition } from "../types.js";

export const scannerToolDefinitions: Record<string, ToolDefinition> = {
  // ── Engagement-gated structured scanner wrappers (pwnkit#555) ──
  // These are ONLY present in the tool set when the engagement passed
  // --allow-scanners (ctx.allowScanners). See getToolsForRole + SCANNER_TOOL_NAMES.
  // They build a safe argv (no shell concat), enforce scope + rate-limit +
  // wallclock, and return PARSED structured output (no raw blobs).
  run_sqlmap: {
    name: "run_sqlmap",
    description:
      "Run sqlmap against an in-scope URL and return a STRUCTURED result (confirmed DBMS, injection points, enumerated databases/tables, dumped columns) — not raw output. Engagement-gated: only available when the scan was started with --allow-scanners. Use for authorized SQLi testing on CTF/internal/pentest targets. Always non-interactive; never escalates to OS/file shells.",
    parameters: {
      url: { type: "string", description: "Target URL (in-scope), e.g. http://host/item?id=1" },
      data: { type: "string", description: "POST body to test (implies POST), e.g. 'user=a&pass=b'" },
      level: { type: "number", description: "sqlmap --level 1-5 (default 1)" },
      risk: { type: "number", description: "sqlmap --risk 1-3 (default 1)" },
      technique: { type: "string", description: "Restrict techniques, letters from BEUSTQ" },
      dbms: { type: "string", description: "DBMS hint, e.g. mysql, postgresql" },
      enumerate_dbs: { type: "boolean", description: "Pass --dbs to enumerate databases" },
      dump: { type: "boolean", description: "Pass --dump to dump tables/columns once injectable" },
      threads: { type: "number", description: "Concurrent requests 1-10 (default 1)" },
      timeout: { type: "number", description: "Requested wallclock seconds (clamped to ceiling)" },
    },
    required: ["url"],
  },

  run_nmap: {
    name: "run_nmap",
    description:
      "Run nmap against an in-scope host and return a STRUCTURED port table (open ports, services, versions) — not raw output. Engagement-gated: only available with --allow-scanners. NSE scripts are not enabled.",
    parameters: {
      target: { type: "string", description: "Target host or IP (in-scope)" },
      ports: { type: "string", description: "Port spec e.g. '22,80,443' or '1-1024'" },
      service_detection: { type: "boolean", description: "Enable -sV service/version detection" },
      top_ports: { type: "number", description: "Scan the N most common ports (--top-ports)" },
      skip_ping: { type: "boolean", description: "Skip host discovery (-Pn). Default true." },
      timeout: { type: "number", description: "Requested wallclock seconds (clamped to ceiling)" },
    },
    required: ["target"],
  },

  run_ffuf: {
    name: "run_ffuf",
    description:
      "Run ffuf content/path fuzzing against an in-scope URL (with a FUZZ keyword) and return STRUCTURED hits (path/input, status, length). Engagement-gated: only available with --allow-scanners.",
    parameters: {
      url: { type: "string", description: "Target URL with FUZZ keyword, e.g. http://host/FUZZ" },
      wordlist: { type: "string", description: "Path to a wordlist file on the runner" },
      match_status: { type: "string", description: "Status allowlist e.g. '200,204,301,302,403'" },
      threads: { type: "number", description: "Concurrent requests 1-50 (default 10)" },
      timeout: { type: "number", description: "Requested wallclock seconds (clamped to ceiling)" },
    },
    required: ["url", "wordlist"],
  },

  run_nuclei: {
    name: "run_nuclei",
    description:
      "Run nuclei template-driven scanning against an in-scope target and return STRUCTURED findings (template id, severity, matched-at). Engagement-gated: only available with --allow-scanners.",
    parameters: {
      target: { type: "string", description: "Target URL/host (in-scope)" },
      severity: { type: "string", description: "Severity allowlist e.g. 'critical,high,medium'" },
      tags: { type: "string", description: "Template tag allowlist e.g. 'cve,rce'" },
      timeout: { type: "number", description: "Requested wallclock seconds (clamped to ceiling)" },
    },
    required: ["target"],
  },
};

/**
 * Names of the engagement-gated structured scanner wrappers (pwnkit#555).
 * These are exposed ONLY when the engagement passed --allow-scanners
 * (`opts.allowScanners`), preserving the stealthy generic-scanner-suppression
 * default (pwnkit#217). Kept as a module constant so both the role tool sets
 * and the `allEnabledTools` (audit/review) path filter on the same source.
 */
export const SCANNER_TOOL_NAMES: ReadonlyArray<string> = [
  "run_sqlmap",
  "run_nmap",
  "run_ffuf",
  "run_nuclei",
];

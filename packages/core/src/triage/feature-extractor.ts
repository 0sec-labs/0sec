/**
 * Layer 1: Handcrafted Feature Extractor for Finding Triage
 *
 * Extracts a 55-element numeric vector from a Finding using pure
 * regex/string operations. No LLM calls, no network requests.
 *
 * Inspired by VulnBERT's hybrid architecture — handcrafted features
 * alone achieve ~77% recall / 16% FPR; fused with neural embeddings
 * they reach 92% recall / 1.2% FPR.
 */

import type { AttackCategory, CrashType, Finding, Severity } from "@pwnkit/shared";

// ────────────────────────────────────────────────────────────────────
// Feature name registry (55 features, ordered by group)
// ────────────────────────────────────────────────────────────────────

export const FEATURE_NAMES: string[] = [
  // Response features (13) — indices 0-12
  "resp_http_status",
  "resp_sql_error",
  "resp_stack_trace",
  "resp_error_message",
  "resp_payload_exact_reflection",
  "resp_payload_partial_reflection",
  "resp_sensitive_data",
  "resp_flag_pattern",
  "resp_content_type_match",
  "resp_length",
  "resp_waf_signature",
  "resp_redirect",
  "resp_5xx_status",

  // Request features (10) — indices 13-22
  "req_sql_syntax",
  "req_xss_payload",
  "req_ssti_syntax",
  "req_path_traversal",
  "req_command_injection",
  "req_encoding_detected",
  "req_http_method",
  "req_auth_header",
  "req_param_count",
  "req_body_length",

  // Metadata features (8) — indices 23-30
  "meta_severity_ordinal",
  "meta_confidence",
  "meta_high_confidence_category",
  "meta_injection_class",
  "meta_access_control_class",
  "meta_has_template_id",
  "meta_has_cwe",
  "meta_has_cve",

  // Text quality features (10) — indices 31-40
  "text_description_length",
  "text_repro_steps",
  "text_impact_statement",
  "text_hedging_language",
  "text_verification_language",
  "text_analysis_length",
  "text_code_blocks",
  "text_evidence_request_nonempty",
  "text_evidence_response_nonempty",
  "text_evidence_analysis_nonempty",

  // Cross-field features (4) — indices 41-44
  "cross_payload_category_consistent",
  "cross_severity_confidence_interaction",
  "cross_response_request_length_ratio",
  "cross_evidence_completeness",

  // Kernel crash features (10) — indices 45-54
  "kernel_crash_type_ordinal",
  "kernel_stack_depth",
  "kernel_has_reproducer",
  "kernel_access_is_write",
  "kernel_access_size",
  "kernel_network_subsystem",
  "kernel_has_alloc_site",
  "kernel_has_free_site",
  "kernel_is_kasan",
  "kernel_subsystem_criticality",
];

// ────────────────────────────────────────────────────────────────────
// Regex pattern banks
// ────────────────────────────────────────────────────────────────────

// SQL error strings across major databases
const SQL_ERROR_PATTERNS = new RegExp(
  [
    // MySQL
    "you have an error in your sql syntax",
    "warning:.*mysql",
    "unclosed quotation mark",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_connect",
    "mysqld",
    "MySqlException",
    // PostgreSQL
    "pg_query",
    "pg_exec",
    "pg_connect",
    "PostgreSQL.*ERROR",
    'ERROR:\\s+syntax error at or near "',
    "invalid input syntax for",
    "unterminated quoted string",
    "PSQLException",
    // SQLite
    "sqlite3?\\.OperationalError",
    "SQLite3::SQLException",
    "SQLITE_ERROR",
    "near \".*\": syntax error",
    "unrecognized token",
    // MSSQL
    "\\[Microsoft\\]\\[ODBC SQL Server Driver\\]",
    "\\[SqlServer\\]",
    "Incorrect syntax near",
    "Unclosed quotation mark after the character string",
    "mssql_query",
    "SqlException",
    "OLE DB.*SQL Server",
    // Oracle
    "ORA-\\d{5}",
    "Oracle error",
    "oracle\\.jdbc",
    "quoted string not properly terminated",
    "PLS-\\d{5}",
    // Generic
    "SQL syntax.*error",
    "sql error",
    "SQLSTATE",
    "ODBC.*Driver",
    "javax\\.persistence",
    "hibernate\\.QueryException",
  ].join("|"),
  "i",
);

// Stack trace patterns
const STACK_TRACE_PATTERN = new RegExp(
  [
    "Traceback \\(most recent call last\\)",
    "at .+\\(.+:\\d+:\\d+\\)",
    "at .+\\(.+\\.java:\\d+\\)",
    "File \".+\", line \\d+",
    "\\s+at\\s+[\\w.$]+\\([^)]*\\)",
    "Exception in thread",
    "goroutine \\d+",
    "panic:",
    "stack trace:",
    "\\[stacktrace\\]",
    "#\\d+\\s+0x[0-9a-f]+\\s+in\\s+",
    "\\.rb:\\d+:in `",
    "from .+\\.rb:\\d+",
    "\\w+Error:.*\\n\\s+at\\s",
  ].join("|"),
  "im",
);

// Generic error message patterns
const ERROR_MESSAGE_PATTERN = new RegExp(
  [
    "\\b(error|exception|fatal|failure|failed|denied|forbidden|unauthorized|invalid)\\b",
    "internal server error",
    "an error occurred",
    "unexpected error",
    "unhandled exception",
  ].join("|"),
  "i",
);

// Sensitive data patterns (PII, secrets, etc.)
const SENSITIVE_DATA_PATTERN = new RegExp(
  [
    // Credentials / tokens
    "password\\s*[:=]\\s*\\S+",
    "passwd\\s*[:=]\\s*\\S+",
    "api[_-]?key\\s*[:=]\\s*\\S+",
    "secret[_-]?key\\s*[:=]\\s*\\S+",
    "access[_-]?token\\s*[:=]\\s*\\S+",
    "Bearer\\s+[A-Za-z0-9\\-._~+/]+=*",
    // AWS keys
    "AKIA[0-9A-Z]{16}",
    // Private keys
    "-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    // PII
    "\\b\\d{3}-\\d{2}-\\d{4}\\b", // SSN
    "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z]{2,}\\b",
    // Database connection strings
    "(?:mysql|postgres|mongodb|redis)://[^\\s]+",
    // JWTs
    "eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+",
  ].join("|"),
  "i",
);

// FLAG / CTF flag patterns
const FLAG_PATTERN = /FLAG\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}|XBOW\{[^}]+\}|flag\s*[:=]\s*\S+/i;

// WAF / security-blocking signatures
const WAF_SIGNATURE_PATTERN = new RegExp(
  [
    "\\b(cloudflare|akamai|imperva|incapsula|sucuri|modsecurity|f5|barracuda|fortinet)\\b",
    "access denied",
    "request blocked",
    "web application firewall",
    "waf",
    "not acceptable",
    "406 not acceptable",
    "security policy",
    "blocked by",
    "your request has been blocked",
  ].join("|"),
  "i",
);

// Redirect patterns
const REDIRECT_PATTERN = /(?:301|302|303|307|308)\s|location:\s*https?:\/\/|redirect|moved permanently|found\b/i;

// SQL syntax in requests
const SQL_SYNTAX_PATTERN = new RegExp(
  [
    "\\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|AND|OR|ORDER BY|GROUP BY|HAVING)\\b",
    "'\\s*(OR|AND)\\s*'?\\s*\\d+\\s*=\\s*\\d+",
    "'\\s*OR\\s+'[^']*'\\s*=\\s*'",
    "--\\s*$",
    "#\\s*$",
    "/\\*.*\\*/",
    "WAITFOR\\s+DELAY",
    "SLEEP\\s*\\(",
    "BENCHMARK\\s*\\(",
    "\\bEXTRACTVALUE\\b",
    "\\bUPDATEXML\\b",
    "1\\s*=\\s*1",
    "1'\\s*OR\\s*'1'\\s*=\\s*'1",
  ].join("|"),
  "i",
);

// XSS payload patterns
const XSS_PAYLOAD_PATTERN = new RegExp(
  [
    "<\\s*script[^>]*>",
    "<\\s*/\\s*script\\s*>",
    "\\bon\\w+\\s*=",                       // event handlers: onerror=, onload=, etc.
    "javascript\\s*:",
    "vbscript\\s*:",
    "data\\s*:.*text/html",
    "<\\s*img[^>]+onerror",
    "<\\s*svg[^>]+onload",
    "<\\s*iframe",
    "<\\s*object",
    "<\\s*embed",
    "<\\s*body[^>]+onload",
    "\\balert\\s*\\(",
    "\\bprompt\\s*\\(",
    "\\bconfirm\\s*\\(",
    "\\bdocument\\.cookie\\b",
    "\\bdocument\\.location\\b",
    "\\bwindow\\.location\\b",
    "\\beval\\s*\\(",
    "expression\\s*\\(",
    "url\\s*\\(",
    "String\\.fromCharCode",
    "\\batob\\s*\\(",
  ].join("|"),
  "i",
);

// SSTI patterns
const SSTI_PATTERN = new RegExp(
  [
    "\\{\\{.*\\}\\}",                       // Jinja2/Twig: {{ }}
    "\\$\\{.*\\}",                          // EL/Freemarker: ${ }
    "\\{%.*%\\}",                           // Jinja2 block: {% %}
    "#\\{.*\\}",                            // Ruby ERB: #{ }
    "\\{\\*.*\\*\\}",                       // Smarty: {* *}
    "__class__",
    "__mro__",
    "__subclasses__",
    "__globals__",
    "__builtins__",
    "\\|attr\\(",
    "lipsum\\.",
    "cycler\\.",
    "joiner\\.",
    "request\\.application",
    "\\bTEMPLATE\\b.*\\bINJECTION\\b",
  ].join("|"),
  "i",
);

// Path traversal patterns
const PATH_TRAVERSAL_PATTERN = new RegExp(
  [
    "\\.\\./",
    "\\.\\.\\\\/",
    "%2e%2e[%/\\\\]",
    "\\.\\.%2f",
    "\\.\\.%5c",
    "/etc/passwd",
    "/etc/shadow",
    "\\bC:\\\\Windows\\b",
    "\\bwin\\.ini\\b",
    "/proc/self",
    "/proc/version",
    "file:///",
    "php://filter",
    "php://input",
    "zip://",
  ].join("|"),
  "i",
);

// Command injection patterns
const CMD_INJECTION_PATTERN = new RegExp(
  [
    "[;|&`]\\s*\\w",                        // shell metacharacters followed by commands
    "\\$\\(\\w",                            // $() subshell
    "\\|\\|\\s*\\w",
    "&&\\s*\\w",
    "\\bexec\\s*\\(",
    "\\bsystem\\s*\\(",
    "\\bpassthru\\s*\\(",
    "\\bpopen\\s*\\(",
    "\\bproc_open\\s*\\(",
    "\\bshell_exec\\s*\\(",
    "`[^`]+`",                              // backtick execution
    "\\bping\\s+-",
    "\\bwhoami\\b",
    "\\bid\\b",
    "\\bcat\\s+/etc/",
    "\\bcurl\\s+",
    "\\bwget\\s+",
    "\\bnc\\s+-",
    "\\bnslookup\\s+",
    "\\bdig\\s+",
  ].join("|"),
  "i",
);

// Encoding detection
const ENCODING_PATTERN = new RegExp(
  [
    "%[0-9a-fA-F]{2}",                     // URL encoding
    "&#\\d+;",                              // HTML numeric entity
    "&#x[0-9a-fA-F]+;",                    // HTML hex entity
    "\\\\u[0-9a-fA-F]{4}",                 // Unicode escape
    "\\\\x[0-9a-fA-F]{2}",                 // Hex escape
    "[A-Za-z0-9+/]{20,}={0,2}",            // Base64 (20+ chars)
    "0x[0-9a-fA-F]{4,}",                   // Hex literal
    "\\\\[0-7]{3}",                         // Octal escape
    "data:[^;]+;base64,",
    "fromCharCode",
  ].join("|"),
  "i",
);

// HTTP method mapping
const HTTP_METHOD_MAP: Record<string, number> = {
  GET: 0,
  POST: 1,
  PUT: 2,
  PATCH: 3,
  DELETE: 4,
  HEAD: 5,
  OPTIONS: 6,
};

// Hedging language
const HEDGING_PATTERN =
  /\b(possible|possibly|might|could be|may be|appears to|seems to|potentially|likely|unlikely|suspect|uncertain|unclear|unconfirmed|speculative|hypothetical)\b/i;

// Verification language
const VERIFICATION_PATTERN =
  /\b(confirmed|verified|reproduced|demonstrated|proven|validated|successfully exploited|exploitation confirmed|proof of concept|PoC|flag captured|flag extracted|successfully retrieved)\b/i;

// Reproduction steps
const REPRO_STEPS_PATTERN =
  /\b(step[s]?\s*\d|steps to reproduce|reproduction|how to reproduce|to reproduce|1\.\s|2\.\s|curl\s|request:|payload:|poc:)\b/i;

// Impact statement
const IMPACT_PATTERN =
  /\b(impact|allows|attacker can|attacker could|leads to|results in|enables|exposes|compromises|unauthorized|escalat|remote code execution|RCE|data leak|data exposure|privilege escalation|account takeover|information disclosure|denial of service|DoS)\b/i;

// Code block patterns
const CODE_BLOCK_PATTERN = /```[\s\S]*?```|`[^`]+`|\bHTTP\/\d\.\d\b|\bcurl\b/;

// Severity ordinal mapping
const SEVERITY_ORDINAL: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

// High-confidence categories (injection-based with clear signal)
const HIGH_CONFIDENCE_CATEGORIES: Set<AttackCategory> = new Set([
  "sql-injection",
  "xss",
  "command-injection",
  "code-injection",
  "path-traversal",
  "ssrf",
]);

// Injection-class categories
const INJECTION_CATEGORIES: Set<AttackCategory> = new Set([
  "sql-injection",
  "xss",
  "command-injection",
  "code-injection",
  "prompt-injection",
]);

// Access-control-class categories
const ACCESS_CONTROL_CATEGORIES: Set<AttackCategory> = new Set([
  "data-exfiltration",
  "system-prompt-extraction",
  "information-disclosure",
  "cors",
  "security-misconfiguration",
]);

// CWE reference pattern
const CWE_PATTERN = /\bCWE-\d+\b/i;

// CVE reference pattern
const CVE_PATTERN = /\bCVE-\d{4}-\d{4,}\b/i;

// Payload-to-category consistency mapping
const PAYLOAD_CATEGORY_MAP: Record<string, RegExp> = {
  "sql-injection": SQL_SYNTAX_PATTERN,
  xss: XSS_PAYLOAD_PATTERN,
  "command-injection": CMD_INJECTION_PATTERN,
  "code-injection": CMD_INJECTION_PATTERN,
  "path-traversal": PATH_TRAVERSAL_PATTERN,
};

// ────────────────────────────────────────────────────────────────────
// Helper utilities
// ────────────────────────────────────────────────────────────────────

/** Convert boolean to 0/1 */
function b(value: boolean): number {
  return value ? 1 : 0;
}

/** Extract HTTP status code from response text */
function extractHttpStatus(response: string): number {
  // Match "HTTP/1.1 200 OK" or "status: 200" or "Status Code: 200"
  const match = response.match(
    /(?:HTTP\/\d\.\d\s+(\d{3})|status(?:\s*code)?[:\s]+(\d{3}))/i,
  );
  if (match) return parseInt(match[1] || match[2], 10);
  return 0;
}

/** Extract HTTP method from request text */
function extractHttpMethod(request: string): number {
  const match = request.match(
    /\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/i,
  );
  if (match) return HTTP_METHOD_MAP[match[1].toUpperCase()] ?? 0;
  return 0;
}

/** Count URL/form parameters in a request */
function countParameters(request: string): number {
  // Count query string params: ?a=1&b=2&c=3
  const queryMatch = request.match(/\?([^#\s]+)/);
  let count = 0;
  if (queryMatch) {
    count += queryMatch[1].split("&").length;
  }
  // Count JSON keys in body (rough heuristic)
  const jsonBodyMatch = request.match(/\{[^}]+\}/);
  if (jsonBodyMatch) {
    const keys = jsonBodyMatch[0].match(/"[^"]+"\s*:/g);
    if (keys) count += keys.length;
  }
  // Count form-encoded params
  const formMatch = request.match(
    /(?:Content-Type:.*x-www-form-urlencoded[\s\S]*?\n\n)([^\n]+)/i,
  );
  if (formMatch) {
    count += formMatch[1].split("&").length;
  }
  return count;
}

/** Extract request body length */
function extractBodyLength(request: string): number {
  // Try to find body after double newline (HTTP convention)
  const bodyStart = request.indexOf("\n\n");
  if (bodyStart >= 0) {
    return request.length - bodyStart - 2;
  }
  return 0;
}

/** Extract payload from request for reflection checking */
function extractPayload(request: string): string | null {
  // Look for common payload locations

  // URL query params (grab the longest value)
  const queryMatch = request.match(/\?([^#\s]+)/);
  if (queryMatch) {
    const params = queryMatch[1].split("&");
    let longest = "";
    for (const p of params) {
      const val = p.split("=")[1] || "";
      if (val.length > longest.length) longest = val;
    }
    if (longest.length > 3) return decodeURIComponent(longest);
  }

  // JSON body values
  const jsonMatch = request.match(/"(?:value|payload|input|data|query|body|message|content|prompt|text)"\s*:\s*"([^"]+)"/i);
  if (jsonMatch) return jsonMatch[1];

  // POST body (form-encoded, grab longest value)
  const bodyStart = request.indexOf("\n\n");
  if (bodyStart >= 0) {
    const body = request.slice(bodyStart + 2);
    if (body.includes("=") && !body.startsWith("{")) {
      const params = body.split("&");
      let longest = "";
      for (const p of params) {
        const val = p.split("=")[1] || "";
        if (val.length > longest.length) longest = val;
      }
      if (longest.length > 3) return decodeURIComponent(longest);
    }
  }

  return null;
}

/** Check if response content-type matches expected for the finding category */
function contentTypeMatches(response: string, category: AttackCategory): boolean {
  const ctMatch = response.match(/content-type:\s*([^\n;]+)/i);
  if (!ctMatch) return false;
  const ct = ctMatch[1].toLowerCase().trim();

  // For XSS we expect HTML
  if (category === "xss") return ct.includes("text/html");
  // For API-related attacks we expect JSON
  if (
    category === "sql-injection" ||
    category === "data-exfiltration" ||
    category === "information-disclosure"
  ) {
    return ct.includes("application/json") || ct.includes("text/html");
  }
  // Default: any non-empty content-type is a match
  return ct.length > 0;
}

// ────────────────────────────────────────────────────────────────────
// Kernel crash feature helpers
// ────────────────────────────────────────────────────────────────────

/** Ordinal encoding for CrashType — higher = more exploitable */
const CRASH_TYPE_ORDINAL: Record<CrashType, number> = {
  unknown: 0,
  lockdep: 1,
  "kasan-null": 2,
  "rcu-stall": 3,
  "kasan-oob": 4,
  "kasan-uaf": 5,
  "kasan-stack-oob": 6,
  "kasan-double-free": 7,
  "kasan-invalid-free": 8,
  "kasan-wild": 9,
  ubsan: 10,
  "ubsan-shift": 11,
  "ubsan-overflow": 12,
  "ubsan-bounds": 13,
  "ubsan-alignment": 14,
  "kernel-bug": 15,
  "kernel-oops": 16,
  "kernel-panic": 17,
  "general-protection": 18,
};

/** Network-facing subsystems where crashes have higher impact */
const KERNEL_NETWORK_SUBSYSTEMS = new Set([
  "net/tcp", "net/udp", "net/sctp", "net/ip", "net/netfilter",
  "drivers/bluetooth", "net/wireless", "net/core",
  "fs/nfsd",
]);

/** Subsystem criticality ordinal: 0=unknown, 1=drivers, 2=fs, 3=net, 4=mm/core */
function subsystemCriticality(subsystem: string): number {
  if (subsystem.startsWith("mm") || subsystem.startsWith("kernel/")) return 4;
  if (subsystem.startsWith("net/") || KERNEL_NETWORK_SUBSYSTEMS.has(subsystem)) return 3;
  if (subsystem.startsWith("fs/")) return 2;
  if (subsystem.startsWith("drivers/") || subsystem === "sound" || subsystem === "block") return 1;
  return 0;
}

/** Detect if a finding is a kernel crash finding */
function isKernelFinding(templateId: string | undefined, category: AttackCategory): boolean {
  if (templateId?.startsWith("kernel-")) return true;
  // Kernel crash categories that web findings never produce
  const kernelCategories: Set<AttackCategory> = new Set([
    "heap-overflow", "stack-buffer-overflow", "use-after-free",
    "double-free", "null-pointer-deref", "integer-overflow",
    "race-condition", "type-confusion",
  ]);
  return kernelCategories.has(category);
}

/** Extract kernel crash features (10 features, indices 45-54) */
function extractKernelFeatures(finding: Finding): number[] {
  const { evidence, category, templateId } = finding;
  const analysis = evidence.analysis || "";
  const request = evidence.request || "";
  const description = finding.description || "";
  const allText = `${description}\n${analysis}`;

  if (!isKernelFinding(templateId, category)) {
    // Not a kernel finding — return 10 zeros
    return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  }

  // 45: crash type ordinal — extract from analysis line "Crash type: <type>"
  let crashTypeOrdinal = 0;
  const crashTypeMatch = analysis.match(/Crash type:\s*([\w-]+)/);
  if (crashTypeMatch) {
    const ct = crashTypeMatch[1] as CrashType;
    crashTypeOrdinal = CRASH_TYPE_ORDINAL[ct] ?? 0;
  }

  // 46: stack depth — extract from analysis line "Stack depth: N frames"
  let stackDepth = 0;
  const stackDepthMatch = analysis.match(/Stack depth:\s*(\d+)\s*frames/);
  if (stackDepthMatch) {
    stackDepth = parseInt(stackDepthMatch[1], 10);
  } else {
    // Fallback: count "Call path:" entries or stack-like lines
    const callPathMatch = description.match(/Call path:\s*(.+)/);
    if (callPathMatch) {
      stackDepth = callPathMatch[1].split("→").length;
    }
  }

  // 47: has reproducer — 1 if evidence.request is not the placeholder
  const hasReproducer = b(request !== "N/A (kernel crash report)" && request.length > 0);

  // 48: access is write — check analysis or description for "write"
  const accessIsWrite = b(/\baccess.*write\b/i.test(allText) || /\bWrite of size\b/i.test(allText) || /\baccess:\s*write\b/i.test(allText));

  // 49: access size — extract from "size N" or "size=N"
  let accessSize = 0;
  const accessSizeMatch = allText.match(/(?:size[=\s]+)(\d+)/i);
  if (accessSizeMatch) {
    accessSize = parseInt(accessSizeMatch[1], 10);
  }

  // 50: network subsystem
  const subsystemMatch = analysis.match(/Subsystem:\s*(\S+)/);
  const subsystem = subsystemMatch ? subsystemMatch[1] : "";
  const networkSubsystem = b(KERNEL_NETWORK_SUBSYSTEMS.has(subsystem));

  // 51: has alloc site
  const hasAllocSite = b(/\bAlloc site:\s*\S+/i.test(analysis));

  // 52: has free site
  const hasFreeSite = b(/\bFree site:\s*\S+/i.test(analysis));

  // 53: is KASAN
  const isKasan = b(crashTypeMatch ? crashTypeMatch[1].startsWith("kasan-") : false);

  // 54: subsystem criticality
  const criticalityScore = subsystemCriticality(subsystem);

  return [
    crashTypeOrdinal,
    stackDepth,
    hasReproducer,
    accessIsWrite,
    accessSize,
    networkSubsystem,
    hasAllocSite,
    hasFreeSite,
    isKasan,
    criticalityScore,
  ];
}

// ────────────────────────────────────────────────────────────────────
// Main extractor
// ────────────────────────────────────────────────────────────────────

/**
 * Extract a 55-element numeric feature vector from a Finding.
 *
 * All features are computed via pure regex/string operations.
 * No LLM calls, no network requests.
 *
 * @returns number[] of length 55, ordered per FEATURE_NAMES
 */
export function extractFeatures(finding: Finding): number[] {
  const { evidence, severity, category, confidence, description, templateId } = finding;
  const request = evidence.request || "";
  const response = evidence.response || "";
  const analysis = evidence.analysis || "";
  const allText = `${description} ${analysis}`;

  const payload = extractPayload(request);
  const httpStatus = extractHttpStatus(response);

  const features: number[] = [];

  // ── Response features (13) ──

  // 0: HTTP status code
  features.push(httpStatus);
  // 1: SQL error patterns
  features.push(b(SQL_ERROR_PATTERNS.test(response)));
  // 2: Stack trace
  features.push(b(STACK_TRACE_PATTERN.test(response)));
  // 3: Error message
  features.push(b(ERROR_MESSAGE_PATTERN.test(response)));
  // 4: Payload exact reflection
  features.push(b(payload !== null && payload.length > 3 && response.includes(payload)));
  // 5: Payload partial reflection (first 10 chars)
  features.push(
    b(
      payload !== null &&
        payload.length > 5 &&
        response.toLowerCase().includes(payload.slice(0, 10).toLowerCase()),
    ),
  );
  // 6: Sensitive data patterns
  features.push(b(SENSITIVE_DATA_PATTERN.test(response)));
  // 7: FLAG pattern
  features.push(b(FLAG_PATTERN.test(response)));
  // 8: Content-type match
  features.push(b(contentTypeMatches(response, category)));
  // 9: Response length
  features.push(response.length);
  // 10: WAF signature
  features.push(b(WAF_SIGNATURE_PATTERN.test(response)));
  // 11: Redirect
  features.push(b(REDIRECT_PATTERN.test(response)));
  // 12: 5xx status
  features.push(b(httpStatus >= 500 && httpStatus < 600));

  // ── Request features (10) ──

  // 13: SQL syntax
  features.push(b(SQL_SYNTAX_PATTERN.test(request)));
  // 14: XSS payloads
  features.push(b(XSS_PAYLOAD_PATTERN.test(request)));
  // 15: SSTI syntax
  features.push(b(SSTI_PATTERN.test(request)));
  // 16: Path traversal
  features.push(b(PATH_TRAVERSAL_PATTERN.test(request)));
  // 17: Command injection
  features.push(b(CMD_INJECTION_PATTERN.test(request)));
  // 18: Encoding detected
  features.push(b(ENCODING_PATTERN.test(request)));
  // 19: HTTP method
  features.push(extractHttpMethod(request));
  // 20: Auth header
  features.push(
    b(/\b(authorization|cookie|x-api-key|x-auth-token)\s*:/i.test(request)),
  );
  // 21: Parameter count
  features.push(countParameters(request));
  // 22: Body length
  features.push(extractBodyLength(request));

  // ── Metadata features (8) ──

  // 23: Severity ordinal
  features.push(SEVERITY_ORDINAL[severity] ?? 0);
  // 24: Confidence
  features.push(confidence ?? 0);
  // 25: High-confidence category
  features.push(b(HIGH_CONFIDENCE_CATEGORIES.has(category)));
  // 26: Injection class
  features.push(b(INJECTION_CATEGORIES.has(category)));
  // 27: Access-control class
  features.push(b(ACCESS_CONTROL_CATEGORIES.has(category)));
  // 28: Has template ID
  features.push(b(templateId !== undefined && templateId.length > 0));
  // 29: Has CWE reference
  features.push(b(CWE_PATTERN.test(allText)));
  // 30: Has CVE reference
  features.push(b(CVE_PATTERN.test(allText)));

  // ── Text quality features (10) ──

  // 31: Description length
  features.push(description.length);
  // 32: Reproduction steps
  features.push(b(REPRO_STEPS_PATTERN.test(allText)));
  // 33: Impact statement
  features.push(b(IMPACT_PATTERN.test(allText)));
  // 34: Hedging language
  features.push(b(HEDGING_PATTERN.test(allText)));
  // 35: Verification language
  features.push(b(VERIFICATION_PATTERN.test(allText)));
  // 36: Analysis length
  features.push(analysis.length);
  // 37: Code blocks
  features.push(b(CODE_BLOCK_PATTERN.test(allText)));
  // 38: Evidence request non-empty
  features.push(b(request.length > 0));
  // 39: Evidence response non-empty
  features.push(b(response.length > 0));
  // 40: Evidence analysis non-empty
  features.push(b(analysis.length > 0));

  // ── Cross-field features (4) ──

  // 41: Payload-category consistency
  const categoryPattern = PAYLOAD_CATEGORY_MAP[category];
  features.push(b(categoryPattern !== undefined && categoryPattern.test(request)));
  // 42: Severity * confidence interaction
  features.push((SEVERITY_ORDINAL[severity] ?? 0) * (confidence ?? 0));
  // 43: Response/request length ratio
  features.push(request.length > 0 ? response.length / request.length : 0);
  // 44: Evidence completeness (non-empty fields / 3)
  const evidenceCount =
    b(request.length > 0) + b(response.length > 0) + b(analysis.length > 0);
  features.push(evidenceCount / 3);

  // ── Kernel crash features (10) ──

  features.push(...extractKernelFeatures(finding));

  return features;
}

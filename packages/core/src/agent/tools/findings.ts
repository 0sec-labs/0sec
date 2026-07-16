/**
 * Findings / reporting tool definitions (pwnkit#611 — split out of the monolithic
 * agent/tools.ts registry).
 *
 * Tools that read and write the findings ledger, loot store, and the
 * task-completion signal.
 *
 * Pure `ToolDefinition` metadata (name / description / parameter schema). The
 * ./tools/index.ts barrel merges every per-domain map into the canonical
 * `TOOL_DEFINITIONS` registry; the matching runtime handlers live on the
 * `ToolExecutor` class in agent/tools.ts.
 */
import type { ToolDefinition } from "../types.js";

export const findingsToolDefinitions: Record<string, ToolDefinition> = {
  save_finding: {
    name: "save_finding",
    description:
      "Save a security finding to the database. Call this when you discover a vulnerability.",
    parameters: {
      title: { type: "string", description: "Short title for the finding" },
      description: { type: "string", description: "Detailed description of the vulnerability" },
      severity: {
        type: "string",
        description: "Severity level",
        enum: ["critical", "high", "medium", "low", "info"],
      },
      category: {
        type: "string",
        description: "Attack category",
        enum: [
          // AI/LLM attack categories
          "prompt-injection",
          "jailbreak",
          "system-prompt-extraction",
          "data-exfiltration",
          "tool-misuse",
          "output-manipulation",
          "encoding-bypass",
          "multi-turn",
          // Source-code audit categories (pwnkit audit)
          "prototype-pollution",
          "path-traversal",
          "command-injection",
          "code-injection",
          "regex-dos",
          "unsafe-deserialization",
          "information-disclosure",
          "ssrf",
          "sql-injection",
          "xss",
          "cors",
          "security-misconfiguration",
          "missing-validation",
          // Memory corruption / binary categories (C/C++ review, kernel review)
          "heap-overflow",
          "out-of-bounds-read",
          "out-of-bounds-write",
          "use-after-free",
          "stack-buffer-overflow",
          "null-pointer-deref",
          "null-deref",
          "integer-overflow",
          "integer-truncation",
          "race-condition",
          "toctou",
          "type-confusion",
          "double-free",
          "format-string",
          "uninitialized-memory",
          // Supply-chain / package categories
          "known-vulnerable-package",
          "supply-chain",
          "other",
        ],
      },
      template_id: { type: "string", description: "ID of the attack template used" },
      evidence_request: { type: "string", description: "The request/prompt that triggered the vuln" },
      evidence_response: { type: "string", description: "The response showing the vulnerability" },
      evidence_analysis: { type: "string", description: "Your analysis of why this is a vulnerability" },
      source_path: {
        type: "string",
        description:
          "OPTIONAL repository-relative source path for an inline CI review comment. Must be inside the scan workspace. Supply only when you inspected the exact vulnerable line.",
      },
      source_start_line: {
        type: "number",
        description:
          "OPTIONAL 1-based source line for the inline CI review comment. Requires source_path.",
      },
      source_end_line: {
        type: "number",
        description:
          "OPTIONAL inclusive 1-based end line. Must be >= source_start_line.",
      },
      suggested_replacement: {
        type: "string",
        description:
          "OPTIONAL exact replacement text for source_start_line..source_end_line. Do not send a unified diff or markdown fence.",
      },
      // pwnkit#170 — optional structured proof-of-concept step graph. When the
      // agent has structured execution data (e.g. it actually ran the curl /
      // docker steps and observed predictable outputs), it can pass them as a
      // JSON string here. Each step has { id, kind, summary, action, expect? }.
      // See PocStep / PocStepKind in @pwnkit/shared/types.ts. Optional —
      // findings with prose-only evidence MUST leave this unset.
      poc_steps: {
        type: "string",
        description:
          "OPTIONAL JSON-encoded PocStep[] array (pwnkit#170). Each step: { id, kind: setup|auth|prerequisite|exploit|verify, summary, action: { type: shell|http|docker|note, ... }, expect?: { type: ... } }. Leave unset when you only have prose evidence.",
      },
      // pwnkit#193 — optional machine-executable verification contract. When
      // the agent has cited concrete file:line evidence, it should populate
      // `code[]` predicates so cloud's canary watcher can later re-evaluate
      // the finding deterministically. Each predicate is one of:
      //   - { kind:"file-contains", file, pattern, flags? } — vulnerable
      //     shape still present.
      //   - { kind:"file-missing-pattern", file, pattern, flags? } — fix
      //     marker still absent.
      //   - { kind:"file-exists", file } — vulnerable file still present.
      //   - { kind:"ast-shape", file, query } — tree-sitter (not yet eval'd
      //     by the OSS verifier; record for future use).
      // Pass as a JSON-encoded string to match the LLM tool wire format.
      verification_spec: {
        type: "string",
        description:
          "OPTIONAL JSON-encoded VerificationSpec (pwnkit#193). Shape: { code: Array<{ kind:'file-contains'|'file-missing-pattern'|'file-exists'|'ast-shape', file, pattern?, flags?, query? }>, behavior?: { steps: Array<{ method, path, body?, expect: 'success'|'forbidden'|{status:number} }> } }. Populate code[] predicates from the file:line evidence you cited so cloud can re-verify the finding deterministically. Example for a SQLi at app/users.ts:43: code:[{kind:'file-contains',file:'app/users.ts',pattern:'db\\\\.query.*req\\\\.body'}]. Leave unset when you cannot pin the vulnerable shape to a regex.",
      },
      // Self-reported calibration of how confident the agent is that this
      // finding is a true positive. The cloud DB stores it in
      // `findings.confidence` (numeric(4,3)) and the dashboard surfaces it in
      // triage views. LLMs are notoriously bad at calibration, so the OSS
      // engine clamps to [0,1] AND applies a PoC-status floor in
      // `saveFinding()` (no PoC → no floor; pocSteps present → ≥0.6;
      // pocSteps with at least one verifiable `expect` predicate → ≥0.8).
      // Leave unset if you genuinely have no signal.
      confidence: {
        type: "number",
        description:
          "OPTIONAL self-reported confidence in [0,1]. Use 0.9+ only when the PoC actually executed and produced the expected output. 0.6–0.8 for solid evidence without execution. 0.3–0.5 for plausible but unverified leads. Leave unset when you have no signal.",
      },
      // pwnkit#409 — structural validation at the report-creation boundary.
      // CVE / CWE / CVSS are shape-checked before persistence by
      // `validateFindingDraft` (agent/finding-validator.ts). Malformed values
      // come back to the agent as `validation_failed` so it can fix and
      // re-submit on the same turn. We deliberately don't auto-uppercase or
      // re-format — silent correction hides upstream prompt bugs.
      cve: {
        type: "string",
        description:
          "OPTIONAL CVE identifier this finding maps to. Format: CVE-YYYY-N (uppercase, year 1900–2099, ≥4-digit sequence). Example: CVE-2024-1086. Leave unset when no CVE is assigned.",
      },
      cwe: {
        type: "string",
        description:
          "OPTIONAL CWE identifier this finding maps to. Format: CWE-N (uppercase, integer). Example: CWE-89 for SQL injection. Leave unset when no CWE is appropriate.",
      },
      cvss: {
        type: "string",
        description:
          "OPTIONAL CVSS v3.1 base vector string. Format: CVSS:3.1/AV:?/AC:?/PR:?/UI:?/S:?/C:?/I:?/A:?. Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. We accept v3.1 only.",
      },
      cvss_score: {
        type: "number",
        description:
          "OPTIONAL numeric CVSS base score in [0.0, 10.0]. Only meaningful alongside `cvss`. Leave unset if you only have the vector.",
      },
      evidence_paths: {
        type: "string",
        description:
          "OPTIONAL JSON-encoded string[] of filesystem paths inside the scan workspace that back this finding (screenshots, captured-request blobs, etc.). Paths must be relative to the workspace root OR absolute and inside it. '..' segments, paths outside the workspace, and symlinks that escape the workspace are rejected.",
      },
    },
    required: ["title", "severity", "category", "evidence_request", "evidence_response"],
  },

  query_findings: {
    name: "query_findings",
    description:
      "Query existing findings from the database. Use this to check what has been found so far.",
    parameters: {
      severity: {
        type: "string",
        description: "Filter by severity",
        enum: ["critical", "high", "medium", "low", "info"],
      },
      category: { type: "string", description: "Filter by attack category" },
      status: {
        type: "string",
        description: "Filter by status",
        enum: ["discovered", "confirmed", "false-positive"],
      },
      limit: { type: "number", description: "Max results to return (default 20)" },
    },
  },

  // pwnkit#567 — retrieve previously captured footholds for exploit chaining.
  use_loot: {
    name: "use_loot",
    description:
      "Retrieve footholds (credentials, tokens, cookies, hashes, endpoints, sensitive paths) captured EARLIER this scan so you can REUSE them in a follow-up request and chain to higher impact — e.g. authenticate with a leaked credential, replay a session cookie, hit a discovered endpoint, or crack a captured hash. Returns the FULL stored values (the per-turn 'known footholds' summary may truncate long ones). Optionally filter by kind and/or a case-insensitive substring.",
    parameters: {
      kind: {
        type: "string",
        description: "Optional: only return loot of this kind.",
        enum: ["credential", "token", "path", "endpoint", "hash", "cookie"],
      },
      search: {
        type: "string",
        description:
          "Optional: only return loot whose id, value, or context contains this substring (case-insensitive).",
      },
      id: { type: "string", description: "Optional: return only the loot item with this id (e.g. 'loot-3')." },
    },
  },

  update_finding: {
    name: "update_finding",
    description:
      "Update the status of an existing finding (e.g., mark as confirmed or false-positive).",
    parameters: {
      finding_id: { type: "string", description: "ID of the finding to update" },
      status: {
        type: "string",
        description: "New status",
        enum: ["discovered", "confirmed", "false-positive"],
      },
    },
    required: ["finding_id", "status"],
  },

  done: {
    name: "done",
    description:
      "Signal that you have completed your task. Include a summary of what you found or did.",
    parameters: {
      summary: { type: "string", description: "Summary of completed work" },
    },
    required: ["summary"],
  },
};

// Tool-name → ToolExecutor handler-method name (pwnkit#614). Co-located with
// this domain's definitions so a new tool adds its route here, not in a
// shared dispatch switch. Assembled by ./dispatch.ts; resolved off the
// executor instance in agent/tools.ts (handler bodies stay private methods).
export const findingsDispatch: Record<string, string> = {
  save_finding: "saveFinding",
  query_findings: "queryFindings",
  use_loot: "useLoot",
  update_finding: "updateFinding",
  done: "markDone",
};

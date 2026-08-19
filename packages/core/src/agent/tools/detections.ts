/**
 * Detection tool definitions (pwnkit #774 / #775) — exposes the
 * structural-SQLi and prompt-layer detection engines as first-class agent
 * tools so the live loop can invoke them, not just the JIT skill methodology.
 *
 * - structural_sqli_probe: drives the JSON-key break/balance refinement loop
 *   over real HTTP (the McKinsey-class vector standard scanners miss).
 * - prompt_layer_probe: classifies the WRITE impact of a prompt-layer DB asset
 *   the agent has already read (verification-only; performs no writes).
 *
 * Pure `ToolDefinition` metadata; the runtime handlers live on the
 * `ToolExecutor` class in agent/tools.ts and are routed by `detectionDispatch`.
 */
import type { ToolDefinition } from "../types.js";

export const detectionToolDefinitions: Record<string, ToolDefinition> = {
  structural_sqli_probe: {
    name: "structural_sqli_probe",
    description:
      "Detect STRUCTURAL SQL injection — injection through a JSON KEY / field name concatenated into SQL (e.g. ORDER BY ${key}), the value-fuzzing blind spot that standard scanners (sqlmap/ZAP) miss. " +
      "Drives a break→balance refinement loop: sends a broken key (trailing quote) to see if it reaches the parser, fingerprints the DB dialect from the error, then sends a balanced key using that dialect's comment syntax. A balanced key that parses cleanly while the broken key errored = differential CONFIRMED. " +
      "Use this when a JSON endpoint reflects field NAMES into DB error messages, or you suspect dynamic identifiers (sort/filter/column params). Returns the verdict (confirmed / error_signal / exhausted), the fingerprinted dialect, and the full iteration trail — call save_finding with it on `confirmed`.",
    parameters: {
      url: { type: "string", description: "The JSON endpoint to probe (must be in scope)." },
      base_key: {
        type: "string",
        description: "The JSON key / field name to fuzz (the suspected dynamic identifier, e.g. \"sort\", \"orderBy\", \"column\").",
      },
      method: { type: "string", description: "HTTP method (default POST).", enum: ["POST", "PUT", "PATCH", "GET"] },
      body: {
        type: "object",
        description: "Optional base JSON body; the probed key is injected/mutated into a copy of this object each iteration. Other fields are sent verbatim.",
      },
      max_iterations: { type: "number", description: "Hard cap on probe iterations (default 6, min 2)." },
    },
    required: ["url", "base_key"],
  },
  prompt_layer_probe: {
    name: "prompt_layer_probe",
    description:
      "Classify the WRITE impact of a discovered prompt-layer asset — system prompts / model configs stored in a DB the agent can reach. Verification-only: derives impact from read-only evidence you pass in; it performs NO writes. " +
      "Pass the table/column names and a read-only sample of the value, plus whether your foothold can WRITE it and whether the app re-reads it at inference. Returns whether it is a prompt-layer control asset, the impact classes a write enables (prompt_poisoning / guardrail_removal / output_exfil), and a coarse severity (high ONLY when writable AND re-read at inference — persistent server-side prompt injection). Use after you get DB read access on an AI app; feed the narrative to save_finding.",
    parameters: {
      table: { type: "string", description: "Table / collection name of the asset." },
      column: { type: "string", description: "Column / field / key name." },
      sample: { type: "string", description: "A read-only, truncated SAMPLE of the current value (do NOT dump secrets in full)." },
      writable: { type: "boolean", description: "Whether the current foothold can WRITE this asset (privilege/endpoint evidence)." },
      re_read_at_inference: {
        type: "boolean",
        description: "Whether the app re-reads this row at inference time (vs. baked into code/env at deploy). Drives the high-severity verdict.",
      },
    },
    required: ["writable"],
  },
  auth_boundary_probe: {
    name: "auth_boundary_probe",
    description:
      "Detect unauthenticated-reachable endpoints (the McKinsey '22 of 200 endpoints required no auth' class). For each endpoint, sends an UNAUTHENTICATED request (auth stripped) and, when the scan has credentials, an AUTHENTICATED baseline, then diffs them. " +
      "Reports per endpoint whether it is reachable with no credentials (`unauth-reachable`), the boundary holds (`auth-required` 401/403), or it is `not-found`/`inconclusive`. HIGH severity when an anonymous caller gets the SAME protected resource the authed baseline did. " +
      "Use after enumerating an API surface (recon / OpenAPI docs) to find which endpoints leak without auth. Returns full unauth-vs-auth evidence per endpoint; call save_finding for each unauth-reachable break.",
    parameters: {
      endpoints: {
        type: "object",
        description: "Array of endpoints to probe. Each item is a URL string or { url, method, body }. All must be in scope.",
      },
    },
    required: ["endpoints"],
  },
};

// Tool-name → ToolExecutor handler-method name (pwnkit#614).
export const detectionDispatch: Record<string, string> = {
  structural_sqli_probe: "structuralSqliProbe",
  prompt_layer_probe: "promptLayerProbe",
  auth_boundary_probe: "authBoundaryProbe",
};

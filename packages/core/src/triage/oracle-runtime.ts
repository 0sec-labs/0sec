/**
 * Runtime indirection for the oracles module.
 *
 * Why: the oracles rely on `crypto.randomUUID` and `http.createServer`. We
 * re-export them from this tiny module so that tests can spin up fake
 * collectors / deterministic UUIDs without monkey-patching Node globals.
 */

export { randomUUID } from "node:crypto";
export { createServer } from "node:http";

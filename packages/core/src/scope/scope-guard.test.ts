/**
 * Unit tests for the scope-guard visibility vocabulary (0sec#133).
 *
 * These pin the *contract* the two call sites depend on:
 *   - the inert-guard list is non-empty and names the bash guards, so the
 *     `scope_guards_inert` event payload can never quietly become `[]`;
 *   - `describeScopeGuards(false)` always produces a non-empty message;
 *   - the strictness switch is opt-in and defaults to off, which is what
 *     keeps the currently-shipping unscoped scan modes working.
 */
import { describe, it, expect } from "vitest";
import {
  describeScopeGuards,
  isScopeRequired,
  networkScopeRequiredRefusal,
  scopeRequiredRefusal,
  targetRequiresScope,
  SCOPE_DEPENDENT_BASH_GUARDS,
  SCOPE_GUARDS_INERT_EVENT,
} from "./scope-guard.js";

describe("describeScopeGuards (0sec#133)", () => {
  it("reports the guards as active when a scope is configured, with nothing inert", () => {
    const status = describeScopeGuards(true, {});
    expect(status.active).toBe(true);
    expect(status.inertGuards).toEqual([]);
    expect(status.message).toBe("");
  });

  it("reports every scope-dependent bash guard as inert when no scope is configured", () => {
    const status = describeScopeGuards(false, {});
    expect(status.active).toBe(false);
    // The whole point of the issue: the absence must not be silent. If a
    // future refactor empties this list or blanks the message, the signal is
    // gone and this test fails.
    expect(status.inertGuards.length).toBeGreaterThan(0);
    expect(status.inertGuards).toEqual([...SCOPE_DEPENDENT_BASH_GUARDS]);
    expect(status.message).not.toBe("");
    expect(status.message).toMatch(/INERT/);
    expect(status.message).toMatch(/--scope/);
  });

  it("names the specific guards a reviewer would otherwise assume ran", () => {
    expect(SCOPE_DEPENDENT_BASH_GUARDS).toContain("bash_out_of_scope_url_refusal");
    expect(SCOPE_DEPENDENT_BASH_GUARDS).toContain("bash_generic_scanner_suppression");
    expect(SCOPE_DEPENDENT_BASH_GUARDS).toContain("bash_http_audit_path_allowlist");
    expect(SCOPE_DEPENDENT_BASH_GUARDS).toContain("bash_auth_header_injection");
  });

  it("keeps the event type stable — it is the queryable audit key", () => {
    expect(SCOPE_GUARDS_INERT_EVENT).toBe("scope_guards_inert");
  });
});

describe("isScopeRequired (0SEC_REQUIRE_SCOPE)", () => {
  it("defaults to false so today's unscoped scan modes keep running", () => {
    expect(isScopeRequired({})).toBe(false);
    expect(isScopeRequired({ "0SEC_REQUIRE_SCOPE": "" })).toBe(false);
    expect(isScopeRequired({ "0SEC_REQUIRE_SCOPE": "0" })).toBe(false);
    expect(isScopeRequired({ "0SEC_REQUIRE_SCOPE": "false" })).toBe(false);
  });

  it("accepts the usual truthy spellings", () => {
    for (const raw of ["1", "true", "TRUE", "yes", " on "]) {
      expect(isScopeRequired({ "0SEC_REQUIRE_SCOPE": raw })).toBe(true);
    }
  });

  it("threads through describeScopeGuards as `required`", () => {
    expect(describeScopeGuards(false, { "0SEC_REQUIRE_SCOPE": "1" }).required).toBe(true);
    expect(describeScopeGuards(false, {}).required).toBe(false);
  });
});

describe("scopeRequiredRefusal", () => {
  it("names the site and tells the operator how to fix it", () => {
    const msg = scopeRequiredRefusal("bash");
    expect(msg).toMatch(/^bash refused:/);
    expect(msg).toMatch(/0SEC_REQUIRE_SCOPE/);
    expect(msg).toMatch(/--scope/);
  });
});

describe("targetRequiresScope", () => {
  it("identifies live network protocols without gating local targets", () => {
    expect(targetRequiresScope("https://example.com")).toBe(true);
    expect(targetRequiresScope("http://example.com")).toBe(true);
    expect(targetRequiresScope("mcp://example.com")).toBe(true);
    expect(targetRequiresScope("lodash")).toBe(false);
    expect(targetRequiresScope("./local-source")).toBe(false);
  });

  it("names the target and remediation in the live-target refusal", () => {
    const message = networkScopeRequiredRefusal("https://example.com");
    expect(message).toMatch(/https:\/\/example\.com/);
    expect(message).toMatch(/--scope/);
  });
});
